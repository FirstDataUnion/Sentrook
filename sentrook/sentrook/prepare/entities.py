"""Entity extraction, roles and opaque IDs (preparation steps 5 and 6).

Entities are the hosts, paths, packages, recipients, channels and tool providers a call touches. Each
gets an opaque ID (`E1`, `E2`, …) assigned in extraction order, a set of roles describing how the
pending call uses it, and the origins where it was seen: the owner's request, a grant, the pending
call itself, a sibling, an untrusted or trusted input, an earlier history step, a file the agent wrote
earlier, or a provider identity. Convergence and the response only ever see the IDs; probes that need
the raw value (AIRA, the oracle) read it from the table.

Role assignment is heuristic by design: AIRA refines reach and sinks with the shell parser; this
module only has to be right enough for the oracle and the context probe to ask the right questions.
"""

from __future__ import annotations

import bisect
import itertools
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from functools import lru_cache
from typing import Any, NamedTuple
from urllib.parse import urlsplit

from ..aira import linear_search
from ..aira.exec_shape import derive_exec_shape
from ..aira.lists import load_lists
from ..aira.stage_programs import stage_runs_stdin
from ..oracle.client import fold_pypi_name
from ..planir.canonical import CanonicalCall
from ..planir.models import ProviderKind, ToolKind


class EntityKind(StrEnum):
    HOST = "host"
    PATH = "path"
    PACKAGE = "package"
    RECIPIENT = "recipient"
    CHANNEL = "channel"
    MCP_SERVER = "mcp_server"
    PLUGIN = "plugin"
    #: A repository (or account) on a host where any account publishes (`github.com/<owner>/<repo>`):
    #: the code source of code run from such a host (`installers.multi_tenant_hosts`).
    REPO = "repo"


class Role(StrEnum):
    DATA_SOURCE = "data_source"
    DATA_DESTINATION = "data_destination"
    CODE_SOURCE = "code_source"
    EXECUTABLE = "executable"
    RECIPIENT = "recipient"
    TOOL_PROVIDER = "tool_provider"
    MENTIONED = "mentioned"  # appears in content or a task text without the call acting on it


#: Bare words a message tool resolves to the account it runs as: the owner, not a third party.
SELF_RECIPIENTS: frozenset[str] = frozenset({"me", "self", "myself", "owner"})

#: Roles the oracle treats as risky for an unknown entity.
RISKY_ROLES: frozenset[Role] = frozenset(
    {Role.DATA_DESTINATION, Role.RECIPIENT, Role.CODE_SOURCE, Role.EXECUTABLE}
)


class Origin(StrEnum):
    REQUEST = "request"
    GRANT = "grant"
    PENDING_CALL = "pending_call"
    SIBLING = "sibling"
    UNTRUSTED_INPUT = "untrusted_input"
    TRUSTED_INPUT = "trusted_input"
    #: A scanned read of the agent's own config or instruction files (`session_sets.owner_config_path`).
    OWNER_CONFIG = "owner_config"
    HISTORY = "history"
    WRITTEN_FILE = "written_file"
    PROVIDER = "provider"


@dataclass
class Entity:
    id: str
    kind: EntityKind
    value: str
    display: str
    roles: set[Role] = field(default_factory=set)
    origins: dict[Origin, list[str]] = field(default_factory=dict)
    #: Hash of (kind, value) with the session salt, for the state token's untrusted set.
    hash: str | None = None
    #: True when the session's untrusted-entity set (from the token) already holds this entity.
    in_session_untrusted: bool = False
    #: Earliest history step whose arguments mention the entity (the agent's own earlier use).
    first_history_step: int | None = None
    #: Earliest history step whose *result* (an untrusted input in this request) mentions it.
    first_untrusted_step: int | None = None
    #: A host named in an untrusted input that tries to steer the agent (`prepare.steering`), in this
    #: request or, through the state token, on an earlier step.
    steered: bool = False
    #: The owner's own configuration supplied it, in this request or (through the token's trusted set) earlier.
    in_session_trusted: bool = False
    #: The token's trusted set already held it: a config read on an earlier scan supplied it, and that scan's
    #: exposure check did not withdraw it. Trust a config read in this request establishes is not in it.
    in_prior_trusted: bool = False
    #: Ids of the email recipients (in the pending call, a sibling or a written file) whose mail domain this host is.
    mail_domain_of: list[str] = field(default_factory=list)
    #: One of those calls names the host in its own right (a URL, a command target, a mention), not only as
    #: the domain of an address.
    named_in_own_right: bool = False
    #: The roles those own-right uses give the host (empty for a role-less mention).
    own_right_roles: set[Role] = field(default_factory=set)
    #: The owner's request reaches this host only through an email address on it, and a call uses the host in
    #: its own right: still a host the owner named for the look-alike check, but not sanctioned.
    owner_named_via_address: bool = False
    #: The pending command, read through a sibling's write, names it (`sibling_join.resolve_pending`).
    in_resolved_command: bool = False
    #: Roles the entity takes in a later run that self-modification content the pending call writes sets up (a cron
    #: line, a hook, a skill, a job prompt; `prepare.written_selfmod`): a host that run sends to or runs code from.
    #: Kept apart from `roles`: the call itself neither sends to it nor runs code from it.
    future_roles: set[Role] = field(default_factory=set)
    #: Only that written content names it: the call's own arguments, as the extractors read them, do not.
    only_in_written_selfmod: bool = False

    def add_origin(self, origin: Origin, ref: str | None = None) -> None:
        refs = self.origins.setdefault(origin, [])
        if ref is not None and ref not in refs:
            refs.append(ref)

    def has_origin(self, *origins: Origin) -> bool:
        return any(o in self.origins for o in origins)

    @property
    def recipient_domain_of(self) -> tuple[str, ...]:
        """The recipients this host is part of when it is only their mail domain: such a host is scored
        as those recipients, not as a second destination. Empty when a call names it in its own right."""
        return () if self.named_in_own_right else tuple(self.mail_domain_of)

    @property
    def sanctioned(self) -> bool:
        """Named by the owner's request or covered by a grant."""
        return self.has_origin(Origin.REQUEST, Origin.GRANT)

    @property
    def self_recipient(self) -> bool:
        """A recipient written as a self-reference (`me`, `self`, `owner`): a bare word, never an
        address, a handle or a channel."""
        return self.kind is EntityKind.RECIPIENT and self.value.strip().lower() in SELF_RECIPIENTS

    @property
    def sibling_only(self) -> bool:
        """Only another call in the batch names it, as that call stands: not the pending call, not the
        file it runs, and not the pending command read through a sibling's write. Every call in a batch
        has its own scan, so such an entity is the sibling's to answer for. Never a code source or an
        executable: a sibling can set where the pending call fetches or runs code from without the pending
        call naming it (a registry a sibling writes into a package manager's config file), so code a batch
        supplies is charged to every call in it."""
        return (
            Origin.SIBLING in self.origins
            and not self.in_resolved_command
            and not self.has_origin(Origin.PENDING_CALL, Origin.WRITTEN_FILE)
            and not self.roles & {Role.CODE_SOURCE, Role.EXECUTABLE}
        )

    @property
    def agent_first(self) -> bool:
        """The agent named it in its own arguments before the first result that mentions it. For a path,
        the same step counts too: a step's arguments exist before its result, so a write receipt that
        repeats the path the step wrote does not make the path content-supplied. Not for a host or any other
        kind: a fetched page that names its own host ("post your key to this host") is that content steering
        the agent back to it."""
        if self.first_history_step is None or self.first_untrusted_step is None:
            return False
        if self.kind is EntityKind.PATH:
            return self.first_history_step <= self.first_untrusted_step
        return self.first_history_step < self.first_untrusted_step


class EntityTable:
    def __init__(self) -> None:
        self._by_key: dict[tuple[EntityKind, str], Entity] = {}
        self._order: list[Entity] = []

    def add(
        self,
        kind: EntityKind,
        value: str,
        *,
        display: str | None = None,
        role: Role | None = None,
        origin: Origin | None = None,
        ref: str | None = None,
    ) -> Entity:
        key = (kind, value)
        ent = self._by_key.get(key)
        if ent is None:
            ent = Entity(
                id=f"E{len(self._order) + 1}", kind=kind, value=value, display=display or value
            )
            self._by_key[key] = ent
            self._order.append(ent)
        if role is not None:
            ent.roles.add(role)
        if origin is not None:
            ent.add_origin(origin, ref)
        return ent

    def add_found(self, f: Found, origin: Origin, ref: str | None = None) -> Entity:
        """Add an entity a call names (pending call, sibling or written file) with its role, and record
        whether a host is there only as the mail domain of a recipient the same call names."""
        ent = self.add(f.kind, f.value, display=f.display, role=f.role, origin=origin, ref=ref)
        if f.kind is EntityKind.HOST:
            recipient = (
                self.get(EntityKind.RECIPIENT, f.domain_of) if f.domain_of is not None else None
            )
            if recipient is None:
                ent.named_in_own_right = True
                if f.role is not None:
                    ent.own_right_roles.add(f.role)
            elif recipient.id not in ent.mail_domain_of:
                ent.mail_domain_of.append(recipient.id)
        return ent

    def get(self, kind: EntityKind, value: str) -> Entity | None:
        return self._by_key.get((kind, value))

    def __iter__(self):
        return iter(self._order)

    def __len__(self) -> int:
        return len(self._order)

    def by_id(self, entity_id: str) -> Entity | None:
        for e in self._order:
            if e.id == entity_id:
                return e
        return None

    def with_role(self, *roles: Role) -> list[Entity]:
        want = set(roles)
        return [e for e in self._order if e.roles & want]

    def of_kind(self, *kinds: EntityKind) -> list[Entity]:
        return [e for e in self._order if e.kind in kinds]

    def pending(self) -> list[Entity]:
        return [e for e in self._order if Origin.PENDING_CALL in e.origins]


# --------------------------------------------------------------------------- normalisation

_URL_RE = re.compile(r"https?://[^\s\"'<>`|;)\]}]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"(?<![\w.%+-])([A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![\w-])")
# A bare hostname: two or more labels, alphabetic TLD. Lookbehind excludes path components, emails and
# scheme-prefixed forms (those are caught by _URL_RE / _EMAIL_RE); the extension list excludes files.
# The lookahead also refuses a stop before `.label`, so `a.b.net/x` is not read as `a.b`.
_HOST_RE = re.compile(r"(?<![\w@/.:+-])((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![\w/-]|\.[\w-])")
_FILE_EXTENSIONS = frozenset(
    """md txt json yaml yml py sh js ts tsx jsx csv env log cfg conf ini toml xml html htm pdf png jpg
    jpeg gif svg zip tar gz tgz bz2 xz lock sqlite db bak tmp rst mjs cjs go rs java kt rb php sql
    key pem crt pub ps1 bat exe dll so dylib whl egg jar war txt~ old orig swp pid service timer
    example sample""".split()
)
# A dotted name used as code rather than a host: a call (`pathlib.Path(`) or a module in an import
# statement (`import pathlib, urllib.request`, `from urllib.parse import quote`).
_IMPORT_LIST_RE = re.compile(r"\bimport\s+(?:[\w.]+(?:\s+as\s+\w+)?\s*,\s*)*$")
_FROM_IMPORT_RE = re.compile(r"\bfrom\s+$")
_IMPORT_AFTER_RE = re.compile(r"\s+import\b")
# Other places a bare dotted token names code or configuration rather than a host: the module run by
# `python -m`, the key of a config command, and the text of an inline program (`python -c`, `node -e`,
# …), where only URLs and whole quoted string literals can name a host.
_PY_MODULE_RE = re.compile(r"\bpython[\d.]*\s+(?:-[A-Za-z]+\s+)*?-m\s*([\w.]+)")
# Config commands are found by head and walked token by token (see `_config_key_spans`); a regex with a
# repeated flag group backtracks exponentially on a run of flags with no key after it.
_CONFIG_HEAD_RE = re.compile(r"\b(openclaw|hermes|git)\b")
_CONFIG_VERBS = {
    "openclaw": frozenset({"set", "get", "unset"}),
    "hermes": frozenset({"set", "get", "unset", "edit", "show", "reset"}),
    "git": frozenset({"set", "get", "unset"}),
}
_CONFIG_VALUE_FLAGS = frozenset({"--file", "-f", "--blob", "-C", "-c"})
_CONFIG_KEY_TOKEN_RE = re.compile(r"[A-Za-z][\w.-]*")
_TOKEN_RE = re.compile(r"\S+")
# Search tools whose pattern argument is a regex, not a host (`grep -A 30 "tools.profile" ref.md`).
_SEARCH_HEAD_RE = re.compile(r"\b(?:git\s+grep|grep|egrep|fgrep|rg|ag|ack)\b")
_SEARCH_PATTERN_FLAGS = frozenset({"-e", "--regexp"})
_SEARCH_VALUE_FLAGS = frozenset(
    """-A -B -C -m -f -d -D -g -t -T -M -j --file --glob --iglob --type --type-not --max-count
    --context --before-context --after-context --max-depth --include --exclude --exclude-dir
    --ignore-dir""".split()
)
_SHELL_SEPARATORS = frozenset({"|", "||", "&&", ";", "&"})
#: The object a SQL statement defines, destroys or writes rows to (`DROP TABLE app.ledger`,
#: `DELETE FROM app.ledger`): a dotted name there is schema.table, not a host. Only the name
#: straight after the keywords; URLs, addresses and host arguments are read before this applies.
_SQL_OBJECT_RE = re.compile(
    r"\b(?:(?:DROP|ALTER|CREATE|TRUNCATE)\s+(?:TABLE|VIEW|INDEX|SCHEMA|DATABASE|COLLECTION)\s+"
    r"(?:IF\s+(?:NOT\s+)?EXISTS\s+)?|TRUNCATE\s+|DELETE\s+FROM\s+|INSERT\s+INTO\s+)"
    r"([\w.\"`]+)",
    re.IGNORECASE,
)
_INLINE_PROGRAM_RE = re.compile(
    r"\b(?:python[\d.]*\s+(?:-[A-Za-z]+\s+)*?-[A-Za-z]*c"
    r"|(?:node|nodejs|bun)\s+(?:-\S+\s+)*?(?:-e|--eval|-p|--print)"
    r"|(?:perl|ruby)\s+(?:-\S+\s+)*?-[A-Za-z]*[eE]"
    r"|php\s+(?:-\S+\s+)*?-r"
    r"|deno\s+eval)[\s=]+"
)
# Host-taking arguments: a host given to curl or wget without a scheme (`curl host.example/path`,
# `wget host:8080/x`), `--host`/`--hostname`, and a `Host:` header. These are hosts whatever their
# suffix, so the file-extension filter does not apply.
_HOST_ARG_RE = re.compile(
    r"(?:--host(?:name)?[=\s]+|\bHost:\s*)['\"]?((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![\w-])",
    re.IGNORECASE,
)
_FETCH_ARGS_RE = re.compile(r"\b(?:curl|wget)\s+([^;&|\n]*)")
_SCHEMELESS_URL_RE = re.compile(
    r"\A['\"]?(?:[\w.-]+@)?((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?::\d+)?/"
)
_WORD_RE = re.compile(r"\S*")
_PORT_RE = re.compile(r":\d{1,5}")
_FETCH_FILE_FLAGS = frozenset(
    """-o --output -O --output-document -T --upload-file -K --config -P --directory-prefix -i
    --input-file --cacert --capath --cert -E --key -b --cookie -c --cookie-jar -D --dump-header
    --netrc-file --trace --trace-ascii --stderr --ca-certificate --certificate --private-key
    --load-cookies --save-cookies""".split()
)
_IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?![\w.])")
_PATH_RE = re.compile(r"(?<![\w.:-])((?:~|\$HOME|\.{1,2})?/(?:[\w.@%+~-]+/)*[\w.@%+~-]+/?)")
# The process's own streams: redirecting to or reading from these moves no data to or from a file.
_STREAM_PATHS = frozenset({"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"})
_SSH_HOST_RE = re.compile(
    r"(?:ssh|scp|rsync|sftp)\s+(?:-\S+\s+)*(?:[\w.-]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)
_NC_HOST_RE = re.compile(
    r"\b(?:nc|ncat|netcat|telnet)\s+(?:-\w+\s+)*([A-Za-z0-9.-]+\.[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})"
)
_DEV_TCP_RE = re.compile(r"/dev/tcp/([A-Za-z0-9.-]+)/\d+")
# A channel target: `channel:<id>`, `user:<id>`, … The id may be a WhatsApp JID (`<digits>@g.us`).
_JID_SUFFIX = r"@(?:g\.us|s\.whatsapp\.net|broadcast|newsletter|lid)"
_CHANNEL_RE = re.compile(
    r"\b(channel|user|dm|group|thread):([A-Za-z0-9_-]{3,}(?:" + _JID_SUFFIX + r")?)(?![\w@-]|\.\w)"
)
_JID_RE = re.compile(r"(?<![\w.@+-])\d{5,}(?:-\d+)?" + _JID_SUFFIX + r"(?![\w@-]|\.\w)")
# In free text, `user:`, `dm:` and `group:` name a channel only with an id-shaped id: numeric, a JID, or
# at least eight characters with a digit. A bare word (`group:runtime`, an OpenClaw tool group) is not.
_WORD_PREFIXES = frozenset({"user", "dm", "group"})
_ID_TOKEN_RE = re.compile(r"(?=.*\d)[A-Za-z0-9][A-Za-z0-9_-]{7,}")
_NUMERIC_ID_RE = re.compile(r"-?\d{3,}")
# Chat platforms a message target may be prefixed with (`telegram:-100…`, `slack:C0…`, `discord:#x`).
_CHAT_PLATFORMS = frozenset(
    """telegram discord slack whatsapp signal matrix mattermost msteams teams googlechat imessage irc
    line zulip rocketchat wechat feishu dingtalk sms""".split()
)
# Platforms whose bare numeric target is a phone number, an address.
_PHONE_PLATFORMS = frozenset({"sms", "whatsapp", "signal", "imessage"})
_PLATFORM_TARGET_RE = re.compile(r"([A-Za-z][A-Za-z0-9_-]{1,20}):(.+)")
_E164_RE = re.compile(r"\+\d[\d\s().-]{5,}\d")
_MATRIX_ROOM_RE = re.compile(r"![\w-]+:[\w.-]+")
_CHANNEL_NAME_RE = re.compile(r"#[\w-]{2,}")
_HANDLE_RE = re.compile(r"(?<![\w.])@([A-Za-z0-9_]{2,32})\b")
_PHONE_RE = re.compile(r"(?<![\w-])(\+?\d[\d\s().-]{6,}\d)(?![\w-])")

_INSTALLERS = re.compile(
    r"(?:^|[\s;&|(])"
    r"(?P<eco>pip3?|pipx|uv(?:\s+pip)?|poetry|npm|npx|pnpm|yarn|bun|cargo|gem|go|brew|apt(?:-get)?|dnf|yum|apk|conda|"
    r"openclaw\s+(?:plugins|skills)|hermes\s+(?:plugins|skills))"
    r"\s+(?:install|add|i|run|get|exec|-S)\b(?P<rest>[^;&|\n]*)",
    re.IGNORECASE,
)
_ECOSYSTEM = {
    "pip": "pypi",
    "pip3": "pypi",
    "pipx": "pypi",
    "uv": "pypi",
    "uv pip": "pypi",
    "poetry": "pypi",
    "conda": "pypi",
    "npm": "npm",
    "npx": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bun": "npm",
    "cargo": "crates",
    "gem": "gem",
    "go": "go",
    "brew": "brew",
    "apt": "apt",
    "apt-get": "apt",
    "dnf": "rpm",
    "yum": "rpm",
    "apk": "apk",
}
_DOCKER_VERB_RE = re.compile(r"\bdocker\s+(?:run|pull|create)\b([^;&|\n]*)", re.IGNORECASE)
# docker flags that take no value; any other `-x`/`--x` flag without `=` consumes the next token.
_DOCKER_BARE_FLAGS = frozenset(
    {
        "-d",
        "--detach",
        "-i",
        "--interactive",
        "-t",
        "--tty",
        "-it",
        "-ti",
        "-dit",
        "--rm",
        "-q",
        "--quiet",
        "--privileged",
        "--init",
        "--no-healthcheck",
        "--read-only",
        "--sig-proxy",
        "-P",
        "--publish-all",
        "-a",
        "--all-tags",
        "--disable-content-trust",
        "--help",
    }
)
_DOCKER_IMAGE_RE = re.compile(r"\A[a-z0-9][\w./:-]*\Z", re.IGNORECASE)


def _docker_images(text: str) -> list[str]:
    """Image references of `docker run|pull|create …`, found by walking tokens (a regex with a nested
    optional group here backtracks exponentially on long flag runs)."""
    out: list[str] = []
    for m in _DOCKER_VERB_RE.finditer(text):
        tokens = m.group(1).split()
        skip = False
        for tok in tokens:
            if skip:
                skip = False
                continue
            if tok.startswith("-"):
                skip = "=" not in tok and tok not in _DOCKER_BARE_FLAGS
                continue
            if _DOCKER_IMAGE_RE.match(tok):
                out.append(tok)
            break
    return out


_GIT_RE = re.compile(r"\bgit\s+clone\s+(?:-\S+\s+)*(\S+)|\bgit\+(\S+)", re.IGNORECASE)

_EGRESS_MARKERS = re.compile(
    r"(?:\s|^)(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file|"
    r"-X\s*(?:POST|PUT|PATCH)|--request\s*(?:POST|PUT|PATCH)|--method\s*(?:POST|PUT))\b"
    r"|urlopen\(|requests\.(?:post|put|patch)\(|\.post\(|/dev/tcp/|\bnc\b|\bncat\b|\bscp\b|\brsync\b|\bsftp\b|\bssh\b"
    # a mailer where a command starts, by name or path; not a directory named `mail` in a path
    r"|(?:\A|[;&|({\"'`]|\$\(|(?:\b(?:sudo|doas|env|nohup|exec|command|time|xargs)|-exec(?:dir)?|-c)\s)\s*"
    r"(?:[\w.~-]*/)*(?:mail|sendmail)(?=[\s;&|)\"'`]|\Z)",
    re.IGNORECASE,
)
_PIPE_TO_INTERPRETER = re.compile(
    r"\|\s*(?:sudo\s+)?(?:ba|z|k|c|da|fi)?sh\b|\|\s*(?:python[23]?|node|perl|ruby|deno|bun)\b|source\s+<\(|\beval\s+",
    re.IGNORECASE,
)
_PIPE_STAGE_HEAD = re.compile(r"(?:ba|z|k|c|da|fi)?sh|python[23]?|node|perl|ruby|deno|bun")
_READING_HEADS = re.compile(
    r"(?:^|[\s;&|(])(?:cat|head|tail|tac|less|more|strings|xxd|od|base64|gpg|openssl|jq|yq|grep|rg|awk|sed|cut|sort|uniq|wc|tar|zip|gzip|cp|scp|rsync)\s+([^;&|\n]*)",
    re.IGNORECASE,
)
_EXECUTABLE_HEADS = re.compile(
    r"(?:^|[\s;&|(])(?:bash|sh|zsh|source|\.|python[23]?|node|deno|bun|perl|ruby|exec)\s+((?:~|\$HOME|\.{1,2})?/[\w./@%+~-]+)",
    re.IGNORECASE,
)
_DIRECT_EXEC_RE = re.compile(r"(?:^|[\s;&|(])((?:~|\$HOME|\.{1,2})?/[\w./@%+~-]+)(?=\s|$|[;&|)])")
#: Every separator occurrence, overlapping ones included (zero-width, so `&&&` yields two `&&`);
#: their ends never decrease, so one forward pass finds the last one before a position.
_DIRECT_EXEC_SEP_RE = re.compile(r"(?=(;|&&|\|))")
_WRITE_TARGET_RE = re.compile(
    r"(?:>>?|\btee\s+(?:-a\s+)?|-o\s+|--output\s+|\bmv\s+\S+\s+|\bcp\s+\S+\s+)\s*((?:~|\$HOME|\.{1,2})?/[\w./@%+~-]+)"
)
_DESTRUCTIVE_HEADS = re.compile(
    r"(?:^|[\s;&|(])(?:rm|shred|srm|unlink|rmdir|truncate|chmod|chown|mkdir|touch|mv|ln)\s+([^;&|\n]*)",
    re.IGNORECASE,
)
_AT_FILE_RE = re.compile(r"@((?:~|\$HOME|\.{1,2})?/[\w./@%+~-]+)")
_STDIN_FILE_RE = re.compile(r"<\s*((?:~|\$HOME|\.{1,2})?/[\w./@%+~-]+)")
_WRITEISH_TOOL = re.compile(
    r"(send|post|upload|put|create|update|publish|notify|pay|transfer|delete|remove|archive|apply|set|write|edit|move|forward|share|export|add|submit|book|order|reply|comment|invite|schedule)",
    re.IGNORECASE,
)
_RUNISH_TOOL = re.compile(r"(install|run|exec|execute|spawn|launch|deploy|start)", re.IGNORECASE)


def normalise_host(host: str) -> str:
    h = host.strip().strip(".").lower()
    if h.startswith("[") and "]" in h:
        return h[: h.index("]") + 1]
    if ":" in h and h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h


_REMOTE_PORT_RE = re.compile(r"[^:]*:(?:[0-9]*|\*)")


def normalise_remote_identity(identity: str) -> str:
    """A remote MCP server is `remote:<hostname>`: the lowercase hostname, without the port, the scheme or
    the brackets around an IPv6 literal (http and https on one host are one server). An identity or a
    provider grant pattern written with a port (`remote:x.test:8200`, `remote:[::1]:8200`) reads as that
    form. A pattern with no host written (`remote:*:8200`) is left as it is, so dropping its port never
    widens it to every server; any other identity is returned as it is."""
    if identity[:7].lower() != "remote:":
        return identity
    raw = identity.strip().lower()
    host = raw[7:]
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif _REMOTE_PORT_RE.fullmatch(host):
        host = host.rsplit(":", 1)[0]
    host = host.rstrip(".")
    return "remote:" + host if host.strip("*?[]") else raw


def host_of_url(url: str) -> str | None:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if not parts.hostname:
        return None
    return normalise_host(parts.hostname)


def normalise_path(
    path: str, *, home: str | None, workspace_root: str | None, cwd: str | None = None
) -> str:
    p = path.strip().rstrip("/") or "/"
    p = re.sub(r"[`'\"]", "", p)
    if home:
        if p == "~" or p.startswith("~/"):
            p = home.rstrip("/") + p[1:]
        p = p.replace("$HOME", home.rstrip("/"))
        if workspace_root and (workspace_root.startswith("~")):
            workspace_root = home.rstrip("/") + workspace_root[1:]
    if p.startswith("./") and cwd:
        p = cwd.rstrip("/") + p[1:]
    elif p.startswith("./") and workspace_root:
        p = workspace_root.rstrip("/") + p[1:]
    # collapse `a/./b` and `a/b/../c`
    parts: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            if not parts:
                parts.append("")
            continue
        if seg == ".." and len(parts) > 1:
            parts.pop()
            continue
        parts.append(seg)
    out = "/".join(parts)
    return out if out else "/"


def display_path(path: str, home: str | None) -> str:
    if home and path.startswith(home.rstrip("/") + "/"):
        return "~" + path[len(home.rstrip("/")) :]
    return path


def normalise_package(ecosystem: str, name: str) -> str | None:
    n = name.strip().strip("'\"")
    if not n or n.startswith("-") or n in ("install", "add", "run", "i", "exec", "get"):
        return None
    if n.startswith("http://") or n.startswith("https://") or n.startswith("git+"):
        return "git+" + re.sub(r"^(git\+)?https?://", "", n).rstrip("/").removesuffix(".git")
    if ecosystem in ("pypi",):
        n = fold_pypi_name(re.split(r"[=<>!~\[;]", n)[0])
    elif ecosystem == "npm":
        if n.startswith("@"):
            scope, _, rest = n[1:].partition("/")
            rest = rest.split("@", 1)[0]
            n = f"@{scope}/{rest}"
        else:
            n = n.split("@", 1)[0]
    else:
        n = n.split("@", 1)[0].split("==", 1)[0]
    return f"{ecosystem}:{n}" if n else None


_PROVIDER_VERSION_RE = re.compile(r"@[^@/:\s]+$")


def provider_name(identity: str) -> str:
    """A provider identity without its version: `npm:@acme/gmail-mcp@1.4.2` → `npm:@acme/gmail-mcp`.
    The scope's `@` is kept because a version never contains `/`."""
    identity = identity.strip().lower()
    name = _PROVIDER_VERSION_RE.sub("", identity)
    return name if name and not name.endswith(":") else identity


def provider_counterpart(identity: str) -> tuple[EntityKind, str] | None:
    """The entity a tool provider's identity is extracted as when a command or content names it: the
    host of a remote server (`remote:mcp.x.test` is the host `mcp.x.test`) or the package a local
    server runs (`npm:@acme/x-mcp@1.2.0` is the package `npm:@acme/x-mcp`). None for any other
    identity, and for a remote identity with no host written."""
    ident = normalise_remote_identity(identity.strip())
    if ident[:7].lower() == "remote:":
        host = ident[7:]
        return (EntityKind.HOST, host) if host and host.strip("*?[]") == host else None
    eco, sep, name = ident.partition(":")
    eco = eco.lower()
    if not sep or eco not in set(_ECOSYSTEM.values()):
        return None
    norm = normalise_package(eco, name)
    return (EntityKind.PACKAGE, norm) if norm else None


def normalise_recipient(value: str) -> str:
    v = value.strip().strip("<>\"'")
    if _EMAIL_RE.fullmatch(v):
        return v.lower()
    return v


# --------------------------------------------------------------------------- extraction


@dataclass(frozen=True)
class Found:
    kind: EntityKind
    value: str
    display: str
    role: Role | None = None
    #: For a host that is the mail domain of an email recipient: that recipient's normalised address.
    domain_of: str | None = None


def _is_code_reference(text: str, start: int, end: int) -> bool:
    if text[end : end + 1] in ("(", "["):
        return True
    line = text[text.rfind("\n", 0, start) + 1 : start]
    if _IMPORT_LIST_RE.search(line):
        return True
    return bool(_FROM_IMPORT_RE.search(line) and _IMPORT_AFTER_RE.match(text, end))


def _line_end(text: str, start: int) -> int:
    end = text.find("\n", start)
    return end if end >= 0 else len(text)


def _quoted_span(text: str, start: int) -> tuple[int, int]:
    """The extent of the shell word starting at `start`: inside its quotes when quoted (to the end of
    the line when the quote is not closed), else up to the next whitespace."""
    quote = text[start : start + 1]
    if quote == "'":
        close = text.find("'", start + 1)
        return start + 1, close if close >= 0 else _line_end(text, start)
    if quote == '"':
        i = start + 1
        while i < len(text):
            if text[i] == "\\":
                i += 2
                continue
            if text[i] == '"':
                return start + 1, i
            i += 1
        return start + 1, _line_end(text, start)
    return start, _WORD_RE.match(text, start).end()  # type: ignore[union-attr]


def _non_host_spans(text: str, *, inline_program: bool) -> tuple[list[range], list[range]]:
    """Spans where a bare dotted token is not a host: (always skipped, inline program text). In
    program text a token is kept only when it is a whole quoted string literal. The object a SQL
    statement defines, destroys or inserts into is always skipped."""
    skip = [range(*m.span(1)) for m in linear_search.option_run_finditer(_PY_MODULE_RE, text)]
    skip += _config_key_spans(text)
    skip += _search_pattern_spans(text)
    skip += [range(*m.span(1)) for m in _SQL_OBJECT_RE.finditer(text)]
    programs = [range(0, len(text))] if inline_program else []
    for m in linear_search.option_run_finditer(_INLINE_PROGRAM_RE, text):
        programs.append(range(*_quoted_span(text, m.end())))
    return skip, programs


def _config_key_spans(text: str) -> list[range]:
    """The key argument of `openclaw config set|get|unset <key>`, `hermes config [verb] <key>` and
    `git [-C dir] config [verb] <key>`, skipping flags (and the value of `--file`/`-f`/`--blob`)."""
    spans: list[range] = []
    words = _Words(text)
    for m in _CONFIG_HEAD_RE.finditer(text):
        head = m.group(1)
        toks = words.after(m.end(), 32)
        i = 0
        while head == "git" and i < len(toks) and toks[i][2] in ("-C", "-c"):
            i += 2
        if i >= len(toks) or toks[i][2] != "config":
            continue
        i += 1
        if i < len(toks) and toks[i][2] in _CONFIG_VERBS[head]:
            i += 1
        elif head == "openclaw":
            continue
        while i < len(toks) and toks[i][2].startswith("-"):
            i += 2 if toks[i][2] in _CONFIG_VALUE_FLAGS else 1
        if i < len(toks):
            start, end, _ = toks[i]
            key = _CONFIG_KEY_TOKEN_RE.match(text, start, end)
            if key:
                spans.append(range(start, key.end()))
    return spans


class _Words:
    """The whitespace-separated words of a text, found once. `after(pos, limit)` gives the first `limit`
    of the words `_TOKEN_RE.finditer(text, pos, _line_end(text, pos))` gives (a word `pos` is inside
    starts at `pos`), each as (start, end, a prefix of it): reading the words after each head with the
    regex reads the rest of a long word again at every head inside it (`hermes.hermes.…`). The prefix
    is the whole word up to `PREFIX` characters, longer than any word the walks compare a word with or
    test it starts with, so it answers those questions as the word would."""

    PREFIX = 64

    def __init__(self, text: str) -> None:
        self.text = text
        self.spans = [m.span() for m in _TOKEN_RE.finditer(text)]
        self.starts = [s for s, _ in self.spans]

    def after(self, pos: int, limit: int) -> list[tuple[int, int, str]]:
        text = self.text
        out: list[tuple[int, int, str]] = []
        i = bisect.bisect_right(self.starts, pos) - 1
        if i >= 0 and self.spans[i][1] > pos:
            out.append(
                (pos, self.spans[i][1], text[pos : min(self.spans[i][1], pos + self.PREFIX)])
            )
            prev = self.spans[i][1]
        else:
            prev = pos
        i += 1
        while len(out) < limit and i < len(self.spans):
            start, end = self.spans[i]
            if text.find("\n", prev, start) >= 0:
                break
            out.append((start, end, text[start : min(end, start + self.PREFIX)]))
            prev = end
            i += 1
        return out[:limit]


def _search_pattern_spans(text: str) -> list[range]:
    """The pattern argument of grep-like tools: each `-e`/`--regexp` value, or else the first
    positional. Later positionals are files and are left alone."""
    spans: list[range] = []
    words = _Words(text)
    for m in _SEARCH_HEAD_RE.finditer(text):
        explicit = False
        take: str | None = None  # "pattern" or "value": what the previous flag consumes
        for start, end, word in words.after(m.end(), 32):
            if word in _SHELL_SEPARATORS:
                break
            if take is not None:
                if take == "pattern":
                    spans.append(range(start, end))
                take = None
                continue
            if word in _SEARCH_PATTERN_FLAGS:
                take, explicit = "pattern", True
            elif word.startswith("--regexp="):
                spans.append(range(start + len("--regexp="), end))
                explicit = True
            elif word in _SEARCH_VALUE_FLAGS:
                take = "value"
            elif word.startswith("-") and word != "-":
                continue
            else:
                if not explicit:
                    spans.append(range(start, end))
                break
    return spans


def _is_quoted_literal(text: str, start: int, end: int) -> bool:
    """A whole quoted string literal, optionally with a port (`'host.example:443'`)."""
    port = _PORT_RE.match(text, end)
    if port:
        end = port.end()
    return text[start - 1 : start] in ("'", '"') and text[end : end + 1] in ("'", '"', "\\")


def _host_arg_hosts(text: str) -> list[str]:
    """Hosts in host-taking arguments: `--host`, `Host:`, and curl or wget targets without a
    scheme (skipping the files their flags name)."""
    hosts = [normalise_host(m.group(1)) for m in _HOST_ARG_RE.finditer(text)]
    for m in _FETCH_ARGS_RE.finditer(text):
        prev = ""
        for tok in m.group(1).split():
            file_flag = prev in _FETCH_FILE_FLAGS or re.fullmatch(r"-[A-Za-z]*o", prev)
            prev = tok
            if file_flag:
                continue
            u = _SCHEMELESS_URL_RE.match(tok)
            if u:
                hosts.append(normalise_host(u.group(1)))
    return hosts


def _hosts_in(text: str, *, inline_program: bool = False, emails: bool = True) -> list[str]:
    """Hosts named in `text`: URLs, emails, host-taking arguments, IPv4 addresses, and bare dotted
    tokens outside code and config-key positions. With `inline_program` the whole text is program
    source (a Hermes `execute_code` body). Without `emails`, the domains of email addresses are left
    to the caller."""
    hosts: list[str] = []
    for m in _URL_RE.finditer(text):
        h = host_of_url(m.group(0))
        if h:
            hosts.append(h)
    for m in _EMAIL_RE.finditer(text) if emails else ():
        hosts.append(normalise_host(m.group(1).split("@", 1)[1]))
    for rx in (_SSH_HOST_RE, _NC_HOST_RE, _DEV_TCP_RE):
        for m in linear_search.option_run_finditer(rx, text):
            hosts.append(normalise_host(m.group(1)))
    for m in _IPV4_RE.finditer(text):
        hosts.append(m.group(1))
    hosts.extend(_host_arg_hosts(text))

    def _blank(m: re.Match[str]) -> str:  # keeps offsets, so the spans below line up
        return " " * len(m.group(0))

    stripped = _URL_RE.sub(_blank, _EMAIL_RE.sub(_blank, text))
    skip, programs = _non_host_spans(stripped, inline_program=inline_program)
    for m in _HOST_RE.finditer(stripped):
        cand = m.group(1)
        start, end = m.span(1)
        tld = cand.rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXTENSIONS or cand.lower() in ("e.g", "i.e", "etc.etc"):
            continue
        if cand[0].isdigit() and cand.replace(".", "").isdigit():
            continue
        if _is_code_reference(stripped, start, end):
            continue
        if any(start < r.stop and end > r.start for r in skip):
            continue
        if any(start in r for r in programs) and not _is_quoted_literal(stripped, start, end):
            continue
        hosts.append(normalise_host(cand))
    return list(dict.fromkeys(hosts))


def paths_in(
    text: str, home: str | None, workspace_root: str | None, cwd: str | None
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    text = _URL_RE.sub(" ", text)  # URL paths are not filesystem paths
    for m in _PATH_RE.finditer(text):
        raw = m.group(1).rstrip(".,:;)")
        if raw in ("/", "//") or raw.count("/") == 0:
            continue
        # drop URL path fragments (preceded by a hostname) and version-like `1/2`
        start = m.start(1)
        before = text[max(0, start - 1) : start]
        if before and before not in (" ", "\t", "\n", "'", '"', "=", "(", "@", "<", ">", ",", ":"):
            continue
        if re.fullmatch(r"/\d+", raw):
            continue
        norm = normalise_path(raw, home=home, workspace_root=workspace_root, cwd=cwd)
        if norm in _STREAM_PATHS or norm.startswith("/dev/fd/"):
            continue
        out.append((norm, display_path(norm, home)))
    return list(dict.fromkeys(out))


def substitution_spans(command: str) -> list[tuple[int, int]]:
    """Spans of `$(…)` and backtick substitutions, outermost only. Parentheses inside quotes do
    not count; an unclosed substitution ends the scan."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(command)
    while i < n:
        if command.startswith("$(", i):
            depth, j, quote = 0, i + 1, None
            while j < n:
                c = command[j]
                if quote:
                    if c == "\\" and quote == '"':
                        j += 1
                    elif c == quote:
                        quote = None
                elif c in ("'", '"'):
                    quote = c
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= n:
                break
            spans.append((i, j + 1))
            i = j + 1
        elif command[i] == "`":
            j = command.find("`", i + 1)
            if j < 0:
                break
            spans.append((i, j + 1))
            i = j + 1
        else:
            i += 1
    return spans


#: The package name of an install operand the shell computes when the command runs (`$(…)` or
#: backticks). What it prints cannot be read off the command, so the operand is one package nobody can
#: name, and the words inside the substitution are another command's, never package names.
COMPUTED_PACKAGE = "$(...)"
_COMPUTED = "\x00computed\x00"


def is_computed_package(value: str) -> bool:
    """`value` is the entity of an install operand computed at run time (`npm:$(...)`)."""
    return value == COMPUTED_PACKAGE or value.endswith(":" + COMPUTED_PACKAGE)


def _install_operands(text: str, start: int, spans: list[tuple[int, int]]) -> str:
    """An installer's operands: the text from `start` to the end of its simple command, with each
    command substitution among them replaced by one marker word. A separator inside a substitution
    belongs to the substituted command and does not end the installer's."""
    ends = {a: b for a, b in spans if a >= start}
    out: list[str] = []
    i = start
    while i < len(text):
        if i in ends:
            out.append(_COMPUTED)
            i = ends[i]
        elif text[i] in ";&|\n":
            break
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _strip_extras(tok: str) -> str:
    """`tok` without package extras after a local operand (`.[dev]`, `./pkg[test,docs]`): from the first
    `[` after the last `]` before the closing one. One pass, however many brackets the token holds."""
    if not tok.endswith("]"):
        return tok
    start = tok.find("[", tok.rfind("]", 0, len(tok) - 1) + 1, len(tok) - 1)
    return tok[:start] if start >= 0 else tok


#: Installer options whose value is a package index or registry, by installer: where the packages come
#: from, so a code source, never a package.
_PIP_INDEX_FLAGS = frozenset({"-i", "--index-url", "--extra-index-url", "-f", "--find-links"})
_INDEX_FLAGS = {
    **dict.fromkeys(("pip", "pip3", "pipx", "uv pip"), _PIP_INDEX_FLAGS),
    **dict.fromkeys(("npm", "pnpm", "yarn", "bun"), frozenset({"--registry"})),
}


#: A shell redirection among a command's words: an optional fd number (or `&`), the operator (`>`, `>>`,
#: `>|`, `<`, `<<`, `<<<`, `>&`, `<&`, `<>`), and the target when it is glued on (`2>&1`, `>/dev/null`).
_REDIRECTION = re.compile(r"(?:\d+|&)?(?:>>|>\||>&|>|<<<|<<-?|<&|<>|<)(.*)")


def _local_install_operand(token: str, eco: str = "") -> str | None:
    """The path an installer operand names when it is on disk rather than in a registry: `.`, `..`, or a
    path starting `./`, `../`, `/`, `~/` or `$HOME/`, without quotes, package extras (`.[dev]`) or, for
    Go, its `/...` package pattern. None for any other operand (a name, a version spec, a URL)."""
    tok = token.strip().strip("'\"")
    tok = _strip_extras(tok)
    if eco == "go" and tok.endswith("/..."):
        tok = tok[:-4] or "."
    if tok in (".", "..", "~", "$HOME") or tok.startswith(("./", "../", "/", "~/", "$HOME/")):
        return tok
    return None


def _packages_in(text: str) -> list[str]:
    return _installs_in(text)[0]


def _installs_in(text: str) -> tuple[list[str], list[str], list[str]]:
    """The packages installer commands in `text` name, their operands that are local paths (as written,
    see `_local_install_operand`), and the index or registry URLs their options name (`--index-url URL`,
    `--registry=URL`). A local path installs what is on disk and an index serves packages: neither is a
    package."""
    pkgs: list[str] = []
    local: list[str] = []
    indexes: list[str] = []
    spans = substitution_spans(text) if ("$(" in text or "`" in text) else []
    for m in _INSTALLERS.finditer(text):
        eco_key = re.sub(r"\s+", " ", m.group("eco").lower())
        if eco_key.startswith(("openclaw", "hermes")):
            eco = "plugin"
        else:
            eco = _ECOSYSTEM.get(eco_key, eco_key)
        rest = _install_operands(text, m.start("rest"), spans) if spans else m.group("rest")
        tokens = rest.split()
        index_flags = _INDEX_FLAGS.get(eco_key, frozenset())
        skip_next = index_next = False
        for tok in tokens:
            redirect = _REDIRECTION.fullmatch(tok)
            if redirect:
                # not an operand, nor is the target that follows a bare operator
                skip_next = not redirect.group(1)
                index_next = False
                continue
            if index_next:
                indexes.append(tok.strip("'\""))
                index_next = False
                continue
            if skip_next:
                skip_next = False
                continue
            if _COMPUTED in tok:
                pkgs.append(COMPUTED_PACKAGE if eco == "plugin" else f"{eco}:{COMPUTED_PACKAGE}")
                continue
            if tok.startswith("-"):
                flag, eq, value = tok.partition("=")
                if flag in index_flags:
                    if eq:
                        indexes.append(value.strip("'\""))
                    else:
                        index_next = True
                    continue
                if tok in (
                    "-r",
                    "--requirement",
                    "-c",
                    "--constraint",
                    "-t",
                    "--target",
                    "-g",
                    "--prefix",
                    "-e",
                    "--editable",
                ):
                    skip_next = tok not in ("-g", "-e", "--editable")
                continue
            if tok in ("install", "add", "i", "run", "get", "exec", "-S"):
                continue
            if eco == "plugin":
                pkgs.append(tok.strip("'\""))
                continue
            path = _local_install_operand(tok, eco)
            if path is not None:
                local.append(path)
                continue
            p = normalise_package(eco, tok)
            if p:
                pkgs.append(p)
    for image in _docker_images(text):
        pkgs.append("docker:" + image)
    for m in _GIT_RE.finditer(text):
        url = m.group(1) or m.group(2)
        if url:
            pkgs.append(
                "git+"
                + re.sub(r"^(git\+)?(https?://|git@)", "", url)
                .replace(":", "/", 1)
                .rstrip("/")
                .removesuffix(".git")
            )
    return list(dict.fromkeys(pkgs)), list(dict.fromkeys(local)), list(dict.fromkeys(indexes))


def _is_address(value: str, platform: str | None) -> bool:
    """An email, a phone number or an `@handle`: a recipient, not a channel. A WhatsApp JID is
    shaped like an email but is a chat id."""
    if _JID_RE.fullmatch(value):
        return False
    if value.startswith("@") or _EMAIL_RE.fullmatch(value) or _E164_RE.fullmatch(value):
        return True
    if value.isdigit():
        return platform in _PHONE_PLATFORMS
    return bool(_PHONE_RE.fullmatch(value))


def _is_channel_target(value: str, *, chat: bool, platform: str | None) -> bool:
    """A message target that names a channel. Any tool's prefixed target or JID counts; a chat send's
    target also counts when it is platform-prefixed (`telegram:-100…`, `discord:#bot-home`), a `#name`,
    a Matrix room or id-shaped (a numeric chat id, or at least eight characters with a digit, such as a
    Slack id) and not an address."""
    if _CHANNEL_RE.fullmatch(value) or _JID_RE.fullmatch(value):
        return True
    if not chat:
        return False
    m = _PLATFORM_TARGET_RE.fullmatch(value)
    if m and m.group(1).lower() in _CHAT_PLATFORMS:
        return not _is_address(m.group(2).strip(), m.group(1).lower())
    if _CHANNEL_NAME_RE.fullmatch(value) or _MATRIX_ROOM_RE.fullmatch(value):
        return True
    if _is_address(value, platform):
        return False
    return bool(_NUMERIC_ID_RE.fullmatch(value) or _ID_TOKEN_RE.fullmatch(value))


def channel_names(value: str) -> set[str]:
    """The shorter names an owner may use for a channel target, lower-cased: `ops-yard` and `#ops-yard`
    for `channel:ops-yard`; for a platform-prefixed target, the part after the platform when it is a
    `#name` or id-shaped (`#bot-home` for `discord:#bot-home`, not `general` for `slack:general`). A
    Matrix room has none (the part after its `:` is the homeserver)."""
    m = _CHANNEL_RE.fullmatch(value)
    if m:
        name = m.group(2).lower()
        return {name, "#" + name}
    m = _PLATFORM_TARGET_RE.fullmatch(value)
    if m and m.group(1).lower() in _CHAT_PLATFORMS:
        rest = m.group(2).strip()
        if (
            _CHANNEL_NAME_RE.fullmatch(rest)
            or _NUMERIC_ID_RE.fullmatch(rest)
            or _ID_TOKEN_RE.fullmatch(rest)
        ):
            return {rest.lower()}
    return set()


def _chat_send(call: CanonicalCall) -> tuple[bool, str | None]:
    """Whether a message send goes to a chat (not mail), and its platform when the call names one."""
    platform = call.get("channel")
    platform = platform.strip().lower() if isinstance(platform, str) else None
    mail = platform in ("email", "mail", "smtp") or "mail" in call.tool.lower()
    return not mail, platform


def send_platform(call: CanonicalCall) -> str | None:
    """The chat platform a message send names in its own argument (`discord` for OpenClaw's
    `{channel: discord, target: "#x"}`), lower-cased; None for any other call."""
    if call.tool_kind is not ToolKind.MESSAGE_SEND:
        return None
    return _chat_send(call)[1] or None


#: A direct-message target, in any letter case and with an id of any length.
_PERSON_PREFIX = re.compile(r"(?i)\s*(?:user|dm):")


def platform_targets(call: CanonicalCall) -> set[tuple[EntityKind, str]]:
    """The targets of a message send that a pattern naming the send's platform may cover: its channels and
    chat names, as (kind, value). Never a direct message (`user:`, `dm:`), an address (an email, a phone
    number, an `@handle`) or a target that names a platform of its own."""
    if call.tool_kind is not ToolKind.MESSAGE_SEND:
        return set()
    chat, platform = _chat_send(call)
    if not chat or not platform:
        return set()
    out: set[tuple[EntityKind, str]] = set()
    for f in _recipients_in(call.recipients, chat=chat, platform=platform):
        named = _PLATFORM_TARGET_RE.fullmatch(f.value)
        if _PERSON_PREFIX.match(f.value) or (named and named.group(1).lower() in _CHAT_PLATFORMS):
            continue
        if f.kind is EntityKind.CHANNEL or (
            f.kind is EntityKind.RECIPIENT
            and "@" not in f.value
            and not _is_address(f.display, platform)
        ):
            out.add((f.kind, f.value))
    return out


def _recipients_in(
    values: list[str], *, chat: bool = False, platform: str | None = None
) -> list[Found]:
    out: list[Found] = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        if _is_channel_target(v, chat=chat, platform=platform):
            out.append(Found(EntityKind.CHANNEL, v, v, Role.RECIPIENT))
            continue
        if _EMAIL_RE.fullmatch(v):
            norm = normalise_recipient(v)
            domain = normalise_host(norm.split("@", 1)[1])
            out.append(Found(EntityKind.RECIPIENT, norm, norm, Role.RECIPIENT))
            out.append(
                Found(EntityKind.HOST, domain, domain, Role.DATA_DESTINATION, domain_of=norm)
            )
            continue
        out.append(Found(EntityKind.RECIPIENT, normalise_recipient(v), v, Role.RECIPIENT))
    return out


def extract_mentions(
    text: str,
    *,
    home: str | None,
    workspace_root: str | None,
    role: Role | None = Role.MENTIONED,
    inline_program: bool = False,
) -> list[Found]:
    """Entities named in free text (request, inputs, content): hosts, emails, paths, packages,
    channels. `inline_program` marks the text as program source (see `_hosts_in`). A JID is blanked before
    the other kinds are read, so it is not also a mailbox and a host."""
    channels = _channels_in(text)
    for start, end, value in channels:
        if "@" in value:
            text = text[:start] + " " * (end - start) + text[end:]
    found: list[Found] = []
    for h in _hosts_in(text, inline_program=inline_program, emails=False):
        found.append(Found(EntityKind.HOST, h, h, role))
    for m in _EMAIL_RE.finditer(text):
        norm = normalise_recipient(m.group(1))
        domain = normalise_host(m.group(1).split("@", 1)[1])
        found.append(Found(EntityKind.RECIPIENT, norm, norm, role))
        found.append(Found(EntityKind.HOST, domain, domain, role, domain_of=norm))
    for norm, disp in paths_in(text, home, workspace_root, None):
        found.append(Found(EntityKind.PATH, norm, disp, role))
    for p in _packages_in(text):
        found.append(Found(EntityKind.PACKAGE, p, p, role))
    for _, _, value in channels:
        found.append(Found(EntityKind.CHANNEL, value, value, role))
    return found


def _channels_in(text: str) -> list[tuple[int, int, str]]:
    """Channel tokens in free text, as (start, end, value) in text order."""
    out: list[tuple[int, int, str]] = []
    for m in _CHANNEL_RE.finditer(text):
        ident = m.group(2)
        if m.group(1) in _WORD_PREFIXES and not (
            _NUMERIC_ID_RE.fullmatch(ident) or "@" in ident or _ID_TOKEN_RE.fullmatch(ident)
        ):
            continue
        out.append((m.start(), m.end(), m.group(0)))
    taken = [(s, e) for s, e, _ in out]
    for m in _JID_RE.finditer(text):
        if not any(s <= m.start() < e for s, e in taken):
            out.append((m.start(), m.end(), m.group(0)))
    return sorted(out)


# --------------------------------------------------------------------------- shell segments

_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||[;|\n]")
_ENV_ASSIGN_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPER_HEADS = frozenset({"sudo", "doas", "nohup", "time", "env", "exec", "command"})


def shell_segments(command: str) -> list[list[str]]:
    """The simple commands of a shell string as token lists, wrappers (`sudo`, `env`, …) and leading
    variable assignments dropped. Quoting is honoured within a segment where it parses; this is a
    light split for lineage questions, not the AIRA shell parser."""
    return [tokens for _, tokens in shell_segments_sep(command)]


def shell_segments_sep(command: str) -> list[tuple[str, list[str]]]:
    """`shell_segments`, each with the separator before it (`|`, `&&`, `||`, `;`, a newline, or `""`
    for the first)."""
    return [(sep, list(tokens)) for sep, tokens in _segments_of(command or "")]


def _drop_wrappers(tokens: list[str]) -> list[str]:
    """The tokens after any leading wrappers (`sudo`, `env`, …) and variable assignments (counted, then
    cut once: dropping them one copy at a time is quadratic in a long run of them)."""
    i = 0
    while i < len(tokens) and (tokens[i] in _WRAPPER_HEADS or _ENV_ASSIGN_RE.match(tokens[i])):
        i += 1
    return tokens[i:]


@lru_cache(maxsize=64)
def _segments_of(command: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """`shell_segments_sep` for one command, parsed once: preparation and every probe split the same
    commands many times over."""
    import shlex

    out: list[tuple[str, tuple[str, ...]]] = []
    parts = re.split("(" + _SEGMENT_SPLIT_RE.pattern + ")", command or "")
    sep = ""
    for i, seg in enumerate(parts):
        if i % 2:
            sep = seg
            continue
        seg = seg.strip().lstrip("(").rstrip(")").strip()
        if not seg or seg.startswith("#"):
            continue
        try:
            tokens = shlex.split(seg, comments=True)
        except ValueError:
            tokens = seg.split()
        tokens = _drop_wrappers(tokens)
        if tokens:
            out.append((sep, tuple(tokens)))
    return tuple(out)


def resolve_token(
    tok: str, cwd: str, *, home: str | None, workspace_root: str | None
) -> tuple[str, bool]:
    """Resolve a path argument against the running cwd; returns (normalised path, wildcard). A
    trailing glob (`dir/*`) or an embedded one resolves to the directory it ranges over."""
    tok = tok.strip().strip("'\"")
    wildcard = False
    if tok.endswith(("/*", "/**")):
        tok = tok.rsplit("/", 1)[0] or "/"
        wildcard = True
    elif "*" in tok or "?" in tok:
        tok = re.split(r"[*?]", tok, maxsplit=1)[0]
        tok = tok.rsplit("/", 1)[0] if "/" in tok else tok
        wildcard = True
        if not tok:
            tok = "."
    if not tok.startswith(("/", "~", "$HOME")):
        tok = cwd.rstrip("/") + "/" + tok.removeprefix("./") if tok not in (".", "./") else cwd
    return normalise_path(tok, home=home, workspace_root=workspace_root), wildcard


def is_under(path: str, root: str) -> bool:
    """`path` is `root` or inside it."""
    root = root.rstrip("/")
    return not root or path == root or path.startswith(root + "/")


def fed_paths(written: Iterable[str], used: Iterable[str]) -> list[str]:
    """The `used` paths that a call writing `written` decides: the same path, one inside a written
    directory or link, or a directory the write lands in (archiving or uploading a staging
    directory takes the file written into it). A sibling that writes what the pending call reads,
    runs, sends or writes through makes the two calls one action. The filesystem root decides
    nothing."""
    roots = [w for w in written if w.rstrip("/")]
    return [
        u for u in used if u.rstrip("/") and any(is_under(u, r) or is_under(r, u) for r in roots)
    ]


_FETCH_HEADS = frozenset({"curl", "wget"})
_RUN_HEADS = frozenset(
    "bash sh zsh dash ksh source . python python2 python3 node deno bun perl ruby exec".split()
)
_BUILD_RE = re.compile(
    r"(?:\A|\s)(?:\./configure|\./setup[\w.-]*|\./install[\w.-]*|make|cmake|python[23]?\s+setup\.py)(?:\s|\Z)"
)


def _fetch_outputs(tokens: list[str]) -> list[str]:
    """The files a `curl`/`wget` segment saves to: `-o FILE`, `--output FILE`, combined short flags
    ending in `o` (`-fsSLo FILE`), wget's `-O FILE` / `--output-document FILE`, and curl's `-O`
    (the URL's basename)."""
    head = tokens[0]
    out: list[str] = []
    urls = [t for t in tokens[1:] if _URL_RE.match(t)]
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok.startswith(("--output=", "--output-document=")):
            out.append(tok.split("=", 1)[1])
        elif tok in ("--output", "--output-document") and nxt:
            out.append(nxt)
            i += 1
        elif head == "wget" and tok == "-O" and nxt:
            out.append(nxt)
            i += 1
        elif head == "curl" and re.fullmatch(r"-[A-Za-z]*o", tok) and nxt:
            out.append(nxt)
            i += 1
        elif head == "curl" and (
            tok in ("--remote-name", "-O") or re.fullmatch(r"-[A-Za-z]*O", tok)
        ):
            for url in urls:
                base = urlsplit(url).path.rsplit("/", 1)[-1]
                if base:
                    out.append(base)
        i += 1
    return [o for o in out if o and o != "-"]


_WGET_OUTPUT_FLAG = re.compile(r"--output-document(?:=.*)?|-[A-Za-z]*O(?:.+)?")
_WGET_SHORT_O = re.compile(r"-[A-Za-z]*O(.*)")
#: A redirection of standard output to a file: `>f`, `> f`, `>>f`, `1>f`, `&>f`.
_STDOUT_REDIRECT = re.compile(r"(?:1|&)?>>?(.*)")


def _download_outputs(tokens: list[str]) -> list[str]:
    """`_fetch_outputs`, plus wget's combined short flags ending in `O` (`-qO FILE`, `-qOFILE`) and, when
    no output flag names a file, the one wget saves to: the URL's basename, under `-P DIR` /
    `--directory-prefix DIR` when given."""
    out = _fetch_outputs(tokens)
    if tokens[0] != "wget":
        return out
    for i, tok in enumerate(tokens[1:], 1):
        m = _WGET_SHORT_O.fullmatch(tok)
        if m and m.group(1) and m.group(1) != "-":
            out.append(m.group(1))
        elif m and tok != "-O" and not m.group(1) and i + 1 < len(tokens):
            out.append(tokens[i + 1])
    if any(_WGET_OUTPUT_FLAG.fullmatch(t) for t in tokens[1:]):
        return [o for o in out if o != "-"]
    prefix = ""
    for i, tok in enumerate(tokens[1:], 1):
        if tok in ("-P", "--directory-prefix") and i + 1 < len(tokens):
            prefix = tokens[i + 1].rstrip("/") + "/"
        elif tok.startswith("--directory-prefix="):
            prefix = tok.split("=", 1)[1].rstrip("/") + "/"
    for url in (t for t in tokens[1:] if _URL_RE.match(t)):
        base = urlsplit(url).path.rsplit("/", 1)[-1]
        if base:
            out.append(prefix + base)
    return out


def _stdout_files(tokens: list[str]) -> list[str]:
    """The files a segment's standard output is redirected to, and a `tee`'s file operands."""
    out: list[str] = []
    for i, tok in enumerate(tokens):
        m = _STDOUT_REDIRECT.fullmatch(tok)
        if m and m.group(1):
            out.append(m.group(1))
        elif m and i + 1 < len(tokens):
            out.append(tokens[i + 1])
    if tokens[0] == "tee":
        out.extend(t for t in tokens[1:] if not t.startswith(("-", ">")) and t not in out)
    return [o for o in out if o not in ("-", "/dev/null") and not o.startswith("&")]


@dataclass
class InstallWalk:
    """What a command installs from disk and downloads, read segment by segment (`install_walk`)."""

    #: Local installer operands: (as written, resolved where that segment runs).
    local: list[tuple[str, str]] = field(default_factory=list)
    #: Local paths an installer installs from a download earlier in the command → the download's hosts.
    installed: dict[str, set[str]] = field(default_factory=dict)
    #: Every file the command downloads (`curl`, `wget`, or their output redirected or teed), as a
    #: normalised path, and where it is copied or moved to later in the command → the download's hosts.
    downloaded: dict[str, set[str]] = field(default_factory=dict)


def install_walk(
    command: str, *, home: str | None, workspace_root: str | None, cwd: str | None
) -> InstallWalk:
    """Read a command's segments in order, tracking `cd`: the local paths its installers install, the
    files its `curl` and `wget` segments save (with their output flags, a redirection or a `tee` later in
    the same pipeline), carried through a later `cp` or `mv`, and which installs take a download."""
    from .copies import _operands

    base = normalise_path(cwd or workspace_root or "/", home=home, workspace_root=workspace_root)
    walk = InstallWalk()

    def at(raw: str) -> str:
        return resolve_token(raw, base, home=home, workspace_root=workspace_root)[0]

    def save(path: str, hosts: set[str]) -> None:
        walk.downloaded.setdefault(path, set()).update(hosts)

    piped: set[str] = set()  # hosts a fetch earlier in this pipeline writes to standard output
    for sep, tokens in shell_segments_sep(command):
        piped = piped if sep == "|" else set()
        head = tokens[0]
        if head == "cd" and len(tokens) > 1:
            base = at(tokens[1])
            continue
        if head in _FETCH_HEADS:
            piped = set(_hosts_in(" ".join(tokens)))
            for raw in _download_outputs(tokens):
                save(at(raw), piped)
        if piped:
            for raw in _stdout_files(tokens):
                save(at(raw), piped)
        if head in ("cp", "mv") and walk.downloaded:
            ops = _operands(tokens[1:])
            for src in ops[0] if ops else ():
                hosts = walk.downloaded.get(at(src))
                if hosts:
                    dest = at(ops[1])
                    save(dest, hosts)
                    save(dest.rstrip("/") + "/" + at(src).rsplit("/", 1)[-1], hosts)
            continue
        for raw in _installs_in(" ".join(tokens))[1]:
            path = at(raw)
            walk.local.append((raw, path))
            if path in walk.downloaded:
                walk.installed.setdefault(path, set()).update(walk.downloaded[path])
    return walk


def fetched_then_run(
    command: str, *, home: str | None, workspace_root: str | None, cwd: str | None
) -> tuple[set[str], set[str]]:
    """Hosts that supply code and the files that are run when a command fetches to a file and later
    runs it: `curl -o f URL && chmod +x f && ./f`, `wget -O f URL; sh f`, or a `git clone URL`
    followed by a build or setup step. Returns (hosts, normalised executable paths)."""
    hosts: set[str] = set()
    executables: set[str] = set()
    base = cwd or workspace_root or "/"
    base = normalise_path(base, home=home, workspace_root=workspace_root)
    segments = shell_segments(command)
    fetched: list[tuple[int, str, list[str]]] = []  # (segment index, normalised file, hosts)
    for idx, tokens in enumerate(segments):
        if tokens[0] == "cd" and len(tokens) > 1:
            base, _ = resolve_token(tokens[1], base, home=home, workspace_root=workspace_root)
            continue
        if tokens[0] in _FETCH_HEADS:
            seg_hosts = _hosts_in(" ".join(tokens))
            for raw in _fetch_outputs(tokens):
                path, _ = resolve_token(raw, base, home=home, workspace_root=workspace_root)
                fetched.append((idx, path, seg_hosts))
            continue
        if not fetched:
            continue
        candidates: list[str] = []
        if tokens[0] == "chmod":
            args = [t for t in tokens[1:] if not re.fullmatch(r"-[A-Za-z]+", t)]
            if args and ("x" in args[0] or re.fullmatch(r"0?[0-7]*[1357][0-7]*", args[0])):
                candidates = args[1:]
        elif tokens[0] in _RUN_HEADS:
            candidates = [t for t in tokens[1:] if not t.startswith("-")][:1]
        else:
            candidates = [tokens[0]]
        for cand in candidates:
            if not cand or cand.startswith("-"):
                continue
            path, _ = resolve_token(cand, base, home=home, workspace_root=workspace_root)
            for f_idx, f_path, f_hosts in fetched:
                if f_idx < idx and f_path == path:
                    hosts.update(f_hosts)
                    executables.add(path)
    clones = [m for m in _GIT_RE.finditer(command) if m.group(1)]
    if clones and _BUILD_RE.search(command[clones[0].end() :]):
        for m in clones:
            h = host_of_url(m.group(1)) if "://" in m.group(1) else None
            if h is None and "@" in m.group(1) and ":" in m.group(1):
                h = normalise_host(m.group(1).split("@", 1)[1].split(":", 1)[0])
            if h:
                hosts.add(h)
    return hosts, executables


#: Publishing commands: head → (the verb word sequences that publish, the options that name the target).
#: The target is where the package goes, so its host is a data destination. Installing, viewing or
#: checking with the same option reads from the host and is left alone.
_PUBLISH_COMMANDS: dict[str, tuple[tuple[tuple[str, ...], ...], tuple[str, ...]]] = {
    "npm": ((("publish",),), ("--registry",)),
    "pnpm": ((("publish",),), ("--registry",)),
    "yarn": ((("publish",), ("npm", "publish")), ("--registry",)),
    "twine": ((("upload",),), ("--repository-url",)),
    "uv": ((("publish",),), ("--publish-url",)),
    "gem": ((("push",),), ("--host",)),
    "cargo": ((("publish",),), ("--index",)),
    "dotnet": ((("nuget", "push"),), ("--source", "-s")),
}
#: Environment variables that name the target instead of an option (matched without case).
_PUBLISH_ENV = {
    "npm": ("npm_config_registry",),
    "pnpm": ("npm_config_registry",),
    "yarn": ("npm_config_registry", "yarn_npm_registry_server"),
    "twine": ("twine_repository_url",),
    "uv": ("uv_publish_url",),
    "gem": ("rubygems_host",),
}
#: Commands that push an image or chart; the target is the registry the reference names.
_PUSH_COMMANDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "docker": (("push",), ("image", "push")),
    "podman": (("push",), ("image", "push")),
    "helm": (("push",),),
}
#: `docker build --push` and `docker buildx build --push` publish the image they tag.
_BUILD_PUSH_VERBS = (("buildx", "build"), ("build",), ("image", "build"))
#: Options whose value is a separate word (global ones before the verb, and push options), per head.
_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "npm": frozenset(
        {"-w", "--workspace", "--userconfig", "--tag", "--cache", "--prefix", "--otp", "--access"}
    ),
    "pnpm": frozenset({"-C", "--dir", "--filter", "-F", "--tag", "--otp", "--access"}),
    "yarn": frozenset({"--cwd", "--tag", "--otp", "--access"}),
    "twine": frozenset(
        {"-r", "--repository", "-u", "--username", "-p", "--password", "--config-file", "--cert"}
    ),
    "uv": frozenset({"--directory", "--project", "--index", "--username", "--password", "--token"}),
    "gem": frozenset({"-k", "--key", "--otp", "-p", "--http-proxy"}),
    "cargo": frozenset({"--registry", "--token", "-p", "--package", "--manifest-path", "--target"}),
    "dotnet": frozenset(
        {"-k", "--api-key", "-ss", "--symbol-source", "-sk", "--symbol-api-key", "-t", "--timeout"}
    ),
    "docker": frozenset(
        {
            "-H",
            "--host",
            "--context",
            "-c",
            "--config",
            "-l",
            "--log-level",
            "--platform",
            "-t",
            "--tag",
            "-f",
            "--file",
            "--build-arg",
            "--target",
            "--output",
            "-o",
            "--builder",
            "--cache-from",
            "--cache-to",
            "--label",
            "--secret",
            "--ssh",
            "--progress",
            "--iidfile",
            "--metadata-file",
        }
    ),
    "podman": frozenset(
        {
            "--connection",
            "-c",
            "--url",
            "--identity",
            "--authfile",
            "--cert-dir",
            "--creds",
            "--digestfile",
            "--format",
            "-f",
            "--sign-by",
            "--platform",
            "--compression-format",
        }
    ),
    "helm": frozenset(
        {
            "--kube-context",
            "-n",
            "--namespace",
            "--registry-config",
            "--ca-file",
            "--cert-file",
            "--key-file",
            "--username",
            "--password",
            "--repository-cache",
            "--repository-config",
        }
    ),
}
_PUBLISH_HINT = re.compile(r"\b(?:npm|pnpm|yarn|twine|uv|gem|cargo|dotnet|docker|podman|helm)\b")
_EXPORT_RE = re.compile(r"\bexport\s+([A-Za-z_]\w*)=(\S+)")
_PYTHON_HEAD_RE = re.compile(r"python(?:\d+(?:\.\d+)?)?")
#: A registry name: a dotted hostname, `localhost` or a bracketed IPv6 address, with an optional port.
_REGISTRY_RE = re.compile(
    r"(?:(?:[a-z0-9-]{1,63}\.)+[a-z][a-z0-9-]{1,23}|localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\])(?::\d{1,5})?",
    re.IGNORECASE,
)


def _target_host(value: str) -> str | None:
    """The host a publish target names: a URL (`sparse+https://…` too) or a bare `host[:port][/path]`;
    None for anything else (a repository name, a local feed directory)."""
    value = re.sub(r"^[a-z]+\+(?=[a-z]+://)", "", value.strip().strip("'\""))
    if "://" in value:
        return host_of_url(value)
    head = value.split("/", 1)[0].rsplit("@", 1)[-1]
    if not _REGISTRY_RE.fullmatch(head) or head.rsplit(".", 1)[-1].lower() in _FILE_EXTENSIONS:
        return None
    return normalise_host(head).strip("[]")


def _image_registry(ref: str) -> str | None:
    """The registry an image reference names (`reg.example.test:5000/team/app:1` → `reg.example.test`),
    or None when it names none (`app:1`, `someuser/app`: the default registry; a local transport such
    as `dir:` or `oci-archive:`). A `docker://` destination is read after its prefix."""
    if ref.startswith(("oci://", "docker://")):
        h = host_of_url(ref)
        return h.strip("[]") if h else None
    first, slash, _ = ref.partition("/")
    if not slash or not _REGISTRY_RE.fullmatch(first):
        return None
    return normalise_host(first).strip("[]")


def _unwrap_launcher(head: str, argv: list[str]) -> tuple[str, list[str]]:
    """The tool a launcher runs: `python3 [-I] -m twine …`, `npx [-y] npm@10 …`, `corepack pnpm …`,
    `uvx twine …`, `uv run twine …`, `pipx run twine …`."""
    for _ in range(3):
        if _PYTHON_HEAD_RE.fullmatch(head) and "-m" in argv:
            k = argv.index("-m")
            if k + 1 < len(argv) and all(a.startswith("-") for a in argv[:k]):
                head, argv = argv[k + 1], argv[k + 2 :]
                continue
        if head in ("npx", "uvx", "corepack") or (head in ("uv", "pipx") and argv[:1] == ["run"]):
            rest = argv[1:] if head in ("uv", "pipx") else argv
            rest = [a for a in itertools.dropwhile(lambda a: a.startswith("-"), rest)]
            if rest:
                head, argv = re.sub(r"(?<=.)@[^/]*$", "", rest[0]), rest[1:]
                continue
        break
    return head, argv


def publish_targets(command: str) -> set[str]:
    """Hosts the command publishes to: the target a publishing command names by option or
    environment variable (`npm publish --registry URL`, `TWINE_REPOSITORY_URL=URL twine upload`,
    an earlier `export` of one), or the registry of the image or chart it pushes (`docker push
    reg.example.test/app`, `docker buildx build --push -t reg.example.test/app .`, `helm push chart
    oci://reg.example.test/charts`). A publish that names no target goes to the public default, which
    names no host here, and a `--dry-run` sends nothing. The verb must lead the command's words, so
    `npm run publish` and an echoed command are not publishes. A command that does not parse names
    no publish target (its hosts keep the roles the text gives them)."""
    out: set[str] = set()
    if not _PUBLISH_HINT.search(command):
        return out
    shape = derive_exec_shape(command, load_lists().path_groups)
    # the shell parse keeps no `export` segment, so exports are read from the text
    exported = {m.group(1).lower(): m.group(2).strip("'\"") for m in _EXPORT_RE.finditer(command)}
    for seg in shape.segments:
        head, argv = _unwrap_launcher(seg.head, list(seg.argv))
        if head in _PUBLISH_COMMANDS:
            verbs, options = _PUBLISH_COMMANDS[head]
        elif head in _PUSH_COMMANDS:
            verbs, options = _PUSH_COMMANDS[head], ()
        else:
            continue
        valued = _VALUE_OPTIONS.get(head, frozenset())
        words: list[str] = []
        targets: list[str] = []
        flags: set[str] = set()
        i = 0
        while i < len(argv):
            tok = argv[i]
            name, eq, val = tok.partition("=")
            scoped = head in ("npm", "pnpm", "yarn") and re.fullmatch(r"--@[\w.-]+:registry", name)
            if (tok in options or (scoped and not eq)) and i + 1 < len(argv):
                targets.append(argv[i + 1])
                i += 2
                continue
            if eq and (name in options or scoped):
                targets.append(val)
            elif tok in valued and i + 1 < len(argv):
                if head == "docker" and tok in ("-t", "--tag"):
                    targets.append("image:" + argv[i + 1])
                i += 2
                continue
            elif tok.startswith("-"):
                flags.add(name)
            else:
                words.append(tok)
            i += 1
        if "--dry-run" in flags:
            continue
        verb = next((v for v in verbs if tuple(words[: len(v)]) == v), None)
        build_push = (
            head == "docker"
            and "--push" in flags
            and any(tuple(words[: len(v)]) == v for v in _BUILD_PUSH_VERBS)
        )
        if verb is None and not build_push:
            continue
        env = {
            **exported,
            **{a.partition("=")[0].lower(): a.partition("=")[2] for a in seg.env_assignments},
        }
        targets += [env[n] for n in _PUBLISH_ENV.get(head, ()) if n in env]
        hosts: list[str | None] = []
        for t in targets:
            if t.startswith("image:"):
                hosts.append(_image_registry(t[6:]) if build_push else None)
            else:
                hosts.append(_target_host(t))
        if verb is not None and head == "helm":
            hosts += [_image_registry(w) for w in words[len(verb) :] if w.startswith("oci://")]
        elif verb is not None and head in _PUSH_COMMANDS:
            hosts += [_image_registry(w) for w in words[len(verb) : len(verb) + 2]]
        out.update(h for h in hosts if h)
    return out


def pipes_into_code(command: str, *, inline_program: bool = False) -> bool:
    """Whether the command pipes something into a stage that runs it as code (`… | sh`,
    `… | python3`), or evaluates text (`source <(…)`, `eval …`).

    A pipe into a shell or interpreter that brings its own program (`… | python3 -m json.tool`)
    hands it data, not code: when every pipe the text shows is a stage of a parsed pipeline, the
    stages decide, by the same rule AIRA's code checks use. Anything the parse does not settle keeps
    the text answer: a pipe inside an argument or assignment (a quoted program, a decoded URL
    parameter), a command or process substitution (`tee >(sh)`), a heredoc, a command that does
    not parse, or an inline program."""
    matches = list(_PIPE_TO_INTERPRETER.finditer(command))
    if not matches:
        return False
    if inline_program or any(not m.group(0).startswith("|") for m in matches):
        return True
    lists = load_lists()
    shape = derive_exec_shape(command, lists.path_groups)
    if not shape.parse_ok or shape.substitution or "heredoc" in shape.sinks:
        return True
    if any(_PIPE_TO_INTERPRETER.search(t) for t in (shape.argv, *shape.env_assignments)):
        return True
    stages = [
        shape.segments[i]
        for p in shape.pipelines
        for i in p[1:]
        if i < len(shape.segments) and _PIPE_STAGE_HEAD.fullmatch(shape.segments[i].head)
    ]
    if len(stages) != len(matches):
        return True
    return any(stage_runs_stdin(s, lists) for s in stages)


def registry_hosts(call: CanonicalCall) -> list[str]:
    """Hosts the call points a package manager at: named on a registry line written into a
    package-manager config file (`.npmrc`, `pip.conf`, …), or in a command that sets the registry
    (`npm config set registry URL`). Later installs come from there, so each is a code source.
    A host the file or the command names anywhere else is not one."""
    lists = load_lists()
    kind = call.tool_kind
    if kind is ToolKind.EXEC:
        text = call.analysis_text or ""
        spans = [
            text[m.start() : _command_end(text, m.end())]
            for rx in lists.patterns("installers", "registry_cli_patterns")
            for m in linear_search.finditer(rx, text)
        ]
    elif kind is ToolKind.FILE_READ or not call.path:
        return []
    else:
        if not any(
            rx.search(call.path)
            for rx in lists.patterns("installers", "registry_config_path_patterns")
        ):
            return []
        edits = [e.get("new") or "" for e in call.get("edits") or [] if isinstance(e, dict)]
        text = "\n".join(e for e in edits if e) or str(call.get("content") or "")
        spans = [
            text[m.start() : _setting_end(text, m.start())]
            for rx in lists.patterns("installers", "registry_config_text_patterns")
            for m in rx.finditer(text)
        ]
    return list(dict.fromkeys(h for span in spans for h in _hosts_in(span, emails=False)))


def _setting_end(text: str, start: int) -> int:
    """The end of the registry setting that starts at `start`: its line, and for a section header
    (`[registries.x]`) or a list key (`channels:`) the lines under it, up to the next section
    header, the next key at the margin or a blank line."""
    end = _line_end(text, start)
    line = text[start:end].strip()
    if not (line.startswith("[") or line.endswith(":")):
        return end
    while end < len(text):
        nxt = _line_end(text, end + 1)
        body = text[end + 1 : nxt]
        if not body.strip() or body.lstrip().startswith("["):
            break
        if line.endswith(":") and not body.startswith((" ", "\t", "-")):
            break
        end = nxt
    return end


def _command_end(text: str, start: int) -> int:
    """The end of the simple command `start` lies in: the next separator or the end of the text."""
    m = _SEGMENT_SPLIT_RE.search(text, start)
    return m.start() if m else len(text)


def extract_exec(
    command: str,
    *,
    home: str | None,
    workspace_root: str | None,
    cwd: str | None,
    inline_program: bool = False,
) -> list[Found]:
    """Entities a shell command touches, with roles from the command's shape. A host the command
    fetches a file from and then runs that file (or clones and builds) is a code source, whatever
    else the command does. `inline_program` marks the command as program source (see `_hosts_in`)."""
    found: list[Found] = []
    egress = bool(_EGRESS_MARKERS.search(command))
    to_interpreter = pipes_into_code(command, inline_program=inline_program)
    code_hosts, run_files = fetched_then_run(
        command, home=home, workspace_root=workspace_root, cwd=cwd
    )
    published = set() if inline_program else publish_targets(command)

    named = _hosts_in(command, inline_program=inline_program)
    for h in named + sorted(published - set(named)):
        if h in ("localhost",):
            role = Role.DATA_SOURCE
        elif h in code_hosts:
            role = Role.CODE_SOURCE
        elif egress:
            role = Role.DATA_DESTINATION
        elif to_interpreter:
            role = Role.CODE_SOURCE
        else:
            role = Role.DATA_SOURCE
        if h in published and h != "localhost" and role is not Role.DATA_DESTINATION:
            # a publish target is a destination whatever else the command does with the host
            if role is not Role.CODE_SOURCE:
                role = Role.DATA_DESTINATION
            else:
                found.append(Found(EntityKind.HOST, h, h, Role.DATA_DESTINATION))
        found.append(Found(EntityKind.HOST, h, h, role))

    for m in _EMAIL_RE.finditer(command):
        norm = normalise_recipient(m.group(1))
        found.append(
            Found(EntityKind.RECIPIENT, norm, norm, Role.RECIPIENT if egress else Role.MENTIONED)
        )

    sources: set[str] = set()
    destinations: set[str] = set()
    executables: set[str] = set()
    for m in _AT_FILE_RE.finditer(command):
        sources.add(m.group(1))
    for m in _STDIN_FILE_RE.finditer(command):
        sources.add(m.group(1))
    for m in _READING_HEADS.finditer(command):
        for tok in m.group(1).split():
            if _PATH_RE.fullmatch(tok) or tok.startswith(("/", "~", "./", "../", "$HOME")):
                sources.add(tok.strip("'\""))
    for m in _EXECUTABLE_HEADS.finditer(command):
        executables.add(m.group(1))
    # A path that starts its simple command runs: the text between the last `;`, `&&`, `||` or `|`
    # before it and the path is blank. One forward pass keeps the last separator end in hand.
    seps = _DIRECT_EXEC_SEP_RE.finditer(command)
    sep_end, nxt = 0, next(seps, None)
    for m in _DIRECT_EXEC_RE.finditer(command):
        while nxt is not None and nxt.end(1) <= m.start():
            sep_end = nxt.end(1)
            nxt = next(seps, None)
        if command[sep_end : m.start(1)].strip() == "":
            executables.add(m.group(1))
    for m in _WRITE_TARGET_RE.finditer(command):
        destinations.add(m.group(1))
    for m in _DESTRUCTIVE_HEADS.finditer(command):
        for tok in m.group(1).split():
            if tok.startswith(("/", "~", "./", "../", "$HOME")):
                destinations.add(tok.strip("'\""))

    # An installer operand that is a local path installs, and so runs, what is there: a code source
    # resolved against the working directory (`.` is that directory), not a registry package.
    # An index or registry an installer option names serves the packages: a code source too.
    packages, _, indexes = _installs_in(command)
    local = install_walk(command, home=home, workspace_root=workspace_root, cwd=cwd).local
    installed = list(dict.fromkeys(path for _, path in local))
    # The same operands as the generic path scan spells them, which the installed paths replace.
    unresolved = {
        normalise_path(raw, home=home, workspace_root=workspace_root, cwd=cwd) for raw, _ in local
    }

    def normalised(raws: set[str]) -> set[str]:
        return {normalise_path(r, home=home, workspace_root=workspace_root, cwd=cwd) for r in raws}

    # Each raw spelling is normalised once, so a call with many paths stays linear.
    executable_paths = normalised(executables)
    destination_paths = normalised(destinations)
    matched_paths = normalised(sources) | destination_paths | executable_paths
    installed_set = set(installed)
    for norm, disp in paths_in(command, home, workspace_root, cwd):
        raw_matches = norm in matched_paths
        if (
            (norm in installed_set or norm in unresolved)
            and not raw_matches
            and norm not in run_files
        ):
            continue  # only installed: added below as a code source
        if norm in run_files or norm in executable_paths:
            role = Role.EXECUTABLE
        elif norm in destination_paths:
            role = Role.DATA_DESTINATION
        elif raw_matches or not egress:
            role = Role.DATA_SOURCE
        else:
            role = Role.DATA_SOURCE
        found.append(Found(EntityKind.PATH, norm, disp, role))
    for norm in installed:
        found.append(Found(EntityKind.PATH, norm, display_path(norm, home), Role.CODE_SOURCE))
    for url in indexes:
        h = host_of_url(url)
        if h:
            found.append(Found(EntityKind.HOST, h, h, Role.CODE_SOURCE))

    for p in packages:
        kind = (
            EntityKind.PLUGIN
            if (p.startswith("@") or (p.count("/") == 1 and ":" not in p))
            and not p.startswith(("npm:", "pypi:", "docker:", "git+"))
            else EntityKind.PACKAGE
        )
        found.append(Found(kind, p, p, Role.CODE_SOURCE))
    return _repo_code_sources(command, found)


# --------------------------------------------------------------------------- multi-tenant code hosts

#: `git@github.com:owner/repo.git`: a git remote in scp form (no scheme, a `:` before the path).
_SCP_REMOTE_RE = re.compile(
    r"\A(?:[\w.-]+@)?((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}):(?!//)(?!\d+(?:/|\Z))(\S+)\Z"
)
#: A token that may be a URL: what is left between shell quotes, separators and brackets.
_URL_TOKEN_RE = re.compile(r"[^\s\"'<>`|;&()\[\]{}]+")


class TenantRule(NamedTuple):
    #: The name repositories are written under (`github.com` for raw.githubusercontent.com).
    name: str
    #: Path segments that name a repository; 0 when no path does.
    segments: int
    #: Leading segments kept in front of them (`spaces` on huggingface.co).
    prefixes: frozenset[str]
    #: Leading segments dropped before them (`repos` on api.github.com).
    skip: frozenset[str]


def tenant_rules() -> dict[str, TenantRule]:
    """`installers.multi_tenant_hosts` by host."""
    out: dict[str, TenantRule] = {}
    for rule in load_lists().get("installers", "multi_tenant_hosts", default=[]) or []:
        if not isinstance(rule, dict) or not rule.get("host"):
            continue
        host = normalise_host(str(rule["host"]))
        out[host] = TenantRule(
            normalise_host(str(rule.get("as") or host)),
            int(rule.get("segments") or 0),
            frozenset(str(p).lower() for p in rule.get("prefixes") or ()),
            frozenset(str(p).lower() for p in rule.get("skip") or ()),
        )
    return out


def tenant_rule(host: str) -> TenantRule | None:
    """The rule for a multi-tenant host. Any other subdomain of a listed host (`cdn-lfs.huggingface.co`,
    `user-images.githubusercontent.com`) serves the same accounts' files with no repository in a form
    known here: it names none. None for any other host."""
    rules = tenant_rules()
    host = normalise_host(host)
    if host in rules:
        return rules[host]
    if any(host.endswith("." + listed) for listed in rules):
        return TenantRule(host, 0, frozenset(), frozenset())
    return None


def _remove_dot_segments(segs: list[str]) -> list[str]:
    """The path as a client sends it: `.` dropped, `..` removing the segment before it."""
    out: list[str] = []
    for seg in segs:
        if seg == ".":
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return out


def _tenant_split(url: str) -> tuple[str, str] | None:
    """(host, repository) for a URL, a schemeless URL or an scp-style git remote on a multi-tenant
    host; None for any other host."""
    url = url.strip().strip("'\"")
    m = None if "://" in url else _SCP_REMOTE_RE.match(url)
    if m:
        host, path = normalise_host(m.group(1)), m.group(2)
    else:
        try:
            parts = urlsplit(url if "://" in url else "https://" + url)
            hostname = parts.hostname
        except ValueError:
            return None
        if not hostname:
            return None
        host, path = normalise_host(hostname), parts.path
    rule = tenant_rule(host)
    if rule is None:
        return None
    if rule.segments <= 0:
        return host, host
    segs = _remove_dot_segments([s for s in path.split("/") if s])
    if segs and segs[0].lower() in rule.skip:
        segs = segs[1:]
    lead: list[str] = []
    if segs and segs[0].lower() in rule.prefixes:
        lead, segs = [segs[0]], segs[1:]
    if len(segs) < rule.segments:
        return host, rule.name
    named = [*lead, *segs[: rule.segments]]
    named[-1] = named[-1].removesuffix(".git")
    return host, "/".join([rule.name, *named]).lower()


def repo_of_url(url: str) -> str | None:
    """The repository a URL on a multi-tenant host (`installers.multi_tenant_hosts`) names:
    `github.com/<owner>/<repo>` for GitHub and its raw and archive hosts, `gist.github.com/<user>`,
    `huggingface.co/<org>/<name>` (and `huggingface.co/spaces/<org>/<name>`), in lower case. A path that
    names no repository gives the host's own name, and a host whose paths never do (a release-asset
    host) gives the host: neither is a repository a grant can cover. None for any other host."""
    split = _tenant_split(url)
    return split[1] if split else None


def repos_named_in(text: str) -> set[str]:
    """The repositories (`repo_of_url`) that URLs, schemeless URLs and scp-style git remotes in `text` name."""
    out: set[str] = set()
    for m in _URL_TOKEN_RE.finditer(text):
        # URLs run together with commas, markdown emphasis around them, a possessive after them
        for tok in m.group(0).split(","):
            tok = re.sub(r"[’'‘]s$", "", tok.strip("*_~’‘“”")).rstrip(".:;!?")
            if "." not in tok:
                continue
            split = _tenant_split(tok)
            if split is not None:
                out.add(split[1])
    return out


def _repo_code_sources(command: str, found: list[Found]) -> list[Found]:
    """A multi-tenant host the command takes code from supplies anyone's files: the code source is the
    repository each of its URLs in the command names, and the host is only read from. A fetch run by
    substitution (`sh -c "$(curl …)"`, `bash <(curl …)`) counts, as the installers list reads it."""
    hosts = {f.value for f in found if f.kind is EntityKind.HOST}
    tenant = {
        f.value
        for f in found
        if f.kind is EntityKind.HOST and f.role is Role.CODE_SOURCE and tenant_rule(f.value)
    }
    if any(tenant_rule(h) for h in hosts - tenant) and any(
        linear_search.found(p, command)
        for p in load_lists().patterns("installers", "fetch_to_shell_patterns")
    ):
        tenant |= {h for h in hosts if tenant_rule(h)}
    if not tenant:
        return found
    repos: dict[str, None] = {}
    seen: set[str] = set()
    for m in _URL_TOKEN_RE.finditer(command):
        split = _tenant_split(m.group(0))
        if split is not None and split[0] in tenant:
            seen.add(split[0])
            repos[split[1]] = None
    for host in sorted(tenant - seen):
        rule = tenant_rule(host)
        repos[host if rule is None or rule.segments <= 0 else rule.name] = None
    # A clone is already its repository as a `git+` package; the package stays its code source.
    packaged = {f.value for f in found if f.kind is EntityKind.PACKAGE}
    repos = {r: None for r in repos if "git+" + r not in packaged}
    out = [
        replace(f, role=Role.DATA_SOURCE)
        if f.kind is EntityKind.HOST and f.role is Role.CODE_SOURCE and f.value in tenant
        else f
        for f in found
    ]
    out.extend(Found(EntityKind.REPO, r, r, Role.CODE_SOURCE) for r in repos)
    return out


def extract_call(
    call: CanonicalCall, *, home: str | None, workspace_root: str | None
) -> list[Found]:
    """Entities of a canonical call with roles by tool kind. A host the call sets as a package
    registry is a code source as well as whatever else the call makes of it."""
    found = _extract_call(call, home=home, workspace_root=workspace_root)
    for h in registry_hosts(call):
        found.append(Found(EntityKind.HOST, h, h, Role.CODE_SOURCE))
    return found


def _extract_call(
    call: CanonicalCall, *, home: str | None, workspace_root: str | None
) -> list[Found]:
    found: list[Found] = []
    cwd = call.get("cwd")
    kind = call.tool_kind

    if kind is ToolKind.EXEC:
        cmd = call.command or ""
        inline = bool(call.get("interpreter"))
        found.extend(
            extract_exec(
                cmd, home=home, workspace_root=workspace_root, cwd=cwd, inline_program=inline
            )
        )
        decoded = call.analysis_text
        if decoded != call.text:
            found.extend(
                extract_exec(
                    decoded,
                    home=home,
                    workspace_root=workspace_root,
                    cwd=cwd,
                    inline_program=inline,
                )
            )
        if cwd:
            norm = normalise_path(cwd, home=home, workspace_root=workspace_root)
            found.append(Found(EntityKind.PATH, norm, display_path(norm, home), Role.MENTIONED))
        return found

    path = call.path
    if kind is ToolKind.FILE_READ:
        if path:
            norm = normalise_path(path, home=home, workspace_root=workspace_root)
            found.append(Found(EntityKind.PATH, norm, display_path(norm, home), Role.DATA_SOURCE))
    elif kind in (ToolKind.FILE_WRITE, ToolKind.FILE_EDIT, ToolKind.MEMORY_WRITE):
        if path:
            norm = normalise_path(path, home=home, workspace_root=workspace_root)
            found.append(
                Found(EntityKind.PATH, norm, display_path(norm, home), Role.DATA_DESTINATION)
            )
        found.extend(
            extract_mentions(call.get("content") or "", home=home, workspace_root=workspace_root)
        )
    elif kind is ToolKind.WEB_FETCH or kind is ToolKind.BROWSER:
        url = call.get("url")
        method = str(call.get("method") or "GET").upper()
        if url:
            h = host_of_url(url)
            if h:
                role = (
                    Role.DATA_DESTINATION
                    if (method in ("POST", "PUT", "PATCH") or call.get("body"))
                    else Role.DATA_SOURCE
                )
                found.append(Found(EntityKind.HOST, h, h, role))
            decoded = call.analysis_text
            if decoded != call.text:
                for f in extract_exec(decoded, home=home, workspace_root=workspace_root, cwd=None):
                    if f.kind is EntityKind.HOST and f.value == h:
                        continue
                    found.append(f)
        found.extend(
            extract_mentions(str(call.get("body") or ""), home=home, workspace_root=workspace_root)
        )
    elif kind is ToolKind.MESSAGE_SEND:
        chat, platform = _chat_send(call)
        found.extend(_recipients_in(call.recipients, chat=chat, platform=platform))
        for a in call.get("attachments") or []:
            norm = normalise_path(a, home=home, workspace_root=workspace_root)
            found.append(Found(EntityKind.PATH, norm, display_path(norm, home), Role.DATA_SOURCE))
        for f in extract_mentions(
            str(call.get("body") or "") + "\n" + str(call.get("subject") or ""),
            home=home,
            workspace_root=workspace_root,
        ):
            found.append(f)
    elif kind is ToolKind.SUBAGENT_SPAWN:
        found.extend(
            extract_mentions(str(call.get("task") or ""), home=home, workspace_root=workspace_root)
        )
    else:  # mcp, other
        writeish = bool(_WRITEISH_TOOL.search(call.tool))
        runish = bool(_RUNISH_TOOL.search(call.tool))
        url = call.get("url")
        if url:
            h = host_of_url(url) or normalise_host(url) if "." in url else None
            if h:
                found.append(
                    Found(
                        EntityKind.HOST,
                        h,
                        h,
                        Role.CODE_SOURCE
                        if runish
                        else (Role.DATA_DESTINATION if writeish else Role.DATA_SOURCE),
                    )
                )
        found.extend(_recipients_in(call.recipients))
        if path:
            norm = normalise_path(path, home=home, workspace_root=workspace_root)
            found.append(
                Found(
                    EntityKind.PATH,
                    norm,
                    display_path(norm, home),
                    Role.DATA_DESTINATION if writeish else Role.DATA_SOURCE,
                )
            )
        for a in call.get("attachments") or []:
            norm = normalise_path(a, home=home, workspace_root=workspace_root)
            found.append(Found(EntityKind.PATH, norm, display_path(norm, home), Role.DATA_SOURCE))
        for p in call.get("packages") or []:
            found.append(
                Found(EntityKind.PACKAGE if ":" in p else EntityKind.PLUGIN, p, p, Role.CODE_SOURCE)
            )
        found.extend(
            extract_mentions(
                str(call.get("content") or ""), home=home, workspace_root=workspace_root
            )
        )

    if call.provider.kind in (ProviderKind.MCP, ProviderKind.PLUGIN) and call.provider.identity:
        ekind = (
            EntityKind.PLUGIN
            if call.provider.kind is ProviderKind.PLUGIN
            else EntityKind.MCP_SERVER
        )
        identity = normalise_remote_identity(call.provider.identity)
        found.append(Found(ekind, identity, identity, Role.TOOL_PROVIDER))
    return found


def any_text(value: Any) -> str:
    from ..planir.canonical import joined_text

    if isinstance(value, dict):
        return joined_text(value)
    return str(value or "")
