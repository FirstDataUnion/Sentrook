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

import itertools
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

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


class Role(StrEnum):
    DATA_SOURCE = "data_source"
    DATA_DESTINATION = "data_destination"
    CODE_SOURCE = "code_source"
    EXECUTABLE = "executable"
    RECIPIENT = "recipient"
    TOOL_PROVIDER = "tool_provider"
    MENTIONED = "mentioned"  # appears in content or a task text without the call acting on it


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

    def add_origin(self, origin: Origin, ref: str | None = None) -> None:
        refs = self.origins.setdefault(origin, [])
        if ref is not None and ref not in refs:
            refs.append(ref)

    def has_origin(self, *origins: Origin) -> bool:
        return any(o in self.origins for o in origins)

    @property
    def sanctioned(self) -> bool:
        """Named by the owner's request or covered by a grant."""
        return self.has_origin(Origin.REQUEST, Origin.GRANT)


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
_EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![\w-])")
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
_CHANNEL_RE = re.compile(r"\b(channel|user|dm|group|thread):([A-Za-z0-9_-]{3,})")
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
    r"|urlopen\(|requests\.(?:post|put|patch)\(|\.post\(|/dev/tcp/|\bnc\b|\bncat\b|\bscp\b|\brsync\b|\bsftp\b|\bssh\b|\bmail\b|\bsendmail\b",
    re.IGNORECASE,
)
_PIPE_TO_INTERPRETER = re.compile(
    r"\|\s*(?:sudo\s+)?(?:ba|z|k|c|da|fi)?sh\b|\|\s*(?:python[23]?|node|perl|ruby|deno|bun)\b|source\s+<\(|\beval\s+",
    re.IGNORECASE,
)
_READING_HEADS = re.compile(
    r"(?:^|[\s;&|(])(?:cat|head|tail|tac|less|more|strings|xxd|od|base64|gpg|openssl|jq|yq|grep|rg|awk|sed|cut|sort|uniq|wc|tar|zip|gzip|cp|scp|rsync)\s+([^;&|\n]*)",
    re.IGNORECASE,
)
_EXECUTABLE_HEADS = re.compile(
    r"(?:^|[\s;&|(])(?:bash|sh|zsh|source|\.|python[23]?|node|deno|bun|perl|ruby|exec)\s+((?:~|\$HOME|\.{1,2})?/[\w./@%+~-]+)",
    re.IGNORECASE,
)
_DIRECT_EXEC_RE = re.compile(r"(?:^|[\s;&|(])((?:~|\$HOME|\.{1,2})?/[\w./@%+~-]+)(?=\s|$|[;&|)])")
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
        n = re.split(r"[=<>!~\[;]", n)[0].lower()
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
    program text a token is kept only when it is a whole quoted string literal."""
    skip = [range(*m.span(1)) for m in _PY_MODULE_RE.finditer(text)]
    skip += _config_key_spans(text)
    skip += _search_pattern_spans(text)
    programs = [range(0, len(text))] if inline_program else []
    for m in _INLINE_PROGRAM_RE.finditer(text):
        programs.append(range(*_quoted_span(text, m.end())))
    return skip, programs


def _config_key_spans(text: str) -> list[range]:
    """The key argument of `openclaw config set|get|unset <key>`, `hermes config [verb] <key>` and
    `git [-C dir] config [verb] <key>`, skipping flags (and the value of `--file`/`-f`/`--blob`)."""
    spans: list[range] = []
    for m in _CONFIG_HEAD_RE.finditer(text):
        head = m.group(1)
        toks = list(
            itertools.islice(_TOKEN_RE.finditer(text, m.end(), _line_end(text, m.end())), 32)
        )
        i = 0
        while head == "git" and i < len(toks) and toks[i].group(0) in ("-C", "-c"):
            i += 2
        if i >= len(toks) or toks[i].group(0) != "config":
            continue
        i += 1
        if i < len(toks) and toks[i].group(0) in _CONFIG_VERBS[head]:
            i += 1
        elif head == "openclaw":
            continue
        while i < len(toks) and toks[i].group(0).startswith("-"):
            i += 2 if toks[i].group(0) in _CONFIG_VALUE_FLAGS else 1
        if i < len(toks):
            key = _CONFIG_KEY_TOKEN_RE.match(toks[i].group(0))
            if key:
                spans.append(range(toks[i].start(), toks[i].start() + key.end()))
    return spans


def _search_pattern_spans(text: str) -> list[range]:
    """The pattern argument of grep-like tools: each `-e`/`--regexp` value, or else the first
    positional. Later positionals are files and are left alone."""
    spans: list[range] = []
    for m in _SEARCH_HEAD_RE.finditer(text):
        toks = itertools.islice(_TOKEN_RE.finditer(text, m.end(), _line_end(text, m.end())), 32)
        explicit = False
        take: str | None = None  # "pattern" or "value": what the previous flag consumes
        for tok in toks:
            word = tok.group(0)
            if word in _SHELL_SEPARATORS:
                break
            if take is not None:
                if take == "pattern":
                    spans.append(range(*tok.span()))
                take = None
                continue
            if word in _SEARCH_PATTERN_FLAGS:
                take, explicit = "pattern", True
            elif word.startswith("--regexp="):
                spans.append(range(tok.start() + len("--regexp="), tok.end()))
                explicit = True
            elif word in _SEARCH_VALUE_FLAGS:
                take = "value"
            elif word.startswith("-") and word != "-":
                continue
            else:
                if not explicit:
                    spans.append(range(*tok.span()))
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


def _hosts_in(text: str, *, inline_program: bool = False) -> list[str]:
    """Hosts named in `text`: URLs, emails, host-taking arguments, IPv4 addresses, and bare dotted
    tokens outside code and config-key positions. With `inline_program` the whole text is program
    source (a Hermes `execute_code` body)."""
    hosts: list[str] = []
    for m in _URL_RE.finditer(text):
        h = host_of_url(m.group(0))
        if h:
            hosts.append(h)
    for m in _EMAIL_RE.finditer(text):
        hosts.append(normalise_host(m.group(1).split("@", 1)[1]))
    for rx in (_SSH_HOST_RE, _NC_HOST_RE, _DEV_TCP_RE):
        for m in rx.finditer(text):
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


def _packages_in(text: str) -> list[str]:
    pkgs: list[str] = []
    for m in _INSTALLERS.finditer(text):
        eco_key = re.sub(r"\s+", " ", m.group("eco").lower())
        if eco_key.startswith(("openclaw", "hermes")):
            eco = "plugin"
        else:
            eco = _ECOSYSTEM.get(eco_key, eco_key)
        tokens = m.group("rest").split()
        skip_next = False
        for tok in tokens:
            if skip_next:
                skip_next = False
                continue
            if tok.startswith("-"):
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
    return list(dict.fromkeys(pkgs))


def _recipients_in(values: list[str]) -> list[Found]:
    out: list[Found] = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        m = _CHANNEL_RE.fullmatch(v)
        if m:
            out.append(Found(EntityKind.CHANNEL, v, v, Role.RECIPIENT))
            continue
        if _EMAIL_RE.fullmatch(v):
            norm = normalise_recipient(v)
            out.append(Found(EntityKind.RECIPIENT, norm, norm, Role.RECIPIENT))
            out.append(
                Found(
                    EntityKind.HOST,
                    normalise_host(norm.split("@", 1)[1]),
                    normalise_host(norm.split("@", 1)[1]),
                    Role.DATA_DESTINATION,
                )
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
    """Entities named in free text (request, inputs, content): hosts, emails, paths, packages.
    `inline_program` marks the text as program source (see `_hosts_in`)."""
    found: list[Found] = []
    for h in _hosts_in(text, inline_program=inline_program):
        found.append(Found(EntityKind.HOST, h, h, role))
    for m in _EMAIL_RE.finditer(text):
        norm = normalise_recipient(m.group(1))
        found.append(Found(EntityKind.RECIPIENT, norm, norm, role))
    for norm, disp in paths_in(text, home, workspace_root, None):
        found.append(Found(EntityKind.PATH, norm, disp, role))
    for p in _packages_in(text):
        found.append(Found(EntityKind.PACKAGE, p, p, role))
    for m in _CHANNEL_RE.finditer(text):
        found.append(Found(EntityKind.CHANNEL, m.group(0), m.group(0), role))
    return found


# --------------------------------------------------------------------------- shell segments

_SEGMENT_SPLIT_RE = re.compile(r"&&|\|\||[;|\n]")
_ENV_ASSIGN_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPER_HEADS = frozenset({"sudo", "doas", "nohup", "time", "env", "exec", "command"})


def shell_segments(command: str) -> list[list[str]]:
    """The simple commands of a shell string as token lists, wrappers (`sudo`, `env`, …) and leading
    variable assignments dropped. Quoting is honoured within a segment where it parses; this is a
    light split for lineage questions, not the AIRA shell parser."""
    import shlex

    out: list[list[str]] = []
    for seg in _SEGMENT_SPLIT_RE.split(command or ""):
        seg = seg.strip().lstrip("(").rstrip(")").strip()
        if not seg or seg.startswith("#"):
            continue
        try:
            tokens = shlex.split(seg, comments=True)
        except ValueError:
            tokens = seg.split()
        while tokens and (tokens[0] in _WRAPPER_HEADS or _ENV_ASSIGN_RE.match(tokens[0])):
            tokens = tokens[1:]
        if tokens:
            out.append(tokens)
    return out


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
    to_interpreter = bool(_PIPE_TO_INTERPRETER.search(command))
    code_hosts, run_files = fetched_then_run(
        command, home=home, workspace_root=workspace_root, cwd=cwd
    )

    for h in _hosts_in(command, inline_program=inline_program):
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
    for m in _DIRECT_EXEC_RE.finditer(command):
        seg_start = command.rfind(";", 0, m.start()) + 1
        for sep in ("&&", "||", "|"):
            k = command.rfind(sep, 0, m.start())
            seg_start = max(seg_start, k + len(sep) if k >= 0 else 0)
        if command[seg_start : m.start(1)].strip() == "":
            executables.add(m.group(1))
    for m in _WRITE_TARGET_RE.finditer(command):
        destinations.add(m.group(1))
    for m in _DESTRUCTIVE_HEADS.finditer(command):
        for tok in m.group(1).split():
            if tok.startswith(("/", "~", "./", "../", "$HOME")):
                destinations.add(tok.strip("'\""))

    for norm, disp in paths_in(command, home, workspace_root, cwd):
        raw_matches = [
            r
            for r in sources | destinations | executables
            if normalise_path(r, home=home, workspace_root=workspace_root, cwd=cwd) == norm
        ]
        if norm in run_files or any(
            normalise_path(r, home=home, workspace_root=workspace_root, cwd=cwd) == norm
            for r in executables
        ):
            role = Role.EXECUTABLE
        elif any(
            normalise_path(r, home=home, workspace_root=workspace_root, cwd=cwd) == norm
            for r in destinations
        ):
            role = Role.DATA_DESTINATION
        elif raw_matches or not egress:
            role = Role.DATA_SOURCE
        else:
            role = Role.DATA_SOURCE
        found.append(Found(EntityKind.PATH, norm, disp, role))

    for p in _packages_in(command):
        kind = (
            EntityKind.PLUGIN
            if (p.startswith("@") or (p.count("/") == 1 and ":" not in p))
            and not p.startswith(("npm:", "pypi:", "docker:", "git+"))
            else EntityKind.PACKAGE
        )
        found.append(Found(kind, p, p, Role.CODE_SOURCE))
    return found


def extract_call(
    call: CanonicalCall, *, home: str | None, workspace_root: str | None
) -> list[Found]:
    """Entities of a canonical call with roles by tool kind."""
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
        found.extend(_recipients_in(call.recipients))
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
        found.append(
            Found(ekind, call.provider.identity, call.provider.identity, Role.TOOL_PROVIDER)
        )
    return found


def grant_matches(kind: str, pattern: str, entity: Entity) -> bool:
    """Does a grant of `kind` with glob `pattern` cover `entity`? Over-broad patterns never match."""
    import fnmatch

    if pattern.strip() in ("*", "**", "*.*", "") or pattern.strip("*") == "":
        return False
    pat = pattern.strip().lower()
    if kind == "destination" and entity.kind in (
        EntityKind.HOST,
        EntityKind.RECIPIENT,
        EntityKind.CHANNEL,
    ):
        value = entity.value.lower()
        if entity.kind is EntityKind.RECIPIENT and "@" in value and "@" not in pat:
            value = value.split("@", 1)[1]
        if fnmatch.fnmatch(value, pat):
            return True
        if pat.startswith("*.") and value == pat[2:]:
            return True
        return False
    if kind == "file" and entity.kind is EntityKind.PATH:
        return fnmatch.fnmatch(entity.value, pat) or fnmatch.fnmatch(entity.display, pat)
    if kind == "provider" and entity.kind in (EntityKind.MCP_SERVER, EntityKind.PLUGIN):
        return fnmatch.fnmatch(entity.value.lower(), pat)
    return False


def any_text(value: Any) -> str:
    from ..planir.canonical import joined_text

    if isinstance(value, dict):
        return joined_text(value)
    return str(value or "")
