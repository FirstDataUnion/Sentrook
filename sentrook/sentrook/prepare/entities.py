"""Entity extraction, roles and opaque IDs (preparation steps 5 and 6).

Entities are the hosts, paths, packages, recipients, channels and tool providers a call touches. Each
gets an opaque ID (`E1`, `E2`, …) assigned in extraction order, a set of roles describing how the
pending call uses it, and the origins where it was seen: the owner's request, a grant, the pending
call itself, a sibling, an untrusted or trusted input, an earlier history step, a file the agent wrote
earlier, or a provider identity. Convergence and the response only ever see the IDs; probes that need
the raw value (AIRA, the oracle) read it from the table.

Role assignment is heuristic by design: AIRA (WP3) refines reach and sinks with the shell parser; this
module only has to be right enough for the oracle and the context probe to ask the right questions.
"""

from __future__ import annotations

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


#: Roles the oracle treats as risky for an unknown entity (skeleton 3.2, 4.1).
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
_HOST_RE = re.compile(r"(?<![\w@/.:+-])((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![\w/-])")
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
_IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?![\w.])")
_PATH_RE = re.compile(r"(?<![\w.:-])((?:~|\$HOME|\.{1,2})?/(?:[\w.@%+~-]+/)*[\w.@%+~-]+/?)")
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
    if text[end : end + 1] == "(":
        return True
    line = text[text.rfind("\n", 0, start) + 1 : start]
    if _IMPORT_LIST_RE.search(line):
        return True
    return bool(_FROM_IMPORT_RE.search(line) and _IMPORT_AFTER_RE.match(text, end))


def _hosts_in(text: str) -> list[str]:
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
    stripped = _URL_RE.sub(" ", _EMAIL_RE.sub(" ", text))
    for m in _HOST_RE.finditer(stripped):
        cand = m.group(1)
        tld = cand.rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXTENSIONS or cand.lower() in ("e.g", "i.e", "etc.etc"):
            continue
        if cand[0].isdigit() and cand.replace(".", "").isdigit():
            continue
        if _is_code_reference(stripped, m.start(1), m.end(1)):
            continue
        hosts.append(normalise_host(cand))
    return list(dict.fromkeys(hosts))


def _paths_in(
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
    text: str, *, home: str | None, workspace_root: str | None, role: Role | None = Role.MENTIONED
) -> list[Found]:
    """Entities named in free text (request, inputs, content): hosts, emails, paths, packages."""
    found: list[Found] = []
    for h in _hosts_in(text):
        found.append(Found(EntityKind.HOST, h, h, role))
    for m in _EMAIL_RE.finditer(text):
        norm = normalise_recipient(m.group(1))
        found.append(Found(EntityKind.RECIPIENT, norm, norm, role))
    for norm, disp in _paths_in(text, home, workspace_root, None):
        found.append(Found(EntityKind.PATH, norm, disp, role))
    for p in _packages_in(text):
        found.append(Found(EntityKind.PACKAGE, p, p, role))
    for m in _CHANNEL_RE.finditer(text):
        found.append(Found(EntityKind.CHANNEL, m.group(0), m.group(0), role))
    return found


def extract_exec(
    command: str, *, home: str | None, workspace_root: str | None, cwd: str | None
) -> list[Found]:
    """Entities a shell command touches, with roles from the command's shape."""
    found: list[Found] = []
    egress = bool(_EGRESS_MARKERS.search(command))
    to_interpreter = bool(_PIPE_TO_INTERPRETER.search(command))

    for h in _hosts_in(command):
        if h in ("localhost",):
            role = Role.DATA_SOURCE
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

    for norm, disp in _paths_in(command, home, workspace_root, cwd):
        raw_matches = [
            r
            for r in sources | destinations | executables
            if normalise_path(r, home=home, workspace_root=workspace_root, cwd=cwd) == norm
        ]
        if any(
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
        found.extend(extract_exec(cmd, home=home, workspace_root=workspace_root, cwd=cwd))
        decoded = call.analysis_text
        if decoded != call.text:
            found.extend(extract_exec(decoded, home=home, workspace_root=workspace_root, cwd=cwd))
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
