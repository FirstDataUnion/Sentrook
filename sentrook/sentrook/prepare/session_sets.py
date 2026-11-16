"""Session judgements bound to what they are about.

The token's `sensitive` and `tainted` sets hold hashed files and database tables (`state.token`). This module
answers three questions for the preparation stage:

- Which files and tables does a call touch, and in which direction (`call_artefacts`)? The pending call's
  binding to the sets is decided from this, and so is what a call writes from a bound file.
- What did an injected result come from (`producer_artefacts`)? The files and tables the producing call
  names: what it wrote the result to (`out`, `-o`, a table) and what it read it from. Both now hold the
  injected content.
- Is an input the owner's own configuration (`owner_config_path`)? A scanned read of one of the agent's own
  config or instruction files that the agent did not write in this session.

A call is *bound* to a set when one of the files or tables it reads, runs or applies is in the set. A call
with no file or table to match (a raw body, a pipe, a message text) is *unidentifiable*: nothing can be
matched, so the bare session flag keeps its weight.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from ..planir.canonical import CanonicalCall
from ..planir.models import ToolKind
from ..state.token import entity_hash, table_key
from .entities import (
    _RUNISH_TOOL,
    _WRITEISH_TOOL,
    EntityKind,
    Role,
    extract_call,
    normalise_path,
    resolve_token,
    shell_segments,
)

#: Raw argument keys that name a database table.
TABLE_KEYS = frozenset({"table", "table_name", "target_table", "source_table", "into_table"})
#: Raw argument keys that carry SQL in a tool call (exec commands are read only behind a SQL client head).
_SQL_KEYS = ("sql", "query", "statement")
_SQL_HEADS = frozenset(
    {"psql", "mysql", "mariadb", "sqlite3", "duckdb", "sqlcmd", "clickhouse-client"}
)
_SQL_TABLE_RE = re.compile(
    r"\b(from|join|into|update|table(?:\s+if\s+(?:not\s+)?exists)?)\s+"
    r"((?:[\w\"`\[\]]+\.)*[\w\"`\[\]]+)",
    re.IGNORECASE,
)
#: A statement that changes data or schema, by its opening shape (a `replace(...)` function is not one).
_SQL_WRITE_RE = re.compile(
    r"\b(?:delete\s+from|update\s+[\w\"`.\[\]]+\s+set|insert\s+(?:or\s+\w+\s+)?into|replace\s+into"
    r"|merge\s+into|drop\s+\w+|truncate\s+|alter\s+\w+|create\s+(?:or\s+replace\s+)?\w+"
    r"|grant\s+|revoke\s+)",
    re.IGNORECASE,
)
_URLISH = re.compile(r"[a-z][a-z0-9+.-]*:/", re.IGNORECASE)
_OUTPUT_KEYS = frozenset(
    {"out", "output", "out_path", "output_path", "outfile", "dest", "destination"}
)
_SQL_WORDS = frozenset({"select", "where", "set", "values", "lateral", "only", "unnest"})
#: Heads that only read or copy: a call made of these alone does not act on what it reads.
READ_HEADS = frozenset(
    "cat head tail less more ls stat wc grep rg file md5sum sha1sum sha256sum du find diff jq yq "
    "sort uniq cut awk sed tr nl od xxd hexdump strings column".split()
)
COPY_HEADS = frozenset("cp mv ln tee rsync".split())
#: Flags that make a reading head run or rewrite what it reads (`awk -f prog`, `sed -i`, `find -exec`).
_ACTING_FLAGS = {
    "awk": ("-f",),
    "gawk": ("-f",),
    "sed": ("-i", "--in-place", "-f"),
    "find": ("-exec", "-execdir", "-ok", "-okdir", "-delete"),
}
#: A copy onto one of these locations applies what it copies (the agent's own setup).
_APPLY_GROUPS = ("agent_config", "agent_plugins", "agent_memory", "agent_scheduler")
#: Tool names that list or search rather than read one file.
_LISTING_TOOL = re.compile(r"\b(?:ls|list|glob|find|search|grep|tree)", re.IGNORECASE)
#: Tool kinds whose arguments have no fixed meaning: their path and table arguments are read by key.
_GENERIC_KINDS = frozenset({ToolKind.OTHER, ToolKind.MCP})
#: Roles that run a file.
_RUNNING_ROLES = frozenset({Role.EXECUTABLE, Role.CODE_SOURCE})


@dataclass(frozen=True)
class Artefact:
    """A file or table a call touches."""

    kind: str  # "path" | "table"
    value: str  # normalised path, or table key
    hash: str
    entity_id: str | None = None  # the entity table's id, for a path
    takes: bool = False  # the call takes content from it (reads, sends, attaches, selects from it)
    writes: bool = False  # the call writes it (a local destination)
    runs: bool = False  # the call runs it (an executable, a code source)


@dataclass
class Binding:
    """How the pending call relates to one of the token's sets."""

    #: Artefacts the call takes content from (or, for the tainted set, runs) that the set holds.
    matched: list[Artefact] = field(default_factory=list)
    #: The call has at least one file or table it takes content from, so a miss is a real miss. The
    #: program a command runs and a directory it changes into are not content it sends.
    identifiable: bool = False

    @property
    def bound(self) -> bool:
        return bool(self.matched)

    def subject(self) -> str | None:
        return next((a.entity_id for a in self.matched if a.entity_id), None)

    def names(self) -> list[str]:
        return [f"{a.kind}:{a.value}" if a.kind == "table" else a.value for a in self.matched]


@dataclass
class SessionBinding:
    """The pending call against the token's sets, as they stood before this request."""

    sensitive: Binding = field(default_factory=Binding)
    tainted: Binding = field(default_factory=Binding)
    #: The call sends something off this machine (`grants.sends_off_host`).
    off_host: bool = False
    #: The call does more than read or copy what it takes: it sends, runs, installs, applies or
    #: changes something (`acts`).
    acts: bool = False
    #: Hashes of the files and tables the call takes content from, and of the local files it writes:
    #: what it writes from a bound file joins that file's set.
    takes: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)


def sql_table_uses(text: str) -> list[tuple[str, bool]]:
    """Tables a SQL statement names, as (table key, read): a table after FROM or JOIN is read; one
    after INTO, UPDATE or TABLE is written."""
    out: dict[str, bool] = {}
    for m in _SQL_TABLE_RE.finditer(text or ""):
        key = table_key(m.group(2))
        if not key or key in _SQL_WORDS or key[0].isdigit():
            continue
        read = m.group(1).lower() in ("from", "join")
        out[key] = out.get(key, False) or read
    return list(out.items())


def sql_tables(text: str) -> list[str]:
    """Tables a SQL statement names (after FROM, JOIN, INTO, UPDATE, TABLE), as table keys."""
    return [name for name, _ in sql_table_uses(text)]


def _sql_text(call: CanonicalCall) -> str:
    if call.tool_kind is ToolKind.EXEC:
        cmd = call.command or ""
        heads = {PurePosixPath(seg[0]).name for seg in shell_segments(cmd) if seg}
        return cmd if heads & _SQL_HEADS else ""
    parts = [call.raw.get(k) for k in _SQL_KEYS]
    return "\n".join(p for p in parts if isinstance(p, str))


def _raw_strings(value: Any) -> list[tuple[str | None, str]]:
    """Top-level string arguments and strings in top-level lists, with their key."""
    out: list[tuple[str | None, str]] = []
    if not isinstance(value, dict):
        return out
    for k, v in value.items():
        if isinstance(v, str):
            out.append((str(k), v))
        elif isinstance(v, list):
            out.extend((str(k), x) for x in v if isinstance(x, str))
    return out


def _path_like(value: str) -> bool:
    v = value.strip()
    return (
        "://" not in v
        and "\n" not in v
        and " " not in v
        and v.startswith(("/", "~/", "./", "../", "$HOME/"))
    )


def call_artefacts(
    call: CanonicalCall, salt: str, *, home: str | None, workspace_root: str | None, entity_ids=None
) -> list[Artefact]:
    """The files and tables `call` touches. `entity_ids` maps a normalised path to its entity id."""
    entity_ids = entity_ids or {}
    by_key: dict[tuple[str, str], Artefact] = {}

    skip = _changed_into(call, home=home, workspace_root=workspace_root)

    def put(kind: str, value: str, *, takes: bool, writes: bool, runs: bool = False) -> None:
        if kind == "path" and (_URLISH.match(value) or value in skip):
            return  # a URL argument normalised as a path is not a file, nor is a directory `cd` enters
        key = (kind, value)
        old = by_key.get(key)
        by_key[key] = Artefact(
            kind=kind,
            value=value,
            hash=entity_hash(salt, kind, value),
            entity_id=entity_ids.get(value) if kind == "path" else None,
            takes=takes or (old.takes if old else False),
            writes=writes or (old.writes if old else False),
            runs=runs or (old.runs if old else False),
        )

    for f in extract_call(call, home=home, workspace_root=workspace_root):
        if f.kind is not EntityKind.PATH or f.role is Role.MENTIONED or f.role is None:
            continue
        put(
            "path",
            f.value,
            takes=f.role is Role.DATA_SOURCE,
            writes=f.role is Role.DATA_DESTINATION,
            runs=f.role in _RUNNING_ROLES,
        )
    if call.tool_kind in _GENERIC_KINDS:
        # Generic tools: any argument that is a path, or a table named by a table key.
        writeish = bool(_WRITEISH_TOOL.search(call.tool))
        for key, value in _raw_strings(call.raw):
            if key in TABLE_KEYS and value.strip():
                put("table", table_key(value), takes=True, writes=writeish)
            elif _path_like(value):
                norm = normalise_path(value.strip(), home=home, workspace_root=workspace_root)
                put("path", norm, takes=key not in _OUTPUT_KEYS, writes=key in _OUTPUT_KEYS)
    for name, read in sql_table_uses(_sql_text(call)):
        put("table", name, takes=read, writes=not read)
    return list(by_key.values())


def _changed_into(call: CanonicalCall, *, home: str | None, workspace_root: str | None) -> set[str]:
    """Directories a command changes into (`cd`, `pushd`): where it runs, not content it reads."""
    if call.tool_kind is not ToolKind.EXEC:
        return set()
    cwd = call.get("cwd") or workspace_root or "/"
    out: set[str] = set()
    for seg in shell_segments(call.command or ""):
        if PurePosixPath(seg[0]).name in ("cd", "pushd") and len(seg) > 1:
            out.add(resolve_token(seg[1], cwd, home=home, workspace_root=workspace_root)[0])
    return out


def producer_artefacts(
    call: CanonicalCall, salt: str, *, home: str | None, workspace_root: str | None
) -> list[str]:
    """Hashes of what the call whose result was injected produced: the files and tables it wrote (`out`,
    `-o`, a table it filled), or the one file a read tool read, or the tables and files a generic tool
    named. A command that lists or searches a tree names no file the injection came from."""
    arts = call_artefacts(call, salt, home=home, workspace_root=workspace_root)
    out = [a.hash for a in arts if a.writes]
    if call.tool_kind is ToolKind.FILE_READ and not _LISTING_TOOL.search(call.tool):
        out += [a.hash for a in arts if a.takes and a.kind == "path"]
    elif call.tool_kind in _GENERIC_KINDS:
        out += [a.hash for a in arts if a.takes]
    return list(dict.fromkeys(out))


def _exec_acts(call: CanonicalCall, applies_to) -> bool:
    for seg in shell_segments(call.command or ""):
        head = PurePosixPath(seg[0]).name
        if head in ("cd", "pushd", "popd"):
            continue
        if head in _SQL_HEADS:
            if _SQL_WRITE_RE.search(" ".join(seg)):
                return True
            continue
        if head in READ_HEADS:
            flags = _ACTING_FLAGS.get(head, ())
            if any(t == f or t.startswith(f) and f in ("-i", "-f") for t in seg[1:] for f in flags):
                return True
            continue
        if head in COPY_HEADS:
            if applies_to(seg):
                return True
            continue
        return True
    return False


def acts(
    call: CanonicalCall,
    off_host: bool,
    destroys: bool,
    *,
    home: str | None = None,
    workspace_root: str | None = None,
) -> bool:
    """The call does more than read or copy: it sends off the host, destroys, runs, installs, applies or
    changes something. A plain read, a listing, a read-only query or a local copy does not act on what it
    reads; a copy onto the agent's own config, plugins, memory or schedule applies it."""
    if off_host or destroys:
        return True

    def applies_to(seg: list[str]) -> bool:
        from ..aira.lists import load_lists

        lists = load_lists()
        cwd = call.get("cwd") or workspace_root or "/"
        targets = [t for t in seg[1:] if not t.startswith("-")][-1:]
        for tok in targets:
            path = resolve_token(tok, cwd, home=home, workspace_root=workspace_root)[0]
            if any(lists.group(g).search(path) for g in _APPLY_GROUPS):
                return True
        return False

    kind = call.tool_kind
    if kind in (ToolKind.FILE_READ, ToolKind.FILE_WRITE, ToolKind.FILE_EDIT):
        return False
    if kind is ToolKind.EXEC:
        return _exec_acts(call, applies_to)
    if _SQL_WRITE_RE.search(_sql_text(call)):
        return True
    if call.tool_kind in _GENERIC_KINDS and _sql_text(call):
        return False  # a read-only query
    return bool(_WRITEISH_TOOL.search(call.tool) or _RUNISH_TOOL.search(call.tool)) or kind in (
        ToolKind.MESSAGE_SEND,
        ToolKind.MEMORY_WRITE,
        ToolKind.SUBAGENT_SPAWN,
    )


def bind(
    artefacts: list[Artefact],
    *,
    sensitive: frozenset[str],
    tainted: frozenset[str],
) -> tuple[Binding, Binding]:
    taking = [a for a in artefacts if a.takes]
    using = [a for a in artefacts if a.takes or a.runs]
    return (
        Binding(matched=[a for a in taking if a.hash in sensitive], identifiable=bool(taking)),
        Binding(matched=[a for a in using if a.hash in tainted], identifiable=bool(using)),
    )


def owner_config_path(
    call: CanonicalCall, *, home: str | None, workspace_root: str | None
) -> str | None:
    """The agent config or instruction file `call` reads, when that is all it does: a file read, or a
    command made only of reading heads over one file in the agent's config list (`agent_config` in the
    sensitive-path lists), in the agent's own place: under `~/.openclaw/` or `~/.hermes/`, in
    `/etc/hermes/`, or at the top of the workspace. An AGENTS.md in a cloned repository is not the owner's.
    None otherwise."""
    from ..aira.lists import load_lists

    group = load_lists().group("agent_config")

    def owned(path: str) -> bool:
        roots = [f"{home.rstrip('/')}/.openclaw/", f"{home.rstrip('/')}/.hermes/"] if home else []
        if path.startswith((*roots, "/etc/hermes/")):
            return True
        return bool(workspace_root) and str(PurePosixPath(path).parent) == workspace_root.rstrip(
            "/"
        )

    if call.tool_kind is ToolKind.FILE_READ:
        if not call.path:
            return None
        norm = normalise_path(call.path, home=home, workspace_root=workspace_root)
        return norm if group.search(norm) and owned(norm) else None
    if call.tool_kind is not ToolKind.EXEC:
        return None
    segments = shell_segments(call.command or "")
    if not segments or any(PurePosixPath(seg[0]).name not in READ_HEADS for seg in segments):
        return None
    sources = [
        f.value
        for f in extract_call(call, home=home, workspace_root=workspace_root)
        if f.kind is EntityKind.PATH and f.role is Role.DATA_SOURCE
    ]
    if len(sources) != 1 or not group.search(sources[0]) or not owned(sources[0]):
        return None
    return sources[0]
