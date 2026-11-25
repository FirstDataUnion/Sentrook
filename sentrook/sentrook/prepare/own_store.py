"""Reads of the agent's own skill library and memory: marked in the self-edit view, and left out of the exposure probe.

A self-edit is judged against the conversation its host process reviewed. Most `tool` entries there are content the
agent read (a page, a file, command output), whose instructions must not become standing directives. A read of the
agent's own installed skills is different: it returns procedures the agent already has and already follows, so a save
that carries them over unchanged (a curator merging near-duplicates, a review patching a skill it just viewed) adds
nothing new. The self-edit questions can only treat the two differently if they can tell them apart, and the content
cannot be trusted to say which it is, so the scanner marks such entries itself.

A read is marked only from the platform and the bare tool name the plugin reports (and, for a `new_inputs` item, a
`host` provider and an `ok` status), never from a tool's output. Any `source` key the request already carries on these
entries is dropped first, so no tool result, and no key a plugin adds, can mark an entry; the plugin's tool name and
platform remain trusted, as everywhere else in the request. A conversation entry has no status, so a failed read is
marked too; it carries no skill content to carry over.

Per platform:
- Hermes: `skill_view` and `skills_list` serve only installed skills (the agent's own directory, the owner's configured
  external directories, a trusted project's skill directories, plugin and bundled skills); hub search and install are
  separate tools. A project's skill applies only in that project, so the questions count moving its content into the
  agent's own library, or any skill into memory, as applying it more widely. Hermes's `memory` tool
  is left out: it writes, and its results only echo entries as a side effect.
- OpenClaw is not covered by the self-edit mark: its own-store reads are plain `read` calls whose relative paths
  cannot be resolved for entries from the owner's session, and `skill_workshop` reads include proposals nobody has
  approved.

The exposure probe asks whether an input carries instructions or claims authority. A skill is instructions by design
and a memory note is the agent's own standing context, so every read of them scored as injected and tainted the
session, though the host loads the same content into the prompt with no tool call. `own_store_read` names the new
tool results that are such reads, for the exposure probe to leave out (`prepare`, step 8). They stay untrusted for
everything else. A read counts only as a host tool that succeeded:
- Hermes: `skill_view` and `skills_list` (installed skills, as for the self-edit mark).
- OpenClaw: `skill_workshop` `view` (and `read` on hosts before the proposal flow was retired), which read a skill
  the agent has; `list` and `inspect` can show proposals nobody approved and keep exposure.
- OpenClaw: `plugin_skill:read` (`PLUGIN_SKILL_READ`), the name the Sentrook plugin reports a `read` under when the
  file it read resolves to one of the skill files the plugin itself ships (its real path inside the plugin's own
  folder). Tool names hold no `:`, so no tool the agent can call has this name. A read of the same text anywhere
  else (a copy in the workspace, a link swapped in for the plugin's file) stays a plain `read` and keeps exposure.
- OpenClaw: a `read` or `memory_get` of `MEMORY.md` or a `.md` file directly under `memory/` at the top of the
  workspace (a relative path resolves against the workspace, as the host resolves it; a path with `$` or quotes,
  which the host reads literally, never counts). `memory_search` and `memory_get` with another corpus can return
  other sessions' transcripts or wiki pages, and `DREAMS.md` and the dreaming files under `memory/` are written from
  conversations: they keep exposure. A memory file the session's tainted set holds, under any spelling lineage may
  have recorded, is excluded by the caller.

A background run's exec call (OpenClaw's review may save a skill with a heredoc, `tee` or `cp`) is declared with the
run's `self_edit` block, since the plugin cannot tell whether a command saves. The scanner decides by target
(`exec_store_writes`): the call is a self-edit only when it is a plain save into the declared store, a command that
does nothing but write the store's files; otherwise the block is dropped before anything reads it (coverage note
`self_edit_not_own_store`) and the command keeps its ordinary scoring.
"""

from __future__ import annotations

import re
from typing import Any

from .entities import normalise_path

#: The key and value the self-edit view puts on a marked entry.
SOURCE = "source"
OWN_STORE = "own_store"

#: Per host platform, the host tools whose results are the agent's own installed skills as they stand.
OWN_STORE_READS: dict[str, frozenset[str]] = {
    "hermes": frozenset({"skill_view", "skills_list"}),
}


def is_own_store_read(platform: Any, tool: Any) -> bool:
    """`tool` on `platform` reads the agent's own skill library."""
    return (
        isinstance(platform, str)
        and isinstance(tool, str)
        and tool in OWN_STORE_READS.get(platform, ())
    )


#: The OpenClaw tool name the Sentrook plugin reports a read of one of its own shipped skill files under.
PLUGIN_SKILL_READ = "plugin_skill:read"
#: OpenClaw `skill_workshop` actions that read a skill the agent already has.
WORKSHOP_SKILL_READS = frozenset({"view", "read"})
#: OpenClaw `memory_get` corpora that hold only the workspace's memory files.
MEMORY_CORPORA = frozenset({"", "memory"})
SKILL = "skill"
MEMORY = "memory"


#: Characters the host reads literally in a path but the scanner's normaliser would rewrite: `$HOME` and quotes.
_LITERAL = frozenset("$'\"`")


def memory_path_spellings(
    platform: Any, tool: Any, args: dict[str, Any], *, home: str | None, workspace_root: str | None
) -> list[str]:
    """Every spelling under which lineage may have recorded the memory file a call reads: the resolved path and the
    argument as given (lineage keeps a bare relative path unresolved). Empty when the call reads no own memory file."""
    path = own_memory_path(platform, tool, args, home=home, workspace_root=workspace_root)
    if path is None:
        return []
    raw = str(args.get("path") or args.get("file_path") or "").strip()
    given = normalise_path(raw, home=home, workspace_root=workspace_root)
    return sorted({path, given})


def own_memory_path(
    platform: Any, tool: Any, args: dict[str, Any], *, home: str | None, workspace_root: str | None
) -> str | None:
    """The workspace memory file an OpenClaw `read` or `memory_get` reads (normalised), or None: `MEMORY.md` or a
    `.md` file directly under `memory/` at the top of the workspace. Deeper files (dreaming reports under
    `memory/dreaming/`, the session corpus under `memory/.dreams/`, anything cloned into `memory/`) are not."""
    if platform != "openclaw" or tool not in ("read", "memory_get") or not workspace_root:
        return None
    if tool == "memory_get" and str(args.get("corpus") or "").strip().lower() not in MEMORY_CORPORA:
        return None
    raw = args.get("path") or args.get("file_path")
    if not isinstance(raw, str) or not raw.strip() or _LITERAL & set(raw):
        return None
    ws = normalise_path(workspace_root, home=home, workspace_root=None)
    path = raw.strip()
    if not path.startswith(("/", "~")):
        path = f"{ws}/{path}"
    norm = normalise_path(path, home=home, workspace_root=ws)
    return norm if _is_memory_file(norm, ws) else None


def _is_memory_file(norm: str, ws: str) -> bool:
    """`norm` (normalised) is `MEMORY.md` or a `.md` file directly under `memory/` at the top of workspace `ws`."""
    if norm == f"{ws}/MEMORY.md":
        return True
    rest = norm.removeprefix(f"{ws}/memory/")
    return rest != norm and "/" not in rest and rest.endswith(".md")


def own_store_read(
    platform: Any,
    tool: Any,
    args: dict[str, Any] | None,
    *,
    home: str | None,
    workspace_root: str | None,
) -> str | None:
    """What of the agent's own store a host tool call with these arguments reads: `skill`, `memory` or None. The
    caller checks that the call is the host's own and succeeded."""
    if not isinstance(platform, str) or not isinstance(tool, str):
        return None
    args = args or {}
    if platform == "hermes":
        return SKILL if tool in OWN_STORE_READS["hermes"] else None
    if platform == "openclaw":
        if tool == PLUGIN_SKILL_READ:
            return SKILL
        if tool == "skill_workshop":
            action = str(args.get("action") or "").strip().lower()
            return SKILL if action in WORKSHOP_SKILL_READS else None
        if own_memory_path(platform, tool, args, home=home, workspace_root=workspace_root):
            return MEMORY
    return None


def _host_ok(item: dict[str, Any]) -> bool:
    provider = item.get("provider")
    return (
        isinstance(provider, dict)
        and provider.get("kind") == "host"
        and item.get("status", "ok") == "ok"
    )


def mark_own_store(v: dict[str, Any]) -> int:
    """Mark the self-edit view's own-store reads with `source: own_store`, after dropping any `source` the request
    carried on the conversation's entries and the turn's inputs. Mutates `v`; returns how many entries were marked."""
    host = v.get("host")
    platform = host.get("platform") if isinstance(host, dict) else None
    marked = 0
    block = v.get("self_edit")
    conv = block.get("conversation") if isinstance(block, dict) else None
    for e in conv if isinstance(conv, list) else []:
        if not isinstance(e, dict):
            continue
        e.pop(SOURCE, None)
        if e.get("role") == "tool" and is_own_store_read(platform, e.get("tool")):
            e[SOURCE] = OWN_STORE
            marked += 1
    inputs = v.get("new_inputs")
    for n in inputs if isinstance(inputs, list) else []:
        if not isinstance(n, dict):
            continue
        n.pop(SOURCE, None)
        if (
            n.get("kind") == "tool_result"
            and _host_ok(n)
            and is_own_store_read(platform, n.get("tool"))
        ):
            n[SOURCE] = OWN_STORE
            marked += 1
    return marked


#: The folder OpenClaw's Skill Workshop review and skill collection review run in: the agent's own skills.
WORKSHOP_DIR = "workshop-skills"
#: The coverage note of a background run's exec that is not a plain save into the declared store.
NOT_OWN_STORE = "self_edit_not_own_store"
#: The commands a plain shell save is made of: text written out, a staged file copied or moved in, a folder made.
SAVE_HEADS = frozenset({"cat", "cp", "echo", "mkdir", "mv", "printf", "tee", "touch"})
#: Of those, the ones whose operands are files (`echo` and `printf` print theirs as text).
_FILE_HEADS = frozenset({"cat", "cp", "mkdir", "mv", "tee", "touch"})
#: Where a save may stage its text before copying it in.
TEMP_DIRS = ("/tmp/", "/var/tmp/")
#: Syntax a plain save may use besides its commands, redirects and heredocs.
_STRUCTURE = frozenset({"program", "list", "pipeline", "redirected_statement", "comment"})
#: The day's note the memory flush appends to.
_DAY_NOTE = re.compile(r"memory/\d{4}-\d{2}-\d{2}\.md")


def in_own_store(platform: Any, store: Any, path: str, *, workspace_root: str | None) -> bool:
    """`path` (normalised) lies in the agent's own `store` as the background run that saves sees it. OpenClaw only,
    the one host whose background runs are sent with exec calls declared:
    - `skills`: inside the workspace when the workspace is the agent's Skill Workshop folder, where OpenClaw roots a
      Skill Workshop review and a skill collection review (as the plugin decides for their file tools);
    - `memory`: the day's note the flush appends to, `memory/YYYY-MM-DD.md` at the top of the workspace (as the
      plugin decides for the flush's `write`).
    Any other platform or store has no layout the scanner knows, so no path lies in it."""
    if platform != "openclaw" or not workspace_root:
        return False
    ws = workspace_root.rstrip("/")
    if store == "skills":
        return ws.rsplit("/", 1)[-1] == WORKSHOP_DIR and path.startswith(f"{ws}/")
    if store == "memory":
        return _DAY_NOTE.fullmatch(path.removeprefix(f"{ws}/")) is not None
    return False


def plain_save_operands(command: str) -> list[str] | None:
    """The file operands and redirect targets of a plain shell save, as written; None when the command is not one.

    A plain save runs only `SAVE_HEADS`, with literal words (no variable, command or process substitution, no
    assignment prefix, no `cd`, subshell or group), joined by lists and pipelines, with redirects and heredocs. A
    command after a heredoc's start on its line is read as a command too, and an unquoted heredoc's body runs its
    substitutions, so one there is not plain either. Anything else (a fetch, a send, a script, a wrapper such as
    `bash -c`) does more than save, and is scored as the ordinary command it is."""
    from ..aira.exec_shape import _parser, _unquote

    src = command.encode("utf-8", "replace")
    root = _parser().parse(src).root_node
    if root.has_error:
        return None
    operands: list[str] = []

    def text(n: Any) -> str:
        return src[n.start_byte : n.end_byte].decode("utf-8", "replace")

    def literal(n: Any) -> bool:
        if n.type in ("word", "raw_string", "number"):
            return not any(c.is_named for c in n.children)
        return n.type == "string" and all(c.type in ('"', "string_content") for c in n.children)

    def runs_nothing(n: Any) -> bool:
        if n.type in ("command_substitution", "process_substitution"):
            return False
        return all(runs_nothing(c) for c in n.children)

    def plain(n: Any) -> bool:
        t = n.type
        if t == "command":
            head, args = "", []
            for c in n.children:
                if c.type == "command_name":
                    head = text(c)
                elif literal(c):
                    args.append(_unquote(text(c)))
                else:
                    return False
            if head not in SAVE_HEADS:
                return False
            if head in _FILE_HEADS:
                operands.extend(a for a in args if not a.startswith("-"))
            return True
        if t == "file_redirect":
            named = [c for c in n.children if c.is_named and c.type != "file_descriptor"]
            if not named or not all(literal(c) for c in named):
                return False
            if not any(c.type.endswith("&") for c in n.children):  # `2>&1` names no file
                operands.append(_unquote(text(named[-1])))
            return True
        if t == "heredoc_redirect":
            # `<<'EOF'`, `<<"EOF"` and `<<\EOF` keep the body literal
            quoted = any(
                c.type == "heredoc_start" and set("'\"\\") & set(text(c)) for c in n.children
            )
            for c in n.children:
                if c.type == "heredoc_body":
                    if not quoted and not runs_nothing(c):
                        return False
                elif c.type not in ("heredoc_start", "heredoc_end") and c.is_named and not plain(c):
                    return False
            return True
        if t in _STRUCTURE:
            return all(plain(c) for c in n.children)
        return not n.is_named  # punctuation: `&&`, `;`, `|`, a newline

    return operands if plain(root) else None


def exec_store_writes(
    planir: Any, pending: Any, *, home: str | None, workspace_root: str | None
) -> list[str]:
    """The store files a declared self-edit's exec writes, when the command is a plain save into the store; empty
    otherwise, and the command is scored as the ordinary command it is.

    A plugin that cannot tell whether a command saves (OpenClaw: a background review may write a skill with a
    heredoc, `tee` or `cp`) declares every exec of a background run, and the scanner decides. The self-edit path
    judges a save, so a command takes it only when saving is all it does: a plain save (`plain_save_operands`)
    whose every file operand and redirect lies in the declared store, a temporary folder or `/dev/null`, and that
    writes at least one store file (for skills, a file inside a skill's folder, not the Workshop root). A written
    file is read as the rule-based probe reads it (`aira.detectors._written_paths`). A Code Mode cell writes only
    through the tool calls it makes, each scanned on its own."""
    from types import SimpleNamespace

    from ..aira.analysis import analyse
    from ..aira.detectors import PACK_TIER1, Context, _written_paths
    from ..aira.lists import load_lists
    from .entities import EntityTable

    platform = planir.host.platform
    store = planir.self_edit.store.value
    if pending.code_cell or not isinstance(pending.command, str):
        return []
    operands = plain_save_operands(pending.command)
    if operands is None:
        return []
    lists = load_lists()
    # what the analysis reads of a prepared request, before it is prepared
    view = SimpleNamespace(
        planir=planir, home=home, workspace_root=workspace_root, entities=EntityTable()
    )
    a = analyse(pending, view, lists)  # type: ignore[arg-type]
    cwd = a.cwd or workspace_root or ""

    def inside(p: str) -> bool:
        return in_own_store(platform, store, p, workspace_root=workspace_root)

    for raw in operands:
        path = raw if raw.startswith(("/", "~")) else f"{cwd.rstrip('/')}/{raw}"
        norm = normalise_path(path, home=home, workspace_root=workspace_root)
        if not (norm == "/dev/null" or norm.startswith(TEMP_DIRS) or inside(norm)):
            return []
    ctx = Context(prepared=view, lists=lists, packs=frozenset({PACK_TIER1}))  # type: ignore[arg-type]
    ws = (workspace_root or "").rstrip("/")
    return [
        ref.value
        for ref, _mechanism in _written_paths(a, ctx)
        if inside(ref.value) and (store != "skills" or "/" in ref.value.removeprefix(f"{ws}/"))
    ]
