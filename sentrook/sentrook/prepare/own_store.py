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
- OpenClaw: a `read` or `memory_get` of `MEMORY.md` or a `.md` file directly under `memory/` at the top of the
  workspace (a relative path resolves against the workspace, as the host resolves it; a path with `$` or quotes,
  which the host reads literally, never counts). `memory_search` and `memory_get` with another corpus can return
  other sessions' transcripts or wiki pages, and `DREAMS.md` and the dreaming files under `memory/` are written from
  conversations: they keep exposure. A memory file the session's tainted set holds, under any spelling lineage may
  have recorded, is excluded by the caller.
"""

from __future__ import annotations

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
    if norm == f"{ws}/MEMORY.md":
        return norm
    rest = norm.removeprefix(f"{ws}/memory/")
    return norm if rest != norm and "/" not in rest and rest.endswith(".md") else None


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
