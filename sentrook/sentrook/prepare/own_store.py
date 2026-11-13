"""Reads of the agent's own skill library, marked in the self-edit view.

A self-edit is judged against the conversation its host process reviewed. Most `tool` entries there are content the
agent read (a page, a file, command output), whose instructions must not become standing directives. A read of the
agent's own installed skills is different: it returns procedures the agent already has and already follows, so a save
that carries them over unchanged (a curator merging near-duplicates, a review patching a skill it just viewed) adds
nothing new. The self-edit questions can only treat the two differently if they can tell them apart, and the content
cannot be trusted to say which it is, so the scanner marks such entries itself.

A read is marked only from what the host sets: the platform and the bare tool name (and, for a `new_inputs` item, a
`host` provider and an `ok` status). Any `source` key the request already carries on these entries is dropped first,
so a plugin or a tool result cannot mark itself.

Per platform:
- Hermes: `skill_view` and `skills_list` serve only installed skills (the agent's own directory, the owner's configured
  external directories, plugin and bundled skills); hub search and install are separate tools. Hermes's `memory` tool
  is left out: it writes, and its results only echo entries as a side effect.
- OpenClaw is not covered: its own-store reads are plain `read` calls whose relative paths cannot be resolved for
  entries from the owner's session, and `skill_workshop` reads include proposals nobody has approved.
"""

from __future__ import annotations

from typing import Any

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
