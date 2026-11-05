"""Hermes's self-improvement loop: the skill and memory saves it makes on its own.

After a turn, Hermes forks a background review (and, when idle, the curator) that saves skills through
`skill_manage` and memory through `memory`. Those calls carry a self-modification reason, so they would
be reviewed, and where nobody can answer a review (API server, webhook, a chat after the turn ended) a
review is a block: nothing is saved and the loop stops working.

A loop save is recognised only from Hermes's own write origin (`tools.skill_provenance`): the origin
is `background_review` and the review is unattended (not an owner's `/refine`), and the tool is
`skill_manage` or `memory`. Any other tool the fork calls is scanned as usual. A host without that
module has no loop saves.

With `skill_review: allow` (the default), a loop save whose verdict is review is allowed when the
scanner did not enforce a floor, gave a skill or memory change as a reason, and gave no reason
outside `LOOP_REASONS` (the change, the system trigger, and content the agent chose). A block, an
enforced review or block, and a review with any other reason (an exposure or tainted session,
exfiltration, untrusted origin, any call-judge reason, missing coverage, anything else) are left as
they are.
The plugin never answers an approval itself. `skill_review: review` turns the relief off; any other
value reads as allow, and status and the startup log name it.

Every loop save is sent with trigger `system` (the fork otherwise inherits the owner's chat) and its
traffic record says `skill_review: true`; `/sentrook history` shows a relieved one as
`allowed (skill review)` and `/sentrook status` counts allowed and blocked loop saves.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

#: The tools the loop saves through.
LOOP_TOOLS = frozenset({"skill_manage", "memory"})
#: The finding a relieved loop save must carry: the skill or memory change itself.
SAVE_REASONS = frozenset({"selfmod.plugin", "selfmod.memory"})
#: Every reason a relieved loop save may carry: the change, plus the context any loop save has (it is
#: sent with trigger system, and the agent chose what to save).
LOOP_REASONS = SAVE_REASONS | {"trigger.system", "origin.agent_generated"}
#: Hermes's write origin for the review fork and the curator.
BACKGROUND_REVIEW = "background_review"
#: The `skill_review` setting: allow (default) relieves loop saves, review keeps the normal decision.
SETTINGS = ("allow", "review")
#: The PlanIR trigger a loop save is sent with.
TRIGGER = {"kind": "system", "channel": None, "sender": {"relation": "unknown", "basis": ["none"]}}


def is_loop_save(tool: str) -> bool:
    """`tool` is being called by Hermes's own unattended review or curator to save a skill or memory.
    Any failure to read the write origin means no."""
    if tool not in LOOP_TOOLS:
        return False
    try:
        from tools.skill_provenance import get_current_write_origin, is_unattended_review

        return get_current_write_origin() == BACKGROUND_REVIEW and is_unattended_review() is True
    except Exception:  # noqa: BLE001 - an older or different host: no loop saves
        return False


def _codes(resp: dict[str, Any]) -> list[Any]:
    reasons = resp.get("reasons")
    if not isinstance(reasons, list):
        return [None]
    return [r.get("code") if isinstance(r, dict) else None for r in reasons]


def relieves(resp: dict[str, Any]) -> bool:
    """A loop save's review may become an allow: no scanner-enforced floor, a skill or memory change
    among the reasons, and no reason outside `LOOP_REASONS`. The caller checks the verdict is review."""
    if resp.get("enforced") not in (None, "allow"):
        return False
    codes = _codes(resp)
    return any(c in SAVE_REASONS for c in codes) and all(c in LOOP_REASONS for c in codes)


def counts(path: Path) -> dict[str, int]:
    """Loop saves in the recent traffic log, by what was done: allowed, blocked, asked."""
    from .history import action_of, recent_scans

    out = {"allowed": 0, "blocked": 0, "asked": 0}
    for scan, resolution in recent_scans(path, 10_000, None):
        if scan.get("skill_review") is not True:
            continue
        action = action_of(scan, resolution)
        key = (
            "blocked"
            if action.startswith("blocked")
            else "asked"
            if action.startswith("review")
            else "allowed"
        )
        out[key] += 1
    return out


def setting_text(setting: str, unknown: str | None) -> str:
    """The setting as status shows it, naming a value that was not understood."""
    if unknown is None:
        return setting
    shown = "".join(c if c.isprintable() else "?" for c in unknown)
    return f'{setting} (unknown value "{shown}" read as allow)'


def status_line(setting: str, path: Path | None) -> str:
    """The `skill review:` line of status (`setting` as from `setting_text`); `path` is None when the
    traffic log is off."""
    if path is None:
        return f"{setting} (loop saves not counted: the traffic log is off)"
    c = counts(path)
    asked = f", {c['asked']} asked" if c["asked"] else ""
    return f"{setting}; loop saves in the traffic log: {c['allowed']} allowed, {c['blocked']} blocked{asked}"
