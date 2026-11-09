"""Hermes's self-improvement loop: the skill and memory saves it makes on its own.

After a turn, Hermes forks a background review (and, when idle, the curator) that saves skills through
`skill_manage` and memory through `memory`. The fork runs without a request or a chat of its own, so a
scan of its save would show a write with nothing to justify it, and where nobody can answer a review
(API server, webhook, a chat after the turn ended) a review is a block.

A loop save is recognised only from Hermes's own write origin (`tools.skill_provenance`): the origin
is `background_review` and the review is unattended (not an owner's `/refine`), and the tool is
`skill_manage` or `memory`. Any other tool the fork calls is scanned as usual. A host without that
module has no loop saves.

With `skill_review: allow` (the default) a loop save is declared as a self-edit: it is sent with trigger
`system` and a top-level `self_edit` block carrying the conversation the review read (see
`conversation.py`), and the scanner judges the save against it. Its verdict is applied like any other.
`skill_review: review` sends a loop save like any other call (the turn's own trigger, no block). Any
other value reads as allow, and status and the startup log name it.

Every call the fork or the curator makes (a loop save or not) carries the session's last owner request
and that turn's number, and is not counted as a new turn: the fork fires no `pre_llm_call`, and the
curator's carries its own prompt, not a request. With no owner request stored it carries `REQUEST_TEXT`.

Every loop save's traffic record says `skill_review: true`, and `/sentrook status` counts allowed,
blocked and asked loop saves.
"""

from __future__ import annotations

from pathlib import Path

#: The tools the loop saves through.
LOOP_TOOLS = frozenset({"skill_manage", "memory"})
#: Hermes's write origin for the review fork and the curator.
BACKGROUND_REVIEW = "background_review"
#: The `skill_review` setting: allow (default) declares loop saves as self-edits, review sends them as
#: any other call.
SETTINGS = ("allow", "review")
#: The PlanIR trigger a loop save is sent with.
TRIGGER = {"kind": "system", "channel": None, "sender": {"relation": "unknown", "basis": ["none"]}}
#: The request text a background-review call carries when the session has no owner request stored.
REQUEST_TEXT = (
    "No owner request: Hermes's background self-improvement review, "
    "saving what it learned in this session as skills or memory."
)


def in_background_review() -> bool:
    """Hermes's write origin is its background review (attended or not). Any failure to read it means no."""
    try:
        from tools.skill_provenance import get_current_write_origin

        return get_current_write_origin() == BACKGROUND_REVIEW
    except Exception:  # noqa: BLE001 - an older or different host
        return False


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


def store_of(tool: str) -> str:
    """The `self_edit.store` a loop save writes to."""
    return "memory" if tool == "memory" else "skills"


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
