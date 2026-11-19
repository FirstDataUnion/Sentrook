"""Hermes's self-improvement loop: the skill and memory saves it makes on its own.

After a turn, Hermes forks a background review (and, when idle, the curator) that saves skills through
`skill_manage` and memory through `memory`. The fork runs without a request or a chat of its own, so a
scan of its save would show a write with nothing to justify it.

A loop save is recognised only from Hermes's own write origin (`tools.skill_provenance`): the origin
is `background_review` and the review is unattended (not an owner's `/refine`), and the tool is
`skill_manage` or `memory`. Any other tool the fork calls is scanned as usual. A host without that
module has no loop saves.

With `skill_review: allow` (the default) a loop save is declared as a self-edit: it is sent with trigger
`system` and a top-level `self_edit` block carrying the conversation the review read (see
`conversation.py`), and the scanner judges the save against it. `skill_review: review` sends a loop save
like any other call, without the block (a background call never reads as the owner's message: an owner
sender becomes unknown, trigger `system`). Any other value reads as allow, and status and the startup log
name it.

A loop save never asks for approval, whatever the setting, the surface or Hermes's approval settings. Nobody
can answer it: the owner's turn is over. On the local terminal Hermes's callback on the fork's thread denies
every prompt unseen; on a gateway the session's approval route is gone by the time the fork calls, so the
prompt reaches nobody; Hermes fails the curator's prompts closed. A prompt would lose the save without a word. So a
loop save is decided as an unattended run's call is, and the owner is told:
- allow: it runs;
- block: it is blocked, and the owner gets a notice (`block_notice_text`);
- review the scanner marks lenient (`lenient`), below the block line and not enforced: it runs, and the owner
  gets a notice that it was let through (`let_through_text`). `lenient` counts only on an ok scan of a save sent
  with its `self_edit` block. The same when a snooze covers the session and that session is one the owner attends
  (a chat or the terminal): unattended runs are never snoozed;
- any other review: it is held, so not saved. It is not an approvable hold in `holds.json`: the hold keeps no
  arguments and suggests no grant for a background save, so approving could not make the save, and a curator pass
  must not crowd out other runs' holds. When Hermes can replay it, the held save is staged in Hermes's own pending
  store (`staging`) and the notice gives its id and Hermes's commands to look at it and approve or reject it
  (`staged_text`); otherwise the notice says it was not saved (`stopped_text`). A destructive memory change Hermes's
  own gate stages is let through to that gate, and the notice says what Hermes did (`staged_text`, or
  `unstaged_text` when Hermes did not stage it). History and status record it;
- scan failure: as on any unattended run (`scan_error_policy`), with the scan-failure notice when it blocks.
These notices (blocked, held, staged, not staged by Hermes, let through as lenient, let through by a snooze) are sent
at most once per kind per session every 6 hours (`scan_failure_notice` keeps the times).

Every call the fork or the curator makes (a loop save or not) carries the session's last owner request
and that turn's number, and is not counted as a new turn: the fork fires no `pre_llm_call`, and the
curator's carries its own prompt, not a request. With no owner request stored it carries `REQUEST_TEXT`.

Every loop save's traffic record says `skill_review: true`, history marks it "self-edit", and
`/sentrook status` counts allowed, blocked, held, staged and let-through loop saves.

The fork's other calls, and an owner's `/refine`, can still ask. On the local terminal Hermes's callback
denies those prompts unseen (see `auto_denied`). That denial is recorded as `blocked` (a review nobody could
answer), never `denied_by_user`, its resolution says `decided_by: review_loop`, and history shows
"auto-denied by the review loop".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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
    "saving or tidying its skills and memory."
)


def in_background_review() -> bool:
    """Hermes's write origin is its background review (attended or not). Any failure to read it means no."""
    try:
        from tools.skill_provenance import get_current_write_origin

        return get_current_write_origin() == BACKGROUND_REVIEW
    except Exception:  # noqa: BLE001 - an older or different host
        return False


def auto_denied(kw: dict[str, Any], choice: str) -> bool:
    """The review loop denied an approval prompt itself, with nobody asked.

    The review fork (the automatic review and an owner's `/refine`) cannot reach the terminal, so Hermes
    gives its thread an approval callback that always says deny. The answer hook fires on that thread.
    A deny is that callback's when it came from the `cli` surface under the background-review origin,
    the thread's callback is Hermes's review auto-deny, and no gateway notifier is registered for the
    session. A gateway route (Hermes's managed local runtime) also reports `cli` but takes the prompt
    to a person, so the denial stays theirs; so does a deny from any other callback. Loop saves never ask
    (see the module note), so this covers the fork's other calls and a `/refine`'s. Any failure to read
    Hermes means no."""
    if choice != "deny" or kw.get("surface") != "cli" or not in_background_review():
        return False
    try:
        from agent.background_review import _bg_review_auto_deny
        from tools.approval import _gateway_notify_cb
        from tools.terminal_tool import _get_approval_callback

        session_key = kw.get("session_key")
        return (
            _get_approval_callback() is _bg_review_auto_deny
            and isinstance(session_key, str)
            and _gateway_notify_cb(session_key) is None
        )
    except Exception:  # noqa: BLE001 - an older or different host: the denial stays the user's
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


def lenient(resp: dict[str, Any], *, declared: bool) -> bool:
    """The scanner marks this reviewed save as one to let through without asking: `self_edit.lenient` is a JSON
    true, on a scan whose status is ok, of a save the plugin declared with its `self_edit` block (`declared`). A
    missing block or flag (an older scanner), a degraded scan, or a mark on a save sent without the block (with
    `skill_review: review`) is not lenient."""
    block = resp.get("self_edit")
    return (
        declared
        and resp.get("status") == "ok"
        and isinstance(block, dict)
        and block.get("lenient") is True
    )


def what(tool: str) -> str:
    """What a loop save saves, in the owner's words."""
    return "memory" if store_of(tool) == "memory" else "skill"


#: How the owner's notices name the run of a loop save.
RUN = "background save"


def quiet_key(outcome: str, session_ref: str) -> str:
    """What the quiet period of a loop-save notice is kept by: its kind and the session."""
    return f"background-{outcome}:session:{session_ref}"


def _save_line(tool: str, shown: str) -> str:
    from .hold import inert

    return f"Save: {inert(tool, 80)}: {inert(shown, 160)}"


def _details(details: str | None) -> list[str]:
    return [details] if details else []


def let_through_text(
    tool: str, shown: str, where: str, details: str | None, snoozed: bool = False
) -> str:
    """The owner's notice that a reviewed loop save ran without asking. Like the hold notice it may be copied into
    the agent's own transcript, so it carries only the plugin's own words, the run (`hold.where_text`, already
    inert), the tool and its description as a review prompt shows it, and the commands. `details` names where to
    read more (None when the traffic log is off)."""
    because = " because a snooze is on" if snoozed else " without asking"
    return "\n".join(
        (
            f"Sentrook let a background {what(tool)} save through{because}, though it would normally ask "
            "about a save like this.",
            f"Run: {where}",
            _save_line(tool, shown),
            *_details(details),
            f"More background saves let through in this session are not announced for {_quiet_hours()} hours.",
        )
    )


def stopped_text(
    outcome: str, tool: str, shown: str, where: str, category: str, details: str | None
) -> str:
    """The owner's notice that a loop save was blocked or held (`outcome`); `category` as the agent's block text
    names it. A held save offers no approval: approving could not make it. To keep it, the owner asks for it."""
    first = (
        f"Sentrook blocked a background {what(tool)} save, so it was not saved."
        if outcome == "blocked"
        else f"Sentrook held a background {what(tool)} save for you, so it was not saved. To keep it, ask the "
        "agent for it in a chat."
    )
    more = "More blocked background saves" if outcome == "blocked" else "More background saves held"
    return "\n".join(
        (
            first,
            f"Run: {where}",
            _save_line(tool, shown),
            f"{'Blocked' if outcome == 'blocked' else 'Held'} because {category}.",
            *_details(details),
            f"{more} in this session are not announced for {_quiet_hours()} hours.",
        )
    )


def _commands(store: str, pending_id: str, own_text: bool) -> list[str]:
    """Hermes's commands for a staged record: look first, then approve or reject. `/memory pending` lists a memory
    record by its summary, so for a record whose summary the plugin wrote it also says where the text is."""
    if store == "memory":
        look = "Look first: /memory pending" + (
            f" (it lists the change, not the text; the text is in pending/memory/{pending_id}.json in the "
            "Hermes home folder)"
            if own_text
            else ""
        )
    else:
        look = f"Look first: /skills diff {pending_id}"
    return [
        f"Pending id: {pending_id}",
        look,
        f"Then approve it: /{store} approve {pending_id}",
        f"Or reject it: /{store} reject {pending_id}",
    ]


def staged_text(
    tool: str,
    shown: str,
    where: str,
    category: str,
    rule: bool,
    store: str,
    pending_id: str,
    details: str | None,
    by_hermes: bool = False,
) -> str:
    """The owner's notice that a loop save was held and staged in Hermes's pending store (`staging`), by the plugin or
    by Hermes's own gate (`by_hermes`). Like the other notices it carries only the plugin's own words, the run, the
    tool and its description as a review prompt shows it, the pending id and the commands: never what the save
    writes. `rule`: a Sentrook rule asked for the review."""
    because = f"Held because {category}" + (
        " (a Sentrook rule asks for a review of this)." if rule else "."
    )
    return "\n".join(
        (
            f"Sentrook held a background {what(tool)} save and "
            + ("Hermes staged it" if by_hermes else "staged it in Hermes")
            + " for you to approve, so it is not saved yet.",
            f"Run: {where}",
            _save_line(tool, shown),
            because,
            *_commands(store, pending_id, own_text=not by_hermes),
            *_details(details),
            f"More staged background saves in this session are not announced for {_quiet_hours()} hours; "
            "/skills pending and /memory pending list them all.",
        )
    )


def unstaged_text(tool: str, shown: str, where: str, details: str | None, saved: bool) -> str:
    """The owner's notice that a destructive memory change Sentrook left to Hermes's own gate was not staged by it:
    Hermes saved it (`saved`), or its result did not say."""
    what_happened = (
        "but Hermes saved it without staging it."
        if saved
        else "but Hermes did not report it as staged, so it may have been saved without your approval."
    )
    return "\n".join(
        (
            f"Sentrook let a background {what(tool)} change through for Hermes to stage for your approval, "
            + what_happened,
            f"Run: {where}",
            _save_line(tool, shown),
            *_details(details),
            f"More such changes in this session are not announced for {_quiet_hours()} hours.",
        )
    )


def _quiet_hours() -> int:
    from .scan_failure_notice import QUIET

    return int(QUIET.total_seconds() // 3600)


def notice_line(owner_channel: str, homes: list[str]) -> str:
    """Where loop-save notices go, for status and verify (`homes`: the platforms with a home channel)."""
    from .hold import notice_target

    target, why = notice_target(owner_channel, homes)
    if target:
        return f"to the {target} home channel"
    why = why if owner_channel else "owner_channel is not set"
    return (
        f"cannot be delivered ({why}). Set owner_channel to a platform with a home channel: "
        "hermes config set plugins.entries.sentrook.settings.owner_channel <platform>, then /sethome in that "
        "chat. Until then background saves Sentrook lets through, holds or blocks show only in /sentrook "
        "history and the skill review counts."
    )


def counts(path: Path) -> dict[str, int]:
    """Loop saves in the recent traffic log, by what was done: allowed, blocked, asked (before loop saves stopped
    asking), held, staged (held and kept in Hermes's pending store for the owner, or sent to Hermes's own gate to
    stage), let through (a review allowed without asking: lenient, snoozed, or not staged by Hermes)."""
    from .history import action_of, recent_scans

    out = {"allowed": 0, "blocked": 0, "asked": 0, "held": 0, "staged": 0, "let_through": 0}
    for scan, resolution in recent_scans(path, 10_000, None):
        if scan.get("skill_review") is not True:
            continue
        action = action_of(scan, resolution)
        key = (
            "blocked"
            if action.startswith("blocked")
            else "asked"
            if action.startswith("review")
            else "held"
            if action.startswith("held")
            else "staged"
            if action.startswith(("staged", "sent to Hermes to stage"))
            else "let_through"
            if action.startswith(("saved", "sent to Hermes (outcome"))
            or scan.get("decision") == "allowed"
            and (scan.get("lenient") is True or scan.get("snoozed") is True)
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
    held = f", {c['held']} held" if c["held"] else ""
    staged = f", {c['staged']} staged" if c["staged"] else ""
    let = f", {c['let_through']} let through" if c["let_through"] else ""
    return (
        f"{setting}; loop saves in the traffic log: {c['allowed']} allowed, {c['blocked']} blocked"
        f"{asked}{held}{staged}{let}"
    )
