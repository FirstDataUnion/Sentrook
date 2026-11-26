"""Snooze: the owner's relief from review prompts, kept in `<hermes home>/sentrook/snooze.json`.

A snooze covers the session the command was sent from, or every session with `--all`, for a
duration from 1 minute to 24 hours (default 1 hour). While one applies, a review the plugin would
ask about is allowed instead; the call is still scanned and its traffic record says `snoozed: true`.
A snooze never allows:
- a block, or a block it turned into a review;
- a review the scanner enforces (`enforced` is review or block);
- an unattended run, where a review stays a block;
- a scan error, or observe mode.

Hermes's own background skill and memory saves (`skill_review`) never ask. One whose review would otherwise be
held is allowed when a snooze covers its session (or every session) and that session is one the owner attends (a
chat platform, the local terminal or a platform in `attended_platforms`; never the curator, a webhook, the API
server or an unknown platform, whatever stdin is), under the same rules: never a block, an enforced review or one at the block line, and never
after an unattended run. The owner gets a notice that it was let through.

In a chat the owner attends, a snooze also turns a block the scanner marks `relaxable` (the owner attends,
nothing independent points to an attack and nothing is enforced: the score alone blocks) into a review. It is
allowed without asking only where the owner answered Session or Always for the same action while the same
snoozes covered the session.

Beta (`BLOCKS_ASK`): in a chat the owner attends, a snooze turns every other block into a review too: a block with a
floor, a strong signal or `enforced: block`, from an older scanner too. Its card warns, naming the reason it would be
blocked, and says to allow it only for exactly the call the owner asked for. It is never allowed silently: its rule
key is the call's own, so Hermes's Session and Always answers allow that call only. Attended here is what the
scanner's attended-owner check reads from the request (`owner_attends`): the owner's own message on the main agent,
outside a group chat or a host open to anyone, on a chat the plugin could tell apart. A change to Sentrook itself (a
`guardrail_tampering` floor that blocks: a write into its state folder, turning the plugin off, a Sentrook command
only the owner runs) stays a block: a snooze is never a way for the agent to switch Sentrook off. With `BLOCKS_ASK`
off, only a block marked `relaxable` asks.

A session is named by its `session_ref`, the same hash a scan sends. A command with no current
session (the command line) can only snooze every session.

Expiry is mandatory: an entry with no readable expiry, or one more than 24 hours away, never applies.
A file that cannot be read relaxes nothing and is never overwritten. Expired entries are dropped on
the next change. A change holds the file's cross-process lock, because the gateway, a `hermes cron run`
process and the command line can change it at the same time; when another process keeps the lock
longer than the wait, nothing is changed and the owner is told to try again. Every change is written to the traffic log as a `snooze` record (none when the owner
has turned the traffic log off). The OpenClaw plugin keeps the same file format and prints the same
text.
"""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .planir import session_ref as session_ref  # what an entry is keyed on
from .store import LockTimeout, Store, file_lock, read_time

DEFAULT = timedelta(hours=1)
MAX = timedelta(hours=24)
MAX_ENTRIES = 200
_DURATION = re.compile(r"([0-9]{1,5})([mh])")
#: Beta: during a snooze, every block in a chat the owner attends asks, with a warning, except a change to Sentrook
#: itself. False: only a block the scanner marks `relaxable` asks; every other block stays a block.
BLOCKS_ASK = True
RULE = (
    (
        "A snoozed review is allowed and logged. In beta, a block in a chat you attend asks you instead, "
        "with a warning; a change to Sentrook itself stays blocked, and enforced reviews and unattended "
        "runs are never snoozed."
    )
    if BLOCKS_ASK
    else (
        "A snoozed review is allowed and logged. A block with no clear attack signal asks you instead; "
        "other blocks, enforced reviews and unattended runs are never snoozed."
    )
)
#: The tail of the reply to a snooze that was set.
SET_RULE = (
    (
        "In beta, blocks in a chat you attend ask you instead, with a warning; changes to Sentrook "
        "itself stay blocked, and enforced reviews and unattended runs are not snoozed."
    )
    if BLOCKS_ASK
    else (
        "Blocks with no clear attack signal ask you instead; other blocks, enforced reviews and "
        "unattended runs are not snoozed."
    )
)
#: Sender bases of a room others can write to, and bases that say nothing about how the sender was known.
_SHARED_BASIS = frozenset({"group_chat", "host_open_access"})
_NO_BASIS = frozenset({"none", "unknown"})
#: Serialises read-modify-write of the file within this process; `file_lock` does across processes.
_LOCK = threading.Lock()

#: (subcommand) -> the command as the owner types it, e.g. "/sentrook snooze".
Cmd = Callable[[str], str]


def load(state_dir: Path) -> dict[str, Any] | None:
    """The file's contents; empty when there is no file, None when it cannot be read."""
    return Store(state_dir).load_snooze()


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _left(span: timedelta) -> str:
    minutes = max(1, math.ceil(span.total_seconds() / 60))
    h, m = divmod(minutes, 60)
    return " ".join(p for p in (f"{h}h" if h else "", f"{m}m" if m else "") if p)


def _clean(s: Any, cap: int = 40) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


def _live(e: Any, now: datetime) -> datetime | None:
    """The entry's expiry while it applies: a known scope and an expiry within the next 24 hours."""
    if not isinstance(e, dict):
        return None
    if e.get("scope") == "session":
        if not isinstance(e.get("session_ref"), str) or not e["session_ref"]:
            return None
    elif e.get("scope") != "all":
        return None
    at = read_time(e.get("expires_at"))
    return at if at is not None and now < at <= now + MAX else None


def _entries(data: dict[str, Any] | None, now: datetime) -> list[tuple[dict[str, Any], datetime]]:
    return [(e, at) for e in (data or {}).get("snoozes") or [] if (at := _live(e, now))]


def _applies_to(e: dict[str, Any], ref: str | None) -> bool:
    return e["scope"] == "all" or (ref is not None and e.get("session_ref") == ref)


def active(data: dict[str, Any] | None, ref: str, now: datetime) -> bool:
    """Whether a snooze covers the session `ref` now."""
    return any(_applies_to(e, ref) for e, _ in _entries(data, now))


def covering(data: dict[str, Any] | None, ref: str, now: datetime) -> str:
    """The snoozes covering the session `ref` now, as one string: a new or replaced snooze gives a new one."""
    return "|".join(
        sorted(
            f"{e['scope']}:{e.get('session_ref') or ''}:{e.get('expires_at')}"
            for e, _ in _entries(data, now)
            if _applies_to(e, ref)
        )
    )


def applies(resp: dict[str, Any], block_at: float) -> bool:
    """A snooze may relax this review: the scanner did not enforce it, and its score is under the block line (a
    block the scanner's ceiling lowered to a review always asks)."""
    if resp.get("enforced") in ("review", "block"):
        return False
    return float(resp.get("risk") or 0) < block_at


def relaxes(resp: dict[str, Any], verdict: str) -> bool:
    """A snooze in a chat the owner attends turns this block into a review: the block comes from
    the score and the scanner marks it `relaxable` (only a JSON true counts; an older scanner sends none)."""
    return (
        verdict == "block"
        and resp.get("relaxable") is True
        and resp.get("enforced") not in ("review", "block")
    )


def owner_attends(planir: dict[str, Any]) -> bool:
    """The owner is in the conversation, as the scanner's attended-owner check reads the request: a message turn from
    the owner on the main agent, outside a group chat or a host open to anyone, on a basis that says how the plugin
    knows (not `none` alone), and no host background process behind the call (`self_edit`)."""
    trig = planir.get("trigger") if isinstance(planir.get("trigger"), dict) else {}
    sender = trig.get("sender") if isinstance(trig.get("sender"), dict) else {}
    session = planir.get("session") if isinstance(planir.get("session"), dict) else {}
    basis = {b for b in sender.get("basis") or [] if isinstance(b, str)}
    return (
        trig.get("kind") == "message"
        and sender.get("relation") == "owner"
        and session.get("agent_role") == "main"
        and not basis & _SHARED_BASIS
        and bool(basis - _NO_BASIS)
        and planir.get("self_edit") is None
    )


def tampering(resp: dict[str, Any]) -> bool:
    """The call changes Sentrook itself at the blocking tier: a `guardrail_tampering` floor that does not only ask
    (`enforce` review), or a reason that says so. The guardrail's review tier is not this: it asks already."""
    for f in resp.get("floors_applied") or []:
        if (
            isinstance(f, dict)
            and f.get("floor") == "guardrail_tampering"
            and f.get("enforce") != "review"
        ):
            return True
    for r in resp.get("reasons") or []:
        code = r.get("code") if isinstance(r, dict) else None
        if not isinstance(code, str):
            continue
        if code == "floor.guardrail_tampering":
            detail = r.get("detail") if isinstance(r.get("detail"), dict) else {}
            behind = detail.get("reason")
            if not (isinstance(behind, str) and behind.endswith("_review")):
                return True
        elif code.startswith("guardrail.") and not code.endswith("_review"):
            return True
    return False


def asks(resp: dict[str, Any], verdict: str, planir: dict[str, Any]) -> str | None:
    """What a snooze in a session on a run the owner attends does with this verdict: `relaxed` for a block the
    scanner marks `relaxable` (today's question), `strong` for any other block in the owner's own chat (`BLOCKS_ASK`;
    the card warns and nothing allows it silently), None where it stays as it is (not a block, a change to Sentrook
    itself, another sender or a shared room, or `BLOCKS_ASK` off). The caller checks the snooze, the run and the
    mode."""
    if verdict != "block":
        return None
    if relaxes(resp, verdict):
        return "relaxed"
    if BLOCKS_ASK and not tampering(resp) and owner_attends(planir):
        return "strong"
    return None


# ---- status -----------------------------------------------------------------------------------------


def format_status(data: dict[str, Any] | None, ref: str | None, now: datetime) -> str:
    """`snooze status`, as seen from the session `ref` (None: no current session)."""
    if data is None:
        return f"The snooze file could not be read, so no snooze applies.\n{RULE}"
    live = _entries(data, now)
    lines = []
    here = next((at for e, at in live if e["scope"] == "session" and e["session_ref"] == ref), None)
    every = max((at for e, at in live if e["scope"] == "all"), default=None)
    if here:
        lines.append(f"Snooze: on in this session until {_show(here)} ({_left(here - now)} left)")
    if every:
        lines.append(
            f"Snooze: on in every session until {_show(every)} ({_left(every - now)} left)"
        )
    if not here and not every:
        lines.append("Snooze: off")
    others = len({e["session_ref"] for e, _ in live if e["scope"] == "session"} - {ref})
    if others:
        lines.append(f"{'Other sessions' if ref else 'Sessions'} snoozed: {others}")
    lines.append(RULE)
    return "\n".join(lines)


def status_line(data: dict[str, Any] | None, now: datetime) -> str:
    """The `snooze:` line of status."""
    if data is None:
        return "unreadable, none applies"
    live = _entries(data, now)
    parts = []
    every = max((at for e, at in live if e["scope"] == "all"), default=None)
    if every:
        parts.append(f"every session until {_show(every)}")
    n = len({e["session_ref"] for e, _ in live if e["scope"] == "session"})
    if n:
        parts.append(f"{n} session{'' if n == 1 else 's'}")
    return ", ".join(parts) or "off"


# ---- changes ------------------------------------------------------------------------------------------


def usage(cmd: Cmd) -> str:
    c = cmd("snooze")
    return (
        f"usage: {c} [duration] [--all], {c} off [--all] or {c} status\n"
        "duration is 1m to 24h (default 1h); a snooze covers this session unless --all; off ends the "
        "snoozes that apply here (this session's and an --all one), off --all ends every snooze"
    )


def parse(rest: str) -> dict[str, Any] | str:
    """The snooze typed after `snooze`, or the reason it is refused ("" for a plain usage error)."""
    words = rest.split()
    every = "--all" in words
    words = [w for w in words if w != "--all"]
    for w in words:
        if w.startswith("--"):
            return f"Unknown option {_clean(w)}."
    if len(words) > 1:
        return ""
    arg = words[0].lower() if words else ""
    if arg in ("off", "status"):
        return {"op": arg, "all": every}
    if not arg:
        return {"op": "set", "all": every, "span": DEFAULT, "text": "1h"}
    m = _DURATION.fullmatch(arg)
    span = (
        timedelta(**{"minutes" if m.group(2) == "m" else "hours": int(m.group(1))}) if m else None
    )
    if span is None or not timedelta(minutes=1) <= span <= MAX:
        return f'Unknown duration "{_clean(arg)}": use a number with m or h, from 1m to 24h.'
    return {"op": "set", "all": every, "span": span, "text": arg}


def _no_session(cmd: Cmd) -> str:
    return (
        "There is no current session here, so a snooze cannot be bound to one; "
        f"use {cmd('snooze')} --all to snooze every session."
    )


def run(
    state_dir: Path,
    rest: str,
    ref: str | None,
    by: dict[str, Any],
    now: datetime,
    cmd: Cmd,
) -> tuple[str, dict[str, Any] | None]:
    """`snooze ...` from the session `ref` (None: no current session): the reply and the change
    record for the traffic log, or None when nothing changed."""
    parsed = parse(rest)
    if isinstance(parsed, str):
        return (f"{parsed}\n{usage(cmd)}" if parsed else usage(cmd)), None
    if parsed["op"] == "status":
        return format_status(load(state_dir), ref, now), None
    if parsed["op"] == "set" and not parsed["all"] and ref is None:
        return _no_session(cmd), None

    try:
        with _LOCK, file_lock(state_dir / "snooze.json"):
            reply, record = _change(Store(state_dir), state_dir, parsed, ref, by, now)
    except LockTimeout:
        return (
            f"The snooze file {state_dir / 'snooze.json'} is locked by another process; "
            "no snooze was changed. Try again."
        ), None
    return reply, record


def _change(
    store: Store,
    state_dir: Path,
    parsed: dict[str, Any],
    ref: str | None,
    by: dict[str, Any],
    now: datetime,
) -> tuple[str, dict[str, Any] | None]:
    """The change `parsed` asks for, read and written while the caller holds the file's locks."""
    data = store.load_snooze()
    if data is None:
        return (
            f"The snooze file {state_dir / 'snooze.json'} could not be read; "
            "fix or remove it first."
        ), None
    kept = [e for e in data["snoozes"] if _live(e, now)]
    if parsed["op"] == "off":
        every = parsed["all"] or ref is None
        ended = [e for e in kept if every or _applies_to(e, ref)]
        if not ended:
            return "No snooze was on.", None
        data["snoozes"] = [e for e in kept if not any(e is x for x in ended)]
        store.save_snooze(data)
        n = len(ended)
        return f"Snooze off: ended {n} snooze{'' if n == 1 else 's'}.", {
            "op": "off",
            "entries": ended,
        }
    e: dict[str, Any] = {"scope": "all" if parsed["all"] else "session"}
    if not parsed["all"]:
        e["session_ref"] = ref
    e.update(set_at=iso(now), expires_at=iso(now + parsed["span"]), set_by=by)
    kept = [
        x
        for x in kept
        if not (x["scope"] == e["scope"] and x.get("session_ref") == e.get("session_ref"))
    ]
    data["snoozes"] = [*kept, e][-MAX_ENTRIES:]
    store.save_snooze(data)
    where = "in every session" if parsed["all"] else "in this session"
    return (
        f"Snoozed reviews {where} for {parsed['text']}, until {_show(now + parsed['span'])}. "
        f"{SET_RULE}"
    ), {"op": "set", "entry": e}
