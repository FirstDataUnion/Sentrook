"""Snooze: the owner's relief from review prompts, kept in `<hermes home>/sentrook/snooze.json`.

A snooze covers the session the command was sent from, or every session with `--all`, for a
duration from 1 minute to 24 hours (default 1 hour). While one applies, a review the plugin would
ask about is allowed instead; the call is still scanned and its traffic record says `snoozed: true`.
A snooze never applies to:
- a block;
- a review the scanner enforces (`enforced` is review or block);
- an unattended run, where a review stays a block;
- a scan error, or observe mode.

A session is named by its `session_ref`, the same hash a scan sends. A command with no current
session (the command line) can only snooze every session.

Expiry is mandatory: an entry with no readable expiry, or one more than 24 hours away, never applies.
A file that cannot be read relaxes nothing and is never overwritten. Expired entries are dropped on
the next change. Every change is written to the traffic log as a `snooze` record (none when the owner
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

from .planir import _h
from .store import Store, read_time

DEFAULT = timedelta(hours=1)
MAX = timedelta(hours=24)
MAX_ENTRIES = 200
_DURATION = re.compile(r"([0-9]{1,5})([mh])")
RULE = (
    "A snoozed review is allowed and logged; blocks, enforced reviews and unattended runs are "
    "never snoozed."
)
#: Serialises read-modify-write of the file within this process; writes are atomic across processes.
_LOCK = threading.Lock()

#: (subcommand) -> the command as the owner types it, e.g. "/sentrook snooze".
Cmd = Callable[[str], str]


def session_ref(sid: str) -> str:
    """The session's name in the file: the `session_ref` a scan of that session sends."""
    return f"s_{_h(sid)}"


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


def applies(resp: dict[str, Any]) -> bool:
    """A snooze may relax this review: the scanner did not enforce it."""
    return resp.get("enforced") not in ("review", "block")


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

    store = Store(state_dir)
    with _LOCK:
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
        "Blocks, enforced reviews and unattended runs are not snoozed."
    ), {"op": "set", "entry": e}
