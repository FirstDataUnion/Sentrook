"""Holds: a review on an unattended run waits for the owner instead of becoming a block.

Nobody can answer a review prompt on a cron job, a subagent, a run with approvals off or YOLO, or a
process with no terminal. There the plugin holds the call:
- the call does not run, and the agent is told it is held for the owner's approval and must not be
  retried in this run (`HELD_TEXT`);
- the owner gets one notice on the home channel of the platform in `owner_channel` (or of the only
  platform with a home channel): where the call was held, the tool and what it does, the block
  category, the scanner's suggested grant when there is one, and an approve id;
- `/sentrook approve <id>` within 24 hours sets the suggested grant as a persistent grant that ends
  after 30 days. The held call is not run again; the next run of the job is scanned with the grant.
  With no suggested grant, approving sets nothing and the reply says so.
- After 24 hours the hold expires and nothing runs. Expiry is found and recorded when the holds are
  next changed (a new hold or an approval).

A block (at the block line, or one the scanner enforces) is never held, and attended runs are
unchanged: a review there is still a review prompt.

The traffic log gets the scan with decision `held` and, later, a `resolution` record with resolution
`hold_approved` or `hold_expired`, joined by `request_id` as review answers are. Holds are kept in
`<hermes home>/sentrook/holds.json`; the OpenClaw plugin keeps the same file and prints the same
notice text.

The notice goes out through Hermes's own `send_message` tool (`ctx.dispatch_tool`, which does not run
tool hooks, so the plugin never scans its own notice), from a worker thread with an empty context: a
cron run's own delivery target is bound to the run's context, and Hermes skips a send to that target
from inside the run, which would swallow the notice when the job delivers to the home channel.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import grants
from .decision import BLOCK_CATEGORIES, block_category, review_message
from .store import Store, file_lock, read_time

logger = logging.getLogger("sentrook")

HOLD_TTL = timedelta(hours=24)
GRANT_TTL = timedelta(days=30)
MAX_HOLDS = 200
_ID = re.compile(r"h-[0-9a-f]{6}")
#: Serialises read-modify-write of the file within this process; `file_lock` does across processes.
_LOCK = threading.Lock()

HELD_TEXT = (
    "Sentrook held this tool call for the owner's approval, so it did not run. Do not retry this "
    "call in this run."
)

#: (subcommand) -> the command as the owner types it, e.g. "/sentrook approve".
Cmd = Callable[[str], str]
#: Writes one record to the traffic log.
Record = Callable[[dict[str, Any]], None]


def grant_hint(resp: dict[str, Any]) -> dict[str, Any] | None:
    """The grant the scan response suggests for this call, if any.

    Grant hints are optional: the scan response does not carry one yet, so every hold is made without
    one, and approving it sets nothing. A hold stores whatever this returns, and approval reads it with
    `grants.hint_grant`, which refuses anything that is not a plain grant."""
    return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _clean(s: Any, cap: int = 200) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


# ---- the text ---------------------------------------------------------------------------------------


def notice_text(
    resp: dict[str, Any],
    tool: str,
    where: str,
    hold_id: str,
    hint: dict[str, Any] | None,
    approve: str,
) -> str:
    """The owner's notice. `where` names the job or session, `approve` is the approve command as the
    owner types it. The review line is the one a review prompt shows; nothing more is added."""
    grant = grants.hint_grant(hint)
    if grant is not None:
        relief = (
            f"Approving sets a persistent grant for 30 days: {grants.describe_grant(grant)}, so the "
            "next run passes."
        )
    else:
        relief = (
            "Sentrook suggested no grant for this call, so approving sets nothing; the next run is "
            "scanned as before."
        )
    return "\n".join(
        (
            f"Sentrook held a tool call on an unattended run ({_clean(where)}); it did not run.",
            f"Tool: {_clean(tool, 80)}. {review_message(resp, tool)}",
            f"Held because {BLOCK_CATEGORIES[block_category(resp)]}.",
            relief,
            f"To approve within 24 hours: {approve} {hold_id}",
            "The held call is not run again either way.",
        )
    )


# ---- the file ---------------------------------------------------------------------------------------


def _live(h: Any, now: datetime) -> bool:
    if not isinstance(h, dict):
        return False
    at = read_time(h.get("expires_at"))
    return at is not None and at > now


def _sweep(data: dict[str, Any], now: datetime, record: Record) -> list[dict[str, Any]]:
    """Drops the expired holds from `data` (unreadable entries too) and records each expiry."""
    keep, gone = [], []
    for h in data["holds"]:
        (keep if _live(h, now) else gone).append(h)
    data["holds"] = keep
    for h in gone:
        if isinstance(h, dict) and isinstance(h.get("request_id"), str):
            record(
                {
                    "kind": "resolution",
                    "request_id": h["request_id"],
                    "resolution": "hold_expired",
                    "decision": "held",
                    "hold_id": h.get("id"),
                }
            )
    return [h for h in gone if isinstance(h, dict)]


def sweep(state_dir: Path, now: datetime, record: Record) -> None:
    """Records and drops every expired hold; a file that cannot be read is left alone."""
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return
        if _sweep(data, now, record):
            store.save_holds(data)


def create(
    state_dir: Path,
    *,
    request_id: str,
    session_ref: str,
    tool: str,
    where: str,
    hint: dict[str, Any] | None,
    notice: dict[str, Any],
    now: datetime,
    record: Record,
) -> str | None:
    """Stores a new hold and returns its approve id; None when the file cannot be read (the call is
    still held, but cannot be approved)."""
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return None
        _sweep(data, now, record)
        taken = {h.get("id") for h in data["holds"]}
        hid = f"h-{secrets.token_hex(3)}"
        while hid in taken:
            hid = f"h-{secrets.token_hex(3)}"
        data["holds"].append(
            {
                "id": hid,
                "request_id": request_id,
                "session_ref": session_ref,
                "tool": tool,
                "where": where,
                "held_at": _iso(now),
                "expires_at": _iso(now + HOLD_TTL),
                "hint": hint,
                "notice": notice,
            }
        )
        data["holds"] = data["holds"][-MAX_HOLDS:]
        store.save_holds(data)
        return hid


def waiting(state_dir: Path, now: datetime) -> int | None:
    """How many holds wait for the owner; None when the file cannot be read."""
    data = Store(state_dir).load_holds()
    return None if data is None else sum(1 for h in data["holds"] if _live(h, now))


def approve(
    state_dir: Path,
    rest: str,
    who: dict[str, Any],
    now: datetime,
    cmd: Cmd,
    record: Record,
) -> str:
    """`approve <id>`: sets the held call's suggested grant (if any) and records the answer."""
    hid = rest.strip()
    if not _ID.fullmatch(hid):
        return f"usage: {cmd('approve')} <id>, with the id from Sentrook's notice (h- and 6 hex digits)"
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return f"The holds file {state_dir / 'holds.json'} could not be read; fix or remove it first."
        gone = _sweep(data, now, record)
        found = next((h for h in data["holds"] if h.get("id") == hid), None)
        if found is not None:
            data["holds"].remove(found)
        if gone or found is not None:
            store.save_holds(data)
    if found is None:
        if any(h.get("id") == hid for h in gone):
            return (
                f"Held call {hid} expired: holds last 24 hours. Nothing was approved; the next run "
                "is scanned as before."
            )
        return f"No held call {_clean(hid, 40)}: the id is unknown, already answered or expired."
    grant = grants.hint_grant(found.get("hint"))
    done = {
        "kind": "resolution",
        "request_id": found.get("request_id"),
        "resolution": "hold_approved",
        "decision": "held",
        "hold_id": hid,
        "by": who,
    }
    if grant is None:
        record(done)
        return (
            f"Approved {hid}. Sentrook suggested no grant for this call, so nothing was set: the next "
            f"run is scanned as before. To let it pass, add a grant with {cmd('grant')}. The held call "
            "is not run again."
        )
    reply, change = grants.add_suggested(state_dir, grant, who, now, GRANT_TTL, hid)
    if change is None:
        record(done)
        return f"Approved {hid}, but no grant was set. {reply}"
    record({"kind": "grants", **change, "by": who})
    record({**done, "grant_id": change["entry"]["id"]})
    return f"Approved {hid}. {reply} The held call is not run again; the next run is scanned with this grant."


# ---- where the notice goes ----------------------------------------------------------------------------


def home_platforms() -> list[str]:
    """The connected platforms with a home channel, as Hermes's gateway config names them; empty when
    the config cannot be read."""
    try:
        from gateway.config import load_gateway_config

        config = load_gateway_config()
        out = []
        for p in config.get_connected_platforms():
            if config.get_home_channel(p):
                out.append(str(getattr(p, "value", p)))
        return sorted(out)
    except Exception as exc:  # noqa: BLE001 - no gateway config: no home channel
        logger.debug("home channels not readable: %s", exc)
        return []


def notice_target(owner_channel: str, homes: list[str]) -> tuple[str | None, str]:
    """(platform whose home channel gets the notice, or None; why there is none)."""
    if owner_channel:
        if owner_channel in homes:
            return owner_channel, ""
        return None, f"owner_channel {owner_channel} has no home channel"
    if len(homes) == 1:
        return homes[0], ""
    if not homes:
        return None, "no platform has a home channel; set one, or set owner_channel"
    return None, f"several platforms have a home channel ({', '.join(homes)}); set owner_channel"


def status_line(state_dir: Path, owner_channel: str, now: datetime) -> str:
    target, why = notice_target(owner_channel, home_platforms())
    count = waiting(state_dir, now)
    held = "holds file unreadable" if count is None else f"{count} waiting"
    where = f"notices to the {target} home channel" if target else f"notices not sent ({why})"
    return f"{held}; {where}"


#: Notice threads still running, so a test (or a short-lived process) can wait for them.
_threads: list[threading.Thread] = []


def _send(ctx: Any, platform: str, text: str) -> None:
    try:
        raw = ctx.dispatch_tool(
            "send_message", {"action": "send", "target": platform, "message": text}
        )
        out = json.loads(raw) if isinstance(raw, str) else raw
        if (
            not isinstance(out, dict)
            or out.get("error")
            or out.get("skipped")
            or not out.get("success")
        ):
            logger.warning(
                "sentrook hold notice to %s not delivered: %s", platform, _clean(raw, 300)
            )
    except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
        logger.warning("sentrook hold notice to %s failed: %s", platform, exc)


def deliver(ctx: Any, platform: str, text: str) -> None:
    """Sends `text` to `platform`'s home channel from a worker thread with an empty context (see the
    module note). The thread is not a daemon, so a `hermes cron run` process waits for it."""
    _threads[:] = [t for t in _threads if t.is_alive()]
    t = threading.Thread(
        target=contextvars.Context().run,
        args=(_send, ctx, platform, text),
        name="sentrook-hold-notice",
        daemon=False,
    )
    _threads.append(t)
    t.start()


def wait_for_notices(timeout: float = 10.0) -> None:
    for t in list(_threads):
        t.join(timeout)
