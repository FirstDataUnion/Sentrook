"""Holds: a review on an unattended run waits for the owner instead of becoming a block.

Nobody can answer a review prompt on a cron job, a subagent, a run with approvals off or YOLO, or a
process with no terminal. There the plugin holds the call:
- the call does not run, and the agent is told it is held for the owner's approval and must not be
  retried in this run (`HELD_TEXT`);
- the owner gets one notice on the home channel of the platform in `owner_channel`: which run, the
  tool and its target as a review prompt names them, the block category, and an approve id. Hermes
  copies what `send_message` sends into the agent's own transcript, so the notice carries nothing a
  steered agent could use; the owner reads the risk, reasons and suggested grant with `why <id>`;
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
from .decision import BLOCK_CATEGORIES, block_category, describe
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


def grant_hint(resp: dict[str, Any], review_at: float | None = None) -> dict[str, Any] | None:
    """The grant the scan response suggests for this call, if any: the first of its `grant_hints` that the
    grant command would accept and (with `review_at`) that brings the call below this plugin's review line.

    Grant hints are optional: a response without one makes a hold that approving sets nothing for. A hold
    stores what this returns, and approval reads it again with `grants.hint_grant`, which refuses anything
    that is not a plain grant."""
    found = grants.response_hints(resp, review_at)
    return found[0] if found else None


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _clean(s: Any, cap: int = 200) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


#: Link, mention and code markup in chat formats (Discord and Telegram `[text](url)`, Slack
#: `<url|text>`, `@everyone`, backticks): taken out of every notice field the agent can influence.
_MARKUP = re.compile(r"[\[\]()<>|@`]")


def inert(s: Any, cap: int) -> str:
    """`s` with chat markup taken out and non-printable characters replaced, at most `cap` long."""
    return _clean(_MARKUP.sub("", str(s)), cap)


# ---- the text ---------------------------------------------------------------------------------------


def where_text(
    run: str, session_ref: str, job_id: str | None = None, job_name: str | None = None
) -> str:
    """Which run a hold belongs to: a cron job by its id, with its name quoted and labelled as the
    job's name (whoever made the job chose it, possibly the agent, so it must read as a name, never as
    an instruction), else the kind of run; then the session."""
    if job_id:
        name = (
            f", job name {json.dumps(inert(job_name, 60), ensure_ascii=False)}" if job_name else ""
        )
        return f"cron job {inert(job_id, 40)}{name}, session {session_ref}"
    return f"{run}, session {session_ref}"


def notice_text(
    resp: dict[str, Any], tool: str, where: str, hold_id: str, approve: str, why: str
) -> str:
    """The owner's notice. It may be copied into the agent's own transcript (Hermes keeps what
    `send_message` sends), so it carries only what a steered agent cannot use: that a call was held,
    which run, the tool and its target as a review prompt names them, the block category, and the ids
    and commands. The risk, reason codes, scores and entities are for the owner, through `why`."""
    return "\n".join(
        (
            "Sentrook held a tool call on an unattended run; it did not run.",
            f"Run: {_clean(where, 200)}",
            f"Tool: {inert(tool, 80)}: {inert(describe(resp, tool), 160)}",
            f"Held because {BLOCK_CATEGORIES[block_category(resp)]}.",
            f"To approve within 24 hours: {approve} {hold_id}",
            f"For the reasons: {why} {hold_id}",
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
    change: dict[str, Any] | None = None
    reply = ""
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return f"The holds file {state_dir / 'holds.json'} could not be read; fix or remove it first."
        gone = _sweep(data, now, record)
        found = next((h for h in data["holds"] if h.get("id") == hid), None)
        if found is None:
            if gone:
                store.save_holds(data)
            if any(h.get("id") == hid for h in gone):
                return (
                    f"Held call {hid} expired: holds last 24 hours. Nothing was approved; the next "
                    "run is scanned as before."
                )
            return (
                f"No held call {_clean(hid, 40)}: the id is unknown, already answered or expired."
            )
        # The grant first: when it cannot be written, the hold stays and can be approved again.
        grant = grants.hint_grant(found.get("hint"))
        if grant is not None:
            try:
                reply, change = grants.add_suggested(state_dir, grant, who, now, GRANT_TTL, hid)
            except Exception as exc:  # noqa: BLE001 - reported, and the hold is kept
                reply, change = f"The grants file could not be written ({_clean(exc, 160)}).", None
            if change is None:
                if gone:
                    store.save_holds(data)
                return f"Not approved: {reply} {hid} is still waiting; approve it again once that is fixed."
        if change is not None and not change.get("existing"):
            record({"kind": "grants", **change, "by": who})
        data["holds"].remove(found)
        try:
            store.save_holds(data)
        except Exception as exc:  # noqa: BLE001 - the grant stands; a second approve finishes
            return (
                f"Not finished: {reply} The hold could not be marked answered ({_clean(exc, 160)}); "
                f"approve {hid} again to finish."
            )
    done = {
        "kind": "resolution",
        "request_id": found.get("request_id"),
        "resolution": "hold_approved",
        "decision": "held",
        "hold_id": hid,
        "by": who,
    }
    if change is None:
        record(done)
        return (
            f"Approved {hid}. Sentrook suggested no grant for this call, so nothing was set: the next "
            f"run is scanned as before. To let it pass, add a grant with {cmd('grant')}. The held call "
            "is not run again."
        )
    record({**done, "grant_id": change["entry"]["id"]})
    return f"Approved {hid}. {reply} The held call is not run again; the next run is scanned with this grant."


def find(state_dir: Path, hold_id: str) -> dict[str, Any] | None:
    """The hold with this id while it waits; None when unknown, answered, expired or unreadable."""
    data = Store(state_dir).load_holds()
    return next(
        (
            h
            for h in (data or {}).get("holds") or []
            if isinstance(h, dict) and h.get("id") == hold_id
        ),
        None,
    )


def is_id(text: str) -> bool:
    return bool(_ID.fullmatch(text))


def why_text(state_dir: Path, log: Path, hold_id: str, now: datetime) -> str:
    """`why <hold id>`: the held call's scan as `why` shows any scan, then the hold itself."""
    from .history import format_why, recent_scans, records_backward

    rid = next(
        (
            r.get("request_id")
            for r in records_backward(log)
            if r.get("kind") == "scan"
            and isinstance(r.get("hold"), dict)
            and r["hold"].get("id") == hold_id
        ),
        None,
    )
    found = recent_scans(log, 1, lambda x: x == rid) if isinstance(rid, str) else []
    if not found:
        return f"No held call {hold_id} in the recent traffic log."
    lines = [format_why(*found[0])]
    waiting = find(state_dir, hold_id)
    if waiting is not None:
        at = read_time(waiting.get("expires_at"))
        lines.append(f"hold: waiting, until {_show(at) if at else '?'}")
        grant = grants.hint_grant(waiting.get("hint"))
        lines.append(
            "suggested grant: "
            + (f"{grants.describe_grant(grant)} (persistent, 30 days)" if grant else "none")
        )
    else:
        lines.append("hold: answered or expired")
    return "\n".join(lines)


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


NO_OWNER_CHANNEL = (
    "owner_channel is not set; set it to the platform whose home channel gets held-call notices"
)


def notice_target(owner_channel: str, homes: list[str]) -> tuple[str | None, str]:
    """(platform whose home channel gets the notice, or None; why there is none). The owner names the
    platform: a home channel is not assumed to be the owner's just because it is the only one."""
    if not owner_channel:
        return None, NO_OWNER_CHANNEL
    if owner_channel in homes:
        return owner_channel, ""
    return None, f"owner_channel {owner_channel} has no home channel"


def status_line(state_dir: Path, owner_channel: str, now: datetime) -> str:
    target, why = notice_target(owner_channel, home_platforms())
    count = waiting(state_dir, now)
    held = "holds file unreadable" if count is None else f"{count} waiting"
    where = f"notices to the {target} home channel" if target else f"notices not sent ({why})"
    return f"{held}; {where}"


#: Notice threads still running, so a test (or a short-lived process) can wait for them.
_threads: list[threading.Thread] = []


def _send(ctx: Any, platform: str, text: str, on_fail: Callable[[], None] | None = None) -> None:
    delivered = False
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
        else:
            delivered = True
    except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
        logger.warning("sentrook hold notice to %s failed: %s", platform, exc)
    if not delivered and on_fail is not None:
        try:
            on_fail()
        except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
            logger.warning("sentrook could not undo an undelivered notice: %s", exc)


def deliver(ctx: Any, platform: str, text: str, on_fail: Callable[[], None] | None = None) -> None:
    """Sends `text` to `platform`'s home channel from a worker thread with an empty context (see the
    module note). The thread is not a daemon, so a `hermes cron run` process waits for it. `on_fail`
    runs on that thread when the notice was not delivered."""
    _threads[:] = [t for t in _threads if t.is_alive()]
    t = threading.Thread(
        target=contextvars.Context().run,
        args=(_send, ctx, platform, text, on_fail),
        name="sentrook-hold-notice",
        daemon=False,
    )
    _threads.append(t)
    t.start()


def wait_for_notices(timeout: float = 10.0) -> None:
    for t in list(_threads):
        t.join(timeout)
