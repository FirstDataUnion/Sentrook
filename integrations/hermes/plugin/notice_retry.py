"""Trying an owner's notice again when Hermes could not address the chat yet.

`hermes send` reaches a chat by id only when the platform's target syntax says it is one (Telegram's numeric ids,
phone numbers, Matrix rooms and the like) or when the chat is in Hermes's channel directory. Hermes rebuilds that
directory from its sessions every few minutes, so on a platform without a target syntax (Mattermost, for one) a
chat set with `/sentrook notify here` is unknown to `hermes send` for the first minutes: the send fails with
"Could not resolve ...". Such a notice is kept here and sent again:

- only a notice to one chat (`platform:chat_id[:thread]`) that `hermes send` refused with a resolve error is kept;
  any other failure, and every notice to a home channel or through the send_message tool, is handled as before;
- it is tried again after 30 seconds, then 1, 2 and 3 minutes, and every 3 minutes after, whatever a later try
  fails with, the last time `WINDOW` (10 minutes) after the first failure;
- a kept notice to a chat that is no longer the target set by command (`notify off`, or another target since) is
  dropped unsent;
- while it waits, the target's failure record (`owner_settings.FAILED_KEY`) says so, and `notify status`, `status`
  and `verify` say it is being retried. A retry that gets through clears the record, as any notice that gets
  through does;
- when the last try fails too, the notice goes to the platform's home channel when Hermes has one for it, with a
  first line saying why, and the record says so; with no home channel, or when that send fails too, the record
  says the notice was not delivered.

The queue is `<state>/notice-retries.json`, read and written under the file's lock, so the gateway, a cron run and
the command line share it. A process sends a kept notice only after claiming it for `lease()` seconds under that lock,
so two processes never send the same one at once, and a notice is dropped from the queue as soon as one send
of it gets through, so it is never sent twice by this queue (a process that dies in the middle of a send leaves its
claim to run out, and the next try may then repeat that one). The queue keeps at most `MAX_PENDING` notices.

A notice being retried still counts as sent. The caller's `on_fail` (which lets the next notice of its kind go out,
for a scan failure or a background save) is kept in memory by the process that kept the notice, and runs only if
that same process settles it as finally not delivered; a notice kept by another process (a cron job's worker, a
command) or before a restart has none, and its kind's quiet period simply runs out.

The retries run on one daemon thread per state folder, and only in a process that keeps running: the gateway
(`hermes gateway run`) and the app backends (`hermes serve`, `hermes dashboard`, the TUI's gateway) (`long_lived`).
It never holds up a tool call, a command or the gateway's event loop. It starts with the plugin (`resume`) and keeps
watching the queue file while it is idle: every `POLL` seconds it looks at the file's size and change time (one
`stat`), and reads the queue only when the file changed or a kept notice is due. Any other process (a cron job's
worker, which a managed gateway starts for each job, `hermes sentrook status`, a one-shot chat) only writes the queue:
a send it started could be cut off when it exits, which leaves the notice claimed and then sends it again. The
watching thread finds such a notice within `POLL` seconds; the schedule and the window still count from when the
notice was first kept. `clock` and `wait` are the thread's clock and sleep, which tests replace.
"""

from __future__ import annotations

import contextvars
import functools
import json
import logging
import math
import secrets
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .store import LockTimeout, Store, file_lock

logger = logging.getLogger("sentrook")

FILE = "notice-retries.json"
#: How long after the first failure a notice is tried again, in seconds; then it goes to the home channel.
WINDOW = 600.0
#: Seconds before each try: the first after 30 seconds, then 1, 2 and 3 minutes, then every 3 minutes.
BACKOFF = (30.0, 60.0, 120.0, 180.0)
#: Seconds a claim lasts beyond the longest try, which sends twice (the chat, then the home channel) and may wait
#: on locks (`lease`).
LEASE_MARGIN = 60.0
#: Seconds between looks at the queue file while the retry thread is idle.
POLL = 30.0
MAX_PENDING = 50
#: What `hermes send` says when the chat is not one it can address yet.
RESOLVE_ERROR = "Could not resolve"
#: The first line of a notice that went to the home channel instead of the chat set by `notify here`.
FALLBACK_NOTE = (
    "Sentrook could not reach the {platform} chat where you sent /sentrook notify here, so this notice came "
    "to the {platform} home channel instead."
)

#: The retry thread's clock (seconds since the epoch) and sleep (an event to wake on, seconds); tests replace them.
clock: Callable[[], float] = time.time


def _wait(event: threading.Event, seconds: float) -> None:
    event.wait(seconds)


wait: Callable[[threading.Event, float], None] = _wait

#: Serialises read-modify-write of the file within this process; `file_lock` does across processes.
_LOCK = threading.Lock()
#: The retry thread of each state folder, and the event that wakes it.
_workers: dict[str, tuple[threading.Thread, threading.Event]] = {}
_workers_lock = threading.Lock()


#: The first word after `hermes` (and its `--profile` choice) of a process that keeps running; `gateway` only with
#: `run` or `restart` (which runs it in place without a service manager), or with nothing after it.
_LONG_LIVED = frozenset({"serve", "dashboard", "gui", "desktop"})
_GATEWAY_RUN = frozenset({"run", "restart", ""})
#: Tries at a settle that met a lock held by another process, so a sent notice is not left claimed.
SETTLE_TRIES = 3
#: The `on_fail` of each notice kept by this process, by its id.
_on_fail: dict[str, Callable[[], None]] = {}


def long_lived(argv: list[str] | None = None) -> bool:
    """Whether this process keeps running, so its retry thread is not cut off (see the module note). Read from its
    command line as Hermes's launcher passes it (`python -I -c ... gateway run` gives `-c gateway run`)."""
    args = list(sys.argv if argv is None else argv)
    first = (args[0] if args else "").replace("\\", "/")
    if first.endswith(("gateway/run.py", "tui_gateway/entry.py")):
        return True
    words, skip = [], False
    for a in args[1:]:
        if skip:
            skip = False
        elif a in ("-p", "--profile"):
            skip = True
        elif not a.startswith("-"):
            words.append(a.lower())
    if not words:
        return False
    if words[0] == "gateway":
        return (words[1] if len(words) > 1 else "") in _GATEWAY_RUN
    return words[0] in _LONG_LIVED


def lease() -> float:
    """How long a claim lasts: longer than the longest try (two sends of up to `hold.SEND_TIMEOUT` each, and lock
    waits), so another process never takes over a notice whose try is still running."""
    from .hold import SEND_TIMEOUT

    return 2 * SEND_TIMEOUT + LEASE_MARGIN


def retryable(to: str, said: str) -> bool:
    """Whether a notice to `to` that failed with `said` is kept and tried again: a chat (not a home channel) that
    `hermes send` could not resolve."""
    return ":" in to and RESOLVE_ERROR in said


def _delay(tries: int) -> float:
    return BACKOFF[min(tries, len(BACKOFF)) - 1]


def _number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _load(state_dir: Path) -> list[dict[str, Any]]:
    """The kept notices; an entry with a field of the wrong kind is left out (and so dropped on the next write)."""
    data = Store(state_dir).load_notice_retries()
    found = data.get("notices") if isinstance(data, dict) else None
    out = []
    for e in found if isinstance(found, list) else []:
        if (
            isinstance(e, dict)
            and isinstance(e.get("id"), str)
            and isinstance(e.get("to"), str)
            and ":" in e["to"]
            and isinstance(e.get("text"), str)
            and all(_number(e.get(k)) for k in ("first", "next", "tries"))
            and _number(e.get("claimed_until", 0))
        ):
            out.append(e)
    return out


def _save(state_dir: Path, notices: list[dict[str, Any]]) -> None:
    Store(state_dir).save_notice_retries({"version": 1, "notices": notices})


def _change(state_dir: Path, fn: Callable[[list[dict[str, Any]]], Any]) -> Any:
    """Applies `fn` to the queue under its lock and writes it back when it changed."""
    with _LOCK, file_lock(state_dir / FILE):
        found = Store(state_dir).load_notice_retries()
        notices = _load(state_dir)
        before = json.dumps(notices, sort_keys=True)
        out = fn(notices)
        valid = isinstance(found, dict) and found.get("notices") == notices
        if json.dumps(notices, sort_keys=True) != before or not valid:
            _save(state_dir, notices)
        return out


def keep(
    state_dir: Path,
    to: str,
    text: str,
    on_fail: Callable[[], None] | None = None,
    now: float | None = None,
) -> bool:
    """Keeps a notice to `to` that `hermes send` could not resolve, to try again (see the module note), records the
    failure for the owner's status, and starts this process's retry thread when it runs one. False when it could not
    be kept: the caller then handles the failure as before."""
    from . import owner_settings

    at = clock() if now is None else now
    nid = secrets.token_hex(6)

    def add(notices: list[dict[str, Any]]) -> None:
        notices.append(
            {"id": nid, "to": to, "text": text, "first": at, "next": at + BACKOFF[0], "tries": 1}
        )
        if len(notices) > MAX_PENDING:
            dropped = notices[: len(notices) - MAX_PENDING]
            del notices[: len(notices) - MAX_PENDING]
            logger.warning("sentrook dropped %d notices waiting to be sent again", len(dropped))
            for d in dropped:
                _finally_failed(d["id"])

    try:
        _change(state_dir, add)
    except (LockTimeout, OSError, ValueError) as exc:
        logger.warning("sentrook could not keep a notice to send again: %s", exc)
        return False
    # Kept: from here on it will be tried again whatever fails below, so the caller must not handle it as failed.
    if on_fail is not None:
        _on_fail[nid] = on_fail
    try:
        owner_settings.notice_failed(state_dir, to)
    except Exception as exc:  # noqa: BLE001 - status may say less
        logger.warning("sentrook could not record a notice kept to send again: %s", exc)
    try:
        kick(state_dir)
    except Exception as exc:  # noqa: BLE001 - the watching thread or the next start picks it up
        logger.warning("sentrook could not start the notice retries: %s", exc)
    return True


def pending(state_dir: Path, to: str) -> bool:
    """Whether a notice to `to` is waiting to be sent again."""
    try:
        return any(e["to"] == to for e in _load(state_dir))
    except (OSError, ValueError):
        return False


def _claim(state_dir: Path) -> dict[str, Any] | None:
    def take(notices: list[dict[str, Any]]) -> dict[str, Any] | None:
        now = clock()
        for e in sorted(notices, key=lambda e: e["next"]):
            if e["next"] <= now and float(e.get("claimed_until") or 0) <= now:
                e["claimed_until"] = now + lease()
                return dict(e)
        return None

    return _change(state_dir, take)


def _settle(state_dir: Path, nid: str, next_at: float | None) -> None:
    """Drops notice `nid` (`next_at` None) or sets when it is tried next. A lock another process holds is waited
    out a few times: a notice left claimed after its send would be sent again once the claim runs out."""

    def fn(notices: list[dict[str, Any]]) -> None:
        for i, e in enumerate(notices):
            if e["id"] == nid:
                if next_at is None:
                    del notices[i]
                else:
                    e.update(next=next_at, tries=int(e["tries"]) + 1, claimed_until=0)
                return

    for n in range(SETTLE_TRIES):
        try:
            _change(state_dir, fn)
            return
        except LockTimeout:
            if n == SETTLE_TRIES - 1:
                raise


def _next_due(state_dir: Path) -> float | None:
    notices = _load(state_dir)
    if not notices:
        return None
    return min(max(e["next"], float(e.get("claimed_until") or 0)) for e in notices)


def _can_send() -> bool:
    from .hold import HERMES_SEND, send_route

    return send_route(can_dispatch=False)[0] == HERMES_SEND


def _send(to: str, text: str) -> tuple[bool, str]:
    from .hold import _with_hermes_send, defuse

    return _with_hermes_send(to, defuse(text))


def _finally_failed(nid: str) -> None:
    """Runs the `on_fail` this process was given for notice `nid`, once."""
    fn = _on_fail.pop(nid, None)
    if fn is None:
        return
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
        logger.warning("sentrook could not undo an undelivered notice: %s", exc)


def _still_target(state_dir: Path, to: str) -> bool:
    from . import owner_settings

    current = owner_settings._stored_notify(owner_settings.load(state_dir))
    return current is not None and owner_settings.Notify(**current).to == to


def _try(state_dir: Path, e: dict[str, Any]) -> None:
    """One try of kept notice `e`; when it is the last and fails, the home channel (see the module note)."""
    from . import owner_settings
    from .hold import _unnamed, home_platforms, target_label

    to, text, nid = e["to"], e["text"], e["id"]
    if not _still_target(state_dir, to):
        _settle(state_dir, nid, None)
        logger.info("sentrook dropped a notice to %s: notices go elsewhere now", target_label(to))
        _finally_failed(nid)
        return
    delivered, said = _send(to, text)
    now = clock()
    if delivered:
        _settle(state_dir, nid, None)
        _on_fail.pop(nid, None)
        logger.info(
            "sentrook notice to %s delivered on try %d", target_label(to), int(e["tries"]) + 1
        )
        _bookkeep(owner_settings.notice_delivered, state_dir, to)
        return
    last = e["first"] + WINDOW
    if now < last:
        _settle(state_dir, nid, min(now + _delay(int(e["tries"]) + 1), last))
        return
    logger.warning(
        "sentrook notice to %s not delivered after %d tries: %s",
        target_label(to),
        int(e["tries"]) + 1,
        _unnamed(said, to),
    )
    # The notice stays claimed until the home channel's send returns, so status says it is still being tried.
    platform = to.partition(":")[0]
    moved = False
    if platform in home_platforms():
        moved, said = _send(platform, FALLBACK_NOTE.format(platform=platform) + "\n\n" + text)
        if not moved:
            logger.warning(
                "sentrook notice to the %s home channel not delivered either: %s", platform, said
            )
    _bookkeep(owner_settings.notice_failed, state_dir, to, home=platform if moved else None)
    _settle(state_dir, nid, None)
    if moved:
        _on_fail.pop(nid, None)
    else:
        _finally_failed(nid)


def _bookkeep(fn: Callable[..., None], *args: Any, **kw: Any) -> None:
    """Records an outcome for the owner's status; a failure here must not leave the notice claimed (it would be sent
    again once the claim runs out)."""
    try:
        fn(*args, **kw)
    except Exception as exc:  # noqa: BLE001 - status may say less
        logger.warning("sentrook could not record a kept notice's outcome: %s", exc)


def run_due(state_dir: Path) -> float | None:
    """Tries every kept notice that is due by `clock`, read afresh for each claim and after each send; returns when
    the next one is due, or None when none is kept or this process cannot send them (no `hermes send` here)."""
    if not (state_dir / FILE).exists():
        return None
    if not _can_send():
        return None
    while (e := _claim(state_dir)) is not None:
        try:
            _try(state_dir, e)
        except Exception as exc:  # noqa: BLE001 - the claim runs out and the next try picks it up
            logger.warning("sentrook could not send a kept notice again: %s", exc)
    return _next_due(state_dir)


def _seen(state_dir: Path) -> tuple[int, int] | None:
    """The queue file's change time and size, or None when there is none: what the idle thread watches."""
    try:
        st = (state_dir / FILE).stat()
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size


def _work(state_dir: Path, event: threading.Event) -> None:
    """Tries kept notices when they fall due and, while idle, looks at the queue file every `POLL` seconds for
    notices another process kept; runs until `stop`."""
    key = str(state_dir)
    seen: tuple[int, int] | None | bool = False  # nothing seen yet: read the queue once at start
    due: float | None = None
    while not _stopping.is_set():
        now_seen = _seen(state_dir)
        if event.is_set() or now_seen != seen or (due is not None and clock() >= due):
            event.clear()
            try:
                due = run_due(state_dir)
            except Exception as exc:  # noqa: BLE001 - looked at again on the next poll
                logger.warning("sentrook notice retries failed: %s", exc)
                due = None
            seen = _seen(state_dir)
        wait(event, POLL if due is None else min(POLL, max(0.0, due - clock())))
    with _workers_lock:
        if _workers.get(key, (None,))[0] is threading.current_thread():
            _workers.pop(key, None)


def _start(state_dir: Path, wake: bool) -> None:
    if not _runs_retries():
        return
    key = str(state_dir)
    with _workers_lock:
        found = _workers.get(key)
        if found is not None and found[0].is_alive():
            if wake:
                found[1].set()
            return
        event = threading.Event()
        t = threading.Thread(
            target=contextvars.Context().run,
            args=(_work, state_dir, event),
            name="sentrook-notice-retry",
            daemon=True,
        )
        _workers[key] = (t, event)
        t.start()


def kick(state_dir: Path) -> None:
    """Makes sure this process's retry thread for `state_dir` is running and looks at the queue now; nothing in a
    process that does not keep running (`long_lived`)."""
    _start(state_dir, wake=True)


@functools.cache
def _runs_retries() -> bool:
    return long_lived()


def resume(state_dir: Path) -> None:
    """Starts this process's retry thread for `state_dir` when it keeps running and the thread is not already
    there; cheap when it is (the plugin calls it at start and at each turn)."""
    try:
        _start(state_dir, wake=False)
    except Exception as exc:  # noqa: BLE001 - the next start or turn tries again
        logger.debug("sentrook notice retries not started: %s", exc)


#: Set by `stop`: the retry threads end.
_stopping = threading.Event()


def stop(timeout: float = 10.0) -> None:
    """Ends the retry threads and waits for them (tests, and a process that is shutting down)."""
    _stopping.set()
    for t, event in list(_workers.values()):
        event.set()
        t.join(timeout)
    with _workers_lock:
        _workers.clear()
    _stopping.clear()
