"""File-backed plugin state under `<hermes home>/sentrook/`, so episodes survive gateway restarts and
the separate `hermes cron run` process.

- `sessions/<sid>.json`: step counter, input sequence, state token, history, input buffer
- `turns/<turn_id>.json`: turn context from `pre_llm_call` and `post_api_request`
- `conversations/<sid>.json`: the session's recent messages and tool results, redacted, for a background
  save's `self_edit` block (see `conversation`). When one is written, at most once an hour per process,
  logs not modified in `CONVERSATION_MAX_AGE_S` are deleted and only the `CONVERSATION_KEEP` most recently
  modified are kept
- `reviews.json`: rule_key → the reviews waiting under it (session, request id), for joining approval answers
- `grants.json`: grants and channel bindings set by command (see `grants`)
- `snooze.json`: snoozes set by command (see `snooze`)
- `holds.json`: unattended reviews held for the owner's approval (see `hold`)
- `passes.json`: the passes and denials the owner's answers to held calls set (see `passes`)
- `settings.json`: where notices go and the extra attended platforms, set by command (see `owner_settings`)
- `salt`: per-install key for placeholder refs and hashed ids

Writes are atomic (temp file then replace). One process-wide re-entrant lock serialises
read-modify-write; `session_lock` serialises a whole scan per session. `holds.json`, `passes.json`, `grants.json`,
`snooze.json` and `settings.json` are also changed under `file_lock`, because the gateway and a separate process (`hermes cron run`,
`hermes sentrook`) can change them at the same time.
"""

from __future__ import annotations

import calendar
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: The only time form read back from `grants.json` and `snooze.json`; both plugins accept exactly this.
_ISO = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.[0-9]+)?)?"
    r"(?:Z|[+-]([0-9]{2}):([0-9]{2}))?"
)


def read_time(raw: Any) -> datetime | None:
    """A time from a state file: ISO with a `T`, no offset meaning UTC; anything else is unreadable.

    A field out of range (`24:00`, `12:30:60`, `02-30`, year 0, offset `+24:00`) is unreadable too, as
    it is to the OpenClaw plugin, on every Python version: `fromisoformat` alone accepts `24:00` on 3.14.
    So is a time whose UTC year is not 1-9999. Only ASCII spaces, tabs and line breaks around it are
    ignored.
    """
    text = raw.strip(" \t\r\n") if isinstance(raw, str) else ""
    m = _ISO.fullmatch(text)
    if not m:
        return None
    y, mo, d, h, mi, s, oh, om = (int(v or 0) for v in m.groups())
    if not (
        1 <= y
        and 1 <= mo <= 12
        and 1 <= d <= calendar.monthrange(y, mo)[1]
        and h <= 23
        and mi <= 59
        and s <= 59
        and oh <= 23
        and om <= 59
    ):
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    except (ValueError, OverflowError):
        return None


#: How long to wait for another process's lock before giving up. Short: a scan waits on it.
LOCK_WAIT_S = 2.0

try:  # POSIX
    import fcntl as _fcntl

    _msvcrt = None
except ImportError:  # Windows
    _fcntl = None
    import msvcrt as _msvcrt  # type: ignore[no-redef]


class LockTimeout(TimeoutError):
    """Another process held a state file's lock for longer than `LOCK_WAIT_S`."""


def _try_lock(fd: int) -> bool:
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        else:
            os.lseek(fd, 0, os.SEEK_SET)
            _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
        return True
    except OSError:
        return False


def _unlock(fd: int) -> None:
    if _fcntl is not None:
        _fcntl.flock(fd, _fcntl.LOCK_UN)
    else:
        os.lseek(fd, 0, os.SEEK_SET)
        _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Holds an OS lock on `<path>.lock` for a read-modify-write of `path`, so it is safe across
    processes (the gateway and a separate `hermes cron run` or `hermes sentrook` process), not only
    across threads. The operating system releases the lock when its process dies, so a crash leaves
    nothing to clean up; the lock file itself is kept. Raises `LockTimeout` when another process holds
    it for longer than `LOCK_WAIT_S`. The write inside stays atomic (temp file, then rename)."""
    lock = path.with_name(path.name + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + LOCK_WAIT_S
        while not _try_lock(fd):
            if time.monotonic() > deadline:
                raise LockTimeout(f"{lock} is held by another process")
            time.sleep(0.005)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


#: Conversation logs: deleted when not modified for 7 days; at most 100 kept; pruned at most hourly.
CONVERSATION_MAX_AGE_S = 7 * 86_400
CONVERSATION_KEEP = 100
CONVERSATION_PRUNE_EVERY_S = 3_600
#: When this process last pruned each state directory's conversation logs.
_PRUNED_AT: dict[str, float] = {}

_FKEY_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")


def _fkey(s: Any) -> str:
    return "".join(c if c in _FKEY_OK else "_" for c in str(s))[:120]


def empty_session() -> dict[str, Any]:
    return {
        "next_step": 1,
        "input_seq": 0,
        "token": None,
        "turns": [],
        "seen_call_ids": [],
        "history": [],
        "buffer": [],
        "last_turn_id": None,
        "last_request_turn_id": None,
    }


#: Reviews of one action waiting at once, per rule key (one per session).
REVIEWS_PER_KEY = 20


def _review_entries(value: Any) -> list[dict[str, Any]]:
    """The waiting reviews stored under one key: a list of entries (a single entry from before keys were shared
    across sessions reads as a list of one)."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [e for e in value if isinstance(e, dict)]
    return []


#: One lock per session in this process, shared by every `Store` of the same directory: a scan holds it for the
#: whole scan, and an answer to a held call takes it to set the held call's history (`hold`), so neither overwrites
#: the other's copy of the session.
_SESSION_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_SESSION_LOCKS_GUARD = threading.Lock()


class Store:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.lock = threading.RLock()
        self._salt: str | None = None

    def _read(self, path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _write(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False, default=str)
        tmp.replace(path)

    def salt(self) -> str:
        if self._salt:
            return self._salt
        path = self.dir / "salt"
        with self.lock:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except OSError:
                value = ""
            if not value:
                self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                value = secrets.token_hex(32)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(value)
            self._salt = value
            return value

    @contextmanager
    def session_lock(self, sid: str) -> Iterator[None]:
        with _SESSION_LOCKS_GUARD:
            lock = _SESSION_LOCKS.setdefault((str(self.dir), sid), threading.Lock())
        with lock:
            yield

    def load_session(self, sid: str) -> dict[str, Any]:
        with self.lock:
            s = self._read(self.dir / "sessions" / f"{_fkey(sid)}.json", None)
            return s if isinstance(s, dict) else empty_session()

    def save_session(self, sid: str, s: dict[str, Any], history_keep: int) -> None:
        s["history"] = s["history"][-history_keep:]
        s["seen_call_ids"] = s["seen_call_ids"][-2000:]
        s["turns"] = s["turns"][-2000:]
        with self.lock:
            self._write(self.dir / "sessions" / f"{_fkey(sid)}.json", s)

    def merge_turn(self, turn_id: Any, patch: dict[str, Any]) -> None:
        if not turn_id:
            return
        path = self.dir / "turns" / f"{_fkey(turn_id)}.json"
        with self.lock:
            cur = self._read(path, {"turn_id": turn_id})
            cur.update({k: v for k, v in patch.items() if v not in (None, "", [], {})})
            self._write(path, cur)

    def load_turn(self, turn_id: Any) -> dict[str, Any]:
        if not turn_id:
            return {}
        with self.lock:
            t = self._read(self.dir / "turns" / f"{_fkey(turn_id)}.json", {})
            return t if isinstance(t, dict) else {}

    def load_conversation(self, sid: str) -> list[dict[str, Any]]:
        with self.lock:
            data = self._read(self.dir / "conversations" / f"{_fkey(sid)}.json", None)
        entries = data.get("entries") if isinstance(data, dict) else None
        return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []

    def update_conversation(
        self, sid: str, change: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    ) -> None:
        """Read-modify-write of a session's conversation log under the store lock."""
        with self.lock:
            entries = change(self.load_conversation(sid))
            self._write(
                self.dir / "conversations" / f"{_fkey(sid)}.json",
                {"version": 1, "entries": entries},
            )
            self._prune_conversations()

    def _prune_conversations(self) -> None:
        """At most once an hour per process: delete logs not modified in `CONVERSATION_MAX_AGE_S`, then
        all but the `CONVERSATION_KEEP` most recently modified."""
        now = time.time()
        key = str(self.dir)
        if now - _PRUNED_AT.get(key, float("-inf")) < CONVERSATION_PRUNE_EVERY_S:
            return
        _PRUNED_AT[key] = now
        logs = []
        for path in (self.dir / "conversations").glob("*.json"):
            try:
                logs.append((path.stat().st_mtime, path))
            except OSError:
                continue
        logs.sort(reverse=True)
        for i, (mtime, path) in enumerate(logs):
            if i >= CONVERSATION_KEEP or now - mtime > CONVERSATION_MAX_AGE_S:
                path.unlink(missing_ok=True)

    def delete_conversations(self) -> bool:
        """Deletes every conversation log; True when there were any."""
        d = self.dir / "conversations"
        with self.lock:
            if not d.exists():
                return False
            for path in d.iterdir():
                path.unlink(missing_ok=True)
            d.rmdir()
            return True

    def put_review(self, rule_key: str, value: dict[str, Any]) -> None:
        """Record a review waiting for its answer under the rule key its prompt carries. The same action can be
        under review in several chats at once with one key (a key holds no session), so each key keeps a short list,
        one entry per waiting review; a newer review from the same session replaces its older one."""
        path = self.dir / "reviews.json"
        with self.lock:
            cur = self._read(path, {})
            waiting = [
                e for e in _review_entries(cur.get(rule_key)) if e.get("sid") != value.get("sid")
            ]
            cur.pop(rule_key, None)
            cur[rule_key] = [*waiting, value][-REVIEWS_PER_KEY:]
            if len(cur) > 500:
                cur = dict(list(cur.items())[-500:])
            self._write(path, cur)

    def pop_review(self, rule_key: str, sid: str | None = None) -> dict[str, Any] | None:
        """Take the waiting review an answer under `rule_key` belongs to: the one from session `sid` when the host
        names the answering session, else the oldest waiting one."""
        path = self.dir / "reviews.json"
        with self.lock:
            cur = self._read(path, {})
            waiting = _review_entries(cur.get(rule_key))
            if not waiting:
                return None
            idx = next((i for i, e in enumerate(waiting) if sid and e.get("sid") == sid), 0)
            value = waiting.pop(idx)
            if waiting:
                cur[rule_key] = waiting
            else:
                cur.pop(rule_key, None)
            self._write(path, cur)
            return value

    def load_grants(self) -> dict[str, Any] | None:
        """`grants.json`, empty when absent; None when it exists but cannot be read, so a change never
        overwrites entries it could not see."""
        path = self.dir / "grants.json"
        with self.lock:
            if not path.exists():
                return {"version": 1, "grants": [], "bindings": []}
            data = self._read(path, None)
        if not isinstance(data, dict):
            return None
        data.setdefault("grants", [])
        data.setdefault("bindings", [])
        # A key that is present must hold a list (null included): otherwise it is unreadable.
        if not isinstance(data["grants"], list) or not isinstance(data["bindings"], list):
            return None
        return data

    def save_grants(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "grants.json", value)

    def load_snooze(self) -> dict[str, Any] | None:
        """`snooze.json`, empty when absent; None when it exists but cannot be read."""
        path = self.dir / "snooze.json"
        with self.lock:
            if not path.exists():
                return {"version": 1, "snoozes": []}
            data = self._read(path, None)
        if not isinstance(data, dict):
            return None
        data.setdefault("snoozes", [])
        return data if isinstance(data["snoozes"], list) else None

    def save_snooze(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "snooze.json", value)

    def load_scan_failure_notices(self) -> dict[str, Any]:
        """When each job or session last had a scan-failure notice; empty when absent or unreadable."""
        with self.lock:
            data = self._read(self.dir / "scan-failure-notices.json", None)
        sent = data.get("sent") if isinstance(data, dict) else None
        return sent if isinstance(sent, dict) else {}

    def save_scan_failure_notices(self, sent: dict[str, str]) -> None:
        with self.lock:
            self._write(self.dir / "scan-failure-notices.json", {"version": 1, "sent": sent})

    def load_holds(self) -> dict[str, Any] | None:
        """`holds.json`, empty when absent; None when it exists but cannot be read."""
        path = self.dir / "holds.json"
        with self.lock:
            if not path.exists():
                return {"version": 1, "holds": []}
            data = self._read(path, None)
        if not isinstance(data, dict):
            return None
        data.setdefault("holds", [])
        return data if isinstance(data["holds"], list) else None

    def save_holds(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "holds.json", value)

    def load_passes(self) -> dict[str, Any] | None:
        """`passes.json`, empty when absent; None when it exists but cannot be read."""
        path = self.dir / "passes.json"
        with self.lock:
            if not path.exists():
                return {"version": 1, "passes": []}
            data = self._read(path, None)
        if not isinstance(data, dict):
            return None
        data.setdefault("passes", [])
        return data if isinstance(data["passes"], list) else None

    def save_passes(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "passes.json", value)

    def load_settings(self) -> dict[str, Any] | None:
        """`settings.json`, empty when absent; None when it exists but cannot be read."""
        path = self.dir / "settings.json"
        with self.lock:
            if not path.exists():
                return {"version": 1, "notify": None, "attended": []}
            data = self._read(path, None)
        if not isinstance(data, dict):
            return None
        data.setdefault("notify", None)
        data.setdefault("attended", [])
        if not isinstance(data["attended"], list) or not (
            data["notify"] is None or isinstance(data["notify"], dict)
        ):
            return None
        return data

    def save_settings(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "settings.json", value)

    def load_proposals(self) -> dict[str, Any] | None:
        """`proposals.json` (the agent's setup proposals), empty when absent; None when it cannot be read."""
        path = self.dir / "proposals.json"
        with self.lock:
            if not path.exists():
                return {"version": 1, "proposals": []}
            data = self._read(path, None)
        if not isinstance(data, dict):
            return None
        data.setdefault("proposals", [])
        return data if isinstance(data["proposals"], list) else None

    def save_proposals(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "proposals.json", value)

    def load_setup(self) -> dict[str, Any]:
        """`setup.json`: the setup screen last shown, its code and items; empty when absent or unreadable."""
        with self.lock:
            data = self._read(self.dir / "setup.json", None)
        return data if isinstance(data, dict) else {}

    def save_setup(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "setup.json", value)
