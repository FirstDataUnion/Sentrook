"""File-backed plugin state under `<hermes home>/sentrook/`, so episodes survive gateway restarts and
the separate `hermes cron run` process.

- `sessions/<sid>.json`: step counter, input sequence, state token, history, input buffer
- `turns/<turn_id>.json`: turn context from `pre_llm_call` and `post_api_request`
- `reviews.json`: rule_key → (session, request id) for joining approval answers
- `grants.json`: grants and channel bindings set by command (see `grants`)
- `salt`: per-install key for placeholder refs and hashed ids

Writes are atomic (temp file then replace). One process-wide re-entrant lock serialises
read-modify-write; `session_lock` serialises a whole scan per session.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

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
    }


class Store:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.lock = threading.RLock()
        self._session_locks: dict[str, threading.Lock] = {}
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
        with self.lock:
            lock = self._session_locks.setdefault(sid, threading.Lock())
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

    def put_review(self, rule_key: str, value: dict[str, Any]) -> None:
        path = self.dir / "reviews.json"
        with self.lock:
            cur = self._read(path, {})
            cur[rule_key] = value
            if len(cur) > 500:
                cur = dict(list(cur.items())[-500:])
            self._write(path, cur)

    def pop_review(self, rule_key: str) -> dict[str, Any] | None:
        path = self.dir / "reviews.json"
        with self.lock:
            cur = self._read(path, {})
            value = cur.pop(rule_key, None)
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
        if not isinstance(data["grants"], list) or not isinstance(data["bindings"], list):
            return None
        return data

    def save_grants(self, value: dict[str, Any]) -> None:
        with self.lock:
            self._write(self.dir / "grants.json", value)
