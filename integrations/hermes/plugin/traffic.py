"""Local traffic log: one JSON line per scan (the redacted PlanIR as sent and the response or failure)
and one per review resolution, joined by `request_id`. Nothing here is sent anywhere by the plugin.
Created 0600 and rotated to `<path>.1` past `max_bytes`. A write cut off mid-line (a crash, a full disk)
leaves the file without a final newline; the next record then starts with one, so it lands on its own line."""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentrook")


class TrafficLog:
    def __init__(self, path: Path, max_bytes: int, enabled: bool) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.enabled = enabled
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        if not self.enabled:
            return
        line = json.dumps(
            {"ts": datetime.now(UTC).isoformat(timespec="milliseconds"), **record},
            ensure_ascii=False,
            default=str,
        )
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                try:
                    if self.path.stat().st_size > self.max_bytes:
                        self.path.replace(self.path.with_name(self.path.name + ".1"))
                except FileNotFoundError:
                    pass
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(("\n" if _torn(fd) else "") + line + "\n")
        except OSError as exc:
            logger.warning("traffic log write failed: %s", exc)


def _torn(fd: int) -> bool:
    """True when the file is non-empty and does not end with a newline."""
    size = os.fstat(fd).st_size
    if size == 0:
        return False
    os.lseek(fd, size - 1, os.SEEK_SET)
    return os.read(fd, 1) != b"\n"
