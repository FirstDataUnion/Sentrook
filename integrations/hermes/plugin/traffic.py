"""Local traffic log: one JSON line per scan (the redacted PlanIR as sent and the response or failure)
and one per review resolution, joined by `request_id`. Nothing here is sent anywhere by the plugin.
Created 0600 and rotated to `<path>.1` past `max_bytes`. A write cut off mid-line (a crash, a full disk)
leaves the file without a final newline; the next record then starts with one, so it lands on its own line.

Records are kept for 30 days. A write prunes the log and its rotated file (at most once an hour per process
and log): a file holding only older records is deleted, and one that straddles the boundary is rewritten
without them, atomically. A line's age is the `ts` it starts with (a cut-off line keeps its `ts` when the
cut came after it); a line without one goes with the dated line before it (or, at the top of the file, the
first dated line after it). A file with no dated line is left alone. Most of the time the first line is
inside the window and only the start of each file is read."""

from __future__ import annotations

import calendar
import json
import logging
import os
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

logger = logging.getLogger("sentrook")

#: Records older than this are deleted from the log and its rotated file.
RETENTION_SECONDS = 30 * 24 * 3600
#: A process prunes a given log at most this often (its first write always prunes).
PRUNE_INTERVAL_SECONDS = 3600
#: How much of a file is read to see whether its first record is still inside the window.
_HEAD_BYTES = 64 * 1024

_TS = re.compile(
    rb'^\{"ts":\s*"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})"'
)

_prune_lock = threading.Lock()
_last_prune: dict[str, float] = {}


class TrafficLog:
    def __init__(
        self,
        path: Path,
        max_bytes: int,
        enabled: bool,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.enabled = enabled
        self._now = now
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        if not self.enabled:
            return
        now = self._now()
        line = json.dumps(
            {"ts": now.isoformat(timespec="milliseconds"), **record},
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
                self._maybe_prune(now.timestamp())
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(("\n" if _torn(fd) else "") + line + "\n")
        except OSError as exc:
            logger.warning("traffic log write failed: %s", exc)

    def _maybe_prune(self, now: float) -> None:
        key = str(self.path)
        with _prune_lock:
            last = _last_prune.get(key)
            if last is not None and 0 <= now - last < PRUNE_INTERVAL_SECONDS:
                return
            _last_prune[key] = now
        prune(self.path, now - RETENTION_SECONDS)


def prune(path: Path, cutoff: float) -> None:
    """Drop the records older than `cutoff` (epoch seconds) from the log at `path` and its rotated file."""
    for target in (Path(path), Path(path).with_name(Path(path).name + ".1")):
        try:
            _prune_file(target, cutoff)
        except OSError as exc:
            logger.warning("traffic log prune failed for %s: %s", target, exc)


def _prune_file(path: Path, cutoff: float) -> None:
    try:
        f = open(path, "rb")  # noqa: SIM115 - kept open for the whole rewrite below
    except FileNotFoundError:
        return
    # Every read goes through this one handle, so the bytes carried over are from the file we checked.
    with f:
        _rewrite(path, f, cutoff)


def _rewrite(path: Path, f: BinaryIO, cutoff: float) -> None:
    data = f.read(_HEAD_BYTES)
    for raw in data.split(b"\n"):
        ts = _line_ts(raw)
        if ts is not None:
            if ts >= cutoff:
                return  # the first record is inside the window
            break
    data += f.read()
    keep = _kept(data, cutoff)
    if keep is None or keep == data:
        return
    tmp = path.with_name(path.name + ".prune.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(keep)
            # Another process may have appended since the read: carry its bytes over.
            extra = f.read()
            out.write(extra)
            written = len(keep) + len(extra)
        if written == 0:
            path.unlink()
            tmp.unlink()
        else:
            os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _kept(data: bytes, cutoff: float) -> bytes | None:
    """The bytes of `data` without its lines older than `cutoff`; None when no line is dated."""
    parts = data.split(b"\n")
    # Each element but the last ended with a newline; the last is "" or a cut-off line.
    stamps = [_line_ts(p) for p in parts]
    first = next((t for t in stamps if t is not None), None)
    if first is None:
        return None
    current = first
    out = []
    for i, part in enumerate(parts):
        if stamps[i] is not None:
            current = stamps[i]
        if current >= cutoff:
            out.append(part + (b"\n" if i < len(parts) - 1 else b""))
    return b"".join(out)


def _line_ts(line: bytes) -> float | None:
    m = _TS.match(line[:64])
    if m is None:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    frac = float(b"0." + m.group(7)) if m.group(7) else 0.0
    zone = m.group(8)
    offset = (
        0
        if zone == b"Z"
        else (1 if zone[:1] == b"+" else -1) * (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60)
    )
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)) + frac - offset


def _torn(fd: int) -> bool:
    """True when the file is non-empty and does not end with a newline."""
    size = os.fstat(fd).st_size
    if size == 0:
        return False
    os.lseek(fd, size - 1, os.SEEK_SET)
    return os.read(fd, 1) != b"\n"
