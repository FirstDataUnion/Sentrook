"""Lightweight runtime statistics for the shadow sidecar."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from threading import Lock


def percentile(values: list[int], p: float) -> int | None:
    """Return the *p*th percentile (0–100) of integer samples."""
    if not values:
        return None
    ordered = sorted(values)
    index = int(round((p / 100.0) * (len(ordered) - 1)))
    index = max(0, min(index, len(ordered) - 1))
    return ordered[index]


@dataclass
class LatencyTracker:
    """Rolling scan latency samples for p50/p95 reporting."""

    maxlen: int = 2_000
    _samples: deque[int] = field(default_factory=deque)
    _lock: Lock = field(default_factory=Lock)

    def record(self, ms: int) -> None:
        with self._lock:
            self._samples.append(ms)
            while len(self._samples) > self.maxlen:
                self._samples.popleft()

    def snapshot(self) -> dict[str, int | None]:
        with self._lock:
            values = list(self._samples)
        if not values:
            return {
                "samples": 0,
                "p50_ms": None,
                "p95_ms": None,
                "min_ms": None,
                "max_ms": None,
            }
        return {
            "samples": len(values),
            "p50_ms": percentile(values, 50),
            "p95_ms": percentile(values, 95),
            "min_ms": min(values),
            "max_ms": max(values),
        }
