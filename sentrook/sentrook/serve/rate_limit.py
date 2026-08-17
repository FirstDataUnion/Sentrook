"""In-process token-bucket rate limiter for hosted ``sentrook serve``.

Per-user fairness after JWT verify. Not a shared store — one process, one table.
Swap :class:`MemoryTokenBucketLimiter` later if replicas need Redis.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass

from sentrook.serve.auth import ScanAuthResult

_MAX_BUCKETS = 10_000


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_s: float
    remaining: int
    limit: int
    key: str


@dataclass
class _Bucket:
    tokens: float
    updated: float
    rate: float
    burst: int


def rate_limit_key(result: ScanAuthResult) -> str | None:
    """Stable limiter key, or None to skip (anonymous local sidecar)."""
    if result.method == "oidc":
        caller = (result.caller_id or "").strip()
        return f"oidc:{caller}" if caller else None
    if result.method == "apikey":
        return "apikey:shared"
    return None


def aux_route(path: str) -> bool:
    return path.rstrip("/") in ("/feedback", "/latency")


class MemoryTokenBucketLimiter:
    """Thread-safe token buckets keyed by caller id (or shared API key)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str, *, rate: float, burst: int) -> RateLimitDecision:
        if rate <= 0 or burst < 1:
            return RateLimitDecision(
                allowed=True, retry_after_s=0.0, remaining=burst, limit=max(burst, 0), key=key
            )
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or bucket.rate != rate or bucket.burst != burst:
                bucket = _Bucket(tokens=float(burst), updated=now, rate=rate, burst=burst)
                if len(self._buckets) >= _MAX_BUCKETS:
                    self._evict_unlocked()
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(float(burst), bucket.tokens + elapsed * rate)
            bucket.updated = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                remaining = int(bucket.tokens)
                return RateLimitDecision(
                    allowed=True,
                    retry_after_s=0.0,
                    remaining=remaining,
                    limit=burst,
                    key=key,
                )
            retry = (1.0 - bucket.tokens) / rate
            return RateLimitDecision(
                allowed=False,
                retry_after_s=retry,
                remaining=0,
                limit=burst,
                key=key,
            )

    def _evict_unlocked(self) -> None:
        # Drop the oldest half when the map fills (abuse / many distinct callers).
        items = sorted(self._buckets.items(), key=lambda item: item[1].updated)
        for key, _bucket in items[: max(1, len(items) // 2)]:
            del self._buckets[key]


def check_request(
    limiter: MemoryTokenBucketLimiter | None,
    result: ScanAuthResult,
    path: str,
    *,
    enabled: bool,
    scan_rate: float,
    scan_burst: int,
    aux_rate: float,
    aux_burst: int,
) -> RateLimitDecision | None:
    if not enabled or limiter is None:
        return None
    key = rate_limit_key(result)
    if key is None:
        return None
    if aux_route(path):
        return limiter.allow(f"{key}:aux", rate=aux_rate, burst=aux_burst)
    return limiter.allow(f"{key}:scan", rate=scan_rate, burst=scan_burst)


def retry_after_header(seconds: float) -> str:
    return str(max(1, int(seconds + 0.999)))


def rate_limit_headers(decision: RateLimitDecision) -> Mapping[str, str]:
    reset = retry_after_header(decision.retry_after_s) if not decision.allowed else "0"
    headers = {
        "RateLimit-Limit": str(decision.limit),
        "RateLimit-Remaining": str(decision.remaining),
        "RateLimit-Reset": reset,
    }
    if not decision.allowed:
        headers["Retry-After"] = retry_after_header(decision.retry_after_s)
    return headers
