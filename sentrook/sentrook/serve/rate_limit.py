"""In-process token-bucket rate limiter (carried from 1.x): per caller after auth, one process, one
table. Anonymous local traffic is not limited."""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass

from .auth import ScanAuthResult

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
    if result.method == "oidc":
        caller = (result.caller_id or "").strip()
        return f"oidc:{caller}" if caller else None
    if result.method == "apikey":
        return "apikey:shared"
    return None


class MemoryTokenBucketLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str, *, rate: float, burst: int) -> RateLimitDecision:
        if rate <= 0 or burst < 1:
            return RateLimitDecision(True, 0.0, burst, max(burst, 0), key)
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
                return RateLimitDecision(True, 0.0, int(bucket.tokens), burst, key)
            return RateLimitDecision(False, (1.0 - bucket.tokens) / rate, 0, burst, key)

    def _evict_unlocked(self) -> None:
        items = sorted(self._buckets.items(), key=lambda item: item[1].updated)
        for key, _ in items[: max(1, len(items) // 2)]:
            del self._buckets[key]


def check_request(
    limiter: MemoryTokenBucketLimiter | None,
    result: ScanAuthResult,
    *,
    enabled: bool,
    rate: float,
    burst: int,
) -> RateLimitDecision | None:
    if not enabled or limiter is None:
        return None
    key = rate_limit_key(result)
    if key is None:
        return None
    return limiter.allow(f"{key}:scan", rate=rate, burst=burst)


def rate_limit_headers(decision: RateLimitDecision) -> Mapping[str, str]:
    retry = str(max(1, int(decision.retry_after_s + 0.999)))
    headers = {
        "RateLimit-Limit": str(decision.limit),
        "RateLimit-Remaining": str(decision.remaining),
        "RateLimit-Reset": retry if not decision.allowed else "0",
    }
    if not decision.allowed:
        headers["Retry-After"] = retry
    return headers
