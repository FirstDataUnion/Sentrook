"""Whether Jev is answering, as `/healthz` reports it.

`TrackedDecider` wraps the scanner's decider and records the outcome of every Jev call (one `decide()`, after
the client's own retries) in a `JevHealth`. A success clears any failure run. Within a run of failures, Jev is
`failing` once it holds `AUTH_FAILURES_TO_FAIL` auth or credit refusals (401, 402, 403), which do not heal on
their own, or `FAILURES_TO_FAIL` failures of any counted kind (timeouts, network errors, 5xx, 429). Other client
errors, such as a request over the context limit, say nothing about Jev itself and are not counted.

Without a configured key every call is refused, which is expected: the run is still counted, but the state is
not reported as `failing`. The change into `failing` and the recovery are each logged once, with the HTTP status
and never the key or the response body.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from .client import RETRY_STATUSES, ApiError, Decider, DecisionResult

logger = logging.getLogger("sentrook.jev")

AUTH_STATUSES = frozenset({401, 402, 403})
AUTH_FAILURES_TO_FAIL = 3
FAILURES_TO_FAIL = 10


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _failure_status(exc: ApiError) -> int | str:
    if exc.status is not None:
        return exc.status
    return "timeout" if exc.timeout else "network"


def _describe(status: int | str | None) -> str:
    return f"HTTP {status}" if isinstance(status, int) else str(status)


def _counts(exc: ApiError) -> bool:
    return (
        exc.status is None
        or exc.status in AUTH_STATUSES
        or exc.status in RETRY_STATUSES
        or exc.status >= 500
    )


class JevHealth:
    """Outcome of the last Jev calls. Thread-safe: scans run on the server's request threads."""

    def __init__(self, *, key_configured: bool):
        self.key_configured = key_configured
        self._lock = threading.Lock()
        self._last_success_at: str | None = None
        self._last_failure_at: str | None = None
        self._last_failure_status: int | str | None = None
        self._consecutive_failures = 0
        self._auth_failures = 0
        self._failing = False

    def record_success(self) -> None:
        with self._lock:
            run, was_failing = self._consecutive_failures, self._failing
            last = self._last_failure_status
            self._last_success_at = _now()
            self._consecutive_failures = self._auth_failures = 0
            self._failing = False
        if was_failing:
            logger.warning("Jev recovered after %d failed calls, last %s", run, _describe(last))

    def record_failure(self, exc: ApiError) -> None:
        if not _counts(exc):
            return
        status = _failure_status(exc)
        with self._lock:
            self._last_failure_at = _now()
            self._last_failure_status = status
            self._consecutive_failures += 1
            if exc.status in AUTH_STATUSES:
                self._auth_failures += 1
            started = (
                not self._failing
                and self.key_configured
                and (
                    self._auth_failures >= AUTH_FAILURES_TO_FAIL
                    or self._consecutive_failures >= FAILURES_TO_FAIL
                )
            )
            if started:
                self._failing = True
            run = self._consecutive_failures
        if started:
            logger.warning(
                "Jev is failing: %d consecutive failed calls, last %s; scans are degraded until it recovers",
                run,
                _describe(status),
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": "failing" if self._failing else "ok",
                "consecutive_failures": self._consecutive_failures,
                "last_success_at": self._last_success_at,
                "last_failure_at": self._last_failure_at,
                "last_failure_status": self._last_failure_status,
            }


class TrackedDecider:
    """A decider that records each call's outcome in a `JevHealth` and otherwise behaves as the one it wraps."""

    def __init__(self, inner: Decider, health: JevHealth):
        self.inner = inner
        self.health = health

    def decide(self, body: dict[str, Any], *, repeat: int | None = None) -> DecisionResult:
        try:
            result = self.inner.decide(body, repeat=repeat)
        except ApiError as exc:
            self.health.record_failure(exc)
            raise
        self.health.record_success()
        return result
