"""Prometheus metrics for the hosted scan daemon.

HTTP series reuse the FIDU identity/gateway names (``http_requests_total``,
``http_request_duration_seconds``) so Grafana/PromQL stay consistent; scrape
``job``/``node`` labels distinguish Sentrook. Business series are ``sentrook_*``.

Caller mix is anonymous: OIDC ``caller_id`` is SHA-256 hashed in memory and never
exported. Process restart resets the rolling windows — a rough guide only.
Shared API-key traffic is not counted (it would look like one user).
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client import (
    Counter as PromCounter,
)

CONTENT_TYPE = CONTENT_TYPE_LATEST
# Private registry so Rookery tests (same process, same metric names) do not collide.
REGISTRY = CollectorRegistry(auto_describe=True)
_WINDOWS = (("5m", 300.0), ("1h", 3600.0), ("24h", 86_400.0))
_MAX_WINDOW_SEC = 86_400.0
_KNOWN_ENDPOINTS = frozenset({"/health", "/healthz", "/scan", "/feedback", "/latency"})

HTTP_REQUESTS = PromCounter(
    "http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status"],
    registry=REGISTRY,
)
HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    registry=REGISTRY,
)
SCAN_DECISIONS = PromCounter(
    "sentrook_scan_decisions_total",
    "Scan decisions returned by the engine",
    ["decision"],
    registry=REGISTRY,
)
SCAN_MATCHED_RULES = PromCounter(
    "sentrook_scan_matched_rules_total",
    "Rules matched per scan (one increment per matched rule per request)",
    ["rule_id", "authority", "action"],
    registry=REGISTRY,
)
SCAN_WINNING_RULES = PromCounter(
    "sentrook_scan_winning_rules_total",
    "Winning rule after L2/L3 aggregate (absent when decision is allow with no matches)",
    ["rule_id", "authority", "decision"],
    registry=REGISTRY,
)
SCAN_L3_OUTCOMES = PromCounter(
    "sentrook_scan_l3_outcomes_total",
    "Per-rule L3 tie-breaker outcomes for soft reviews considered during a scan",
    ["rule_id", "outcome"],
    registry=REGISTRY,
)
SCAN_FAIL_OPEN = PromCounter(
    "sentrook_scan_fail_open_total",
    "Scan responses that failed open (HTTP 200 with error, decision forced allow)",
    registry=REGISTRY,
)
FEEDBACK = PromCounter(
    "sentrook_feedback_total",
    "Feedback handler outcomes",
    ["status"],
    registry=REGISTRY,
)
SCAN_LATENCY = Histogram(
    "sentrook_scan_latency_seconds",
    "Scan request duration in seconds (handler wall time)",
    registry=REGISTRY,
)
PLUGIN_E2E_LATENCY = Histogram(
    "sentrook_plugin_e2e_latency_seconds",
    "Plugin-reported end-to-end scan round-trip in seconds",
    registry=REGISTRY,
)
ACTIVE_CALLERS = Gauge(
    "sentrook_active_callers",
    "Distinct hashed OIDC callers observed in the rolling window (no identities)",
    ["window"],
    registry=REGISTRY,
)
TOP_CALLER_SHARE = Gauge(
    "sentrook_top_caller_share",
    "Fraction of OIDC scans from the single busiest hashed caller (0-1, approximate)",
    ["window"],
    registry=REGISTRY,
)
RULES_LOADED = Gauge(
    "sentrook_rules_loaded",
    "Number of YAIRA rules currently loaded in the warm scanner",
    registry=REGISTRY,
)
LIBRARY_SYNC_OK = Gauge(
    "sentrook_library_sync_ok",
    "1 if the last library sync/status check succeeded, else 0",
    registry=REGISTRY,
)
LIBRARY_SYNC_AGE = Gauge(
    "sentrook_library_sync_age_seconds",
    "Seconds since last successful library sync; -1 if unknown",
    registry=REGISTRY,
)


class CallerMixTracker:
    """Bounded in-memory ring of hashed OIDC callers for approximate mix gauges."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[tuple[float, str]] = []

    def observe(self, caller_id: str) -> None:
        digest = hashlib.sha256(caller_id.encode("utf-8")).hexdigest()
        now = time.monotonic()
        with self._lock:
            self._events.append((now, digest))
            self._prune_unlocked(now)

    def snapshot(self) -> dict[str, tuple[int, float]]:
        now = time.monotonic()
        with self._lock:
            self._prune_unlocked(now)
            return {label: self._stats_unlocked(now, window) for label, window in _WINDOWS}

    def hashed_ids(self) -> set[str]:
        """Test helper: in-memory hashes only, never exported on /metrics."""
        with self._lock:
            return {digest for _, digest in self._events}

    def _prune_unlocked(self, now: float) -> None:
        cutoff = now - _MAX_WINDOW_SEC
        self._events = [event for event in self._events if event[0] >= cutoff]

    def _stats_unlocked(self, now: float, window: float) -> tuple[int, float]:
        cutoff = now - window
        counts: Counter[str] = Counter(digest for ts, digest in self._events if ts >= cutoff)
        unique = len(counts)
        total = sum(counts.values())
        top_share = (max(counts.values()) / total) if total else 0.0
        return unique, top_share


def endpoint_label(path: str) -> str:
    cleaned = path.split("?", 1)[0].rstrip("/") or "/"
    if cleaned == "/healthz":
        return "/health"
    if cleaned in _KNOWN_ENDPOINTS:
        return cleaned
    return "other"


def record_http(method: str, endpoint: str, status: int, duration_seconds: float) -> None:
    if endpoint == "/metrics":
        return
    status_label = str(status)
    HTTP_REQUESTS.labels(method=method, endpoint=endpoint, status=status_label).inc()
    HTTP_REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration_seconds)


def record_scan_decision(decision: str, request_ms: int | None = None) -> None:
    SCAN_DECISIONS.labels(decision=decision).inc()
    if request_ms is not None:
        SCAN_LATENCY.observe(max(request_ms, 0) / 1000.0)


def record_scan_rule_breakdown(
    result: Any,
    *,
    authority_by_rule_id: dict[str, str] | None = None,
    default_authority: str = "hard",
) -> None:
    """Record per-rule match, winning-rule, and L3 outcome counters.

    Authority labels are resolved from the warm rule set when provided; unknown
    rules fall back to ``default_authority`` (scanner default). Rule-id cardinality
    is bounded by the shipped YAIRA library (~tens of rules), not by traffic.
    """
    auth_map = authority_by_rule_id or {}

    def _authority(rule_id: str) -> str:
        return auth_map.get(rule_id) or default_authority

    for matched in getattr(result, "matched_rules", None) or []:
        rule_id = getattr(matched, "id", None) or "unknown"
        action = getattr(matched, "action", None) or "unknown"
        SCAN_MATCHED_RULES.labels(
            rule_id=rule_id,
            authority=_authority(rule_id),
            action=action,
        ).inc()

    winning_id = getattr(result, "winning_rule_id", None)
    decision = getattr(result, "decision", None) or "unknown"
    if winning_id:
        SCAN_WINNING_RULES.labels(
            rule_id=winning_id,
            authority=_authority(winning_id),
            decision=decision,
        ).inc()

    debug = getattr(result, "debug", None)
    traces = getattr(debug, "l3_traces", None) if debug is not None else None
    for trace in traces or []:
        rule_id = getattr(trace, "rule_id", None) or "unknown"
        if not getattr(trace, "ran", False):
            outcome = "skipped"
        else:
            outcome = getattr(trace, "decision", None) or "no_change"
        SCAN_L3_OUTCOMES.labels(rule_id=rule_id, outcome=outcome).inc()


def record_fail_open() -> None:
    SCAN_FAIL_OPEN.inc()


def record_feedback(status: str) -> None:
    FEEDBACK.labels(status=status or "unknown").inc()


def record_plugin_e2e_ms(plugin_e2e_ms: int) -> None:
    PLUGIN_E2E_LATENCY.observe(max(plugin_e2e_ms, 0) / 1000.0)


def record_oidc_scan_caller(tracker: CallerMixTracker, caller_id: str | None) -> None:
    if not caller_id:
        return
    tracker.observe(caller_id)


def publish_caller_mix(tracker: CallerMixTracker) -> None:
    for window, (unique, share) in tracker.snapshot().items():
        ACTIVE_CALLERS.labels(window=window).set(unique)
        TOP_CALLER_SHARE.labels(window=window).set(share)


def refresh_from_runtime(runtime: Any) -> None:
    """Push runtime health + caller-mix gauges immediately before exposition."""
    publish_caller_mix(runtime.caller_mix)
    health = runtime.health_payload()
    RULES_LOADED.set(int(health.get("rules_loaded") or 0))
    LIBRARY_SYNC_OK.set(0.0 if health.get("last_sync_error") else 1.0)
    LIBRARY_SYNC_AGE.set(_sync_age_seconds(health.get("last_sync_at")))


def _sync_age_seconds(last_sync_at: str | None) -> float:
    if not last_sync_at:
        return -1.0
    try:
        then = datetime.fromisoformat(last_sync_at.replace("Z", "+00:00"))
    except ValueError:
        return -1.0
    if then.tzinfo is None:
        then = then.replace(tzinfo=UTC)
    return max((datetime.now(UTC) - then).total_seconds(), 0.0)


def exposition() -> bytes:
    return generate_latest(REGISTRY)


def contains_forbidden_ids(body: bytes, candidates: Iterable[str]) -> list[str]:
    text = body.decode("utf-8", errors="replace")
    return [value for value in candidates if value and value in text]
