"""Prometheus metrics for the scan daemon. HTTP series reuse the FIDU gateway names so dashboards stay
consistent; business series are `sentrook_*`. No request content and no caller identity is exported."""

from __future__ import annotations

from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client import Counter as PromCounter

from ..response.models import Response

CONTENT_TYPE = CONTENT_TYPE_LATEST
REGISTRY = CollectorRegistry(auto_describe=True)
# A Jev call may take 20 s; nginx gives a scan 35 s and the plugins 30 s.
_LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 20, 25, 30, 35, 60)
_KNOWN_ENDPOINTS = frozenset({"/health", "/healthz", "/metrics", "/scan", "/testnest/scan"})

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
    buckets=_LATENCY_BUCKETS,
    registry=REGISTRY,
)
SCAN_STATUS = PromCounter(
    "sentrook_scan_status_total", "Scan responses by status", ["status"], registry=REGISTRY
)
SCAN_ENFORCED = PromCounter(
    "sentrook_scan_enforced_total",
    "Scan responses with an enforced floor outcome",
    ["enforced"],
    registry=REGISTRY,
)
SCAN_RISK = Histogram(
    "sentrook_scan_risk",
    "Risk score distribution (0-100)",
    buckets=(5, 10, 20, 30, 40, 45, 50, 60, 70, 80, 90, 100),  # 45: the review line
    registry=REGISTRY,
)
PROBE_STATUS = PromCounter(
    "sentrook_probe_status_total", "Probe outcomes per scan", ["step", "status"], registry=REGISTRY
)
PROBE_LATENCY = Histogram(
    "sentrook_probe_latency_seconds",
    "Probe latency in seconds",
    ["step"],
    buckets=_LATENCY_BUCKETS,
    registry=REGISTRY,
)
JEV_FAILING = Gauge(
    "sentrook_jev_failing",
    "1 while Jev is failing as /healthz reports it (scans are degraded), else 0",
    registry=REGISTRY,
)
JEV_CONSECUTIVE_FAILURES = Gauge(
    "sentrook_jev_consecutive_failures",
    "Jev calls failed since the last success",
    registry=REGISTRY,
)
JEV_KEY_CONFIGURED = Gauge(
    "sentrook_jev_key_configured", "1 when a Jev API key is configured, else 0", registry=REGISTRY
)


def endpoint_label(path: str) -> str:
    return path if path in _KNOWN_ENDPOINTS else "other"


def record_http(method: str, endpoint: str, status: int, seconds: float) -> None:
    HTTP_REQUESTS.labels(method=method, endpoint=endpoint, status=str(status)).inc()
    HTTP_REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(max(0.0, seconds))


def record_scan(response: Response) -> None:
    SCAN_STATUS.labels(status=response.status.value).inc()
    if response.enforced is not None:
        SCAN_ENFORCED.labels(enforced=response.enforced.value).inc()
    if response.risk is not None:
        SCAN_RISK.observe(float(response.risk))
    for probe in response.metadata.probes:
        PROBE_STATUS.labels(step=probe.step, status=probe.status.value).inc()
        if probe.latency_ms is not None:
            PROBE_LATENCY.labels(step=probe.step).observe(probe.latency_ms / 1000.0)


def record_jev(snapshot: dict[str, Any], *, key_configured: bool) -> None:
    """Copy the Jev health snapshot into gauges; called on each scrape so they never go stale."""
    JEV_FAILING.set(1 if snapshot.get("state") == "failing" else 0)
    JEV_CONSECUTIVE_FAILURES.set(snapshot.get("consecutive_failures") or 0)
    JEV_KEY_CONFIGURED.set(1 if key_configured else 0)


def exposition() -> bytes:
    return generate_latest(REGISTRY)
