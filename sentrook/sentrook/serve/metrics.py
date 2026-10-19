"""Prometheus metrics for the scan daemon. HTTP series reuse the FIDU gateway names so dashboards stay
consistent; business series are `sentrook_*`. No request content and no caller identity is exported."""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Histogram, generate_latest
from prometheus_client import Counter as PromCounter

from ..response.models import Response

CONTENT_TYPE = CONTENT_TYPE_LATEST
REGISTRY = CollectorRegistry(auto_describe=True)
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
    buckets=(5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100),
    registry=REGISTRY,
)
PROBE_STATUS = PromCounter(
    "sentrook_probe_status_total", "Probe outcomes per scan", ["step", "status"], registry=REGISTRY
)
PROBE_LATENCY = Histogram(
    "sentrook_probe_latency_seconds", "Probe latency in seconds", ["step"], registry=REGISTRY
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


def exposition() -> bytes:
    return generate_latest(REGISTRY)
