"""`/metrics` carries what prod alerting needs: whether Jev is answering, and a risk bucket at the review line.

No request content and no caller identity may appear in any series.
"""

from __future__ import annotations

import re

import httpx
from test_jev_health import API_KEY, KEY, _unauthorized
from test_jev_probes import ATTACK_ANSWERS, FakeDecider

from sentrook.jev.health import AUTH_FAILURES_TO_FAIL
from sentrook.serve.config import ServeConfig
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import ScanServer


def _serve(decider, **config):
    cfg = ServeConfig(state_key=KEY, test_mode=True, scan_auth_mode="open", **config)
    srv = ScanServer(ServeRuntime.build(cfg, decider=decider), host="127.0.0.1", port=0)
    srv.start()
    return srv


def _sample(text: str, name: str) -> float:
    m = re.search(rf"^{re.escape(name)} (\S+)$", text, re.MULTILINE)
    assert m, f"{name} not exported"
    return float(m.group(1))


# --- must fire -------------------------------------------------------------------------------------------


def test_jev_failing_is_exported_as_a_gauge(attack_case):
    srv = _serve(FakeDecider(error=_unauthorized()), jev_api_key=API_KEY)
    try:
        with httpx.Client(base_url=srv.url) as c:
            assert _sample(c.get("/metrics").text, "sentrook_jev_failing") == 0
            for _ in range(AUTH_FAILURES_TO_FAIL):
                c.post("/scan", json=attack_case["fixture"])
            text = c.get("/metrics").text
            assert _sample(text, "sentrook_jev_failing") == 1
            assert _sample(text, "sentrook_jev_consecutive_failures") >= AUTH_FAILURES_TO_FAIL
            assert _sample(text, "sentrook_jev_key_configured") == 1
    finally:
        srv.stop()


def test_risk_histogram_has_a_bucket_at_the_review_line():
    srv = _serve(FakeDecider(ATTACK_ANSWERS))
    try:
        with httpx.Client(base_url=srv.url) as c:
            assert 'sentrook_scan_risk_bucket{le="45.0"}' in c.get("/metrics").text
    finally:
        srv.stop()


# --- must stay silent ------------------------------------------------------------------------------------


def test_healthy_jev_reads_zero_and_missing_key_is_not_failing(attack_case):
    srv = _serve(FakeDecider(error=_unauthorized()))  # no key configured
    try:
        with httpx.Client(base_url=srv.url) as c:
            for _ in range(AUTH_FAILURES_TO_FAIL):
                c.post("/scan", json=attack_case["fixture"])
            text = c.get("/metrics").text
            assert _sample(text, "sentrook_jev_failing") == 0
            assert _sample(text, "sentrook_jev_key_configured") == 0
    finally:
        srv.stop()


def test_no_request_content_or_caller_identity_in_series(attack_case):
    srv = _serve(FakeDecider(ATTACK_ANSWERS), jev_api_key=API_KEY)
    try:
        with httpx.Client(base_url=srv.url) as c:
            c.post("/scan", json=attack_case["fixture"], headers={"X-Forwarded-For": "203.0.113.9"})
            text = c.get("/metrics").text
    finally:
        srv.stop()
    assert API_KEY not in text and "203.0.113.9" not in text and "127.0.0.1" not in text
    labels = set(re.findall(r"(\w+)=\"", text))
    assert labels <= {
        "method",
        "endpoint",
        "status",
        "enforced",
        "step",
        "le",
        "route",
        "outcome",
    }


def test_request_latency_buckets_reach_the_proxy_timeout():
    """nginx and the plugins give a scan 35 s and 30 s: the latency histogram must resolve that range."""
    srv = _serve(FakeDecider(ATTACK_ANSWERS))
    try:
        with httpx.Client(base_url=srv.url) as c:
            c.get("/healthz")
            text = c.get("/metrics").text
    finally:
        srv.stop()
    for le in ("20.0", "30.0", "35.0"):
        assert (
            f'http_request_duration_seconds_bucket{{endpoint="/healthz",le="{le}",method="GET"}}'
            in text
        )


def test_probe_latency_buckets_reach_the_jev_timeout(attack_case):
    """Jev calls may take up to 20 s: the per-probe histogram must resolve that range, not stop at 10 s."""
    srv = _serve(FakeDecider(ATTACK_ANSWERS))
    try:
        with httpx.Client(base_url=srv.url) as c:
            c.post("/scan", json=attack_case["fixture"])
            text = c.get("/metrics").text
    finally:
        srv.stop()
    steps = set(
        re.findall(r'sentrook_probe_latency_seconds_bucket\{le="20.0",step="(\w+)"\}', text)
    )
    assert steps and all(f'le="30.0",step="{s}"' in text for s in steps)
