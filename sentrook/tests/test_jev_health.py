"""Jev health in `/healthz`: the scanner reports whether Jev is answering, not only whether a key is set.

A run of auth or credit refusals (401, 402, 403) marks Jev failing quickly; timeouts, 5xx and rate limits only
after a longer run. A success clears it. Each change of state is logged once, with the HTTP status only.
"""

from __future__ import annotations

import logging

import httpx
import pytest
from test_jev_probes import ATTACK_ANSWERS, FakeDecider

from sentrook.jev.client import ApiError
from sentrook.jev.health import (
    AUTH_FAILURES_TO_FAIL,
    FAILURES_TO_FAIL,
    JevHealth,
    TrackedDecider,
)
from sentrook.serve.config import ServeConfig
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import ScanServer

KEY = "unit-test-state-key-" * 2
API_KEY = "sk-test-not-a-real-key-0000"
LOGGER = "sentrook.jev"


class ScriptedDecider:
    """Plays a script of outcomes, one per call: an `ApiError` is raised, anything else answers."""

    def __init__(self, script: list[ApiError | None]):
        self.script = list(script)
        self.ok = FakeDecider(ATTACK_ANSWERS)

    def decide(self, body, *, repeat=None):
        outcome = self.script.pop(0) if self.script else None
        if isinstance(outcome, ApiError):
            raise outcome
        return self.ok.decide(body, repeat=repeat)


def _unauthorized() -> ApiError:
    return ApiError(401, '{"error":{"message":"User not found.","code":401}}')


def _timeout() -> ApiError:
    return ApiError(None, "timeout: ReadTimeout('timed out')")


def _server_error() -> ApiError:
    return ApiError(502, "bad gateway")


def _run(health: JevHealth, script: list[ApiError | None]) -> None:
    decider = TrackedDecider(ScriptedDecider(script), health)
    body = {"questions": {}}
    for _ in script:
        try:
            decider.decide(body)
        except ApiError:
            pass


def _warnings(caplog) -> list[str]:
    return [
        r.getMessage() for r in caplog.records if r.name == LOGGER and r.levelno >= logging.WARNING
    ]


# --- must fire -------------------------------------------------------------------------------------------


def test_repeated_auth_refusals_mark_jev_failing_and_log_once(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER)
    health = JevHealth(key_configured=True)
    _run(health, [_unauthorized()] * (AUTH_FAILURES_TO_FAIL - 1))
    assert health.snapshot()["state"] == "ok"
    assert _warnings(caplog) == []

    _run(health, [_unauthorized()] * 3)
    snap = health.snapshot()
    assert snap["state"] == "failing"
    assert snap["consecutive_failures"] == AUTH_FAILURES_TO_FAIL + 2
    assert snap["last_failure_status"] == 401 and snap["last_failure_at"]
    assert snap["last_success_at"] is None
    warnings = _warnings(caplog)
    assert len(warnings) == 1 and "401" in warnings[0]
    assert API_KEY not in caplog.text


@pytest.mark.parametrize("status", [402, 403])
def test_credit_and_forbidden_count_as_auth_refusals(status):
    health = JevHealth(key_configured=True)
    _run(health, [ApiError(status, "no")] * AUTH_FAILURES_TO_FAIL)
    assert health.snapshot()["state"] == "failing"
    assert health.snapshot()["last_failure_status"] == status


def test_long_run_of_timeouts_and_server_errors_marks_failing():
    health = JevHealth(key_configured=True)
    blips = [_timeout() if i % 2 else _server_error() for i in range(FAILURES_TO_FAIL - 1)]
    _run(health, blips)
    assert health.snapshot()["consecutive_failures"] == FAILURES_TO_FAIL - 1
    assert health.snapshot()["state"] == "ok"
    _run(health, [_server_error()])
    snap = health.snapshot()
    assert snap["state"] == "failing" and snap["last_failure_status"] == 502


def test_timeout_is_reported_without_an_http_status():
    health = JevHealth(key_configured=True)
    _run(health, [_timeout()])
    snap = health.snapshot()
    assert snap["last_failure_status"] == "timeout"


def test_healthz_reports_failing_jev_and_stays_200(caplog, attack_case):
    caplog.set_level(logging.INFO, logger=LOGGER)
    config = ServeConfig(state_key=KEY, test_mode=True, scan_auth_mode="open", jev_api_key=API_KEY)
    runtime = ServeRuntime.build(config, decider=FakeDecider(error=_unauthorized()))
    srv = ScanServer(runtime, host="127.0.0.1", port=0)
    srv.start()
    try:
        with httpx.Client(base_url=srv.url) as c:
            before = c.get("/healthz").json()["jev"]
            assert before["state"] == "ok" and before["key_configured"] is True
            fixture = attack_case["fixture"]
            for _ in range(AUTH_FAILURES_TO_FAIL):
                body = c.post("/scan", json=fixture).json()
                assert body["status"] == "degraded"
            r = c.get("/healthz")
            assert r.status_code == 200
            h = r.json()
            assert h["ok"] is True
            assert h["jev"]["state"] == "failing"
            assert h["jev"]["last_failure_status"] == 401
            assert h["jev"]["key_configured"] is True
    finally:
        srv.stop()
    assert len(_warnings(caplog)) == 1
    assert API_KEY not in caplog.text


# --- must stay silent ------------------------------------------------------------------------------------


@pytest.mark.parametrize("blip", [_timeout, _server_error])
def test_single_blip_between_successes_stays_ok_and_silent(caplog, blip):
    caplog.set_level(logging.INFO, logger=LOGGER)
    health = JevHealth(key_configured=True)
    _run(health, [None, blip(), None])
    snap = health.snapshot()
    assert snap["state"] == "ok" and snap["consecutive_failures"] == 0
    assert snap["last_success_at"] and snap["last_failure_at"]
    assert _warnings(caplog) == []


def test_missing_key_is_not_reported_as_failing(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER)
    health = JevHealth(key_configured=False)
    _run(health, [_unauthorized()] * (AUTH_FAILURES_TO_FAIL * 3))
    snap = health.snapshot()
    assert snap["state"] != "failing"
    assert _warnings(caplog) == []


def test_missing_key_healthz_keeps_key_configured_false():
    runtime = ServeRuntime.build(
        ServeConfig(state_key=KEY, test_mode=True, scan_auth_mode="open"),
        decider=FakeDecider(error=_unauthorized()),
    )
    jev = runtime.health_payload()["jev"]
    assert jev["key_configured"] is False and jev["state"] != "failing"


def test_context_limit_and_other_client_errors_do_not_count():
    health = JevHealth(key_configured=True)
    _run(
        health,
        [ApiError(400, '{"error":"max_tokens_exceeded"}')] * (FAILURES_TO_FAIL + 1)
        + [ApiError(404, "not found")] * (FAILURES_TO_FAIL + 1),
    )
    snap = health.snapshot()
    assert snap["state"] == "ok" and snap["consecutive_failures"] == 0


# --- recovers --------------------------------------------------------------------------------------------


def test_success_after_failing_clears_state_and_logs_recovery(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER)
    health = JevHealth(key_configured=True)
    _run(health, [_unauthorized()] * AUTH_FAILURES_TO_FAIL)
    assert health.snapshot()["state"] == "failing"
    _run(health, [None, None])
    snap = health.snapshot()
    assert snap["state"] == "ok" and snap["consecutive_failures"] == 0
    assert snap["last_success_at"] and snap["last_failure_status"] == 401
    warnings = _warnings(caplog)
    assert len(warnings) == 2 and "recovered" in warnings[1] and "401" in warnings[1]


def test_success_after_short_run_logs_nothing(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER)
    health = JevHealth(key_configured=True)
    _run(health, [_unauthorized()] * (AUTH_FAILURES_TO_FAIL - 1) + [None])
    assert health.snapshot()["state"] == "ok"
    assert _warnings(caplog) == []
