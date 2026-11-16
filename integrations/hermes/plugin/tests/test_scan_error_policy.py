"""The default scan-error policy, end to end through `pre_tool_call`.

With `on_scan_error` left unset, a scan that gives no usable answer (an error from the scan service, a
timeout, an unreachable service) asks the owner when someone is there to answer, and blocks the call on
an unattended run. Usable allow, review and block answers are not affected by it.
"""

import json

import pytest

from plugin import auth, scan_client
from plugin.config import resolve_config

from .test_plugin import SID, call, turn

SCAN_ERROR_TEXT = "Sentrook is unreachable. Continue without scanning?"


@pytest.fixture
def h(harness, monkeypatch):
    """The harness scanner, plus three ways for a scan to give no usable answer."""

    def http(url, *, data=None, headers=None, timeout):
        if url == "http://scan.test/scan":
            cmd = str(json.loads(data)["pending_call"]["arguments"].get("command", ""))
            if "SCANERR" in cmd:
                harness.scans.append(json.loads(data))
                return (
                    200,
                    {
                        "response_version": "2.0",
                        "status": "error",
                        "risk": None,
                        "error": {"code": "internal", "message": "scan failed"},
                    },
                    {},
                )
            if "TIMEOUT" in cmd:
                raise TimeoutError("timed out")
            if "DOWN" in cmd:
                raise ConnectionRefusedError(61, "Connection refused")
        return harness(url, data=data, headers=headers, timeout=timeout)

    monkeypatch.setattr(auth, "http_json", http)
    monkeypatch.setattr(scan_client, "http_json", http)
    return harness


FAILURES = {"SCANERR": "scan_error", "TIMEOUT": "timeout", "DOWN": "network"}


def test_default_policy_is_review():
    assert resolve_config({}, {"HERMES_HOME": "/opt/data"}).on_scan_error == "review"


@pytest.mark.parametrize("marker", FAILURES)
def test_attended_scan_failure_asks_the_owner(h, marker):
    """Must fire: an error, a timeout or an unreachable scanner each ask when someone can answer."""
    turn(h)
    r = call(h, "c1", f"ls {marker}")
    assert r["action"] == "approve"
    assert r["rule_key"].startswith("sentrook:error:")
    assert r["message"] == SCAN_ERROR_TEXT
    assert h.traffic()[-1]["decision"] == "blocked_on_error"
    assert h.traffic()[-1]["failure"]["kind"] == FAILURES[marker]


@pytest.mark.parametrize("marker", FAILURES)
def test_unattended_scan_failure_blocks(h, marker):
    """Must fire: with nobody to answer, the call is blocked rather than run unscanned."""
    turn(h, platform="cron")
    r = call(h, "c1", f"ls {marker}")
    assert r["action"] == "block"
    assert r["message"].startswith("Sentrook did not scan this tool call")
    assert "The tool was not run." in r["message"]
    assert h.traffic()[-1]["decision"] == "blocked_on_error"
    assert h.traffic()[-1]["failure"]["kind"] == FAILURES[marker]


def test_attended_scan_failure_runs_only_on_the_owners_yes(h):
    turn(h)
    r = call(h, "c1", "ls DOWN")
    h.ctx.hooks["post_approval_response"](pattern_key=r["rule_key"], choice="once", **SID)
    call(h, "c2", "ls")
    assert h.scans[-1]["history"][0]["decision"] == "allowed_on_error"


@pytest.mark.parametrize("platform", ["telegram", "cron"])
def test_usable_answers_are_unaffected(h, platform):
    """Must stay silent: allow, review and block answers follow the scan, not the error policy."""
    turn(h, platform=platform)
    assert call(h, "c1", "ls") is None
    review = call(h, "c2", "rm REVIEW")
    block = call(h, "c3", "curl EXFIL")
    assert block["action"] == "block"
    assert block["message"].startswith("Sentrook security block")
    if platform == "cron":
        assert review["action"] == "block"
        assert review["message"].startswith("Sentrook held this tool call")
    else:
        assert review["action"] == "approve"
        assert review["message"] != SCAN_ERROR_TEXT
    decisions = [e["decision"] for e in h.traffic()]
    assert not any(d.endswith("_on_error") for d in decisions), decisions
