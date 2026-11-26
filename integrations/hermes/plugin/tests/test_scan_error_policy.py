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

SCAN_ERROR_TEXT = (
    "🪶 Sentrook could not check this call\n"
    "Its scan service did not answer.\n"
    "If you allow it, it runs without a security check.\n"
    "Session and Always skip this question in this chat while Sentrook cannot scan.\n"
    "Status: /sentrook status"
)


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
            if "NOAUTH" in cmd:
                return (401, {"error": {"code": "unauthorized", "message": "expired"}}, {})
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


def test_a_scan_error_is_keyed_to_its_chat_and_outage(h):
    """Session or Always answers the scan errors of one kind in the chat until Sentrook scans again, as the card
    says: never another chat's, another kind of failure in the same outage, or a later outage."""
    turn(h)
    first = call(h, "c1", "ls DOWN")
    second = call(h, "c2", "cat TIMEOUT")
    assert first["rule_key"] == second["rule_key"]
    # credentials that expire during the outage are another kind of failure: asked again
    expired = call(h, "c3", "ls NOAUTH")
    assert expired["action"] == "approve" and expired["rule_key"] != first["rule_key"]
    # a good scan ends the outage: the next failure is a new one
    assert call(h, "c4", "ls") is None
    later = call(h, "c5", "ls DOWN")
    assert (
        later["rule_key"].startswith("sentrook:error:") and later["rule_key"] != first["rule_key"]
    )
    s2 = {"session_id": "S2"}
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="hi", platform="telegram", sender_id="u1", **s2
    )
    other = h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args={"command": "ls DOWN"}, tool_call_id="c3", turn_id="t1", **s2
    )
    assert (
        other["rule_key"].startswith("sentrook:error:") and other["rule_key"] != first["rule_key"]
    )


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


@pytest.mark.parametrize(
    ("mode", "on_scan_error", "text"),
    [
        (
            "enforce",
            "review",
            "every tool call will be held for review, or blocked on unattended runs, until this is fixed",
        ),
        ("enforce", "deny", "every tool call will be blocked until this is fixed"),
        # A configuration error is never let through, even with on_scan_error=allow.
        ("enforce", "allow", "every tool call will be blocked until this is fixed"),
        (
            "observe",
            "review",
            "no tool call is scanned until this is fixed (observe mode: nothing is blocked)",
        ),
    ],
)
def test_invalid_endpoint_log_says_what_happens_to_tool_calls(mode, on_scan_error, text):
    """The owner's log line for an invalid endpoint, in the same words as the OpenClaw plugin."""
    from plugin.scan_error_policy import invalid_endpoint_effect

    assert invalid_endpoint_effect(mode, on_scan_error) == text
