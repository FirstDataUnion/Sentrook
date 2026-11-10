"""Channel bindings on scheduled runs.

A binding (`channelBindings` / `channel_bindings` in the plugin config, or `/sentrook bind`) reaches
the scanner as a persistent `destination` grant. A scheduled job delivering to its bound channel is
relieved like any other granted destination; a delivery to any other channel keeps its distrust and
untrusted origin. The scheduled trigger's own `request_origin` stays: relief is about the
destination, not about who started the run.
"""

from __future__ import annotations

import copy

import pytest
from test_aira_detectors import planir
from test_converge_scan import BENIGN_ANSWERS, CLOCK, scanner

from sentrook.scan import ScanOptions

#: What the review threshold of the beta policy is; a relieved delivery must land under it.
REVIEW_AT = 45

SCHEDULED = {
    "kind": "scheduled",
    "channel": None,
    "sender": {"relation": "unknown", "basis": ["none"]},
}
CRON_REQUEST = "[cron:9f1c2a daily-brief] Post the daily brief to the ops channel."

#: (channel the job delivers to, the binding, another channel), as OpenClaw's `message` tool sends them.
#: A binding may be written as the target itself or by the shorter name an owner uses for it.
CASES = [
    pytest.param("slack", "C0B0QV5434G", "C0B0QV5434G", "C0B0QV5434H", id="slack-id"),
    pytest.param("slack", "#daily-brief", "#daily-brief", "#daily-briefs", id="slack-name"),
    pytest.param(
        "discord",
        "channel:1498333845953712258",
        "channel:1498333845953712258",
        "channel:1498333845953712259",
        id="discord-as-sent",
    ),
    pytest.param(
        "discord",
        "channel:1498333845953712258",
        "1498333845953712258",
        "channel:1498333845953712259",
        id="discord-bare-id",
    ),
    pytest.param(
        "telegram",
        "telegram:-1001234567890",
        "-1001234567890",
        "telegram:-1001234567891",
        id="telegram-bare-id",
    ),
]


def binding(pattern: str, **kw) -> dict:
    return {
        "grant_ref": "bind-1",
        "kind": "destination",
        "pattern": pattern,
        "scope": "persistent",
        **kw,
    }


def cron_send(platform: str, target: str, grants: list[dict]) -> dict:
    arguments = {
        "action": "send",
        "channel": platform,
        "target": target,
        "message": "Daily brief: 3 incidents closed, 1 open.",
    }
    p = planir("message", "message_send", arguments, request=CRON_REQUEST)
    p["session"]["session_ref"] = "s_cron_daily_brief"
    p["trigger"] = copy.deepcopy(SCHEDULED)
    p["grants"] = grants
    return p


def scan(p: dict):
    return (
        scanner(BENIGN_ANSWERS)
        .scan(p, ScanOptions(deterministic=True, clock=CLOCK, salt="t"))
        .response
    )


def codes(resp) -> set[str]:
    return {r.code for r in resp.reasons}


@pytest.mark.parametrize(("platform", "target", "pattern", "other"), CASES)
def test_scheduled_delivery_to_its_bound_channel_is_relieved(platform, target, pattern, other):
    """Must fire: the binding relieves the scheduled job's delivery to the channel it is bound to."""
    unbound = scan(cron_send(platform, target, []))
    bound_resp = scan(cron_send(platform, target, [binding(pattern)]))

    assert "relief.destination_grant" in codes(bound_resp)
    assert bound_resp.tree.suspicion.distrust is None
    assert bound_resp.tree.suspicion.untrusted_origin is None
    # The run is still a scheduled one: relief is on the destination, not on the trigger.
    assert "trigger.scheduled" in codes(bound_resp)
    assert bound_resp.tree.suspicion.request_origin == pytest.approx(0.2)
    assert bound_resp.risk < REVIEW_AT <= unbound.risk


@pytest.mark.parametrize(("platform", "target", "pattern", "other"), CASES)
def test_scheduled_delivery_to_any_other_channel_is_not_relieved(platform, target, pattern, other):
    """Must stay silent: a binding covers its own channel only, so a delivery elsewhere scores as if
    there were no binding."""
    unbound = scan(cron_send(platform, other, []))
    elsewhere = scan(cron_send(platform, other, [binding(pattern)]))

    assert "relief.destination_grant" not in codes(elsewhere)
    assert elsewhere.tree.suspicion.distrust is not None
    assert elsewhere.risk == pytest.approx(unbound.risk)
    assert elsewhere.risk >= REVIEW_AT


def test_a_session_grant_from_the_owners_chat_does_not_reach_the_scheduled_run():
    """Must stay silent: a destination granted for one chat session is not a binding; the cron run is
    its own session, so the grant lapses there."""
    grant = binding("C0B0QV5434G", scope="session", session_ref="s_owner_chat")
    unbound = scan(cron_send("slack", "C0B0QV5434G", []))
    resp = scan(cron_send("slack", "C0B0QV5434G", [grant]))

    assert "relief.destination_grant" not in codes(resp)
    assert resp.risk == pytest.approx(unbound.risk)
