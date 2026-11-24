"""A message send that names its channel in `channelId`.

OpenClaw's `message` tool takes `target`, `to` and `channelId` alike as an explicit delivery target, with no
precedence between them. A held cron delivery named its channel only in `channelId` (beside `channelIds`,
`targetAuthor` and a `guildId`) and got no channel entity. Now a `channelId` is a target written `channel:<id>`,
beside any `target`: every one counts, and the same channel named by both is one target. `channelIds` (a read
and search filter), `targetAuthor` (the author of a message reacted to) and `guildId` (a server) are not where
a send goes. A read-only action (`read`, `search`, ...) that names `channelId` or `channelIds` reads from those
channels: they are sources, not recipients.

A channel binding for the id covers the send, and the grant hint for it is `channel:<id>`, a pattern the grant
command accepts. Synthetic ids throughout.
"""

from __future__ import annotations

import copy

import pytest
from test_aira_detectors import CLOCK, KEY, planir
from test_converge_scan import BENIGN_ANSWERS, scanner

from sentrook.converge.hints import plain_pattern
from sentrook.prepare import PrepareOptions, prepare
from sentrook.prepare.entities import EntityKind, Role
from sentrook.scan import ScanOptions

CHANNEL_ID = "1400000000000000101"
OTHER_ID = "1400000000000000102"
GUILD_ID = "1400000000000000900"
REVIEW_AT = 45

SCHEDULED = {
    "kind": "scheduled",
    "channel": None,
    "sender": {"relation": "unknown", "basis": ["none"]},
}
CRON_REQUEST = "[cron:7a3e10 workout] Post today's workout reminder to the training channel."


def cron_shape(channel_id: str = CHANNEL_ID, **over) -> dict:
    """The argument shape of a held OpenClaw cron delivery: the channel only in `channelId`,
    `channelIds` and `targetAuthor`, with a `guildId` and no `target`."""
    args = {
        "action": "send",
        "accountId": "default",
        "targetAuthor": f"channel:{channel_id}",
        "targetAuthorUuid": "0b4f6c1e-2d7a-4e8b-9c3f-5a6d7e8f9a0b",
        "channelId": channel_id,
        "channelIds": [channel_id],
        "guildId": GUILD_ID,
        "message": "Workout today: 5x5 squats, 3x8 rows.",
        "final": True,
    }
    args.update(over)
    return {k: v for k, v in args.items() if v is not None}


def _prepare(raw: dict):
    return prepare(
        raw,
        PrepareOptions(
            token_key=KEY,
            clock=CLOCK,
            deterministic_salt="testnest",
            state_seed={"max_input_seq": 0},
        ),
    )


def entities(arguments: dict, tool: str = "message"):
    p = _prepare(planir(tool, "message_send", arguments, platform="openclaw"))
    return list(p.entities.pending())


def targets(arguments: dict) -> set[tuple[str, str]]:
    return {(e.kind.value, e.value) for e in entities(arguments) if Role.RECIPIENT in e.roles}


# --------------------------------------------------------------------------- must extract


def test_the_cron_shape_names_its_channel():
    """Must fire: the held delivery's channel, named in `channelId`, is its one channel target. Its
    `channelIds`, `targetAuthor`, `targetAuthorUuid` and `guildId` add nothing."""
    assert targets(cron_shape()) == {("channel", f"channel:{CHANNEL_ID}")}
    ents = entities(cron_shape())
    assert [e.value for e in ents if e.kind is EntityKind.CHANNEL] == [f"channel:{CHANNEL_ID}"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(CHANNEL_ID, f"channel:{CHANNEL_ID}", id="bare-id"),
        pytest.param(int(CHANNEL_ID), f"channel:{CHANNEL_ID}", id="number"),
        pytest.param(f"channel:{CHANNEL_ID}", f"channel:{CHANNEL_ID}", id="already-prefixed"),
        pytest.param("C0B0QV5434G", "channel:C0B0QV5434G", id="slack-id"),
        pytest.param("#ops-yard", "#ops-yard", id="hash-name"),
        pytest.param("120363041234567890@g.us", "120363041234567890@g.us", id="jid"),
    ],
)
def test_a_channel_id_is_a_target(value, expected):
    args = {"action": "send", "channel": "discord", "channelId": value, "message": "status: green"}
    assert targets(args) == {("channel", expected)}


@pytest.mark.parametrize(
    "target",
    [f"channel:{CHANNEL_ID}", CHANNEL_ID, f"discord:{CHANNEL_ID}"],
)
def test_the_same_channel_in_target_and_channel_id_is_one_target(target):
    args = {"action": "send", "channel": "discord", "target": target, "channelId": CHANNEL_ID}
    assert targets({**args, "message": "hi"}) == {("channel", target)}


@pytest.mark.parametrize(
    ("key", "target"),
    [("target", "#ops-yard"), ("target", f"channel:{OTHER_ID}"), ("to", f"channel:{OTHER_ID}")],
)
def test_a_different_target_and_channel_id_are_both_targets(key, target):
    """Must fire: OpenClaw gives neither precedence, so both count."""
    args = {"action": "send", "channel": "discord", key: target, "channelId": CHANNEL_ID}
    assert targets({**args, "message": "hi"}) == {
        ("channel", target),
        ("channel", f"channel:{CHANNEL_ID}"),
    }


def test_a_channel_id_beside_a_person_with_the_same_id_is_still_a_channel():
    args = {"action": "send", "target": f"user:{CHANNEL_ID}", "channelId": CHANNEL_ID}
    assert targets({**args, "message": "hi"}) == {
        ("channel", f"user:{CHANNEL_ID}"),
        ("channel", f"channel:{CHANNEL_ID}"),
    }


def test_an_unrelated_number_field_does_not_hide_the_channel():
    """A poll's `number` is a count: the channel is still read from `channelId`."""
    args = {"action": "poll", "channelId": CHANNEL_ID, "number": 3, "message": "Leg day?"}
    assert ("channel", f"channel:{CHANNEL_ID}") in targets(args)


@pytest.mark.parametrize(
    "action", ["set-status", "sendWithEffect", "thread-reply", "react", "set-channel-info"]
)
def test_a_writing_action_keeps_its_channel_a_recipient(action):
    assert targets({"action": action, "channelId": CHANNEL_ID, "message": "hi"}) == {
        ("channel", f"channel:{CHANNEL_ID}")
    }


# --------------------------------------------------------------------------- must stay silent


def test_a_guild_id_alone_is_not_a_destination():
    """Must stay silent: a server id names no channel."""
    args = {"action": "send", "guildId": GUILD_ID, "message": "hello"}
    assert [e for e in entities(args) if e.kind is EntityKind.CHANNEL] == []


@pytest.mark.parametrize(
    "args",
    [
        pytest.param({"channelIds": [CHANNEL_ID, OTHER_ID]}, id="channelIds"),
        pytest.param({"targetAuthor": f"channel:{CHANNEL_ID}"}, id="targetAuthor-channel"),
        pytest.param({"targetAuthor": f"user:{OTHER_ID}"}, id="targetAuthor-user"),
    ],
)
def test_channel_ids_and_target_author_are_not_send_targets(args):
    """Must stay silent: `channelIds` filters a read or search and `targetAuthor` names whose message is
    reacted to; neither is where a send goes."""
    assert targets({"action": "send", "message": "hello", **args}) == set()


@pytest.mark.parametrize(
    "action", ["read", "search", "list", "readMessages", "thread-list", "channel-info", "list-pins"]
)
def test_a_read_action_names_its_channel_as_a_source(action):
    """Must stay silent: reading a channel sends nothing there. The channel is a source."""
    ents = entities({"action": action, "channel": "discord", "channelId": CHANNEL_ID, "limit": 20})
    chans = [e for e in ents if e.kind is EntityKind.CHANNEL]
    assert [e.value for e in chans] == [f"channel:{CHANNEL_ID}"]
    assert all(Role.RECIPIENT not in e.roles for e in chans)
    assert all(Role.DATA_SOURCE in e.roles for e in chans)


def test_a_search_filtered_by_two_channel_ids_reads_two_channels():
    ents = entities({"action": "search", "channelIds": [CHANNEL_ID, OTHER_ID], "query": "squat"})
    chans = {e.value: e for e in ents if e.kind is EntityKind.CHANNEL}
    assert set(chans) == {f"channel:{CHANNEL_ID}", f"channel:{OTHER_ID}"}
    assert all(Role.RECIPIENT not in e.roles for e in chans.values())


# --------------------------------------------------------------------------- bindings and hints


def cron_send(arguments: dict, grants: list[dict]) -> dict:
    p = planir("message", "message_send", arguments, request=CRON_REQUEST)
    p["session"]["session_ref"] = "s_cron_workout"
    p["trigger"] = copy.deepcopy(SCHEDULED)
    p["grants"] = grants
    return p


def scan(p: dict, **opts):
    return (
        scanner(BENIGN_ANSWERS)
        .scan(p, ScanOptions(deterministic=True, clock=CLOCK, salt="t", **opts))
        .response
    )


def codes(resp) -> set[str]:
    return {r.code for r in resp.reasons}


def binding(pattern: str, ref: str = "bind-1") -> dict:
    return {"grant_ref": ref, "kind": "destination", "pattern": pattern, "scope": "persistent"}


@pytest.mark.parametrize("pattern", [f"channel:{CHANNEL_ID}", CHANNEL_ID, f"#{CHANNEL_ID}"])
def test_a_channel_binding_for_the_id_covers_the_send(pattern):
    """Must fire: a binding for the channel relieves a send that names it only by `channelId`, as it
    relieves one that names it in `target`."""
    unbound = scan(cron_send(cron_shape(), []))
    bound = scan(cron_send(cron_shape(), [binding(pattern)]))
    assert "relief.destination_grant" in codes(bound)
    assert bound.tree.suspicion.distrust is None
    assert bound.risk < REVIEW_AT <= unbound.risk
    plain = {
        "action": "send",
        "target": f"channel:{CHANNEL_ID}",
        "message": cron_shape()["message"],
    }
    assert bound.risk == pytest.approx(scan(cron_send(plain, [binding(pattern)])).risk)


def test_a_binding_for_another_channel_does_not_cover_the_send():
    """Must stay silent: the binding covers its own channel only."""
    unbound = scan(cron_send(cron_shape(), []))
    elsewhere = scan(cron_send(cron_shape(), [binding(f"channel:{OTHER_ID}")]))
    assert "relief.destination_grant" not in codes(elsewhere)
    assert elsewhere.risk == pytest.approx(unbound.risk)


def test_a_binding_for_the_target_alone_does_not_cover_a_different_channel_id():
    """Must stay silent: a send naming `target` and a different `channelId` needs both covered."""
    args = cron_shape(target="#ops-yard", channel="discord")
    one = scan(cron_send(args, [binding("#ops-yard")]))
    assert one.risk >= REVIEW_AT
    both = scan(cron_send(args, [binding("#ops-yard"), binding(f"channel:{CHANNEL_ID}", "bind-2")]))
    assert "relief.destination_grant" in codes(both)
    assert both.risk < REVIEW_AT


def test_the_hint_is_a_pattern_the_grant_command_accepts_and_it_clears_the_send():
    """Must fire: the held send gets a destination hint for the channel, written `channel:<id>`; granting
    it brings a second scan below the review line. An empty entity library, so the scan is fully informed."""
    library = {"oracle_seed": {"entities": []}}
    resp = scan(cron_send(cron_shape(), []), **library)
    hinted = [h for h in resp.grant_hints if h.kind == "destination"]
    assert [h.pattern for h in hinted] == [f"channel:{CHANNEL_ID}"]
    pattern = hinted[0].pattern
    assert plain_pattern(pattern) and len(pattern) <= 256 and pattern.isprintable()
    assert hinted[0].risk < REVIEW_AT <= resp.risk
    again = scan(cron_send(cron_shape(), [binding(pattern)]), **library)
    assert "relief.destination_grant" in codes(again)
    assert again.risk < REVIEW_AT
