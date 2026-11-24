"""The same message send gets one channel entity and one approval fingerprint, however its target is written.

OpenClaw's `message` tool takes a send's destination in `target`, `to`, `channelId` or `targets`, and its
Discord plugin also takes a `thread-reply` to a thread by `threadId` alone (written `channel:<threadId>`).
A model writes the same scheduled post differently from run to run, and the channel may be spelt
`channel:<id>`, `discord:channel:<id>` or (on Discord) a bare id. Each of these is the same channel: one
fingerprint, and a channel grant for it covers every shape.

Keys OpenClaw does not read as a destination stay out: `channelIds` (a read filter), `targetAuthor` (the
author of a message reacted to), and `channelRef` or `providerId`, which the tool does not take at all (a send
naming its channel only there is refused for want of a target). `discord:<id>` names a Discord user, not a
channel. Synthetic ids throughout.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import KEY, planir
from test_message_channel_id_targets import (
    REVIEW_AT,
    _prepare,
    binding,
    codes,
    cron_send,
    scan,
)

from sentrook.prepare import approval_salt
from sentrook.prepare.entities import EntityKind, Role
from sentrook.state.token import entity_hash

CHANNEL = "1000000000000000001"
OTHER = "1000000000000000002"
TEXT = "Workout today: 5x5 squats, 3x8 rows."

#: The same send to one Discord channel, in every argument shape OpenClaw takes for it (and one action word
#: it does not take, beside a target it does: the target is read whatever the action word).
SAME_SEND = {
    "target": {"action": "send", "target": f"channel:{CHANNEL}", "message": TEXT},
    "target-with-account": {
        "action": "send",
        "accountId": "default",
        "target": f"channel:{CHANNEL}",
        "message": TEXT,
    },
    "to": {"action": "send", "to": f"channel:{CHANNEL}", "message": TEXT},
    "channelId": {"action": "send", "channelId": CHANNEL, "message": TEXT},
    "channelId-with-filters": {
        "action": "send",
        "channelId": CHANNEL,
        "channelIds": [CHANNEL],
        "guildId": "1000000000000000900",
        "targetAuthor": f"channel:{CHANNEL}",
        "message": TEXT,
    },
    "targets": {"action": "send", "targets": [f"channel:{CHANNEL}"], "message": TEXT},
    "platform-prefixed": {
        "action": "send",
        "target": f"discord:channel:{CHANNEL}",
        "message": TEXT,
    },
    "bare-id-on-discord": {
        "action": "send",
        "channel": "discord",
        "target": CHANNEL,
        "message": TEXT,
    },
    "named-platform": {
        "action": "send",
        "channel": "discord",
        "target": f"channel:{CHANNEL}",
        "message": TEXT,
    },
    "other-action-word": {
        "action": "channel-send",
        "channel": "discord",
        "target": f"channel:{CHANNEL}",
        "message": TEXT,
    },
    "target-and-channelId": {
        "action": "send",
        "target": f"discord:channel:{CHANNEL}",
        "channelId": CHANNEL,
        "message": TEXT,
    },
    "thread-reply-by-threadId": {
        "action": "thread-reply",
        "channel": "discord",
        "threadId": CHANNEL,
        "message": TEXT,
    },
}


def prepared(arguments: dict):
    return _prepare(planir("message", "message_send", arguments, platform="openclaw"))


def fingerprint(arguments: dict) -> str:
    return prepared(arguments).approval_fingerprint


def channel_targets(arguments: dict) -> list[str]:
    return [
        e.value
        for e in prepared(arguments).entities.pending()
        if e.kind is EntityKind.CHANNEL and Role.RECIPIENT in e.roles
    ]


# --------------------------------------------------------------------------- must match


@pytest.mark.parametrize("shape", sorted(SAME_SEND))
def test_every_shape_of_the_same_send_has_one_fingerprint(shape):
    """Must stay silent: the send names its channel, and its approval fingerprint is the one the plain
    `target` shape gets, so an approval made on one run matches the next run's send."""
    assert channel_targets(SAME_SEND[shape])
    assert fingerprint(SAME_SEND[shape]) == fingerprint(SAME_SEND["target"])


def test_an_already_canonical_target_keeps_its_fingerprint():
    """A target written `channel:<id>` hashes as it always did, so earlier approvals still match."""
    expected = entity_hash(approval_salt(KEY), "channel", f"channel:{CHANNEL}")
    assert fingerprint(SAME_SEND["target"]) == f"afp1:message_send|rcpt:{expected}"


def test_the_same_channel_named_twice_is_one_target():
    """`discord:channel:<id>` in `target` and the bare id in `channelId` are one channel."""
    assert channel_targets(SAME_SEND["target-and-channelId"]) == [f"discord:channel:{CHANNEL}"]


def test_a_discord_thread_reply_names_its_thread():
    """Discord's `thread-reply` sends to the thread `threadId` names when no target is given."""
    assert channel_targets(SAME_SEND["thread-reply-by-threadId"]) == [f"channel:{CHANNEL}"]


@pytest.mark.parametrize("shape", sorted(SAME_SEND))
@pytest.mark.parametrize("pattern", [f"channel:{CHANNEL}", f"#{CHANNEL}", CHANNEL])
def test_a_channel_grant_covers_every_shape(shape, pattern):
    """Must stay silent: a channel grant for the id relieves the send in every shape."""
    args = SAME_SEND[shape]
    unbound = scan(cron_send(args, []))
    bound = scan(cron_send(args, [binding(pattern)]))
    assert "relief.destination_grant" in codes(bound)
    assert bound.risk < REVIEW_AT <= unbound.risk


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize(
    "args",
    [
        pytest.param({"target": f"channel:{OTHER}"}, id="target"),
        pytest.param({"channelId": OTHER}, id="channelId"),
        pytest.param({"target": f"discord:channel:{OTHER}"}, id="platform-prefixed"),
        pytest.param({"channel": "discord", "target": OTHER}, id="bare-id"),
        pytest.param(
            {"action": "thread-reply", "channel": "discord", "threadId": OTHER}, id="thread"
        ),
    ],
)
def test_a_send_to_another_channel_differs_and_is_not_covered(args):
    """Must fire: another channel has another fingerprint, and a grant for the first does not cover it."""
    other = {"action": "send", "message": TEXT, **args}
    assert fingerprint(other) != fingerprint(SAME_SEND["target"])
    covered = scan(cron_send(other, [binding(f"channel:{CHANNEL}")]))
    assert "relief.destination_grant" not in codes(covered)
    assert covered.risk >= REVIEW_AT


def test_a_thread_reply_with_a_target_goes_to_the_target():
    """OpenClaw reads `threadId` as the destination only when no target is given."""
    args = {
        "action": "thread-reply",
        "channel": "discord",
        "target": f"channel:{OTHER}",
        "threadId": CHANNEL,
        "message": TEXT,
    }
    assert channel_targets(args) == [f"channel:{OTHER}"]


@pytest.mark.parametrize(
    "args",
    [
        pytest.param({"target": "15550001234"}, id="bare-phone-number"),
        pytest.param({"channel": "slack", "target": "U0000000A1"}, id="slack-user-id"),
        pytest.param({"channel": "telegram", "target": "100000001"}, id="telegram-user-chat"),
    ],
)
def test_a_bare_id_that_may_be_a_person_is_not_covered_by_a_channel_glob(args):
    """Must fire: only a bare Discord id is read as a channel. A bare phone number, a Slack user id or a
    Telegram user's chat may be a person, and a `channel:*` grant does not cover it."""
    covered = scan(cron_send({"action": "send", "message": TEXT, **args}, [binding("channel:*")]))
    assert "relief.destination_grant" not in codes(covered)


@pytest.mark.parametrize("target", [f"discord:user:{CHANNEL}", f"user:{CHANNEL}"])
def test_a_direct_message_to_the_same_id_is_not_the_channel(target):
    """Must fire: a person with the same id is another party; the channel grant does not cover them."""
    args = {"action": "send", "target": target, "message": TEXT}
    assert fingerprint(args) != fingerprint(SAME_SEND["target"])
    covered = scan(cron_send(args, [binding(f"channel:{CHANNEL}")]))
    assert "relief.destination_grant" not in codes(covered)


# --------------------------------------------------------------------------- must stay the same


@pytest.mark.parametrize(
    "args",
    [
        pytest.param({"channelIds": [CHANNEL]}, id="channelIds"),
        pytest.param({"targetAuthor": f"channel:{CHANNEL}"}, id="targetAuthor"),
        pytest.param({"channelRef": f"channel:{CHANNEL}"}, id="channelRef"),
        pytest.param(
            {"channelRef": f"channel:{CHANNEL}", "providerId": "discord"}, id="channelRef-provider"
        ),
        pytest.param({"channel": "discord", "threadId": CHANNEL}, id="threadId-on-send"),
    ],
)
def test_keys_openclaw_does_not_send_to_are_not_targets(args):
    """Must stay silent: none of these is where OpenClaw sends a message."""
    assert channel_targets({"action": "send", "text": TEXT, **args}) == []


def test_a_slack_thread_reply_does_not_read_its_thread_as_a_channel():
    """Only Discord's thread-reply sends to `threadId` alone; elsewhere a thread id is inside a channel."""
    args = {"action": "thread-reply", "channel": "slack", "threadId": "1700000000.000100"}
    assert channel_targets({**args, "message": TEXT}) == []
