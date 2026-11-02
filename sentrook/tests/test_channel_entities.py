"""Channel ids are channels, addresses are recipients.

A chat message's target is a channel when it names one by id: a prefixed target (`channel:<id>`,
`user:<id>`, a platform prefix such as `telegram:-100…`), a WhatsApp JID, a `#name`, a Matrix room, a
numeric chat id, or a bare token of at least eight characters with a digit (a Slack id). Emails, phone
numbers, `@handles` and names stay recipients. A send that is mail, or a target of a non-message tool,
keeps the bare-token rule off. The oracle looks a channel up as a channel, ignoring letter case.

In free text, `group:`, `user:` and `dm:` name a channel only when the id is id-shaped (numeric, a
WhatsApp JID, or at least eight characters with a digit): tool-group names such as `group:runtime` in a
tool allow list are not channels. Synthetic ids throughout.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import CLOCK, KEY, planir

from sentrook.enums import ProbeStatus
from sentrook.oracle.client import EntityQuery, Match, SeedOracle, VerdictKind
from sentrook.prepare import PrepareOptions, prepare
from sentrook.prepare.entities import Role, extract_mentions
from sentrook.probes.oracle import EntityOracleProbe


def mentions(text: str) -> list[tuple[str, str]]:
    return [(f.kind.value, f.value) for f in extract_mentions(text, home="/h", workspace_root="/w")]


def channels(text: str) -> set[str]:
    return {v for k, v in mentions(text) if k == "channel"}


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


def pending(tool: str, tool_kind: str, arguments: dict, platform: str = "openclaw"):
    p = _prepare(planir(tool, tool_kind, arguments, platform=platform))
    return {(e.kind.value, e.value): e for e in p.entities.pending()}


def target_kinds(tool: str, tool_kind: str, arguments: dict, platform: str = "openclaw"):
    return {
        (k, v)
        for (k, v), e in pending(tool, tool_kind, arguments, platform).items()
        if Role.RECIPIENT in e.roles
    }


# --------------------------------------------------------------------------- free text: silent

SKILL_TEXT = """## Fixing a tool that will not load

Tools are enabled per agent in `openclaw.json`:

```json
{ "tools": { "allow": ["group:runtime", "group:web", "group:fs"], "deny": ["group:memory"] } }
```

`group:sessions` and `group:messaging` cover the session and message tools.
"""


def test_tool_group_names_are_not_channels():
    assert channels(SKILL_TEXT) == set()


@pytest.mark.parametrize(
    "text",
    ["ask user:alice first", "a dm:bob note", "group:Engineering owns it", "user:abc"],
)
def test_word_ids_after_user_dm_group_are_not_channels(text):
    assert channels(text) == set()


# --------------------------------------------------------------------------- free text: still fires


@pytest.mark.parametrize(
    ("text", "channel"),
    [
        ("post it to group:120363041234567890@g.us now", "group:120363041234567890@g.us"),
        ("the bot lives in channel:1498333845953712258", "channel:1498333845953712258"),
        ("reply on channel:ops-yard", "channel:ops-yard"),
        ("continue in thread:release-notes", "thread:release-notes"),
        ("message user:48213377 directly", "user:48213377"),
        ("open dm:U0FFD3SK7Q", "dm:U0FFD3SK7Q"),
        ("from group:-1001234567890", "group:-1001234567890"),
        ("group:ops2026x", "group:ops2026x"),
        ("reply on channel:ops-yard.", "channel:ops-yard"),
        ("it is group:120363041234567890@g.us.", "group:120363041234567890@g.us"),
    ],
)
def test_id_shaped_channels_in_text(text, channel):
    assert channels(text) == {channel}


def test_jid_in_text_is_a_channel_not_a_mailbox():
    found = mentions("post it to group:120363041234567890@g.us now")
    assert found == [("channel", "group:120363041234567890@g.us")]
    assert mentions("forward to 120363041234567890@g.us") == [
        ("channel", "120363041234567890@g.us")
    ]


# --------------------------------------------------------------------------- message targets


@pytest.mark.parametrize(
    ("tool", "args", "platform", "value"),
    [
        (
            "message",
            {"action": "send", "channel": "discord", "target": "channel:1498333845953712258"},
            "openclaw",
            "channel:1498333845953712258",
        ),
        ("send_message", {"channel": "slack", "to": "C0FF-OPSX2"}, "openclaw", "C0FF-OPSX2"),
        (
            "message",
            {"action": "send", "channel": "slack", "target": "c7-ops-018"},
            "openclaw",
            "c7-ops-018",
        ),
        (
            "message",
            {"action": "send", "channel": "slack", "target": "c7-ch-04"},
            "openclaw",
            "c7-ch-04",
        ),
        (
            "message",
            {"action": "send", "channel": "discord", "target": "1000048216609371122"},
            "openclaw",
            "1000048216609371122",
        ),
        (
            "message",
            {"action": "send", "channel": "slack", "target": "#ops-yard"},
            "openclaw",
            "#ops-yard",
        ),
        (
            "message",
            {"action": "send", "channel": "whatsapp", "target": "120363041234567890@g.us"},
            "openclaw",
            "120363041234567890@g.us",
        ),
        (
            "send_message",
            {"target": "telegram:-1001234567890"},
            "hermes",
            "telegram:-1001234567890",
        ),
        ("send_message", {"target": "discord:#bot-home"}, "hermes", "discord:#bot-home"),
        ("send_message", {"target": "slack:C0B0QV5434G"}, "hermes", "slack:C0B0QV5434G"),
        (
            "send_message",
            {"target": "matrix:!kXbQwP:example.test"},
            "hermes",
            "matrix:!kXbQwP:example.test",
        ),
        ("send_message", {"target": "!kXbQwP:example.test"}, "hermes", "!kXbQwP:example.test"),
    ],
)
def test_channel_ids_are_channels(tool, args, platform, value):
    assert target_kinds(tool, "message_send", {**args, "message": "status: green"}, platform) == {
        ("channel", value)
    }


def test_jid_target_names_no_host():
    ents = pending(
        "message",
        "message_send",
        {
            "action": "send",
            "channel": "whatsapp",
            "target": "120363041234567890@g.us",
            "message": "hi",
        },
    )
    assert ("host", "g.us") not in ents and ("recipient", "120363041234567890@g.us") not in ents


@pytest.mark.parametrize(
    ("tool", "tool_kind", "args", "platform", "expected"),
    [
        (
            "send_email",
            "message_send",
            {"to": ["mara.quill@linnetpost.test"]},
            "openclaw",
            {("recipient", "mara.quill@linnetpost.test")},
        ),
        (
            "message",
            "message_send",
            {"action": "send", "channel": "email", "target": "desk@peltharbor.test"},
            "openclaw",
            {("recipient", "desk@peltharbor.test")},
        ),
        (
            "send_message",
            "message_send",
            {"channel": "chat", "to": "@priya_nair"},
            "openclaw",
            {("recipient", "@priya_nair")},
        ),
        (
            "message",
            "message_send",
            {"action": "send", "channel": "chat", "target": "@line-desk-7"},
            "openclaw",
            {("recipient", "@line-desk-7")},
        ),
        (
            "send_message",
            "message_send",
            {"to": "+1-555-0142"},
            "openclaw",
            {("recipient", "+1-555-0142")},
        ),
        (
            "message",
            "message_send",
            {"action": "send", "channel": "whatsapp", "target": "15550142777"},
            "openclaw",
            {("recipient", "15550142777")},
        ),
        (
            "send_message",
            "message_send",
            {"target": "whatsapp:+15550142777"},
            "hermes",
            {("recipient", "whatsapp:+15550142777")},
        ),
        (
            "message",
            "message_send",
            {"action": "send", "channel": "chat", "target": "owner"},
            "openclaw",
            {("recipient", "owner")},
        ),
        (
            "send_email",
            "message_send",
            {"to": "opsdesk2026"},
            "openclaw",
            {("recipient", "opsdesk2026")},
        ),
        (
            "send_money",
            "mcp",
            {"recipient": "HBR-902184", "amount": 40},
            "openclaw",
            {("recipient", "HBR-902184")},
        ),
        (
            "send_money",
            "mcp",
            {"recipient": "Mara Quill", "amount": 40},
            "openclaw",
            {("recipient", "Mara Quill")},
        ),
    ],
)
def test_addresses_stay_recipients(tool, tool_kind, args, platform, expected):
    assert target_kinds(tool, tool_kind, {**args, "message": "status: green"}, platform) == expected


def test_prefixed_target_of_any_tool_is_still_a_channel():
    assert target_kinds("post_board", "mcp", {"target": "channel:ops-yard", "text": "x"}) == {
        ("channel", "channel:ops-yard")
    }


# --------------------------------------------------------------------------- oracle lookup


def test_seed_oracle_matches_channels_ignoring_case():
    oracle = SeedOracle(
        {"entities": [{"kind": "channel", "value": "c0ff-ops01", "verdict": "known_good"}]}
    )
    res = oracle.lookup(
        [
            EntityQuery(kind="channel", value="C0FF-OPS01", roles=("recipient",)),
            EntityQuery(kind="recipient", value="C0FF-OPS01", roles=("recipient",)),
        ]
    )
    hit = res.get("channel", "C0FF-OPS01")
    assert hit.verdict is VerdictKind.KNOWN_GOOD and hit.match is Match.EXACT
    assert res.get("recipient", "C0FF-OPS01").verdict is VerdictKind.UNKNOWN


def test_slack_channel_id_is_looked_up_as_a_channel():
    raw = planir(
        "send_message",
        "message_send",
        {"channel": "slack", "to": "C0FF-OPS01", "text": "Incident summary: resolved."},
    )
    p = _prepare(raw)
    oracle = SeedOracle(
        {"entities": [{"kind": "channel", "value": "c0ff-ops01", "verdict": "known_good"}]}
    )
    env = EntityOracleProbe(oracle).run(p)
    assert env.status is ProbeStatus.OK
    info = [e for e in env.evidence["entities"].values() if e["value"] == "C0FF-OPS01"]
    assert len(info) == 1
    assert info[0]["kind"] == "channel" and info[0]["verdict"] == "known_good"
