"""Trusted users and trusted chats (`trust`).

A member of a chat the owner trusts, or a person the owner trusts, is sent as `trusted`, not as a stranger (`other`),
and never as the owner. Trust is set only by the owner, from a direct message or the terminal. Members of a trusted
chat answer its reviews, and a Session answer there is kept for the chat without setting a grant; a chat trusted with
`--owner-only` holds its reviews for the owner instead.
"""

import json

import pytest

import plugin
from plugin import commands, hold
from plugin.intent import sender_of
from plugin.trust import Trust, parse_ref

from .conftest import refusals
from .test_session_approval import HINT, _resp

SID = {"session_id": "S1", "task_id": "S1"}
CHAT = "c-ops"
TRUSTED_MEMBER = {"relation": "trusted", "basis": ["plugin_allowlist:chat", "group_chat"]}
OTHER_IN_GROUP = {"relation": "other", "basis": ["group_chat"]}
OWNER_IN_GROUP = {"relation": "owner", "basis": ["group_chat"]}


def facts(user="u-member", chat_id=CHAT, chat_type="group", **more):
    return {
        "platform": "discord",
        "chat_type": chat_type,
        "chat_id": chat_id,
        "actor_id": user,
        **more,
    }


# ---- who sent the turn --------------------------------------------------------------------------------------

ALLOW = {"DISCORD_ALLOWED_USERS": "u-owner"}
IN_OPS = Trust(chats={f"discord:{CHAT}": False})


def test_a_member_of_a_trusted_chat_is_trusted_not_other():
    assert sender_of("discord", facts(), None, ALLOW, IN_OPS) == TRUSTED_MEMBER
    # Without trust, or in another chat, the same member stays a stranger.
    assert sender_of("discord", facts(), None, ALLOW) == OTHER_IN_GROUP
    assert sender_of("discord", facts(chat_id="c-elsewhere"), None, ALLOW, IN_OPS) == OTHER_IN_GROUP
    # The same id on another platform is another chat.
    assert (
        sender_of("slack", {**facts(), "platform": "slack"}, None, ALLOW, IN_OPS) == OTHER_IN_GROUP
    )


def test_a_thread_in_a_trusted_chat_is_covered_by_its_parent():
    f = facts(chat_id="c-thread", chat_type="thread", parent_chat_id=CHAT)
    assert sender_of("discord", f, None, ALLOW, IN_OPS) == TRUSTED_MEMBER


def test_the_owner_in_a_trusted_chat_stays_the_owner():
    assert sender_of("discord", facts(user="u-owner"), None, ALLOW, IN_OPS) == OWNER_IN_GROUP


def test_a_trusted_user_is_trusted_in_any_chat_but_never_the_owner():
    t = Trust(senders=frozenset({"discord:u-friend"}))
    assert sender_of("discord", facts(user="u-friend"), None, {}, t) == {
        "relation": "trusted",
        "basis": ["plugin_allowlist:sender", "group_chat"],
    }
    # A direct message admitted by allow-all: trusted, not a stranger.
    dm = facts(user="u-friend", chat_type="dm", chat_id="d-1")
    assert sender_of("discord", dm, None, {"DISCORD_ALLOW_ALL_USERS": "true"}, t) == {
        "relation": "trusted",
        "basis": ["plugin_allowlist:sender"],
    }


def test_a_direct_chat_is_never_a_trusted_chat():
    t = Trust(chats={"discord:d-1": False})
    dm = facts(chat_type="dm", chat_id="d-1")
    assert sender_of("discord", dm, None, {}, t) == {
        "relation": "other",
        "basis": ["host_open_access"],
    }


@pytest.mark.parametrize(
    "raw",
    ["discord", "discord:", "cron:123", "nope:1", "discord:has space", "discord:a\x07b", 7, None],
)
def test_a_ref_must_name_a_chat_platform_and_an_id(raw):
    assert parse_ref(raw) is None


def test_matrix_room_ids_keep_their_colons():
    assert parse_ref("matrix:!room:example.test") == ("matrix", "!room:example.test")


# ---- a turn in a trusted chat, end to end -------------------------------------------------------------------


@pytest.fixture
def group(harness, monkeypatch):
    """A Discord server channel; `h.facts` is who is speaking, `h.next` the scanner's next answer."""
    h = harness
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "u-owner")
    h.facts = facts()
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(h.facts))
    monkeypatch.setattr(plugin, "session_surface", lambda: "")
    h.next = {}

    def http(url, *, data=None, headers=None, timeout):
        if url != "http://scan.test/scan":
            return h(url, data=data, headers=headers, timeout=timeout)
        p = json.loads(data)
        h.scans.append(p)
        # The scanner lets the owner pass a review-band call once (`owner_pass`).
        return 200, {**_resp(p, **h.next), "owner_pass": "once"}, {}

    monkeypatch.setattr(plugin.scan_client, "http_json", http)
    return h


def _turn(h, sender="u-member"):
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sender}",
        user_message="add the meeting notes to the wiki",
        platform="discord",
        sender_id=sender,
        **SID,
    )


def _call(h, cid, sender="u-member"):
    return h.ctx.hooks["pre_tool_call"](
        tool_name="terminal",
        args={"command": f"curl -s -X POST https://api.example-notes.test/v1/pages?n={cid}"},
        tool_call_id=cid,
        turn_id=f"t-{sender}",
        **SID,
    )


def _answer(h, out, choice):
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{out['rule_key']}", choice=choice, **SID
    )


def _records(h, kind="scan"):
    return [r for r in h.traffic() if r["kind"] == kind]


def test_a_routine_write_from_a_trusted_chat_member_is_sent_as_trusted(group):
    h = group
    h.ctx.settings["trusted_chats"] = [f"discord:{CHAT}"]
    h.next = {"risk": 20.0}
    _turn(h)
    assert _call(h, "c1") is None
    assert h.scans[-1]["trigger"]["sender"] == TRUSTED_MEMBER


def test_the_same_write_from_an_untrusted_group_stays_other(group):
    h = group
    h.ctx.settings["trusted_chats"] = ["discord:c-another"]
    _turn(h)
    _call(h, "c1")
    assert h.scans[-1]["trigger"]["sender"] == OTHER_IN_GROUP


def test_members_answer_reviews_in_a_trusted_chat(group):
    h = group
    h.ctx.settings["trusted_chats"] = [f"discord:{CHAT}"]
    _turn(h)
    out = _call(h, "c1")
    assert out is not None and out["action"] == "approve"


def test_a_session_answer_in_a_trusted_chat_is_kept_for_the_chat_but_sets_no_grant(group):
    h = group
    h.ctx.settings["trusted_chats"] = [f"discord:{CHAT}"]
    h.next = {"hints": [HINT]}
    _turn(h)
    out = _call(h, "c1")
    assert out["action"] == "approve"
    # The prompt never offers to set the grant: whoever answers is not known to be the owner.
    assert "trusts" not in out["message"]
    _answer(h, out, "session")
    h.next = {"risk": 50.0, "hints": [HINT]}
    assert _call(h, "c2") is None  # the same job at no higher risk goes through
    assert _records(h)[-1]["decision"] == "allowed"
    grants_file = h.dir / "sentrook" / "grants.json"
    assert not grants_file.exists() or json.loads(grants_file.read_text()).get("grants") == []


def test_a_session_answer_in_an_untrusted_group_keeps_nothing(group):
    h = group
    _turn(h)
    out = _call(h, "c1")
    _answer(h, out, "session")
    h.next = {"risk": 50.0}
    assert _call(h, "c2")["action"] == "approve"


def test_an_owner_only_trusted_chat_holds_a_members_review_for_the_owner(group):
    h = group
    h.ctx.settings["trusted_chats"] = [{"chat": f"discord:{CHAT}", "owner_only": True}]
    _turn(h)
    out = _call(h, "c1")
    assert out == {"action": "block", "message": hold.HELD_CHAT_TEXT}
    rec = _records(h)[-1]
    assert rec["decision"] == "held"
    assert h.scans[-1]["trigger"]["sender"] == TRUSTED_MEMBER
    [entry] = json.loads((h.dir / "sentrook" / "holds.json").read_text())["holds"]
    assert entry["where"].startswith("trusted discord chat, session ")
    # The owner allows it from the terminal; the same call then runs once.
    speaking = h.facts
    h.facts = {}
    with pytest.MonkeyPatch.context() as m:
        m.setattr(plugin, "session_surface", lambda: "cli")
        reply = slash(h, f"allow {rec['hold']['id']}")
    assert "only runs in" not in reply and "Only the owner" not in reply, reply
    h.facts = speaking
    assert _call(h, "c1") is None
    assert _records(h)[-1]["decision"] == "allowed_by_pass"


def test_the_owners_own_turn_in_an_owner_only_chat_still_asks(group):
    h = group
    h.ctx.settings["trusted_chats"] = [{"chat": f"discord:{CHAT}", "owner_only": True}]
    h.facts = facts(user="u-owner")
    _turn(h, sender="u-owner")
    out = _call(h, "c1", sender="u-owner")
    assert out["action"] == "approve"


# ---- only the owner sets trust, from a direct message or the terminal -----------------------------------------


def slash(h, raw):
    return h.ctx.commands["sentrook"]["handler"](raw, session_id="")


@pytest.fixture
def term(harness, monkeypatch):
    """Commands run on the owner's machine (the local terminal)."""
    monkeypatch.setattr(plugin, "session_facts", lambda: {})
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    return harness


def stored(h):
    path = h.dir / "sentrook" / "settings.json"
    return json.loads(path.read_text()) if path.exists() else {}


def test_adding_a_chat_warns_first_and_needs_confirm(term):
    h = term
    reply = slash(h, f"trust-chat add discord:{CHAT}")
    assert reply.startswith("Warning: Everyone who can post there")
    assert "may approve a review there" in reply
    assert "trusted_chats" not in stored(h)
    reply = slash(h, f"trust-chat add discord:{CHAT} --confirm")
    assert reply.startswith(f"Trusted discord:{CHAT}")
    [entry] = stored(h)["trusted_chats"]
    assert entry["chat"] == f"discord:{CHAT}" and entry["owner_only"] is False
    # The change is logged by platform, never by id.
    [rec] = [r for r in h.traffic() if r["kind"] == "settings"]
    assert rec["op"] == "trust_chat_add" and rec["platform"] == "discord"
    assert CHAT not in json.dumps(rec)
    assert f"discord:{CHAT}" in slash(h, "trust-chat list")


def test_an_owner_only_chat_says_its_reviews_are_held(term):
    h = term
    assert "hold its reviews for you" in slash(h, f"trust-chat add discord:{CHAT} --owner-only")
    slash(h, f"trust-chat add discord:{CHAT} --owner-only --confirm")
    assert stored(h)["trusted_chats"][0]["owner_only"] is True
    assert "(reviews held for you)" in slash(h, "trust-chat list")


def test_a_platform_open_to_anyone_gets_a_louder_warning(term, monkeypatch):
    monkeypatch.setenv("DISCORD_ALLOW_ALL_USERS", "true")
    assert "lets anyone at all write to the agent" in slash(term, f"trust-chat add discord:{CHAT}")


def test_removing_a_chat_and_a_config_chat(term):
    h = term
    slash(h, f"trust-chat add discord:{CHAT} --confirm")
    assert slash(h, f"trust-chat remove discord:{CHAT}").startswith(f"Removed discord:{CHAT}")
    assert stored(h)["trusted_chats"] == []
    h.ctx.settings["trusted_chats"] = ["discord:c-config"]
    assert "remove it there" in slash(h, "trust-chat remove discord:c-config")


def test_a_trusted_user_is_added_the_same_way(term):
    h = term
    assert slash(h, "trust-user add discord:u-friend").startswith(
        "Warning: messages from discord:u-friend"
    )
    slash(h, "trust-user add discord:u-friend --confirm")
    assert stored(h)["trusted_senders"][0]["user"] == "discord:u-friend"
    assert "Unknown option --owner-only" in slash(h, "trust-user add discord:u-friend --owner-only")


@pytest.mark.parametrize(
    "raw", ["trust-chat add discord", "trust-chat add cron:1 --confirm", "trust-chat add"]
)
def test_a_bad_ref_changes_nothing(term, raw):
    assert "usage" in slash(term, raw) or "is not a chat" in slash(term, raw)
    assert "trusted_chats" not in stored(term)


@pytest.mark.parametrize("verb", ["trust-chat", "trust-user"])
def test_trust_cannot_be_set_from_a_group_or_by_anyone_else(harness, monkeypatch, verb):
    # The ticket's prompt-injection case: a group member asks the agent (or runs the command) to trust them or the
    # chat. The owner check refuses every group, the owner's own messages there included.
    h = harness
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "u-owner")
    ref = f"discord:{CHAT}" if verb == "trust-chat" else "discord:u-member"
    for who in ("u-member", "u-owner"):
        monkeypatch.setattr(plugin, "session_facts", lambda who=who: facts(user=who))
        reply = h.ctx.commands["sentrook"]["handler"](
            f"{verb} add {ref} --confirm", session_id="s-group", platform="discord"
        )
        assert reply in refusals(verb), reply
    assert stored(h).get("trusted_chats") in (None, [])
    assert stored(h).get("trusted_senders") in (None, [])


def test_the_owners_own_direct_chat_cannot_be_trusted_as_a_chat(harness, monkeypatch):
    h = harness
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "u-owner")
    dm = facts(user="u-owner", chat_type="dm", chat_id="d-owner")
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(dm))
    reply = h.ctx.commands["sentrook"]["handler"](
        "trust-chat add discord:d-owner --confirm", session_id="s-dm", platform="discord"
    )
    assert reply.startswith("This is your direct chat with the agent")
    assert stored(h).get("trusted_chats") in (None, [])


def test_help_lists_the_trust_commands_as_owner_only():
    text = commands.run_help()
    assert "/sentrook trust-chat add|remove|list" in text
    assert "/sentrook trust-user add|remove|list" in text


# ---- the setup screen --------------------------------------------------------------------------------------------


def test_the_setup_screen_shows_a_proposed_trusted_chat_with_its_warning_and_sets_it(tmp_path):
    from datetime import UTC, datetime

    from plugin import setup
    from plugin.config import resolve_config

    now = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)
    home = tmp_path / "home"
    state = home / "sentrook"
    state.mkdir(parents=True)
    (state / "proposals.json").write_text(
        json.dumps(
            {
                "version": 1,
                "proposals": [
                    {
                        "id": "p-a1b2c3",
                        "session_ref": "s_0000000000d1",
                        "created_at": "2026-11-28T11:00:00Z",
                        "expires_at": "2026-11-29T11:00:00Z",
                        "items": [
                            {"trusted_chat": "discord:111", "reason": "The team server"},
                            {"trusted_chat": "discord:222", "owner_only": True, "reason": "Ops"},
                            {"trusted_sender": "discord:u-friend", "reason": "A colleague"},
                        ],
                    }
                ],
            }
        )
    )
    group = {"chat": "discord:111", "sender": "a1"}
    (state / "traffic.jsonl").write_text(
        json.dumps(
            {
                "ts": "2026-11-28T10:00:00.000Z",
                "kind": "scan",
                "request_id": "r-1",
                "session_ref": "s_0000000000g1",
                "group": group,
                "planir": {"trigger": {"kind": "message", "sender": {"relation": "other"}}},
            }
        )
        + "\n"
    )
    cfg = resolve_config({}, {"HOME": str(tmp_path), "HERMES_HOME": str(home)})
    records = []
    who = {"basis": ["local_terminal"], "platform": "", "sender_ref": None}

    def run(args):
        return setup.run(
            cfg,
            args,
            who,
            now,
            "/sentrook {}".format,
            records.append,
            home=home,
            host_cfg={},
            code=lambda: "4821",
        )

    screen = run("")
    assert (
        "Trust the chat `discord:111`: its members' messages count as from someone you know"
        in screen
    )
    assert "Seen lately: 1 call from 1 person in this chat" in screen
    assert "Warning: members there may approve the agent's reviews." in screen
    assert "Trust the chat `discord:222`" in screen and "its reviews are held for you" in screen
    assert "Sentrook has not seen the agent used in this chat lately." in screen
    assert "Trust the person `discord:u-friend`" in screen
    reply = run("apply 4821")
    assert "Trusted discord:111" in reply and "Trusted discord:u-friend" in reply
    saved = json.loads((state / "settings.json").read_text())
    assert {e["chat"]: e["owner_only"] for e in saved["trusted_chats"]} == {
        "discord:111": False,
        "discord:222": True,
    }
    assert [e["user"] for e in saved["trusted_senders"]] == ["discord:u-friend"]
    settings = [r for r in records if r.get("kind") == "settings"]
    assert {r["op"] for r in settings} == {"trust_chat_add", "trust_user_add"}
    assert all("111" not in json.dumps(r) and "u-friend" not in json.dumps(r) for r in settings)
    # Shown again, nothing is left to set.
    assert "Trust the chat" not in run("")


def test_a_trusted_users_session_answer_in_an_untrusted_group_keeps_nothing(group):
    # Anyone the host admits may answer there: the answer is kept only in a chat the owner trusts.
    h = group
    h.ctx.settings["trusted_senders"] = ["discord:u-member"]
    _turn(h)
    out = _call(h, "c1")
    assert h.scans[-1]["trigger"]["sender"]["relation"] == "trusted"
    _answer(h, out, "session")
    h.next = {"risk": 50.0}
    assert _call(h, "c2")["action"] == "approve"


def test_a_trusted_chat_cannot_lower_a_floor(group):
    # The scanner applies its floors whoever sent the turn: an enforced block from a trusted chat stays a block.
    h = group
    h.ctx.settings["trusted_chats"] = [f"discord:{CHAT}"]
    h.next = {
        "risk": 100.0,
        "enforced": "block",
        "floors": [{"floor": "sensitive_data_sent", "min_risk": 100, "enforce": "block"}],
    }
    _turn(h)
    out = _call(h, "c1")
    assert h.scans[-1]["trigger"]["sender"] == TRUSTED_MEMBER
    assert out["action"] == "block"
    assert _records(h)[-1]["decision"] == "blocked"
