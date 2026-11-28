"""A trusted Discord server (`trust-chat add discord:server:<server id>`).

Every channel and thread in a server the owner trusts is covered, including ones created later: a turn matches when
Hermes reports that server for it (`HERMES_SESSION_SCOPE_ID`). A server entry never covers a direct message, a chat id
is never read as a server id (nor the other way round), and the entry is refused where Hermes cannot say which server
a message came from. The same owner-only protections as a trusted chat apply.
"""

import json
import sys
import types
from pathlib import Path

import pytest

import plugin
from plugin import cli, setup, trust
from plugin.intent import sender_of, session_facts
from plugin.trust import Trust, parse_ref, server_problem

from .conftest import refusals
from .test_trust import _call, _turn, facts, group, slash, stored  # noqa: F401 - group is a fixture

SERVER = "111"
TRUSTED_MEMBER = {"relation": "trusted", "basis": ["plugin_allowlist:chat", "group_chat"]}
OTHER_IN_GROUP = {"relation": "other", "basis": ["group_chat"]}
ALLOW = {"DISCORD_ALLOWED_USERS": "u-owner"}
IN_SERVER = Trust(chats={f"discord:server:{SERVER}": False})


@pytest.fixture(autouse=True)
def reported(monkeypatch):
    """Hermes reports the server for a turn (the gateway is not installed in these tests)."""
    monkeypatch.setattr(trust, "server_support", lambda: None)


# ---- must stay silent: members anywhere in the server --------------------------------------------------------


@pytest.mark.parametrize("chat_id", ["c-general", "c-created-later"])
def test_a_member_in_any_channel_of_a_trusted_server_is_trusted(chat_id):
    f = facts(chat_id=chat_id, scope_id=SERVER)
    assert sender_of("discord", f, None, ALLOW, IN_SERVER) == TRUSTED_MEMBER


def test_a_member_in_a_thread_of_a_trusted_server_is_trusted():
    f = facts(chat_id="c-thread", chat_type="thread", parent_chat_id="c-general", scope_id=SERVER)
    assert sender_of("discord", f, None, ALLOW, IN_SERVER) == TRUSTED_MEMBER


def test_the_owner_in_a_trusted_server_stays_the_owner():
    f = facts(user="u-owner", scope_id=SERVER)
    assert sender_of("discord", f, None, ALLOW, IN_SERVER) == {
        "relation": "owner",
        "basis": ["group_chat"],
    }


# ---- must still fire -------------------------------------------------------------------------------------------


def test_the_same_member_in_another_server_stays_other():
    assert sender_of("discord", facts(scope_id="222"), None, ALLOW, IN_SERVER) == OTHER_IN_GROUP
    # No server reported (an older gateway, or a platform event without one): nothing matches.
    assert sender_of("discord", facts(), None, ALLOW, IN_SERVER) == OTHER_IN_GROUP


def test_a_direct_message_from_a_member_is_never_covered_by_a_server():
    dm = facts(chat_type="dm", chat_id="d-member", scope_id=SERVER)
    assert sender_of("discord", dm, None, {}, IN_SERVER) == {
        "relation": "other",
        "basis": ["host_open_access"],
    }


def test_a_channel_id_equal_to_the_server_id_is_not_the_server():
    # On Discord an old #general channel can share its server's id. A server entry matches only the server Hermes
    # reports, and a channel entry only the chat.
    f = facts(chat_id=SERVER, scope_id="222")
    assert sender_of("discord", f, None, ALLOW, IN_SERVER) == OTHER_IN_GROUP
    by_channel = Trust(chats={f"discord:{SERVER}": False})
    f = facts(chat_id="c-other", scope_id=SERVER)
    assert sender_of("discord", f, None, ALLOW, by_channel) == OTHER_IN_GROUP


def test_a_chat_id_written_like_a_server_entry_is_not_matched():
    f = facts(chat_id=f"server:{SERVER}", scope_id="222")
    assert sender_of("discord", f, None, ALLOW, IN_SERVER) == OTHER_IN_GROUP


def test_a_server_reported_on_another_platform_does_not_match():
    f = {**facts(scope_id=SERVER), "platform": "slack"}
    assert sender_of("slack", f, None, ALLOW, IN_SERVER) == OTHER_IN_GROUP


def test_an_owner_only_entry_wins_when_a_chat_and_its_server_are_both_trusted():
    t = Trust(chats={"discord:c-general": False, f"discord:server:{SERVER}": True})
    assert t.chat("discord", facts(chat_id="c-general", scope_id=SERVER)) == (
        "discord:c-general",
        True,
    )
    assert t.chat("discord", facts(chat_id="c-new", scope_id=SERVER)) == (
        f"discord:server:{SERVER}",
        True,
    )


@pytest.mark.parametrize(
    "raw",
    [
        "discord:server:",
        "discord:server:abc",
        "discord:server:12 3",
        "slack:server:T123",
        "telegram:server:1",
    ],
)
def test_a_server_entry_needs_discord_and_a_number(raw):
    assert parse_ref(raw) is None


def test_a_server_entry_is_normalised():
    assert parse_ref(f"Discord:SERVER:{SERVER}") == ("discord", f"server:{SERVER}")
    assert server_problem("slack:server:T1").startswith(
        "A whole server can be trusted only on Discord"
    )
    assert server_problem("discord:server:x").startswith("A Discord server id is a number")
    assert server_problem("discord:123") is None


def test_hermes_session_facts_carry_the_server_id(monkeypatch):
    values = {"HERMES_SESSION_SCOPE_ID": SERVER, "HERMES_SESSION_CHAT_ID": "c-general"}
    mod = types.ModuleType("gateway.session_context")
    mod.get_session_env = lambda name, default="": values.get(name, default)
    monkeypatch.setitem(sys.modules, "gateway", types.ModuleType("gateway"))
    monkeypatch.setitem(sys.modules, "gateway.session_context", mod)
    got = session_facts()
    assert got["scope_id"] == SERVER and got["chat_id"] == "c-general"


def test_server_support_reads_the_gateway(monkeypatch):
    monkeypatch.undo()  # the real check, not the fixture's
    monkeypatch.setitem(sys.modules, "gateway", None)
    assert "no gateway session context" in trust.server_support()
    mod = types.ModuleType("gateway.session_context")
    mod.get_session_env = lambda name, default="": default
    monkeypatch.setitem(sys.modules, "gateway", types.ModuleType("gateway"))
    monkeypatch.setitem(sys.modules, "gateway.session_context", mod)
    assert trust.server_support() is None
    # The gateway is read in intent.py only, beside the session facts (no new private import for the validator).
    assert "gateway" not in Path(trust.__file__).read_text()


# ---- the owner's command -----------------------------------------------------------------------------------


@pytest.fixture
def term(harness, monkeypatch):
    monkeypatch.setattr(plugin, "session_facts", lambda: {})
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    return harness


def test_adding_a_server_warns_that_every_channel_is_covered_then_needs_confirm(term):
    h = term
    reply = slash(h, f"trust-chat add discord:server:{SERVER}")
    assert reply.startswith(
        "Warning: Everyone who can post in any channel or thread of this server, including ones created later,"
    )
    assert "Trust a server only when you know every member and who can join it" in reply
    assert "trusted_chats" not in stored(h)
    reply = slash(h, f"trust-chat add discord:server:{SERVER} --confirm")
    assert reply.startswith(
        f"Trusted discord:server:{SERVER}: messages from its members in every channel and thread"
    )
    [entry] = stored(h)["trusted_chats"]
    assert entry["chat"] == f"discord:server:{SERVER}" and entry["owner_only"] is False
    [rec] = [r for r in h.traffic() if r["kind"] == "settings"]
    assert rec == {**rec, "op": "trust_chat_add", "platform": "discord"}
    assert SERVER not in json.dumps(rec)
    listed = slash(h, "trust-chat list")
    assert f"- discord:server:{SERVER} (every channel and thread in this server)" in listed
    assert "(1 whole server)" in listed
    assert slash(h, f"trust-chat remove discord:server:{SERVER}").startswith(
        f"Removed discord:server:{SERVER}"
    )


def test_a_server_can_be_owner_only(term):
    slash(term, f"trust-chat add discord:server:{SERVER} --owner-only --confirm")
    assert stored(term)["trusted_chats"][0]["owner_only"] is True


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ("slack:server:T123", "only on Discord"),
        ("discord:server:general", "is a number"),
    ],
)
def test_a_server_entry_off_discord_or_without_a_number_is_refused(term, raw, why):
    reply = slash(term, f"trust-chat add {raw} --confirm")
    assert why in reply and "Nothing was changed" in reply
    assert "trusted_chats" not in stored(term)


def test_a_server_is_refused_where_hermes_cannot_report_it(term, monkeypatch):
    monkeypatch.setattr(trust, "server_support", lambda: "this Hermes does not report which server")
    reply = slash(term, f"trust-chat add discord:server:{SERVER} --confirm")
    assert reply.startswith(
        "A whole server cannot be trusted here: this Hermes does not report which server"
    )
    assert "trusted_chats" not in stored(term)
    # A channel is still trusted as before.
    assert slash(term, "trust-chat add discord:c-ops --confirm").startswith("Trusted discord:c-ops")


def test_a_server_cannot_be_trusted_from_inside_it(harness, monkeypatch):
    h = harness
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "u-owner")
    for who in ("u-member", "u-owner"):
        monkeypatch.setattr(
            plugin, "session_facts", lambda who=who: facts(user=who, scope_id=SERVER)
        )
        reply = h.ctx.commands["sentrook"]["handler"](
            f"trust-chat add discord:server:{SERVER} --confirm",
            session_id="s-group",
            platform="discord",
        )
        assert reply in refusals("trust-chat"), reply
    assert stored(h).get("trusted_chats") in (None, [])


# ---- verify -------------------------------------------------------------------------------------------------


def _verify(h):
    return {n: (ok, d) for n, ok, d in cli.run_verify(dict(h.ctx.settings), env={}, timeout=0.01)}


def test_verify_names_a_trusted_server(harness):
    harness.ctx.settings["trusted_chats"] = [f"discord:server:{SERVER}", "discord:c-ops"]
    ok, detail = _verify(harness)["trusted chats"]
    assert ok and detail.startswith("Trusted: 2 trusted chats (1 whole server)")


def test_verify_fails_a_server_hermes_cannot_match(harness, monkeypatch):
    monkeypatch.setattr(trust, "server_support", lambda: "this Hermes does not report which server")
    harness.ctx.settings["trusted_chats"] = [f"discord:server:{SERVER}"]
    ok, detail = _verify(harness)["trusted chats"]
    assert (
        not ok
        and "the trusted servers never match: this Hermes does not report which server" in detail
    )


# ---- end to end, and the setup screen -------------------------------------------------------------------------


def test_a_write_from_any_channel_of_a_trusted_server_is_sent_as_trusted(group):  # noqa: F811 - the fixture
    h = group
    h.ctx.settings["trusted_chats"] = [f"discord:server:{SERVER}"]
    h.facts = facts(chat_id="c-new-channel", scope_id=SERVER)
    h.next = {"risk": 20.0}
    _turn(h)
    assert _call(h, "c1") is None
    assert h.scans[-1]["trigger"]["sender"] == TRUSTED_MEMBER
    # The same member in another server is a stranger.
    h.facts = facts(chat_id="c-elsewhere", scope_id="222")
    _turn(h)
    _call(h, "c2")
    assert h.scans[-1]["trigger"]["sender"] == OTHER_IN_GROUP


def test_the_setup_screen_describes_a_whole_server():
    item = {"kind": "trusted_chat", "pattern": f"discord:server:{SERVER}", "owner_only": False}
    assert setup.describe(item, None).startswith(
        f"Trust the whole server `discord:server:{SERVER}`"
    )
    [warning, reviews] = setup.item_warnings(item)
    assert "including ones created later" in warning and "members there may approve" in reviews
