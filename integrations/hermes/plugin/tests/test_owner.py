"""Owner-only commands: who may run a command that changes how Sentrook behaves, and the audit trail."""

import hashlib
import hmac

import pytest

import plugin
from plugin import owner

ALLOWLIST = {"MATTERMOST_ALLOWED_USERS": "u1"}


def dm(user):
    return {"platform": "mattermost", "chat_type": "dm", "user_id": user}


def test_owner_is_an_allowlisted_dm_or_the_local_terminal():
    assert owner.owner_of(dm("u1"), ALLOWLIST) == {
        "owner": True,
        "basis": ["host_allowlist_dm"],
        "platform": "mattermost",
    }
    assert owner.owner_of(dm("u1"), {"GATEWAY_ALLOWED_USERS": "u1"})["owner"]
    # Inside a command handler an empty platform can only be the local CLI or TUI.
    assert owner.owner_of({}, {}) == {"owner": True, "basis": ["local_terminal"], "platform": ""}
    assert owner.owner_of({"platform": "cli"}, {})["owner"]


@pytest.mark.parametrize(
    ("facts", "env", "basis"),
    [
        ({**dm("u1"), "chat_type": "group"}, ALLOWLIST, ["group_chat"]),
        ({**dm("u1"), "chat_type": "channel"}, ALLOWLIST, ["group_chat"]),
        (dm("u2"), ALLOWLIST, ["host_open_access"]),
        (dm("u1"), {"MATTERMOST_ALLOW_ALL_USERS": "true"}, ["host_open_access"]),
        ({"platform": "mattermost", "user_id": "u1"}, ALLOWLIST, ["none"]),
        ({"platform": "api_server"}, ALLOWLIST, ["none"]),
        ({"platform": "webhook"}, ALLOWLIST, ["none"]),
        ({"platform": "cron"}, ALLOWLIST, ["none"]),
        ({"platform": "subagent"}, ALLOWLIST, ["none"]),
        # No session facts, but the process says it serves a chat platform: not the local terminal.
        ({}, {"HERMES_SESSION_PLATFORM": "mattermost"}, ["none"]),
    ],
)
def test_everyone_else_is_refused(facts, env, basis):
    check = owner.owner_of(facts, env)
    assert check["owner"] is False
    assert check["basis"] == basis


@pytest.fixture
def gated(harness, monkeypatch):
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "u1")
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM", "GATEWAY_ALLOWED_USERS"):
        monkeypatch.delenv(k, raising=False)
    facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(facts))
    ran = []
    handler = plugin.owner_command("grant", lambda raw_args: ran.append(raw_args) or "granted")
    commands = lambda: [r for r in harness.traffic() if r["kind"] == "command"]  # noqa: E731
    return facts, handler, ran, commands


def test_owner_runs_the_command_and_is_audited(gated, harness):
    facts, handler, ran, commands = gated
    facts.update(dm("u1"))
    assert handler("exec 24h") == "granted"
    assert ran == ["exec 24h"]
    salt = (harness.dir / "sentrook" / "salt").read_text().strip()
    ref = "u_" + hmac.new(salt.encode(), b"u1", hashlib.sha256).hexdigest()[:16]
    [rec] = commands()
    assert {k: rec[k] for k in ("verb", "outcome", "basis", "sender_ref", "platform")} == {
        "verb": "grant",
        "outcome": "allowed",
        "basis": ["host_allowlist_dm"],
        "sender_ref": ref,
        "platform": "mattermost",
    }
    assert rec["ts"]
    assert "u1" not in str(rec)


def test_local_terminal_runs_the_command(gated):
    _facts, handler, ran, commands = gated
    assert handler("") == "granted"
    assert ran == [""]
    [rec] = commands()
    assert (rec["outcome"], rec["basis"], rec["sender_ref"]) == (
        "allowed",
        ["local_terminal"],
        None,
    )


@pytest.mark.parametrize(
    "facts",
    [
        {**dm("u1"), "chat_type": "group"},
        dm("u2"),
        {"platform": "api_server"},
    ],
)
def test_non_owner_is_refused_and_audited(gated, facts):
    current, handler, ran, commands = gated
    current.update(facts)
    reply = handler("exec 24h")
    assert reply.startswith("Only the owner can run /sentrook grant")
    assert ran == []
    [rec] = commands()
    assert rec["verb"] == "grant"
    assert rec["outcome"] == "refused"
    assert rec["basis"] != ["host_allowlist_dm"]


def test_allow_all_dm_is_refused(gated, monkeypatch):
    facts, handler, ran, commands = gated
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "")
    monkeypatch.setenv("MATTERMOST_ALLOW_ALL_USERS", "true")
    facts.update(dm("u1"))
    assert handler("").startswith("Only the owner")
    assert ran == []
    assert commands()[0]["basis"] == ["host_open_access"]


def test_a_failing_owner_check_refuses(gated, monkeypatch):
    facts, handler, ran, commands = gated

    def boom():
        raise RuntimeError("session context unavailable")

    monkeypatch.setattr(plugin, "session_facts", boom)
    assert handler("").startswith("Only the owner")
    assert ran == []
