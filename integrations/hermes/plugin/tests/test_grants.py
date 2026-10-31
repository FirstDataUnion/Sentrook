"""Grants and channel bindings set by command, kept in `<state>/sentrook/grants.json`."""

import argparse
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import plugin
from plugin import grants, owner
from plugin.config import resolve_config

#: Shared with the OpenClaw plugin's tests: both hosts print the same text for the same state.
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "grants"
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def golden(name):
    return (FIXTURES / name).read_text().rstrip("\n").replace("{bind}", "/sentrook bind")


@pytest.fixture
def term(harness, monkeypatch):
    """Commands run from the local terminal unless a test sets chat facts."""
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM"):
        monkeypatch.delenv(k, raising=False)
    facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(facts))
    monkeypatch.setattr(owner, "gateway_engaged", lambda: bool(facts.get("platform")))
    harness.facts = facts
    harness.file = harness.dir / "sentrook" / "grants.json"
    return harness


def slash(h, raw_args):
    return h.ctx.commands["sentrook"]["handler"](raw_args)


def cli(h, capsys, *argv):
    parser = argparse.ArgumentParser()
    h.ctx.cli["setup_fn"](parser)
    h.ctx.cli["handler_fn"](parser.parse_args(list(argv)))
    return capsys.readouterr().out.rstrip("\n")


def stored(h):
    return json.loads(h.file.read_text())


def records(h, kind):
    return [r for r in h.traffic() if r.get("kind") == kind]


def scan_grants(h, cmd):
    """The grants sent with one scan of `cmd`."""
    h.ctx.hooks["pre_tool_call"](
        tool_name="terminal",
        args={"command": cmd},
        tool_call_id=f"c{len(h.scans)}",
        session_id="S1",
    )
    return h.scans[-1]["grants"]


def fixture_state(h):
    cfg = json.loads((FIXTURES / "config.json").read_text())
    h.ctx.settings.update(cfg)
    h.file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "grants.json", h.file)


def test_the_fixture_renders(term):
    fixture_state(term)
    cfg = resolve_config(term.ctx.settings)
    data = grants.load(cfg.state_dir)
    assert grants.format_grants(cfg, data, NOW, "/sentrook {}".format) == golden("grants.txt")
    assert grants.format_bindings(cfg, data) == golden("bindings.txt")
    assert grants.effective(cfg, data, NOW) == json.loads(
        (FIXTURES / "planir-grants.json").read_text()
    )


def test_a_grant_round_trips_through_the_file_and_into_scans(term):
    out = slash(term, "grant destination #ops")
    [g] = stored(term)["grants"]
    assert out == f"Granted {g['id']}: destination #ops (session)."
    assert g["id"].startswith("gr-")
    assert (g["kind"], g["pattern"], g["scope"]) == ("destination", "#ops", "session")
    assert "allows" not in g and "expires_at" not in g
    assert g["set_by"] == {"basis": ["local_terminal"], "platform": "", "sender_ref": None}
    assert datetime.fromisoformat(g["granted_at"].replace("Z", "+00:00")) <= datetime.now(UTC)
    assert f"{g['id']}  destination  session  #ops     set " in slash(term, "grants")
    sent = scan_grants(term, "post to #ops")
    assert sent == [
        {
            "grant_ref": "g_1",
            "kind": "destination",
            "pattern": "#ops",
            "scope": "session",
            "granted_at": g["granted_at"],
        }
    ]
    assert slash(term, f"revoke {g['id']}") == f"Revoked {g['id']}: destination #ops."
    assert stored(term)["grants"] == []
    assert scan_grants(term, "post to #ops") == []


def test_options_scope_allows_and_expiry(term):
    before = datetime.now(UTC)
    out = slash(term, "grant file /srv/reports/* --persistent --allows=read,write --expires 12h")
    [g] = stored(term)["grants"]
    assert (g["scope"], g["allows"]) == ("persistent", ["read", "write"])
    expires = datetime.fromisoformat(g["expires_at"].replace("Z", "+00:00"))
    assert timedelta(hours=11, minutes=59) < expires - before <= timedelta(hours=12, seconds=5)
    assert out.startswith(
        f"Granted {g['id']}: file /srv/reports/* (persistent, allows read,write, expires "
    )
    slash(term, "grant provider npm:left-pad --scope persistent")
    assert stored(term)["grants"][1]["scope"] == "persistent"
    slash(term, "grant destination #ops --scope session")
    assert stored(term)["grants"][2]["scope"] == "session"


@pytest.mark.parametrize(
    ("args", "reply"),
    [
        (
            "grant destination #ops --scope persistant",
            'Unknown scope "persistant": use session or persistent.',
        ),
        (
            "grant destination #ops --scope=Persistent",
            'Unknown scope "Persistent": use session or persistent.',
        ),
        ("grant destination #ops --persistant", "Unknown option --persistant."),
        (
            "grant destinaton #ops",
            'Unknown grant kind "destinaton": use destination, file or provider.',
        ),
        (
            "grant file /x --allows read,wrte",
            'Unknown allows value "wrte": use read, write, edit, delete or exec.',
        ),
        ("grant destination #ops --allows write", "--allows applies to file grants only."),
        (
            "grant destination #ops --expires 2w",
            'Unknown expiry "2w": use a number with m, h or d, from 1m to 365d.',
        ),
        (
            "grant destination #ops --expires 366d",
            'Unknown expiry "366d": use a number with m, h or d, from 1m to 365d.',
        ),
        ("grant destination #ops --expires", "--expires needs a value."),
        ("grant destination", None),
        ("grant destination #ops extra", None),
        ("grant destination " + "x" * 257, "The pattern must be at most 256 printable characters."),
    ],
)
def test_bad_input_is_refused_and_nothing_is_written(term, args, reply):
    out = slash(term, args)
    usage = grants.grant_usage("/sentrook grant")
    assert out == (f"{reply}\n{usage}" if reply else usage)
    assert not term.file.exists()
    assert records(term, "grants") == []


def test_config_scope_is_strict():
    cfg = resolve_config(
        {
            "grants": [
                {"kind": "destination", "pattern": "a.example"},
                {"kind": "destination", "pattern": "b.example", "scope": "persistent"},
                {"kind": "destination", "pattern": "c.example", "scope": "session"},
                {"kind": "destination", "pattern": "d.example", "scope": "persistant"},
                {"kind": "destination", "pattern": "e.example", "scope": "Persistent"},
                {"kind": "destination", "pattern": "f.example", "scope": True},
            ]
        },
        {},
    )
    assert [g["scope"] for g in cfg.grants] == [
        "persistent",
        "persistent",
        "session",
        "session",
        "session",
        "session",
    ]


@pytest.mark.parametrize(
    "facts",
    [
        {"platform": "mattermost", "chat_type": "group", "user_id": "u1"},
        {"platform": "mattermost", "chat_type": "dm", "user_id": "u2"},
        {"platform": "api_server"},
    ],
)
@pytest.mark.parametrize(
    ("verb", "args"),
    [
        ("grants", ""),
        ("grant", "destination #ops"),
        ("revoke", "gr-1a2b3c"),
        ("bind", "add #ops"),
        ("bind", "remove discord:1234"),
        ("bind", "list"),
    ],
)
def test_a_non_owner_is_refused_and_nothing_changes(term, monkeypatch, facts, verb, args):
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "u1")
    fixture_state(term)
    before = term.file.read_text()
    term.facts.update(facts)
    assert slash(term, f"{verb} {args}") == owner.refusal(verb)
    assert term.file.read_text() == before
    [rec] = records(term, "command")
    assert (rec["verb"], rec["outcome"]) == (verb, "refused")
    assert records(term, "grants") == []


def test_the_owner_in_a_dm_is_recorded_as_the_setter(term, monkeypatch):
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "u1")
    term.facts.update({"platform": "mattermost", "chat_type": "dm", "user_id": "u1"})
    slash(term, "grant destination #ops")
    [g] = stored(term)["grants"]
    assert g["set_by"]["basis"] == ["host_allowlist_dm"]
    assert g["set_by"]["platform"] == "mattermost"
    assert g["set_by"]["sender_ref"].startswith("u_") and "u1" not in g["set_by"]["sender_ref"]


def test_config_entries_are_read_only(term):
    fixture_state(term)
    before = term.file.read_text()
    assert slash(term, "revoke cfg-1") == "cfg-1 is set in the plugin config; remove it there."
    assert slash(term, "revoke gr-zzzzzz") == "No grant gr-zzzzzz; see /sentrook grants."
    assert slash(term, "revoke") == "usage: /sentrook revoke <id>, with an id from /sentrook grants"
    assert (
        slash(term, "bind remove #daily-brief")
        == "#daily-brief is bound in the plugin config; remove it there."
    )
    assert (
        slash(term, "bind add #daily-brief")
        == "#daily-brief is already bound in the plugin config."
    )
    assert slash(term, "bind add discord:1234") == "discord:1234 is already bound."
    assert slash(term, "bind remove #nowhere") == "#nowhere is not bound."
    assert term.file.read_text() == before
    assert records(term, "grants") == []


def test_bindings_round_trip(term):
    assert slash(term, "bind add discord:999") == "Channel binding added: discord:999."
    [b] = stored(term)["bindings"]
    assert b["pattern"] == "discord:999" and b["set_by"]["basis"] == ["local_terminal"]
    assert "discord:999  set " in slash(term, "bind list")
    assert slash(term, "bind") == slash(term, "bind list")
    assert scan_grants(term, "send to discord:999")[0] | {"granted_at": None} == {
        "grant_ref": "g_1",
        "kind": "destination",
        "pattern": "discord:999",
        "scope": "persistent",
        "granted_at": None,
    }
    assert slash(term, "bind remove discord:999") == "Channel binding removed: discord:999."
    assert stored(term)["bindings"] == []
    assert (
        slash(term, "bind frob x")
        == "usage: /sentrook bind add|remove <channel>, or /sentrook bind list"
    )


def test_every_change_is_audited(term):
    slash(term, "grant destination #ops")
    gid = stored(term)["grants"][0]["id"]
    slash(term, f"revoke {gid}")
    slash(term, "bind add discord:999")
    slash(term, "bind remove discord:999")
    changes = records(term, "grants")
    assert [r["op"] for r in changes] == ["grant", "revoke", "bind_add", "bind_remove"]
    assert changes[0]["entry"]["id"] == gid and changes[1]["entry"]["id"] == gid
    assert changes[2]["entry"]["pattern"] == "discord:999"
    assert all(r["entry"]["set_by"]["basis"] == ["local_terminal"] for r in changes)
    assert [r["verb"] for r in records(term, "command")] == ["grant", "revoke", "bind", "bind"]


def test_expired_grants_are_not_sent_and_are_dropped_on_the_next_change(term):
    fixture_state(term)
    sent = scan_grants(term, "npm install npm:left-pad then post to #ops")
    assert [g["pattern"] for g in sent] == ["#ops"]
    slash(term, "bind add discord:999")
    assert "gr-4d5e6f" not in [g.get("id") for g in stored(term)["grants"]]
    assert "gr-1a2b3c" in [g.get("id") for g in stored(term)["grants"]]


def test_an_expired_grant_can_still_be_revoked(term):
    fixture_state(term)
    assert slash(term, "revoke gr-4d5e6f") == "Revoked gr-4d5e6f: provider npm:left-pad."
    assert [r["op"] for r in records(term, "grants")] == ["revoke"]


def test_an_over_broad_pattern_is_stored_as_typed(term):
    """Whether a pattern is too broad to relieve on is the scanner's call, not the plugin's."""
    out = slash(term, "grant destination *")
    assert out.startswith("Granted ") and out.endswith(": destination * (session).")
    assert stored(term)["grants"][0]["pattern"] == "*"


@pytest.mark.parametrize(
    "expires_at",
    [
        "2026-11-05 09:00:00",
        "11/05/2026",
        "Nov 5 2026 09:00",
        "2026-11-05",
        "soon",
        7,
        # A field out of range is unreadable, not rolled forward into a later time.
        "2099-12-31T24:00Z",
        "2099-02-30T00:00Z",
        "2099-12-31T12:30:60Z",
    ],
)
def test_an_expiry_in_any_other_form_counts_as_past(term, expires_at):
    term.file.parent.mkdir(parents=True, exist_ok=True)
    entry = {"id": "gr-000001", "kind": "destination", "pattern": "#ops", "expires_at": expires_at}
    term.file.write_text(json.dumps({"grants": [entry]}))
    assert scan_grants(term, "post to #ops") == []
    assert "expired ?" in slash(term, "grants")


def test_a_null_list_makes_the_file_unreadable(term):
    term.file.parent.mkdir(parents=True, exist_ok=True)
    term.file.write_text('{"grants": null}')
    assert "could not be read" in slash(term, "bind add #x")


def test_an_unreadable_grants_file_blocks_changes_but_not_scans(term):
    term.ctx.settings["grants"] = [{"kind": "destination", "pattern": "#ops"}]
    term.file.parent.mkdir(parents=True, exist_ok=True)
    term.file.write_text("{not json")
    assert slash(term, "grant destination #x") == (
        f"The grants file {term.file} could not be read; fix or remove it first."
    )
    assert term.file.read_text() == "{not json"
    assert "The grants file could not be read" in slash(term, "grants")
    assert [g["pattern"] for g in scan_grants(term, "post to #ops")] == ["#ops"]


def test_the_cli_forms_match_the_slash_forms(term, capsys):
    fixture_state(term)
    assert cli(term, capsys, "grants") == slash(term, "grants")
    assert cli(term, capsys, "bind", "list") == slash(term, "bind list")
    out = cli(term, capsys, "grant", "file", "/srv/x/*", "--allows", "read", "--persistent")
    gid = out.split()[1].rstrip(":")
    assert out == f"Granted {gid}: file /srv/x/* (persistent, allows read)."
    first = cli(term, capsys, "grant", "--persistent", "--expires=1h", "destination", "#y")
    assert first.endswith(").") and ": destination #y (persistent, expires " in first
    slash(term, f"revoke {first.split()[1].rstrip(':')}")
    assert cli(term, capsys, "grant", "file", "/x", "--scope", "persistant").startswith(
        'Unknown scope "persistant"'
    )
    assert cli(term, capsys, "revoke", gid) == f"Revoked {gid}: file /srv/x/*."
    assert cli(term, capsys, "bind", "add", "discord:5") == "Channel binding added: discord:5."
    assert {r["basis"][0] for r in records(term, "command")} == {"local_terminal"}


def test_status_counts_grants_from_both_sources(term):
    fixture_state(term)
    out = slash(term, "status").splitlines()
    assert "grants: 2 in config, 7 by command" in out
    assert "channel bindings: 1 in config, 1 by command" in out


def test_help_lists_the_grant_commands(term):
    text = slash(term, "help")
    for usage in ("/sentrook grants", "/sentrook grant <kind> <pattern>", "/sentrook revoke <id>"):
        assert usage in text
    assert "/sentrook bind add|remove|list [channel]" in text
