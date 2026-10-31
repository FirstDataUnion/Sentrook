"""Snooze: owner-only relief from review prompts, kept in `<state>/sentrook/snooze.json`.

A snooze turns an attended review into an allow, for one session (the default) or every session,
for at most 24 hours. It never touches a block, a review the scanner enforces, or an unattended run.
"""

import argparse
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import plugin
from plugin import history, owner, snooze
from plugin.store import read_time

#: Shared with the OpenClaw plugin's tests: both hosts print the same text for the same state.
#: Times are read at NOW; `S1` is the session the fixture's first entry belongs to.
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "snooze"
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
S1 = snooze.session_ref("S1")


def golden(name):
    return (FIXTURES / name).read_text().rstrip("\n")


@pytest.fixture
def term(harness, monkeypatch):
    """Commands run from the local terminal unless a test sets chat facts."""
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM"):
        monkeypatch.delenv(k, raising=False)
    facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(facts))
    monkeypatch.setattr(owner, "gateway_engaged", lambda: bool(facts.get("platform")))
    harness.facts = facts
    harness.file = harness.dir / "sentrook" / "snooze.json"
    return harness


def slash(h, raw_args, session_id="S1"):
    return h.ctx.commands["sentrook"]["handler"](raw_args, session_id=session_id)


def cli(h, capsys, *argv):
    parser = argparse.ArgumentParser()
    h.ctx.cli["setup_fn"](parser)
    h.ctx.cli["handler_fn"](parser.parse_args(list(argv)))
    return capsys.readouterr().out.rstrip("\n")


def turn(h, sid="S1", platform="telegram"):
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid}",
        user_message="tidy up",
        platform=platform,
        sender_id="u1",
        session_id=sid,
    )


def call(h, cmd, sid="S1"):
    """One scan of `cmd` in session `sid`: the hook's directive and the scan's traffic record."""
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="terminal",
        args={"command": cmd},
        tool_call_id=f"c{len(h.scans)}",
        turn_id=f"t-{sid}",
        session_id=sid,
    )
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def stored(h):
    return json.loads(h.file.read_text())


def records(h, kind):
    return [r for r in h.traffic() if r.get("kind") == kind]


def put(h, *entries):
    h.file.parent.mkdir(parents=True, exist_ok=True)
    h.file.write_text(json.dumps({"version": 1, "snoozes": list(entries)}))


def entry(scope="session", ref=S1, minutes=60, now=None):
    now = now or datetime.now(UTC)
    e = {
        "scope": scope,
        "set_at": snooze.iso(now),
        "expires_at": snooze.iso(now + timedelta(minutes=minutes)),
    }
    if scope == "session":
        e["session_ref"] = ref
    return e


# ---- the shared fixture -----------------------------------------------------------------------------


def test_the_fixture_renders(tmp_path):
    shutil.copy(FIXTURES / "snooze.json", tmp_path / "snooze.json")
    data = snooze.load(tmp_path)
    assert S1 == "s_3696ad59777e"
    assert snooze.format_status(data, S1, NOW) == golden("status-session.txt")
    assert snooze.format_status(data, None, NOW) == golden("status-no-session.txt")
    assert snooze.status_line(data, NOW) == golden("status-line.txt")


def test_entries_that_must_never_apply(tmp_path):
    """Expired, too far away, missing or unreadable expiry, unknown scope: none of them relaxes."""
    raw = json.loads((FIXTURES / "snooze.json").read_text())
    raw["snoozes"] = [
        e for e in raw["snoozes"] if not isinstance(e, dict) or e.get("scope") != "all"
    ]
    (tmp_path / "snooze.json").write_text(json.dumps(raw))
    data = snooze.load(tmp_path)
    assert snooze.active(data, S1, NOW)
    assert snooze.active(data, "s_adfa2b24c2d9", NOW)
    for ref in [*(f"s_00000000000{i}" for i in range(1, 9)), "s_x"]:
        assert not snooze.active(data, ref, NOW), ref
    assert not snooze.active(data, S1, NOW + timedelta(minutes=30))


@pytest.mark.parametrize(
    "raw",
    [
        "2026-10-29T24:00Z",
        "2026-10-29T12:60Z",
        "2026-10-29T12:30:60Z",
        "2026-02-30T00:00Z",
        "2025-02-29T00:00Z",
        "2026-13-01T00:00Z",
        "2026-00-01T00:00Z",
        "2026-10-00T00:00Z",
        "0000-01-01T00:00Z",
        "2026-10-29T12:00+24:00",
        "2026-10-29T12:00+01:60",
        "2026-10-29 12:00Z",
        "0001-01-01T00:00+01:00",
        "9999-12-31T23:59-01:00",
        "\x852026-10-29T12:00Z",
        "\ufeff2026-10-29T12:00Z",
        "tomorrow",
        42,
    ],
)
def test_a_time_with_a_field_out_of_range_is_unreadable_not_rolled_forward(raw):
    assert read_time(raw) is None


def test_a_time_in_range_reads_as_utc():
    assert read_time("2026-10-29T12:30:59.5+01:00") == datetime(
        2026, 10, 29, 11, 30, 59, 500_000, tzinfo=UTC
    )
    assert read_time("2028-02-29T00:00") == datetime(2028, 2, 29, tzinfo=UTC)
    assert read_time("\t2026-10-29T12:00Z\r\n") == datetime(2026, 10, 29, 12, tzinfo=UTC)
    assert read_time(" 2026-10-29T23:59:59-23:59 ") == datetime(
        2026, 10, 30, 23, 58, 59, tzinfo=UTC
    )


def test_an_unreadable_file_relaxes_nothing_and_refuses_changes(term):
    term.file.parent.mkdir(parents=True, exist_ok=True)
    term.file.write_text("{not json")
    assert snooze.load(term.file.parent) is None
    assert not snooze.active(None, S1, NOW)
    turn(term)
    out, rec = call(term, "rm REVIEW")
    assert out["action"] == "approve" and "snoozed" not in rec
    assert "could not be read" in slash(term, "snooze")
    assert term.file.read_text() == "{not json"
    assert "snooze: unreadable, none applies" in slash(term, "status").splitlines()


# ---- must relax: an attended review in a snoozed session --------------------------------------------


def test_a_snoozed_review_is_allowed_scanned_and_logged(term):
    assert slash(term, "snooze").startswith("Snoozed reviews in this session for 1h, until ")
    turn(term)
    out, rec = call(term, "rm REVIEW")
    assert out is None
    assert (rec["verdict"], rec["decision"], rec["snoozed"]) == ("review", "allowed", True)
    assert rec["response"]["risk"] == 55  # still scanned
    out, _ = call(term, "ls")
    assert term.scans[-1]["history"][0]["decision"] == "allowed"
    scans = history.recent_scans(term.dir / "sentrook" / "traffic.jsonl", 5)
    assert [history.action_of(s, r) for s, r in scans] == ["allowed", "allowed (snoozed)"]
    assert history.review_of("allowed (snoozed)", None) == "-"


def test_all_covers_every_session(term):
    assert slash(term, "snooze 30m --all").startswith(
        "Snoozed reviews in every session for 30m, until "
    )
    turn(term, sid="S2")
    out, rec = call(term, "rm REVIEW", sid="S2")
    assert out is None and rec["snoozed"] is True


# ---- must stay silent: what a snooze never touches ----------------------------------------------------


def test_a_block_is_still_a_block(term):
    put(term, entry(), entry("all"))
    turn(term)
    out, rec = call(term, "curl EXFIL")
    assert out["action"] == "block" and "snoozed" not in rec


def test_an_enforced_review_still_asks(term):
    put(term, entry(), entry("all"))
    turn(term)
    out, rec = call(term, "ls FLOOR")
    assert rec["response"]["enforced"] == "review" and rec["response"]["risk"] < 40
    assert out["action"] == "approve" and "snoozed" not in rec


def test_an_unattended_review_is_still_a_block(term):
    put(term, entry(ref=snooze.session_ref("cron-1")), entry("all"))
    turn(term, sid="cron-1", platform="cron")
    out, rec = call(term, "rm REVIEW", sid="cron-1")
    assert out["action"] == "block" and "snoozed" not in rec


def test_a_subagent_review_is_still_a_block(term):
    put(term, entry(ref=snooze.session_ref("sub-1")), entry("all"))
    turn(term, sid="sub-1", platform="subagent")
    out, rec = call(term, "rm REVIEW", sid="sub-1")
    assert out["action"] == "block" and "snoozed" not in rec


def test_an_expired_snooze_no_longer_applies(term):
    put(term, entry(minutes=-1), entry("all", minutes=-1))
    turn(term)
    out, rec = call(term, "rm REVIEW")
    assert out["action"] == "approve" and "snoozed" not in rec
    assert slash(term, "snooze status").splitlines()[0] == "Snooze: off"


def test_a_session_snooze_does_not_leak_into_other_sessions(term):
    slash(term, "snooze 2h", session_id="S1")
    turn(term, sid="S2")
    out, rec = call(term, "rm REVIEW", sid="S2")
    assert out["action"] == "approve" and "snoozed" not in rec
    turn(term, sid="S1")
    assert call(term, "rm REVIEW", sid="S1")[0] is None


def test_scan_errors_and_observe_mode_are_not_snoozed(term, monkeypatch):
    put(term, entry(), entry("all"))
    turn(term)
    out, rec = call(term, "FAIL")
    assert out["action"] == "approve" and rec["decision"] == "blocked_on_error"
    assert "snoozed" not in rec
    monkeypatch.setenv("SENTROOK_MODE", "observe")
    out, rec = call(term, "rm REVIEW")
    assert out is None and "snoozed" not in rec


# ---- the commands -------------------------------------------------------------------------------------


def test_only_the_owner_may_snooze(term):
    term.facts.update(platform="telegram", chat_type="group", user_id="u9")
    reply = slash(term, "snooze --all")
    assert reply == owner.refusal("snooze")
    assert not term.file.exists()
    audit = records(term, "command")[-1]
    assert (audit["verb"], audit["outcome"]) == ("snooze", "refused")
    assert slash(term, "snooze status") == owner.refusal("snooze")


def test_duration_default_limits_and_refusals(term):
    now = datetime.now(UTC)
    slash(term, "snooze")
    exp = read_time(stored(term)["snoozes"][0]["expires_at"])
    assert timedelta(minutes=59) < exp - now <= timedelta(hours=1, seconds=5)
    assert slash(term, "snooze 24h").startswith("Snoozed reviews in this session for 24h")
    for too_long in ("25h", "1441m", "2d"):
        reply = slash(term, f"snooze {too_long}")
        assert reply.startswith(
            f'Unknown duration "{too_long}": use a number with m or h, from 1m to 24h.'
        )
    assert slash(term, "snooze 0m").startswith('Unknown duration "0m"')
    assert slash(term, "snooze --forever").startswith("Unknown option --forever.")
    assert slash(term, "snooze 1h 2h").startswith("usage: /sentrook snooze")
    # A later snooze for the same session replaces the earlier one.
    assert len(stored(term)["snoozes"]) == 1


def test_a_snooze_needs_a_session_unless_all(term, capsys):
    reply = slash(term, "snooze 1h", session_id="")
    assert reply == (
        "There is no current session here, so a snooze cannot be bound to one; "
        "use /sentrook snooze --all to snooze every session."
    )
    assert cli(term, capsys, "snooze", "2h") == reply
    assert not term.file.exists()
    assert cli(term, capsys, "snooze", "2h", "--all").startswith("Snoozed reviews in every session")
    assert cli(term, capsys, "snooze", "--all").startswith(
        "Snoozed reviews in every session for 1h"
    )
    assert [e["scope"] for e in stored(term)["snoozes"]] == ["all"]


def test_off_ends_what_applies_here_and_all_ends_everything(term, capsys):
    put(term, entry(), entry(ref=snooze.session_ref("S2")), entry("all"))
    assert slash(term, "snooze off") == "Snooze off: ended 2 snoozes."
    assert [e["session_ref"] for e in stored(term)["snoozes"]] == [snooze.session_ref("S2")]
    assert slash(term, "snooze off") == "No snooze was on."
    assert cli(term, capsys, "snooze", "off") == "Snooze off: ended 1 snooze."
    assert stored(term)["snoozes"] == []
    put(term, entry(), entry(ref=snooze.session_ref("S2")))
    assert slash(term, "snooze off --all") == "Snooze off: ended 2 snoozes."


def test_status_and_the_traffic_log(term):
    slash(term, "snooze 90m")
    lines = slash(term, "snooze status").splitlines()
    assert lines[0].startswith("Snooze: on in this session until ")
    assert lines[0].endswith("(1h 30m left)")
    assert slash(term, "snooze status", session_id="S2").splitlines()[:2] == [
        "Snooze: off",
        "Other sessions snoozed: 1",
    ]
    status = slash(term, "status").splitlines()
    assert "snooze: 1 session" in status
    slash(term, "snooze off")
    assert "snooze: off" in slash(term, "status").splitlines()
    changes = records(term, "snooze")
    assert [c["op"] for c in changes] == ["set", "off"]
    assert changes[0]["entry"]["session_ref"] == S1
    assert changes[0]["by"] == {"basis": ["local_terminal"], "platform": "", "sender_ref": None}
    assert changes[1]["entries"][0]["session_ref"] == S1
    assert stored(term)["snoozes"] == []


def test_a_write_drops_expired_entries(term):
    put(term, entry(ref="s_old", minutes=-5), entry(ref=snooze.session_ref("S2")))
    slash(term, "snooze")
    assert [e["session_ref"] for e in stored(term)["snoozes"]] == [
        snooze.session_ref("S2"),
        S1,
    ]


def test_help_lists_snooze_as_owner_only(term):
    text = slash(term, "help")
    line = next(x for x in text.splitlines() if x.startswith("/sentrook snooze"))
    assert "[duration|off|status] [--all]" in line and line.endswith("(owner only)")
