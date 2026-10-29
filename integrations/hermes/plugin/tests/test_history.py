"""`/sentrook history` and `/sentrook why`: scan history read back from the local traffic log."""

import argparse
import json
import shutil
from pathlib import Path

import pytest

import plugin
from plugin import history, owner

#: Shared with the OpenClaw plugin's tests: both hosts print the same text for the same log.
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "traffic-log"
#: Strings that appear only in call arguments, reason details and failure details in the fixture.
RAW = "RAW-ARG-MARKER"


def golden(name):
    return (FIXTURES / name).read_text().rstrip("\n").replace("{why}", "/sentrook why")


@pytest.fixture
def log(harness, monkeypatch):
    """The fixture log in place of this install's traffic log, run from the local terminal."""
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM"):
        monkeypatch.delenv(k, raising=False)
    facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(facts))
    monkeypatch.setattr(owner, "gateway_engaged", lambda: bool(facts.get("platform")))
    path = harness.dir / "sentrook" / "traffic.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    for name in ("traffic.jsonl", "traffic.jsonl.1"):
        shutil.copy(FIXTURES / name, path.parent / name)
    harness.facts = facts
    harness.log = path
    return harness


def slash(h, raw_args):
    return h.ctx.commands["sentrook"]["handler"](raw_args)


def cli(h, capsys, *argv):
    parser = argparse.ArgumentParser()
    h.ctx.cli["setup_fn"](parser)
    h.ctx.cli["handler_fn"](parser.parse_args(list(argv)))
    return capsys.readouterr().out.rstrip("\n")


def untorn(h):
    """Drop the fixture's torn last line, so the audit record appended next starts on its own line."""
    text = h.log.read_text()
    h.log.write_text(text[: text.rindex("\n") + 1])


def commands(h):
    out = []
    for line in h.log.read_text().splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("kind") == "command":
            out.append(rec)
    return out


def test_the_fixture_log_renders(log):
    assert slash(log, "history") == golden("history.txt")
    assert slash(log, "why") == golden("why-last.txt")
    assert slash(log, "why last") == golden("why-last.txt")
    assert slash(log, "why 4444a1b2") == golden("why-4444a1b2.txt")
    assert slash(log, "why 5555a1b2-0000-4000-8000-000000000005") == golden("why-5555a1b2.txt")


def test_a_resolution_joins_its_scan_across_the_rotation(log):
    """The scan is in `<path>.1`, its approval in the current file."""
    row = next(line for line in slash(log, "history").splitlines() if line.startswith("3333a1b2"))
    assert row.split()[-1] == "approved"


def test_a_torn_last_line_and_a_garbled_line_are_skipped(log):
    out = slash(log, "history 50")
    assert "9999a1b2" not in out
    assert out.startswith("Last 8 scans")
    assert slash(log, "history 1").splitlines()[2].startswith("8888a1b2")


def test_only_the_rotated_file(log):
    log.log.unlink()
    out = slash(log, "history")
    assert out.startswith("Last 3 scans")
    assert "3333a1b2" in out and "no answer" in out  # its resolution went with the newer file


def test_history_takes_a_count_up_to_50(log):
    two = slash(log, "history 2").splitlines()
    assert [row[:8] for row in two[2:-1]] == ["8888a1b2", "7777a1b2"]
    for bad in ("0", "-1", "two", "3 4"):
        assert slash(log, f"history {bad}").startswith("usage: /sentrook history [n]"), bad
    lines = [
        json.dumps(
            {
                "ts": f"2026-10-30T10:{i // 60:02d}:{i % 60:02d}.000Z",
                "kind": "scan",
                "request_id": f"{i:08x}-0000-4000-8000-000000000000",
                "tool": "terminal",
                "mode": "enforce",
                "verdict": "allow",
                "decision": "allowed",
                "response": {"risk": 1},
            }
        )
        for i in range(70)
    ]
    log.log.write_text("\n".join(lines) + "\n")
    assert slash(log, "history 999").startswith("Last 50 scans")
    assert slash(log, "history").startswith("Last 10 scans")


def test_no_raw_arguments_are_ever_shown(log):
    outputs = [slash(log, "history 50"), slash(log, "why")]
    outputs += [slash(log, f"why {n}{n}{n}{n}a1b2") for n in range(1, 9)]
    assert all("scan:" in o for o in outputs[1:])
    for out in outputs:
        assert RAW not in out
        assert "curl" not in out


def test_why_for_an_unknown_or_malformed_id(log):
    assert slash(log, "why abcdef12") == "No scan abcdef12 in the recent traffic log."
    assert slash(log, "why ../../etc").startswith("usage: /sentrook why [request_id|last]")


def test_a_missing_or_disabled_log(log):
    log.log.unlink()
    log.log.with_name("traffic.jsonl.1").unlink()
    assert slash(log, "history") == "No scans in the traffic log yet."
    assert slash(log, "why") == "No scans in the traffic log yet."
    log.ctx.settings["traffic_log"] = {"enabled": False}
    assert slash(log, "history") == "The traffic log is off, so there is no scan history."


@pytest.mark.parametrize(
    "facts",
    [
        {"platform": "mattermost", "chat_type": "group", "user_id": "u1"},
        {"platform": "mattermost", "chat_type": "dm", "user_id": "u2"},
        {"platform": "api_server"},
    ],
)
@pytest.mark.parametrize("verb", ["history", "why"])
def test_a_non_owner_is_refused_and_audited(log, monkeypatch, facts, verb):
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "u1")
    untorn(log)
    log.facts.update(facts)
    assert slash(log, f"{verb} 5") == owner.refusal(verb)
    [rec] = commands(log)
    assert (rec["verb"], rec["outcome"]) == (verb, "refused")


def test_the_owner_is_audited_and_status_stays_open(log, monkeypatch):
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "u1")
    untorn(log)
    log.facts.update({"platform": "mattermost", "chat_type": "dm", "user_id": "u1"})
    assert slash(log, "history").startswith("Last ")
    log.facts.update({"chat_type": "group"})
    assert slash(log, "status").startswith("Sentrook plugin")
    [rec] = commands(log)
    assert (rec["verb"], rec["outcome"], rec["basis"]) == (
        "history",
        "allowed",
        ["host_allowlist_dm"],
    )


def test_the_cli_forms_match_the_slash_forms(log, capsys):
    untorn(log)
    assert cli(log, capsys, "history") == slash(log, "history")
    assert cli(log, capsys, "history", "2") == slash(log, "history 2")
    assert cli(log, capsys, "why") == slash(log, "why")
    assert cli(log, capsys, "why", "4444a1b2") == golden("why-4444a1b2.txt")
    assert [r["basis"] for r in commands(log)] == [["local_terminal"]] * 7


def test_help_lists_the_owner_commands(log):
    help_text = slash(log, "help")
    assert "/sentrook history [n]" in help_text
    assert "/sentrook why [request_id|last]" in help_text
    assert "history" in log.ctx.commands["sentrook"]["args_hint"]


def test_only_the_tail_is_read(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(
        "".join(
            json.dumps({"kind": "scan", "request_id": f"r{i}", "pad": "x" * 1000}) + "\n"
            for i in range(200)
        )
    )
    ids = [r["request_id"] for r in history.records_backward(path, budget=10_000)]
    assert ids[0] == "r199"
    assert 5 <= len(ids) <= 10
    # Stops as soon as it has enough scans.
    assert [s["request_id"] for s, _ in history.recent_scans(path, 3)] == ["r199", "r198", "r197"]


def test_halves_and_wide_characters_print_as_on_openclaw(log):
    """Risk 92.5 and a 0.125 score round up, and text is cut and padded by character."""
    edge = FIXTURES / "edge"
    shutil.copy(edge / "traffic.jsonl", log.log)
    log.log.with_name("traffic.jsonl.1").unlink()
    assert slash(log, "history") == golden("edge/history.txt")
    assert slash(log, "why") == golden("edge/why-last.txt")


def test_lines_cross_read_chunks_intact(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(
        "".join(
            json.dumps(
                {"kind": "scan", "request_id": f"r{i}", "pad": "é🙂" * (50 + i * 3)},
                ensure_ascii=False,
            )
            + "\n"
            for i in range(300)
        ),
        encoding="utf-8",
    )
    assert path.stat().st_size > 10 * 64 * 1024
    assert [r["request_id"] for r in history.records_backward(path)] == [
        f"r{i}" for i in reversed(range(300))
    ]


def test_a_count_in_other_digits_is_a_usage_error(log):
    for bad in ("²", "١٢", "1234567"):
        assert slash(log, f"history {bad}").startswith("usage: /sentrook history [n]"), bad
