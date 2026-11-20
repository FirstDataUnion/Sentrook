"""`/sentrook report`: one scan packed for sending to Sentrook, from the local traffic log."""

import argparse
import os
import shutil
import stat
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

import plugin
from plugin import config, history, owner, report

#: Shared with the OpenClaw plugin's tests: both hosts build the same report for the same log.
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "traffic-log" / "report"
ISSUE_FORM = Path(__file__).resolve().parents[4] / ".github" / "ISSUE_TEMPLATE" / "wrong_scan.yml"
#: Strings that appear only in the PlanIR body, reason details and failure details in the fixture.
PRIVATE = ("PLANIR-BODY-MARKER", "PRIVATE-PATH-MARKER")
IDS = ["aaaa1b2c", "bbbb1b2c", "cccc1b2c"]
LONG_IDS = ["dddd1b2c", "eeee1b2c"]


def golden(name):
    return (FIXTURES / name).read_text().rstrip("\n")


def found(log_name, ref):
    return report.find(FIXTURES / log_name, history.parse_ref(ref))


@pytest.fixture
def log(harness, monkeypatch):
    """The report fixture log in place of this install's traffic log, run from the local terminal."""
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM"):
        monkeypatch.delenv(k, raising=False)
    facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(facts))
    monkeypatch.setattr(plugin, "session_surface", lambda: "" if facts.get("platform") else "cli")
    path = harness.dir / "sentrook" / "traffic.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "traffic.jsonl", path)
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


CASES = (
    [("traffic.jsonl", i) for i in IDS]
    + [("long.jsonl", i) for i in LONG_IDS]
    + [("odd.jsonl", "odd")]
)


@pytest.mark.parametrize(("log_name", "ref"), CASES)
def test_the_fixture_reports_match_the_shared_goldens(log_name, ref):
    f = found(log_name, "last" if ref == "odd" else ref)
    assert report.summary(f.scan, f.resolution) == golden(f"summary-{ref}.txt")
    assert report.full_record(f) == golden(f"full-{ref}.txt")
    url, fitted = report.github_link(f.scan, f.resolution)
    assert f"{fitted or 'whole'}\n{url}" == golden(f"github-{ref}.txt")
    assert report.mailto(f.scan) == golden(f"mailto-{ref}.txt")


def test_the_full_record_is_the_log_lines_byte_for_byte():
    lines = (FIXTURES / "traffic.jsonl").read_text(encoding="utf-8").splitlines()
    block = report.full_record(found("traffic.jsonl", "aaaa1b2c")).split("\n")
    assert block == [report.FULL_BEGIN, lines[0], lines[1], report.FULL_END]


def test_summaries_and_links_hold_no_private_content():
    for log_name, ids in (("traffic.jsonl", IDS), ("long.jsonl", LONG_IDS)):
        for ref in ids:
            f = found(log_name, ref)
            url, _ = report.github_link(f.scan, f.resolution)
            for out in (report.summary(f.scan, f.resolution), url, report.mailto(f.scan)):
                assert not any(m in out for m in PRIVATE), (ref, out[:80])
    assert any(m in report.full_record(found("traffic.jsonl", "aaaa1b2c")) for m in PRIVATE)


def test_grant_suggestions_stay_out_of_the_summary():
    f = found("traffic.jsonl", "aaaa1b2c")
    assert "grants that would allow" in history.format_why(f.scan, f.resolution)
    assert "grant" not in report.summary(f.scan, f.resolution)


def test_links_fit_and_name_the_form_fields():
    fields = {item.get("id") for item in yaml.safe_load(ISSUE_FORM.read_text())["body"]}
    for log_name, ids in (("traffic.jsonl", IDS), ("long.jsonl", LONG_IDS)):
        for ref in ids:
            f = found(log_name, ref)
            url, fitted = report.github_link(f.scan, f.resolution)
            assert len(url) <= report.URL_MAX
            assert url.startswith(config.WRONG_SCAN_ISSUE_URL)
            params = parse_qs(urlsplit(url).query, keep_blank_values=True)
            assert set(params) - {"template", "title"} <= fields
            assert params["template"] == ["wrong_scan.yml"]
            assert ("report" in params) == (fitted != "blank")
            mail = report.mailto(f.scan)
            assert mail.startswith(f"mailto:{config.SUPPORT_EMAIL}?") and len(mail) < 500
            assert f.scan["request_id"][:8] in parse_qs(urlsplit(mail).query)["subject"][0]
    trimmed = parse_qs(urlsplit(golden("github-dddd1b2c.txt").split("\n")[1]).query)["report"][0]
    assert "  (trimmed, 28 more)" in trimmed and trimmed.endswith(report.END)


def test_the_issue_form_requires_the_privacy_check():
    form = yaml.safe_load(ISSUE_FORM.read_text())
    [box] = [item for item in form["body"] if item.get("id") == "private"]
    assert all(opt["required"] for opt in box["attributes"]["options"])
    assert config.SUPPORT_EMAIL in form["body"][0]["attributes"]["value"]


def test_report_replies(log, tmp_path):
    out = slash(log, "report aaaa1b2c")
    assert out.startswith(golden("summary-aaaa1b2c.txt") + "\n\n")
    assert "/sentrook report aaaa1b2c --github" in out and config.SUPPORT_EMAIL in out
    assert slash(log, "report").startswith(golden("summary-cccc1b2c.txt"))
    assert slash(log, "report last") == slash(log, "report")

    full = slash(log, "report aaaa1b2c --full")
    assert full == "\n\n".join(
        (golden("summary-aaaa1b2c.txt"), report.FULL_WARNING, golden("full-aaaa1b2c.txt"))
    )

    gh = slash(log, "report bbbb --github")
    url = golden("github-bbbb1b2c.txt").split("\n")[1]
    assert url in gh.split("\n") and "The issue is public" in gh
    assert "/sentrook report bbbb1b2c --save" in gh

    for out in (slash(log, "report aaaa1b2c"), slash(log, "report aaaa1b2c --github")):
        assert not any(m in out for m in PRIVATE)


def test_save_writes_a_private_file(log):
    out = slash(log, "report aaaa1b2c --save")
    path = Path(out.split(" to ", 1)[1].split(" (readable", 1)[0])
    assert path.parent == log.log.parent / "reports"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert (
        path.read_text()
        == "\n\n".join(
            (golden("summary-aaaa1b2c.txt"), report.FULL_WARNING, golden("full-aaaa1b2c.txt"))
        )
        + "\n"
    )
    assert config.SUPPORT_EMAIL in out and '"Sentrook wrong scan aaaa1b2c"' in out
    assert not any(m in out for m in PRIVATE)


def test_bad_arguments_and_unknown_ids(log):
    for bad in ("aaaa --bogus", "aaaa --full --github", "aaaa bbbb", "../../etc", "--full --save"):
        assert slash(log, f"report {bad}") == plugin.commands.REPORT_USAGE, bad
    assert slash(log, "report abcdef12") == "No scan abcdef12 in the recent traffic log."
    assert slash(log, "report --full").startswith(golden("summary-cccc1b2c.txt"))
    log.log.unlink()
    assert slash(log, "report") == history.NO_SCANS
    log.ctx.settings["traffic_log"] = {"enabled": False}
    assert slash(log, "report") == history.LOG_OFF


def test_a_non_owner_is_refused(log, monkeypatch):
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "u1")
    log.facts.update({"platform": "mattermost", "chat_type": "group", "user_id": "u1"})
    assert slash(log, "report aaaa1b2c --full") == owner.refusal("report")


def test_the_cli_form_matches_the_slash_form(log, capsys):
    assert cli(log, capsys, "report", "aaaa1b2c", "--full") == slash(log, "report aaaa1b2c --full")
    assert cli(log, capsys, "report", "--full", "aaaa1b2c") == slash(log, "report aaaa1b2c --full")
    assert cli(log, capsys, "report", "--full") == slash(log, "report --full")
    assert cli(log, capsys, "report", "--github") == slash(log, "report --github")
    assert cli(log, capsys, "report", "--full", "--save") == plugin.commands.REPORT_USAGE
    assert cli(log, capsys, "report") == slash(log, "report")


def test_a_malformed_record_still_reports_and_saves_inside_the_reports_folder(log):
    """An id with path characters, lone surrogates and a non-text mode: the log is the plugin's own, but a
    report never writes outside its folder or fails on what the log holds."""
    shutil.copy(FIXTURES / "odd.jsonl", log.log)
    assert slash(log, "report").startswith(golden("summary-odd.txt"))
    assert golden("github-odd.txt").split("\n")[1] in slash(log, "report --github")
    out = slash(log, "report --save")
    path = Path(out.split(" to ", 1)[1].split(" (readable", 1)[0])
    assert path.parent == log.log.parent / "reports"
    assert path.name.startswith("sentrook-report-_______x-")


def test_help_lists_report(log):
    assert "/sentrook report [request_id|last] [--full|--github|--save]" in slash(log, "help")
