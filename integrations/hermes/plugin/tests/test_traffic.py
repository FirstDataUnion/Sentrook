"""The traffic log writer: every record lands on its own line, even after a write cut off mid-line, and
records older than 30 days are dropped."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from plugin.traffic import TrafficLog

#: The start of a scan record whose write was cut off (a crash or a full disk): no closing brace, no newline.
TORN = '{"kind": "scan", "request_id": "9999'
SCAN = '{"kind": "scan", "request_id": "1111"}\n'


def records(path):
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def test_a_record_after_a_torn_last_line_starts_its_own_line(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(SCAN + TORN)
    TrafficLog(path, 1_000_000, True).write({"kind": "command", "verb": "history"})
    lines = path.read_text().split("\n")
    assert lines[:2] == [SCAN.rstrip("\n"), TORN]
    assert json.loads(lines[2])["kind"] == "command"
    assert lines[3:] == [""]
    assert [r["kind"] for r in records(path)] == ["scan", "command"]


def test_a_log_ending_with_a_newline_gets_no_blank_line(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(SCAN)
    log = TrafficLog(path, 1_000_000, True)
    log.write({"kind": "command", "verb": "history"})
    log.write({"kind": "command", "verb": "why"})
    text = path.read_text()
    assert "\n\n" not in text
    assert text.startswith(SCAN)
    assert [r.get("verb") for r in records(path)] == [None, "history", "why"]


def test_a_new_or_empty_file_starts_with_the_record(tmp_path):
    for path in (tmp_path / "new" / "traffic.jsonl", tmp_path / "empty.jsonl"):
        if path.name == "empty.jsonl":
            path.write_text("")
        TrafficLog(path, 1_000_000, True).write({"kind": "command"})
        text = path.read_text()
        assert text.startswith('{"ts": ') and text.endswith("}\n") and text.count("\n") == 1


def test_a_freshly_rotated_file_starts_with_the_record(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(SCAN + TORN)
    TrafficLog(path, 10, True).write({"kind": "command"})
    assert (tmp_path / "traffic.jsonl.1").read_text() == SCAN + TORN
    text = path.read_text()
    assert text.startswith('{"ts": ') and text.count("\n") == 1
    assert records(path)[0]["kind"] == "command"


# Retention: records older than 30 days are dropped on a write, from the log and its rotated file.

RETENTION = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "traffic-log"
        / "retention"
        / "cases.json"
    ).read_text()
)
NOW = datetime.fromisoformat(RETENTION["now"])


def at(when):
    return lambda: when


def scan(ts, rid):
    return json.dumps({"ts": ts, "kind": "scan", "request_id": rid}) + "\n"


@pytest.mark.parametrize("case", RETENTION["cases"], ids=lambda c: c["name"])
def test_retention_golden(tmp_path, case):
    for name, text in case["before"].items():
        (tmp_path / name).write_bytes(text.encode())
    TrafficLog(tmp_path / "traffic.jsonl", 1_000_000, True, now=at(NOW)).write(
        {"kind": "command", "verb": "history"}
    )
    names = {"traffic.jsonl", "traffic.jsonl.1"}
    assert {p.name for p in tmp_path.iterdir()} & names == set(case["after"]) | {"traffic.jsonl"}
    assert not list(tmp_path.glob("*.tmp"))
    for name in set(case["after"]) - {"traffic.jsonl"}:
        assert (tmp_path / name).read_bytes().decode() == case["after"][name]
    text = (tmp_path / "traffic.jsonl").read_bytes().decode()
    expected = case["after"]["traffic.jsonl"]
    assert text.startswith(expected)
    new = text[len(expected) :]
    if expected and not expected.endswith("\n"):
        assert new.startswith("\n")
        new = new[1:]
    assert new.count("\n") == 1 and new.endswith("\n")
    assert json.loads(new)["verb"] == "history"


def test_a_31_day_old_record_is_gone_after_the_next_write_and_a_29_day_old_one_stays(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(
        scan("2026-10-26T11:00:00.000+00:00", "old") + scan("2026-10-28T13:00:00.000+00:00", "new")
    )
    path.chmod(0o644)
    TrafficLog(path, 1_000_000, True, now=at(NOW)).write({"kind": "command"})
    assert [r.get("request_id") for r in records(path)] == ["new", None]
    assert path.stat().st_mode & 0o777 == 0o600  # the rewrite is readable only by the user


def test_pruning_runs_at_most_once_an_hour_per_log(tmp_path):
    path = tmp_path / "traffic.jsonl"
    old = scan("2026-10-26T11:00:00.000+00:00", "old")
    path.write_text(scan("2026-10-27T12:30:00.000+00:00", "edge"))
    TrafficLog(path, 1_000_000, True, now=at(NOW)).write({"kind": "command"})
    # Forty minutes later "edge" is over 30 days old, but this process pruned this log less than an hour ago.
    later = NOW + timedelta(minutes=40)
    TrafficLog(path, 1_000_000, True, now=at(later)).write({"kind": "command"})
    assert records(path)[0]["request_id"] == "edge"
    rotated = tmp_path / "traffic.jsonl.1"
    rotated.write_text(old)
    TrafficLog(path, 1_000_000, True, now=at(NOW + timedelta(hours=1))).write({"kind": "command"})
    assert records(path)[0]["kind"] == "command"
    assert not rotated.exists()


def test_a_rotation_with_a_stale_rotated_file_keeps_only_recent_records(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(
        scan("2026-10-20T00:00:00.000+00:00", "old") + scan("2026-11-20T00:00:00.000+00:00", "new")
    )
    (tmp_path / "traffic.jsonl.1").write_text(scan("2026-10-01T00:00:00.000+00:00", "older"))
    TrafficLog(path, 10, True, now=at(NOW)).write({"kind": "command"})
    assert [r["request_id"] for r in records(tmp_path / "traffic.jsonl.1")] == ["new"]
    assert [r["kind"] for r in records(path)] == ["command"]


def test_a_large_log_inside_the_window_is_not_rewritten(tmp_path):
    path = tmp_path / "traffic.jsonl"
    path.write_text(
        scan("2026-11-01T00:00:00.000+00:00", "a") * 5000
        + scan("2026-10-01T00:00:00.000+00:00", "z")
    )
    inode = path.stat().st_ino
    TrafficLog(path, 10_000_000, True, now=at(NOW)).write({"kind": "command"})
    assert path.stat().st_ino == inode
