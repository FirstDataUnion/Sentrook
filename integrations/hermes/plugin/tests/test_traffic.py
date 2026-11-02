"""The traffic log writer: every record lands on its own line, even after a write cut off mid-line."""

import json

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
