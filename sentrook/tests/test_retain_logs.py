"""Tests for hosted log retention pruning (deploy/retain_logs.py)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentrook.ops.retain_logs import (
    classify_line,
    cutoff_utc,
    parse_ts,
    prune_jsonl_file,
)


def _line(ts: datetime, **extra: object) -> str:
    row = {"ts": ts.isoformat(), "decision": "allow", **extra}
    return json.dumps(row) + "\n"


def test_parse_ts_z_suffix() -> None:
    got = parse_ts("2026-07-14T12:00:00Z")
    assert got == datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_cutoff_utc_days() -> None:
    now = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
    assert cutoff_utc(now=now, days=14) == now - timedelta(days=14)


def test_classify_keeps_recent_drops_old() -> None:
    now = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
    cutoff = now - timedelta(days=14)
    keep_ts = now - timedelta(days=1)
    drop_ts = now - timedelta(days=30)
    assert classify_line(_line(keep_ts), cutoff=cutoff)[0] == "keep"
    assert classify_line(_line(drop_ts), cutoff=cutoff)[0] == "drop"


def test_classify_keeps_unparsed() -> None:
    cutoff = datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert classify_line("not-json\n", cutoff=cutoff)[0] == "keep_unparsed"
    assert classify_line('{"decision":"allow"}\n', cutoff=cutoff)[0] == "keep_unparsed"


def test_prune_jsonl_dry_run_and_apply(tmp_path: Path) -> None:
    now = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
    path = tmp_path / "shadow.log.jsonl"
    path.write_text(
        _line(now - timedelta(days=30), id="old")
        + _line(now - timedelta(days=1), id="new")
        + "garbage\n",
        encoding="utf-8",
    )
    cutoff = cutoff_utc(now=now, days=14)

    dry = prune_jsonl_file(path, cutoff=cutoff, dry_run=True)
    assert dry["dropped"] == 1
    assert dry["kept"] == 1
    assert dry["kept_unparsed"] == 1
    assert dry["rewritten"] is False
    assert "old" in path.read_text(encoding="utf-8")

    applied = prune_jsonl_file(path, cutoff=cutoff, dry_run=False)
    assert applied["rewritten"] is True
    assert applied["dropped"] == 1
    text = path.read_text(encoding="utf-8")
    assert "old" not in text
    assert "new" in text
    assert "garbage" in text


def test_prune_noop_when_nothing_to_drop(tmp_path: Path) -> None:
    now = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
    path = tmp_path / "latency.log.jsonl"
    path.write_text(_line(now - timedelta(days=1)), encoding="utf-8")
    summary = prune_jsonl_file(
        path, cutoff=cutoff_utc(now=now, days=14), dry_run=False
    )
    assert summary["dropped"] == 0
    assert summary["rewritten"] is False


def test_cutoff_rejects_zero_days() -> None:
    with pytest.raises(ValueError):
        cutoff_utc(days=0)
