"""Unit tests for plugin-reported latency logs."""

from __future__ import annotations

from pathlib import Path

from sentrook.serve.latency import LatencyReport, append_latency_log, build_latency_record


def test_build_and_append_latency_record(tmp_path: Path) -> None:
    log_path = tmp_path / "latency.log.jsonl"
    report = LatencyReport(
        tool_call_id="exec:1",
        session_id="sess",
        run_id="sess:run_1",
        pending_tool="exec",
        decision="allow",
        plugin_e2e_ms=45,
        engine_ms=42,
        request_ms=44,
        transport_ms=3,
        sanitize_enabled=True,
        sanitize_ms=2,
    )
    append_latency_log(log_path, build_latency_record(report))
    line = log_path.read_text().strip()
    assert '"schema_version": "sentrook.latency.log/v1"' in line
    assert '"plugin_e2e_ms": 45' in line
    assert '"transport_ms": 3' in line
    assert '"sanitize_enabled": true' in line
    assert '"sanitize_ms": 2' in line
