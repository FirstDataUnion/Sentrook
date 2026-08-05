"""Plugin-reported scan latency log (JSON Lines).

Records end-to-end plugin round-trip time alongside engine timing from the scan
response. Join to ``scan.log.jsonl`` on ``tool_call_id`` when needed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class LatencyLogRecord(BaseModel):
    """One enforce-mode scan timing sample from the OpenClaw plugin."""

    ts: str
    schema_version: str = "sentrook.latency.log/v1"
    tool_call_id: str | None = None
    session_id: str | None = None
    run_id: str | None = None
    pending_tool: str | None = None
    decision: Literal["allow", "review", "block"] | None = None
    plugin_e2e_ms: int = Field(ge=0)
    engine_ms: int | None = Field(default=None, ge=0)
    request_ms: int | None = Field(default=None, ge=0)
    transport_ms: int | None = Field(default=None, ge=0)
    sanitize_enabled: bool | None = None
    sanitize_ms: int | None = Field(default=None, ge=0)

    def to_json_line(self) -> str:
        return json.dumps(self.model_dump(mode="json"), ensure_ascii=False)


class LatencyReport(BaseModel):
    """Body for ``POST /latency`` from the OpenClaw plugin."""

    tool_call_id: str | None = None
    session_id: str | None = None
    run_id: str | None = None
    pending_tool: str | None = None
    decision: Literal["allow", "review", "block"] | None = None
    plugin_e2e_ms: int = Field(ge=0)
    engine_ms: int | None = Field(default=None, ge=0)
    request_ms: int | None = Field(default=None, ge=0)
    transport_ms: int | None = Field(default=None, ge=0)
    sanitize_enabled: bool | None = None
    sanitize_ms: int | None = Field(default=None, ge=0)


def build_latency_record(report: LatencyReport, *, ts: str | None = None) -> LatencyLogRecord:
    return LatencyLogRecord(
        ts=ts or datetime.now(timezone.utc).isoformat(),
        tool_call_id=report.tool_call_id,
        session_id=report.session_id,
        run_id=report.run_id,
        pending_tool=report.pending_tool,
        decision=report.decision,
        plugin_e2e_ms=report.plugin_e2e_ms,
        engine_ms=report.engine_ms,
        request_ms=report.request_ms,
        transport_ms=report.transport_ms,
        sanitize_enabled=report.sanitize_enabled,
        sanitize_ms=report.sanitize_ms,
    )


def append_latency_log(log_path: Path, record: LatencyLogRecord | dict[str, Any]) -> None:
    log_path = Path(log_path).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    line = (
        record.to_json_line()
        if isinstance(record, LatencyLogRecord)
        else json.dumps(record, ensure_ascii=False)
    )
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
