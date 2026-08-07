"""Scan decision log content policy and production logging guards."""

from __future__ import annotations

import json
from pathlib import Path

from sentrook.planir import PlanIR, PlanMetadata, PlanStep
from sentrook.result import DebugInfo, PlanEcho, ScanResult
from sentrook.serve.config import ServeConfig, validate_production_logging
from sentrook.serve.log import (
    append_scan_log,
    build_log_record,
    record_for_disk,
)


def _plan(*, intent: str, command: str, session_id: str = "sess-raw") -> PlanIR:
    return PlanIR(
        version="1.0",
        run_id=f"{session_id}:run_1",
        intent=intent,
        steps=[
            PlanStep(
                id="s1",
                tool="exec",
                status="pending",
                args={"command": command},
            )
        ],
        metadata=PlanMetadata(
            adapter="fixture",
            hook="before_tool_call",
            session_id=session_id,
        ),
    )


def _result(plan: PlanIR) -> ScanResult:
    pending = plan.steps[0]
    return ScanResult(
        decision="allow",
        risk=0.0,
        summary="No matching rules. Early exit at Layer 1.",
        plan=PlanEcho(
            run_id=plan.run_id,
            plan_size=1,
            pending_step_id=pending.id,
            pending_tool=pending.tool,
            tools=[pending.tool],
        ),
        debug=DebugInfo(scanner_version="0.0.0", rules_loaded=0),
    )


def test_build_log_record_metadata_scrubs_for_wire_echo() -> None:
    """metadata mode still returns scrubbed text for HTTP/feedback; disk strips."""
    plan = _plan(intent="email Jane Doe jane@example.com", command="curl https://x")
    record = build_log_record(_result(plan), plan, log_content="metadata")
    assert record.intent is not None
    assert "jane@example.com" not in record.intent
    assert record.pending_command_excerpt == "curl https://x"
    disk = record_for_disk(record, log_content="metadata")
    assert disk.intent is None
    assert disk.pending_command_excerpt is None
    assert record.decision == "allow"
    assert record.pending_tool == "exec"


def test_build_log_record_scrubbed_redacts_email() -> None:
    plan = _plan(intent="email jane@example.com please", command="echo hi")
    record = build_log_record(_result(plan), plan, log_content="scrubbed")
    assert record.intent is not None
    assert "jane@example.com" not in record.intent
    assert record.pending_command_excerpt == "echo hi"


def test_build_log_record_full_keeps_raw() -> None:
    plan = _plan(intent="email jane@example.com please", command="secret-argv")
    record = build_log_record(_result(plan), plan, log_content="full")
    assert record.intent == "email jane@example.com please"
    assert record.pending_command_excerpt == "secret-argv"


def test_append_scan_log_metadata_strips_even_if_record_has_content(
    tmp_path: Path,
) -> None:
    plan = _plan(intent="keep off disk", command="rm -rf /tmp/x")
    record = build_log_record(_result(plan), plan, log_content="full")
    assert record.intent == "keep off disk"
    path = tmp_path / "scan.log.jsonl"
    append_scan_log(path, record, log_content="metadata")
    row = json.loads(path.read_text().strip())
    assert row["intent"] is None
    assert row["pending_command_excerpt"] is None
    assert row["decision"] == "allow"
    # Response-facing record is unchanged.
    assert record.intent == "keep off disk"


def test_record_for_disk_passthrough_when_scrubbed() -> None:
    plan = _plan(intent="hello", command="ls")
    record = build_log_record(_result(plan), plan, log_content="scrubbed")
    assert record_for_disk(record, log_content="scrubbed") is record


def test_production_defaults_to_metadata_log_content() -> None:
    cfg = ServeConfig.from_env({"SENTROOK_ENV": "production"})
    assert cfg.environment == "production"
    assert cfg.log_content == "metadata"
    assert cfg.server_sanitize_planir is True
    assert validate_production_logging(cfg) == []


def test_production_rejects_scrubbed_and_sanitize_off() -> None:
    scrubbed = ServeConfig(
        environment="production",
        log_content="scrubbed",
        server_sanitize_planir=True,
    )
    assert any("LOG_CONTENT=metadata" in e for e in validate_production_logging(scrubbed))

    raw = ServeConfig(
        environment="production",
        log_content="metadata",
        server_sanitize_planir=False,
    )
    assert any("SANITIZE_PLANIR" in e for e in validate_production_logging(raw))


def test_development_defaults_to_scrubbed() -> None:
    cfg = ServeConfig.from_env({})
    assert cfg.environment == "development"
    assert cfg.log_content == "scrubbed"
    assert validate_production_logging(cfg) == []


def test_log_level_from_env() -> None:
    cfg = ServeConfig.from_env({"SENTROOK_LOG_LEVEL": "debug"})
    assert cfg.log_level == "DEBUG"
