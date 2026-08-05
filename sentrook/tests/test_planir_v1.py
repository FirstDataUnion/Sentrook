"""PlanIR 1.0 + ScanResult 1.0 contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentrook.adapters.snapshot import SnapshotCall, build_planir_snapshot
from sentrook.planir import PlanIR
from sentrook.result import DebugInfo, PlanEcho, ScanResult

ROOT = Path(__file__).resolve().parents[2]
PLANS = ROOT / "fixtures" / "plans"


def test_fixture_plans_are_planir_1_0() -> None:
    for path in sorted(PLANS.glob("*.json")):
        plan = PlanIR.model_validate_json(path.read_text(encoding="utf-8"))
        assert plan.version == "1.0"
        assert any(s.status == "pending" for s in plan.steps)


def test_rejects_planir_0_1() -> None:
    raw = json.loads((PLANS / "safe_read_only.json").read_text(encoding="utf-8"))
    raw["version"] = "0.1"
    with pytest.raises(ValidationError):
        PlanIR.model_validate(raw)


def test_requires_pending_step() -> None:
    with pytest.raises(ValidationError, match="pending"):
        PlanIR.model_validate(
            {
                "version": "1.0",
                "run_id": "r1",
                "steps": [
                    {"id": "s1", "tool": "read", "status": "executed", "args": {}},
                ],
            }
        )


def test_rejects_executed_after_pending() -> None:
    with pytest.raises(ValidationError, match="precede"):
        PlanIR.model_validate(
            {
                "version": "1.0",
                "run_id": "r1",
                "steps": [
                    {"id": "s1", "tool": "read", "status": "pending", "args": {}},
                    {"id": "s2", "tool": "exec", "status": "executed", "args": {}},
                ],
            }
        )


def test_rejects_non_sequential_step_ids() -> None:
    with pytest.raises(ValidationError, match="sequential"):
        PlanIR.model_validate(
            {
                "version": "1.0",
                "run_id": "r1",
                "steps": [
                    {"id": "step-a", "tool": "exec", "status": "pending", "args": {}},
                ],
            }
        )


def test_build_planir_snapshot_golden_emits_1_0() -> None:
    plan = build_planir_snapshot(
        executed=[
            SnapshotCall(tool="read", args={"path": "/tmp/a.txt"}),
        ],
        pending=SnapshotCall(tool="exec", args={"command": "ls"}),
        run_id="golden:1",
        intent="list files",
        adapter="fixture",
    )
    assert plan.version == "1.0"
    assert [s.id for s in plan.steps] == ["s1", "s2"]
    assert plan.steps[0].status == "executed"
    assert plan.steps[1].status == "pending"
    # Round-trip through JSON stays 1.0
    restored = PlanIR.model_validate_json(plan.model_dump_json())
    assert restored.version == "1.0"


def test_scan_result_version_1_0() -> None:
    result = ScanResult(
        decision="allow",
        risk=0.0,
        summary="ok",
        plan=PlanEcho(run_id="r1", plan_size=1),
        debug=DebugInfo(scanner_version="0.0.0", rules_loaded=0),
    )
    assert result.version == "1.0"
    dumped = result.to_json_dict()
    assert dumped["version"] == "1.0"
