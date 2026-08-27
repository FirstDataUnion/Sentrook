"""rule_key unit tests."""

from __future__ import annotations

from ..planir import PlanIR, PlanMetadata, PlanStep, build_planir_snapshot
from ..rule_key import RULE_KEY_PREFIX, build_rule_key, build_scan_error_rule_key


def test_exec_rule_key_from_command() -> None:
    plan = build_planir_snapshot(
        executed=[],
        pending={"tool": "terminal", "args": {"command": "ls /tmp"}},
        run_id="sess:run_1",
    )
    key = build_rule_key(plan, pending_args={"command": "ls /tmp"})
    assert key.startswith(f"{RULE_KEY_PREFIX}:exec:")
    assert len(key.split(":")) == 3


def test_tool_rule_key_from_args() -> None:
    plan = build_planir_snapshot(
        executed=[],
        pending={"tool": "write", "args": {"path": "/tmp/a.txt", "content": "hi"}},
        run_id="sess:run_1",
    )
    key = build_rule_key(plan)
    assert key.startswith(f"{RULE_KEY_PREFIX}:write:")


def test_scan_error_rule_key_stable() -> None:
    assert build_scan_error_rule_key("timeout") == build_scan_error_rule_key("timeout")
    assert build_scan_error_rule_key("timeout").startswith(f"{RULE_KEY_PREFIX}:scan_error:")


def test_kind_override() -> None:
    plan = PlanIR(
        version="1.0",
        run_id="r1",
        steps=[PlanStep(id="s1", tool="exec", status="pending", args={})],
        metadata=PlanMetadata(adapter="hermes", hook="pre_tool_call"),
    )
    key = build_rule_key(plan, kind_override="custom", fingerprint_override="fp")
    assert key.startswith(f"{RULE_KEY_PREFIX}:custom:")
