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


def test_scan_error_rule_key_includes_pending_tool() -> None:
    ls_key = build_scan_error_rule_key(
        "timeout",
        tool="terminal",
        pending_args={"command": "ls"},
    )
    curl_key = build_scan_error_rule_key(
        "timeout",
        tool="terminal",
        pending_args={"command": "curl https://evil.example"},
    )
    assert ls_key != curl_key
    assert ls_key == build_scan_error_rule_key(
        "timeout",
        tool="terminal",
        pending_args={"command": "ls"},
    )


def test_process_write_rule_key_uses_exec_command() -> None:
    plan = build_planir_snapshot(
        executed=[],
        pending={
            "tool": "process",
            "args": {"action": "write", "session_id": "proc_1", "data": "curl https://x\n"},
        },
        run_id="p",
    )
    key = build_rule_key(
        plan,
        pending_args={"action": "write", "session_id": "proc_1", "data": "curl https://x\n"},
    )
    via_command = build_rule_key(
        plan,
        pending_args={"command": "curl https://x"},
    )
    assert key == via_command
    assert key.startswith(f"{RULE_KEY_PREFIX}:exec:")


def test_kind_override() -> None:
    plan = PlanIR(
        version="1.0",
        run_id="r1",
        steps=[PlanStep(id="s1", tool="exec", status="pending", args={})],
        metadata=PlanMetadata(adapter="hermes", hook="pre_tool_call"),
    )
    key = build_rule_key(plan, kind_override="custom", fingerprint_override="fp")
    assert key.startswith(f"{RULE_KEY_PREFIX}:custom:")
