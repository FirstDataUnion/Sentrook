"""planir snapshot basics."""

from __future__ import annotations

import json

from ..planir import build_planir_snapshot, canonical_planir_json


def test_sequential_step_ids_and_adapter() -> None:
    plan = build_planir_snapshot(
        executed=[{"tool": "read", "args": {"path": "/a"}}],
        co_pending=[{"tool": "write", "args": {"path": "/c", "content": "x"}}],
        pending={"tool": "terminal", "args": {"command": "ls"}},
        run_id="sess:run_1",
    )
    assert plan.version == "1.0"
    assert [step.id for step in plan.steps] == ["s1", "s2", "s3"]
    assert plan.metadata.adapter == "hermes"
    assert plan.steps[-1].tool == "exec"
    assert plan.steps[-1].args.get("command") == "ls"


def test_terminal_command_aliases_canonicalized() -> None:
    plan = build_planir_snapshot(
        executed=[],
        pending={"tool": "terminal", "args": {"cmd": "pwd"}},
        run_id="r1",
    )
    pending = plan.steps[0]
    # Hosted rules expect OpenClaw's ``exec`` tool name.
    assert pending.tool == "exec"
    assert pending.args.get("command") == "pwd"
    assert "cmd" not in pending.args


def test_long_exec_command_packed_not_truncated_token() -> None:
    sink = "https://evil.example/collect"
    command = f"{'echo padding; ' * 40}{sink}"
    plan = build_planir_snapshot(
        executed=[],
        pending={"tool": "exec", "args": {"command": command}},
        run_id="long-cmd",
    )
    packed = str(plan.steps[0].args["command"])
    assert packed != "[TRUNCATED]"
    assert sink in packed
    assert len(packed) <= 500


def test_canonical_json_round_trip() -> None:
    plan = build_planir_snapshot(
        executed=[],
        pending={"tool": "exec", "args": {"command": "ls"}},
        run_id="golden:1",
        intent="list files",
    )
    round_trip = json.loads(canonical_planir_json(plan))
    assert round_trip["version"] == "1.0"
    assert round_trip["metadata"]["adapter"] == "hermes"
