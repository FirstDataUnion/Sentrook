"""Community feedback: matched-step slice and duplicate exec excerpts."""

from __future__ import annotations

from sentrook.planir import PlanIR
from sentrook.serve.feedback import (
    keep_step_ids_for_rule,
    plan_to_corpus_example,
)


def _plan() -> PlanIR:
    return PlanIR.model_validate(
        {
            "version": "1.0",
            "run_id": "r1",
            "intent": "please send the workout and then list files",
            "intent_kind": "user",
            "steps": [
                {
                    "id": "s1",
                    "tool": "message",
                    "status": "executed",
                    "args": {"message": "ATTENTION MARINE, time to train."},
                    "result_summary": {
                        "ok": True,
                        "byte_size": 12,
                        "excerpt": "sent",
                        "extracted": {"urls": [], "paths": [], "commands": []},
                        "flags": {"truncated": False, "injection_markers": False},
                    },
                },
                {
                    "id": "s2",
                    "tool": "exec",
                    "status": "executed",
                    "args": {"command": "ls -la /tmp"},
                    "result_summary": {
                        "ok": True,
                        "byte_size": 10,
                        "excerpt": "ls -la /tmp",
                        "extracted": {
                            "urls": [],
                            "paths": [],
                            "commands": ["ls -la /tmp"],
                        },
                        "flags": {"truncated": False, "injection_markers": False},
                    },
                },
                {
                    "id": "s3",
                    "tool": "exec",
                    "status": "pending",
                    "args": {"command": "ls -la /home/node/.openclaw"},
                },
            ],
            "metadata": {"adapter": "openclaw", "hook": "before_tool_call"},
        }
    )


def test_keep_step_ids_uses_rule_match_plus_pending() -> None:
    plan = _plan()
    log = {
        "matched_rules": [
            {
                "id": "AIRA-010",
                "action": "review",
                "matched_step_ids": ["s3"],
            }
        ]
    }
    assert keep_step_ids_for_rule(plan, log, "AIRA-010") == ["s3"]


def test_keep_step_ids_falls_back_to_pending() -> None:
    plan = _plan()
    assert keep_step_ids_for_rule(plan, {"matched_rules": ["AIRA-010"]}, "AIRA-010") == ["s3"]


def test_plan_to_corpus_example_slices_to_matched_steps() -> None:
    plan = _plan()
    example = plan_to_corpus_example(
        plan,
        rule_id="AIRA-010",
        label="benign",
        example_id="ex-1",
        derive_intent=True,
        keep_step_ids=["s3"],
    )
    assert [step.tool for step in example.steps] == ["exec"]
    assert example.steps[0].status == "pending"
    assert example.steps[0].args["command"] == "ls -la /home/node/.openclaw"
    assert example.steps[0].excerpt is None
    assert example.intent is not None
    assert example.intent.startswith("user: exec —")
    assert "ATTENTION MARINE" not in (example.intent or "")


def test_plan_to_corpus_example_drops_duplicate_exec_excerpt() -> None:
    plan = _plan()
    example = plan_to_corpus_example(
        plan,
        rule_id="AIRA-010",
        label="benign",
        example_id="ex-2",
        keep_step_ids=["s2", "s3"],
    )
    executed = example.steps[0]
    assert executed.tool == "exec"
    assert executed.status == "executed"
    assert executed.excerpt is None
    assert executed.args["command"] == "ls -la /tmp"
