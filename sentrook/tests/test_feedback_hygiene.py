"""Tests for community derived intent, fingerprints, and session caps."""

from __future__ import annotations

from sentrook.corpus.models import CorpusStep
from sentrook.planir import PlanIR
from sentrook.serve.feedback import (
    FeedbackSessionCapTracker,
    keep_step_ids_for_rule,
    pick_feedback_rule_ids,
    plan_to_corpus_example,
)
from sentrook.serve.fingerprint import (
    command_fingerprint,
    derive_community_intent,
    is_sensitive_fingerprint,
    path_class,
)
from sentrook.serve.harvest import log_row_to_corpus_example


def _plan(*, with_read: bool = False) -> PlanIR:
    steps: list[dict] = []
    if with_read:
        steps.append(
            {
                "id": "s1",
                "tool": "read",
                "status": "executed",
                "args": {"path": "/tmp/notes.md"},
            }
        )
        next_id = 2
    else:
        next_id = 1
    steps.extend(
        [
            {
                "id": f"s{next_id}",
                "tool": "message",
                "status": "executed",
                "args": {"message": "long user brief should not appear in intent"},
            },
            {
                "id": f"s{next_id + 1}",
                "tool": "exec",
                "status": "executed",
                "args": {"command": "ls -la /tmp"},
            },
            {
                "id": f"s{next_id + 2}",
                "tool": "exec",
                "status": "pending",
                "args": {"command": "ls -la /home/node/.openclaw"},
            },
        ]
    )
    return PlanIR.model_validate(
        {
            "version": "1.0",
            "run_id": "r1",
            "intent": "please send the workout and then list files " * 20,
            "intent_kind": "user",
            "steps": steps,
            "metadata": {
                "adapter": "openclaw",
                "hook": "before_tool_call",
                "session_id": "sess-abc",
            },
        }
    )


def test_derive_community_intent_is_pending_only() -> None:
    steps = [
        CorpusStep(tool="read", status="executed", args={"path": "/tmp/a"}),
        CorpusStep(tool="exec", status="executed", args={"command": "ls /tmp"}),
        CorpusStep(
            tool="exec",
            status="pending",
            args={"command": "grep foo /tmp/bar"},
        ),
    ]
    intent = derive_community_intent(intent_kind="user", steps=steps)
    assert intent.startswith("user: exec —")
    assert "read→" not in intent
    assert "grep foo" in intent


def test_plan_to_corpus_example_pending_only_intent() -> None:
    plan = _plan()
    example = plan_to_corpus_example(
        plan,
        rule_id="AIRA-010",
        label="benign",
        example_id="ex-1",
        derive_intent=True,
        keep_step_ids=["s2", "s3"],
    )
    assert example.intent is not None
    assert example.intent.startswith("user: exec —")
    assert "→" not in example.intent.split("—", 1)[0]
    assert "workout" not in (example.intent or "")


def test_fingerprint_separates_sensitive_paths() -> None:
    routine = [
        CorpusStep(
            tool="exec",
            status="pending",
            args={"command": "ls -la /home/node/.openclaw/workspace"},
        )
    ]
    sensitive = [
        CorpusStep(
            tool="exec",
            status="pending",
            args={"command": "cat /home/node/.openclaw/agents/main/agent/auth-profiles.json"},
        )
    ]
    fp_r = command_fingerprint(rule_id="AIRA-010", label="benign", steps=routine)
    fp_s = command_fingerprint(rule_id="AIRA-010", label="benign", steps=sensitive)
    assert fp_r != fp_s
    assert path_class(sensitive[0].args["command"]) == "sensitive"
    assert is_sensitive_fingerprint(fp_s)
    assert not is_sensitive_fingerprint(fp_r)


def test_session_cap_skips_duplicate_fingerprints() -> None:
    tracker = FeedbackSessionCapTracker(max_per_session_rule=2)
    fp = "AIRA-010:benign:ls:openclaw"
    ok, _ = tracker.allow(session_id="s1", rule_id="AIRA-010", fingerprint=fp, sensitive=False)
    assert ok
    ok2, reason = tracker.allow(
        session_id="s1", rule_id="AIRA-010", fingerprint=fp, sensitive=False
    )
    assert not ok2
    assert reason == "session_fingerprint_duplicate"
    ok3, _ = tracker.allow(
        session_id="s1",
        rule_id="AIRA-010",
        fingerprint="AIRA-010:benign:grep:openclaw",
        sensitive=False,
    )
    assert ok3
    ok4, reason4 = tracker.allow(
        session_id="s1",
        rule_id="AIRA-010",
        fingerprint="AIRA-010:benign:find:openclaw",
        sensitive=False,
    )
    assert not ok4
    assert reason4 == "session_rule_cap"
    # Sensitive bypasses cap
    ok5, _ = tracker.allow(
        session_id="s1",
        rule_id="AIRA-010",
        fingerprint="AIRA-010:benign:cat:sensitive",
        sensitive=True,
    )
    assert ok5


def test_pick_feedback_rule_ids_requires_ingest_for_cofirers() -> None:
    plan = _plan(with_read=False)
    pending_id = plan.steps[-1].id
    log = {
        "winning_rule_id": "AIRA-010",
        "l3_kept_review_rules": ["AIRA-010", "AIRA-064"],
        "matched_rules": [
            {"id": "AIRA-010", "action": "review", "matched_step_ids": [pending_id]},
            {"id": "AIRA-064", "action": "review", "matched_step_ids": [pending_id]},
        ],
    }
    assert pick_feedback_rule_ids(plan, log, resolution="allow-once") == ["AIRA-010"]

    plan2 = _plan(with_read=True)
    read_id = plan2.steps[0].id
    pending_id2 = plan2.steps[-1].id
    log2 = {
        "winning_rule_id": "AIRA-010",
        "l3_kept_review_rules": ["AIRA-010", "AIRA-064"],
        "matched_rules": [
            {
                "id": "AIRA-010",
                "action": "review",
                "matched_step_ids": [pending_id2],
            },
            {
                "id": "AIRA-064",
                "action": "review",
                "matched_step_ids": [read_id, pending_id2],
            },
        ],
    }
    assert keep_step_ids_for_rule(plan2, log2, "AIRA-064") == [read_id, pending_id2]
    assert pick_feedback_rule_ids(plan2, log2, resolution="allow-once") == [
        "AIRA-010",
        "AIRA-064",
    ]


def test_harvest_derives_intent_not_session_prompt() -> None:
    row = {
        "pending_tool": "exec",
        "pending_args": {"command": "ls -la /tmp"},
        "intent": "huge session transcript " * 40,
        "intent_kind": "user",
        "session_id": "abcdef12-xxxx",
        "tool_call_id": "functions.exec:1",
        "summary": "Review triggered by AIRA-010",
    }
    example = log_row_to_corpus_example(row, rule_id="AIRA-010", label="benign")
    assert example is not None
    assert example.intent is not None
    assert example.intent.startswith("user: exec —")
    assert "huge session" not in example.intent
