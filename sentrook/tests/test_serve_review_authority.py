"""`review_authority` on the wire — the field that makes hard authority real.

Three documents (`docs/consequence-taxonomy.md`, `docs/yaira-matcher-dialect.md`
and `rules/compiler.py`'s own docstring) stated that hard authority exists so
an operator's lenient floor cannot waive a rule. None of it was true: the floor
lives in the plugin and is keyed on `review_severity`, which comes from
`meta.severity` alone, and `authority` was never put on the response at all. It
governed L3 downgrade and allow-rule suppression and nothing else.

These are the engine half. `sessionPolicy.test.ts` is the half that enforces.
"""

from __future__ import annotations

from sentrook.planir import PlanIR, PlanMetadata, PlanStep
from sentrook.result import DebugInfo, MatchedRule, PendingStepDebug, PlanEcho, ScanResult
from sentrook.serve.config import ServeConfig
from sentrook.serve.log import ScanLogRecord
from sentrook.serve.response import build_scan_response


def _plan() -> PlanIR:
    return PlanIR(
        version="1.0",
        run_id="sess:run_1",
        steps=[PlanStep(id="s1", tool="exec", status="pending", args={"command": "cat x"})],
        metadata=PlanMetadata(adapter="fixture", hook="before_tool_call"),
    )


def _result(matched: list[MatchedRule], decision: str = "review") -> ScanResult:
    plan = _plan()
    pending = plan.steps[0]
    return ScanResult(
        decision=decision,
        risk=0.4,
        summary="Review",
        matched_rules=matched,
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
            pending_step=PendingStepDebug(id=pending.id, tool=pending.tool, args={}),
        ),
    )


def _record() -> ScanLogRecord:
    return ScanLogRecord(
        ts="2026-09-18T00:00:00+00:00",
        adapter="fixture",
        run_id="sess:run_1",
        pending_tool="exec",
        decision="review",
        risk=0.4,
        summary="Review",
        scanner_version="0.0.0",
    )


def _rule(rule_id: str, *, action: str = "review", severity: str = "medium") -> MatchedRule:
    return MatchedRule(
        id=rule_id,
        name=rule_id,
        severity=severity,
        action=action,
        reason="matched",
        confidence=1.0,
        layer="L2",
        pass_id="pending_tool",
    )


def _response(matched: list[MatchedRule], authority: dict[str, str] | None) -> dict:
    return build_scan_response(
        ServeConfig(),
        _result(matched),
        _record(),
        authority_by_rule_id=authority,
    )


def test_a_soft_review_reports_soft() -> None:
    payload = _response([_rule("AIRA-010")], {"AIRA-010": "soft"})
    assert payload["review_authority"] == "soft"


def test_one_hard_rule_makes_the_whole_review_hard() -> None:
    """`any`, not `worst`. A hard review co-firing with a soft one is still hard.

    Aggregating by severity would get this wrong in the case that matters:
    AIRA-010 (`medium`) fires on every exec, so a `worst`-style rule keyed on
    anything but authority would be dominated by the catch-all.
    """
    payload = _response(
        [_rule("AIRA-010"), _rule("AIRA-059", severity="high")],
        {"AIRA-010": "soft", "AIRA-059": "hard"},
    )
    assert payload["review_authority"] == "hard"


def test_an_unresolvable_rule_id_is_treated_as_hard() -> None:
    """Fail closed. An unwaivable review costs a prompt; the inverse costs the
    detection, and the map can be stale for exactly one scan across a reload."""
    payload = _response([_rule("AIRA-999")], {})
    assert payload["review_authority"] == "hard"


def test_block_rules_do_not_decide_review_authority() -> None:
    """A block is not waivable by this path, so it must not colour the field.

    Without the `action == "review"` filter a soft review co-firing with a
    block would report `hard` for a reason that has nothing to do with the
    review, which is the wrong explanation on the approval card.
    """
    payload = _response(
        [_rule("AIRA-010"), _rule("AIRA-020", action="block", severity="high")],
        {"AIRA-010": "soft", "AIRA-020": "hard"},
    )
    assert payload["review_authority"] == "soft"


def test_the_field_is_absent_unless_the_decision_is_review() -> None:
    result = _result([_rule("AIRA-010")], decision="allow")
    payload = build_scan_response(
        ServeConfig(), result, _record(), authority_by_rule_id={"AIRA-010": "soft"}
    )
    assert "review_authority" not in payload
    assert "review_severity" not in payload


def test_severity_and_authority_are_independent_on_the_wire() -> None:
    """The bug in one sentence: they had been the same field.

    13 of the shipped soft review rules are `severity: high`, and all 5 hard
    ones are too — so a plugin keyed on severity cannot distinguish them, and
    every hard review was waivable by a `critical` floor.
    """
    soft_but_critical = _response([_rule("AIRA-052", severity="high")], {"AIRA-052": "soft"})
    assert soft_but_critical["review_severity"] == "critical"
    assert soft_but_critical["review_authority"] == "soft"

    hard_but_warning = _response([_rule("AIRA-083", severity="medium")], {"AIRA-083": "hard"})
    assert hard_but_warning["review_severity"] == "warning"
    assert hard_but_warning["review_authority"] == "hard"


def test_the_scan_log_records_the_authority() -> None:
    """Otherwise nothing downstream can tell a waivable review from an
    unwaivable one.

    The fatigue report, the review inbox and every post-hoc analysis read the
    scan log, and `authority` is the property Phase 3a made load-bearing. The
    field is set in `ServeRuntime.log_scan`, where the warm rule set lives —
    not by another parameter on `build_log_record`, which is the shape that
    left the plugin's hard-review guard dead three separate times.
    """
    import tempfile
    from pathlib import Path

    from sentrook.serve.runtime import ServeRuntime

    plan = _plan()
    with tempfile.TemporaryDirectory() as tmp:
        config = ServeConfig(log_path=Path(tmp) / "scan.jsonl", rules_path=Path(tmp) / "rules")
        (Path(tmp) / "rules").mkdir()
        (Path(tmp) / "rules" / "AIRA-900.yaml").write_text(
            "rule: AIRA-900\n"
            "meta: {name: hard one, severity: medium, action: review, authority: hard}\n"
            "condition: {pending_tool: exec}\n",
            encoding="utf-8",
        )
        runtime = ServeRuntime(config)
        result = runtime.scanner.scan(plan)
        _, record = runtime.log_scan(plan, result)
        assert result.decision == "review"
        assert record.review_authority == "hard", (
            "the scan log lost the authority; a reader cannot tell whether this "
            "review could have been waived"
        )


def test_a_non_review_records_no_authority() -> None:
    """`None` rather than a default, so the log does not imply a judgement that
    was never made."""
    record = _record()
    assert record.review_authority is None
