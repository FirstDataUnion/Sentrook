"""`action: observe` — matches, logs, counts, holds no decision.

Covered through `scan_plan` and the serve/plugin end of the chain (F28, F63).
Synthetic rules throughout: the library half is what demotes AIRA-010/064.
"""

from __future__ import annotations

from sentrook.config import L3Policy, MatcherConfig, ScannerConfig
from sentrook.layers.l2_match import MatchOutcome, classify_match
from sentrook.layers.pass_kind import L2PassKind
from sentrook.planir import PlanIR
from sentrook.rules.compiler import compile_rule
from sentrook.scan import scan_plan
from sentrook.serve.config import ServeConfig
from sentrook.serve.log import build_log_record
from sentrook.serve.response import build_scan_response


def _plan(command: str = "ls -la") -> PlanIR:
    return PlanIR.model_validate(
        {
            "version": "1.0",
            "run_id": "r-observe",
            "intent": "check something",
            "intent_kind": "user",
            "steps": [
                {"id": "s1", "tool": "exec", "status": "pending", "args": {"command": command}}
            ],
            "metadata": {"adapter": "fixture", "hook": "before_tool_call"},
        }
    )


def _rule(rule_id: str, action: str, *, authority: str = "soft", severity: str = "medium") -> dict:
    return {
        "rule": rule_id,
        "meta": {
            "name": f"{rule_id} {action}",
            "action": action,
            "authority": authority,
            "severity": severity,
        },
        "condition": {"pending_tool": "exec"},
    }


def _scan(docs: list[dict], command: str = "ls -la"):
    rules = [compile_rule(doc) for doc in docs]
    return scan_plan(_plan(command), rules, config=ScannerConfig(l3_policy=L3Policy.OFF))


def test_observe_only_plan_decides_allow_with_the_rule_in_matched_rules() -> None:
    result = _scan([_rule("OBS-001", "observe")])
    assert result.decision == "allow"
    assert result.winning_rule_id is None
    assert result.consequence is None
    matched = {m.id: m for m in result.matched_rules}
    assert "OBS-001" in matched
    assert matched["OBS-001"].action == "observe"


def test_observe_plus_soft_review_is_held_by_the_soft_rule() -> None:
    result = _scan([_rule("OBS-001", "observe"), _rule("REV-001", "review", authority="soft")])
    assert result.decision == "review"
    assert result.winning_rule_id == "REV-001"
    actions = {m.id: m.action for m in result.matched_rules}
    assert actions["OBS-001"] == "observe"
    assert actions["REV-001"] == "review"


def test_observe_plus_block_decides_block() -> None:
    result = _scan([_rule("OBS-001", "observe"), _rule("BLK-001", "block")])
    assert result.decision == "block"
    assert result.winning_rule_id == "BLK-001"


def test_review_authority_ignores_observe_matches() -> None:
    """A hard observe must not colour a soft review, and the inverse."""
    from sentrook.serve.response import _review_authority

    soft_review = _scan(
        [
            _rule("OBS-001", "observe", authority="hard", severity="critical"),
            _rule("REV-001", "review", authority="soft"),
        ]
    )
    assert soft_review.decision == "review"
    assert _review_authority(soft_review, {"OBS-001": "hard", "REV-001": "soft"}) == "soft"

    hard_review = _scan(
        [
            _rule("OBS-001", "observe", authority="soft"),
            _rule("REV-001", "review", authority="hard"),
        ]
    )
    assert _review_authority(hard_review, {"OBS-001": "soft", "REV-001": "hard"}) == "hard"


def test_review_severity_ignores_observe_matches() -> None:
    from sentrook.serve.response import _review_severity

    result = _scan(
        [
            _rule("OBS-001", "observe", severity="critical"),
            _rule("REV-001", "review", severity="medium"),
        ]
    )
    assert result.decision == "review"
    assert _review_severity(result) == "warning"


def test_build_log_record_accepts_observe_and_never_raises() -> None:
    """F63 — the allow-action gap a second time.

    An unknown action used to raise `ValidationError` inside `build_log_record`
    on the serve request path. Asserted through the function, not the
    annotation: the annotation is not what broke.
    """
    result = _scan([_rule("OBS-001", "observe")])
    record = build_log_record(result, _plan(), mode="observe")
    assert {m.id: m.action for m in record.matched_rules}["OBS-001"] == "observe"
    assert record.decision == "allow"
    assert record.winning_rule_id is None


def test_observe_match_is_counted_on_the_metrics_endpoint() -> None:
    from prometheus_client import generate_latest

    from sentrook.serve.metrics import REGISTRY, record_scan_rule_breakdown

    result = _scan([_rule("OBS-001", "observe")])
    record_scan_rule_breakdown(result, authority_by_rule_id={"OBS-001": "soft"})
    exported = generate_latest(REGISTRY).decode("utf-8")
    assert 'sentrook_scan_matched_rules_total{action="observe"' in exported.replace(
        ",", ", "
    ) or ('rule_id="OBS-001"' in exported and 'action="observe"' in exported)
    winning_lines = [
        line for line in exported.splitlines() if "sentrook_scan_winning_rules_total" in line
    ]
    assert not any('rule_id="OBS-001"' in line for line in winning_lines)


def test_partial_observe_does_not_degrade_to_review() -> None:
    config = MatcherConfig()
    partial = MatchOutcome(False, 0.5, "one slot of two", [], L2PassKind.SEQUENCE)
    assert config.review_threshold <= 0.5 < config.definitive_threshold
    assert classify_match(partial, "observe", config) == (True, "observe")


def test_scan_response_carries_consequence_of_the_winning_review() -> None:
    result = _scan([_rule("OBS-001", "observe"), _rule("AIRA-083", "review", authority="hard")])
    assert result.decision == "review"
    assert result.winning_rule_id == "AIRA-083"
    assert result.consequence == "C1 credential"
    payload = build_scan_response(ServeConfig(), result, build_log_record(result, _plan()))
    assert payload["consequence"] == "C1 credential"
    assert "entity" not in payload


def test_observe_only_response_has_no_review_fields() -> None:
    result = _scan([_rule("OBS-001", "observe")])
    payload = build_scan_response(ServeConfig(), result, build_log_record(result, _plan()))
    assert payload["decision"] == "allow"
    assert "review_title" not in payload
    assert "review_authority" not in payload
    assert "consequence" not in payload
