"""`L3Policy.SHADOW` scores and emits; it never moves the decision."""

from __future__ import annotations

from sentrook.config import L2Authority, L3Policy, ScannerConfig
from sentrook.corpus.models import CorpusEntry, LoadedRuleCorpus
from sentrook.layers.l3_score import StubScorer
from sentrook.planir import PlanIR
from sentrook.result import MatchedSubgraph
from sentrook.rules.compiler import compile_rule
from sentrook.scan import scan_plan


def _plan(command: str = "ls -la") -> PlanIR:
    return PlanIR.model_validate(
        {
            "version": "1.0",
            "run_id": "r-shadow",
            "intent": "list files",
            "intent_kind": "user",
            "steps": [
                {"id": "s1", "tool": "exec", "status": "pending", "args": {"command": command}}
            ],
            "metadata": {"adapter": "fixture", "hook": "before_tool_call"},
        }
    )


def _review_rule() -> dict:
    return {
        "rule": "REV-001",
        "meta": {
            "name": "soft review",
            "action": "review",
            "authority": "soft",
            "severity": "medium",
        },
        "condition": {"pending_tool": "exec"},
    }


def _corpus(rule_id: str = "REV-001") -> dict[str, LoadedRuleCorpus]:
    def entry(example_id: str, label: str) -> CorpusEntry:
        return CorpusEntry(
            example_id=example_id,
            label=label,  # type: ignore[arg-type]
            trust="synthetic",
            text="ls -la",
            subgraph=MatchedSubgraph(step_ids=["s1"], tools=["exec"], steps=[]),
        )

    return {
        rule_id: LoadedRuleCorpus(
            rule_id=rule_id,
            allow_margin=0.15,
            fail_closed_margin=0.1,
            pos=[entry("pos-1", "pos")],
            neg=[entry("neg-1", "neg")],
        )
    }


def _scan(policy: L3Policy):
    rules = [compile_rule(_review_rule())]
    # Benign-leading scores: TIE_BREAKER downgrades this review to allow.
    scorer = StubScorer({"neg-1": 0.9, "pos-1": 0.2})
    return scan_plan(
        _plan(),
        rules,
        config=ScannerConfig(l3_policy=policy, default_l2_authority=L2Authority.SOFT),
        corpus=_corpus(),
        l3_scorer=scorer,
    )


def test_shadow_is_the_default() -> None:
    assert ScannerConfig().l3_policy == L3Policy.SHADOW


def test_shadow_never_moves_a_decision_tie_breaker_would_move() -> None:
    tie = _scan(L3Policy.TIE_BREAKER)
    shadow = _scan(L3Policy.SHADOW)
    assert tie.decision == "allow"
    assert tie.winning_rule_id is None
    assert shadow.decision == "review"
    assert shadow.winning_rule_id == "REV-001"
    assert [t.decision for t in shadow.debug.l3_traces if t.ran] == ["allow"]
    assert "L3" in shadow.layers.exits


def test_shadow_still_emits_the_l3_outcome_metric() -> None:
    from prometheus_client import generate_latest

    from sentrook.serve.metrics import REGISTRY, record_scan_rule_breakdown

    result = _scan(L3Policy.SHADOW)
    record_scan_rule_breakdown(result, authority_by_rule_id={"REV-001": "soft"})
    exported = generate_latest(REGISTRY).decode("utf-8")
    assert "sentrook_scan_l3_outcomes_total" in exported
    assert 'rule_id="REV-001"' in exported
    assert 'outcome="allow"' in exported


def test_off_still_skips_scoring() -> None:
    result = _scan(L3Policy.OFF)
    assert result.decision == "review"
    assert result.debug.l3_traces == []
    assert "L3" not in result.layers.exits


def test_tie_breaker_still_downgrades() -> None:
    result = _scan(L3Policy.TIE_BREAKER)
    assert result.decision == "allow"
    assert result.summary.startswith("Allowed after L3 downgrade")
