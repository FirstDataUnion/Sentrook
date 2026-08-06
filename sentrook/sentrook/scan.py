from __future__ import annotations

import time
from pathlib import Path

from sentrook import __version__
from sentrook.adapters.snapshot import primary_pending_step
from sentrook.config import L2Authority, L3Policy, ScannerConfig
from sentrook.corpus.loader import load_corpus, resolve_corpus_dir
from sentrook.corpus.models import LoadedRuleCorpus
from sentrook.corpus.personal import resolve_personal_corpus_dir
from sentrook.layers.l1_index import build_l1_index, l1_candidates
from sentrook.layers.l2_match import classify_match, evaluate_rule
from sentrook.layers.l3_embed import make_scorer
from sentrook.layers.l3_score import (
    BiEncoderScorer,
    L3ScoreParams,
    score_rule,
)
from sentrook.layers.pass_kind import L2PassKind
from sentrook.planir import PlanIR
from sentrook.redact import redact_args
from sentrook.result import (
    DebugInfo,
    L2RuleTrace,
    L3RuleTrace,
    LayerInfo,
    MatchedRule,
    MatcherThresholds,
    PendingStepDebug,
    PlanEcho,
    PlanMetadataEcho,
    ScanResult,
    StepSummary,
    TimingInfo,
)
from sentrook.rules.loader import load_rules
from sentrook.rules.models import Rule
from sentrook.subgraph import (
    SubgraphStrategy,
    extract_subgraph,
    subgraph_from_matched_rule,
    subgraph_to_text,
)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_PASS_RANK = {
    L2PassKind.SEQUENCE_ARGS: 4,
    L2PassKind.SEQUENCE_WITH_GAP: 3,
    L2PassKind.SEQUENCE: 2,
    L2PassKind.ALL: 2,
    L2PassKind.NONE: 1,
    L2PassKind.INTENT_KIND: 1,
    L2PassKind.PENDING_TOOL: 1,
    L2PassKind.DATAFLOW: 5,
    L2PassKind.UNKNOWN: 0,
}


def _match_rank(m: MatchedRule) -> tuple[float, int, int, str]:
    return (
        m.confidence,
        _SEVERITY_RANK[m.severity],
        _PASS_RANK.get(m.pass_id, 0),
        m.id,
    )


def scan_plan(
    plan: PlanIR,
    rules: list[Rule],
    config: ScannerConfig | None = None,
    *,
    plan_source: str | None = None,
    rules_source: str | None = None,
    corpus: dict[str, LoadedRuleCorpus] | None = None,
    l3_scorer: BiEncoderScorer | None = None,
    verbose: bool = False,
) -> ScanResult:
    config = config or ScannerConfig()
    t0 = time.perf_counter()

    redacted_plan = _redact_plan(plan)
    plan_tools = {step.tool for step in redacted_plan.steps}

    # Memoisation candidate for later in development, or replace with pre-compiled
    # index file.
    index = build_l1_index(rules)

    t1 = time.perf_counter()
    candidates = l1_candidates(plan_tools, index, intent_kind=redacted_plan.intent_kind)
    candidate_ids = {rule.id for rule in candidates}
    skipped_rule_ids = sorted(rule.id for rule in rules if rule.id not in candidate_ids)
    t2 = time.perf_counter()

    matched_rules: list[MatchedRule] = []
    l2_traces: list[L2RuleTrace] = []
    winning_rule: MatchedRule | None = None

    if candidates:
        for rule in candidates:
            outcome = evaluate_rule(rule, redacted_plan, config.matcher)
            is_hit, effective_action = classify_match(outcome, rule.meta.action, config.matcher)
            l2_traces.append(
                L2RuleTrace(
                    rule_id=rule.id,
                    hit=is_hit,
                    confidence=outcome.confidence,
                    pass_id=outcome.pass_id,
                    reason=outcome.reason,
                    effective_action=effective_action if is_hit else "allow",
                )
            )
            if not is_hit:
                continue

            matched_rules.append(
                MatchedRule(
                    id=rule.id,
                    name=rule.meta.name,
                    severity=rule.meta.severity,
                    action=effective_action,  # type: ignore[arg-type]
                    reason=outcome.reason,
                    confidence=outcome.confidence,
                    layer="L2",
                    pass_id=outcome.pass_id,
                    matched_step_ids=outcome.matched_step_ids,
                    description=rule.meta.description,
                )
            )

    if not candidates:
        decision, risk, summary = (
            "allow",
            0.0,
            "No matching rules. Early exit at Layer 1.",
        )
        exits = ["L1"]
    elif not matched_rules:
        decision, risk, summary = "allow", 0.0, "No rules matched"
        exits = ["L1", "L2"]
    else:
        decision, risk, summary, winning_rule = _aggregate(matched_rules)
        exits = ["L1", "L2"]

    t3 = time.perf_counter()

    # Layer 3: semantic tie-breaker on soft `review` rules. Only attempted when a
    # policy is active and L2's verdict is `review`; hard blocks and allows never
    # reach L3 (Phase 1 policy fuse).
    l3_traces: list[L3RuleTrace] = []
    if config.l3_policy != L3Policy.OFF and decision == "review":
        if corpus is None:
            corpus = load_corpus(
                resolve_corpus_dir(config.l3.corpus_dir),
                personal_corpus_dir=resolve_personal_corpus_dir(),
            )
        scorer = l3_scorer if l3_scorer is not None else make_scorer(config)
        decision, risk, summary, winning_rule, l3_traces, l3_ran = _apply_l3(
            plan=redacted_plan,
            matched_rules=matched_rules,
            rule_by_id={r.id: r for r in candidates},
            config=config,
            corpus=corpus,
            scorer=scorer,
            decision=decision,
            risk=risk,
            summary=summary,
            winning_rule=winning_rule,
        )
        if l3_ran:
            exits = exits + ["L3"]

    t4 = time.perf_counter()

    pending = primary_pending_step(redacted_plan)
    subgraph = subgraph_from_matched_rule(redacted_plan, winning_rule)

    steps_summary = [
        StepSummary(id=step.id, tool=step.tool, status=step.status) for step in redacted_plan.steps
    ]

    return ScanResult(
        decision=decision,
        risk=risk,
        summary=summary,
        matched_rules=matched_rules,
        winning_rule_id=winning_rule.id if winning_rule is not None else None,
        matched_subgraph=subgraph,
        layers=LayerInfo(
            exits=exits,
            l1_candidates=[r.id for r in candidates],
            l2_evaluated=len(candidates),
        ),
        plan=PlanEcho(
            run_id=redacted_plan.run_id,
            plan_size=len(redacted_plan.steps),
            pending_step_id=pending.id if pending else None,
            pending_tool=pending.tool if pending else None,
            tools=[s.tool for s in redacted_plan.steps],
        ),
        timing=TimingInfo(
            total_ms=int((t4 - t0) * 1000),
            l1_ms=int((t2 - t1) * 1000),
            l2_ms=int((t3 - t2) * 1000),
            l3_ms=int((t4 - t3) * 1000),
        ),
        debug=DebugInfo(
            scanner_version=__version__,
            rules_loaded=len(rules),
            rules_source=rules_source,
            plan_source=plan_source,
            l1_index_keys=sorted(index.keys()),
            plan_tools=sorted(plan_tools),
            plan_metadata=PlanMetadataEcho(
                adapter=redacted_plan.metadata.adapter,
                agent_id=redacted_plan.metadata.agent_id,
                session_id=redacted_plan.metadata.session_id,
                hook=redacted_plan.metadata.hook,
            ),
            intent=redacted_plan.intent,
            l1_candidate_ids=[r.id for r in candidates],
            l1_skipped_rule_ids=skipped_rule_ids,
            l2_traces=l2_traces,
            l3_traces=l3_traces,
            pending_step=(
                PendingStepDebug(
                    id=pending.id,
                    tool=pending.tool,
                    args=pending.args,
                )
                if pending
                else None
            ),
            steps_summary=steps_summary,
            matcher_thresholds=(
                MatcherThresholds(
                    definitive=config.matcher.definitive_threshold,
                    review=config.matcher.review_threshold,
                )
                if verbose
                else None
            ),
        ),
    )


def scan_plan_file(
    plan_path: Path,
    rules_path: Path,
    config: ScannerConfig | None = None,
    *,
    corpus: dict[str, LoadedRuleCorpus] | None = None,
    l3_scorer: BiEncoderScorer | None = None,
    verbose: bool = False,
) -> ScanResult:
    import json

    with plan_path.open(encoding="utf-8") as handle:
        plan = PlanIR.model_validate(json.load(handle))
    rules = load_rules(rules_path)
    return scan_plan(
        plan,
        rules,
        config,
        plan_source=str(plan_path.resolve()),
        rules_source=str(rules_path.resolve()),
        corpus=corpus,
        l3_scorer=l3_scorer,
        verbose=verbose,
    )


def _resolve_authority(rule: Rule | None, config: ScannerConfig) -> L2Authority:
    if rule is not None and rule.meta.authority is not None:
        return rule.meta.authority
    return config.default_l2_authority


def _apply_l3(
    *,
    plan: PlanIR,
    matched_rules: list[MatchedRule],
    rule_by_id: dict[str, Rule],
    config: ScannerConfig,
    corpus: dict[str, LoadedRuleCorpus],
    scorer: BiEncoderScorer,
    decision: str,
    risk: float,
    summary: str,
    winning_rule: MatchedRule | None,
) -> tuple[str, float, str, MatchedRule | None, list[L3RuleTrace], bool]:
    """Score each soft `review` rule and apply the Phase 1 policy fuse.

    Only `review` verdicts on soft-authority rules are candidates; each is scored
    independently. A rule whose L3 signal is `allow` is downgraded, and the overall
    decision is re-aggregated over the rules that survive. Returns the (possibly
    updated) verdict plus the per-rule traces and whether L3 actually scored anything.
    """
    traces: list[L3RuleTrace] = []
    ran_any = False

    for matched in matched_rules:
        if matched.action != "review":
            continue
        if _resolve_authority(rule_by_id.get(matched.id), config) != L2Authority.SOFT:
            continue

        rule_corpus = corpus.get(matched.id)
        if rule_corpus is None:
            traces.append(
                L3RuleTrace(
                    rule_id=matched.id,
                    ran=False,
                    skipped_reason="insufficient_corpus",
                    decision="no_change",
                )
            )
            continue

        subgraph = extract_subgraph(
            plan,
            strategy=SubgraphStrategy.MATCHED_STEPS,
            matched_step_ids=matched.matched_step_ids,
        )
        if subgraph is None:
            traces.append(
                L3RuleTrace(
                    rule_id=matched.id,
                    ran=False,
                    skipped_reason="no_subgraph",
                    decision="no_change",
                )
            )
            continue

        params = L3ScoreParams(
            allow_margin=(
                rule_corpus.allow_margin
                if rule_corpus.allow_margin is not None
                else config.l3.allow_margin
            ),
            fail_closed_margin=(
                rule_corpus.fail_closed_margin
                if rule_corpus.fail_closed_margin is not None
                else config.l3.fail_closed_margin
            ),
            top_k=config.l3.top_k,
        )
        query_text = subgraph_to_text(subgraph, intent=plan.intent, intent_kind=plan.intent_kind)
        trace = score_rule(matched.id, query_text, rule_corpus, params, scorer)
        traces.append(trace)
        if trace.ran:
            ran_any = True

    downgraded = {t.rule_id for t in traces if t.ran and t.decision == "allow"}
    if downgraded:
        for matched in matched_rules:
            if matched.id in downgraded:
                matched.layer = "L3"
        remaining = [m for m in matched_rules if m.action == "review" and m.id not in downgraded]
        if not remaining:
            return (
                "allow",
                0.0,
                f"Allowed after L3 downgrade of {', '.join(sorted(downgraded))}",
                None,
                traces,
                ran_any,
            )
        decision, risk, summary, winning_rule = _aggregate(remaining)

    return decision, risk, summary, winning_rule, traces, ran_any


def _redact_plan(plan: PlanIR) -> PlanIR:
    steps = []
    for step in plan.steps:
        steps.append(step.model_copy(update={"args": redact_args(step.args)}))
    return plan.model_copy(update={"steps": steps})


def _aggregate(
    matched: list[MatchedRule],
) -> tuple[str, float, str, MatchedRule | None]:
    if any(m.action == "block" for m in matched):
        top = max(
            (m for m in matched if m.action == "block"),
            key=_match_rank,
        )
        return (
            "block",
            1.0,
            f"Blocked by {top.id}: {top.reason}",
            top,
        )

    if any(m.action == "review" for m in matched):
        top = max(
            (m for m in matched if m.action == "review"),
            key=_match_rank,
        )
        return (
            "review",
            top.confidence,
            f"Review triggered by {top.id}: {top.reason}",
            top,
        )

    return "allow", 0.0, "No actionable matches", None
