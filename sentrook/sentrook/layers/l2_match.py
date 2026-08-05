from __future__ import annotations

import re
from dataclasses import dataclass

from sentrook.config import MatcherConfig
from sentrook.layers.normalize import match_text_with_normalization
from sentrook.layers.pass_kind import L2PassKind
from sentrook.planir import PlanIR, PlanStep, ResultSummary, stringify_arg_value
from sentrook.rules.models import (
    AllCondition,
    AnyCondition,
    ConditionNode,
    IntentKindCondition,
    NoneCondition,
    PendingToolCondition,
    Rule,
    SequenceCondition,
    SequenceSlot,
    SequenceWithGapCondition,
)


@dataclass
class MatchOutcome:
    matched: bool
    confidence: float
    reason: str
    matched_step_ids: list[str]
    pass_id: L2PassKind = L2PassKind.SEQUENCE


def evaluate_rule(rule: Rule, plan: PlanIR, config: MatcherConfig) -> MatchOutcome:
    return _eval_node(rule.condition, plan, config)


def _eval_node(
    node: ConditionNode, plan: PlanIR, config: MatcherConfig
) -> MatchOutcome:
    if isinstance(node, PendingToolCondition):
        return _match_pending_tool(node, plan)
    if isinstance(node, IntentKindCondition):
        return _match_intent_kind(node, plan)
    if isinstance(node, SequenceCondition):
        return _match_sequence(node, plan)
    if isinstance(node, SequenceWithGapCondition):
        return _match_sequence_with_gap(node, plan)
    if isinstance(node, AllCondition):
        return _match_all(node, plan, config)
    if isinstance(node, AnyCondition):
        return _match_any(node, plan, config)
    if isinstance(node, NoneCondition):
        return _match_none(node, plan, config)
    return MatchOutcome(False, 0.0, "unknown condition", [], L2PassKind.UNKNOWN)


def _match_intent_kind(
    node: IntentKindCondition, plan: PlanIR
) -> MatchOutcome:
    if plan.intent_kind == node.kind:
        return MatchOutcome(
            True,
            1.0,
            f"intent_kind is {node.kind}",
            [],
            L2PassKind.INTENT_KIND,
        )
    return MatchOutcome(
        False,
        0.0,
        f"intent_kind is not {node.kind}",
        [],
        L2PassKind.INTENT_KIND,
    )


def _match_pending_tool(
    node: PendingToolCondition, plan: PlanIR
) -> MatchOutcome:
    from sentrook.adapters.snapshot import primary_pending_step

    step = primary_pending_step(plan)
    if step is not None and step.tool == node.tool:
        return MatchOutcome(
            True,
            1.0,
            f"pending tool is {node.tool}",
            [step.id],
            L2PassKind.PENDING_TOOL,
        )
    return MatchOutcome(
        False, 0.0, f"no pending {node.tool}", [], L2PassKind.PENDING_TOOL
    )


def _sequence_pass_kind(
    slots: list[SequenceSlot], *, with_gap: bool = False
) -> L2PassKind:
    if any(slot.args_match or slot.result_flags for slot in slots):
        return L2PassKind.SEQUENCE_ARGS
    if with_gap:
        return L2PassKind.SEQUENCE_WITH_GAP
    return L2PassKind.SEQUENCE


def _match_sequence(node: SequenceCondition, plan: PlanIR) -> MatchOutcome:
    slots = node.steps
    pass_kind = _sequence_pass_kind(slots)
    if not slots:
        return MatchOutcome(False, 0.0, "empty sequence", [], pass_kind)

    best = MatchOutcome(False, 0.0, "no sequence match", [], pass_kind)
    n = len(plan.steps)
    k = len(slots)

    for start in range(max(0, n - k + 1)):
        window = plan.steps[start : start + k]
        outcome = _match_window(slots, window, pass_kind)
        if outcome.confidence > best.confidence:
            best = outcome
        if outcome.matched:
            return outcome

    partial = _best_partial_sequence(slots, plan.steps, pass_kind)
    if partial.confidence > best.confidence:
        best = partial
    return best


def _match_sequence_with_gap(
    node: SequenceWithGapCondition, plan: PlanIR
) -> MatchOutcome:
    slots = node.steps
    pass_kind = _sequence_pass_kind(slots, with_gap=True)
    if not slots:
        return MatchOutcome(False, 0.0, "empty sequence", [], pass_kind)

    outcome = _match_subsequence(slots, plan.steps, pass_kind, max_gap=node.max_gap)
    if outcome.matched:
        return outcome
    return MatchOutcome(False, 0.0, "no sequence with gap match", [], pass_kind)


def _match_window(
    slots: list[SequenceSlot], window: list[PlanStep], pass_kind: L2PassKind
) -> MatchOutcome:
    if len(window) != len(slots):
        return MatchOutcome(False, 0.0, "window size mismatch", [], pass_kind)

    matched_ids: list[str] = []
    for slot, step in zip(slots, window, strict=True):
        if not _slot_matches(slot, step):
            if step.tool not in _slot_tool_names(slot.tool):
                return MatchOutcome(
                    False, 0.0, f"tool mismatch at {step.id}", [], pass_kind
                )
            if slot.status != "any" and step.status != slot.status:
                return MatchOutcome(
                    False,
                    0.0,
                    f"status mismatch for {step.tool}",
                    [],
                    pass_kind,
                )
            return MatchOutcome(
                False, 0.0, f"args mismatch for {step.tool}", [], pass_kind
            )
        matched_ids.append(step.id)

    return MatchOutcome(
        True,
        1.0,
        "sequence matched",
        matched_ids,
        pass_kind,
    )


def _match_subsequence(
    slots: list[SequenceSlot],
    steps: list[PlanStep],
    pass_kind: L2PassKind,
    *,
    max_gap: int | None = None,
) -> MatchOutcome:
    k = len(slots)
    if k == 2 and max_gap is not None:
        return _match_two_slot_with_max_gap(slots, steps, max_gap, pass_kind)

    for start in range(len(steps)):
        matched = 0
        ids: list[str] = []
        step_idx = start
        for slot in slots:
            found = False
            while step_idx < len(steps):
                step = steps[step_idx]
                step_idx += 1
                if not _slot_matches(slot, step):
                    continue
                matched += 1
                ids.append(step.id)
                found = True
                break
            if not found:
                break

        if matched == k:
            return MatchOutcome(
                True,
                1.0,
                "sequence with gap matched",
                ids,
                pass_kind,
            )

    return MatchOutcome(False, 0.0, "no sequence with gap match", [], pass_kind)


def _match_two_slot_with_max_gap(
    slots: list[SequenceSlot],
    steps: list[PlanStep],
    max_gap: int,
    pass_kind: L2PassKind,
) -> MatchOutcome:
    """Match a two-step gapped sequence with a bounded window between slots."""
    slot_a, slot_b = slots[0], slots[1]
    for i, step_a in enumerate(steps):
        if not _slot_matches(slot_a, step_a):
            continue
        for j in range(i + 1, min(len(steps), i + max_gap + 2)):
            step_b = steps[j]
            if _slot_matches(slot_b, step_b):
                return MatchOutcome(
                    True,
                    1.0,
                    "sequence with gap matched",
                    [step_a.id, step_b.id],
                    pass_kind,
                )
    return MatchOutcome(False, 0.0, "no sequence with gap match", [], pass_kind)


def _best_partial_sequence(
    slots: list[SequenceSlot], steps: list[PlanStep], pass_kind: L2PassKind
) -> MatchOutcome:
    best_conf = 0.0
    best_ids: list[str] = []
    k = len(slots)

    for start in range(len(steps)):
        matched = 0
        ids: list[str] = []
        step_idx = start
        for slot in slots:
            found = False
            while step_idx < len(steps):
                step = steps[step_idx]
                step_idx += 1
                if not _slot_matches(slot, step):
                    continue
                matched += 1
                ids.append(step.id)
                found = True
                break
            if not found:
                break

        conf = matched / k if k else 0.0
        if conf > best_conf:
            best_conf = conf
            best_ids = ids

    if best_conf <= 0:
        return MatchOutcome(False, 0.0, "no partial sequence", [], pass_kind)
    return MatchOutcome(
        best_conf >= 1.0,
        best_conf,
        f"partial sequence ({best_conf:.0%})",
        best_ids,
        pass_kind,
    )


def _slot_tool_names(tool: str) -> frozenset[str]:
    """Expand a rule slot tool name; ``write|edit`` matches either tool."""
    if "|" in tool:
        return frozenset(tool.split("|"))
    return frozenset({tool})


def _slot_matches(slot: SequenceSlot, step: PlanStep) -> bool:
    if step.tool not in _slot_tool_names(slot.tool):
        return False
    if slot.status != "any" and step.status != slot.status:
        return False
    if slot.args_match and not _args_match(slot.args_match, step.args):
        return False
    if slot.result_flags and not _result_flags_match(
        slot.result_flags, step.result_summary
    ):
        return False
    return True


def _result_flags_match(
    expected: dict[str, bool], result_summary: ResultSummary | None
) -> bool:
    if result_summary is None:
        return False
    flags = result_summary.flags
    for key, value in expected.items():
        if getattr(flags, key, None) is not value:
            return False
    return True


def _match_none(
    node: NoneCondition, plan: PlanIR, config: MatcherConfig
) -> MatchOutcome:
    inner = _eval_node(node.condition, plan, config)
    if inner.matched:
        return MatchOutcome(
            False,
            0.0,
            f"forbidden pattern matched ({inner.reason})",
            [],
            L2PassKind.NONE,
        )
    return MatchOutcome(
        True,
        1.0,
        "forbidden pattern absent",
        [],
        L2PassKind.NONE,
    )


def _match_all(
    node: AllCondition, plan: PlanIR, config: MatcherConfig
) -> MatchOutcome:
    if not node.conditions:
        return MatchOutcome(False, 0.0, "empty all()", [], L2PassKind.ALL)

    confidences: list[float] = []
    reasons: list[str] = []
    ids: list[str] = []
    all_matched = True

    for child in node.conditions:
        outcome = _eval_node(child, plan, config)
        confidences.append(outcome.confidence)
        reasons.append(outcome.reason)
        ids.extend(outcome.matched_step_ids)
        if not outcome.matched:
            all_matched = False

    confidence = min(confidences) if confidences else 0.0
    return MatchOutcome(
        all_matched,
        confidence,
        "; ".join(reasons),
        list(dict.fromkeys(ids)),
        L2PassKind.ALL,
    )


def _match_any(
    node: AnyCondition, plan: PlanIR, config: MatcherConfig
) -> MatchOutcome:
    if not node.conditions:
        return MatchOutcome(False, 0.0, "empty any()", [], L2PassKind.ANY)

    best = MatchOutcome(False, 0.0, "no any() branch matched", [], L2PassKind.ANY)
    reasons: list[str] = []

    for child in node.conditions:
        outcome = _eval_node(child, plan, config)
        reasons.append(outcome.reason)
        if outcome.matched:
            return MatchOutcome(
                True,
                outcome.confidence,
                outcome.reason,
                outcome.matched_step_ids,
                L2PassKind.ANY,
            )
        if outcome.confidence > best.confidence:
            best = MatchOutcome(
                False,
                outcome.confidence,
                outcome.reason,
                outcome.matched_step_ids,
                L2PassKind.ANY,
            )

    return MatchOutcome(
        False,
        best.confidence,
        "; ".join(reasons) if reasons else best.reason,
        best.matched_step_ids,
        L2PassKind.ANY,
    )


def _args_match(patterns: dict[str, str], args: dict) -> bool:
    for key, pattern in patterns.items():
        if key not in args:
            return False
        value = stringify_arg_value(args[key])
        if not value:
            return False
        # Search raw + lightly deobfuscated shadow (base64 echo|d, \\xNN, quote concat).
        if not match_text_with_normalization(pattern, value):
            return False
    return True


def _pending_steps(plan: PlanIR) -> list[PlanStep]:
    return [s for s in plan.steps if s.status == "pending"]


def classify_match(
    outcome: MatchOutcome, rule_action: str, config: MatcherConfig
) -> tuple[bool, str]:
    """Return (counts_as_hit, effective_action)."""
    if outcome.confidence >= config.definitive_threshold:
        return True, rule_action
    if outcome.confidence >= config.review_threshold:
        return True, "review"
    return False, "allow"
