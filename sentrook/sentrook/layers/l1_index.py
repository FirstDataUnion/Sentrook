from __future__ import annotations

from collections import defaultdict

from sentrook.layers.l2_match import _slot_tool_names
from sentrook.rules.models import (
    AllCondition,
    AnyCondition,
    ConditionNode,
    IntentKindCondition,
    NoneCondition,
    PendingToolCondition,
    Rule,
    SequenceCondition,
    SequenceWithGapCondition,
)


def build_l1_index(rules: list[Rule]) -> dict[str, list[Rule]]:
    """Map each tool name to rules that might apply when that tool appears in a plan.

    Sequence rules are indexed under every tool in their chain (including pipe
    alternates like ``write|edit``); candidacy still requires the full tool
    requirement to be satisfied (see ``l1_candidates``).
    """
    index: dict[str, list[Rule]] = defaultdict(list)
    for rule in rules:
        for tool in _index_tools(rule.condition):
            index[tool].append(rule)
    return dict(index)


def _index_tools(node: ConditionNode) -> set[str]:
    """All tool names to index this rule under (alternates expanded)."""
    if isinstance(node, PendingToolCondition):
        return {node.tool}
    if isinstance(node, (SequenceCondition, SequenceWithGapCondition)):
        return {t for slot in node.steps for t in _slot_tool_names(slot.tool)}
    if isinstance(node, AllCondition):
        tools: set[str] = set()
        for child in node.conditions:
            tools |= _index_tools(child)
        return tools
    if isinstance(node, AnyCondition):
        tools = set()
        for child in node.conditions:
            tools |= _index_tools(child)
        return tools
    if isinstance(node, NoneCondition):
        return set()
    return set()


def _plan_satisfies_rule(
    plan_tools: set[str],
    node: ConditionNode,
    *,
    intent_kind: str | None = None,
) -> bool:
    """Return whether ``plan_tools`` satisfies this rule's tool requirements.

    Pipe alternates (``write|edit``) require any one listed tool, not all.
    """
    if isinstance(node, IntentKindCondition):
        return intent_kind == node.kind
    if isinstance(node, PendingToolCondition):
        return node.tool in plan_tools
    if isinstance(node, (SequenceCondition, SequenceWithGapCondition)):
        return all(bool(_slot_tool_names(slot.tool) & plan_tools) for slot in node.steps)
    if isinstance(node, AllCondition):
        return all(
            _plan_satisfies_rule(plan_tools, child, intent_kind=intent_kind)
            for child in node.conditions
        )
    if isinstance(node, AnyCondition):
        return any(
            _plan_satisfies_rule(plan_tools, child, intent_kind=intent_kind)
            for child in node.conditions
        )
    if isinstance(node, NoneCondition):
        return True
    return False


def _required_plan_tools(node: ConditionNode) -> set[str]:
    """Tools that must all appear in a plan before L2 evaluates this rule.

    Deprecated for candidacy; prefer ``_plan_satisfies_rule``. Kept for tests
    that expect the expanded alternate set.
    """
    return _index_tools(node)


def l1_candidates(
    plan_tools: set[str],
    index: dict[str, list[Rule]],
    *,
    intent_kind: str | None = None,
) -> list[Rule]:
    """Return rules whose full tool requirement is satisfied by ``plan_tools``.

    Assumes scans run at ``before_tool_call`` with the gated pending step present.
    Partial trajectories (e.g. fetch-only) therefore skip chain rules at L1 without
    evaluating L2.
    """
    seen: set[str] = set()
    candidates: list[Rule] = []
    for tool in plan_tools:
        for rule in index.get(tool, []):
            if rule.id in seen:
                continue
            if not _plan_satisfies_rule(plan_tools, rule.condition, intent_kind=intent_kind):
                continue
            seen.add(rule.id)
            candidates.append(rule)
    return candidates
