from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from sentrook.layers.tool_pattern import (
    exact_index_keys,
    glob_alternates,
    pattern_matches_any_plan_tool,
    tool_pattern_matches,
)
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


@dataclass
class L1Index:
    """Exact tool → rules map plus glob patterns that cannot be enumerated."""

    by_tool: dict[str, list[Rule]] = field(default_factory=dict)
    # (single glob alternate, rule) pairs for the parallel candidate path
    glob_entries: list[tuple[str, Rule]] = field(default_factory=list)


def build_l1_index(rules: list[Rule]) -> L1Index:
    """Map tools/patterns to rules that might apply when those tools appear.

    Sequence rules are indexed under every *exact* tool in their chain (including
    pipe alternates like ``write|edit``). Glob alternates (``mcp__*``,
    ``*__write_file``) are stored on ``glob_entries`` so candidacy can still
    find them without enumerating infinite MCP tool names.
    """
    index: dict[str, list[Rule]] = defaultdict(list)
    glob_entries: list[tuple[str, Rule]] = []
    glob_seen: set[tuple[str, str]] = set()

    for rule in rules:
        for pattern in _tool_patterns(rule.condition):
            for exact in exact_index_keys(pattern):
                index[exact].append(rule)
            for glob_alt in glob_alternates(pattern):
                key = (glob_alt, rule.id)
                if key in glob_seen:
                    continue
                glob_seen.add(key)
                glob_entries.append((glob_alt, rule))

    return L1Index(by_tool=dict(index), glob_entries=glob_entries)


def _tool_patterns(node: ConditionNode) -> set[str]:
    """Collect raw tool patterns from a condition tree (for indexing)."""
    if isinstance(node, PendingToolCondition):
        return {node.tool}
    if isinstance(node, (SequenceCondition, SequenceWithGapCondition)):
        return {slot.tool for slot in node.steps}
    if isinstance(node, AllCondition):
        patterns: set[str] = set()
        for child in node.conditions:
            patterns |= _tool_patterns(child)
        return patterns
    if isinstance(node, AnyCondition):
        patterns = set()
        for child in node.conditions:
            patterns |= _tool_patterns(child)
        return patterns
    if isinstance(node, NoneCondition):
        return set()
    return set()


def _index_tools(node: ConditionNode) -> set[str]:
    """Exact tool names to index this rule under (glob alternates excluded)."""
    tools: set[str] = set()
    for pattern in _tool_patterns(node):
        tools |= set(exact_index_keys(pattern))
    return tools


def _plan_satisfies_rule(
    plan_tools: set[str],
    node: ConditionNode,
    *,
    intent_kind: str | None = None,
) -> bool:
    """Return whether ``plan_tools`` satisfies this rule's tool requirements.

    Pipe alternates and globs require any one matching tool, not all.
    """
    if isinstance(node, IntentKindCondition):
        return intent_kind == node.kind
    if isinstance(node, PendingToolCondition):
        return pattern_matches_any_plan_tool(node.tool, plan_tools)
    if isinstance(node, (SequenceCondition, SequenceWithGapCondition)):
        return all(pattern_matches_any_plan_tool(slot.tool, plan_tools) for slot in node.steps)
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
    that expect the expanded alternate set (exact names only).
    """
    return _index_tools(node)


def l1_candidates(
    plan_tools: set[str],
    index: L1Index | dict[str, list[Rule]],
    *,
    intent_kind: str | None = None,
) -> list[Rule]:
    """Return rules whose full tool requirement is satisfied by ``plan_tools``.

    Assumes scans run at ``before_tool_call`` with the gated pending step present.
    Partial trajectories (e.g. fetch-only) therefore skip chain rules at L1 without
    evaluating L2.

    Accepts a legacy ``dict[str, list[Rule]]`` exact-only index for older callers.
    """
    if isinstance(index, dict):
        index = L1Index(by_tool=index, glob_entries=[])

    seen: set[str] = set()
    candidates: list[Rule] = []

    def _maybe_add(rule: Rule) -> None:
        if rule.id in seen:
            return
        if not _plan_satisfies_rule(plan_tools, rule.condition, intent_kind=intent_kind):
            return
        seen.add(rule.id)
        candidates.append(rule)

    for tool in plan_tools:
        for rule in index.by_tool.get(tool, []):
            _maybe_add(rule)

    for glob_alt, rule in index.glob_entries:
        if rule.id in seen:
            continue
        if any(tool_pattern_matches(glob_alt, tool) for tool in plan_tools):
            _maybe_add(rule)

    return candidates
