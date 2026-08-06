from __future__ import annotations

from enum import Enum

from sentrook.planir import PlanIR, PlanStep
from sentrook.result import MatchedRule, MatchedSubgraph
from sentrook.sanitize.signal_excerpt import is_content_like_key, pack_signal_excerpt


class SubgraphStrategy(str, Enum):
    """How to slice a PlanIR for L3 embedding or debug output."""

    MATCHED_STEPS = "matched_steps"
    PENDING_WINDOW = "pending_window"
    RISKY_CLOSURE = "risky_closure"


_RISKY_TOOLS = frozenset({"exec", "write", "browser", "web_fetch"})


def extract_subgraph(
    plan: PlanIR,
    *,
    strategy: SubgraphStrategy = SubgraphStrategy.PENDING_WINDOW,
    matched_step_ids: list[str] | None = None,
    window_before: int = 3,
) -> MatchedSubgraph | None:
    """Extract a relevant step slice from PlanIR for L3 or reporting."""
    if strategy == SubgraphStrategy.MATCHED_STEPS:
        if not matched_step_ids:
            return None
        steps = [s for s in plan.steps if s.id in matched_step_ids]
        if not steps:
            return None
        return _to_subgraph(steps)

    if strategy == SubgraphStrategy.PENDING_WINDOW:
        pending_idx = next(
            (i for i, s in enumerate(plan.steps) if s.status == "pending"),
            None,
        )
        if pending_idx is None:
            return None
        start = max(0, pending_idx - window_before)
        return _to_subgraph(plan.steps[start : pending_idx + 1])

    if strategy == SubgraphStrategy.RISKY_CLOSURE:
        risky_ids = {s.id for s in plan.steps if s.tool in _RISKY_TOOLS}
        if not risky_ids:
            return None
        steps = [s for s in plan.steps if s.id in risky_ids]
        return _to_subgraph(steps)

    return None


def subgraph_from_matched_rule(
    plan: PlanIR, matched_rule: MatchedRule | None
) -> MatchedSubgraph | None:
    """Backward-compatible helper: slice by L2 winning rule step IDs."""
    if matched_rule is None or not matched_rule.matched_step_ids:
        return None
    return extract_subgraph(
        plan,
        strategy=SubgraphStrategy.MATCHED_STEPS,
        matched_step_ids=matched_rule.matched_step_ids,
    )


def subgraph_to_text(
    subgraph: MatchedSubgraph,
    *,
    intent: str | None = None,
    intent_kind: str | None = None,
) -> str:
    """Serialize a subgraph for L3 embedding (stable, human-readable).

    Exec ``command`` values are emitted first so bi-encoder scoring can separate
    benign shell introspection from high-risk commands when session intent is long
    and dominates shorter fields.
    """
    lines: list[str] = []
    for step in subgraph.steps:
        command = step.args.get("command") if step.args else None
        if command is not None:
            lines.append(f"command: {command}")
    if intent_kind:
        lines.append(f"intent_kind: {intent_kind}")
    if intent:
        lines.append(f"intent: {intent}")
    trajectory = " → ".join(f"{step.tool}({step.status})" for step in subgraph.steps)
    lines.append(f"trajectory: {trajectory}")
    for step in subgraph.steps:
        if step.args:
            arg_bits = ", ".join(
                f"{k}={_brief(v, key=k)}" for k, v in step.args.items() if k != "command"
            )
            if arg_bits:
                lines.append(f"  {step.id} args: {arg_bits}")
        if step.result_summary and step.result_summary.excerpt:
            excerpt = step.result_summary.excerpt.replace("\n", " ")[:200]
            lines.append(f"  {step.id} excerpt: {excerpt}")
    return "\n".join(lines)


def _to_subgraph(steps: list[PlanStep]) -> MatchedSubgraph:
    return MatchedSubgraph(
        step_ids=[s.id for s in steps],
        tools=[s.tool for s in steps],
        steps=steps,
    )


_L3_BRIEF_LIMIT = 80


def _brief(value: object, *, key: str | None = None) -> str:
    text = str(value)
    if len(text) <= _L3_BRIEF_LIMIT:
        return text
    if is_content_like_key(key):
        return pack_signal_excerpt(text, _L3_BRIEF_LIMIT, ellipsis="...")
    return text[: _L3_BRIEF_LIMIT - 3] + "..."
