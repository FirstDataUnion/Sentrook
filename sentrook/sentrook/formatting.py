"""Human-readable scan output for operators and agent reporting."""

from __future__ import annotations

from sentrook.result import ScanResult

_STATUS_ICON = {"executed": "✓", "pending": "⏳"}


def format_scan_text(result: ScanResult, *, verbose: bool = False) -> str:
    lines: list[str] = [
        "=== Sentrook Scan ===",
        f"Decision: {result.decision} (risk {result.risk:.2f})",
        f"Summary: {result.summary}",
        "",
        _format_plan_section(result),
        "",
        _format_layers_section(result),
    ]

    if result.debug.l2_traces:
        lines.append(_format_l2_traces(result))
        lines.append("")

    if result.matched_rules:
        lines.append(_format_matches_section(result))
        lines.append("")

    if result.matched_subgraph:
        lines.append(
            "Matched subgraph: "
            + " → ".join(
                f"{sid} ({tool})"
                for sid, tool in zip(
                    result.matched_subgraph.step_ids,
                    result.matched_subgraph.tools,
                    strict=True,
                )
            )
        )
        lines.append("")

    lines.append(_format_debug_footer(result, verbose=verbose))
    return "\n".join(lines)


def _format_plan_section(result: ScanResult) -> str:
    plan = result.plan
    meta = result.debug.plan_metadata
    parts = [f"Plan: {plan.run_id} | {plan.plan_size} step(s)"]
    if plan.pending_tool:
        parts.append(f"pending {plan.pending_tool} ({plan.pending_step_id})")
    if meta:
        parts.append(f"adapter={meta.adapter} hook={meta.hook}")
        if meta.session_id:
            parts.append(f"session={meta.session_id}")
    if result.debug.intent:
        parts.append(f'intent="{result.debug.intent}"')

    trajectory = " → ".join(
        f"{step.tool}{_STATUS_ICON.get(step.status, '?')}"
        for step in result.debug.steps_summary
    )
    section = [" | ".join(parts)]
    if trajectory:
        section.append(f"Trajectory: {trajectory}")
    if result.debug.pending_step:
        pending = result.debug.pending_step
        section.append(f"Pending args: {pending.args}")
    return "\n".join(section)


def _format_layers_section(result: ScanResult) -> str:
    layers = result.layers
    debug = result.debug
    lines = [
        f"Layer exits: {', '.join(layers.exits)}",
        f"Plan tools: {', '.join(debug.plan_tools) or '(none)'}",
        f"L1 candidates ({len(debug.l1_candidate_ids)}): "
        + (", ".join(debug.l1_candidate_ids) or "(none)"),
    ]
    if debug.l1_skipped_rule_ids:
        lines.append(
            f"L1 skipped ({len(debug.l1_skipped_rule_ids)}): "
            + ", ".join(debug.l1_skipped_rule_ids)
        )
    lines.append(f"L2 evaluated: {layers.l2_evaluated}")
    return "\n".join(lines)


def _format_l2_traces(result: ScanResult) -> str:
    lines = ["L2 rule traces:"]
    for trace in result.debug.l2_traces:
        status = "HIT " if trace.hit else "miss"
        action = f" → {trace.effective_action}" if trace.hit else ""
        pass_label = trace.pass_id.value if trace.pass_id else "—"
        lines.append(
            f"  {trace.rule_id:<10} {status}{action:<8} "
            f"conf={trace.confidence:.2f} pass={pass_label:<14} {trace.reason}"
        )
    return "\n".join(lines)


def _format_matches_section(result: ScanResult) -> str:
    lines = ["Matched rules:"]
    for rule in result.matched_rules:
        lines.append(
            f"  {rule.id} ({rule.severity}) {rule.action} "
            f"conf={rule.confidence:.2f} pass={rule.pass_id.value} "
            f"steps={','.join(rule.matched_step_ids) or '—'}"
        )
        lines.append(f"    {rule.reason}")
    return "\n".join(lines)


def _format_debug_footer(result: ScanResult, *, verbose: bool) -> str:
    debug = result.debug
    timing = result.timing
    parts = [
        f"Rules: {debug.rules_loaded} loaded",
        f"v{debug.scanner_version}",
        f"{timing.total_ms}ms (L1 {timing.l1_ms}ms, L2 {timing.l2_ms}ms)",
    ]
    if debug.rules_source:
        parts.append(f"rules={debug.rules_source}")
    if debug.plan_source:
        parts.append(f"plan={debug.plan_source}")
    lines = [" | ".join(parts)]

    if verbose and debug.matcher_thresholds:
        thresholds = debug.matcher_thresholds
        lines.append(
            f"Thresholds: block/review @ {thresholds.definitive:.2f}, "
            f"review @ {thresholds.review:.2f}"
        )
        lines.append(f"L1 index keys: {', '.join(debug.l1_index_keys)}")
    return "\n".join(lines)
