"""Batch scan of replayed OpenClaw session snapshots."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook.adapters.snapshot import primary_pending_step
from sentrook.config import L3Policy, ScannerConfig
from sentrook.corpus.loader import load_corpus, resolve_corpus_dir
from sentrook.layers.l3_score import BiEncoderScorer
from sentrook.planir import PlanIR
from sentrook.replay.openclaw import replay_session
from sentrook.result import ScanResult
from sentrook.rules.loader import load_rules
from sentrook.scan import scan_plan

Decision = Literal["allow", "review", "block"]


class SnapshotAudit(BaseModel):
    """One ``before_tool_call`` moment in a replayed session."""

    index: int
    tool_call_id: str | None = None
    step_seq: int | None = None
    batch_size: int | None = None
    pending_tool: str | None = None
    pending_step_id: str | None = None
    pending_command: str | None = None
    decision: Decision
    risk: float
    summary: str
    matched_rule_ids: list[str] = Field(default_factory=list)
    layer_exits: list[str] = Field(default_factory=list)
    l3_allow_rules: list[str] = Field(default_factory=list)
    l3_kept_review_rules: list[str] = Field(default_factory=list)
    trajectory: str = ""
    steps_since_fetch: int | None = None
    fetch_exec_tier: Literal["hard", "soft"] | None = None


class ReviewCommandSummary(BaseModel):
    """Grouped pending exec commands that stayed at review or block."""

    command: str
    count: int
    snapshot_indices: list[int] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)


class ExecSummary(BaseModel):
    """Exec-only decision breakdown for a replayed session."""

    total: int = 0
    allow: int = 0
    review: int = 0
    block: int = 0
    l3_allow: int = 0
    top_review_commands: list[ReviewCommandSummary] = Field(default_factory=list)


class SessionAuditReport(BaseModel):
    """Aggregate scan results for an OpenClaw session replay."""

    mode: Literal["observe"] = "observe"
    session_path: str
    session_id: str | None = None
    agent_id: str | None = None
    run_id: str | None = None
    intent: str | None = None
    total_snapshots: int = 0
    decision_counts: dict[str, int] = Field(default_factory=dict)
    rule_hit_counts: dict[str, int] = Field(default_factory=dict)
    first_block_index: int | None = None
    snapshots: list[SnapshotAudit] = Field(default_factory=list)
    notable: list[SnapshotAudit] = Field(default_factory=list)
    exec_summary: ExecSummary = Field(default_factory=ExecSummary)
    scanner: dict[str, Any] = Field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def audit_openclaw_session(
    session_path: Path,
    rules_path: Path,
    config: ScannerConfig,
    *,
    trajectory_path: Path | None = None,
    agent_id: str = "main",
    max_snapshots: int | None = None,
    l3_scorer: BiEncoderScorer | None = None,
) -> SessionAuditReport:
    """Replay an OpenClaw session and scan every ``before_tool_call`` snapshot."""
    session_path = session_path.expanduser().resolve()
    rules_path = rules_path.expanduser().resolve()
    rules = load_rules(rules_path)
    corpus_dir = Path(resolve_corpus_dir(config.l3.corpus_dir))
    corpus = load_corpus(corpus_dir) if config.l3_policy != L3Policy.OFF else {}

    snapshots = replay_session(
        session_path,
        trajectory_path=trajectory_path,
        agent_id=agent_id,
        max_snapshots=max_snapshots,
    )

    audits: list[SnapshotAudit] = []
    decision_counts: Counter[str] = Counter()
    rule_hit_counts: Counter[str] = Counter()
    first_block_index: int | None = None
    session_id: str | None = None
    run_id: str | None = None
    intent: str | None = None

    for index, plan in enumerate(snapshots, start=1):
        if index == 1:
            session_id = plan.metadata.session_id
            run_id = plan.run_id
            intent = plan.intent

        result = scan_plan(
            plan,
            rules,
            config,
            plan_source=f"{session_path}:snapshot_{index:03d}",
            rules_source=str(rules_path),
            corpus=corpus,
            l3_scorer=l3_scorer,
        )
        audit = _snapshot_from_result(index, plan, result)
        audits.append(audit)
        decision_counts[audit.decision] += 1
        for rule_id in audit.matched_rule_ids:
            rule_hit_counts[rule_id] += 1
        if audit.decision == "block" and first_block_index is None:
            first_block_index = index

    notable = [a for a in audits if _is_notable(a)]
    exec_summary = build_exec_summary(audits)

    return SessionAuditReport(
        session_path=str(session_path),
        session_id=session_id or _session_id_from_path(session_path),
        agent_id=agent_id,
        run_id=run_id,
        intent=intent,
        total_snapshots=len(audits),
        decision_counts=dict(sorted(decision_counts.items())),
        rule_hit_counts=dict(sorted(rule_hit_counts.items())),
        first_block_index=first_block_index,
        snapshots=audits,
        notable=notable,
        exec_summary=exec_summary,
        scanner=_scanner_summary(config, corpus_dir, rules_path, rules_loaded=len(rules)),
    )


def _session_id_from_path(session_path: Path) -> str | None:
    stem = session_path.stem.split(".")[0]
    return stem if stem else None


def _snapshot_from_result(
    index: int, plan: PlanIR, result: ScanResult
) -> SnapshotAudit:
    l3_allow: list[str] = []
    l3_kept: list[str] = []
    for trace in result.debug.l3_traces:
        if not trace.ran:
            continue
        if trace.decision == "allow":
            l3_allow.append(trace.rule_id)
        elif trace.decision == "no_change" and trace.rule_id in {
            m.id for m in result.matched_rules if m.action == "review"
        }:
            l3_kept.append(trace.rule_id)

    trajectory = " → ".join(
        f"{step.tool}{'✓' if step.status == 'executed' else '⏳'}"
        for step in result.debug.steps_summary
    )
    matched_ids = [m.id for m in result.matched_rules]
    steps_since_fetch, fetch_exec_tier = _fetch_exec_context(plan, matched_ids)

    pending = primary_pending_step(plan)
    pending_command: str | None = None
    if pending and pending.args.get("command") is not None:
        pending_command = str(pending.args["command"])

    return SnapshotAudit(
        index=index,
        tool_call_id=plan.metadata.tool_call_id,
        step_seq=plan.metadata.step_seq,
        batch_size=plan.metadata.batch_size,
        pending_tool=result.plan.pending_tool,
        pending_step_id=result.plan.pending_step_id,
        pending_command=pending_command,
        decision=result.decision,
        risk=result.risk,
        summary=result.summary,
        matched_rule_ids=matched_ids,
        layer_exits=list(result.layers.exits),
        l3_allow_rules=l3_allow,
        l3_kept_review_rules=l3_kept,
        trajectory=trajectory,
        steps_since_fetch=steps_since_fetch,
        fetch_exec_tier=fetch_exec_tier,
    )


def _fetch_exec_context(
    plan: PlanIR, matched_rule_ids: list[str]
) -> tuple[int | None, Literal["hard", "soft"] | None]:
    """Steps between the latest executed web_fetch and a pending exec, if applicable."""
    fetch_indices = [
        i
        for i, step in enumerate(plan.steps)
        if step.tool == "web_fetch" and step.status == "executed"
    ]
    primary = primary_pending_step(plan)
    pending_exec_idx: int | None = None
    if primary and primary.tool == "exec":
        pending_exec_idx = next(
            i for i, step in enumerate(plan.steps) if step.id == primary.id
        )
    steps_since: int | None = None
    if fetch_indices and pending_exec_idx is not None:
        last_fetch = fetch_indices[-1]
        if last_fetch < pending_exec_idx:
            steps_since = pending_exec_idx - last_fetch - 1

    tier: Literal["hard", "soft"] | None = None
    if "AIRA-001" in matched_rule_ids:
        tier = "hard"
    elif "AIRA-058" in matched_rule_ids:
        tier = "soft"
    return steps_since, tier


def _is_notable(audit: SnapshotAudit) -> bool:
    if audit.decision != "allow":
        return True
    if audit.l3_allow_rules:
        return True
    if audit.l3_kept_review_rules:
        return True
    return False


def build_exec_summary(
    audits: list[SnapshotAudit], *, top_n: int = 10
) -> ExecSummary:
    """Summarise pending exec snapshots for baseline and tuning reports."""
    exec_snaps = [a for a in audits if a.pending_tool == "exec"]
    if not exec_snaps:
        return ExecSummary()

    by_decision: Counter[str] = Counter(a.decision for a in exec_snaps)
    l3_allow = sum(1 for a in exec_snaps if a.l3_allow_rules)

    review_groups: dict[str, list[SnapshotAudit]] = {}
    for snap in exec_snaps:
        if snap.decision not in ("review", "block"):
            continue
        key = snap.pending_command or "(no command)"
        review_groups.setdefault(key, []).append(snap)

    top_review: list[ReviewCommandSummary] = []
    ranked = sorted(review_groups.items(), key=lambda pair: (-len(pair[1]), pair[0]))
    for command, snaps in ranked[:top_n]:
        rules: set[str] = set()
        for snap in snaps:
            rules.update(snap.matched_rule_ids)
        top_review.append(
            ReviewCommandSummary(
                command=command,
                count=len(snaps),
                snapshot_indices=sorted(s.index for s in snaps),
                matched_rules=sorted(rules),
            )
        )

    return ExecSummary(
        total=len(exec_snaps),
        allow=by_decision.get("allow", 0),
        review=by_decision.get("review", 0),
        block=by_decision.get("block", 0),
        l3_allow=l3_allow,
        top_review_commands=top_review,
    )


def _scanner_summary(
    config: ScannerConfig,
    corpus_dir: Path,
    rules_path: Path,
    *,
    rules_loaded: int,
) -> dict[str, Any]:
    return {
        "l3_policy": config.l3_policy.value,
        "corpus_dir": str(corpus_dir),
        "rules_dir": str(rules_path),
        "rules_loaded": rules_loaded,
        "allow_margin": config.l3.allow_margin,
        "fail_closed_margin": config.l3.fail_closed_margin,
        "top_k": config.l3.top_k,
    }


def format_session_audit_text(report: SessionAuditReport) -> str:
    """Operator-readable session audit summary."""
    lines: list[str] = [
        "=== Sentrook Session Audit (observe) ===",
        f"Session: {report.session_id or '(unknown)'}",
        f"Path: {report.session_path}",
        f"Snapshots scanned: {report.total_snapshots}",
        "",
        "Decisions:",
    ]

    for decision in ("allow", "review", "block"):
        count = report.decision_counts.get(decision, 0)
        if count:
            lines.append(f"  {decision}: {count}")

    if report.rule_hit_counts:
        lines.append("")
        lines.append("Rule hits (matched at least once):")
        for rule_id, count in report.rule_hit_counts.items():
            lines.append(f"  {rule_id}: {count}")

    if report.first_block_index is not None:
        block = report.snapshots[report.first_block_index - 1]
        lines.append("")
        lines.append(
            f"First block: #{report.first_block_index:03d} "
            f"pending {block.pending_tool} — {block.summary}"
        )

    exec_sum = report.exec_summary
    if exec_sum.total:
        lines.append("")
        lines.append("Exec summary:")
        lines.append(
            f"  allow {exec_sum.allow}/{exec_sum.total} · "
            f"review {exec_sum.review} · block {exec_sum.block} · "
            f"l3_allow {exec_sum.l3_allow}"
        )
        if exec_sum.top_review_commands:
            lines.append("  top review commands:")
            for item in exec_sum.top_review_commands[:8]:
                cmd = item.command
                if len(cmd) > 72:
                    cmd = cmd[:69] + "..."
                idx = item.snapshot_indices[0] if item.snapshot_indices else 0
                lines.append(f"    ×{item.count} #{idx:03d} {cmd}")

    lines.append("")
    lines.append(f"Notable moments ({len(report.notable)}):")
    if not report.notable:
        lines.append("  (none — all allow with no L3 activity)")
    else:
        for snap in report.notable:
            lines.extend(_format_notable_line(snap))

    scanner = report.scanner
    lines.append("")
    lines.append(
        "Scanner: "
        f"l3_policy={scanner.get('l3_policy')} "
        f"corpus={scanner.get('corpus_dir')} "
        f"rules={scanner.get('rules_dir')}"
    )
    return "\n".join(lines)


def _format_notable_line(snap: SnapshotAudit) -> list[str]:
    rules = ", ".join(snap.matched_rule_ids) or "(none)"
    l3_bits: list[str] = []
    if snap.l3_allow_rules:
        l3_bits.append(f"L3 allow: {', '.join(snap.l3_allow_rules)}")
    if snap.l3_kept_review_rules:
        l3_bits.append(f"L3 kept review: {', '.join(snap.l3_kept_review_rules)}")
    l3_suffix = f" | {'; '.join(l3_bits)}" if l3_bits else ""
    pending = snap.pending_tool or "?"
    fetch_bits: list[str] = []
    if snap.steps_since_fetch is not None:
        fetch_bits.append(f"steps_since_fetch={snap.steps_since_fetch}")
    if snap.fetch_exec_tier is not None:
        fetch_bits.append(f"tier={snap.fetch_exec_tier}")
    fetch_suffix = f" | {'; '.join(fetch_bits)}" if fetch_bits else ""
    return [
        f"  #{snap.index:03d} {snap.decision} pending {pending} — {rules}{l3_suffix}{fetch_suffix}",
        f"         {snap.summary}",
    ]
