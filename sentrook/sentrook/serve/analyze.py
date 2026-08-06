"""Aggregate analysis of observe-mode scan JSONL logs."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sentrook.replay.audit import ExecSummary, SnapshotAudit, build_exec_summary
from sentrook.serve.log import load_scan_log
from sentrook.serve.stats import percentile


class ScanLatencySummary(BaseModel):
    samples: int = 0
    p50_ms: int | None = None
    p95_ms: int | None = None
    min_ms: int | None = None
    max_ms: int | None = None


class SessionScanSummary(BaseModel):
    session_id: str
    total: int = 0
    decision_counts: dict[str, int] = Field(default_factory=dict)
    rule_hit_counts: dict[str, int] = Field(default_factory=dict)
    exec_summary: ExecSummary = Field(default_factory=ExecSummary)
    harvest_candidates: list[dict[str, Any]] = Field(default_factory=list)


class ScanAnalyzeReport(BaseModel):
    log_path: str
    schema_versions: dict[str, int] = Field(default_factory=dict)
    total_records: int = 0
    decision_counts: dict[str, int] = Field(default_factory=dict)
    rule_hit_counts: dict[str, int] = Field(default_factory=dict)
    bundle_versions: dict[str, int] = Field(default_factory=dict)
    sessions: list[SessionScanSummary] = Field(default_factory=list)
    exec_summary: ExecSummary = Field(default_factory=ExecSummary)
    scan_latency: ScanLatencySummary = Field(default_factory=ScanLatencySummary)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def _row_to_exec_audit(index: int, row: dict[str, Any]) -> SnapshotAudit:
    matched = [str(m.get("id")) for m in row.get("matched_rules") or [] if m.get("id")]
    return SnapshotAudit(
        index=index,
        tool_call_id=row.get("tool_call_id"),
        step_seq=row.get("step_seq"),
        batch_size=row.get("batch_size"),
        pending_tool=row.get("pending_tool"),
        pending_step_id=row.get("pending_step_id"),
        pending_command=row.get("pending_command_excerpt"),
        decision=row.get("decision", "allow"),
        risk=float(row.get("risk", 0.0)),
        summary=str(row.get("summary", "")),
        matched_rule_ids=matched,
        layer_exits=list(row.get("layer_exits") or []),
        l3_allow_rules=list(row.get("l3_allow_rules") or []),
        l3_kept_review_rules=list(row.get("l3_kept_review_rules") or []),
    )


def analyze_scan_log(path: Path) -> ScanAnalyzeReport:
    """Summarise a scan JSONL file for operator triage."""
    records = load_scan_log(path)
    decision_counts: Counter[str] = Counter()
    rule_hit_counts: Counter[str] = Counter()
    schema_versions: Counter[str] = Counter()
    bundle_versions: Counter[str] = Counter()

    by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exec_audits: list[SnapshotAudit] = []

    for index, row in enumerate(records, start=1):
        decision = str(row.get("decision", "allow"))
        decision_counts[decision] += 1
        schema_versions[str(row.get("schema_version", "unknown"))] += 1
        bundle = row.get("bundle_version")
        if bundle:
            bundle_versions[str(bundle)] += 1

        matched = [str(m.get("id")) for m in row.get("matched_rules") or [] if m.get("id")]
        for rule_id in matched:
            rule_hit_counts[rule_id] += 1

        session_id = row.get("session_id") or "(unknown)"
        by_session[str(session_id)].append(row)

        if row.get("pending_tool") == "exec":
            exec_audits.append(_row_to_exec_audit(index, row))

    sessions: list[SessionScanSummary] = []
    for session_id, rows in sorted(by_session.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        sess_decisions: Counter[str] = Counter()
        sess_rules: Counter[str] = Counter()
        sess_exec: list[SnapshotAudit] = []
        harvest: list[dict[str, Any]] = []

        for index, row in enumerate(rows, start=1):
            decision = str(row.get("decision", "allow"))
            sess_decisions[decision] += 1
            matched = [str(m.get("id")) for m in row.get("matched_rules") or [] if m.get("id")]
            for rule_id in matched:
                sess_rules[rule_id] += 1

            if row.get("pending_tool"):
                audit = _row_to_exec_audit(index, row)
                if row.get("pending_tool") == "exec":
                    sess_exec.append(audit)
                if decision == "review" and matched:
                    harvest.append(
                        {
                            "snapshot_index": index,
                            "tool_call_id": row.get("tool_call_id"),
                            "pending_tool": row.get("pending_tool"),
                            "command_excerpt": row.get("pending_command_excerpt"),
                            "summary": row.get("summary"),
                            "matched_rules": matched,
                        }
                    )

        sessions.append(
            SessionScanSummary(
                session_id=session_id,
                total=len(rows),
                decision_counts=dict(sorted(sess_decisions.items())),
                rule_hit_counts=dict(sorted(sess_rules.items())),
                exec_summary=build_exec_summary(sess_exec),
                harvest_candidates=harvest,
            )
        )

    return ScanAnalyzeReport(
        log_path=str(path.expanduser().resolve()),
        schema_versions=dict(schema_versions),
        total_records=len(records),
        decision_counts=dict(sorted(decision_counts.items())),
        rule_hit_counts=dict(sorted(rule_hit_counts.items())),
        bundle_versions=dict(bundle_versions),
        sessions=sessions,
        exec_summary=build_exec_summary(exec_audits),
        scan_latency=_latency_summary(records),
    )


def _latency_summary(records: list[dict[str, Any]]) -> ScanLatencySummary:
    values = [int(row["total_ms"]) for row in records if isinstance(row.get("total_ms"), int)]
    if not values:
        return ScanLatencySummary()
    return ScanLatencySummary(
        samples=len(values),
        p50_ms=percentile(values, 50),
        p95_ms=percentile(values, 95),
        min_ms=min(values),
        max_ms=max(values),
    )


def format_scan_analyze_text(report: ScanAnalyzeReport) -> str:
    lines = [
        "=== Sentrook Scan Log Analysis ===",
        f"Log: {report.log_path}",
        f"Records: {report.total_records}",
        "",
        "Decisions:",
    ]
    for decision in ("allow", "review", "block"):
        count = report.decision_counts.get(decision, 0)
        if count:
            lines.append(f"  {decision}: {count}")

    if report.rule_hit_counts:
        lines.append("")
        lines.append("Rule hits:")
        for rule_id, count in report.rule_hit_counts.items():
            lines.append(f"  {rule_id}: {count}")

    exec_sum = report.exec_summary
    if exec_sum.total:
        lines.append("")
        lines.append("Exec summary (all sessions):")
        lines.append(
            f"  allow {exec_sum.allow}/{exec_sum.total} · "
            f"review {exec_sum.review} · block {exec_sum.block} · "
            f"l3_allow {exec_sum.l3_allow}"
        )

    if report.sessions:
        lines.append("")
        lines.append("Per session:")
        for sess in report.sessions[:12]:
            lines.append(
                f"  {sess.session_id}: {sess.total} scans "
                f"({sess.decision_counts.get('review', 0)} review)"
            )
            if sess.harvest_candidates:
                lines.append(f"    harvest candidates: {len(sess.harvest_candidates)}")

    if report.schema_versions:
        lines.append("")
        lines.append(f"Schema versions: {report.schema_versions}")
    if report.bundle_versions:
        lines.append(f"Bundle versions: {report.bundle_versions}")

    latency = report.scan_latency
    if latency.samples:
        lines.append("")
        lines.append("Scan latency (ms):")
        lines.append(
            f"  p50 {latency.p50_ms} · p95 {latency.p95_ms} · "
            f"min {latency.min_ms} · max {latency.max_ms} · n={latency.samples}"
        )

    return "\n".join(lines)
