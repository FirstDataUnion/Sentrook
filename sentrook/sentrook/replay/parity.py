"""Compare live scan log decisions against replay audit for parity."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook.config import ScannerConfig
from sentrook.replay.audit import SnapshotAudit, audit_openclaw_session
from sentrook.serve.log import load_scan_log

MatchKind = Literal["tool_call_id", "tool_command_hash", "unmatched"]


class ParityRow(BaseModel):
    scan_index: int | None = None
    replay_index: int | None = None
    match_kind: MatchKind
    tool_call_id: str | None = None
    pending_tool: str | None = None
    pending_command: str | None = None
    scan_decision: str | None = None
    replay_decision: str | None = None
    decision_match: bool = False
    scan_rules: list[str] = Field(default_factory=list)
    replay_rules: list[str] = Field(default_factory=list)
    rules_match: bool = False
    note: str | None = None


class ParityReport(BaseModel):
    scan_log_path: str
    session_path: str
    session_id: str | None = None
    scan_records: int = 0
    replay_snapshots: int = 0
    matched: int = 0
    decision_mismatches: int = 0
    rule_mismatches: int = 0
    unmatched_scan: int = 0
    unmatched_replay: int = 0
    rows: list[ParityRow] = Field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def _command_hash(tool: str | None, command: str | None) -> str:
    key = f"{tool or ''}|{command or ''}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _scan_rules(row: dict[str, Any]) -> list[str]:
    return [str(m.get("id")) for m in row.get("matched_rules") or [] if m.get("id")]


def _index_replay_by_tool_call_id(
    snapshots: list[SnapshotAudit],
) -> dict[str, SnapshotAudit]:
    out: dict[str, SnapshotAudit] = {}
    for snap in snapshots:
        if snap.tool_call_id:
            out[snap.tool_call_id] = snap
    return out


def _index_replay_by_hash(snapshots: list[SnapshotAudit]) -> dict[str, SnapshotAudit]:
    out: dict[str, SnapshotAudit] = {}
    for snap in snapshots:
        key = _command_hash(snap.pending_tool, snap.pending_command)
        out.setdefault(key, snap)
    return out


def compare_scan_to_replay(
    scan_log_path: Path,
    session_path: Path,
    rules_path: Path,
    config: ScannerConfig,
    *,
    session_id: str | None = None,
) -> ParityReport:
    """Match scan log rows to replay snapshots and flag decision drift."""
    scan_rows = load_scan_log(scan_log_path)
    if session_id:
        scan_rows = [r for r in scan_rows if r.get("session_id") == session_id]

    replay_report = audit_openclaw_session(session_path, rules_path, config)
    by_id = _index_replay_by_tool_call_id(replay_report.snapshots)
    by_hash = _index_replay_by_hash(replay_report.snapshots)

    used_replay: set[int] = set()
    rows: list[ParityRow] = []
    matched = 0
    decision_mismatches = 0
    rule_mismatches = 0
    unmatched_scan = 0

    for scan_index, row in enumerate(scan_rows, start=1):
        tool_call_id = row.get("tool_call_id")
        replay_snap: SnapshotAudit | None = None
        match_kind: MatchKind = "unmatched"

        if tool_call_id and tool_call_id in by_id:
            replay_snap = by_id[str(tool_call_id)]
            match_kind = "tool_call_id"
        else:
            key = _command_hash(row.get("pending_tool"), row.get("pending_command_excerpt"))
            replay_snap = by_hash.get(key)
            if replay_snap is not None:
                match_kind = "tool_command_hash"

        if replay_snap is None:
            unmatched_scan += 1
            rows.append(
                ParityRow(
                    scan_index=scan_index,
                    match_kind="unmatched",
                    tool_call_id=tool_call_id,
                    pending_tool=row.get("pending_tool"),
                    pending_command=row.get("pending_command_excerpt"),
                    scan_decision=row.get("decision"),
                    scan_rules=_scan_rules(row),
                    note="no replay snapshot matched",
                )
            )
            continue

        used_replay.add(replay_snap.index)
        matched += 1
        scan_decision = str(row.get("decision", "allow"))
        scan_rule_ids = _scan_rules(row)
        replay_rule_ids = replay_snap.matched_rule_ids
        decision_match = scan_decision == replay_snap.decision
        rules_match = scan_rule_ids == replay_rule_ids

        if not decision_match:
            decision_mismatches += 1
        if not rules_match:
            rule_mismatches += 1

        note = None
        if not decision_match:
            note = f"scan={scan_decision} replay={replay_snap.decision}"

        rows.append(
            ParityRow(
                scan_index=scan_index,
                replay_index=replay_snap.index,
                match_kind=match_kind,
                tool_call_id=tool_call_id or replay_snap.tool_call_id,
                pending_tool=row.get("pending_tool"),
                pending_command=row.get("pending_command_excerpt") or replay_snap.pending_command,
                scan_decision=scan_decision,
                replay_decision=replay_snap.decision,
                decision_match=decision_match,
                scan_rules=scan_rule_ids,
                replay_rules=replay_rule_ids,
                rules_match=rules_match,
                note=note,
            )
        )

    unmatched_replay = sum(1 for snap in replay_report.snapshots if snap.index not in used_replay)

    return ParityReport(
        scan_log_path=str(scan_log_path.expanduser().resolve()),
        session_path=str(session_path.expanduser().resolve()),
        session_id=session_id or replay_report.session_id,
        scan_records=len(scan_rows),
        replay_snapshots=replay_report.total_snapshots,
        matched=matched,
        decision_mismatches=decision_mismatches,
        rule_mismatches=rule_mismatches,
        unmatched_scan=unmatched_scan,
        unmatched_replay=unmatched_replay,
        rows=rows,
    )


def format_parity_text(report: ParityReport) -> str:
    lines = [
        "=== Sentrook Scan / Replay Parity ===",
        f"Scan log: {report.scan_log_path}",
        f"Session: {report.session_path}",
        f"Session id: {report.session_id or '(unknown)'}",
        f"Scan records: {report.scan_records}",
        f"Replay snapshots: {report.replay_snapshots}",
        f"Matched: {report.matched}",
        f"Decision mismatches: {report.decision_mismatches}",
        f"Rule mismatches: {report.rule_mismatches}",
        f"Unmatched scan: {report.unmatched_scan}",
        f"Unmatched replay: {report.unmatched_replay}",
        "",
        "Mismatches:",
    ]

    mismatches = [r for r in report.rows if not r.decision_match or not r.rules_match]
    if not mismatches:
        lines.append("  (none)")
    else:
        for row in mismatches[:30]:
            rules_bit = ""
            if not row.rules_match:
                rules_bit = f" rules scan={row.scan_rules} replay={row.replay_rules}"
            lines.append(
                f"  scan#{row.scan_index} replay#{row.replay_index} "
                f"{row.pending_tool} — {row.note or 'rules differ'}{rules_bit}"
            )

    return "\n".join(lines)
