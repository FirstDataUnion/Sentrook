"""Canonical OpenClaw replay sessions and baseline comparison for tuning."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sentrook import __version__
from sentrook.config import ScannerConfig
from sentrook.layers.l3_score import BiEncoderScorer
from sentrook.replay.audit import SessionAuditReport, audit_openclaw_session

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_BASELINE_PATH = _REPO_ROOT / "replay" / "baselines" / "v0.2.0.json"


@dataclass(frozen=True)
class CanonicalReplaySession:
    """A pinned OpenClaw session used for regression-style replay scans."""

    label: str
    session_id: str
    relative_path: str
    description: str = ""


CANONICAL_REPLAY_SESSIONS: tuple[CanonicalReplaySession, ...] = (
    CanonicalReplaySession(
        label="memory-token-optimization",
        session_id="52d3c8dc-0141-46bc-82bd-ad26a52a2db2",
        relative_path=(
            "openclaw_example/agents/main/sessions/"
            "52d3c8dc-0141-46bc-82bd-ad26a52a2db2.jsonl"
        ),
        description="Long memory/token session — exec-heavy, early doc fetch",
    ),
    CanonicalReplaySession(
        label="wiki-notion-work",
        session_id="3bad67cf-3323-4569-846c-dfbde83daf15",
        relative_path=(
            "openclaw_example/agents/main/sessions/"
            "3bad67cf-3323-4569-846c-dfbde83daf15.jsonl"
        ),
        description="Wiki/Notion session — exec-heavy, little web_fetch",
    ),
)


class ReplayBaselineReport(BaseModel):
    """Aggregate metrics across the canonical replay set."""

    version: str = "0.1.1"
    sentrook_version: str = Field(default_factory=lambda: __version__)
    recorded_at: str = Field(default_factory=lambda: date.today().isoformat())
    scanner: dict[str, Any] = Field(default_factory=dict)
    sessions: dict[str, dict[str, Any]] = Field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def default_baseline_path() -> Path:
    return _DEFAULT_BASELINE_PATH


def resolve_session_path(relative_path: str, *, repo_root: Path | None = None) -> Path:
    root = repo_root or _REPO_ROOT
    return (root / relative_path).resolve()


def session_report_to_baseline_entry(
    canonical: CanonicalReplaySession, report: SessionAuditReport
) -> dict[str, Any]:
    """Shrink a session audit report to baseline-comparable fields."""
    return {
        "label": canonical.label,
        "description": canonical.description,
        "session_id": report.session_id,
        "session_path": report.session_path,
        "total_snapshots": report.total_snapshots,
        "decision_counts": report.decision_counts,
        "rule_hit_counts": report.rule_hit_counts,
        "first_block_index": report.first_block_index,
        "exec_summary": report.exec_summary.model_dump(mode="json"),
    }


def _relativize_scanner_paths(scanner: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    out = dict(scanner)
    for key in ("corpus_dir", "rules_dir"):
        value = out.get(key)
        if not value:
            continue
        path = Path(str(value))
        try:
            out[key] = str(path.resolve().relative_to(repo_root.resolve()))
        except ValueError:
            out[key] = str(path)
    return out


def run_replay_baseline(
    rules_path: Path,
    config: ScannerConfig,
    *,
    repo_root: Path | None = None,
    l3_scorer: BiEncoderScorer | None = None,
    sessions: tuple[CanonicalReplaySession, ...] = CANONICAL_REPLAY_SESSIONS,
    max_snapshots: int | None = None,
) -> ReplayBaselineReport:
    """Shadow-scan all canonical replay sessions and build a baseline report."""
    from sentrook.rules.loader import load_rules

    root = repo_root or _REPO_ROOT
    rules_path = rules_path.expanduser().resolve()
    rules_loaded = len(load_rules(rules_path))
    scanner_summary: dict[str, Any] = {}
    session_entries: dict[str, dict[str, Any]] = {}

    for canonical in sessions:
        session_path = resolve_session_path(canonical.relative_path, repo_root=root)
        report = audit_openclaw_session(
            session_path,
            rules_path,
            config,
            l3_scorer=l3_scorer,
            max_snapshots=max_snapshots,
        )
        if not scanner_summary:
            scanner_summary = _relativize_scanner_paths(
                dict(report.scanner), root
            )
            scanner_summary["rules_loaded"] = rules_loaded
        session_entries[canonical.label] = session_report_to_baseline_entry(
            canonical, report
        )

    return ReplayBaselineReport(
        scanner=scanner_summary,
        sessions=session_entries,
    )


def load_baseline_file(path: Path) -> ReplayBaselineReport:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return ReplayBaselineReport.model_validate(payload)


def write_baseline_file(report: ReplayBaselineReport, path: Path) -> Path:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_json_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _comparable_sessions(report: ReplayBaselineReport) -> dict[str, Any]:
    return {
        label: {
            "total_snapshots": entry["total_snapshots"],
            "decision_counts": entry["decision_counts"],
            "rule_hit_counts": entry["rule_hit_counts"],
            "first_block_index": entry.get("first_block_index"),
            "exec_summary": entry["exec_summary"],
        }
        for label, entry in report.sessions.items()
    }


def compare_baselines(
    current: ReplayBaselineReport, expected: ReplayBaselineReport
) -> list[str]:
    """Return human-readable drift messages; empty when metrics match."""
    drifts: list[str] = []

    if current.scanner.get("allow_margin") != expected.scanner.get("allow_margin"):
        drifts.append(
            "scanner.allow_margin: "
            f"{expected.scanner.get('allow_margin')} → {current.scanner.get('allow_margin')}"
        )

    current_sessions = _comparable_sessions(current)
    expected_sessions = _comparable_sessions(expected)

    for label in sorted(set(current_sessions) | set(expected_sessions)):
        if label not in expected_sessions:
            drifts.append(f"{label}: new session (not in baseline)")
            continue
        if label not in current_sessions:
            drifts.append(f"{label}: missing session (was in baseline)")
            continue

        cur = current_sessions[label]
        exp = expected_sessions[label]

        for key in ("total_snapshots", "decision_counts", "rule_hit_counts", "first_block_index"):
            if cur.get(key) != exp.get(key):
                drifts.append(f"{label}.{key}: {exp.get(key)!r} → {cur.get(key)!r}")

        cur_exec = cur.get("exec_summary") or {}
        exp_exec = exp.get("exec_summary") or {}
        for key in ("total", "allow", "review", "block", "l3_allow"):
            if cur_exec.get(key) != exp_exec.get(key):
                drifts.append(
                    f"{label}.exec.{key}: {exp_exec.get(key)!r} → {cur_exec.get(key)!r}"
                )

        cur_top = cur_exec.get("top_review_commands") or []
        exp_top = exp_exec.get("top_review_commands") or []
        if cur_top != exp_top:
            drifts.append(
                f"{label}.exec.top_review_commands: "
                f"{len(exp_top)} entries → {len(cur_top)} entries (content differs)"
            )

    return drifts


def format_baseline_text(
    report: ReplayBaselineReport,
    *,
    compare_to: ReplayBaselineReport | None = None,
) -> str:
    lines: list[str] = [
        "=== Sentrook Replay Baseline (shadow) ===",
        f"Version: {report.version} · Sentrook {report.sentrook_version} · {report.recorded_at}",
        "",
    ]

    scanner = report.scanner
    lines.append(
        "Scanner: "
        f"l3_policy={scanner.get('l3_policy')} "
        f"allow_margin={scanner.get('allow_margin')} "
        f"rules_loaded={scanner.get('rules_loaded')}"
    )
    lines.append("")

    for label, entry in report.sessions.items():
        lines.append(f"## {label}")
        if entry.get("description"):
            lines.append(f"   {entry['description']}")
        lines.append(f"   session: {entry.get('session_id', '?')}")
        lines.append(f"   snapshots: {entry.get('total_snapshots', 0)}")

        decisions = entry.get("decision_counts") or {}
        parts = [
            f"{k}={decisions[k]}"
            for k in ("allow", "review", "block")
            if decisions.get(k)
        ]
        lines.append(f"   decisions: {', '.join(parts) or '(none)'}")

        rules = entry.get("rule_hit_counts") or {}
        if rules:
            rule_bits = ", ".join(f"{rid}:{n}" for rid, n in rules.items())
            lines.append(f"   rule hits: {rule_bits}")

        exec_sum = entry.get("exec_summary") or {}
        if exec_sum.get("total"):
            lines.append(
                "   exec: "
                f"allow {exec_sum.get('allow', 0)}/{exec_sum.get('total', 0)} "
                f"review {exec_sum.get('review', 0)} "
                f"block {exec_sum.get('block', 0)} "
                f"(l3_allow {exec_sum.get('l3_allow', 0)})"
            )
            top = exec_sum.get("top_review_commands") or []
            if top:
                lines.append("   top review commands:")
                for item in top[:8]:
                    cmd = str(item.get("command", ""))
                    if len(cmd) > 72:
                        cmd = cmd[:69] + "..."
                    indices = item.get("snapshot_indices") or []
                    idx_hint = f" #{indices[0]:03d}" if indices else ""
                    lines.append(
                        f"     ×{item.get('count', 1)}{idx_hint} {cmd}"
                    )
        lines.append("")

    if compare_to is not None:
        drifts = compare_baselines(report, compare_to)
        lines.append("=== Baseline comparison ===")
        if not drifts:
            lines.append("  OK — metrics match pinned baseline")
        else:
            lines.append(f"  DRIFT ({len(drifts)} difference(s)):")
            for msg in drifts:
                lines.append(f"    - {msg}")

    return "\n".join(lines).rstrip() + "\n"
