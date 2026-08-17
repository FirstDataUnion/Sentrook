"""Harvest scan log records into Rookery corpus submission payloads."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sentrook import __version__
from sentrook.corpus.models import CorpusExample, CorpusLabel, CorpusStep
from sentrook.redact import redact_args
from sentrook.sanitize.corpus import policy_reject, sanitize_corpus_example
from sentrook.serve.feedback import (
    FeedbackResolution,
    build_submission_body,
    pick_feedback_rule_ids,
    pick_rule_id,
    submit_to_rookery,
)
from sentrook.serve.log import load_scan_log


def _resolution_for_harvest_label(label: CorpusLabel | None) -> FeedbackResolution:
    """Mirror live feedback: benign→fatigue multi-kept; attack→winner only."""
    if label == "benign":
        return "allow-once"
    return "deny"


def log_row_to_corpus_example(
    row: dict[str, Any],
    *,
    rule_id: str,
    label: CorpusLabel | None = None,
    example_id_suffix: str = "scan-harvest",
) -> CorpusExample | None:
    pending_tool = row.get("pending_tool")
    if not pending_tool:
        return None

    session_id = str(row.get("session_id") or "unknown")
    tool_call_id = str(row.get("tool_call_id") or row.get("pending_step_id") or "call")
    example_id = f"harvest-{rule_id.lower()}-{session_id[:8]}-{tool_call_id.replace(':', '-')}-{example_id_suffix}"

    steps = [
        CorpusStep(
            tool=str(pending_tool),
            status="pending",
            args=redact_args(dict(row.get("pending_args") or {})),
        )
    ]

    if label is None:
        return None

    example = CorpusExample(
        id=example_id,
        label=label,
        trust="community",
        intent=row.get("intent"),
        intent_kind=row.get("intent_kind"),
        notes=str(row.get("summary") or "scan log harvest candidate"),
        steps=steps,
    )
    result = sanitize_corpus_example(example)
    if policy_reject(result.report):
        return None
    return result.example


def harvest_candidates_from_log(
    path: Path,
    *,
    decision: str = "review",
    label: CorpusLabel | None = None,
) -> list[dict[str, Any]]:
    """Return submission-ready dicts for review (or other) decisions in a scan log."""
    records = load_scan_log(path)
    candidates: list[dict[str, Any]] = []

    for index, row in enumerate(records, start=1):
        if str(row.get("decision", "allow")) != decision:
            continue
        rule_ids = pick_feedback_rule_ids(
            None,
            row,
            resolution=_resolution_for_harvest_label(label),
        )
        if not rule_ids:
            continue

        primary = rule_ids[0]
        for rule_id in rule_ids:
            example = log_row_to_corpus_example(
                {**row, "pending_args": _pending_args_from_row(row)},
                rule_id=rule_id,
                label=label,
            )
            if example is None:
                continue
            provenance = {
                "scanner_version": row.get("scanner_version") or __version__,
                "bundle_version": row.get("bundle_version"),
                "source": "scan_log_harvest",
                "session_id": row.get("session_id"),
                "run_id": row.get("run_id"),
                "snapshot_index": index,
                "decision": row.get("decision"),
                "winning_rule_id": row.get("winning_rule_id") or primary,
                "primary_rule_id": primary,
                "co_fired_rules": rule_ids,
                "attribution": (
                    "fatigue_all_kept" if label == "benign" and len(rule_ids) > 1 else "winner_only"
                ),
            }
            candidates.append(
                build_submission_body(example, rule_id=rule_id, provenance=provenance)
            )
    return candidates


def _pending_args_from_row(row: dict[str, Any]) -> dict[str, Any]:
    command = row.get("pending_command_excerpt")
    if row.get("pending_tool") == "exec" and command:
        return {"command": command}
    return {}


def submit_harvest_candidates(
    path: Path,
    *,
    rookery_url: str,
    dry_run: bool = False,
    decision: str = "review",
    label: CorpusLabel | None = None,
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    if dry_run and label is None:
        return [
            {"status": "dry_run", "preview": preview}
            for preview in preview_harvest_candidates(path, decision=decision)
        ]
    if not dry_run and label is None:
        raise ValueError(
            "submit requires --label attack|benign (use --dry-run to preview unlabelled candidates)"
        )
    candidates = harvest_candidates_from_log(path, decision=decision, label=label)
    results: list[dict[str, Any]] = []
    for body in candidates:
        example_id = body.get("example", {}).get("id", "?")
        if dry_run:
            results.append({"status": "dry_run", "example_id": example_id, "submission": body})
            continue
        payload = submit_to_rookery(rookery_url, body, api_key=api_key)
        submission = payload.get("submission", {})
        results.append(
            {
                "status": "submitted",
                "example_id": example_id,
                "submission_id": submission.get("id"),
            }
        )
    return results


def preview_harvest_candidates(
    path: Path,
    *,
    decision: str = "review",
) -> list[dict[str, Any]]:
    """Dry-run payloads without corpus labels (metadata only)."""
    records = load_scan_log(path)
    previews: list[dict[str, Any]] = []
    for index, row in enumerate(records, start=1):
        if str(row.get("decision", "allow")) != decision:
            continue
        matched = row.get("matched_rules") or []
        rule_ids = [
            str(item["id"]) if isinstance(item, dict) else str(item)
            for item in matched
            if (isinstance(item, dict) and item.get("id")) or isinstance(item, str)
        ]
        causal = pick_rule_id(None, row)
        fatigue_ids = pick_feedback_rule_ids(None, row, resolution="allow-once")
        previews.append(
            {
                "snapshot_index": index,
                "session_id": row.get("session_id"),
                "tool_call_id": row.get("tool_call_id"),
                "pending_tool": row.get("pending_tool"),
                "command_excerpt": row.get("pending_command_excerpt"),
                "summary": row.get("summary"),
                "matched_rules": rule_ids,
                "winning_rule_id": causal,
                "fatigue_rule_ids": fatigue_ids,
            }
        )
    return previews
