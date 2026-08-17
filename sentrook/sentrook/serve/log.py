"""Structured observe/enforce decision log (JSON Lines).

Each line records one ``before_tool_call`` decision in a compact, stable shape so
operators can tail it live and so it can be diffed against ``sentrook replay scan``
on the same session for live-vs-replay parity checks.

Free-text PlanIR fields (``intent``, ``pending_command_excerpt``) are gated by
``SENTROOK_LOG_CONTENT`` / :func:`append_scan_log`'s ``log_content``:

- ``metadata`` — omit free text **on disk** (required for ``SENTROOK_ENV=production``);
  the HTTP echo still carries pattern-scrubbed text for feedback/review tooling
- ``scrubbed`` — pattern-redacted text on disk and wire (secrets/PII patterns; not a guarantee)
- ``full`` — unsanitized (development only)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook.adapters.snapshot import primary_pending_step
from sentrook.planir import PlanIR
from sentrook.result import ScanResult
from sentrook.sanitize.text import scrub_text

COMMAND_EXCERPT_LIMIT = 120


class ScanMatchedRule(BaseModel):
    id: str
    action: Literal["block", "review"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float
    layer: Literal["L1", "L2", "L3"]
    #: PlanIR step ids this rule matched. Feedback uses these to slice community
    #: corpus examples to the same subgraph L3 embeds (not the full session).
    matched_step_ids: list[str] = Field(default_factory=list)


class ScanLogRecord(BaseModel):
    """One scan decision, as written to the scan log."""

    ts: str
    mode: str = "observe"
    schema_version: str = "sentrook.scan.log/v1"
    adapter: str
    session_id: str | None = None
    run_id: str
    agent_id: str | None = None
    tool_call_id: str | None = None
    step_seq: int | None = None
    batch_size: int | None = None
    pending_tool: str | None = None
    pending_step_id: str | None = None
    pending_command_excerpt: str | None = None
    decision: Literal["allow", "review", "block"]
    risk: float
    summary: str
    matched_rules: list[ScanMatchedRule] = Field(default_factory=list)
    #: Rule that actually drove review/block after L3 (causal for feedback).
    winning_rule_id: str | None = None
    layer_exits: list[str] = Field(default_factory=list)
    l3_allow_rules: list[str] = Field(default_factory=list)
    l3_kept_review_rules: list[str] = Field(default_factory=list)
    total_ms: int = 0
    request_ms: int | None = None
    scanner_version: str
    bundle_version: str | None = None
    intent: str | None = None
    intent_kind: Literal["user", "cron", "subagent", "system"] | None = None

    def to_json_line(self) -> str:
        return json.dumps(self.model_dump(mode="json"), ensure_ascii=False)


def _pending_command_excerpt(plan: PlanIR) -> str | None:
    pending = primary_pending_step(plan)
    if pending is None:
        return None
    args = pending.args or {}
    command = args.get("command") or args.get("cmd")
    if command is None:
        return None
    text = str(command).strip()
    if not text:
        return None
    if len(text) > COMMAND_EXCERPT_LIMIT:
        return text[: COMMAND_EXCERPT_LIMIT - 3] + "..."
    return text


def _l3_rule_lists(result: ScanResult) -> tuple[list[str], list[str]]:
    l3_allow: list[str] = []
    l3_kept: list[str] = []
    review_ids = {m.id for m in result.matched_rules if m.action == "review"}
    for trace in result.debug.l3_traces:
        if not trace.ran:
            continue
        if trace.decision == "allow":
            l3_allow.append(trace.rule_id)
        elif trace.decision == "no_change" and trace.rule_id in review_ids:
            l3_kept.append(trace.rule_id)
    return l3_allow, l3_kept


def build_log_record(
    result: ScanResult,
    plan: PlanIR,
    *,
    mode: str = "observe",
    ts: str | None = None,
    bundle_version: str | None = None,
    request_ms: int | None = None,
    sanitize_log_fields: bool = False,
    log_content: str = "scrubbed",
) -> ScanLogRecord:
    """Build a scan log record for the HTTP response / feedback echo.

    Free-text fields (``intent``, ``pending_command_excerpt``):

    - ``full`` — as present on the plan (developer debugging only)
    - ``metadata`` — pattern-scrubbed on the wire; disk writers strip via
      :func:`record_for_disk`
    - ``scrubbed`` — pattern-scrubbed when ``sanitize_log_fields`` is true;
      otherwise raw (matches ``SENTROOK_SERVER_SANITIZE_PLANIR=0``)

    Disk writers must call :func:`append_scan_log` (or :func:`record_for_disk`)
    with the same ``log_content`` so ``metadata`` omits free text on disk.
    """
    l3_allow, l3_kept = _l3_rule_lists(result)
    intent = plan.intent
    pending_excerpt = _pending_command_excerpt(plan)
    should_scrub = log_content == "metadata" or (log_content == "scrubbed" and sanitize_log_fields)
    if should_scrub:
        if intent:
            intent = scrub_text(intent, max_chars=1000, pii=True)
        if pending_excerpt:
            pending_excerpt = scrub_text(
                pending_excerpt,
                max_chars=COMMAND_EXCERPT_LIMIT,
                pii=True,
            )
    meta = plan.metadata
    return ScanLogRecord(
        ts=ts or datetime.now(UTC).isoformat(),
        mode=mode,
        adapter=meta.adapter,
        session_id=meta.session_id,
        run_id=result.plan.run_id,
        agent_id=meta.agent_id,
        tool_call_id=meta.tool_call_id,
        step_seq=meta.step_seq,
        batch_size=meta.batch_size,
        pending_tool=result.plan.pending_tool,
        pending_step_id=result.plan.pending_step_id,
        pending_command_excerpt=pending_excerpt,
        decision=result.decision,
        risk=result.risk,
        summary=result.summary,
        matched_rules=[
            ScanMatchedRule(
                id=m.id,
                action=m.action,
                severity=m.severity,
                confidence=m.confidence,
                layer=m.layer,
                matched_step_ids=list(m.matched_step_ids),
            )
            for m in result.matched_rules
        ],
        winning_rule_id=result.winning_rule_id,
        layer_exits=list(result.layers.exits),
        l3_allow_rules=l3_allow,
        l3_kept_review_rules=l3_kept,
        total_ms=result.timing.total_ms,
        request_ms=request_ms,
        scanner_version=result.debug.scanner_version,
        bundle_version=bundle_version,
        intent=intent,
        intent_kind=plan.intent_kind,
    )


def record_for_disk(record: ScanLogRecord, *, log_content: str) -> ScanLogRecord:
    """Return a copy safe to append to scan.log.jsonl under ``log_content`` policy.

    ``metadata`` strips PlanIR free text. Other modes pass through (callers
    must have built scrubbed/full content via :func:`build_log_record`).
    """
    if log_content != "metadata":
        return record
    if record.intent is None and record.pending_command_excerpt is None:
        return record
    return record.model_copy(
        update={
            "intent": None,
            "pending_command_excerpt": None,
        }
    )


def load_scan_log(path: Path) -> list[dict[str, Any]]:
    """Load a scan JSONL file, skipping blank lines."""
    records: list[dict[str, Any]] = []
    with Path(path).expanduser().open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def append_scan_log(
    log_path: Path,
    record: ScanLogRecord | dict[str, Any],
    *,
    log_content: str = "scrubbed",
) -> None:
    """Append one record as a JSON line, creating parent dirs as needed.

    When ``record`` is a :class:`ScanLogRecord`, free-text fields are stripped
    according to ``log_content`` before write. Dict payloads are written as-is
    (callers must pre-strip).
    """
    log_path = Path(log_path).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(record, ScanLogRecord):
        disk_record = record_for_disk(record, log_content=log_content)
        line = disk_record.to_json_line()
    else:
        line = json.dumps(record, ensure_ascii=False)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
