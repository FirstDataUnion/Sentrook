"""Structured shadow-mode decision log (JSON Lines).

Each line records one ``before_tool_call`` decision in a compact, stable shape so
operators can tail it live and so it can be diffed against ``sentrook replay scan``
on the same session for live-vs-replay parity checks.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook.result import ScanResult
from sentrook.sanitize.text import scrub_text
from sentrook.shadow.snapshot import ShadowSnapshot
COMMAND_EXCERPT_LIMIT = 120


class ShadowMatchedRule(BaseModel):
    id: str
    action: Literal["block", "review"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float
    layer: Literal["L1", "L2", "L3"]


class ShadowLogRecord(BaseModel):
    """One observe-only decision, as written to the shadow log."""

    ts: str
    mode: str = "shadow"
    schema_version: str = "sentrook.shadow.log/v2"
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
    matched_rules: list[ShadowMatchedRule] = Field(default_factory=list)
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


def _pending_command_excerpt(snapshot: ShadowSnapshot) -> str | None:
    args = snapshot.pending.args or {}
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
    snapshot: ShadowSnapshot,
    *,
    mode: str = "shadow",
    ts: str | None = None,
    bundle_version: str | None = None,
    request_ms: int | None = None,
    sanitize_log_fields: bool = False,
) -> ShadowLogRecord:
    l3_allow, l3_kept = _l3_rule_lists(result)
    intent = snapshot.intent
    pending_excerpt = _pending_command_excerpt(snapshot)
    if sanitize_log_fields:
        if intent:
            intent = scrub_text(intent, max_chars=1000, pii=True)
        if pending_excerpt:
            pending_excerpt = scrub_text(
                pending_excerpt,
                max_chars=COMMAND_EXCERPT_LIMIT,
                pii=True,
            )
    return ShadowLogRecord(
        ts=ts or datetime.now(timezone.utc).isoformat(),
        mode=mode,
        adapter=snapshot.adapter,
        session_id=snapshot.session_id,
        run_id=result.plan.run_id,
        agent_id=snapshot.agent_id,
        tool_call_id=snapshot.tool_call_id,
        step_seq=snapshot.step_seq,
        batch_size=snapshot.batch_size,
        pending_tool=result.plan.pending_tool,
        pending_step_id=result.plan.pending_step_id,
        pending_command_excerpt=pending_excerpt,
        decision=result.decision,
        risk=result.risk,
        summary=result.summary,
        matched_rules=[
            ShadowMatchedRule(
                id=m.id,
                action=m.action,
                severity=m.severity,
                confidence=m.confidence,
                layer=m.layer,
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
        intent_kind=snapshot.intent_kind,
    )


def load_shadow_log(path: Path) -> list[dict[str, Any]]:
    """Load a shadow JSONL file, skipping blank lines."""
    records: list[dict[str, Any]] = []
    with Path(path).expanduser().open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def append_shadow_log(log_path: Path, record: ShadowLogRecord | dict[str, Any]) -> None:
    """Append one record as a JSON line, creating parent dirs as needed."""
    log_path = Path(log_path).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    line = (
        record.to_json_line()
        if isinstance(record, ShadowLogRecord)
        else json.dumps(record, ensure_ascii=False)
    )
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
