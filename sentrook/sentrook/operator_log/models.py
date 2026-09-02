"""Operator log event models — PlanIR field names in an event envelope."""

from __future__ import annotations

import secrets
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from sentrook.planir.models import IntentKind, PlanMetadata, PlanStep, ResultSummary

SCHEMA_VERSION = "sentrook.operator.log/v1"

EventKind = Literal["scan", "result", "resolution", "scan_error"]
Effect = Literal["ran", "blocked", "never_ran"]
LabelSource = Literal[
    "scanner",
    "human",
    "quiet",
    "lenient",
    "allowlist",
    "timeout",
    "unattended",
]
HookAction = Literal["requireApproval", "block", "continue"]
SkipReason = Literal["allowlist", "quiet", "lenient", "allow-all"]
ResolutionKind = Literal[
    "allow-once",
    "allow-always",
    "deny",
    "timeout",
    "cancelled",
    "quiet-skip",
    "lenient-skip",
    "allowlist-hit",
]


def mint_event_id() -> str:
    return f"sr_{secrets.token_hex(6)}"


class ScanBody(BaseModel):
    decision: Literal["allow", "review", "block"]
    risk: float | None = None
    summary: str | None = None
    matched_rules: list[str] = Field(default_factory=list)
    review_severity: str | None = None
    block_reason: str | None = None
    winning_rule_id: str | None = None
    log: dict[str, Any] | None = None


class HookBody(BaseModel):
    action: HookAction
    skip_reason: SkipReason | None = None


class ScanErrorBody(BaseModel):
    kind: str
    detail: str | None = None
    status: int | None = None


class ResolutionBody(BaseModel):
    decision: ResolutionKind
    feedback_posted: bool | None = None


class OperatorLogEvent(BaseModel):
    """One JSONL line. ``event`` is the discriminator, not a PlanIR document."""

    schema_version: Literal["sentrook.operator.log/v1"] = SCHEMA_VERSION
    id: str
    ts: str
    event: EventKind
    run_id: str
    intent: str | None = None
    intent_kind: IntentKind | None = None
    metadata: PlanMetadata
    parent_session_id: str | None = None
    host: dict[str, Any] | None = None
    plugin_version: str | None = None
    effect: Effect | None = None
    label_source: LabelSource | None = None
    unattended: bool | None = None
    feedback_posted: bool | None = None
    contribute_eligible: bool | None = None
    host_tool: str | None = None
    host_truncated: bool | None = None
    pending: PlanStep | None = None
    co_pending: list[str] = Field(default_factory=list)
    scan: ScanBody | None = None
    hook: HookBody | None = None
    result: ResultSummary | None = None
    resolution: ResolutionBody | None = None
    scan_error: ScanErrorBody | None = None

    @model_validator(mode="after")
    def _require_event_body(self) -> OperatorLogEvent:
        if not self.id.startswith("sr_"):
            raise ValueError("operator log id must start with 'sr_'")
        if self.event == "scan":
            if self.pending is None:
                raise ValueError("scan event requires pending")
            if self.scan is None:
                raise ValueError("scan event requires scan")
        elif self.event == "result":
            if self.result is None:
                raise ValueError("result event requires result")
        elif self.event == "resolution":
            if self.resolution is None:
                raise ValueError("resolution event requires resolution")
        elif self.event == "scan_error":
            if self.scan_error is None:
                raise ValueError("scan_error event requires scan_error")
            if self.pending is None:
                raise ValueError("scan_error event requires pending")
        return self
