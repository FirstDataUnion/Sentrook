from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

IntentKind = Literal["user", "cron", "subagent", "system"]


class ResultSummaryExtracted(BaseModel):
    urls: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)


class ResultSummaryFlags(BaseModel):
    truncated: bool = False
    injection_markers: bool = False


class ResultSummary(BaseModel):
    ok: bool
    content_type: str | None = None
    byte_size: int = 0
    excerpt: str = ""
    extracted: ResultSummaryExtracted = Field(default_factory=ResultSummaryExtracted)
    flags: ResultSummaryFlags = Field(default_factory=ResultSummaryFlags)


class PlanStep(BaseModel):
    id: str
    tool: str
    status: Literal["executed", "pending"]
    args: dict[str, Any] = Field(default_factory=dict)
    result_summary: ResultSummary | None = None


class PlanMetadata(BaseModel):
    adapter: str = "fixture"
    agent_id: str | None = None
    session_id: str | None = None
    hook: str = "before_tool_call"
    tool_call_id: str | None = None
    step_seq: int | None = None
    batch_size: int | None = None


class PlanIR(BaseModel):
    version: Literal["0.1"] = "0.1"
    run_id: str
    intent: str | None = None
    intent_kind: IntentKind | None = None
    steps: list[PlanStep]
    metadata: PlanMetadata = Field(default_factory=PlanMetadata)
