from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

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
    """PlanIR 1.0 — single public scan ingress (conceptual id: ``sentrook.planir/v1``)."""

    version: Literal["1.0"] = "1.0"
    run_id: str
    intent: str | None = None
    intent_kind: IntentKind | None = None
    steps: list[PlanStep]
    metadata: PlanMetadata = Field(default_factory=PlanMetadata)

    @model_validator(mode="after")
    def _validate_invariants(self) -> PlanIR:
        if not self.steps:
            raise ValueError("PlanIR requires at least one step")

        pending = [s for s in self.steps if s.status == "pending"]
        if not pending:
            raise ValueError("PlanIR requires at least one pending step")

        # Executed history must precede all pending steps (no executed after first pending).
        seen_pending = False
        for step in self.steps:
            if step.status == "pending":
                seen_pending = True
            elif seen_pending:
                raise ValueError(
                    "PlanIR executed steps must precede pending steps "
                    "(no executed step after the first pending)"
                )

        for index, step in enumerate(self.steps, start=1):
            expected = f"s{index}"
            if step.id != expected:
                raise ValueError(
                    f"PlanIR step ids must be sequential s1..sN; "
                    f"expected {expected!r} at index {index}, got {step.id!r}"
                )

        return self
