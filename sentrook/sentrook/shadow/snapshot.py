"""The ``sentrook.shadow.snapshot/v1`` wire contract.

This is the host-agnostic boundary between a live agent host and Sentrook. A host
sends the executed trajectory plus the single pending tool call; Sentrook converts
it into a PlanIR snapshot using the same adapter helpers as offline replay, so
live and replay decisions stay in lockstep.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentrook.adapters.snapshot import (
    SnapshotCall,
    build_planir_snapshot,
    build_result_summary,
)
from sentrook.planir import PlanIR

SNAPSHOT_SCHEMA = "sentrook.shadow.snapshot/v1"


class ShadowResult(BaseModel):
    """Result of an executed tool call, as the host observed it."""

    ok: bool = True
    text: str = ""
    content_type: str | None = None
    command: str | None = None


class ShadowCall(BaseModel):
    """One tool call: ``result`` is present only for executed calls."""

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    result: ShadowResult | None = None


class ShadowSnapshot(BaseModel):
    """One ``before_tool_call`` moment sent by a live host."""

    model_config = ConfigDict(populate_by_name=True)

    schema_: Literal["sentrook.shadow.snapshot/v1"] = Field(
        default=SNAPSHOT_SCHEMA, alias="schema"
    )
    adapter: str = "openclaw"
    session_id: str | None = None
    agent_id: str | None = "main"
    run_id: str
    intent: str | None = None
    intent_kind: Literal["user", "cron", "subagent", "system"] | None = None
    executed: list[ShadowCall] = Field(default_factory=list)
    co_pending: list[ShadowCall] = Field(default_factory=list)
    pending: ShadowCall
    tool_call_id: str | None = None
    step_seq: int | None = None
    batch_size: int | None = None

    def to_planir(self) -> PlanIR:
        executed = [
            SnapshotCall(
                tool=call.tool,
                args=call.args,
                result_summary=(
                    build_result_summary(
                        call.result.text,
                        ok=call.result.ok,
                        content_type=call.result.content_type,
                        command=call.result.command,
                    )
                    if call.result is not None
                    else None
                ),
            )
            for call in self.executed
        ]
        co_pending = [
            SnapshotCall(tool=call.tool, args=call.args) for call in self.co_pending
        ]
        pending = SnapshotCall(tool=self.pending.tool, args=self.pending.args)
        return build_planir_snapshot(
            executed=executed,
            co_pending=co_pending,
            pending=pending,
            run_id=self.run_id,
            intent=self.intent,
            intent_kind=self.intent_kind,
            session_id=self.session_id,
            agent_id=self.agent_id,
            adapter=self.adapter,
            tool_call_id=self.tool_call_id,
            step_seq=self.step_seq,
            batch_size=self.batch_size,
        )
