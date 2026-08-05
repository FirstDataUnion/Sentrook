from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook.config import L2Authority


class OwaspRefs(BaseModel):
    """Cross-reference to OWASP GenAI security taxonomies (informational)."""

    asi: list[str] = Field(default_factory=list)
    llm: list[str] = Field(default_factory=list)


class RuleMeta(BaseModel):
    name: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    action: Literal["block", "review"] = "block"
    description: str | None = None
    owasp: OwaspRefs | None = None
    # Whether L3 may override this rule's L2 verdict. When unset, the scanner falls
    # back to ScannerConfig.default_l2_authority.
    authority: L2Authority | None = None


class PendingToolCondition(BaseModel):
    type: Literal["pending_tool"] = "pending_tool"
    tool: str


class IntentKindCondition(BaseModel):
    type: Literal["intent_kind"] = "intent_kind"
    kind: Literal["user", "cron", "subagent", "system"]


class SequenceSlot(BaseModel):
    tool: str
    status: Literal["executed", "pending", "any"] = "any"
    args_match: dict[str, str] | None = None
    result_flags: dict[str, bool] | None = None


class SequenceCondition(BaseModel):
    type: Literal["sequence"] = "sequence"
    steps: list[SequenceSlot]


class SequenceWithGapCondition(BaseModel):
    type: Literal["sequence_with_gap"] = "sequence_with_gap"
    steps: list[SequenceSlot]
    # Max plan steps strictly between consecutive matched slots (inclusive pair window).
    # When unset, any gap is allowed (sticky behaviour when max_gap omitted).
    max_gap: int | None = None


class AllCondition(BaseModel):
    type: Literal["all"] = "all"
    conditions: list[ConditionNode]


class AnyCondition(BaseModel):
    type: Literal["any"] = "any"
    conditions: list[ConditionNode]


class NoneCondition(BaseModel):
    type: Literal["none"] = "none"
    condition: ConditionNode


ConditionNode = (
    PendingToolCondition
    | IntentKindCondition
    | SequenceCondition
    | SequenceWithGapCondition
    | AllCondition
    | AnyCondition
    | NoneCondition
)
AllCondition.model_rebuild()
AnyCondition.model_rebuild()
NoneCondition.model_rebuild()


class Rule(BaseModel):
    id: str
    meta: RuleMeta
    condition: ConditionNode
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)
