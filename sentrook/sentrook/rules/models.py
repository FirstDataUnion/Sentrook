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
    action: Literal["block", "review", "allow"] = "block"
    description: str | None = None
    owasp: OwaspRefs | None = None
    # Whether L3 may override this rule's L2 verdict. When unset, the scanner falls
    # back to ScannerConfig.default_l2_authority.
    authority: L2Authority | None = None
    #: Review rule ids this allow rule removes from the review set (§1.2).
    #: Required on `action: allow`, and validated at compile time to name only
    #: soft-authority review rules — an allow rule may never touch a block or a
    #: hard review.
    suppresses: list[str] = Field(default_factory=list)


class PendingToolCondition(BaseModel):
    type: Literal["pending_tool"] = "pending_tool"
    tool: str


class IntentKindCondition(BaseModel):
    type: Literal["intent_kind"] = "intent_kind"
    kind: Literal["user", "cron", "heartbeat", "subagent", "system"]


class PathsCondition(BaseModel):
    """Per-path matching over the pending exec step, with an explicit quantifier.

    Every sub-predicate is optional and they are ANDed *per path*: a path
    "matches" when all the given ones match it. ``locations`` and ``roles`` are
    matched as newline-joined strings, the same convention as ``_shape.heads``.

    ``quantifier`` has **no default**. F27 was two bugs, and only one of them was
    the flat vocabulary — the other was an *implicit quantifier*. "Path class
    other than tmp/workspace" reads as both "some path" and "every path", and
    the two give opposite answers on the same command. Requiring the word makes
    that unrepresentable.
    """

    type: Literal["paths"] = "paths"
    #: any  — at least one path matches (**false when there are no paths**)
    #: every — all paths match, and there is at least one (**never vacuous**)
    #: none  — no path matches (**true when there are no paths**)
    quantifier: Literal["any", "every", "none"]
    location: str | None = None
    role: str | None = None
    path: str | None = None


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
    | PathsCondition
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
