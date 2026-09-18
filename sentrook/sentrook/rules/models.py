from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

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

    #: Unknown keys are **refused**, not ignored. Pydantic's default is
    #: `extra="ignore"`, so `segment_heads:` (a plural typo) silently became no
    #: constraint at all — a rule quietly wider than its author wrote, which is
    #: F31(b)'s class: where a field draws from a closed set, "can this ever
    #: mean what it says?" is decidable and belongs at compile.
    model_config = ConfigDict(extra="forbid")

    type: Literal["paths"] = "paths"
    #: any  — at least one path matches (**false when there are no paths**)
    #: every — all paths match, and there is at least one (**never vacuous**)
    #: none  — no path matches (**true when there are no paths**)
    quantifier: Literal["any", "every", "none"]
    location: str | None = None
    role: str | None = None
    path: str | None = None
    #: Restrict which paths count to those belonging to a segment whose **head**
    #: matches this pattern — "a path outside scratch, *belonging to the `rm`*".
    #:
    #: Without it the two halves of a rule like AIRA-084 are unrelated: "a
    #: destructive head is somewhere in the command" and "some path somewhere is
    #: outside scratch", so `cat /etc/hosts && rm -rf /tmp/scratch` satisfies
    #: both and fires, although the `rm` targets scratch. That is F27's implicit
    #: quantifier one level up — the quantifier *over paths* was stated, the
    #: association between head and path was implicit and wrong.
    #:
    #: **`cd` rebase is handled by the engine, not by the rule.** `cd /srv/app
    #: && rm -rf logs` puts the only extractable path in the `cd`'s segment
    #: while the destruction happens in the next one, so a strictly per-segment
    #: reading would spare it — turning AIRA-084's false positive into the
    #: `cd`-rebase false negative §1.1 exists to prevent.
    #:
    #: `_segment_heads_for` credits a `cd` segment's path to `cd` **and** to
    #: every *later* segment's head, so a rule asking `segment_head: "rm"`
    #: catches `cd /srv/app && rm -rf logs` without mentioning `cd`. Ordering is
    #: respected: `rm -rf /tmp/x && cd /srv/app` does not credit `/srv/app` to
    #: the `rm`, because the `cd` comes after it.
    #:
    #: A rule that lists `cd` in this pattern gets `cd` on its own as well,
    #: which is a different question and usually not the one intended.
    segment_head: str | None = None


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
