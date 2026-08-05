from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook.layers.pass_kind import L2PassKind
from sentrook.planir import PlanStep


class MatchedRule(BaseModel):
    id: str
    name: str
    severity: Literal["low", "medium", "high", "critical"]
    action: Literal["block", "review"]
    reason: str
    confidence: float
    layer: Literal["L1", "L2", "L3"] = "L2"
    pass_id: L2PassKind = Field(serialization_alias="pass")
    matched_step_ids: list[str] = Field(default_factory=list)
    description: str | None = None

    model_config = {"populate_by_name": True}


class MatchedSubgraph(BaseModel):
    step_ids: list[str]
    tools: list[str]
    steps: list[PlanStep]


class LayerInfo(BaseModel):
    exits: list[str] = Field(default_factory=list)
    l1_candidates: list[str] = Field(default_factory=list)
    l2_evaluated: int = 0


class PlanEcho(BaseModel):
    run_id: str
    plan_size: int
    pending_step_id: str | None = None
    pending_tool: str | None = None
    tools: list[str] = Field(default_factory=list)


class TimingInfo(BaseModel):
    total_ms: int = 0
    l1_ms: int = 0
    l2_ms: int = 0
    l3_ms: int = 0


class L3CandidateTrace(BaseModel):
    example_id: str
    label: Literal["pos", "neg"]
    bi_score: float | None = None
    cross_score: float | None = None  # Phase 2 (cross-encoder rerank)


class L3RuleTrace(BaseModel):
    rule_id: str
    ran: bool
    skipped_reason: str | None = None  # insufficient_corpus, policy_skip, hard_block, ...
    query_text_hash: str | None = None
    top_pos: list[L3CandidateTrace] = Field(default_factory=list)
    top_neg: list[L3CandidateTrace] = Field(default_factory=list)
    margin: float | None = None
    decision: Literal["allow", "review", "block", "no_change"] = "no_change"


class StepSummary(BaseModel):
    id: str
    tool: str
    status: Literal["executed", "pending"]


class PendingStepDebug(BaseModel):
    id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class PlanMetadataEcho(BaseModel):
    adapter: str
    agent_id: str | None = None
    session_id: str | None = None
    hook: str


class MatcherThresholds(BaseModel):
    definitive: float
    review: float


class L2RuleTrace(BaseModel):
    rule_id: str
    hit: bool
    confidence: float
    pass_id: L2PassKind | None = Field(default=None, serialization_alias="pass")
    reason: str
    effective_action: Literal["allow", "review", "block"] | None = None

    model_config = {"populate_by_name": True}


class DebugInfo(BaseModel):
    scanner_version: str
    rules_loaded: int
    rules_source: str | None = None
    plan_source: str | None = None
    l1_index_keys: list[str] = Field(default_factory=list)
    plan_tools: list[str] = Field(default_factory=list)
    plan_metadata: PlanMetadataEcho | None = None
    intent: str | None = None
    l1_candidate_ids: list[str] = Field(default_factory=list)
    l1_skipped_rule_ids: list[str] = Field(default_factory=list)
    l2_traces: list[L2RuleTrace] = Field(default_factory=list)
    l3_traces: list[L3RuleTrace] = Field(default_factory=list)
    pending_step: PendingStepDebug | None = None
    steps_summary: list[StepSummary] = Field(default_factory=list)
    matcher_thresholds: MatcherThresholds | None = None


class ScanResult(BaseModel):
    version: Literal["0.1"] = "0.1"
    decision: Literal["allow", "review", "block"]
    risk: float
    summary: str
    matched_rules: list[MatchedRule] = Field(default_factory=list)
    #: Rule that drove the final decision after L2/L3 aggregate (not list order).
    winning_rule_id: str | None = None
    matched_subgraph: MatchedSubgraph | None = None
    layers: LayerInfo = Field(default_factory=LayerInfo)
    plan: PlanEcho
    timing: TimingInfo = Field(default_factory=TimingInfo)
    debug: DebugInfo

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)
