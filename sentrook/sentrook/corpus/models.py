from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrook.adapters.intent import IntentKind
from sentrook.result import MatchedSubgraph

CorpusLabel = Literal["attack", "benign"]
CorpusTrust = Literal["verified", "community", "synthetic"]
IndexLabel = Literal["pos", "neg"]

# Human-readable corpus labels map to the pos/neg index names used internally and
# in L3 traces (attack examples are the positive class for an attack detector).
LABEL_TO_INDEX: dict[CorpusLabel, IndexLabel] = {
    "attack": "pos",
    "benign": "neg",
}


class CorpusStep(BaseModel):
    """One ordered step of a corpus example's mini-trajectory."""

    tool: str
    status: Literal["executed", "pending"]
    args: dict[str, Any] = Field(default_factory=dict)
    excerpt: str | None = None

    model_config = {"extra": "forbid"}


class CorpusThresholds(BaseModel):
    """Per-rule overrides for the global L3 margins. Omitted fields fall back."""

    allow_margin: float | None = None
    fail_closed_margin: float | None = None

    model_config = {"extra": "forbid"}


class CorpusExample(BaseModel):
    """A single labelled trajectory authored for one rule's corpus."""

    id: str
    label: CorpusLabel
    trust: CorpusTrust
    intent: str | None = None
    intent_kind: IntentKind | None = None
    notes: str | None = None
    steps: list[CorpusStep] = Field(min_length=1)

    model_config = {"extra": "forbid"}


class RuleCorpus(BaseModel):
    """Parsed contents of one ``corpus/<RULE_ID>.yaml`` file."""

    rule_id: str
    thresholds: CorpusThresholds | None = None
    examples: list[CorpusExample] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class CorpusEntry(BaseModel):
    """A corpus example resolved into its embeddable trajectory text.

    ``text`` is produced by the shared ``subgraph_to_text()`` so corpus and live
    scans serialize identically. ``embedding`` is populated later (Step 5).
    """

    example_id: str
    label: IndexLabel
    trust: CorpusTrust
    text: str
    subgraph: MatchedSubgraph
    embedding: list[float] | None = None


class LoadedRuleCorpus(BaseModel):
    """A rule's corpus split into pre-serialized pos/neg indexes."""

    rule_id: str
    allow_margin: float | None = None
    fail_closed_margin: float | None = None
    pos: list[CorpusEntry] = Field(default_factory=list)
    neg: list[CorpusEntry] = Field(default_factory=list)

    @property
    def is_sufficient(self) -> bool:
        """L3 only runs for a rule with at least one attack and one benign example."""
        return bool(self.pos) and bool(self.neg)
