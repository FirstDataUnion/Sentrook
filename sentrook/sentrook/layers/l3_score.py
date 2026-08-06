from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from sentrook.corpus.models import CorpusEntry, LoadedRuleCorpus
from sentrook.result import L3CandidateTrace, L3RuleTrace


@dataclass(frozen=True)
class L3ScoreParams:
    """Resolved thresholds for one scoring call (per-rule overrides already applied)."""

    allow_margin: float
    fail_closed_margin: float
    top_k: int = 5


class BiEncoderScorer(Protocol):
    """Computes cosine similarity of a query against pre-loaded corpus entries.

    Phase 1 ships :class:`StubScorer`; Step 5 adds a fastembed bi-encoder implementing
    this same interface, so nothing downstream changes.
    """

    def similarities(self, query_text: str, entries: list[CorpusEntry]) -> list[float]: ...


class StubScorer:
    """Deterministic scorer for wiring tests and the pre-embedder default.

    With no configured scores it returns ``0.0`` for every entry, so margins collapse
    to zero and L3 fails closed (stays ``review``). Tests inject per-example-id scores
    to drive a specific margin and exercise the policy fuse.
    """

    def __init__(self, scores: dict[str, float] | None = None, *, default: float = 0.0) -> None:
        self._scores = scores or {}
        self._default = default

    def similarities(self, query_text: str, entries: list[CorpusEntry]) -> list[float]:
        return [self._scores.get(e.example_id, self._default) for e in entries]


def query_text_hash(text: str) -> str:
    """Short, stable hash of the embed text for trace reproducibility."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def score_rule(
    rule_id: str,
    query_text: str,
    corpus: LoadedRuleCorpus,
    params: L3ScoreParams,
    scorer: BiEncoderScorer,
) -> L3RuleTrace:
    """Score one rule's query against its corpus and return a populated trace.

    Returns a ``ran=False`` trace with ``insufficient_corpus`` when the rule lacks at
    least one attack and one benign example. Otherwise computes the benign-leading
    margin and maps it to ``allow`` / ``no_change`` per the fail-closed thresholds.
    """
    if not corpus.is_sufficient:
        return L3RuleTrace(
            rule_id=rule_id,
            ran=False,
            skipped_reason="insufficient_corpus",
            decision="no_change",
        )

    pos_scores = scorer.similarities(query_text, corpus.pos)
    neg_scores = scorer.similarities(query_text, corpus.neg)

    margin = max(neg_scores) - max(pos_scores)

    if abs(margin) < params.fail_closed_margin:
        decision = "no_change"
    elif margin > params.allow_margin:
        decision = "allow"
    else:
        decision = "no_change"

    return L3RuleTrace(
        rule_id=rule_id,
        ran=True,
        query_text_hash=query_text_hash(query_text),
        top_pos=_top_candidates(corpus.pos, pos_scores, params.top_k),
        top_neg=_top_candidates(corpus.neg, neg_scores, params.top_k),
        margin=margin,
        decision=decision,
    )


def _top_candidates(
    entries: list[CorpusEntry], scores: list[float], top_k: int
) -> list[L3CandidateTrace]:
    ranked = sorted(
        zip(entries, scores, strict=True),
        key=lambda pair: pair[1],
        reverse=True,
    )[:top_k]
    return [
        L3CandidateTrace(
            example_id=entry.example_id,
            label=entry.label,
            bi_score=score,
        )
        for entry, score in ranked
    ]
