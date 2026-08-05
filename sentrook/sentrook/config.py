from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class L3Policy(str, Enum):
    """When Layer 3 semantic scoring runs (prototype tuning knob)."""

    OFF = "off"
    TIE_BREAKER = "tie_breaker"
    RISKY_PENDING = "risky_pending"
    L1_MISS = "l1_miss"
    ALL_CANDIDATES = "all_candidates"


class L2Authority(str, Enum):
    """Whether an L2 match can be overridden by L3 (per-rule override in future)."""

    HARD = "hard"
    SOFT = "soft"


class Reranker(str, Enum):
    """Second-stage L3 scorer. Phase 1 ships ``none``; Phase 2 adds cross-encoder."""

    NONE = "none"
    CROSS_ENCODER = "cross_encoder"


class MatcherConfig(BaseModel):
    definitive_threshold: float = 1.0
    review_threshold: float = 0.4


class L3Config(BaseModel):
    """Layer 3 semantic-scoring defaults.

    Always constructed (even when ``l3_policy=off``) so every profile shares one
    code path. Per-rule ``thresholds`` in corpus YAML override ``allow_margin``
    and ``fail_closed_margin`` at scoring time.
    """

    corpus_dir: str = "~/.sentrook/corpus/"
    top_k: int = 5
    fail_closed_margin: float = 0.1
    allow_margin: float = 0.15
    bi_encoder_model: str = "all-MiniLM-L6-v2"
    reranker: Reranker = Reranker.NONE


class ScannerConfig(BaseModel):
    matcher: MatcherConfig = Field(default_factory=MatcherConfig)
    l3_policy: L3Policy = L3Policy.TIE_BREAKER
    default_l2_authority: L2Authority = L2Authority.HARD
    l3: L3Config = Field(default_factory=L3Config)
