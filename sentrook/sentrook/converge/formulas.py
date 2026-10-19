"""Tier scores and risk. Numeric inputs only.

    taint_link  = untrusted_origin × max(exposure, taint_floor)
    suspicion   = 1 − (1 − misalignment)(1 − concealment)(1 − distrust)(1 − taint_link)
                      (1 − request_origin)(1 − retry_after_denial)
    consequence = max(sensitivity × reach, irreversibility × reach, self_modification)       [max]
                | max(mean(sensitivity, reach, irreversibility), self_modification)           [mean]
    agreement   = 1 − disagreeing / shared, a disagreement being one explicit value above `high` and
                  another below `low` on the same signal from different probes
    coverage    = min(coverage contributions, probe-status penalty)
    confidence  = min(agreement, coverage, model_certainty)
    risk        = consequence × max(suspicion, u × (1 − confidence))

Absent signals contribute nothing (0 in a product of complements, 0 in a max). Monotonic: raising any
sub-score never lowers its parent.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..enums import ProbeStatus
from ..probes.base import Envelope
from .merge import Merged
from .params import ConvergenceParams
from .registry import SIGNALS


@dataclass
class Tiers:
    suspicion: float
    consequence: float
    confidence: float
    agreement: float
    coverage: float
    model_certainty: float | None
    taint_link: float
    disagreements: list[tuple[str, float, float]]  # (signal, low, high)
    risk: float  # 0–1


def _noisy_or(values: list[float]) -> float:
    acc = 1.0
    for v in values:
        acc *= 1.0 - min(1.0, max(0.0, v))
    return 1.0 - acc


def agreement(
    merged: Merged, params: ConvergenceParams
) -> tuple[float, list[tuple[str, float, float]]]:
    shared = 0
    disagreements: list[tuple[str, float, float]] = []
    for signal, claims in merged.claims.items():
        spec = SIGNALS[signal]
        if spec.tier == "confidence":
            continue
        by_step: dict[str, float] = {}
        for c in claims:
            by_step[c.step] = max(by_step.get(c.step, 0.0), c.value)
        if len(by_step) < 2:
            continue
        shared += 1
        lo, hi = min(by_step.values()), max(by_step.values())
        if hi > params.agreement_high and lo < params.agreement_low:
            disagreements.append((signal, lo, hi))
    if shared == 0:
        return 1.0, []
    return 1.0 - len(disagreements) / shared, disagreements


def probe_status_penalty(envelopes: list[Envelope], params: ConvergenceParams) -> float:
    penalty = 1.0
    for env in envelopes:
        if env.status is ProbeStatus.ERROR:
            penalty = min(penalty, params.coverage_penalty.get("error", 0.5))
        elif env.status is ProbeStatus.TIMEOUT:
            penalty = min(penalty, params.coverage_penalty.get("timeout", 0.6))
        elif env.status is ProbeStatus.SKIPPED:
            penalty = min(penalty, params.coverage_penalty.get("skipped", 1.0))
    return penalty


def compute(merged: Merged, envelopes: list[Envelope], params: ConvergenceParams) -> Tiers:
    g = merged.value_or
    taint_link = g("suspicion.untrusted_origin", 0.0) * max(
        g("suspicion.exposure", 0.0), params.taint_floor
    )
    suspicion = _noisy_or(
        [
            g("suspicion.misalignment", 0.0),
            g("suspicion.concealment", 0.0),
            g("suspicion.distrust", 0.0),
            taint_link,
            g("suspicion.request_origin", 0.0),
            g("suspicion.retry_after_denial", 0.0),
        ]
    )
    sens, reach, irr, selfmod = (
        g("consequence.sensitivity", 0.0),
        g("consequence.reach", 0.0),
        g("consequence.irreversibility", 0.0),
        g("consequence.self_modification", 0.0),
    )
    if params.consequence == "mean":
        consequence = max((sens + reach + irr) / 3.0, selfmod)
    else:
        consequence = max(sens * reach, irr * reach, selfmod)

    agree, disagreements = agreement(merged, params)
    coverage = min(g("confidence.coverage", 1.0), probe_status_penalty(envelopes, params))
    certainty = merged.get("confidence.model_certainty")
    confidence = min([agree, coverage] + ([certainty] if certainty is not None else []))
    risk = consequence * max(suspicion, params.u * (1.0 - confidence))
    return Tiers(
        suspicion=round(suspicion, 6),
        consequence=round(consequence, 6),
        confidence=round(confidence, 6),
        agreement=round(agree, 6),
        coverage=round(coverage, 6),
        model_certainty=None if certainty is None else round(certainty, 6),
        taint_link=round(taint_link, 6),
        disagreements=disagreements,
        risk=round(min(1.0, max(0.0, risk)), 6),
    )
