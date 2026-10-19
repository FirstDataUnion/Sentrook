"""Merge probe contributions into leaf signals (each signal's merge rule is in the signal registry).

A `Merged` view is computed over all contributions minus an exclusion set (what relief removed), so
relief can recompute by excluding `(signal, subject)` pairs rather than mutating envelopes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..enums import ProbeStatus
from ..probes.base import Contribution, Envelope
from .registry import SIGNALS, Merge


@dataclass(frozen=True)
class Claim:
    signal: str
    value: float
    step: str
    subject: str | None
    reason: str | None


@dataclass
class Merged:
    values: dict[str, float] = field(
        default_factory=dict
    )  # merged leaf value per signal (absent = not present)
    claims: dict[str, list[Claim]] = field(default_factory=dict)  # kept claims per signal
    dropped: list[Claim] = field(default_factory=list)  # contributions to unregistered signals

    def get(self, signal: str) -> float | None:
        return self.values.get(signal)

    def value_or(self, signal: str, default: float) -> float:
        v = self.values.get(signal)
        return default if v is None else v

    def contributors(self, signal: str) -> set[str]:
        return {c.step for c in self.claims.get(signal, ())}


def collect(envelopes: list[Envelope]) -> list[Claim]:
    out: list[Claim] = []
    for env in envelopes:
        if env.status is not ProbeStatus.OK:
            continue
        for c in env.contributions:
            out.append(Claim(c.signal, float(c.value), env.step.value, c.subject, c.reason))
    return out


def merge(claims: list[Claim], excluded: set[tuple[str, str | None]] | None = None) -> Merged:
    excluded = excluded or set()
    merged = Merged()
    for claim in claims:
        spec = SIGNALS.get(claim.signal)
        if spec is None:
            merged.dropped.append(claim)
            continue
        if (claim.signal, claim.subject) in excluded:
            continue
        merged.claims.setdefault(claim.signal, []).append(claim)
    for signal, kept in merged.claims.items():
        spec = SIGNALS[signal]
        vals = [c.value for c in kept]
        if spec.merge is Merge.MIN:
            merged.values[signal] = min(vals)
        else:
            merged.values[signal] = max(vals)
    return merged


def contribution_to_claim(c: Contribution, step: str) -> Claim:
    return Claim(c.signal, float(c.value), step, c.subject, c.reason)
