"""The probe result envelope (skeleton 3.1) and the `Probe` protocol.

Every probe returns the same envelope. Its native output stays bespoke in `evidence` (logs, debugging,
TestNest; never used in maths); its claims about signals go in `contributions`; hard signals that must
never be lowered go in `floors`; session flags to set at the end of convergence go in `flags_set`.

Explicit versus absent (skeleton, Conventions): a probe emits a contribution only for a signal it
actually evaluated. Absent means no opinion. For suspicion and consequence signals an explicit 0 means
"evaluated, no evidence found"; for confidence signals the value is the measured confidence.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from ..enums import Enforce, ProbeStatus, ProbeStep, SessionFlag


class Contribution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal: str = Field(description="Registry name, e.g. consequence.reach")
    value: float = Field(ge=0, le=1)
    subject: str | None = Field(
        default=None, description="Opaque entity ID (E1, E2, …) when the claim is about one entity"
    )
    reason: str | None = Field(
        default=None, description="Reason code (domain.detail) for the review card"
    )


class Floor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    floor: str = Field(
        description="guardrail_tampering | known_bad_entity | untrusted_code_execution | …"
    )
    min_risk: float = Field(ge=0, le=1, description="Minimum risk, on the same 0–1 scale as risk")
    enforce: Enforce | None = Field(
        default=None, description="Minimum outcome; null raises the score only"
    )
    subject: str | None = None
    reason: str | None = None


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step: ProbeStep
    versions: dict[str, str | None] = Field(
        default_factory=dict,
        description="Everything that determines this probe's output; keys vary by probe (skeleton 3.1)",
    )
    status: ProbeStatus = ProbeStatus.OK
    latency_ms: float | None = Field(default=None, ge=0)
    contributions: list[Contribution] = Field(default_factory=list)
    floors: list[Floor] = Field(default_factory=list)
    flags_set: list[SessionFlag] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def failed(
        cls,
        step: ProbeStep,
        status: ProbeStatus,
        message: str,
        versions: dict[str, str | None] | None = None,
        latency_ms: float | None = None,
    ) -> Envelope:
        """An envelope for a probe that produced no answer. The scan continues as `degraded`."""
        if status is ProbeStatus.OK:
            raise ValueError("a failed envelope cannot have status ok")
        return cls(
            step=step,
            versions=dict(versions or {}),
            status=status,
            latency_ms=latency_ms,
            evidence={"error": message[:2000]},
        )

    @classmethod
    def skipped(
        cls, step: ProbeStep, reason: str, versions: dict[str, str | None] | None = None
    ) -> Envelope:
        """An envelope for a probe that was disabled (ablation) or had nothing to evaluate."""
        return cls(
            step=step,
            versions=dict(versions or {}),
            status=ProbeStatus.SKIPPED,
            evidence={"skipped": reason},
        )


@runtime_checkable
class Probe(Protocol):
    """A probe runs over the prepared request and returns one envelope. It must not raise: a failure is
    an envelope with `status` error or timeout. `prepared` is the `Prepared` object from WP1."""

    step: ProbeStep

    @property
    def versions(self) -> dict[str, str | None]: ...

    def run(self, prepared: Any) -> Envelope: ...
