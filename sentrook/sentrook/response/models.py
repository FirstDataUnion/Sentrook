"""Response 2.0 models: the risk tree Sentrook returns to the plugin.

- Scores inside the tree are 0–1; only `risk` is 0–100. In suspicion and consequence higher is worse;
  in confidence higher is better.
- A signal is `null` when no probe evaluated it (explicit versus absent), never 0.
- The plugin decides allow / review / block from `risk` and its local thresholds, then takes the
  stricter of that and `enforced`.
- `tool_description` and `reasons` are built from categories and reason codes with templates, never
  from model-generated text. Entities are referenced as opaque IDs the plugin resolves locally.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..enums import Enforce, ProbeStatus, ScanStatus

SUSPICION_SIGNALS: tuple[str, ...] = (
    "exposure",
    "untrusted_origin",
    "misalignment",
    "concealment",
    "distrust",
    "request_origin",
    "retry_after_denial",
)
CONSEQUENCE_SIGNALS: tuple[str, ...] = (
    "sensitivity",
    "reach",
    "irreversibility",
    "self_modification",
)
CONFIDENCE_SIGNALS: tuple[str, ...] = ("agreement", "coverage", "model_certainty")

Unit = float | None  # a 0–1 score, or null when absent


class _Model(BaseModel):
    model_config = ConfigDict(extra="allow")


class _Tier(_Model):
    score: Unit = Field(default=None, ge=0, le=1, description="Tier 2 result")


class SuspicionTier(_Tier):
    """How much the call looks like it serves a goal the owner did not set. Higher is worse."""

    exposure: Unit = Field(default=None, ge=0, le=1)
    untrusted_origin: Unit = Field(default=None, ge=0, le=1)
    misalignment: Unit = Field(default=None, ge=0, le=1)
    concealment: Unit = Field(default=None, ge=0, le=1)
    distrust: Unit = Field(default=None, ge=0, le=1)
    request_origin: Unit = Field(default=None, ge=0, le=1)
    retry_after_denial: Unit = Field(default=None, ge=0, le=1)


class ConsequenceTier(_Tier):
    """The worst harm if the call runs. Higher is worse."""

    sensitivity: Unit = Field(default=None, ge=0, le=1)
    reach: Unit = Field(default=None, ge=0, le=1)
    irreversibility: Unit = Field(default=None, ge=0, le=1)
    self_modification: Unit = Field(default=None, ge=0, le=1)


class ConfidenceTier(_Tier):
    """How much to trust the other two tiers. Higher is better."""

    agreement: Unit = Field(default=None, ge=0, le=1)
    coverage: Unit = Field(default=None, ge=0, le=1)
    model_certainty: Unit = Field(default=None, ge=0, le=1)


class RiskTree(_Model):
    suspicion: SuspicionTier = Field(default_factory=SuspicionTier)
    consequence: ConsequenceTier = Field(default_factory=ConsequenceTier)
    confidence: ConfidenceTier = Field(default_factory=ConfidenceTier)


class FloorApplied(_Model):
    floor: str
    min_risk: float = Field(ge=0, le=1)
    enforce: Enforce | None = None
    subject: str | None = None
    reason: str | None = None


class ReliefApplied(_Model):
    """A grant (or the request-named destination rule, with `grant_ref` null) that lowered a score."""

    grant_ref: str | None = None
    subject: str | None = None
    effect: str = Field(
        description="What was removed, e.g. distrust+untrusted_origin, sensitivity:read"
    )


class Reason(_Model):
    """`code` is a stable `domain.detail` value from the reason registry; deployment-specific
    qualifiers (a tool alias, a step number) go in `detail` so codes stay finite and countable."""

    code: str
    signal: str | None = None
    subject: str | None = None
    detail: dict[str, Any] | None = None


class ToolDescription(_Model):
    """Templated from the Jev action category; the plugin substitutes `{E1}` placeholders."""

    category: str | None = None
    template: str | None = None


class EntityDisplay(_Model):
    kind: str
    display: str = Field(description="Trimmed display string (host only, no query strings)")


class ProbeMeta(_Model):
    """The single record of what produced each part of the result."""

    step: str
    status: ProbeStatus
    latency_ms: float | None = Field(default=None, ge=0)
    versions: dict[str, str | None] = Field(default_factory=dict)


class Metadata(_Model):
    scanner_version: str
    latency_ms: float | None = Field(default=None, ge=0)
    probes: list[ProbeMeta] = Field(default_factory=list)
    versions: dict[str, Any] = Field(
        default_factory=dict,
        description="Scan-wide versions: convergence parameter set, probes_enabled, lists",
    )


class ScanError(_Model):
    code: str
    message: str


class Response(_Model):
    response_version: Literal["2.0"] = "2.0"
    request_id: str
    status: ScanStatus = ScanStatus.OK
    risk: float | None = Field(
        default=None, ge=0, le=100, description="0–100; null only when status is error"
    )
    enforced: Enforce | None = Field(
        default=None, description="Strongest enforcement of any applied floor"
    )
    tree: RiskTree = Field(default_factory=RiskTree)
    floors_applied: list[FloorApplied] = Field(default_factory=list)
    relief_applied: list[ReliefApplied] = Field(default_factory=list)
    reasons: list[Reason] = Field(
        default_factory=list, description="Ordered by contribution to the result"
    )
    tool_description: ToolDescription | None = None
    entities: dict[str, EntityDisplay] = Field(default_factory=dict)
    action_fingerprint: str | None = Field(
        default=None, description="Echoed back by the plugin in history; opaque to it"
    )
    state: str | None = Field(default=None, description="New signed state token")
    error: ScanError | None = Field(default=None, description="Only when status is error")
    metadata: Metadata

    @classmethod
    def empty(cls, request_id: str, scanner_version: str) -> Response:
        """A response with every signal absent, for a scan that has not run its probes yet."""
        return cls(request_id=request_id, metadata=Metadata(scanner_version=scanner_version))

    @classmethod
    def errored(cls, request_id: str, scanner_version: str, code: str, message: str) -> Response:
        """The error shape: no risk, `status: error`, the plugin's fail-open or fail-closed policy applies."""
        return cls(
            request_id=request_id,
            status=ScanStatus.ERROR,
            error=ScanError(code=code, message=message[:2000]),
            metadata=Metadata(scanner_version=scanner_version),
        )
