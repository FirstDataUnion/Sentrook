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
    "session_exposure",
    "untrusted_origin",
    "misalignment",
    "concealment",
    "overreach",
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

    exposure: Unit = Field(
        default=None,
        ge=0,
        le=1,
        description="This scan's new untrusted inputs carried agent-directed instructions",
    )
    session_exposure: Unit = Field(
        default=None,
        ge=0,
        le=1,
        description="Earlier in this session the agent read content carrying instructions aimed at it",
    )
    untrusted_origin: Unit = Field(default=None, ge=0, le=1)
    misalignment: Unit = Field(default=None, ge=0, le=1)
    concealment: Unit = Field(default=None, ge=0, le=1)
    overreach: Unit = Field(
        default=None,
        ge=0,
        le=1,
        description="The call acts on more than the request covers, judged against what the agent read",
    )
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


class GrantHint(_Model):
    """A grant the owner could set so that a call like this would usually not be reviewed next time (the next scan's
    model sees the grant too, so it is not a promise). Offered only on the owner's own turns, and only when the
    scanner, re-scoring this call with the grant applied (the same probe answers, no new model call), finds
    the risk below the review line. Never for a known-bad entity, a look-alike, content the agent read, an
    `enforced` decision or a call with an independent strong signal."""

    kind: Literal["destination", "file", "provider"] = Field(
        description="The grant kind, as `/sentrook grant` takes it"
    )
    pattern: str = Field(
        description=(
            "The grant pattern: the entity's value as the scanner reads it (a path under the home directory written "
            "with `~/`), never a secret"
        )
    )
    allows: list[str] | None = Field(
        default=None, description="For a file grant: what the call does to the file"
    )
    scope: Literal["persistent"] = "persistent"
    expires_in_days: int = Field(default=30, ge=1, le=365)
    subject: str | None = Field(
        default=None, description="The entity it covers (an `entities` key)"
    )
    relieves: list[str] = Field(
        default_factory=list, description="The reason codes in `reasons` the grant would remove"
    )
    risk: float = Field(ge=0, le=100, description="This call's risk with the grant applied, 0-100")


class Reason(_Model):
    """`code` is a stable `domain.detail` value from the reason registry; deployment-specific
    qualifiers (a tool alias, a step number) go in `detail` so codes stay finite and countable."""

    code: str
    signal: str | None = None
    subject: str | None = None
    detail: dict[str, Any] | None = None
    text: str | None = Field(
        default=None,
        description=(
            "The reason in plain words for the review card, from a fixed list: a clause in lower case with no full "
            "stop, which may name the subject as its `{E1}` placeholder. Null for a reason that does not say why "
            "the call is risky (relief, gaps in what the scan could check, split model answers) and for a repeat of "
            "an earlier reason's text."
        ),
    )


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


SaveAdds = Literal["command", "destination", "permission", "secret"]


class SelfEditSave(_Model):
    """What a self-edit's saved content adds, read by rule from the written text, and whether the save qualifies for
    lenient handling. Present only on a self-edit (trigger `system` with a `self_edit` block)."""

    adds: list[SaveAdds] = Field(
        default_factory=list,
        description=(
            "Sorted and de-duplicated: `command` runnable steps; `destination` a host, URL, mail address, recipient "
            "or remote a later run reaches or sends to; `permission` a step that changes permissions, tool "
            "allowlists, host or agent config, plugins, hooks, the scheduler, approval or safety settings, or "
            "privilege (not the write into the memory or skill store itself); `secret` a secret-like value or a "
            "redaction placeholder"
        ),
    )
    lenient: bool = Field(
        default=False,
        description=(
            "True only when `adds` is empty or only `command`; the save writes content the scanner read, removes "
            "nothing the request shows, holds no code the rules cannot read and targets the declared store; the "
            "scan's status is ok; no rule fired on the saved content and no floor applies; the entity lookup "
            "answered; and the self-edit judge answered with its directive-from-read-content, loosened-oversight, "
            "unsupported-owner-claim and saved-secret answers, and its probability of hidden intent, all below 0.7. "
            "Says nothing about the verdict: a plugin consults it only when the risk is in its review band, for a "
            "background save nobody can be asked about"
        ),
    )


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
    ceiling: Literal["review"] | None = Field(
        default=None,
        description=(
            "Highest outcome the plugin may reach from risk: it decides from risk and its lines, lowers that to "
            "the ceiling, then raises it to `enforced`. Set when the owner attends the chat and nothing independent "
            "points to an attack; never together with `enforced`. A plugin that ignores it still blocks."
        ),
    )
    relaxable: Literal[True] | None = Field(
        default=None,
        description=(
            "True when the owner attends the chat, the scan is fully informed, nothing independent points to an "
            "attack and nothing is `enforced`: a block here comes from the score alone. A plugin may then turn such "
            "a block into a review it always asks about, only while the owner has snoozed reviews; it never allows "
            "it silently. Null otherwise; it never changes `risk`. A plugin that ignores it still blocks."
        ),
    )
    tree: RiskTree = Field(default_factory=RiskTree)
    floors_applied: list[FloorApplied] = Field(default_factory=list)
    relief_applied: list[ReliefApplied] = Field(default_factory=list)
    reasons: list[Reason] = Field(
        default_factory=list, description="Ordered by contribution to the result"
    )
    grant_hints: list[GrantHint] = Field(
        default_factory=list,
        description=(
            "Up to three grants, each of which alone would bring this call below the review line next time, "
            "lowest resulting risk first. Empty when none would, and on every call below the line."
        ),
    )
    tool_description: ToolDescription | None = None
    entities: dict[str, EntityDisplay] = Field(default_factory=dict)
    action_fingerprint: str | None = Field(
        default=None, description="Echoed back by the plugin in history; opaque to it"
    )
    approval_fingerprint: str | None = Field(
        default=None,
        description="The same action in every session of this deployment (its entities hashed with a salt derived "
        "from the scanner's key, not the session's): what a plugin keys an owner's remembered approval on; opaque "
        "to it and used for nothing else",
    )
    state: str | None = Field(default=None, description="New signed state token")
    error: ScanError | None = Field(default=None, description="Only when status is error")
    self_edit: SelfEditSave | None = Field(
        default=None,
        exclude_if=lambda v: v is None,
        description="Only on a self-edit: what the saved content adds and whether the save qualifies for lenient "
        "handling; absent otherwise",
    )
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
