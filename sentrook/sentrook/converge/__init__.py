"""Convergence: probe envelopes → Response 2.0 and a new token.

Order: merge → tier scores → risk → relief (recompute) → floors → reasons → tool description → flags
and token. Only numbers, enums and opaque entity IDs enter here; no request text.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime

from ..enums import Enforce, ProbeStatus, ProbeStep, ScanStatus, SessionFlag
from ..prepare import Prepared
from ..probes.base import Envelope
from ..response.models import (
    ConfidenceTier,
    ConsequenceTier,
    EntityDisplay,
    FloorApplied,
    Metadata,
    ProbeMeta,
    Reason,
    ReliefApplied,
    Response,
    RiskTree,
    SuspicionTier,
)
from ..state.token import encode_state
from .describe import describe, entity_table
from .formulas import Tiers, compute
from .merge import Merged, collect, merge
from .params import ConvergenceParams, load_params
from .registry import SIGNALS
from .relief import Relief, compute_relief

__all__ = ["converge", "ConvergeResult", "ConvergenceParams", "load_params"]

_ENFORCE_ORDER = {None: 0, Enforce.REVIEW: 1, Enforce.BLOCK: 2}
_DEGRADING_COVERAGE = {
    "input_truncated",
    "content_dropped",
    "content_missing",
    "written_file_truncated",
    "written_file_not_visible",
}


@dataclass
class ConvergeResult:
    response: Response
    tiers: Tiers
    merged: Merged
    relief: list[Relief] = field(default_factory=list)
    flags: set[SessionFlag] = field(default_factory=set)
    state_token: str | None = None


def _tree(merged: Merged, tiers: Tiers) -> RiskTree:
    g = merged.get
    return RiskTree(
        suspicion=SuspicionTier(
            score=tiers.suspicion,
            exposure=g("suspicion.exposure"),
            untrusted_origin=g("suspicion.untrusted_origin"),
            misalignment=g("suspicion.misalignment"),
            concealment=g("suspicion.concealment"),
            overreach=g("suspicion.overreach"),
            distrust=g("suspicion.distrust"),
            request_origin=g("suspicion.request_origin"),
            retry_after_denial=g("suspicion.retry_after_denial"),
        ),
        consequence=ConsequenceTier(
            score=tiers.consequence,
            sensitivity=g("consequence.sensitivity"),
            reach=g("consequence.reach"),
            irreversibility=g("consequence.irreversibility"),
            self_modification=g("consequence.self_modification"),
        ),
        confidence=ConfidenceTier(
            score=tiers.confidence,
            agreement=tiers.agreement,
            coverage=tiers.coverage,
            model_certainty=tiers.model_certainty,
        ),
    )


def _reasons(
    merged: Merged,
    tiers: Tiers,
    floors: list[FloorApplied],
    relief: list[Relief],
    params: ConvergenceParams,
    u: float,
) -> list[Reason]:
    """Ordered by contribution to the result. Floors first, then relief that applied, then weighted
    leaf contributions: a suspicion claim weighs its value × consequence, a consequence claim its value
    × suspicion, a confidence claim (1 − value) × u × consequence."""
    scored: list[tuple[float, Reason]] = []
    for f in floors:
        scored.append(
            (
                10.0 + f.min_risk,
                Reason(
                    code=f"floor.{f.floor}",
                    signal=None,
                    subject=f.subject,
                    detail={"reason": f.reason} if f.reason else None,
                ),
            )
        )
    for r in relief:
        scored.append(
            (
                5.0,
                Reason(
                    code=r.reason,
                    signal=None,
                    subject=r.subject,
                    detail={"grant_ref": r.grant_ref, "effect": r.effect},
                ),
            )
        )
    seen: set[tuple[str, str | None]] = set()
    for signal, claims in merged.claims.items():
        spec = SIGNALS[signal]
        for c in claims:
            if c.reason is None:
                continue
            if spec.tier == "suspicion":
                weight = c.value * max(tiers.consequence, 0.05)
            elif spec.tier == "consequence":
                weight = c.value * max(tiers.suspicion, 0.05)
            else:
                weight = (1.0 - c.value) * u * max(tiers.consequence, 0.05)
            if spec.higher_is_worse and c.value < params.reason_min_value:
                continue
            if not spec.higher_is_worse and c.value >= 1.0:
                continue
            key = (c.reason, c.subject)
            if key in seen:
                continue
            seen.add(key)
            scored.append((weight, Reason(code=c.reason, signal=signal, subject=c.subject)))
    for signal, lo, hi in tiers.disagreements:
        tier = signal.split(".", 1)[0]
        scored.append(
            (
                0.5,
                Reason(
                    code=f"agreement.{tier}_split",
                    signal="confidence.agreement",
                    detail={"signal": signal, "low": round(lo, 3), "high": round(hi, 3)},
                ),
            )
        )
    scored.sort(key=lambda t: -t[0])
    return [r for _, r in scored]


def converge(
    prepared: Prepared,
    envelopes: list[Envelope],
    *,
    params: ConvergenceParams,
    scanner_version: str,
    token_key: str | bytes,
    started: float | None = None,
    probes_enabled: list[str] | None = None,
    views: str = "trim-v1",
) -> ConvergeResult:
    claims = collect(envelopes)
    merged = merge(claims)
    tiers = compute(merged, envelopes, params)

    known_good = [
        eid
        for env in envelopes
        if env.step is ProbeStep.ENTITY_ORACLE and env.status is ProbeStatus.OK
        for eid, info in (env.evidence.get("entities") or {}).items()
        if isinstance(info, dict) and info.get("verdict") == "known_good"
    ]
    relief = compute_relief(prepared, params, known_good)
    if relief:
        excluded = {pair for r in relief for pair in r.excluded}
        merged = merge(claims, excluded)
        tiers = compute(merged, envelopes, params)

    floors: list[FloorApplied] = []
    risk = tiers.risk
    enforced: Enforce | None = None
    for env in envelopes:
        if env.status is not ProbeStatus.OK:
            continue
        for f in env.floors:
            floors.append(
                FloorApplied(
                    floor=f.floor,
                    min_risk=f.min_risk,
                    enforce=f.enforce,
                    subject=f.subject,
                    reason=f.reason,
                )
            )
            risk = max(risk, f.min_risk)
            if _ENFORCE_ORDER[f.enforce] > _ENFORCE_ORDER[enforced]:
                enforced = f.enforce
    tiers.risk = round(risk, 6)

    flags = set(prepared.state.flags)
    for env in envelopes:
        if env.status is ProbeStatus.OK:
            flags.update(env.flags_set)

    probe_statuses = [env.status for env in envelopes]
    coverage_codes = {c.code for c in prepared.coverage}
    degraded = (
        any(s in (ProbeStatus.ERROR, ProbeStatus.TIMEOUT) for s in probe_statuses)
        or any(env.evidence.get("fallback") for env in envelopes)
        or bool(coverage_codes & _DEGRADING_COVERAGE)
        or prepared.state.fresh
    )
    status = ScanStatus.DEGRADED if degraded else ScanStatus.OK

    category = None
    for env in envelopes:
        if env.step.value == "jev_call" and env.status is ProbeStatus.OK:
            category = env.evidence.get("action_category")

    state = prepared.state
    state.flags = flags
    state.max_input_seq = prepared.scanned_max_seq
    token = encode_state(
        state,
        key=token_key,
        session_ref=prepared.planir.session.session_ref,
        step=prepared.planir.session.step,
        clock=prepared.clock,
    )

    latency = None if started is None else round((time.perf_counter() - started) * 1000, 1)
    entities: dict[str, EntityDisplay] = entity_table(prepared)
    reasons = _reasons(merged, tiers, floors, relief, params, params.u)
    for r in reasons:  # make sure every entity a reason names is displayable
        if r.subject and r.subject not in entities:
            ent = prepared.entities.by_id(r.subject)
            if ent is not None:
                entities[r.subject] = EntityDisplay(kind=ent.kind.value, display=ent.display)

    response = Response(
        request_id=prepared.planir.request_id,
        status=status,
        risk=round(tiers.risk * 100.0, 2),
        enforced=enforced,
        tree=_tree(merged, tiers),
        floors_applied=floors,
        relief_applied=[
            ReliefApplied(grant_ref=r.grant_ref, subject=r.subject, effect=r.effect) for r in relief
        ],
        reasons=reasons,
        tool_description=describe(prepared, category),
        entities=entities,
        action_fingerprint=prepared.fingerprint.render(),
        state=token,
        metadata=Metadata(
            scanner_version=scanner_version,
            latency_ms=latency,
            probes=[
                ProbeMeta(
                    step=env.step.value,
                    status=env.status,
                    latency_ms=env.latency_ms,
                    versions=env.versions,
                )
                for env in envelopes
            ],
            versions={
                "convergence": params.name,
                "probes_enabled": probes_enabled or [env.step.value for env in envelopes],
                "views": views,
                "taint_link": tiers.taint_link,
                "flags": sorted(f.value for f in flags),
                "token_status": prepared.state.status.value,
                "coverage_notes": sorted(coverage_codes),
            },
        ),
    )
    return ConvergeResult(
        response=response, tiers=tiers, merged=merged, relief=relief, flags=flags, state_token=token
    )


def now_utc() -> datetime:
    from datetime import UTC

    return datetime.now(tz=UTC)
