"""Convergence: probe envelopes → Response 2.0 and a new token.

Order: (the model's sensitivity held under the credential-home relief) → merge → tier scores → risk → relief (recompute) → attended-owner check (the `relaxable` mark always; the ceiling when the parameters turn it on)
→ floors → unanswered-review retry cap (`retry_cap`: a ceiling of review) → local-code cap (`local_cap`: a ceiling of review for
a code tool's program with no network sink in sight) → reasons → grant hints (a deterministic re-score per candidate grant, `hints`) → owner pass (`owner_pass`: whether a held
call may be passed once, always or not at all) → tool description → flags and token. Only numbers, enums and opaque entity IDs enter here; no request text.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from datetime import datetime

from ..aira.detectors import call_label
from ..enums import Enforce, ProbeStatus, ProbeStep, ScanStatus, SessionFlag
from ..planir.models import ToolKind
from ..prepare import INPUT_TOO_LARGE, Prepared, kernel_effects_of, kernel_hashes
from ..prepare.entities import EntityKind
from ..prepare.save_adds import SaveReading
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
from ..state.token import PendingMarks, call_hash, encode_state
from .attended import DEFAULT_BLOCK_LINE, relaxable, withheld
from .attended import check as attended_check
from .describe import describe, entity_table
from .formulas import Tiers, compute
from .hints import grant_hints
from .local_cap import REASON as LOCAL_CAP_REASON
from .local_cap import local_cap
from .merge import Claim, Merged, collect, merge
from .owner_pass import owner_pass
from .params import ConvergenceParams, load_params
from .registry import SIGNALS, reason_text
from .relief import Relief, compute_relief
from .retry_cap import REASON as RETRY_CAP_REASON
from .retry_cap import risk_without_retry, unanswered_retry
from .self_edit import self_edit_save

__all__ = ["converge", "ConvergeResult", "ConvergenceParams", "load_params"]

_ENFORCE_ORDER = {None: 0, Enforce.REVIEW: 1, Enforce.BLOCK: 2}
#: The floor for a call of this request that was over preparation's bounds (`INPUT_TOO_LARGE`): always the owner's review, scored like the other review floor.
INPUT_TOO_LARGE_MIN_RISK = 0.5

_DEGRADING_COVERAGE = {
    INPUT_TOO_LARGE,
    "input_truncated",
    "content_dropped",
    "content_missing",
    "written_file_truncated",
    "written_file_not_visible",
    "argument_dropped",
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
            session_exposure=g("suspicion.session_exposure"),
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


#: Flags a scan sets from the pending call's own read: they wait in the token until the call is known to have run.
OWN_READ_FLAGS = frozenset({SessionFlag.HOLDS_SENSITIVE})


def _add_new(into: list[str], hashes: list[str]) -> None:
    into.extend(h for h in hashes if h not in into)


def _mint_session_sets(
    prepared: Prepared,
    envelopes: list[Envelope],
    own_flags: frozenset[SessionFlag] | set[SessionFlag] = frozenset(),
) -> PendingMarks:
    """Add what this scan's judgements are about to the token's sets: the files and tables an injected
    result's call produced (when the judgement was about that input alone), and moving anything an injected
    input added to the trusted set into the untrusted set. Those results came from calls that ran.

    What the pending call itself would add waits in the token, keyed to the call, until a later scan's
    history shows it ran (`state.token.settle_pending`): `own_flags`, the files a sensitive judgement names
    (or the unbound marker when it names none), and the local files the call writes from a file already in a
    set (or that it read itself). Returns those pending marks."""
    state = prepared.state
    marks = PendingMarks(
        call=call_hash(state.salt, prepared.planir.pending_call.call_id),
        flags=set(own_flags),
    )
    # What a code-tool call leaves in the conversation's interpreter for later programs.
    effects = kernel_effects_of(state, prepared.pending)
    if effects is not None:
        marks.kernel = sorted(kernel_hashes(state, effects.names))
        marks.kernel_unknown = effects.unknown
    for env in envelopes:
        if env.status is not ProbeStatus.OK:
            continue
        for m in env.marks:
            if m.judgement == "sensitive":
                ent = prepared.entities.by_id(m.subject) if m.subject else None
                if m.subject is None:
                    marks.sensitive_unbound = True
                elif ent is not None and ent.hash and ent.kind is EntityKind.PATH:
                    _add_new(marks.sensitive, [ent.hash])
            elif m.input_seq is not None:
                if m.attributed:
                    state.add_tainted(prepared.producer_artefacts.get(m.input_seq, []))
                # Config content judged injected is not the owner's: what it supplied is untrusted.
                withdrawn = prepared.trusted_by_input.get(m.input_seq, [])
                state.drop_trusted(withdrawn)
                state.add_untrusted(withdrawn)
                # Other content named them: a skill naming them too no longer excuses them.
                state.drop_skill_named(withdrawn)
            elif m.subject is not None:
                ent = prepared.entities.by_id(m.subject)
                if ent is not None and ent.hash and ent.kind is EntityKind.PATH:
                    _add_new(marks.tainted, [ent.hash])
    binding = prepared.session_binding
    if binding.writes:
        if any(h in state.sensitive or h in marks.sensitive for h in binding.takes):
            _add_new(marks.sensitive, binding.writes)
        if any(h in state.tainted or h in marks.tainted for h in binding.takes):
            _add_new(marks.tainted, binding.writes)
    state.add_pending(marks)
    return marks


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


def _fill_reason_text(reasons: list[Reason], entities: dict[str, EntityDisplay]) -> None:
    """Each reason's plain words for the review card (`registry.reason_text`), naming its subject by its placeholder
    when the plugin can show it. A floor speaks with the words of the reason it records (`detail.reason`), so the
    claim behind it does not say the same thing again: a reason whose words repeat an earlier one's gets none."""
    shown: set[str] = set()
    for r in reasons:
        behind = (r.detail or {}).get("reason") if r.code.startswith("floor.") else None
        text = (reason_text(behind) if isinstance(behind, str) else None) or reason_text(r.code)
        if text is None:
            continue
        named = r.subject is not None and r.subject in entities
        words = text.subject.replace("{subject}", "{" + r.subject + "}") if named else text.plain
        if words not in shown:
            shown.add(words)
            r.text = words


def cap_model_sensitivity(claims: list[Claim], cap: float) -> list[Claim]:
    """The model's call-level sensitivity held to `cap`: with the credential-home relief the call's credential no
    longer counts, so what the call moves is at most the level below credentials."""
    return [
        replace(c, value=min(c.value, cap))
        if c.signal == "consequence.sensitivity" and c.step == ProbeStep.JEV_CALL.value
        else c
        for c in claims
    ]


def exposure_unjudged(prepared: Prepared, envelopes: list[Envelope]) -> bool:
    """The request brings new untrusted content the exposure probe would judge (not only reads of the agent's own
    skills or memory, or of the owner's own instruction files), and no exposure envelope came back OK: the probe failed, timed out or did not run, so nobody
    looked at that content. A probe skipped because there was nothing new to read is not this."""
    if not any(
        i.input.content and i.input.input_seq not in prepared.exposure_left_out
        for i in prepared.untrusted_inputs(new_only=True)
    ):
        return False
    return not any(
        env.step is ProbeStep.JEV_EXPOSURE and env.status is ProbeStatus.OK for env in envelopes
    )


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
    self_edit_reading: SaveReading | None = None,
) -> ConvergeResult:
    """`self_edit_reading`: what a self-edit's saved content adds and whether the reading can vouch for it
    (`prepare.save_adds`), None for any other scan; it sets `Response.self_edit` and nothing else."""

    def hold_claims(cs: list[Claim]) -> list[Claim]:
        if params.credential_home and prepared.credential_home is not None:
            return cap_model_sensitivity(cs, params.credential_home_model_sensitivity_cap)
        return cs

    claims = hold_claims(collect(envelopes))
    merged = merge(claims)
    unjudged = exposure_unjudged(prepared, envelopes)
    tiers = compute(merged, envelopes, params, exposure_unjudged=unjudged)

    known_good = [
        eid
        for env in envelopes
        if env.step is ProbeStep.ENTITY_ORACLE and env.status is ProbeStatus.OK
        for eid, info in (env.evidence.get("entities") or {}).items()
        if isinstance(info, dict) and info.get("verdict") == "known_good"
    ]
    # What a config read supplied is not the owner's when this scan judges that read injected.
    withdrawn_trust = {
        h
        for env in envelopes
        if env.status is ProbeStatus.OK
        for m in env.marks
        if m.judgement != "sensitive" and m.input_seq is not None
        for h in prepared.trusted_by_input.get(m.input_seq, [])
    }
    known_good_exact = [
        eid
        for env in envelopes
        if env.step is ProbeStep.ENTITY_ORACLE and env.status is ProbeStatus.OK
        for eid, info in (env.evidence.get("entities") or {}).items()
        if isinstance(info, dict)
        and info.get("verdict") == "known_good"
        and info.get("match") == "exact"
    ]
    # Hosts the owner's request names by their service, where the call judge read the request as meaning the service.
    service_named = [
        eid
        for env in envelopes
        if env.step is ProbeStep.JEV_CALL
        and env.status is ProbeStatus.OK
        and (env.evidence.get("names_service") or 0.0) >= params.service_name_min_yes
        for eid in env.evidence.get("services_sent") or []
    ]
    relief = compute_relief(
        prepared,
        params,
        known_good,
        withdrawn_trust,
        known_good_exact=known_good_exact,
        exposure=merged.get("suspicion.exposure"),
        service_named=service_named,
    )
    excluded = {pair for r in relief for pair in r.excluded}
    if relief:
        merged = merge(claims, excluded)
        tiers = compute(merged, envelopes, params, exposure_unjudged=unjudged)

    retry_unanswered = unanswered_retry(envelopes)
    cap = attended_check(
        prepared,
        claims,
        [c for kept in merged.claims.values() for c in kept],
        [(r.subject, r.reason) for r in relief],
        [f.floor for env in envelopes if env.status is ProbeStatus.OK for f in env.floors],
        params,
        unanswered_retry=retry_unanswered,
    )

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
    coverage_codes = {c.code for c in prepared.coverage}
    if INPUT_TOO_LARGE in coverage_codes:
        # Nobody read all of the call, so the owner is asked whatever the probes found in the part
        # that was read. Applied here, not by a probe, so it holds when a probe fails.
        floors.append(
            FloorApplied(
                floor=INPUT_TOO_LARGE,
                min_risk=INPUT_TOO_LARGE_MIN_RISK,
                enforce=Enforce.REVIEW,
                subject=None,
                reason=f"coverage.{INPUT_TOO_LARGE}",
            )
        )
        risk = max(risk, INPUT_TOO_LARGE_MIN_RISK)
        if _ENFORCE_ORDER[Enforce.REVIEW] > _ENFORCE_ORDER[enforced]:
            enforced = Enforce.REVIEW
    tiers.risk = round(risk, 6)

    # A retry of a review nobody answered may ask, never block on its own (`retry_cap`).
    retry_cap: dict | None = None
    if retry_unanswered:
        alone = risk_without_retry(
            claims,
            excluded,
            envelopes,
            params,
            [f.min_risk for f in floors],
            exposure_unjudged=unjudged,
        )
        retry_cap = {
            "risk_without_retry": round(alone * 100.0, 2),
            "capped": enforced is not Enforce.BLOCK
            and alone < DEFAULT_BLOCK_LINE
            and tiers.risk > alone,
        }

    flags = set(prepared.state.flags)
    for env in envelopes:
        if env.status is ProbeStatus.OK:
            flags.update(env.flags_set)

    probe_statuses = [env.status for env in envelopes]
    degraded = (
        any(s in (ProbeStatus.ERROR, ProbeStatus.TIMEOUT) for s in probe_statuses)
        or any(env.evidence.get("fallback") for env in envelopes)
        or bool(coverage_codes & _DEGRADING_COVERAGE)
        or prepared.state.fresh
    )
    status = ScanStatus.DEGRADED if degraded else ScanStatus.OK
    if retry_cap is not None and degraded:
        # the risk without the retry rests on partial evidence: no cap, as for the attended ceiling
        retry_cap["capped"] = False
        retry_cap["withheld"] = "degraded"

    # A code tool's program with no network sink in sight may be reviewed or held, never blocked (`local_cap`).
    code_cap = local_cap(
        envelopes,
        excluded,
        params,
        hold_claims=hold_claims,
        extra_floor_risks=[f.min_risk for f in floors if f.floor == INPUT_TOO_LARGE],
        enforced=enforced,
        risk=tiers.risk,
        degraded=degraded,
        exposure_unjudged=unjudged,
    )
    local_capped = bool(code_cap and code_cap.capped)
    text_blocks = enforced is Enforce.BLOCK or tiers.risk >= DEFAULT_BLOCK_LINE
    if code_cap is not None and local_capped:
        # the floors and enforcement are the code reading's; the risk stays as scored
        floors = [f for f in floors if f.floor == INPUT_TOO_LARGE] + [
            FloorApplied(
                floor=f.floor,
                min_risk=f.min_risk,
                enforce=f.enforce,
                subject=f.subject,
                reason=f.reason,
            )
            for f in code_cap.floors
        ]
        enforced = code_cap.enforced

    not_informed = withheld(
        envelopes,
        degraded=degraded,
        state_lost=prepared.state.fresh,
        exposure_unjudged=unjudged,
    )
    held_back = not_informed if cap.attended else []
    # One check: the mark in every parameter set, the ceiling only where the parameters turn it on.
    relax = relaxable(cap, held_back, enforced)
    attended_ceiling = relax and params.attended_owner_cap
    retry_capped = bool(retry_cap and retry_cap["capped"])
    ceiling: str | None = "review" if attended_ceiling or retry_capped or local_capped else None
    attended = {
        "attended": cap.attended,
        "strong": cap.strong,
        "withheld": held_back,
        "relaxable": relax,
        "ceiling": ceiling,
    }

    category = None
    for env in envelopes:
        if env.step.value == "jev_call" and env.status is ProbeStatus.OK:
            category = env.evidence.get("action_category")

    state = prepared.state
    # `flags` stays this scan's whole view (hints, metadata); the token holds the call's own read back.
    own_flags = {f for f in flags if f in OWN_READ_FLAGS} - state.flags
    state.flags = flags - own_flags
    state.max_input_seq = prepared.scanned_max_seq
    state.add_impact(tiers.impact)
    pending = _mint_session_sets(prepared, envelopes, own_flags)
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
    # why the call is held for review rather than blocked: first when the risk reaches the default block line
    for code, applies in (
        (LOCAL_CAP_REASON, local_capped),
        (RETRY_CAP_REASON, retry_capped),
        ("cap.attended_owner", attended_ceiling),
    ):
        if not applies:
            continue
        cap_reason = Reason(code=code, detail={"ceiling": "review"})
        if tiers.risk >= DEFAULT_BLOCK_LINE or (code == LOCAL_CAP_REASON and text_blocks):
            reasons.insert(0, cap_reason)
        else:
            reasons.append(cap_reason)
    hints = grant_hints(
        prepared,
        claims,
        envelopes,
        relief,
        reasons,
        params,
        risk=tiers.risk,
        enforced=enforced,
        floors=[f.floor for f in floors],
        degraded=degraded,
        exposure_unjudged=unjudged,
        flags=flags,
    )
    passable = owner_pass(
        prepared,
        claims,
        [c for kept in merged.claims.values() for c in kept],
        [(r.subject, r.reason) for r in relief],
        [f.floor for f in floors],
        params,
        enforced=enforced,
        held_back=not_informed,
        flags=flags,
        unanswered_retry=retry_unanswered,
    )
    # make sure every entity a reason or a hint names is displayable
    for r in [*reasons, *hints]:
        if r.subject and r.subject not in entities:
            ent = prepared.entities.by_id(r.subject)
            if ent is not None:
                entities[r.subject] = EntityDisplay(kind=ent.kind.value, display=ent.display)
    _fill_reason_text(reasons, entities)

    response = Response(
        request_id=prepared.planir.request_id,
        status=status,
        risk=round(tiers.risk * 100.0, 2),
        enforced=enforced,
        ceiling=ceiling,
        relaxable=True if relax else None,
        tree=_tree(merged, tiers),
        floors_applied=floors,
        relief_applied=[
            ReliefApplied(grant_ref=r.grant_ref, subject=r.subject, effect=r.effect) for r in relief
        ],
        reasons=reasons,
        grant_hints=hints,
        owner_pass=passable,
        tool_description=describe(prepared, category),
        entities=entities,
        action_fingerprint=prepared.fingerprint.render(),
        approval_fingerprint=prepared.approval_fingerprint or None,
        state=token,
        self_edit=self_edit_save(
            self_edit_reading,
            envelopes,
            floors,
            status=status,
            pending_label=call_label(prepared.pending),
            exec_save=prepared.pending.tool_kind is ToolKind.EXEC,
        )
        if self_edit_reading is not None
        else None,
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
                **(
                    {"flags_pending": sorted(f.value for f in pending.flags)}
                    if pending.flags
                    else {}
                ),
                "token_status": prepared.state.status.value,
                "coverage_notes": sorted(coverage_codes),
                "attended_owner": attended,
                **({"unanswered_retry": retry_cap} if retry_cap is not None else {}),
                **({"local_code": code_cap.evidence()} if code_cap is not None else {}),
            },
        ),
    )
    return ConvergeResult(
        response=response, tiers=tiers, merged=merged, relief=relief, flags=flags, state_token=token
    )


def now_utc() -> datetime:
    from datetime import UTC

    return datetime.now(tz=UTC)
