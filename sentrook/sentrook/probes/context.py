"""Context probe: what the trajectory and the session state say about
the call, with no model and no raw text.

- `suspicion.untrusted_origin` per key entity: 0 when the owner named it (request) or a grant covers it;
  about 0.1 for a local entity the agent visibly created with clean lineage; about 0.4 when it appears
  nowhere or first in the agent's own arguments (always for off-host kinds); 1.0 when it appeared only
  in untrusted content before the agent used it (the token's untrusted set remembers across steps).
- `suspicion.request_origin` from the trigger: owner 0, scheduled or heartbeat about 0.2, trusted by a
  plugin allowlist about 0.3, known channel with an unknown sender about 0.5 (coverage reduced), a
  sender marked `other` about 0.8, nothing known no contribution and coverage reduced.
- `suspicion.retry_after_denial` by comparing the pending call's fingerprint components with those of
  denied, blocked or timed-out history steps (recomputed from the history arguments with this
  session's salt, so a plugin's echoed fingerprint is not required).
- Sticky `suspicion.exposure` from `tainted`; `consequence.sensitivity` from `holds_sensitive` when
  the call has a data destination; the `escalating` flag from the history tier scores; coverage from a
  stale carried request, a fresh session and truncated or dropped content.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..planir.canonical import CanonicalCall
from ..planir.models import SenderBasis, SenderRelation, ToolKind, TriggerKind
from ..prepare import Prepared
from ..prepare.entities import Entity, EntityKind, Origin, Role, extract_call
from ..prepare.fingerprint import Fingerprint, fingerprint
from .base import Contribution, Envelope

PROBE_VERSION = "context/2.0.0a1"

KEY_ROLES = (Role.DATA_DESTINATION, Role.RECIPIENT, Role.CODE_SOURCE, Role.EXECUTABLE)
#: Heads that only read; an exec made of these alone is "read-shaped" for retry grading.
_READ_HEADS = frozenset(
    "cat head tail less more ls stat wc grep rg file md5sum sha1sum sha256sum du find diff".split()
)


@dataclass(frozen=True)
class ContextParams:
    name: str = "ctx-v1"
    origin_sanctioned: float = 0.0
    origin_visible_creation: float = 0.1
    origin_agent_generated: float = 0.4
    origin_untrusted: float = 1.0
    #: Weight of untrusted_origin by the entity's strongest role.
    origin_role_weight: dict[str, float] = field(
        default_factory=lambda: {
            Role.DATA_DESTINATION.value: 1.0,
            Role.RECIPIENT.value: 1.0,
            Role.CODE_SOURCE.value: 1.0,
            Role.EXECUTABLE.value: 1.0,
            Role.TOOL_PROVIDER.value: 0.6,
            Role.DATA_SOURCE.value: 0.5,
            Role.MENTIONED.value: 0.25,
        }
    )
    request_origin: dict[str, float] = field(
        default_factory=lambda: {
            "owner": 0.0,
            "scheduled": 0.2,
            "heartbeat": 0.2,
            "subagent": 0.3,
            "hook": 0.3,
            "system": 0.3,
            "trusted": 0.3,
            "channel_unknown_sender": 0.5,
            "other": 0.8,
        }
    )
    coverage_unknown_sender: float = 0.9
    coverage_nothing_known: float = 0.8
    retry_same_action: float = 1.0
    retry_same_source_new_destination: float = 0.8
    retry_same_destination_new_source: float = 0.5
    #: A read-shaped call on the data of a denied step: suspicious, but it is not the
    #: denied action retried, so the denied consequence is not carried.
    retry_same_source_only: float = 0.5
    retry_repeat_bonus: float = 0.1
    retry_decay_per_step: float = 0.1
    retry_floor: float = 0.5
    #: Scale on the denied step's echoed consequence tier, contributed as `consequence.reach` and
    #: `consequence.irreversibility` when the pending call retries that step (0 = off; conv-v3 sets 1).
    retry_carry_consequence: float = 0.0
    sticky_exposure: float = 0.7
    holds_sensitive_sensitivity: float = 0.8
    escalation_rise: float = 0.1
    coverage_stale_request: float = 0.9
    coverage_very_stale_request: float = 0.8
    coverage_fresh_session: float = 0.7
    coverage_truncated: float = 0.7
    coverage_dropped: float = 0.8


def _hashes(hist: Fingerprint, echoed: Fingerprint | None, *roles: Role) -> frozenset[str]:
    """The denied step's hashes for `roles`: recomputed with this session's salt, plus whatever the
    plugin echoed back (its tagging may differ from ours)."""
    out: frozenset[str] = frozenset()
    for role in roles:
        out |= hist.hashes(role)
        if echoed is not None:
            out |= echoed.hashes(role)
    return out


class ContextProbe:
    step = ProbeStep.CONTEXT

    def __init__(self, params: ContextParams | None = None):
        self.params = params or ContextParams()

    @property
    def versions(self) -> dict[str, str | None]:
        return {"probe": PROBE_VERSION, "params": self.params.name}

    # ------------------------------------------------------------------ untrusted_origin

    def _origin_value(
        self, ent: Entity, prepared: Prepared, prior_flags: set[SessionFlag]
    ) -> tuple[float, str]:
        p = self.params
        if ent.sanctioned:
            return (
                p.origin_sanctioned,
                "origin.request_named" if Origin.REQUEST in ent.origins else "origin.granted",
            )
        agent_first = (
            ent.first_history_step is not None
            and ent.first_untrusted_step is not None
            and ent.first_history_step < ent.first_untrusted_step
        )
        if ent.in_session_untrusted or (Origin.UNTRUSTED_INPUT in ent.origins and not agent_first):
            return p.origin_untrusted, "origin.only_in_untrusted"
        if ent.kind is EntityKind.PATH:
            created_step = prepared.created_paths.get(ent.value)
            if created_step is not None:
                local = (
                    ent.value.startswith(
                        (prepared.workspace_root + "/", "/tmp/", prepared.home + "/tmp/")
                    )
                    or "/scratch" in ent.value
                )
                clean = SessionFlag.TAINTED not in prior_flags and not self._dirty_lineage(
                    ent, prepared
                )
                if local and clean:
                    return p.origin_visible_creation, "origin.agent_created_visible"
                if local:
                    return p.origin_untrusted if self._dirty_lineage(
                        ent, prepared
                    ) else p.origin_agent_generated, "origin.agent_created_dirty_lineage"
        return p.origin_agent_generated, "origin.agent_generated"

    @staticmethod
    def _dirty_lineage(ent: Entity, prepared: Prepared) -> bool:
        """The executed file's content names an entity the untrusted set already holds."""
        if prepared.written_file is None or prepared.written_file.path != ent.value:
            return False
        for other in prepared.entities:
            if Origin.WRITTEN_FILE in other.origins and (
                other.in_session_untrusted or Origin.UNTRUSTED_INPUT in other.origins
            ):
                return True
        return False

    def _untrusted_origin(
        self, prepared: Prepared, prior_flags: set[SessionFlag], evidence: dict
    ) -> list[Contribution]:
        out: list[Contribution] = []
        for ent in prepared.entities:
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            if ent.kind is EntityKind.PATH and not (
                ent.roles & {Role.EXECUTABLE, Role.DATA_SOURCE, Role.DATA_DESTINATION}
            ):
                continue
            weight = max(
                (self.params.origin_role_weight.get(r.value, 0.25) for r in ent.roles), default=0.25
            )
            value, reason = self._origin_value(ent, prepared, prior_flags)
            if (
                Origin.WRITTEN_FILE in ent.origins
                and Origin.PENDING_CALL not in ent.origins
                and value >= self.params.origin_untrusted
            ):
                reason = "origin.written_content_untrusted"
            scaled = round(value * weight, 4)
            out.append(
                Contribution(
                    signal="suspicion.untrusted_origin", value=scaled, subject=ent.id, reason=reason
                )
            )
            evidence.setdefault("origins", {})[ent.id] = {
                "value": scaled,
                "reason": reason,
                "origins": {k.value: v for k, v in ent.origins.items()},
                "in_session_untrusted": ent.in_session_untrusted,
                "first_history_step": ent.first_history_step,
                "first_untrusted_step": ent.first_untrusted_step,
            }
        return out

    # ------------------------------------------------------------------ request_origin

    def _request_origin(self, prepared: Prepared, evidence: dict) -> list[Contribution]:
        p = self.params
        trig = prepared.planir.trigger
        rel, kind = trig.sender.relation, trig.kind
        basis = set(trig.sender.basis)
        evidence["trigger"] = {
            "kind": kind.value,
            "relation": rel.value,
            "basis": sorted(b.value for b in basis),
            "channel": trig.channel.value if trig.channel else None,
        }
        out: list[Contribution] = []
        if rel is SenderRelation.OWNER or SenderBasis.HOST_ALLOWLIST_DM in basis:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["owner"],
                    reason="trigger.owner",
                )
            )
        elif kind in (TriggerKind.SCHEDULED, TriggerKind.HEARTBEAT):
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin[kind.value],
                    reason=f"trigger.{kind.value}",
                )
            )
        elif rel is SenderRelation.TRUSTED:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["trusted"],
                    reason="trigger.trusted_allowlist",
                )
            )
        elif rel is SenderRelation.OTHER or basis & {
            SenderBasis.GROUP_CHAT,
            SenderBasis.HOST_OPEN_ACCESS,
        }:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["other"],
                    reason="trigger.sender_other",
                )
            )
        elif kind in (TriggerKind.SUBAGENT, TriggerKind.HOOK, TriggerKind.SYSTEM):
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin[kind.value],
                    reason=f"trigger.{kind.value}",
                )
            )
        elif kind is TriggerKind.MESSAGE and trig.channel is not None:
            out.append(
                Contribution(
                    signal="suspicion.request_origin",
                    value=p.request_origin["channel_unknown_sender"],
                    reason="trigger.unknown_sender",
                )
            )
            out.append(
                Contribution(
                    signal="confidence.coverage",
                    value=p.coverage_unknown_sender,
                    reason="coverage.unknown_sender",
                )
            )
        else:
            out.append(
                Contribution(
                    signal="confidence.coverage",
                    value=p.coverage_nothing_known,
                    reason="coverage.trigger_unknown",
                )
            )
        return out

    # ------------------------------------------------------------------ retry_after_denial

    def _history_fingerprint(self, call: CanonicalCall, prepared: Prepared) -> Fingerprint:
        from ..prepare.entities import EntityTable

        table = EntityTable()
        for f in extract_call(call, home=prepared.home, workspace_root=prepared.workspace_root):
            table.add(f.kind, f.value, display=f.display, role=f.role, origin=Origin.HISTORY)
        return fingerprint(call.tool_kind, list(table), prepared.state.salt)

    def _read_shaped(self, prepared: Prepared) -> bool:
        """A file read, or an exec whose every segment starts with a reading head and writes
        nothing: touching the denied step's data again, not retrying what was denied."""
        kind = prepared.pending.tool_kind
        if kind is ToolKind.FILE_READ:
            return True
        if kind is not ToolKind.EXEC:
            return False
        cmd = prepared.pending.command or ""
        if ">" in cmd:
            return False
        segments = [seg.strip() for seg in re.split(r"[;|&]+|\n", cmd) if seg.strip()]
        return bool(segments) and all((seg.split() or [""])[0] in _READ_HEADS for seg in segments)

    def _retry(self, prepared: Prepared, evidence: dict) -> list[Contribution]:
        """`retry_after_denial`: a retry shares the denied step's source,
        destination or code hash. Matching is role-insensitive on the pending side (a `shred` target
        re-touched by an interpreter one-liner is the same entity whatever role the extractor gave
        it); the grade keeps the role shape of the denied step. A matched retry also
        carries the denied step's echoed consequence tier (`retry_carry_consequence`), except for a
        read-shaped call on the same data, which is scored at `retry_same_source_only` and carries
        nothing."""
        p = self.params
        denied = prepared.denied_steps()
        if not denied:
            return [
                Contribution(signal="suspicion.retry_after_denial", value=0.0, reason="retry.none")
            ]
        pending = prepared.fingerprint
        p_src = pending.hashes(Role.DATA_SOURCE)
        p_dst = pending.hashes(Role.DATA_DESTINATION) | pending.hashes(Role.RECIPIENT)
        p_code = pending.hashes(Role.CODE_SOURCE) | pending.hashes(Role.EXECUTABLE)
        p_all = p_src | p_dst | p_code
        read_shaped = self._read_shaped(prepared)
        by_step = {h.step: h for h in prepared.planir.history}
        best, best_reason, matches = 0.0, "retry.none", []
        carried = 0.0
        step_now = prepared.planir.session.step
        for call in denied:
            hist = self._history_fingerprint(call, prepared)
            echoed_step = by_step.get(call.step) if call.step is not None else None
            echoed = Fingerprint.parse(echoed_step.action_fingerprint if echoed_step else None)

            h_src = _hashes(hist, echoed, Role.DATA_SOURCE)
            h_dst = _hashes(hist, echoed, Role.DATA_DESTINATION, Role.RECIPIENT)
            h_code = _hashes(hist, echoed, Role.CODE_SOURCE, Role.EXECUTABLE)
            src_shared, dst_shared = bool(h_src & p_all), bool(h_dst & p_all)
            code_shared = bool(h_code & p_all)
            if not (src_shared or dst_shared or code_shared):
                continue
            carry = True
            if h_src and h_dst:  # the denied step moved data from a source to a destination
                if src_shared and dst_shared:
                    value, reason = p.retry_same_action, "retry.same_action"
                elif src_shared and p_dst:
                    value, reason = (
                        p.retry_same_source_new_destination,
                        "retry.same_source_new_destination",
                    )
                elif dst_shared and p_src:
                    value, reason = (
                        p.retry_same_destination_new_source,
                        "retry.same_destination_new_source",
                    )
                elif src_shared:
                    value, reason, carry = p.retry_same_source_only, "retry.same_source_only", False
                else:
                    value, reason = (
                        p.retry_same_destination_new_source,
                        "retry.same_destination_new_source",
                    )
            elif read_shaped and not code_shared:
                value, reason, carry = p.retry_same_source_only, "retry.same_source_only", False
            else:  # a single-entity action (destroy, write, install) retried on the same entity
                value, reason = p.retry_same_action, "retry.same_action"
            gap = max(1, step_now - (call.step or step_now))
            value = value * max(p.retry_floor, 1.0 - p.retry_decay_per_step * (gap - 1))
            tiers = echoed_step.tiers if echoed_step is not None else None
            cons = (
                tiers.consequence if tiers is not None and tiers.consequence is not None else None
            )
            if carry and cons is not None:
                carried = max(carried, float(cons))
            matches.append(
                {"step": call.step, "reason": reason, "value": round(value, 4), "carry": carry}
            )
            if value > best:
                best, best_reason = value, reason
        if len(matches) > 1:
            best = min(1.0, best + p.retry_repeat_bonus * (len(matches) - 1))
        carried = round(min(1.0, carried * p.retry_carry_consequence), 4)
        evidence["retry"] = {
            "denied_steps": [c.step for c in denied],
            "matches": matches,
            "carried_consequence": carried,
        }
        out = [
            Contribution(
                signal="suspicion.retry_after_denial", value=round(best, 4), reason=best_reason
            )
        ]
        if carried > 0.0:
            for signal in ("consequence.reach", "consequence.irreversibility"):
                out.append(
                    Contribution(
                        signal=signal, value=carried, reason="retry.denied_consequence_carried"
                    )
                )
        return out

    # ------------------------------------------------------------------ flags and coverage

    def _escalating(self, prepared: Prepared) -> bool:
        tiers = [
            h.tiers.consequence
            for h in prepared.planir.history
            if h.tiers and h.tiers.consequence is not None
        ]
        tail = tiers[-3:]
        return len(tail) >= 2 and all(
            b >= a + self.params.escalation_rise for a, b in zip(tail, tail[1:], strict=False)
        )

    def run(self, prepared: Prepared) -> Envelope:
        started = time.perf_counter()
        p = self.params
        prior_flags = set(prepared.state.flags)
        evidence: dict = {
            "prior_flags": sorted(f.value for f in prior_flags),
            "token": prepared.state.status.value,
        }
        contributions: list[Contribution] = []
        flags: list[SessionFlag] = []
        try:
            contributions += self._untrusted_origin(prepared, prior_flags, evidence)
            contributions += self._request_origin(prepared, evidence)
            contributions += self._retry(prepared, evidence)

            if SessionFlag.TAINTED in prior_flags:
                contributions.append(
                    Contribution(
                        signal="suspicion.exposure",
                        value=p.sticky_exposure,
                        reason="exposure.session_tainted",
                    )
                )
            has_destination = any(
                ent.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}
                for ent in prepared.entities.pending()
            )
            if SessionFlag.HOLDS_SENSITIVE in prior_flags and has_destination:
                contributions.append(
                    Contribution(
                        signal="consequence.sensitivity",
                        value=p.holds_sensitive_sensitivity,
                        reason="sensitivity.session_holds_sensitive",
                    )
                )
            if SessionFlag.ESCALATING in prior_flags or self._escalating(prepared):
                flags.append(SessionFlag.ESCALATING)
            evidence["escalating"] = SessionFlag.ESCALATING in flags

            coverage = 1.0
            carried = prepared.planir.request.carried_from_turn
            if carried is not None:
                gap = prepared.planir.session.turn - carried
                coverage = min(
                    coverage, p.coverage_very_stale_request if gap > 3 else p.coverage_stale_request
                )
                evidence["request_staleness_turns"] = gap
            if prepared.state.fresh:
                coverage = min(coverage, p.coverage_fresh_session)
            codes = {c.code for c in prepared.coverage}
            if codes & {"input_truncated", "written_file_truncated"}:
                coverage = min(coverage, p.coverage_truncated)
            if codes & {"content_dropped", "content_missing", "written_file_not_visible"}:
                coverage = min(coverage, p.coverage_dropped)
            if coverage < 1.0:
                contributions.append(
                    Contribution(
                        signal="confidence.coverage", value=coverage, reason="coverage.context"
                    )
                )
            evidence["coverage_notes"] = [f"{c.code}:{c.detail}" for c in prepared.coverage]
        except Exception as e:  # noqa: BLE001 (a probe never raises)
            return Envelope.failed(
                self.step,
                ProbeStatus.ERROR,
                repr(e),
                self.versions,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        return Envelope(
            step=self.step,
            versions=self.versions,
            status=ProbeStatus.OK,
            latency_ms=(time.perf_counter() - started) * 1000,
            contributions=contributions,
            flags_set=flags,
            evidence=evidence,
        )
