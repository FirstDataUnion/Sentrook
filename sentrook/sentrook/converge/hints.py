"""Grant hints: the grants that would let a reviewed call through next time.

A call at or above the review line (`grant_hints_review_line`, the plugins' default) gets up to
`grant_hints_max` hints. Each names one grant, built from one of the call's own entities as the owner would
type it (`/sentrook grant <kind> <pattern>`), that alone brings the call below the line.

Which entities may be hinted:

- the pending call's own (or a batch sibling's, as grants match them), not one only a sibling names;
- not already covered by a grant, not `known_bad`, not a near miss or look-alike of anything (the oracle's
  near miss, a look-alike reason from any probe);
- not taken from content the agent read (the session's untrusted set, or an untrusted input that named it
  before the agent did), and not one such content tried to steer the agent to;
- not a code source or an executable, now or in a later run the call sets up: a grant to send somewhere never
  sanctions running code from it;
- for a tool provider, only in a chat the owner attends (`attended.attended_owner`), and never one the session
  switched a tool to: a provider grant trusts code that runs inside the agent, so it is suggested only when the
  owner asked for the work in front of them, and never for what may be an impersonating server;
- a kind the owner can grant by command and that relief honours: `destination` (a host, recipient or
  channel), `file` (a path, with what the call does to it, never for a call that also sends off the host) and
  `provider` (an MCP server or plugin);
- a pattern that matches the entity exactly as the grant matcher reads it: no glob characters, no whitespace,
  not over-broad, at most 256 printable characters, and nothing that reads as a secret.

No hints at all unless the turn is the owner's (`owner_turn`): their own message, or a scheduled or heartbeat run
the host started with no sender behind it. On anyone else's turn someone else chose what the call acts on. None for a host that is only a recipient's mail domain, and none whose pattern would cover any
entity of the call but the one it names. No hints at all for a call that sends one of the machine's files off the host in a session that has read content
trying to instruct the agent (the session's `tainted` flag): that is what an injected instruction to upload a file
looks like, and a grant there would let the next one through. None for a fetch whose address carries text the
session read from a local file (`prepare.url_carry`): data leaving in a URL. Nor for a call with an `enforced` decision or any floor, with an independent strong signal
(`attended.strong_signals`, whoever attends), or for a scan that is not fully informed (`attended.withheld`:
a probe failed, the oracle was unavailable, new content went unjudged, the session state was lost, or the
scan is otherwise degraded).

Verification: each candidate is checked by re-scoring this call with that grant applied. The re-score
is deterministic and reuses every probe answer this scan already has, the model's included: it adds the
pairs the grant's relief would remove (`relief.compute_relief`'s grant rule, for the entities the pattern
covers) to the ones relief already removed, merges and computes the tiers again. Nothing is asked again. A
grant also lowers what the rule-based probes say about a sanctioned entity (an origin, a look-alike check);
the re-score keeps their answers as they are, so it never shows a lower risk than a second scan with the
grant in place would, given the same model answers. A `destination` candidate is also re-scored with the
granted-send relief (`converge.granted_send`) as it would apply once the grant is set, when the parameters turn
that relief on: the same coverage, gate and limits, with the candidate counted as a matched destination grant.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..enums import Enforce, ProbeStatus, ProbeStep, SessionFlag
from ..planir.models import OS, SenderRelation, TriggerKind
from ..prepare import Prepared
from ..prepare.entities import Entity, EntityKind, Origin, Role, display_path
from ..prepare.grants import GRANT_KINDS, grant_matches, path_actions, sends_off_host
from ..prepare.secret_like import secret_carried
from ..probes.base import Envelope
from ..response.models import GrantHint, Reason
from .attended import (
    KNOWN_BAD_PREFIX,
    LOOKALIKE_PREFIXES,
    attended_owner,
    strong_signals,
    withheld,
)
from .formulas import compute
from .granted_send import granted_send
from .merge import Claim, merge
from .params import ConvergenceParams
from .relief import Relief
from .retry_cap import unanswered_retry

#: The grant kind a hint offers for each entity kind.
HINT_KIND: dict[EntityKind, str] = {
    EntityKind.HOST: "destination",
    EntityKind.RECIPIENT: "destination",
    EntityKind.CHANNEL: "destination",
    EntityKind.PATH: "file",
    EntityKind.MCP_SERVER: "provider",
    EntityKind.PLUGIN: "provider",
}
MAX_PATTERN = 256
#: Days a remembered grant lasts.
EXPIRES_IN_DAYS = 30
_CODE_ROLES = frozenset({Role.CODE_SOURCE, Role.EXECUTABLE})
_GLOB = frozenset("*?[]")
#: A provider the session switched a tool to: it may be impersonating the one the tool came from before.
_SWITCHED_PROVIDER = frozenset({"origin.switched_provider", "reputation.switched_provider"})
#: Opening of a redaction placeholder, the plugins' and the scanner's own.
_PLACEHOLDER_OPEN = "⟦"


#: Runs the host starts itself from a task the owner set up: a scheduled job or a heartbeat.
_HOST_TASK = frozenset({TriggerKind.SCHEDULED, TriggerKind.HEARTBEAT})


def owner_turn(prepared: Prepared) -> bool:
    """The owner's own turn: the sender is the owner, or the host started the run itself from a scheduled job or a
    heartbeat with no sender behind it (`unknown`). Anyone else (a stranger, a trusted contact, any non-owner on a
    message turn, a sub-agent, a hook) chose what the call acts on, so no grant is suggested for it. A hint on a
    host task run reaches the owner only through a held call they approve themselves."""
    sender = prepared.planir.trigger.sender.relation
    if sender is SenderRelation.OWNER:
        return True
    return prepared.planir.trigger.kind in _HOST_TASK and sender is SenderRelation.UNKNOWN


def rank_key(hint: GrantHint, entity_kind: EntityKind | None) -> tuple:
    """Lowest risk first; on a tie the narrower pattern (a full address, a channel, a path or a provider before a
    host), then the pattern itself."""
    return (hint.risk, 1 if entity_kind is EntityKind.HOST else 0, hint.kind, hint.pattern)


#: The grant ref a hint's re-score gives the grant it proposes.
_HINT_REF = "hint"


@dataclass(frozen=True)
class _Candidate:
    kind: str
    pattern: str
    allows: tuple[str, ...] | None
    subject: str


def _unhintable(prepared: Prepared, claims: list[Claim], envelopes: list[Envelope]) -> set[str]:
    """Entity ids no hint may name: known-bad, near misses and look-alikes, by any probe's account."""
    out = {
        c.subject
        for c in claims
        if c.subject is not None
        and (
            (c.reason or "").startswith((KNOWN_BAD_PREFIX, *LOOKALIKE_PREFIXES))
            or c.reason in _SWITCHED_PROVIDER
        )
    }
    for env in envelopes:
        if env.step is not ProbeStep.ENTITY_ORACLE or env.status is not ProbeStatus.OK:
            continue
        for eid, info in (env.evidence.get("entities") or {}).items():
            if isinstance(info, dict) and (
                info.get("verdict") == "known_bad" or isinstance(info.get("near_miss"), dict)
            ):
                out.add(eid)
    for eid, info in prepared.oracle_entities.items():
        if isinstance(info, dict) and (
            info.get("verdict") == "known_bad" or isinstance(info.get("near_miss"), dict)
        ):
            out.add(eid)
    return out


def _from_content(ent: Entity) -> bool:
    """Content the agent read supplied it, or tried to steer the agent to it."""
    return (
        ent.in_session_untrusted
        or ent.steered
        or (Origin.UNTRUSTED_INPUT in ent.origins and not ent.agent_first)
    )


def plain_pattern(pattern: str) -> bool:
    """One printable word, as the owner could type it, with no glob characters and no secret in it."""
    return (
        0 < len(pattern) <= MAX_PATTERN
        and pattern.isprintable()
        and not any(c.isspace() for c in pattern)
        and not _GLOB & set(pattern)
        and secret_carried(pattern, _PLACEHOLDER_OPEN) is None
    )


def _host_os(prepared: Prepared) -> OS:
    return OS(prepared.planir.host.os)


def _actions(prepared: Prepared, ent: Entity) -> tuple[frozenset[str], frozenset[str]]:
    return path_actions(
        prepared.pending,
        ent,
        home=prepared.home,
        workspace_root=prepared.workspace_root,
        host_os=_host_os(prepared),
    )


def _candidates(prepared: Prepared, unhintable: set[str], off_host: bool) -> list[_Candidate]:
    out: list[_Candidate] = []
    attended = attended_owner(prepared.planir)
    for ent in prepared.entities:
        kind = HINT_KIND.get(ent.kind)
        if kind is None or ent.id in unhintable:
            continue
        if kind == "provider" and not attended:
            continue
        if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING) or ent.sibling_only:
            continue
        if ent.kind is EntityKind.HOST and ent.recipient_domain_of:
            continue  # only a recipient's mail domain: a grant on it would cover every address there
        if Origin.GRANT in ent.origins or _from_content(ent):
            continue
        if (ent.roles | ent.future_roles) & _CODE_ROLES:
            continue
        spec = GRANT_KINDS[kind]
        if spec.local_only and off_host:
            continue
        pattern = _pattern(ent, _host_os(prepared))
        if pattern is None:
            continue
        allows: tuple[str, ...] | None = None
        if spec.actions:
            actions, reach = _actions(prepared, ent)
            if reach or not actions <= spec.actions:
                continue  # a wildcard reaches past the one path a hint would name
            allows = tuple(sorted(actions))
        out.append(_Candidate(kind, pattern, allows, ent.id))
    return out


def _pattern(ent: Entity, host_os: OS) -> str | None:
    """The pattern a hint names for `ent`, as the owner would type it: a path under the home directory with `~/`
    (what a chat the prompt reaches shows, rather than the account's home), anything else as the scanner reads
    it. None when neither form is a plain pattern that covers the entity."""
    path = ent.kind is EntityKind.PATH
    forms = [ent.display.strip(), ent.value.strip()] if path else [ent.value.strip()]
    for form in forms:
        if path and not form.startswith(("~/", "/")):
            continue  # a display cut short, or relative: not what the grant matcher reads
        if plain_pattern(form) and grant_matches(HINT_KIND[ent.kind], form, ent, host_os=host_os):
            return form
    return None


def _sends_a_file(prepared: Prepared) -> bool:
    """The call takes data from a file on this machine: a path the pending call (or a batch sibling, or the file it
    runs) reads as a data source."""
    return any(
        ent.kind is EntityKind.PATH
        and Role.DATA_SOURCE in ent.roles
        and ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE)
        for ent in prepared.entities
    )


def _relieved_pairs(prepared: Prepared, cand: _Candidate) -> set[tuple[str, str | None]]:
    """What relief would remove with this grant in place: the kind's signals on every pending-call or
    sibling entity the pattern covers (with every action the call takes on it, for a file grant). A candidate
    whose pattern covers any entity but its own subject gets nothing: the owner is shown one entity, so the
    grant must relieve that one only."""
    spec = GRANT_KINDS[cand.kind]
    allowed = frozenset(cand.allows or ()) or spec.default_allows
    out: set[tuple[str, str | None]] = set()
    for ent in prepared.entities:
        if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING):
            continue
        if not grant_matches(cand.kind, cand.pattern, ent, host_os=_host_os(prepared)):
            continue
        if ent.future_roles & _CODE_ROLES:
            continue
        if spec.actions:
            actions, reach = _actions(prepared, ent)
            if not actions <= allowed:
                continue
            if not all(
                grant_matches(
                    cand.kind,
                    cand.pattern,
                    Entity("", EntityKind.PATH, g, display_path(g, prepared.home)),
                    host_os=_host_os(prepared),
                )
                for g in reach
            ):
                continue
        if ent.id != cand.subject:
            return set()
        out.update((s, ent.id) for s in spec.relieves)
    return out


def grant_hints(
    prepared: Prepared,
    claims: list[Claim],
    envelopes: list[Envelope],
    relief: list[Relief],
    reasons: list[Reason],
    params: ConvergenceParams,
    *,
    risk: float,
    enforced: Enforce | None,
    floors: list[str],
    degraded: bool,
    exposure_unjudged: bool,
    flags: set[SessionFlag] | None = None,
) -> list[GrantHint]:
    """The grant hints for a scored call (`risk` 0-1, after floors). `claims`: every claim before relief, as
    convergence merged them; `floors`: the floors applied; `flags`: the session's flags with this scan's own
    (the token's alone when not given)."""
    flags = set(prepared.state.flags) | set(flags or ())
    line = params.grant_hints_review_line
    if params.grant_hints_max <= 0 or risk < line or enforced is not None or floors:
        return []
    if withheld(
        envelopes,
        degraded=degraded,
        state_lost=prepared.state.fresh,
        exposure_unjudged=exposure_unjudged,
    ):
        return []
    excluded = {pair for r in relief for pair in r.excluded}
    kept = [c for cs in merge(claims, excluded).claims.values() for c in cs]
    if strong_signals(
        prepared,
        claims,
        kept,
        [(r.subject, r.reason) for r in relief],
        floors,
        params,
        unanswered_retry=unanswered_retry(envelopes),
    ):
        return []
    if not owner_turn(prepared):
        return []
    off_host = sends_off_host(prepared.pending, prepared.entities.pending())
    if off_host and SessionFlag.TAINTED in flags and _sends_a_file(prepared):
        return []
    if prepared.url_carries:
        return []  # a fetch whose address carries text from a local read: data leaving in a URL
    found: dict[tuple[str, str, tuple[str, ...] | None], GrantHint] = {}
    for cand in _candidates(prepared, _unhintable(prepared, claims, envelopes), off_host):
        key = (cand.kind, cand.pattern, cand.allows)
        if key in found:
            continue
        covers = _relieved_pairs(prepared, cand)
        pairs = covers - excluded
        relief_too = cand.kind == "destination" and params.granted_send is not None
        if not covers or (not pairs and not relief_too):
            continue
        hinted = merge(claims, excluded | pairs)
        tiers = compute(hinted, envelopes, params, exposure_unjudged=exposure_unjudged)
        if tiers.risk >= line and relief_too:
            # with this grant set, every destination may be granted: the granted-send relief would apply too
            covered = {eid: _HINT_REF for _, eid in covers if eid is not None}
            gs = granted_send(
                prepared, claims, hinted, envelopes, params.granted_send, extra=covered
            )
            if gs is not None:
                tiers = compute(
                    merge(gs.claims, excluded | pairs),
                    envelopes,
                    params,
                    exposure_unjudged=exposure_unjudged,
                )
        if tiers.risk >= line:
            continue
        relieves = list(
            dict.fromkeys(r.code for r in reasons if r.signal and (r.signal, r.subject) in pairs)
        )
        found[key] = GrantHint(
            kind=cand.kind,
            pattern=cand.pattern,
            allows=list(cand.allows) if cand.allows is not None else None,
            expires_in_days=EXPIRES_IN_DAYS,
            subject=cand.subject,
            relieves=relieves,
            risk=round(tiers.risk * 100.0, 2),
        )

    def entity_kind(h: GrantHint) -> EntityKind | None:
        ent = prepared.entities.by_id(h.subject) if h.subject else None
        return ent.kind if ent is not None else None

    ranked = sorted(found.values(), key=lambda h: rank_key(h, entity_kind(h)))
    return ranked[: params.grant_hints_max]
