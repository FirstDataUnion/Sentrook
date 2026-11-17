"""Relief, applied after the first risk calculation.

Grant relief follows the kinds table in `prepare.grants`, for grants live in this request (scope,
expiry) that cover what the call does (`allows`):

- A matched **destination** grant removes that subject's `distrust` and `untrusted_origin` contributions.
- A matched **file** grant removes that subject's `sensitivity` contribution, on the current call only,
  and never when the call has an off-host data destination.
- A matched **provider** grant removes that MCP server's or plugin's `distrust` contribution.
- A **tool** grant covering every command the call runs removes the call's `self_modification`
  contributions.
- **Request-named destination relief**: on an owner-sender turn, a destination or
  recipient the owner named verbatim in the request is treated as a matched destination grant, for
  sends only, never for code sources or installs. The parameters may extend it to the host's own task
  turns (`request_named_relief.trigger_kinds`: scheduled, heartbeat, sub-agent), whose task text names
  the destination; never to a turn whose sender is someone else or an open channel, and on those turns
  never to a destination that content the agent read supplied. Who wrote the task stays priced by
  `request_origin`.
- **Known-good destination relief**: a destination or recipient the entity oracle marks `known_good`
  is treated the same way, for sends only, unless it reached the agent through untrusted content
  (a destination dictated by something the agent read keeps its origin, however reputable).
  The parameters may relax that (`known_good_relief.content_destinations`, off by default) when the
  library entry matches exactly, the session is not tainted, this scan's exposure check stayed below
  the taint threshold with no new content left unjudged, and nothing steered the agent to it.
- **Owner-config destination relief** (parameter `owner_config_relief`, off by default): a destination
  or recipient the owner's own configuration supplied on an earlier scan (the token's trusted set) loses
  its `distrust` contribution, for sends only; never for trust a config read in this request establishes
  (its exposure check may fail, or judge the read injected), never when content the agent read also
  supplied it, and never in a scan that judges a config read naming it injected.
- **Known-good provider relief**: an MCP server or plugin the call's tool comes from, whose identity
  the entity oracle marks `known_good`, is relieved as a matched provider grant would leave it
  (`distrust` and `untrusted_origin`), unless that identity reached the agent through untrusted
  content: the provider entity itself, or the host of a remote server or the package of a local one
  as content names it, in the session's untrusted set or in this request's untrusted inputs.
- **Credential-home relief** (parameter `credential_home`, off by default): when the credential-home check holds
  (`prepare.credential_home`: a key read from the agent's env file and sent only to the provider API host the entity
  library lists for its name), the call is not charged as sending sensitive data. The rule-based probes leave the env
  file's credential sensitivity and the sensitive-data-sent floor out themselves (a floor is never lowered here);
  convergence holds the model's call-level sensitivity to `credential_home_model_sensitivity_cap`, the level below
  credentials, and reports the relief on the provider host. Nothing on the suspicion side changes, unless
  `credential_home.relieve_host` (off by default) also relieves the provider host of its distrust and untrusted
  origin, as a matched destination grant would.
- **Later roles**: the roles a later run, set up by self-modification content the call writes, gives an entity
  (`Entity.future_roles`) count with its own roles in every rule above: naming, configuration and reputation
  sanction sending to the host in that run, never running code from it, and a grant of a kind that does not cover
  code (any but `repo`) does not relieve a host that run takes code from.
- Grants sanction access, never what happens to the data afterwards: relief never clears session flags
  and never lowers a floor (floors are applied after relief).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..enums import SessionFlag
from ..planir.models import SenderBasis, SenderRelation, TriggerKind
from ..prepare import Prepared
from ..prepare.entities import Entity, Origin, Role
from ..prepare.grants import GRANT_KINDS, sends_off_host
from .merge import ANY_SUBJECT
from .params import ConvergenceParams


def _acting_roles(ent: Entity) -> set[str]:
    """The entity's roles, with those a later run that self-modification content the call writes gives it: naming,
    configuring or vouching for a host sanctions sending to it in that run too, never running code from it."""
    return {r.value for r in ent.roles | ent.future_roles}


#: Grant kinds that sanction taking code from what they cover.
_CODE_GRANT_KINDS = frozenset({"repo"})
_CODE_ROLES = frozenset({Role.CODE_SOURCE, Role.EXECUTABLE})


@dataclass(frozen=True)
class Relief:
    grant_ref: str | None
    #: The relieved entity; None for relief on the whole call.
    subject: str | None
    effect: str
    reason: str
    excluded: tuple[tuple[str, str | None], ...]


#: Trigger kinds the host generates from a stored task: the only ones `request_named_trigger_kinds` may add.
_HOST_TASK_KINDS = frozenset({TriggerKind.SCHEDULED, TriggerKind.HEARTBEAT, TriggerKind.SUBAGENT})
_OPEN_BASIS = frozenset({SenderBasis.GROUP_CHAT, SenderBasis.HOST_OPEN_ACCESS})


def _host_task_turn(prepared: Prepared, params: ConvergenceParams) -> bool:
    """A scheduled, heartbeat or sub-agent turn the parameters list, whose sender is not someone else and
    whose channel is not open to anyone."""
    trig = prepared.planir.trigger
    if (
        trig.kind not in _HOST_TASK_KINDS
        or trig.kind.value not in params.request_named_trigger_kinds
    ):
        return False
    return trig.sender.relation is not SenderRelation.OTHER and not _OPEN_BASIS & set(
        trig.sender.basis
    )


def _clean_content(
    prepared: Prepared, params: ConvergenceParams, ent: Entity, exposure: float | None
) -> bool:
    """The parameters allow known-good relief for a destination content supplied, and that content
    reads as clean: the session is not tainted (no earlier input was judged an injection), this scan's
    exposure check stayed below the taint threshold, new content did not go unjudged (a failed check,
    or inputs the check leaves out), and nothing steered the agent to the host."""
    if not params.known_good_content_relief:
        return False
    if SessionFlag.TAINTED in prepared.state.flags or ent.steered:
        return False
    if exposure is None:
        return not any(i.input.content for i in prepared.untrusted_inputs(new_only=True))
    return exposure < params.jev_taint_threshold


def compute_relief(
    prepared: Prepared,
    params: ConvergenceParams,
    known_good: Iterable[str] = (),
    withdrawn_trust: Iterable[str] = (),
    known_good_exact: Iterable[str] = (),
    exposure: float | None = None,
) -> list[Relief]:
    """`known_good`: entity ids the oracle probe reported as `known_good` in this scan.
    `withdrawn_trust`: hashes of the entities a config read supplied that this scan judged injected.
    `known_good_exact`: the `known_good` ids whose library entry matched exactly.
    `exposure`: this scan's merged exposure, None when no probe judged the new inputs."""
    out: list[Relief] = []
    grants = {g.grant_ref: g for g in prepared.planir.grants}
    off_host = sends_off_host(prepared.pending, prepared.entities.pending())

    for grant_ref, entity_ids in prepared.grant_hits.items():
        grant = grants.get(grant_ref)
        spec = GRANT_KINDS.get(grant.kind) if grant is not None else None
        if spec is None or spec.reason is None or not spec.relieves:
            continue
        if spec.local_only and off_host:
            continue  # a grant sanctions access, never sending the data off the host
        for eid in entity_ids:
            ent = prepared.entities.by_id(eid)
            if ent is None:
                continue
            if grant.kind not in _CODE_GRANT_KINDS and ent.future_roles & _CODE_ROLES:
                continue  # a later run takes code from it: a grant to send there does not sanction that
            effect = "+".join(s.split(".", 1)[1] for s in spec.relieves)
            if spec.actions:
                effect += ":" + "+".join(sorted(prepared.grant_actions.get(eid, ())))
            out.append(
                Relief(
                    grant_ref,
                    eid,
                    effect,
                    spec.reason,
                    tuple((s, eid) for s in spec.relieves),
                )
            )

    for grant_ref in prepared.call_grants:
        grant = grants.get(grant_ref)
        spec = GRANT_KINDS.get(grant.kind) if grant is not None else None
        if spec is None or spec.reason is None or not spec.relieves_call:
            continue
        out.append(
            Relief(
                grant_ref,
                None,
                "+".join(s.split(".", 1)[1] for s in spec.relieves_call),
                spec.reason,
                tuple((s, ANY_SUBJECT) for s in spec.relieves_call),
            )
        )

    if params.request_named_relief:
        owner = prepared.planir.trigger.sender.relation is SenderRelation.OWNER
        host_task = not owner and _host_task_turn(prepared, params)
        if owner or host_task or not params.request_named_owner_only:
            relieved = {r.subject for r in out}
            for ent in prepared.entities:
                if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                    continue  # the destination may live in the script the call runs
                if ent.id in relieved or Origin.REQUEST not in ent.origins:
                    continue
                if host_task and (
                    ent.in_session_untrusted
                    or (Origin.UNTRUSTED_INPUT in ent.origins and not ent.agent_first)
                ):
                    continue  # a task text is not the owner's word against content that supplied it
                roles = _acting_roles(ent)
                if not roles & set(params.request_named_roles):
                    continue
                if roles & {Role.CODE_SOURCE.value, Role.EXECUTABLE.value}:
                    continue  # naming a host sanctions sending to it, never running code from it
                out.append(
                    Relief(
                        None,
                        ent.id,
                        "distrust+untrusted_origin",
                        "relief.request_named_destination",
                        (("suspicion.distrust", ent.id), ("suspicion.untrusted_origin", ent.id)),
                    )
                )

    if params.owner_config_relief:
        relieved = {r.subject for r in out}
        withdrawn = set(withdrawn_trust)
        for ent in prepared.entities:
            if ent.id in relieved or not ent.in_prior_trusted or ent.hash in withdrawn:
                continue
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            if ent.in_session_untrusted or (
                Origin.UNTRUSTED_INPUT in ent.origins and not ent.agent_first
            ):
                continue  # content the agent read wins over the owner's config
            roles = _acting_roles(ent)
            if roles & {Role.CODE_SOURCE.value, Role.EXECUTABLE.value}:
                continue  # a configured host sanctions sending to it, never running code from it
            if not roles & set(params.request_named_roles):
                continue
            out.append(
                Relief(
                    None,
                    ent.id,
                    "distrust",
                    "relief.owner_config_destination",
                    (("suspicion.distrust", ent.id),),
                )
            )

    home = prepared.credential_home if params.credential_home else None
    if home is not None:
        relieved = {r.subject for r in out}
        hosts = [h for h in home.hosts if h not in relieved]
        if params.credential_home_relieve_host and hosts:
            # the host is where the key belongs: it loses its unknown-party distrust and agent-chosen origin too
            for h in hosts:
                out.append(
                    Relief(
                        None,
                        h,
                        "sensitivity+distrust+untrusted_origin",
                        "relief.credential_own_service",
                        (("suspicion.distrust", h), ("suspicion.untrusted_origin", h)),
                    )
                )
        else:
            out.append(
                Relief(
                    None,
                    home.hosts[0] if home.hosts else None,
                    "sensitivity",
                    "relief.credential_own_service",
                    (),
                )
            )

    if params.known_good_relief:
        relieved = {r.subject for r in out}
        exact = set(known_good_exact)
        for eid in known_good:
            ent = prepared.entities.by_id(eid)
            if ent is None or eid in relieved:
                continue
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            roles = _acting_roles(ent)
            if roles & {Role.CODE_SOURCE.value, Role.EXECUTABLE.value}:
                continue  # reputation sanctions sending to a host, never running code from it
            if Role.TOOL_PROVIDER.value in roles:
                if not prepared.provider_from_untrusted(ent):
                    out.append(
                        Relief(
                            None,
                            eid,
                            "distrust+untrusted_origin",
                            "relief.known_good_provider",
                            (("suspicion.distrust", eid), ("suspicion.untrusted_origin", eid)),
                        )
                    )
                continue
            if not roles & set(params.request_named_roles):
                continue
            if (ent.in_session_untrusted or Origin.UNTRUSTED_INPUT in ent.origins) and not (
                eid in exact and _clean_content(prepared, params, ent, exposure)
            ):
                continue  # a destination taken from content the agent read keeps its origin
            out.append(
                Relief(
                    None,
                    eid,
                    "distrust+untrusted_origin",
                    "relief.known_good_destination",
                    (("suspicion.distrust", eid), ("suspicion.untrusted_origin", eid)),
                )
            )
    return out
