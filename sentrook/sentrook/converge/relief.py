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
  sends only, never for code sources or installs.
- **Known-good destination relief**: a destination or recipient the entity oracle marks `known_good`
  is treated the same way, for sends only, unless it reached the agent through untrusted content
  (a destination dictated by something the agent read keeps its origin, however reputable).
- Grants sanction access, never what happens to the data afterwards: relief never clears session flags
  and never lowers a floor (floors are applied after relief).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..planir.models import SenderRelation
from ..prepare import Prepared
from ..prepare.entities import Origin, Role
from ..prepare.grants import GRANT_KINDS
from .merge import ANY_SUBJECT
from .params import ConvergenceParams


@dataclass(frozen=True)
class Relief:
    grant_ref: str | None
    #: The relieved entity; None for relief on the whole call.
    subject: str | None
    effect: str
    reason: str
    excluded: tuple[tuple[str, str | None], ...]


def _has_off_host_destination(prepared: Prepared) -> bool:
    return any(
        e.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}
        and e.kind.value in ("host", "recipient", "channel")
        for e in prepared.entities.pending()
    )


def compute_relief(
    prepared: Prepared, params: ConvergenceParams, known_good: Iterable[str] = ()
) -> list[Relief]:
    """`known_good`: entity ids the oracle probe reported as `known_good` in this scan."""
    out: list[Relief] = []
    grants = {g.grant_ref: g for g in prepared.planir.grants}
    off_host = _has_off_host_destination(prepared)

    for grant_ref, entity_ids in prepared.grant_hits.items():
        grant = grants.get(grant_ref)
        spec = GRANT_KINDS.get(grant.kind) if grant is not None else None
        if spec is None or spec.reason is None or not spec.relieves:
            continue
        if spec.local_only and off_host:
            continue  # a grant sanctions access, never sending the data off the host
        for eid in entity_ids:
            if prepared.entities.by_id(eid) is None:
                continue
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
        if owner or not params.request_named_owner_only:
            relieved = {r.subject for r in out}
            for ent in prepared.entities:
                if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                    continue  # the destination may live in the script the call runs
                if ent.id in relieved or Origin.REQUEST not in ent.origins:
                    continue
                roles = {r.value for r in ent.roles}
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

    if params.known_good_relief:
        relieved = {r.subject for r in out}
        for eid in known_good:
            ent = prepared.entities.by_id(eid)
            if ent is None or eid in relieved:
                continue
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            roles = {r.value for r in ent.roles}
            if not roles & set(params.request_named_roles):
                continue
            if roles & {Role.CODE_SOURCE.value, Role.EXECUTABLE.value}:
                continue  # reputation sanctions sending to a host, never running code from it
            if ent.in_session_untrusted or Origin.UNTRUSTED_INPUT in ent.origins:
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
