"""Relief (skeleton 4.3; build plan 6.7 and D4), applied after the first risk calculation.

- A matched **destination** grant removes that subject's `distrust` and `untrusted_origin` contributions.
- A matched **file** grant removes that subject's `sensitivity` contribution for the granted operation,
  on the current call only, and never when the call has an off-host data destination.
- **Request-named destination relief** (RUBRIC decision 28): on an owner-sender turn, a destination or
  recipient the owner named verbatim in the request is treated as a matched destination grant, for
  sends only, never for code sources or installs.
- Grants sanction access, never what happens to the data afterwards: relief never clears session flags
  and never lowers a floor (floors are applied after relief).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..planir.models import SenderRelation, ToolKind
from ..prepare import Prepared
from ..prepare.entities import Origin, Role
from .params import ConvergenceParams

_OP_FOR_KIND: dict[ToolKind, str] = {
    ToolKind.FILE_READ: "read",
    ToolKind.FILE_WRITE: "write",
    ToolKind.FILE_EDIT: "edit",
    ToolKind.MEMORY_WRITE: "write",
}


@dataclass(frozen=True)
class Relief:
    grant_ref: str | None
    subject: str
    effect: str
    reason: str
    excluded: tuple[tuple[str, str | None], ...]


def _has_off_host_destination(prepared: Prepared) -> bool:
    return any(
        e.roles & {Role.DATA_DESTINATION, Role.RECIPIENT}
        and e.kind.value in ("host", "recipient", "channel")
        for e in prepared.entities.pending()
    )


def _exec_op(prepared: Prepared) -> str:
    kind = prepared.pending.tool_kind
    if kind in _OP_FOR_KIND:
        return _OP_FOR_KIND[kind]
    return "exec" if kind is ToolKind.EXEC else "read"


def compute_relief(prepared: Prepared, params: ConvergenceParams) -> list[Relief]:
    out: list[Relief] = []
    grants = {g.grant_ref: g for g in prepared.planir.grants}
    off_host = _has_off_host_destination(prepared)
    op = _exec_op(prepared)

    for grant_ref, entity_ids in prepared.grant_hits.items():
        grant = grants.get(grant_ref)
        if grant is None:
            continue
        for eid in entity_ids:
            ent = prepared.entities.by_id(eid)
            if ent is None:
                continue
            if grant.kind == "destination":
                out.append(
                    Relief(
                        grant_ref,
                        eid,
                        "distrust+untrusted_origin",
                        "relief.destination_grant",
                        (("suspicion.distrust", eid), ("suspicion.untrusted_origin", eid)),
                    )
                )
            elif grant.kind == "file":
                allows = {a.lower() for a in grant.allows} or {"read"}
                if op in allows and not off_host:
                    out.append(
                        Relief(
                            grant_ref,
                            eid,
                            f"sensitivity:{op}",
                            "relief.file_grant",
                            (("consequence.sensitivity", eid),),
                        )
                    )
            elif grant.kind == "provider":
                out.append(
                    Relief(
                        grant_ref,
                        eid,
                        "distrust",
                        "relief.destination_grant",
                        (("suspicion.distrust", eid),),
                    )
                )

    if params.request_named_relief:
        owner = prepared.planir.trigger.sender.relation is SenderRelation.OWNER
        if owner or not params.request_named_owner_only:
            relieved = {r.subject for r in out}
            for ent in prepared.entities.pending():
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
    return out
