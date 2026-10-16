"""Entity oracle probe (skeleton 3.2; build plan 6.5).

Looks up every off-host or installable entity the pending call (or a sibling, or the agent-written file
it executes) touches, with its roles, and contributes `suspicion.distrust` per entity by verdict and
role. A `known_bad` entity also raises the `known_bad_entity` floor (1.0, block). Unknown entities in a
risky role lower `confidence.coverage`; so does an unavailable oracle. Paths are not reputation
questions (their sensitivity comes from AIRA's path classes) and loopback hosts are the agent's own
machine, so neither is looked up.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..enums import Enforce, ProbeStatus, ProbeStep
from ..oracle.client import EntityQuery, OracleClient, OracleResult, VerdictKind, is_local_host
from ..prepare import Prepared
from ..prepare.entities import Entity, EntityKind, Origin, Role
from .base import Contribution, Envelope, Floor

PROBE_VERSION = "entity_oracle/2.0.0a1"

LOOKUP_KINDS = (
    EntityKind.HOST,
    EntityKind.RECIPIENT,
    EntityKind.CHANNEL,
    EntityKind.PACKAGE,
    EntityKind.PLUGIN,
    EntityKind.MCP_SERVER,
)


@dataclass(frozen=True)
class OracleParams:
    """Starting values (build plan 6.5), overridable from the convergence parameter set."""

    name: str = "oracle-v1"
    unknown_by_role: dict[str, float] = field(
        default_factory=lambda: {
            Role.DATA_DESTINATION.value: 0.5,
            Role.RECIPIENT.value: 0.5,
            Role.CODE_SOURCE.value: 0.5,
            Role.EXECUTABLE.value: 0.5,
            Role.TOOL_PROVIDER.value: 0.3,
            Role.DATA_SOURCE.value: 0.2,
            Role.MENTIONED.value: 0.1,
        }
    )
    known_bad_distrust: float = 1.0
    known_bad_floor: float = 1.0
    coverage_unknown_risky: float = 0.8
    coverage_unavailable: float = 0.7


class EntityOracleProbe:
    step = ProbeStep.ENTITY_ORACLE

    def __init__(self, client: OracleClient, params: OracleParams | None = None):
        self.client = client
        self.params = params or OracleParams()

    @property
    def versions(self) -> dict[str, str | None]:
        return {
            "probe": PROBE_VERSION,
            "params": self.params.name,
            "library_snapshot": None,
            "oracle": self.client.name,
        }

    def _candidates(self, prepared: Prepared) -> list[Entity]:
        out = []
        for ent in prepared.entities:
            if ent.kind not in LOOKUP_KINDS:
                continue
            if not ent.has_origin(Origin.PENDING_CALL, Origin.SIBLING, Origin.WRITTEN_FILE):
                continue
            out.append(ent)
        return out

    def run(self, prepared: Prepared) -> Envelope:
        started = time.perf_counter()
        candidates = self._candidates(prepared)
        local = [e for e in candidates if e.kind is EntityKind.HOST and is_local_host(e.value)]
        remote = [e for e in candidates if e not in local]
        queries = [
            EntityQuery(
                kind=e.kind.value, value=e.value, roles=tuple(sorted(r.value for r in e.roles))
            )
            for e in remote
        ]
        try:
            result: OracleResult = (
                self.client.lookup(queries) if queries else OracleResult({}, None, available=True)
            )
        except Exception as e:  # noqa: BLE001 (a probe never raises)
            env = Envelope.failed(
                self.step,
                ProbeStatus.ERROR,
                repr(e),
                self.versions,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            env.evidence["queries"] = [q.to_wire() for q in queries]
            return env

        contributions: list[Contribution] = []
        floors: list[Floor] = []
        per_entity: dict[str, dict] = {}
        coverage = 1.0
        for ent in local:
            contributions.append(
                Contribution(
                    signal="suspicion.distrust",
                    value=0.0,
                    subject=ent.id,
                    reason="reputation.local_host",
                )
            )
            per_entity[ent.id] = {
                "kind": ent.kind.value,
                "value": ent.display,
                "verdict": "local",
                "roles": sorted(r.value for r in ent.roles),
            }
        for ent in remote:
            v = result.get(ent.kind.value, ent.value)
            roles = sorted(r.value for r in ent.roles) or [Role.MENTIONED.value]
            risky_role = max(roles, key=lambda r: self.params.unknown_by_role.get(r, 0.0))
            if v.verdict is VerdictKind.KNOWN_BAD:
                distrust = (
                    self.params.known_bad_distrust if v.distrust is None else float(v.distrust)
                )
                reason = f"reputation.known_bad_{ent.kind.value}"
                floors.append(
                    Floor(
                        floor="known_bad_entity",
                        min_risk=self.params.known_bad_floor,
                        enforce=Enforce.BLOCK,
                        subject=ent.id,
                        reason=reason,
                    )
                )
            elif v.verdict is VerdictKind.KNOWN_GOOD:
                distrust = 0.0 if v.distrust is None else float(v.distrust)
                reason = f"reputation.known_good_{ent.kind.value}" + (
                    f"_{v.tier}" if v.tier else ""
                )
            else:
                distrust = (
                    float(v.distrust)
                    if v.distrust is not None
                    else self.params.unknown_by_role.get(risky_role, 0.1)
                )
                reason = f"reputation.unknown_{ent.kind.value}_as_{risky_role}"
                if risky_role in (
                    Role.DATA_DESTINATION.value,
                    Role.RECIPIENT.value,
                    Role.CODE_SOURCE.value,
                    Role.EXECUTABLE.value,
                ):
                    coverage = min(coverage, self.params.coverage_unknown_risky)
            contributions.append(
                Contribution(
                    signal="suspicion.distrust",
                    value=min(1.0, max(0.0, distrust)),
                    subject=ent.id,
                    reason=reason,
                )
            )
            per_entity[ent.id] = {
                "kind": ent.kind.value,
                "value": ent.display,
                "roles": roles,
                "verdict": v.verdict.value,
                "tier": v.tier,
                "source": v.source,
                "observations": v.observations or None,
            }
        if not result.available:
            coverage = min(coverage, self.params.coverage_unavailable)
        if coverage < 1.0 or remote:
            contributions.append(
                Contribution(
                    signal="confidence.coverage",
                    value=coverage,
                    reason="coverage.oracle_unavailable"
                    if not result.available
                    else "coverage.unknown_entities",
                )
            )

        versions = self.versions
        versions["library_snapshot"] = result.library_snapshot
        return Envelope(
            step=self.step,
            versions=versions,
            status=ProbeStatus.OK,
            latency_ms=(time.perf_counter() - started) * 1000,
            contributions=contributions,
            floors=floors,
            evidence={
                "entities": per_entity,
                "available": result.available,
                "queried": len(queries),
                "local": [e.id for e in local],
            },
        )
