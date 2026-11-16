"""Entity oracle probe.

Looks up every off-host or installable entity the pending call (or a sibling, or the agent-written file
it executes) touches, with its roles, and contributes `suspicion.distrust` per entity by verdict and
role. A `known_bad` entity also raises the `known_bad_entity` floor (1.0, block). An unknown entity that
is a near miss of a `known_good` one (another TLD, a hyphen, a confusable character or one edit away)
gets the near-miss distrust instead of the unknown one when it takes data, code or tools: it looks like
a party the library vouches for and is not it. When it supplies code or tools, it can also raise the
`lookalike_code_source` floor (`near_miss_floor`, off by default; never for an entity a grant
covers), which lifts the score without setting an outcome. An unknown MCP server or plugin that is the
only known destination of the call's send (a send tool that names no recipient, channel or host) can
take a destination-grade distrust instead of the provider's (`unknown_sole_destination_provider`, off
at 0). An unknown MCP server or plugin serving a tool that an earlier step of the session called through
a different provider takes at least `unknown_switched_provider` (off at 0): the host's configuration did
not simply supply it; where both arms apply the higher value wins. Unknown entities in a risky role lower `confidence.coverage`; so does an unavailable oracle.
A host that is only the mail domain of an
email recipient in the call is part of that recipient: when the library has nothing on the host itself
(unknown, not a near miss, no distrust of its own), it adds no distrust and no coverage loss beyond
the recipient's, so relief on the address leaves nothing behind on its domain. An entity only another
call in the batch names (not the pending call, the file it runs, or the pending command read through a
sibling's write) is looked up and reported, but an unknown one adds no distrust and no coverage loss
here: every call in a batch has its own scan. A known-bad one, a look-alike of a vouched entity and one
the library gives a distrust of its own count wherever in the batch they are. Paths are not reputation
questions (their sensitivity comes from AIRA's path classes), loopback hosts are the agent's own
machine, and a recipient written as a self-reference (`me`, `self`, `owner`) is the account the tool
runs as, so none of these is looked up.

A host or repository that self-modification content the call writes (a cron line, a hook, a skill, a job prompt)
sends to or runs code from in its later run (`Entity.future_roles`) is scored in that role when nobody named it (not
the owner's request, a grant or the owner's own configuration). Unknown, it takes the unknown distrust of that role
with the reason `reputation.unknown_in_written_selfmod`, which the attended-owner check counts as a strong signal.

A provider API host the library lists only as the home of the credentials its service issues (tier
`provider_api`) vouches for nothing else: it is scored, reported and shown to the judge as an unlisted host,
and its credential names are kept in the evidence for the credential-home check (`prepare.credential_home`).
Its look-alikes are still near misses of it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace

from ..enums import Enforce, ProbeStatus, ProbeStep
from ..oracle.client import (
    EntityQuery,
    Match,
    NullOracle,
    OracleClient,
    OracleResult,
    Verdict,
    VerdictKind,
    is_local_host,
)
from ..planir.models import ToolKind
from ..prepare import Prepared
from ..prepare.credential_home import PROVIDER_API_TIER
from ..prepare.entities import Entity, EntityKind, Origin, Role
from .base import Contribution, Envelope, Floor

PROBE_VERSION = "entity_oracle/2.0.0a1"
#: An unknown host or repository nobody named that a later run, set up by self-modification content the call
#: writes (a cron line, a hook, a skill, a job prompt), sends to or runs code from.
WRITTEN_SELFMOD_REASON = "reputation.unknown_in_written_selfmod"

LOOKUP_KINDS = (
    EntityKind.HOST,
    EntityKind.RECIPIENT,
    EntityKind.CHANNEL,
    EntityKind.PACKAGE,
    EntityKind.PLUGIN,
    EntityKind.MCP_SERVER,
    EntityKind.REPO,
)


@dataclass(frozen=True)
class OracleParams:
    """Starting values, overridable from the convergence parameter set."""

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
    #: An unknown MCP server or plugin that is the only known destination of the call's send (a send tool
    #: that names no recipient, channel or host) takes at least this distrust, as a party that receives
    #: data. 0 leaves it scored as a tool provider only.
    unknown_sole_destination_provider: float = 0.0
    #: The pending call's MCP server or plugin, when an earlier step of the session called the same tool
    #: name through a different provider (another version of the same package is the same provider) and
    #: the library does not vouch for this one, takes at least this distrust: the host's configuration
    #: did not simply supply it. With the sole-destination arm, the higher value wins. 0 = off.
    unknown_switched_provider: float = 0.0
    known_bad_distrust: float = 1.0
    #: An unknown entity in one of `NEAR_MISS_ROLES` that is a near miss of a `known_good` entry.
    near_miss_distrust: float = 0.9
    known_bad_floor: float = 1.0
    #: Minimum risk for a near miss that supplies code or tools to the call (`NEAR_MISS_CODE_ROLES`),
    #: unless a grant covers it. It lifts the score and sets no outcome (0 = off).
    near_miss_floor: float = 0.0
    coverage_unknown_risky: float = 0.8
    coverage_unavailable: float = 0.7
    #: `consequence.sensitivity` of installing a package the library does not know and neither the
    #: owner's request nor a grant names: its install scripts run with the agent's own read access and
    #: nobody vouched for them. Read by the AIRA probe, which sees the install (0 = off).
    unvetted_package_sensitivity: float = 0.0
    #: Where "the library does not know it" says something: ecosystems the library covers with its
    #: known-good packages, and installs from a URL (`git+`), which no registry stands behind.
    #: Elsewhere (system package managers and the like) unknown only means not covered.
    unvetted_package_ecosystems: tuple[str, ...] = ("npm", "pypi", "git+")
    #: Carry that sensitivity for a package the owner named too, when the install runs as root
    #: (`sudo apt-get install …`): the package's maintainer scripts then run with root's access, and
    #: naming a package is not vetting it. Off by default.
    unvetted_package_as_root: bool = False


#: The roles in which a near miss takes the near-miss distrust: the entity receives data or supplies
#: code or tools. Read from or only mentioned, it keeps the unknown distrust.
NEAR_MISS_ROLES = frozenset(
    {
        Role.DATA_DESTINATION.value,
        Role.RECIPIENT.value,
        Role.CODE_SOURCE.value,
        Role.EXECUTABLE.value,
        Role.TOOL_PROVIDER.value,
    }
)

#: The roles in which a near miss supplies code or tools: what the call runs, or runs through, is the
#: look-alike's, whatever little the call itself carries.
NEAR_MISS_CODE_ROLES = frozenset(
    {Role.CODE_SOURCE.value, Role.EXECUTABLE.value, Role.TOOL_PROVIDER.value}
)

VIEW_VERDICTS = (VerdictKind.KNOWN_GOOD.value, VerdictKind.KNOWN_BAD.value)


def _credential_home_only(v: Verdict) -> Verdict:
    """A provider API host listed only as its credentials' home answers as an unlisted host, keeping the names."""
    if v.verdict is VerdictKind.KNOWN_GOOD and v.tier == PROVIDER_API_TIER:
        return replace(
            v,
            verdict=VerdictKind.UNKNOWN,
            tier=None,
            distrust=None,
            match=Match.NONE,
            near_miss=None,
        )
    return v


def _near_miss(v: Verdict) -> dict | None:
    """The `known_good` entry an unlisted entity imitates, or None."""
    if v.verdict is not VerdictKind.UNKNOWN or v.distrust is not None:
        return None
    if v.match is not Match.NEAR_MISS or not v.near_miss:
        return None
    return v.near_miss


def verdicts_for_view(envelope: Envelope, *, near_miss: bool = False) -> list[dict[str, object]]:
    """The `reputation` entries a call-v3 view carries: every `known_good` or `known_bad` entity in
    an OK oracle envelope, as `kind`, `value`, `verdict` (and `tier` when the library gives one),
    sorted for a stable request body. Unknown entities are left out: not vouched for is the
    model's default. With `near_miss` (the call-v5 view), an unknown entity that is a near miss of a
    `known_good` one is listed too, as `verdict: unknown` with the entry it imitates in `near_miss`. An entity only
    self-modification content the call writes names (`Entity.only_in_written_selfmod`) is scored, not listed."""
    if envelope.status is not ProbeStatus.OK:
        return []
    out: list[dict[str, object]] = []
    for info in (envelope.evidence.get("entities") or {}).values():
        if not isinstance(info, dict) or info.get("only_in_written_selfmod"):
            # named only inside self-modification content the call writes: scored here, not shown to the judge
            continue
        near = info.get("near_miss") if near_miss else None
        if info.get("verdict") not in VIEW_VERDICTS and not (
            info.get("verdict") == VerdictKind.UNKNOWN.value and isinstance(near, dict)
        ):
            continue
        entry: dict[str, object] = {
            "kind": info.get("kind"),
            "value": info.get("value"),
            "verdict": info.get("verdict"),
        }
        if info.get("tier"):
            entry["tier"] = info["tier"]
        if isinstance(near, dict):
            entry["near_miss"] = near.get("value")
        out.append(entry)
    out.sort(key=lambda e: (str(e["kind"]), str(e["value"]), str(e["verdict"])))
    return out


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

    def _sole_destination_providers(self, prepared: Prepared) -> set[str]:
        """Entity ids of the providers that are the only known destination of the pending call's send."""
        if self.params.unknown_sole_destination_provider <= 0:
            return set()
        if prepared.pending.tool_kind not in (ToolKind.MCP, ToolKind.OTHER):
            return set()
        try:
            from ..aira.analysis import analyse
            from ..aira.detectors import sole_destination_providers
            from ..aira.lists import load_lists

            lists = load_lists()
            refs = sole_destination_providers(analyse(prepared.pending, prepared, lists), lists)
        except Exception:  # noqa: BLE001 (without the rule lists the provider keeps its own role)
            return set()
        return {r.entity_id for r in refs if r.entity_id}

    @staticmethod
    def _later_roles(ent: Entity) -> set[str]:
        """The roles a later run that the call's written self-modification content sets up gives the entity, when
        nobody named it: not the owner's request, a grant or the owner's own configuration."""
        if not ent.future_roles or ent.sanctioned or ent.in_session_trusted:
            return set()
        return {r.value for r in ent.future_roles}

    @staticmethod
    def _entity_info(ent: Entity, v: Verdict, roles: list[str], near: dict | None) -> dict:
        info = {
            "kind": ent.kind.value,
            "value": ent.display,
            "roles": roles,
            "verdict": v.verdict.value,
            "tier": v.tier,
            "source": v.source,
            "observations": v.observations or None,
            "match": v.match.value if v.match else None,
            "near_miss": near,
        }
        if ent.future_roles:
            info["future_roles"] = sorted(r.value for r in ent.future_roles)
        if ent.only_in_written_selfmod:
            info["only_in_written_selfmod"] = True
        if ent.recipient_domain_of:
            info["mail_domain_of"] = list(ent.recipient_domain_of)
        if v.credential_names:
            info["credential_names"] = list(v.credential_names)
        return info

    def run(self, prepared: Prepared) -> Envelope:
        started = time.perf_counter()
        candidates = self._candidates(prepared)
        sole_destinations = self._sole_destination_providers(prepared)
        local = [e for e in candidates if e.kind is EntityKind.HOST and is_local_host(e.value)]
        own = [e for e in candidates if e.self_recipient]
        remote = [e for e in candidates if e not in local and e not in own]
        queries = [
            EntityQuery(
                kind=e.kind.value, value=e.value, roles=tuple(sorted(r.value for r in e.roles))
            )
            for e in remote
        ]
        lookup_error: str | None = None
        try:
            result: OracleResult = (
                self.client.lookup(queries) if queries else OracleResult({}, None, available=True)
            )
        except Exception as e:  # noqa: BLE001 (a probe never raises)
            # A failed lookup must not score lower than having no oracle at all: answer as the null
            # oracle does (everything unknown, coverage lowered) and say so in the evidence, which
            # makes the scan degraded.
            lookup_error = repr(e)
            result = NullOracle().lookup(queries)

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
        for ent in own:
            contributions.append(
                Contribution(
                    signal="suspicion.distrust",
                    value=0.0,
                    subject=ent.id,
                    reason="reputation.self_recipient",
                )
            )
            per_entity[ent.id] = {
                "kind": ent.kind.value,
                "value": ent.display,
                "verdict": "self",
                "roles": sorted(r.value for r in ent.roles),
            }
        for ent in remote:
            v = _credential_home_only(result.get(ent.kind.value, ent.value))
            near = _near_miss(v)
            roles = sorted(r.value for r in ent.roles) or [Role.MENTIONED.value]
            later = self._later_roles(ent)
            risky_role = max(
                sorted(set(roles) | later), key=lambda r: self.params.unknown_by_role.get(r, 0.0)
            )
            # the risk comes from a run the call's written self-modification content sets up
            from_later = bool(later) and self.params.unknown_by_role.get(risky_role, 0.0) >= max(
                self.params.unknown_by_role.get(r, 0.0) for r in roles
            )
            if from_later and risky_role not in later:
                risky_role = max(
                    sorted(later), key=lambda r: self.params.unknown_by_role.get(r, 0.0)
                )
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
                reason = (
                    WRITTEN_SELFMOD_REASON
                    if from_later
                    else f"reputation.unknown_{ent.kind.value}_as_{risky_role}"
                )
                if near is not None and risky_role in NEAR_MISS_ROLES:
                    distrust = max(distrust, self.params.near_miss_distrust)
                    reason = f"reputation.near_miss_{ent.kind.value}"
                    if (
                        self.params.near_miss_floor > 0
                        and NEAR_MISS_CODE_ROLES & set(roles)
                        and Origin.GRANT not in ent.origins
                    ):
                        floors.append(
                            Floor(
                                floor="lookalike_code_source",
                                min_risk=self.params.near_miss_floor,
                                subject=ent.id,
                                reason=reason,
                            )
                        )
                elif v.distrust is None and ent.recipient_domain_of:
                    # only a recipient's mail domain: the recipient's own claim speaks for it
                    per_entity[ent.id] = self._entity_info(ent, v, roles, near)
                    continue
                elif v.distrust is None and ent.sibling_only:
                    # only another call in the batch names it: that call's own scan charges it
                    per_entity[ent.id] = {
                        **self._entity_info(ent, v, roles, near),
                        "sibling_only": True,
                    }
                    continue
                elif (
                    v.distrust is None
                    and ent.id in sole_destinations
                    and self.params.unknown_sole_destination_provider > distrust
                ):
                    # the send names nowhere else for the data to go: the provider receives it
                    distrust = self.params.unknown_sole_destination_provider
                    risky_role = Role.DATA_DESTINATION.value
                    reason = f"reputation.unknown_{ent.kind.value}_as_{risky_role}"
                if (
                    not (near is not None and risky_role in NEAR_MISS_ROLES)
                    and self.params.unknown_switched_provider > 0
                    and self.params.unknown_switched_provider > distrust
                    and prepared.provider_switched_from(ent) is not None
                ):
                    # the session used this tool through another provider: the host did not just supply it
                    distrust = self.params.unknown_switched_provider
                    reason = "reputation.switched_provider"
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
            per_entity[ent.id] = self._entity_info(ent, v, roles, near)
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
                **(
                    {"sole_destination_provider": sorted(sole_destinations)[0]}
                    if sole_destinations
                    else {}
                ),
                **({"lookup_error": lookup_error, "fallback": "null"} if lookup_error else {}),
            },
        )
