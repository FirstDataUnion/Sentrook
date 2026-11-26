"""Entity oracle client: the interface Rookery's reputation endpoint will implement.

`lookup` takes the entities a call touches, each with its role, and returns a verdict per entity:
`known_good`, `known_bad` or `unknown` (unlisted entities are unknown), an optional explicit `distrust`,
an optional `tier` (for example `infrastructure` for the verified installer list) and observations, plus
the library snapshot the answers came from. `match` says whether a library entry answered (`exact`) or
not, and when none did, whether the value is a near miss of a `known_good` entry (`near_miss`, with the
entry in `near_miss`; see `near_miss.py`) or not (`none`). A `known_good` host the library lists as the home of
the credentials its service issues also carries their environment names (`credential_names`, read by
`prepare.credential_home`), and one that names its service lists the names owners call it by (`service_names`, read by
`prepare.service_names`). Reputation depends on role: a host can be a fine code source
and a bad data destination, so the role travels with the query.

Three implementations:
- `SeedOracle`: built from a TestNest case's `oracle_seed` in test mode.
- `NullOracle`: answers `unknown` for everything and reports itself unavailable, so a live `/scan`
  without a Rookery degrades safely (lower coverage) instead of inventing verdicts.
- `HttpOracle`: `POST {base_url}/entities/lookup` with the same shapes, for when Rookery exists.

The remote oracle is asked only about public names: hosts, packages, repositories, MCP servers, plugins,
shared channels, and the mail domain of an email recipient. It never receives a person's contact details: an
email recipient is sent as its mail domain alone, written `@domain` (`wire_query`), and a recipient without a
mail domain (a phone number, a chat handle, a name) or a channel target that is a person (`user:` or `dm:`
ids, a chat id carrying a phone number) is not sent at all and answers `unknown`. A recipient is still judged
by its domain: a `known_bad` mail domain taints every address at it, as it always did.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

import httpx

from .near_miss import FOLD_ONLY_TIERS, near_miss_of

LOOKUP_PATH = "/entities/lookup"


class VerdictKind(StrEnum):
    KNOWN_GOOD = "known_good"
    KNOWN_BAD = "known_bad"
    UNKNOWN = "unknown"


class Match(StrEnum):
    EXACT = "exact"
    NEAR_MISS = "near_miss"
    NONE = "none"


@dataclass(frozen=True)
class EntityQuery:
    kind: str
    value: str
    roles: tuple[str, ...] = ()

    def to_wire(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "roles": list(self.roles)}


@dataclass
class Verdict:
    kind: str
    value: str
    verdict: VerdictKind = VerdictKind.UNKNOWN
    distrust: float | None = None  # explicit override, 0–1
    tier: str | None = None
    observations: dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"  # seed | library | builtin | null
    #: None when the oracle does not say (the null oracle, a library without near misses).
    match: Match | None = None
    #: With `match` near_miss: the `known_good` entry, `{value, verdict, tier?, how}`.
    near_miss: dict[str, Any] | None = None
    #: The environment names of the credentials this host's service issues (a `PREFIX*` is a pattern), from an
    #: exact `known_good` library answer only.
    credential_names: tuple[str, ...] = ()
    #: The names owners call this host's service by (`Notion`), from an exact `known_good` library answer only.
    service_names: tuple[str, ...] = ()


@dataclass
class OracleResult:
    verdicts: dict[tuple[str, str], Verdict]
    library_snapshot: str | None
    available: bool = True

    def get(self, kind: str, value: str) -> Verdict:
        return self.verdicts.get((kind, value)) or Verdict(kind=kind, value=value)


class OracleClient(Protocol):
    name: str

    def lookup(self, queries: list[EntityQuery]) -> OracleResult: ...


def is_local_host(value: str) -> bool:
    """Loopback and link-local hosts are the agent's own machine, not a reputation question."""
    v = value.strip().lower().strip("[]")
    if v in ("localhost", "localhost.localdomain", "host.docker.internal"):
        return True
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified


# PyPI compares project names with every run of `-`, `_` and `.` read as one `-`, ignoring case
# (`Foo_Bar`, `foo.bar` and `foo-bar` are one project). Only a value shaped like a project name is
# folded; a local path or `.` given to an installer is only lower-cased.
_PYPI_NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", re.IGNORECASE)


def fold_pypi_name(name: str) -> str:
    n = name.lower()
    return re.sub(r"[-_.]+", "-", n) if _PYPI_NAME_RE.fullmatch(n) else n


def _normalise(kind: str, value: str) -> str:
    if kind == "package" and value.strip().lower().startswith("pypi:"):
        return "pypi:" + fold_pypi_name(value.strip()[5:])
    if kind in ("host", "mcp_server", "package", "plugin", "channel", "repo"):
        return value.strip().lower()
    if kind == "recipient" and "@" in value:
        return value.strip().lower()
    return value.strip()


def _credential_names(raw: Any, kind: str, verdict: VerdictKind) -> tuple[str, ...]:
    """Credential names count only on a `known_good` host, as the library allows them."""
    if kind != "host" or verdict is not VerdictKind.KNOWN_GOOD or not isinstance(raw, list | tuple):
        return ()
    return tuple(sorted({str(n).strip() for n in raw if isinstance(n, str) and n.strip()}))


def _service_names(raw: Any, kind: str, verdict: VerdictKind) -> tuple[str, ...]:
    """Service names count only on a `known_good` host, as the library allows them."""
    if kind != "host" or verdict is not VerdictKind.KNOWN_GOOD or not isinstance(raw, list | tuple):
        return ()
    names = {" ".join(n.split()) for n in raw if isinstance(n, str)}
    return tuple(sorted(n for n in names if 3 <= len(n) <= 64))


class SeedOracle:
    """Verdicts from a TestNest `oracle_seed`. Hosts also match a seeded parent domain. An `unknown`
    seed entry without a distrust says no more than leaving the entity out, so it is not an exact match
    and the value can still be a near miss of a seeded `known_good` entry."""

    name = "seed"

    def __init__(self, seed: dict[str, Any] | None, snapshot: str = "seed"):
        self._by_key: dict[tuple[str, str], Verdict] = {}
        self.snapshot = snapshot
        for e in (seed or {}).get("entities") or []:
            kind, value = str(e.get("kind", "")), str(e.get("value", ""))
            if not kind or not value:
                continue
            try:
                verdict = VerdictKind(str(e.get("verdict", "unknown")))
            except ValueError:
                verdict = VerdictKind.UNKNOWN
            self._by_key[(kind, _normalise(kind, value))] = Verdict(
                kind=kind,
                value=value,
                verdict=verdict,
                distrust=e.get("distrust"),
                tier=e.get("tier"),
                observations={
                    k: v
                    for k, v in e.items()
                    if k
                    not in (
                        "kind",
                        "value",
                        "verdict",
                        "distrust",
                        "tier",
                        "credential_names",
                        "service_names",
                    )
                },
                source="seed",
                credential_names=_credential_names(e.get("credential_names"), kind, verdict),
                service_names=_service_names(e.get("service_names"), kind, verdict),
            )
        self._known_good: dict[str, dict[str, Verdict]] = {}
        for (kind, norm), v in self._by_key.items():
            if v.verdict is VerdictKind.KNOWN_GOOD:
                self._known_good.setdefault(kind, {})[norm] = v
        #: The longest seeded host: a parent domain longer than it is not looked up.
        self._longest_host = max((len(n) for k, n in self._by_key if k == "host"), default=0)

    def _parent_hit(self, host: str) -> Verdict | None:
        """The verdict of the nearest seeded parent domain of `host` (`a.b.c` -> `b.c`, never the
        last label alone). Only parents no longer than the longest seeded host are looked up, each a
        slice from the label it starts at: a host of many labels is read in linear time."""
        dot = host.find(".", max(len(host) - self._longest_host - 1, 0))
        while dot >= 0:
            after = host.find(".", dot + 1)
            if after < 0:
                return None
            hit = self._by_key.get(("host", host[dot + 1 :]))
            if hit is not None:
                return hit
            dot = after
        return None

    def _near_miss(self, kind: str, norm: str) -> dict[str, Any] | None:
        listed = self._known_good.get(kind) or {}
        fold_only = {v for v, e in listed.items() if e.tier in FOLD_ONLY_TIERS}
        found = near_miss_of(kind, norm, listed, fold_only)
        if found is None:
            return None
        entry, how = found
        out: dict[str, Any] = {"value": entry, "verdict": VerdictKind.KNOWN_GOOD.value}
        if listed[entry].tier:
            out["tier"] = listed[entry].tier
        out["how"] = how
        return out

    def lookup(self, queries: list[EntityQuery]) -> OracleResult:
        out: dict[tuple[str, str], Verdict] = {}
        for q in queries:
            key = (q.kind, _normalise(q.kind, q.value))
            hit = self._by_key.get(key)
            if hit is None and q.kind == "host":
                hit = self._parent_hit(key[1])
            if hit is None and q.kind == "recipient" and "@" in q.value:
                hit = self._by_key.get(("host", q.value.split("@", 1)[1].lower()))
                if hit is not None and hit.verdict is not VerdictKind.KNOWN_BAD:
                    hit = None  # a good mail domain says nothing about one address; a bad one taints it
            if hit is not None and (
                hit.verdict is not VerdictKind.UNKNOWN or hit.distrust is not None
            ):
                out[(q.kind, q.value)] = replace(hit, match=Match.EXACT)
                continue
            v = replace(hit) if hit is not None else Verdict(kind=q.kind, value=q.value)
            v.near_miss = self._near_miss(q.kind, key[1])
            v.match = Match.NEAR_MISS if v.near_miss else Match.NONE
            out[(q.kind, q.value)] = v
        return OracleResult(verdicts=out, library_snapshot=self.snapshot, available=True)


class NullOracle:
    """No reputation data: everything unknown, coverage lowered by the probe."""

    name = "null"

    def lookup(self, queries: list[EntityQuery]) -> OracleResult:
        return OracleResult(
            verdicts={
                (q.kind, q.value): Verdict(kind=q.kind, value=q.value, source="null")
                for q in queries
            },
            library_snapshot=None,
            available=False,
        )


#: A channel target that is a person, not a shared channel: a direct-message id, optionally behind a chat
#: platform prefix (`user:<id>`, `dm:<id>`, `slack:user:<id>`).
_PERSON_TARGET_RE = re.compile(r"(?i)^\s*(?:[a-z][a-z0-9_-]{1,20}:)?(?:user|dm):")


def mail_domain(value: str) -> str | None:
    """The domain of an email address, lower-cased; None for any value that is not one."""
    local, at, domain = value.strip().rpartition("@")
    domain = domain.strip().strip(".").lower()
    if not at or not local or not domain or "." not in domain:
        return None
    return domain


def wire_query(q: EntityQuery) -> EntityQuery | None:
    """What the remote oracle is asked for `q`, or None when it is not asked at all.

    An email recipient becomes its mail domain, `@domain` (the `@` keeps it apart from a handle; the oracle
    matches it against the domain's verdict, so a `known_bad` domain still taints the address). Every other
    recipient is a person's address or name and is not sent. A channel target that is a person (a direct
    message, or a chat id with an `@`, which embeds a phone number) is not sent either. Other kinds go as
    they are: they are public names."""
    if q.kind == "recipient":
        domain = mail_domain(q.value)
        return None if domain is None else replace(q, value="@" + domain)
    if q.kind == "channel" and ("@" in q.value or _PERSON_TARGET_RE.match(q.value)):
        return None
    return q


class HttpOracle:
    """Rookery's oracle over HTTP. Wire shapes: request `{"entities": [{kind, value, roles}]}`, response
    `{"verdicts": [{kind, value, verdict, distrust?, tier?, observations?, match?, near_miss?,
    credential_names?, service_names?}],
    "library_snapshot": "..."}`."""

    name = "rookery"

    def __init__(self, base_url: str, api_key: str | None = None, timeout_s: float = 2.0):
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout_s)

    @staticmethod
    def _wire(
        queries: list[EntityQuery],
    ) -> tuple[dict[EntityQuery, EntityQuery], list[EntityQuery]]:
        """Each query's wire form (absent when it is not sent) and the deduplicated request: queries that
        share a wire value (two addresses at one domain) go once, with their roles merged."""
        sent: dict[EntityQuery, EntityQuery] = {}
        merged: dict[tuple[str, str], set[str]] = {}
        for q in queries:
            w = wire_query(q)
            if w is None:
                continue
            sent[q] = w
            merged.setdefault((w.kind, w.value), set()).update(w.roles)
        request = [EntityQuery(k, v, tuple(sorted(roles))) for (k, v), roles in merged.items()]
        return sent, request

    def lookup(self, queries: list[EntityQuery]) -> OracleResult:
        sent, request = self._wire(queries)
        if not request:
            return OracleResult(
                verdicts={
                    (q.kind, q.value): Verdict(
                        kind=q.kind, value=q.value, source="library", match=Match.NONE
                    )
                    for q in queries
                },
                library_snapshot=None,
                available=True,
            )
        r = self._http.post(LOOKUP_PATH, json={"entities": [q.to_wire() for q in request]})
        r.raise_for_status()
        data = r.json()
        out: dict[tuple[str, str], Verdict] = {}
        for v in data.get("verdicts") or []:
            try:
                verdict = VerdictKind(str(v.get("verdict", "unknown")))
            except ValueError:
                verdict = VerdictKind.UNKNOWN
            try:
                match = Match(v["match"]) if v.get("match") else None
            except ValueError:
                match = None
            near = v.get("near_miss")
            near_ok = (
                match is Match.NEAR_MISS and isinstance(near, dict) and bool(near.get("value"))
            )
            out[(v["kind"], v["value"])] = Verdict(
                kind=v["kind"],
                value=v["value"],
                verdict=verdict,
                distrust=v.get("distrust"),
                tier=v.get("tier"),
                observations=v.get("observations") or {},
                source="library",
                match=match if near_ok or match is not Match.NEAR_MISS else Match.NONE,
                near_miss=dict(near) if near_ok else None,
                credential_names=(
                    _credential_names(v.get("credential_names"), v["kind"], verdict)
                    if match is Match.EXACT
                    else ()
                ),
                service_names=(
                    _service_names(v.get("service_names"), v["kind"], verdict)
                    if match is Match.EXACT
                    else ()
                ),
            )
        for q in queries:
            w = sent.get(q)
            if w is None:
                # never sent: the oracle holds no contact details, so it has nothing to say
                out[(q.kind, q.value)] = Verdict(
                    kind=q.kind, value=q.value, source="library", match=Match.NONE
                )
            elif w != q:
                answer = out.get((w.kind, w.value))
                out[(q.kind, q.value)] = (
                    replace(answer, value=q.value)
                    if answer is not None
                    else Verdict(kind=q.kind, value=q.value, source="library")
                )
            else:
                out.setdefault(
                    (q.kind, q.value), Verdict(kind=q.kind, value=q.value, source="library")
                )
        return OracleResult(
            verdicts=out, library_snapshot=data.get("library_snapshot"), available=True
        )

    def close(self) -> None:
        self._http.close()
