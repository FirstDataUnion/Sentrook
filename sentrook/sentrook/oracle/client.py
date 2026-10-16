"""Entity oracle client: the interface Rookery's reputation endpoint will implement (build plan 6.5, D5).

`lookup` takes the entities a call touches, each with its role, and returns a verdict per entity:
`known_good`, `known_bad` or `unknown` (unlisted entities are unknown), an optional explicit `distrust`,
an optional `tier` (for example `infrastructure` for the verified installer list) and observations, plus
the library snapshot the answers came from. Reputation depends on role: a host can be a fine code source
and a bad data destination, so the role travels with the query.

Three implementations:
- `SeedOracle`: built from a TestNest case's `oracle_seed` in test mode.
- `NullOracle`: answers `unknown` for everything and reports itself unavailable, so a live `/scan`
  without a Rookery degrades safely (lower coverage) instead of inventing verdicts.
- `HttpOracle`: `POST {base_url}/entities/lookup` with the same shapes, for when Rookery exists.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

import httpx

LOOKUP_PATH = "/entities/lookup"


class VerdictKind(StrEnum):
    KNOWN_GOOD = "known_good"
    KNOWN_BAD = "known_bad"
    UNKNOWN = "unknown"


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


def _normalise(kind: str, value: str) -> str:
    if kind in ("host", "mcp_server", "package", "plugin"):
        return value.strip().lower()
    if kind == "recipient" and "@" in value:
        return value.strip().lower()
    return value.strip()


class SeedOracle:
    """Verdicts from a TestNest `oracle_seed`. Hosts also match a seeded parent domain."""

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
                    if k not in ("kind", "value", "verdict", "distrust", "tier")
                },
                source="seed",
            )

    def lookup(self, queries: list[EntityQuery]) -> OracleResult:
        out: dict[tuple[str, str], Verdict] = {}
        for q in queries:
            key = (q.kind, _normalise(q.kind, q.value))
            hit = self._by_key.get(key)
            if hit is None and q.kind == "host":
                parts = key[1].split(".")
                for i in range(1, len(parts) - 1):
                    hit = self._by_key.get(("host", ".".join(parts[i:])))
                    if hit is not None:
                        break
            if hit is None and q.kind == "recipient" and "@" in q.value:
                hit = self._by_key.get(("host", q.value.split("@", 1)[1].lower()))
                if hit is not None and hit.verdict is not VerdictKind.KNOWN_BAD:
                    hit = None  # a good mail domain says nothing about one address; a bad one taints it
            out[(q.kind, q.value)] = hit if hit is not None else Verdict(kind=q.kind, value=q.value)
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


class HttpOracle:
    """Rookery's oracle over HTTP. Wire shapes: request `{"entities": [{kind, value, roles}]}`, response
    `{"verdicts": [{kind, value, verdict, distrust?, tier?, observations?}], "library_snapshot": "..."}`."""

    name = "rookery"

    def __init__(self, base_url: str, api_key: str | None = None, timeout_s: float = 2.0):
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout_s)

    def lookup(self, queries: list[EntityQuery]) -> OracleResult:
        r = self._http.post(LOOKUP_PATH, json={"entities": [q.to_wire() for q in queries]})
        r.raise_for_status()
        data = r.json()
        out: dict[tuple[str, str], Verdict] = {}
        for v in data.get("verdicts") or []:
            try:
                verdict = VerdictKind(str(v.get("verdict", "unknown")))
            except ValueError:
                verdict = VerdictKind.UNKNOWN
            out[(v["kind"], v["value"])] = Verdict(
                kind=v["kind"],
                value=v["value"],
                verdict=verdict,
                distrust=v.get("distrust"),
                tier=v.get("tier"),
                observations=v.get("observations") or {},
                source="library",
            )
        for q in queries:
            out.setdefault((q.kind, q.value), Verdict(kind=q.kind, value=q.value, source="library"))
        return OracleResult(
            verdicts=out, library_snapshot=data.get("library_snapshot"), available=True
        )

    def close(self) -> None:
        self._http.close()
