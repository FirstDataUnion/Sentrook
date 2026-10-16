"""The AIRA probe (WP3): deterministic consequence detectors over the prepared call.

`AiraProbe.run(prepared)` analyses the pending call and each sibling with the detectors in
`aira.detectors`, and returns one envelope: contributions on `consequence.sensitivity`,
`consequence.reach`, `consequence.irreversibility`, `consequence.self_modification` and
`suspicion.concealment`; the `guardrail_tampering` and `untrusted_code_execution` floors; the
`holds_sensitive` session flag; and evidence (classes, internal rule ids, the exec shape summary,
packs, per-finding detail). It never raises: a failure is `Envelope.failed`.

Packs: `tier1` (always on) carries C1, C2, C3, C4, C4*, C9, C10 and extent; `host_gated` carries
C7 and the sudo arm of C8, and is on when `planir.options.packs` lists it (or the constructor's
`enabled_packs` does).
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

from ..aira import AIRA_VERSION
from ..aira.analysis import analyse
from ..aira.detectors import PACK_TIER1, Context, Finding, call_label, run_detectors
from ..aira.lists import Lists, load_lists
from ..enums import ProbeStatus, ProbeStep, SessionFlag
from ..probes.base import Contribution, Envelope, Floor

__all__ = ["AiraProbe", "AIRA_VERSION"]


class AiraProbe:
    """`Probe` implementation for `ProbeStep.AIRA`.

    `lists`: the compiled data lists (default: `load_lists()`, honouring `SENTROOK_LISTS_DIR`).
    `enabled_packs`: overrides `planir.options.packs` when given; `tier1` is always included.
    """

    step: ProbeStep = ProbeStep.AIRA

    def __init__(
        self, lists: Lists | None = None, enabled_packs: Iterable[str] | None = None
    ) -> None:
        self._lists = lists
        self._packs = frozenset(enabled_packs) if enabled_packs is not None else None

    @property
    def lists(self) -> Lists:
        if self._lists is None:
            self._lists = load_lists()
        return self._lists

    @property
    def versions(self) -> dict[str, str | None]:
        return {"probe": AIRA_VERSION, "ruleset": self.lists.version}

    def packs_for(self, prepared: Any) -> frozenset[str]:
        if self._packs is not None:
            return self._packs | {PACK_TIER1}
        listed = getattr(getattr(prepared.planir, "options", None), "packs", None) or [PACK_TIER1]
        return frozenset(str(p) for p in listed) | {PACK_TIER1}

    def run(self, prepared: Any) -> Envelope:
        start = time.perf_counter()
        versions = self.versions
        try:
            return self._run(prepared, versions, start)
        except Exception as exc:  # the probe must never raise
            return Envelope.failed(
                self.step,
                ProbeStatus.ERROR,
                f"{type(exc).__name__}: {exc}",
                versions=versions,
                latency_ms=(time.perf_counter() - start) * 1000,
            )

    def _run(self, prepared: Any, versions: dict[str, str | None], start: float) -> Envelope:
        ctx = Context(prepared=prepared, lists=self.lists, packs=self.packs_for(prepared))
        contributions: list[Contribution] = []
        floors: list[Floor] = []
        flags: list[SessionFlag] = []
        classes: set[str] = set()
        rules: list[str] = []
        reasons: list[str] = []
        evidence_findings: list[dict[str, Any]] = []
        shape_summary: dict[str, Any] | None = None
        paths_evidence: list[dict[str, Any]] = []
        hosts_evidence: list[str] = []
        siblings_evidence: dict[str, Any] = {}
        skipped: list[str] = []
        seen_contributions: set[tuple[str, float, str | None, str | None]] = set()

        for call in [prepared.pending, *prepared.siblings]:
            a = analyse(call, prepared, self.lists)
            findings, skipped_here = run_detectors(a, ctx)
            skipped = skipped_here
            label = call_label(call)
            for f in findings:
                classes.add(f.cls)
                if f.rule not in rules:
                    rules.append(f.rule)
                for c in f.contributions:
                    if c.reason and c.reason not in reasons:
                        reasons.append(c.reason)
                    # C1 and C2 can assert the same sensitivity on the same path: one claim.
                    key = (c.signal, c.value, c.subject, c.reason)
                    if key in seen_contributions:
                        continue
                    seen_contributions.add(key)
                    contributions.append(c)
                floors.extend(f.floors)
                for flag in f.flags:
                    if flag not in flags:
                        flags.append(flag)
                evidence_findings.append(f.to_evidence(label))
            summary = a.shape.summary() if a.shape is not None else None
            call_paths = [
                {
                    "path": p.display,
                    "groups": p.groups,
                    "locations": p.locations,
                    "roles": sorted(r.value for r in p.roles),
                    "entity": p.entity_id,
                }
                for p in a.paths
            ]
            if call is prepared.pending:
                shape_summary = summary
                paths_evidence = call_paths
                hosts_evidence = [h.value for h in a.hosts]
            else:
                siblings_evidence[label] = {
                    "classes": sorted({f.cls for f in findings}),
                    "rules": [f.rule for f in findings],
                    "shape": summary,
                    "paths": call_paths,
                }

        evidence: dict[str, Any] = {
            "classes": sorted(classes),
            "rules": rules,
            "reasons": reasons,
            "shape": shape_summary,
            "paths": paths_evidence,
            "hosts": hosts_evidence,
            "packs": sorted(ctx.packs),
            "skipped_classes": skipped,
            "findings": evidence_findings,
        }
        if siblings_evidence:
            evidence["siblings"] = siblings_evidence
        return Envelope(
            step=self.step,
            versions=versions,
            status=ProbeStatus.OK,
            latency_ms=(time.perf_counter() - start) * 1000,
            contributions=contributions,
            floors=floors,
            flags_set=flags,
            evidence=evidence,
        )


def findings_of(envelope: Envelope) -> list[dict[str, Any]]:
    """The per-finding evidence of an AIRA envelope (a convenience for tests and TestNest)."""
    return list(envelope.evidence.get("findings", []))


_ = Finding  # re-exported type for callers that inspect evidence
