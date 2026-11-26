"""The local-code cap: a code tool's program with no network sink in sight may be reviewed or held, never blocked.

A Hermes `execute_code` program the scanner can read as Python, that calls no network sink and leaves nothing
in the conversation's interpreter it cannot follow (`prepare.code_reach`), can only hold the URLs and quoted
commands in its strings. The AIRA probe still scores it the way it scores any text, so those findings stay, and
it also scores it read as code, with those URLs and commands only mentioned (evidence `local_reading`). When the
call read that way, with every other probe's claims and floors as they are, stays under the default block line
and is not enforced to block, the response carries a verdict ceiling of `review` and reason `cap.local_code`.
The risk stays as scored, and the floors and enforcement are those of the code reading. A program that does show
a network sink is scored as before, and so is one that would block read as code. A degraded scan sets no cap.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..enums import Enforce, ProbeStatus, ProbeStep
from ..probes.aira import LOCAL_READING
from ..probes.base import Contribution, Envelope, Floor
from .attended import DEFAULT_BLOCK_LINE
from .formulas import compute
from .merge import Claim, collect, merge
from .params import ConvergenceParams

REASON = "cap.local_code"

_ENFORCE_ORDER = {None: 0, Enforce.REVIEW: 1, Enforce.BLOCK: 2}


@dataclass
class LocalCap:
    #: The call's risk (0-1) read as code, relief and floors applied.
    risk: float
    #: The strongest enforcement of the floors read as code.
    enforced: Enforce | None
    #: The floors read as code: the AIRA probe's code reading and every other probe's own.
    floors: list[Floor] = field(default_factory=list)
    capped: bool = False
    withheld: str | None = None

    def evidence(self) -> dict:
        out: dict = {"risk_local": round(self.risk * 100.0, 2), "capped": self.capped}
        if self.withheld:
            out["withheld"] = self.withheld
        return out


def local_envelopes(envelopes: list[Envelope]) -> list[Envelope] | None:
    """`envelopes` with the AIRA probe's code reading in place of its text reading; None when the AIRA probe
    gave no code reading (the program reaches a network sink, or the call is not such a program)."""
    out: list[Envelope] = []
    found = False
    for env in envelopes:
        reading = env.evidence.get(LOCAL_READING) if env.step is ProbeStep.AIRA else None
        if env.status is ProbeStatus.OK and isinstance(reading, dict):
            found = True
            env = env.model_copy(
                update={
                    "contributions": [
                        Contribution.model_validate(c) for c in reading.get("contributions") or []
                    ],
                    "floors": [Floor.model_validate(f) for f in reading.get("floors") or []],
                }
            )
        out.append(env)
    return out if found else None


def local_cap(
    envelopes: list[Envelope],
    excluded: set[tuple[str, str | None]],
    params: ConvergenceParams,
    *,
    hold_claims: Callable[[list[Claim]], list[Claim]],
    extra_floor_risks: list[float],
    enforced: Enforce | None,
    risk: float,
    degraded: bool,
    exposure_unjudged: bool,
) -> LocalCap | None:
    """The cap for a program with no network sink in sight, or None when the call is not one.

    `hold_claims`: what convergence does to the claims before merging (the credential-home sensitivity hold).
    `extra_floor_risks`: floors convergence adds itself (input too large). `enforced` and `risk`: the scan's own,
    read as text."""
    local = local_envelopes(envelopes)
    if local is None:
        return None
    tiers = compute(
        merge(hold_claims(collect(local)), excluded),
        local,
        params,
        exposure_unjudged=exposure_unjudged,
    )
    floors = [f for env in local if env.status is ProbeStatus.OK for f in env.floors]
    local_enforced: Enforce | None = None
    for f in floors:
        if _ENFORCE_ORDER[f.enforce] > _ENFORCE_ORDER[local_enforced]:
            local_enforced = f.enforce
    if extra_floor_risks and _ENFORCE_ORDER[Enforce.REVIEW] > _ENFORCE_ORDER[local_enforced]:
        local_enforced = Enforce.REVIEW
    alone = max([tiers.risk, *(f.min_risk for f in floors), *extra_floor_risks])
    out = LocalCap(risk=alone, enforced=local_enforced, floors=floors)
    out.capped = (
        local_enforced is not Enforce.BLOCK
        and alone < DEFAULT_BLOCK_LINE
        and (risk > alone or enforced is not local_enforced)
    )
    if out.capped and degraded:
        # the risk read as code rests on partial evidence: no cap, as for the other ceilings
        out.capped = False
        out.withheld = "degraded"
    return out
