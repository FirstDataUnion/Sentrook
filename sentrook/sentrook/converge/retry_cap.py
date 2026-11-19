"""The unanswered-review retry cap: a retry of a review nobody answered may ask the owner, never block on its own.

`retry_after_denial` scores a call that repeats an earlier denied step. When every step it matches is a review
nobody answered (the review timed out or is held, or the host's own review loop denied it unseen: `blocked` with
`decided_by: review_loop`), the owner never refused the action, and is often the one asking for it again. Such a
retry can raise the verdict to review but not to block: when the call scored without the retry (its suspicion and
the consequence it carried from the denied step) stays under the default block line, the response carries a
verdict ceiling of `review`. The risk stays as scored. A retry that also matches a step the owner refused or the
scanner blocked is unchanged, and so is a call that would block without the retry.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..enums import ProbeStatus, ProbeStep
from ..probes.base import Envelope
from .formulas import compute
from .merge import Claim, merge
from .params import ConvergenceParams

RETRY_SIGNAL = "suspicion.retry_after_denial"
#: The reason of the consequence a matched retry carries from the denied step.
CARRIED_REASON = "retry.denied_consequence_carried"
REASON = "cap.unanswered_retry"


def unanswered_retry(envelopes: Iterable[Envelope]) -> bool:
    """The call is a retry, and every step it matches is a review nobody answered."""
    for env in envelopes:
        if env.step is not ProbeStep.CONTEXT or env.status is not ProbeStatus.OK:
            continue
        retry = env.evidence.get("retry")
        if not isinstance(retry, dict) or not retry.get("unanswered_only"):
            return False
        return any(c.signal == RETRY_SIGNAL and c.value > 0.0 for c in env.contributions)
    return False


def without_retry(claims: Iterable[Claim]) -> list[Claim]:
    """`claims` less the retry's suspicion and the consequence it carried."""
    return [c for c in claims if c.signal != RETRY_SIGNAL and c.reason != CARRIED_REASON]


def risk_without_retry(
    claims: list[Claim],
    excluded: set[tuple[str, str | None]],
    envelopes: list[Envelope],
    params: ConvergenceParams,
    floor_risks: Iterable[float],
    *,
    exposure_unjudged: bool,
) -> float:
    """The call's risk (0-1, relief and floors applied) had it not been a retry."""
    tiers = compute(
        merge(without_retry(claims), excluded),
        envelopes,
        params,
        exposure_unjudged=exposure_unjudged,
    )
    return max([tiers.risk, *floor_risks])
