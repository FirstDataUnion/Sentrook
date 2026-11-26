"""Which Jev route answers a call, and the outcome of every route's call for `/metrics`.

Modes (`SENTROOK_JEV_ROUTE`):

- `primary` (the default): the Decisions API only. A result or an error passes through unchanged, and no route
  is recorded in the scan response.
- `fallback_on_outage`: the primary first; when it fails with an `outage` (5xx, timeout, connection error) the
  secondary answers instead.
- `fallback_on_rejected`: the primary first; when it fails with `provider_rejected` (a 4xx other than 429 and the
  context limit) the secondary answers instead.
- `secondary`: the secondary only.

A rate limit, a request over the context limit and an invalid answer never fall back: the first passes, the
second would be too large for any route, and the third is not the provider's refusal. When the fallback fails too,
the primary's error is raised, so `/healthz` keeps reporting why the primary failed. Outside `primary` mode each
result carries the route that answered (`DecisionResult.route`), which the probes copy into their versions.

Every call to a route is reported to `observer(route, outcome)` with one of `client.OUTCOMES`, whatever the mode.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .client import (
    OK,
    OUTAGE,
    PROVIDER_REJECTED,
    ApiError,
    Decider,
    DecisionResult,
    classify_failure,
)

PRIMARY = "primary"
SECONDARY = "secondary"
MODE_PRIMARY = "primary"
MODE_FALLBACK_ON_OUTAGE = "fallback_on_outage"
MODE_FALLBACK_ON_REJECTED = "fallback_on_rejected"
MODE_SECONDARY = "secondary"
MODES = (MODE_PRIMARY, MODE_FALLBACK_ON_OUTAGE, MODE_FALLBACK_ON_REJECTED, MODE_SECONDARY)
#: The primary failure class each fallback mode hands to the secondary.
FALLS_BACK_ON = {MODE_FALLBACK_ON_OUTAGE: OUTAGE, MODE_FALLBACK_ON_REJECTED: PROVIDER_REJECTED}

Observer = Callable[[str, str], None]


def _ignore(route: str, outcome: str) -> None:
    return None


class RoutedDecider:
    """A decider over a primary and an optional secondary route, in one of `MODES`."""

    def __init__(
        self,
        primary: Decider,
        secondary: Decider | None = None,
        *,
        mode: str = MODE_PRIMARY,
        observer: Observer | None = None,
    ):
        if mode not in MODES:
            raise ValueError(f"unknown Jev route mode {mode!r}; known: {', '.join(MODES)}")
        if mode != MODE_PRIMARY and secondary is None:
            raise ValueError(f"Jev route mode {mode!r} needs a secondary route")
        self.primary = primary
        self.secondary = secondary
        self.mode = mode
        self.observer = observer or _ignore

    def _one(self, route: str, decider: Decider, body: dict[str, Any], repeat: int | None):
        try:
            result = decider.decide(body, repeat=repeat)
        except Exception as exc:
            self.observer(route, classify_failure(exc))
            raise
        self.observer(route, OK)
        if self.mode != MODE_PRIMARY:
            result.route = route
        return result

    def decide(self, body: dict[str, Any], *, repeat: int | None = None) -> DecisionResult:
        if self.mode == MODE_SECONDARY:
            assert self.secondary is not None
            return self._one(SECONDARY, self.secondary, body, repeat)
        try:
            return self._one(PRIMARY, self.primary, body, repeat)
        except ApiError as exc:
            wanted = FALLS_BACK_ON.get(self.mode)
            if wanted is None or classify_failure(exc) != wanted:
                raise
            assert self.secondary is not None
            try:
                return self._one(SECONDARY, self.secondary, body, repeat)
            except Exception:
                raise exc from None
