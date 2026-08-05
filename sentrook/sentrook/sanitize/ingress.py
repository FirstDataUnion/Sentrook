"""Server ingress helpers — optional full PlanIR sanitization."""

from __future__ import annotations

from sentrook.planir import PlanIR
from sentrook.sanitize.planir import sanitize_planir


def maybe_sanitize_planir(
    plan: PlanIR,
    *,
    enabled: bool,
) -> tuple[PlanIR, int]:
    """Sanitize when ``enabled``; otherwise return the input unchanged."""
    if not enabled:
        return plan, 0
    result = sanitize_planir(plan)
    return result.plan, result.sanitize_ms
