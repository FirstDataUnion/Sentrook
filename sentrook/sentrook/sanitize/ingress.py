"""Server ingress helpers — optional full snapshot sanitization."""

from __future__ import annotations

from sentrook.sanitize.snapshot import sanitize_snapshot
from sentrook.shadow.snapshot import ShadowSnapshot


def maybe_sanitize_snapshot(
    snapshot: ShadowSnapshot,
    *,
    enabled: bool,
) -> tuple[ShadowSnapshot, int]:
    """Sanitize when ``enabled``; otherwise return the input unchanged."""
    if not enabled:
        return snapshot, 0
    result = sanitize_snapshot(snapshot)
    return result.snapshot, result.sanitize_ms
