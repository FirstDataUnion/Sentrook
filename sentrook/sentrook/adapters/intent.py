"""Intent text classification shared by live hosts and replay."""

from __future__ import annotations

import re
from typing import Literal

IntentKind = Literal["user", "cron", "subagent", "system"]

_CRON_PREFIX = re.compile(r"^\s*\[cron:", re.IGNORECASE)
_SUBAGENT_MARKERS = re.compile(
    r"\[Subagent Context\]|\[Subagent Task\]", re.IGNORECASE
)
_SYSTEM_PREFIX = re.compile(r"^\s*\[system[:\]]", re.IGNORECASE)


def classify_intent(text: str | None) -> IntentKind | None:
    """Classify a host prompt into a coarse intent kind for logging and L3."""
    if not text or not text.strip():
        return None
    normalized = text.strip()
    if _CRON_PREFIX.search(normalized):
        return "cron"
    if _SUBAGENT_MARKERS.search(normalized):
        return "subagent"
    if _SYSTEM_PREFIX.search(normalized):
        return "system"
    return "user"


def run_id_from_idempotency_key(key: str | None) -> str | None:
    """Extract OpenClaw run id from a user message idempotency key."""
    if not key or ":" not in key:
        return None
    run_id, _suffix = key.split(":", 1)
    return run_id or None
