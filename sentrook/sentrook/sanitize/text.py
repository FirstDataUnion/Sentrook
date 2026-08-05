"""String scrubbing helpers shared by feedback and shadow logs."""

from __future__ import annotations

from sentrook.sanitize.core import scrub_string as _scrub_string
from sentrook.sanitize.rules import SanitizeRules, load_rules


def scrub_text(
    text: str,
    *,
    max_chars: int,
    pii: bool = True,
    rules: SanitizeRules | None = None,
) -> str:
    """Apply secret + optional PII patterns, then truncate."""
    rules = rules or load_rules()
    return _scrub_string(text, rules, pii=pii, max_chars=max_chars)
