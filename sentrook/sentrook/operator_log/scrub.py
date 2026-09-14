"""Secret/PII scrub for the operator log — no per-field length cap."""

from __future__ import annotations

from typing import Any

from sentrook.sanitize.core import (
    apply_pii_patterns,
    apply_secret_patterns,
    is_credential_field,
)
from sentrook.sanitize.rules import SanitizeRules, load_rules

_MAX_DEPTH = 16


def scrub_operator_text(
    text: str,
    *,
    pii: bool = True,
    rules: SanitizeRules | None = None,
) -> str:
    rules = rules or load_rules()
    cleaned = apply_secret_patterns(text, rules)
    if pii:
        cleaned = apply_pii_patterns(cleaned, rules)
    return cleaned


def scrub_operator_value(
    value: Any,
    *,
    parent_key: str | None = None,
    pii: bool = False,
    rules: SanitizeRules | None = None,
    depth: int = 0,
) -> Any:
    """Redact credential fields and secret/PII patterns; never truncate."""
    rules = rules or load_rules()
    if depth > _MAX_DEPTH:
        return "[…]"
    if parent_key is not None and is_credential_field(parent_key, rules):
        return rules.redacted
    if isinstance(value, str):
        return scrub_operator_text(value, pii=True, rules=rules)
    if isinstance(value, dict):
        nested_pii = pii or (parent_key is not None and parent_key.lower() == "env")
        return {
            key: scrub_operator_value(
                child,
                parent_key=key,
                pii=nested_pii,
                rules=rules,
                depth=depth + 1,
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [scrub_operator_value(item, pii=pii, rules=rules, depth=depth + 1) for item in value]
    return value
