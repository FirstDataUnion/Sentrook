"""Secret-pattern unit tests for scrubbing (Discord webhooks, etc.)."""

from __future__ import annotations

import pytest

from sentrook.sanitize.core import apply_secret_patterns
from sentrook.sanitize.rules import load_rules


@pytest.fixture
def rules():
    load_rules.cache_clear()
    try:
        yield load_rules()
    finally:
        load_rules.cache_clear()


def test_redacts_intact_discord_webhook(rules) -> None:
    token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789"
    hook = f"https://discord.com/api/webhooks/123456789012345678/{token}"
    cleaned = apply_secret_patterns(f"curl {hook}", rules)
    assert token not in cleaned
    assert "[REDACTED]" in cleaned


def test_redacts_discord_webhook_after_pii_bitten_id(rules) -> None:
    """Snowflake IDs can be PII-replaced first; leftover token must still scrub."""
    token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789"
    broken = f"https://discord.com/api/webhooks/[REDACTED]/{token}"
    cleaned = apply_secret_patterns(broken, rules)
    assert token not in cleaned
    assert cleaned == "[REDACTED]"
