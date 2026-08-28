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
    assert "https://discord.com/api/webhooks/[REDACTED]" in cleaned


def test_keeps_anthropic_prefix(rules) -> None:
    secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
    cleaned = apply_secret_patterns(secret, rules)
    assert secret not in cleaned
    assert cleaned == "sk-ant-[REDACTED]"


def test_keeps_openai_project_and_live_prefixes(rules) -> None:
    proj = "sk-proj-ab12cd34ef56ghijklmnop"
    live = "sk-live-abcdef12ABCDEFGH"
    assert apply_secret_patterns(proj, rules) == "sk-proj-[REDACTED]"
    assert apply_secret_patterns(live, rules) == "sk-live-[REDACTED]"
    assert apply_secret_patterns(f"apiKey={proj}", rules) == "apiKey=sk-proj-[REDACTED]"


def test_keeps_bearer_prefix(rules) -> None:
    cleaned = apply_secret_patterns(
        "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz012345", rules
    )
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in cleaned
    assert cleaned == "Authorization: Bearer [REDACTED]"


def test_keeps_github_token_prefix(rules) -> None:
    token = "ghp_1234567890abcdefghij"
    cleaned = apply_secret_patterns(f"Authorization: token {token}", rules)
    assert token not in cleaned
    assert cleaned == "Authorization: token ghp_[REDACTED]"


def test_redacts_library_bot_pass_export(rules) -> None:
    secret = "x9fakebotpassvalue32charsxxxxxx"
    command = (
        'export PATH="$HOME/.local/bin:$PATH"\n'
        f'export LIBRARY_BOT_PASS="{secret}"\n'
        "TODAY=$(date +%Y-%m-%d)"
    )
    cleaned = apply_secret_patterns(command, rules)
    assert secret not in cleaned
    assert "LIBRARY_BOT_PASS=[REDACTED]" in cleaned
    assert 'PATH="$HOME/.local/bin:$PATH"' in cleaned


def test_redacts_export_value_with_escaped_quotes(rules) -> None:
    secret = r"x9fake\"botpass"
    command = f'export LIBRARY_BOT_PASS="{secret}"'
    cleaned = apply_secret_patterns(command, rules)
    assert "botpass" not in cleaned
    assert cleaned == "export LIBRARY_BOT_PASS=[REDACTED]"


def test_redacts_cli_password_flag_quoted_value(rules) -> None:
    secret = "x9fakebotpassvalue32charsxxxxxx"
    cleaned = apply_secret_patterns(f'curl --password "{secret}" https://example', rules)
    assert secret not in cleaned
    assert cleaned == "curl --password [REDACTED] https://example"


def test_redacts_discord_webhook_after_pii_bitten_id(rules) -> None:
    """Snowflake IDs can be PII-replaced first; leftover token must still scrub."""
    token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789"
    broken = f"https://discord.com/api/webhooks/[REDACTED]/{token}"
    cleaned = apply_secret_patterns(broken, rules)
    assert token not in cleaned
    assert cleaned == "https://discord.com/api/webhooks/[REDACTED]"
