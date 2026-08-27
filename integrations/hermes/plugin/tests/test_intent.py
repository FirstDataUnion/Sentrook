"""intent + unattended unit tests."""

from __future__ import annotations

from .. import intent as intent_mod
from ..intent import classify_intent, is_unattended, resolve_intent_kind


def test_classify_intent_markers() -> None:
    assert classify_intent("[cron: nightly] backup") == "cron"
    assert classify_intent("[Subagent Task] do work") == "subagent"
    assert classify_intent("[system: init]") == "system"
    assert classify_intent("hello") == "user"


def test_is_unattended_cron_env(monkeypatch) -> None:
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    assert is_unattended() is True


def test_is_unattended_platform_cron() -> None:
    assert is_unattended(platform="cron") is True


def test_is_unattended_platform_subagent() -> None:
    assert is_unattended(platform="subagent") is True


def test_is_unattended_subagent_flag() -> None:
    assert is_unattended(subagent=True) is True


def test_is_unattended_yolo_env(monkeypatch) -> None:
    monkeypatch.setattr(intent_mod, "is_non_tty", lambda: False)
    monkeypatch.setattr(
        intent_mod,
        "is_hermes_approval_bypass",
        lambda env=None: True,
    )
    assert is_unattended(platform="discord") is True


def test_is_unattended_discord_attended_despite_non_tty(monkeypatch) -> None:
    monkeypatch.setattr(intent_mod, "is_non_tty", lambda: True)
    monkeypatch.setattr(intent_mod, "is_hermes_approval_bypass", lambda env=None: False)
    assert is_unattended(platform="discord") is False
    assert is_unattended(platform="telegram") is False


def test_is_unattended_discord_env_platform(monkeypatch) -> None:
    monkeypatch.setattr(intent_mod, "is_non_tty", lambda: True)
    monkeypatch.setattr(intent_mod, "is_hermes_approval_bypass", lambda env=None: False)
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "discord")
    assert is_unattended() is False


def test_is_unattended_cron_wins_over_discord(monkeypatch) -> None:
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    assert is_unattended(platform="discord") is True


def test_is_unattended_webhook_and_homeassistant_non_tty(monkeypatch) -> None:
    monkeypatch.setattr(intent_mod, "is_non_tty", lambda: True)
    monkeypatch.setattr(intent_mod, "is_hermes_approval_bypass", lambda env=None: False)
    assert is_unattended(platform="webhook") is True
    assert is_unattended(platform="homeassistant") is True
    assert is_unattended(platform="discord") is False


def test_is_unattended_non_tty_cli_still_unattended(monkeypatch) -> None:
    monkeypatch.setattr(intent_mod, "is_non_tty", lambda: True)
    monkeypatch.setattr(intent_mod, "is_hermes_approval_bypass", lambda env=None: False)
    assert is_unattended(platform=None) is True
    assert is_unattended(platform="cli") is True


def test_is_unattended_discord_via_session_context(monkeypatch) -> None:
    monkeypatch.setattr(intent_mod, "is_non_tty", lambda: True)
    monkeypatch.setattr(intent_mod, "is_hermes_approval_bypass", lambda env=None: False)
    monkeypatch.setattr(intent_mod, "_hermes_session_platform", lambda: "discord")
    assert is_unattended(platform=None) is False


def test_resolve_session_platform_prefers_explicit(monkeypatch) -> None:
    monkeypatch.setattr(intent_mod, "_hermes_session_platform", lambda: "telegram")
    assert intent_mod.resolve_session_platform("discord") == "discord"
    assert intent_mod.resolve_session_platform(None) == "telegram"


def test_resolve_intent_kind_prefers_subagent() -> None:
    assert resolve_intent_kind("user", "hello", subagent=True) == "subagent"


def test_resolve_intent_kind_platform_subagent() -> None:
    assert resolve_intent_kind(None, None, platform="subagent") == "subagent"


def test_resolve_intent_kind_cron_env(monkeypatch) -> None:
    monkeypatch.setenv("HERMES_CRON_SESSION", "true")
    assert resolve_intent_kind(None, None) == "cron"
