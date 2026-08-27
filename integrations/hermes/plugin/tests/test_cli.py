"""CLI configure helpers."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest

from ..cli import (
    _collect_configure_answers,
    _update_plugin_settings,
    feedback_mode_from_contribute,
)


def test_collect_configure_answers_non_interactive_oidc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_SCAN_CLIENT_ID", "cid")
    monkeypatch.setenv("SENTROOK_SCAN_CLIENT_SECRET", "csec")
    args = Namespace(
        client_id=None,
        client_secret=None,
        timeout_ms=45000,
        on_scan_error="deny",
        contribute_corpus="false",
    )
    answers = _collect_configure_answers(args, interactive=False)
    assert answers is not None
    assert answers.client_id == "cid"
    assert answers.client_secret == "csec"
    assert answers.timeout_ms == 45000
    assert answers.on_scan_error == "deny"
    assert answers.contribute_corpus is False
    assert feedback_mode_from_contribute(answers.contribute_corpus) == "off"


def test_collect_configure_answers_non_interactive_missing_creds() -> None:
    args = Namespace(
        client_id=None,
        client_secret=None,
        timeout_ms=None,
        on_scan_error=None,
        contribute_corpus=None,
    )
    assert _collect_configure_answers(args, interactive=False) is None


def test_update_plugin_settings_enables_plugin_and_strips_scan_url(tmp_path: Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "plugins:\n  entries:\n    sentrook:\n      settings:\n        scan_base_url: https://evil.example\n",
        encoding="utf-8",
    )
    ok, detail = _update_plugin_settings(
        state_dir=tmp_path,
        timeout_ms=12345,
        on_scan_error="allow",
        feedback_mode="off",
    )
    assert ok is True
    assert "Updated plugin settings" in detail
    text = cfg.read_text(encoding="utf-8")
    assert "sentrook" in text
    assert "timeout_ms: 12345" in text
    assert "on_scan_error: allow" in text
    assert "feedback_mode: 'off'" in text or "feedback_mode: off" in text
    assert "scan_base_url" not in text
