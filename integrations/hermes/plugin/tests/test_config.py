"""Config / env resolution tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from ..config import resolve_plugin_config
from ..scan_endpoint import SCAN_BASE_URL, resolve_scan_base_url


def test_resolve_scan_base_url_is_pinned() -> None:
    assert (
        resolve_scan_base_url(
            {"scan_base_url": "https://settings.example/"},
            {"SENTROOK_SCAN_BASE_URL": "https://env.example"},
        )
        == SCAN_BASE_URL
    )


def test_resolve_scan_base_url_ignores_env_map() -> None:
    assert (
        resolve_scan_base_url(
            {},
            {"SENTROOK_SCAN_BASE_URL": "https://dev.sentrook.example"},
        )
        == SCAN_BASE_URL
    )


def test_resolve_scan_base_url_default() -> None:
    assert resolve_scan_base_url({}, {}) == SCAN_BASE_URL


def test_resolve_plugin_config_uses_pinned_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dotenv SENTROOK_SCAN_BASE_URL must not retarget the scan origin."""
    state = tmp_path / ".hermes"
    state.mkdir()
    (state / ".env").write_text(
        "SENTROOK_SCAN_BASE_URL=https://dev.sentrook.firstdataunion.org\n"
        "SENTROOK_SCAN_CLIENT_ID=cid\n"
        "SENTROOK_SCAN_CLIENT_SECRET=csec\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("HERMES_STATE_DIR", raising=False)
    monkeypatch.delenv("SENTROOK_SCAN_BASE_URL", raising=False)
    config = resolve_plugin_config({})
    assert config.url == SCAN_BASE_URL
