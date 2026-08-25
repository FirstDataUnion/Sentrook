"""Config / env resolution tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from ..config import resolve_plugin_config
from ..scan_endpoint import DEFAULT_SCAN_BASE_URL, resolve_scan_base_url


def test_resolve_scan_base_url_prefers_settings() -> None:
    assert (
        resolve_scan_base_url(
            {"scan_base_url": "https://settings.example/"},
            {"SENTROOK_SCAN_BASE_URL": "https://env.example"},
        )
        == "https://settings.example"
    )


def test_resolve_scan_base_url_uses_env_map_not_only_os() -> None:
    """Regression: ~/.hermes/.env values must win even when not in os.environ."""
    assert (
        resolve_scan_base_url(
            {},
            {"SENTROOK_SCAN_BASE_URL": "https://dev.sentrook.example"},
        )
        == "https://dev.sentrook.example"
    )


def test_resolve_scan_base_url_default() -> None:
    assert resolve_scan_base_url({}, {}) == DEFAULT_SCAN_BASE_URL


def test_resolve_plugin_config_reads_dotenv_base_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hermes_home = tmp_path
    state = hermes_home / ".hermes"
    state.mkdir()
    (state / ".env").write_text(
        "SENTROOK_SCAN_BASE_URL=https://dev.sentrook.firstdataunion.org\n"
        "SENTROOK_SCAN_CLIENT_ID=dev-client\n"
        "SENTROOK_SCAN_CLIENT_SECRET=dev-secret\n"
        "SENTROOK_OIDC_ISSUER=https://dev.identity.firstdataunion.org\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    for key in (
        "SENTROOK_SCAN_BASE_URL",
        "SENTROOK_SCAN_CLIENT_ID",
        "SENTROOK_SCAN_CLIENT_SECRET",
        "SENTROOK_OIDC_ISSUER",
        "HERMES_STATE_DIR",
    ):
        monkeypatch.delenv(key, raising=False)

    cfg = resolve_plugin_config({})
    assert cfg.url == "https://dev.sentrook.firstdataunion.org"
    assert cfg.auth.oidc is not None
    assert cfg.auth.oidc.issuer == "https://dev.identity.firstdataunion.org"
    assert cfg.auth.oidc.client_id == "dev-client"
