"""Verify coverage checks."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ..verify import (
    EXPECTED_HOOKS,
    check_expected_hooks,
    check_plugin_enabled,
    check_plugin_installed,
    format_verify_report,
    run_verify,
)

FULL_PLUGIN_YAML = """\
name: sentrook
provides_hooks:
  - pre_llm_call
  - pre_tool_call
  - post_tool_call
  - post_approval_response
  - on_session_finalize
  - on_session_reset
  - subagent_start
"""


def _install_plugin(state: Path, manifest: str = FULL_PLUGIN_YAML) -> None:
    root = state / "plugins" / "sentrook"
    root.mkdir(parents=True)
    (root / "plugin.yaml").write_text(manifest, encoding="utf-8")


def test_check_plugin_installed_missing(tmp_path: Path) -> None:
    result = check_plugin_installed(tmp_path)
    assert result.ok is False
    assert "missing" in result.detail


def test_check_plugin_installed_ok(tmp_path: Path) -> None:
    _install_plugin(tmp_path)
    result = check_plugin_installed(tmp_path)
    assert result.ok is True


def test_check_expected_hooks_ok(tmp_path: Path) -> None:
    _install_plugin(tmp_path)
    result = check_expected_hooks(tmp_path)
    assert result.ok is True
    assert str(len(EXPECTED_HOOKS)) in result.detail


def test_check_expected_hooks_missing_one(tmp_path: Path) -> None:
    # Drop subagent_start
    lines = [ln for ln in FULL_PLUGIN_YAML.splitlines() if "subagent_start" not in ln]
    _install_plugin(tmp_path, "\n".join(lines) + "\n")
    result = check_expected_hooks(tmp_path)
    assert result.ok is False
    assert "subagent_start" in result.detail


def test_check_plugin_enabled_list(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - sentrook\n",
        encoding="utf-8",
    )
    result = check_plugin_enabled(tmp_path)
    assert result.ok is True
    assert "plugins.enabled" in result.detail


def test_check_plugin_enabled_disabled_list(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  disabled:\n    - sentrook\n  enabled: []\n",
        encoding="utf-8",
    )
    result = check_plugin_enabled(tmp_path)
    assert result.ok is False
    assert "plugins.disabled" in result.detail


def test_check_plugin_enabled_entries(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  entries:\n    sentrook:\n      enabled: true\n",
        encoding="utf-8",
    )
    result = check_plugin_enabled(tmp_path)
    assert result.ok is True


def test_check_plugin_enabled_entries_false(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  entries:\n    sentrook:\n      enabled: false\n",
        encoding="utf-8",
    )
    result = check_plugin_enabled(tmp_path)
    assert result.ok is False


def test_check_plugin_enabled_text_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - sentrook\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("plugin.verify._load_yaml", lambda _path: {})
    result = check_plugin_enabled(tmp_path)
    assert result.ok is True
    assert "text scan" in result.detail


def test_run_verify_local_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_plugin(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - sentrook\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    with patch(
        "plugin.verify.resolve_scan_auth_config",
        return_value=__import__("plugin.auth", fromlist=["ScanAuthConfig"]).ScanAuthConfig(
            api_key=None,
            oidc=__import__("plugin.auth", fromlist=["ScanOidcCredentials"]).ScanOidcCredentials(
                client_id="cid",
                client_secret="csec",
                issuer="https://identity.example",
                audience="sentrook",
                scope="sentrook.scan",
            ),
        ),
    ), patch("plugin.verify.has_scan_credentials", return_value=True):
        result = run_verify(
            settings={},
            env={},
            state_dir=tmp_path,
            skip_health=True,
            skip_mint=True,
        )
    assert result.ok is True
    assert result.covering is True
    names = {c.name for c in result.checks}
    assert "plugin install" in names
    assert "hooks manifest" in names
    assert "plugin enabled" in names
    assert "scan credentials" in names
    report = format_verify_report(result)
    assert "OK — ready to cover" in report


def test_run_verify_https_missing_creds(tmp_path: Path) -> None:
    _install_plugin(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - sentrook\n",
        encoding="utf-8",
    )
    with patch("plugin.verify.env_with_hermes_dotenv", return_value={}):
        result = run_verify(
            settings={},
            env={},
            state_dir=tmp_path,
            skip_health=True,
            skip_mint=True,
        )
    assert result.ok is False
    creds = next(c for c in result.checks if c.name == "scan credentials")
    assert creds.ok is False
    assert "not covering" in format_verify_report(result)


def test_run_verify_not_installed(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - sentrook\n",
        encoding="utf-8",
    )
    with patch("plugin.verify.has_scan_credentials", return_value=True):
        result = run_verify(
            settings={},
            env={},
            state_dir=tmp_path,
            skip_health=True,
            skip_mint=True,
        )
    assert result.ok is False
    assert result.covering is False
