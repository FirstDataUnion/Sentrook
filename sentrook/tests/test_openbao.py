from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from sentrook.openbao import (
    OpenBaoError,
    _split_kv_v2_path,
    fetch_sentrook_secrets,
    openbao_enabled,
    reset_openbao_cache,
    runtime_ci_client_secret,
)
from sentrook.serve.config import ServeConfig


@pytest.fixture(autouse=True)
def _clear_openbao_cache() -> None:
    reset_openbao_cache()
    yield
    reset_openbao_cache()


def test_openbao_enabled_truthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_OPENBAO_ENABLED", "1")
    assert openbao_enabled() is True
    monkeypatch.setenv("SENTROOK_OPENBAO_ENABLED", "true # comment")
    assert openbao_enabled() is True
    monkeypatch.delenv("SENTROOK_OPENBAO_ENABLED", raising=False)
    monkeypatch.setenv("SENTROOK_OPENBAO", "yes")
    assert openbao_enabled() is True


def test_openbao_enabled_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTROOK_OPENBAO_ENABLED", raising=False)
    monkeypatch.delenv("SENTROOK_OPENBAO", raising=False)
    assert openbao_enabled() is False
    monkeypatch.setenv("SENTROOK_OPENBAO_ENABLED", "0")
    assert openbao_enabled() is False


def test_split_kv_v2_path() -> None:
    assert _split_kv_v2_path("sentrook/data/prod") == ("sentrook", "prod")
    assert _split_kv_v2_path("sentrook/prod") == ("sentrook", "prod")
    with pytest.raises(OpenBaoError):
        _split_kv_v2_path("sentrook")


def test_fetch_from_token_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    token_file = tmp_path / "sentrook-prod.token"
    token_file.write_text("s.token-value\n", encoding="utf-8")
    monkeypatch.setenv("OPENBAO_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("OPENBAO_TOKEN", raising=False)

    client = MagicMock()
    client.is_authenticated.return_value = True
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "rookery_ci_client_secret": "ci-secret",
                "rookery_api_key": "rook-key",
                "scan_api_key": "scan-key",
            }
        }
    }

    secrets = fetch_sentrook_secrets(client=client)
    assert secrets == {
        "rookery_ci_client_secret": "ci-secret",
        "rookery_api_key": "rook-key",
        "scan_api_key": "scan-key",
    }
    assert runtime_ci_client_secret() == "ci-secret"
    client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="prod",
        mount_point="sentrook",
    )


def test_fetch_optional_scan_api_key_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENBAO_TOKEN", "s.test")
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "rookery_ci_client_secret": "ci-secret",
                "rookery_api_key": "rook-key",
            }
        }
    }
    secrets = fetch_sentrook_secrets(client=client)
    assert "scan_api_key" not in secrets
    assert secrets["rookery_api_key"] == "rook-key"


def test_fetch_missing_sink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENBAO_TOKEN", raising=False)
    monkeypatch.setenv("OPENBAO_TOKEN_FILE", str(tmp_path / "missing.token"))
    with pytest.raises(OpenBaoError, match="cannot read"):
        fetch_sentrook_secrets()


def test_fetch_missing_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENBAO_TOKEN", "s.test")
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"rookery_api_key": "only"}}
    }
    with pytest.raises(OpenBaoError, match="missing required keys"):
        fetch_sentrook_secrets(client=client)


def test_from_env_with_openbao_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTROOK_OPENBAO_ENABLED", raising=False)
    monkeypatch.delenv("SENTROOK_OPENBAO", raising=False)
    monkeypatch.setenv("SENTROOK_ROOKERY_API_KEY", "from-env")
    monkeypatch.setenv("SENTROOK_ROOKERY_CI_CLIENT_SECRET", "env-ci")
    monkeypatch.setenv("SENTROOK_SCAN_API_KEY", "env-scan")
    cfg = ServeConfig.from_env_with_openbao()
    assert cfg.rookery_api_key == "from-env"
    assert cfg.rookery_ci_client_secret == "env-ci"
    assert cfg.scan_api_key == "env-scan"


def test_from_env_with_openbao_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_OPENBAO_ENABLED", "1")
    monkeypatch.setenv("SENTROOK_ROOKERY_API_KEY", "should-be-overridden")
    monkeypatch.setenv("OPENBAO_TOKEN", "s.test")

    fake = MagicMock()
    fake.is_authenticated.return_value = True
    fake.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "rookery_ci_client_secret": "bao-ci",
                "rookery_api_key": "bao-rook",
                "scan_api_key": "bao-scan",
            }
        }
    }

    def _client(*args: Any, **kwargs: Any) -> MagicMock:
        return fake

    monkeypatch.setattr("hvac.Client", _client)
    cfg = ServeConfig.from_env_with_openbao()
    assert cfg.rookery_ci_client_secret == "bao-ci"
    assert cfg.rookery_api_key == "bao-rook"
    assert cfg.scan_api_key == "bao-scan"
    import os

    assert os.environ.get("SENTROOK_ROOKERY_API_KEY") == "should-be-overridden"


def test_from_env_with_openbao_fail_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_OPENBAO_ENABLED", "1")
    monkeypatch.delenv("OPENBAO_TOKEN", raising=False)
    monkeypatch.delenv("OPENBAO_TOKEN_FILE", raising=False)
    with pytest.raises(OpenBaoError):
        ServeConfig.from_env_with_openbao()
