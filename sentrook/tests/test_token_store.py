from __future__ import annotations

import time
from pathlib import Path

import pytest

from sentrook.library import token_store as ts
from sentrook.library.tokens import TokenSet


def test_file_token_store_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    auth_dir = tmp_path / "auth"
    monkeypatch.setenv("SENTROOK_AUTH_DIR", str(auth_dir))
    monkeypatch.setenv("SENTROOK_TOKEN_STORE", "file")
    assert ts.load_cached_tokens() is None

    tokens = TokenSet(
        access_token="abc",
        refresh_token="def",
        expires_at=time.time() + 1800,
        scope="sentrook.library.read",
    )
    ts.save_tokens(tokens)

    path = ts.token_cache_path()
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o600
    assert ts.load_cached_tokens() == tokens

    ts.clear_cached_tokens()
    assert not path.exists()
    assert ts.load_cached_tokens() is None


def test_use_keyring_store_false_when_auth_dir_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_AUTH_DIR", "/tmp/sentrook-auth-test")
    assert ts.use_keyring_store() is False


def test_use_keyring_store_honours_file_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTROOK_AUTH_DIR", raising=False)
    monkeypatch.setenv("SENTROOK_TOKEN_STORE", "file")
    assert ts.use_keyring_store() is False
