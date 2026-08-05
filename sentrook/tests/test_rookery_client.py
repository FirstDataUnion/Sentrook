from __future__ import annotations

import pytest

from sentrook.library import rookery_client


def test_explicit_api_key_wins_and_skips_oidc_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_if_called() -> str | None:
        raise AssertionError("get_access_token should not be called when api_key is given")

    monkeypatch.setattr(rookery_client, "get_access_token", fail_if_called)

    headers = rookery_client.rookery_auth_headers("static-key")
    assert headers == {
        "Authorization": "Bearer static-key",
        rookery_client.ROOKERY_API_KEY_HEADER: "static-key",
    }


def test_falls_back_to_oidc_token_when_no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rookery_client, "get_access_token", lambda: "oidc-access-token")

    headers = rookery_client.rookery_auth_headers(None)
    assert headers == {"Authorization": "Bearer oidc-access-token"}
    assert rookery_client.ROOKERY_API_KEY_HEADER not in headers


def test_returns_no_headers_when_nothing_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rookery_client, "get_access_token", lambda: None)

    assert rookery_client.rookery_auth_headers(None) == {}
    assert rookery_client.rookery_auth_headers("") == {}
    assert rookery_client.rookery_auth_headers("   ") == {}
