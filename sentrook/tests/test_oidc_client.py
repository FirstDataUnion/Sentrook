from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from sentrook.library import oidc_client as oc

ISSUER = "https://identity.test.example"


@pytest.fixture(autouse=True)
def isolated_auth_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Never touch a developer's real ~/.sentrook/auth cache during tests."""
    auth_dir = tmp_path / "auth"
    monkeypatch.setenv("SENTROOK_AUTH_DIR", str(auth_dir))
    for var in (
        "SENTROOK_ROOKERY_CI_CLIENT_SECRET",
        "SENTROOK_ROOKERY_CI_CLIENT_ID",
        "SENTROOK_ROOKERY_CLIENT_ID",
        "SENTROOK_ROOKERY_SCOPE",
        "SENTROOK_IDENTITY_ISSUER",
    ):
        monkeypatch.delenv(var, raising=False)
    return auth_dir


def _fake_response(payload: dict) -> io.BytesIO:
    body = io.BytesIO(json.dumps(payload).encode("utf-8"))

    class _Ctx:
        def __enter__(self):
            return body

        def __exit__(self, *exc):
            return False

    return _Ctx()


def _http_error(payload: dict, code: int = 400) -> urllib.error.HTTPError:
    body = io.BytesIO(json.dumps(payload).encode("utf-8"))
    return urllib.error.HTTPError(
        url=f"{ISSUER}/oauth/token", code=code, msg="error", hdrs=None, fp=body
    )


def test_token_set_expiry() -> None:
    fresh = oc.TokenSet(access_token="a", refresh_token=None, expires_at=time.time() + 300, scope="")
    assert not fresh.is_expired()

    stale = oc.TokenSet(access_token="a", refresh_token=None, expires_at=time.time() - 1, scope="")
    assert stale.is_expired()

    about_to_expire = oc.TokenSet(access_token="a", refresh_token=None, expires_at=time.time() + 5, scope="")
    assert about_to_expire.is_expired(skew_seconds=60)


def test_identity_issuer_defaults_when_unset_or_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTROOK_IDENTITY_ISSUER", raising=False)
    assert oc.identity_issuer() == oc.DEFAULT_IDENTITY_ISSUER

    monkeypatch.setenv("SENTROOK_IDENTITY_ISSUER", "")
    assert oc.identity_issuer() == oc.DEFAULT_IDENTITY_ISSUER

    monkeypatch.setenv("SENTROOK_IDENTITY_ISSUER", "https://identity.example.test")
    assert oc.identity_issuer() == "https://identity.example.test"


def test_save_load_clear_round_trip(isolated_auth_dir: Path) -> None:
    assert oc.load_cached_tokens() is None

    tokens = oc.TokenSet(access_token="abc", refresh_token="def", expires_at=time.time() + 1800, scope="sentrook.library.read")
    oc.save_tokens(tokens)

    path = oc.token_cache_path()
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o600

    loaded = oc.load_cached_tokens()
    assert loaded == tokens

    oc.clear_cached_tokens()
    assert not path.exists()
    assert oc.load_cached_tokens() is None
    oc.clear_cached_tokens()  # no error when already absent


def test_start_device_login(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_urlopen(request, timeout=30):
        captured["url"] = request.full_url
        captured["body"] = request.data
        return _fake_response(
            {
                "device_code": "devcode-1",
                "user_code": "ABCD-1234",
                "verification_uri": f"{ISSUER}/oauth/device",
                "verification_uri_complete": f"{ISSUER}/oauth/device?user_code=ABCD-1234",
                "expires_in": 600,
                "interval": 5,
            }
        )

    monkeypatch.setattr("sentrook.library.http_client.urlopen", fake_urlopen)

    authorization = oc.start_device_login(issuer=ISSUER, client_id="sentrook-cli", scope="openid")
    assert authorization.device_code == "devcode-1"
    assert authorization.user_code == "ABCD-1234"
    assert authorization.interval == 5
    assert captured["url"] == f"{ISSUER}/oauth/device/code"
    assert b"client_id=sentrook-cli" in captured["body"]


def test_poll_device_token_waits_through_pending_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [
        oc.OIDCClientError("authorization_pending: pending"),
        {
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "expires_in": 1800,
            "scope": "sentrook.library.read",
        },
    ]
    calls: list[float] = []
    wait_calls: list[int] = []

    def fake_oauth_post(url, form):
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(oc, "_oauth_post", fake_oauth_post)

    tokens = oc.poll_device_token(
        issuer=ISSUER,
        client_id="sentrook-cli",
        device_code="devcode-1",
        interval=1,
        expires_in=60,
        sleep=calls.append,
        on_wait=wait_calls.append,
    )
    assert tokens.access_token == "access-1"
    assert tokens.refresh_token == "refresh-1"
    assert calls == [1, 1]
    assert wait_calls[0] >= 59
    assert len(wait_calls) == 2


def test_fetch_oidc_discovery(real_oidc_discovery, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request, timeout=30):
        assert request.full_url == f"{ISSUER}/.well-known/openid-configuration"
        return _fake_response(
            {
                "issuer": ISSUER,
                "token_endpoint": f"{ISSUER}/oauth/token",
                "device_authorization_endpoint": f"{ISSUER}/oauth/device/code",
            }
        )

    monkeypatch.setattr("sentrook.library.http_client.urlopen", fake_urlopen)

    discovery = oc.fetch_oidc_discovery(ISSUER)
    assert discovery.issuer == ISSUER
    assert discovery.token_endpoint == f"{ISSUER}/oauth/token"
    assert discovery.device_authorization_endpoint == f"{ISSUER}/oauth/device/code"


def test_normalize_issuer_adds_https_scheme() -> None:
    assert oc.normalize_issuer("identity.test.example") == "https://identity.test.example"
    assert oc.normalize_issuer("https://identity.test.example/") == "https://identity.test.example"


def test_describe_scopes_maps_sentrook_capabilities() -> None:
    labels = oc.describe_scopes("sentrook.library.read sentrook.submissions.write")
    assert labels == [
        "pull Rookery library updates",
        "submit corpus feedback",
    ]


def test_poll_device_token_slow_down_backs_off(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        oc.OIDCClientError("slow_down: too fast"),
        {"access_token": "access-1", "refresh_token": None, "expires_in": 1800, "scope": ""},
    ]

    def fake_oauth_post(url, form):
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(oc, "_oauth_post", fake_oauth_post)
    intervals: list[float] = []

    tokens = oc.poll_device_token(
        issuer=ISSUER,
        client_id="sentrook-cli",
        device_code="devcode-1",
        interval=1,
        expires_in=60,
        sleep=intervals.append,
    )
    assert tokens.access_token == "access-1"
    assert intervals == [1, 6]


def test_poll_device_token_raises_on_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        oc,
        "_oauth_post",
        lambda url, form: (_ for _ in ()).throw(
            oc.OIDCClientError("access_denied: user rejected")
        ),
    )
    with pytest.raises(oc.OIDCClientError, match="access_denied"):
        oc.poll_device_token(
            issuer=ISSUER,
            client_id="sentrook-cli",
            device_code="devcode-1",
            interval=1,
            expires_in=60,
            sleep=lambda _seconds: None,
        )


def test_refresh_tokens_preserves_refresh_token_when_not_rotated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_oauth_post(url, form):
        assert form["grant_type"] == "refresh_token"
        assert form["refresh_token"] == "old-refresh"
        return {"access_token": "new-access", "expires_in": 1800, "scope": "sentrook.library.read"}

    monkeypatch.setattr(oc, "_oauth_post", fake_oauth_post)

    tokens = oc.refresh_tokens(issuer=ISSUER, client_id="sentrook-cli", refresh_token="old-refresh")
    assert tokens.access_token == "new-access"
    assert tokens.refresh_token == "old-refresh"


def test_client_credentials_token(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_oauth_post(url, form):
        assert form["grant_type"] == "client_credentials"
        assert form["client_id"] == "sentrook-ci"
        assert form["client_secret"] == "s3cr3t"
        return {"access_token": "ci-access", "expires_in": 1800, "scope": "sentrook.library.read"}

    monkeypatch.setattr(oc, "_oauth_post", fake_oauth_post)

    tokens = oc.client_credentials_token(
        issuer=ISSUER, client_id="sentrook-ci", client_secret="s3cr3t"
    )
    assert tokens.access_token == "ci-access"
    assert tokens.refresh_token is None


def test_get_access_token_returns_none_when_nothing_cached() -> None:
    assert oc.get_access_token() is None


def test_get_access_token_uses_valid_cached_token(isolated_auth_dir: Path) -> None:
    oc.save_tokens(
        oc.TokenSet(access_token="cached-valid", refresh_token=None, expires_at=time.time() + 1800, scope="")
    )
    assert oc.get_access_token() == "cached-valid"


def test_get_access_token_refreshes_expired_cached_token(
    isolated_auth_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oc.save_tokens(
        oc.TokenSet(
            access_token="expired-access",
            refresh_token="refresh-me",
            expires_at=time.time() - 10,
            scope="sentrook.library.read",
        )
    )

    def fake_refresh(*, issuer, client_id, refresh_token):
        assert refresh_token == "refresh-me"
        return oc.TokenSet(
            access_token="refreshed-access",
            refresh_token="refresh-me",
            expires_at=time.time() + 1800,
            scope="sentrook.library.read",
        )

    monkeypatch.setattr(oc, "refresh_tokens", fake_refresh)

    assert oc.get_access_token() == "refreshed-access"
    # The refreshed token set should now be persisted for next time.
    assert oc.load_cached_tokens().access_token == "refreshed-access"


def test_get_access_token_returns_none_when_refresh_fails(
    isolated_auth_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oc.save_tokens(
        oc.TokenSet(
            access_token="expired-access",
            refresh_token="refresh-me",
            expires_at=time.time() - 10,
            scope="",
        )
    )
    monkeypatch.setattr(
        oc,
        "refresh_tokens",
        lambda **kwargs: (_ for _ in ()).throw(oc.OIDCClientError("invalid_grant: revoked")),
    )
    assert oc.get_access_token() is None


def test_get_access_token_expired_without_refresh_token_returns_none(
    isolated_auth_dir: Path,
) -> None:
    oc.save_tokens(
        oc.TokenSet(access_token="expired", refresh_token=None, expires_at=time.time() - 10, scope="")
    )
    assert oc.get_access_token() is None


def test_get_access_token_prefers_ci_client_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTROOK_ROOKERY_CI_CLIENT_SECRET", "s3cr3t")

    monkeypatch.setattr(
        oc,
        "client_credentials_token",
        lambda **kwargs: oc.TokenSet(
            access_token="ci-token", refresh_token=None, expires_at=time.time() + 1800, scope=""
        ),
    )
    assert oc.get_access_token() == "ci-token"


def test_get_access_token_ci_mode_swallows_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTROOK_ROOKERY_CI_CLIENT_SECRET", "s3cr3t")
    monkeypatch.setattr(
        oc,
        "client_credentials_token",
        lambda **kwargs: (_ for _ in ()).throw(oc.OIDCClientError("invalid_client: nope")),
    )
    assert oc.get_access_token() is None
