"""Unit tests for hosted scan API auth (API key + OIDC hybrid)."""

from __future__ import annotations

import time
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import sentrook.shadow.oidc as oidc
from sentrook.shadow.auth import (
    SCAN_API_KEY_HEADER,
    extract_scan_api_key,
    scan_api_key_enabled,
    scan_auth_health_label,
    verify_scan_api_key,
    verify_scan_auth,
)
from sentrook.shadow.config import ShadowConfig
from sentrook.shadow.oidc import SCOPE_SCAN, caller_id_from_claims

ISSUER = "https://identity.test.example"
AUDIENCE = "sentrook"
KID = "test-key-1"


@pytest.fixture(scope="module")
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJWKClient:
    def __init__(self, public_key):
        self._public_key = public_key

    def get_signing_key_from_jwt(self, token: str) -> _FakeSigningKey:
        return _FakeSigningKey(self._public_key)

    def get_signing_keys(self, *args, **kwargs):
        return [self.get_signing_key_from_jwt("")]


@pytest.fixture(autouse=True)
def patch_jwks(monkeypatch: pytest.MonkeyPatch, rsa_keys) -> None:
    _, public_key = rsa_keys
    monkeypatch.setattr(oidc, "_jwks_client", lambda config: _FakeJWKClient(public_key))


def _mint_token(
    private_key,
    *,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    scope: str = SCOPE_SCAN,
    subject: str = "user-123",
    fidu_user_id: str | None = None,
    expires_in: int = 1800,
    kid: str = KID,
) -> str:
    now = int(time.time())
    claims: dict = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "scope": scope,
        "iat": now,
        "exp": now + expires_in,
    }
    if fidu_user_id is not None:
        claims["fidu_user_id"] = fidu_user_id
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def _oidc_config(**kwargs) -> ShadowConfig:
    base = ShadowConfig(
        scan_auth_mode="auto",
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        scan_api_key=None,
    )
    return replace(base, **kwargs) if kwargs else base


def test_scan_api_key_disabled_when_unset() -> None:
    config = ShadowConfig(scan_api_key=None, scan_auth_mode="apikey", oidc_issuer="")
    assert not scan_api_key_enabled(config)
    assert verify_scan_api_key(config, {})


def test_extract_bearer_and_header() -> None:
    assert extract_scan_api_key({"Authorization": "Bearer secret"}) == "secret"
    assert extract_scan_api_key({SCAN_API_KEY_HEADER: "secret"}) == "secret"


def test_verify_rejects_missing_or_wrong_key() -> None:
    config = ShadowConfig(scan_api_key="expected", scan_auth_mode="apikey", oidc_issuer="")
    assert not verify_scan_api_key(config, {})
    assert not verify_scan_api_key(config, {"Authorization": "Bearer wrong"})


def test_verify_accepts_matching_bearer() -> None:
    config = ShadowConfig(scan_api_key="expected", scan_auth_mode="apikey", oidc_issuer="")
    assert verify_scan_api_key(config, {"Authorization": "Bearer expected"})


def test_oidc_bearer_accepted_with_scan_scope(rsa_keys) -> None:
    private_key, _ = rsa_keys
    config = _oidc_config()
    token = _mint_token(private_key)
    result = verify_scan_auth(config, {"Authorization": f"Bearer {token}"})
    assert result.ok
    assert result.method == "oidc"
    assert result.caller_id == "user-123"


def test_oidc_prefers_fidu_user_id_claim(rsa_keys) -> None:
    private_key, _ = rsa_keys
    config = _oidc_config()
    token = _mint_token(private_key, subject="client-abc", fidu_user_id="user-999")
    result = verify_scan_auth(config, {"Authorization": f"Bearer {token}"})
    assert result.ok
    assert result.caller_id == "user-999"


def test_oidc_rejects_missing_scope(rsa_keys) -> None:
    private_key, _ = rsa_keys
    config = _oidc_config()
    token = _mint_token(private_key, scope="openid profile")
    result = verify_scan_auth(config, {"Authorization": f"Bearer {token}"})
    assert not result.ok
    assert result.error == "insufficient_scope"


def test_oidc_rejects_wrong_audience(rsa_keys) -> None:
    private_key, _ = rsa_keys
    config = _oidc_config()
    token = _mint_token(private_key, audience="rookery")
    result = verify_scan_auth(config, {"Authorization": f"Bearer {token}"})
    assert not result.ok
    assert result.error == "unauthorized"


def test_hybrid_accepts_api_key_when_jwt_absent(rsa_keys) -> None:
    config = _oidc_config(scan_api_key="scan-secret")
    result = verify_scan_auth(config, {"Authorization": "Bearer scan-secret"})
    assert result.ok
    assert result.method == "apikey"


def test_oidc_mode_rejects_api_key(rsa_keys) -> None:
    config = _oidc_config(scan_auth_mode="oidc", scan_api_key="scan-secret")
    result = verify_scan_auth(config, {"Authorization": "Bearer scan-secret"})
    assert not result.ok


def test_caller_id_from_claims_priority() -> None:
    assert caller_id_from_claims({"sub": "a", "fidu_user_id": "b"}) == "b"
    assert caller_id_from_claims({"sub": "a", "user_id": "c"}) == "c"
    assert caller_id_from_claims({"sub": "a"}) == "a"


def test_scan_auth_health_label() -> None:
    assert (
        scan_auth_health_label(ShadowConfig(scan_api_key=None, oidc_issuer="", scan_auth_mode="auto"))
        == "off"
    )
    assert "optional_oidc" in scan_auth_health_label(_oidc_config(scan_api_key=None))
    label = scan_auth_health_label(_oidc_config(scan_api_key="x", scan_auth_mode="auto"))
    assert label.startswith("auto:")
    assert "oidc" in label
    assert "apikey" in label


def test_auto_without_api_key_allows_anonymous() -> None:
    config = _oidc_config(scan_api_key=None)
    result = verify_scan_auth(config, {})
    assert result.ok
    assert result.method is None
