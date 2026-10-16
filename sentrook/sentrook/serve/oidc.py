"""FIDU ID OIDC bearer-token verification for `/scan` (carried from 1.x).

Validates RS256 access tokens issued by the FIDU identity service against its published JWKS.
Additive to the static scan API key; see `serve.auth`. Audience and scope are scan-specific
(`sentrook` / `sentrook.scan`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient

if TYPE_CHECKING:
    from .config import ServeConfig

SCOPE_SCAN = "sentrook.scan"

_jwks_clients: dict[str, PyJWKClient] = {}


class OIDCError(Exception):
    """A bearer token is missing, malformed or invalid."""


class InsufficientScopeError(Exception):
    def __init__(self, required_scope: str) -> None:
        self.required_scope = required_scope
        super().__init__(required_scope)


def normalize_oidc_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme:
        stripped = url.lstrip("/")
        if not stripped or stripped.startswith("."):
            return ""
        url = f"https://{stripped}"
    parsed = urlparse(url)
    if not parsed.netloc or parsed.netloc.startswith("."):
        return ""
    return url.rstrip("/")


def looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2


def oidc_enabled(config: ServeConfig) -> bool:
    if config.scan_auth_mode == "apikey":
        return False
    return bool(normalize_oidc_url(config.oidc_issuer))


def token_scopes(claims: dict[str, Any]) -> set[str]:
    return set(str(claims.get("scope") or "").split())


def caller_id_from_claims(claims: dict[str, Any]) -> str | None:
    for key in ("fidu_user_id", "user_id", "sub"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value is not None and not isinstance(value, dict | list):
            text = str(value).strip()
            if text:
                return text
    return None


def _jwks_url(config: ServeConfig) -> str:
    override = normalize_oidc_url(config.oidc_jwks_url)
    if override:
        return override if override.endswith(".json") else f"{override}/.well-known/jwks.json"
    issuer = normalize_oidc_url(config.oidc_issuer)
    if not issuer:
        raise OIDCError("OIDC issuer is not configured")
    return f"{issuer}/.well-known/jwks.json"


def _jwks_client(config: ServeConfig) -> PyJWKClient:
    url = _jwks_url(config)
    client = _jwks_clients.get(url)
    if client is None:
        client = PyJWKClient(url, cache_keys=True, lifespan=config.oidc_jwks_cache_seconds)
        _jwks_clients[url] = client
    return client


def decode_oidc_token(config: ServeConfig, token: str) -> dict[str, Any]:
    issuer = normalize_oidc_url(config.oidc_issuer)
    if not issuer:
        raise OIDCError("OIDC issuer is not configured")
    try:
        signing_key = _jwks_client(config).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=config.oidc_audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OIDCError(str(exc)) from exc
    except Exception as exc:  # JWKS fetch failures and the like
        raise OIDCError(f"failed to verify token (jwks={_jwks_url(config)}): {exc}") from exc


def require_scan_scope(claims: dict[str, Any]) -> None:
    if SCOPE_SCAN not in token_scopes(claims):
        raise InsufficientScopeError(SCOPE_SCAN)
