"""FIDU ID OIDC bearer-token verification for hosted Sentrook ``/scan``.

Validates RS256 access tokens issued by the FIDU identity-service against its
published JWKS. Additive to the static scan API key — see ``sentrook.shadow.auth``.

Audience and scope are scan-specific (``sentrook`` / ``sentrook.scan``), separate
from Rookery library scopes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient

if TYPE_CHECKING:
    from sentrook.shadow.config import ShadowConfig

SCOPE_SCAN = "sentrook.scan"
DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org"
DEFAULT_OIDC_AUDIENCE = "sentrook"

_jwks_clients: dict[str, PyJWKClient] = {}


class OIDCError(Exception):
    """Raised when an OIDC bearer token is missing, malformed, or invalid."""


class InsufficientScopeError(Exception):
    """Raised when a validated OIDC token lacks the scope a route requires."""

    def __init__(self, required_scope: str) -> None:
        self.required_scope = required_scope
        super().__init__(required_scope)


def normalize_oidc_url(url: str) -> str:
    """Return an absolute http(s) base URL."""
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
    """Cheap shape check to distinguish a JWT from an opaque static API key."""
    return token.count(".") == 2


def oidc_enabled(config: ShadowConfig) -> bool:
    """Backward-compatible alias: JWTs can be verified with the configured issuer."""
    if config.scan_auth_mode == "apikey":
        return False
    return bool(normalize_oidc_url(config.oidc_issuer))


def token_scopes(claims: dict[str, Any]) -> set[str]:
    raw = claims.get("scope") or ""
    return set(str(raw).split())


def caller_id_from_claims(claims: dict[str, Any]) -> str | None:
    """Prefer explicit FIDU user binding; fall back to JWT ``sub``."""
    for key in ("fidu_user_id", "user_id", "sub"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value is not None and not isinstance(value, (dict, list)):
            text = str(value).strip()
            if text:
                return text
    return None


def _jwks_url(config: ShadowConfig) -> str:
    override = normalize_oidc_url(config.oidc_jwks_url)
    if override:
        return f"{override}/.well-known/jwks.json" if not override.endswith(".json") else override
    issuer = normalize_oidc_url(config.oidc_issuer)
    if not issuer:
        raise OIDCError("OIDC issuer is not configured")
    return f"{issuer}/.well-known/jwks.json"


def _jwks_client(config: ShadowConfig) -> PyJWKClient:
    url = _jwks_url(config)
    client = _jwks_clients.get(url)
    if client is None:
        client = PyJWKClient(
            url,
            cache_keys=True,
            lifespan=config.oidc_jwks_cache_seconds,
        )
        _jwks_clients[url] = client
    return client


def decode_oidc_token(config: ShadowConfig, token: str) -> dict[str, Any]:
    """Verify an RS256 bearer token's signature, issuer, audience, and expiry."""
    issuer = normalize_oidc_url(config.oidc_issuer)
    if not issuer:
        raise OIDCError("OIDC issuer is not configured")

    try:
        client = _jwks_client(config)
        signing_key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=config.oidc_audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OIDCError(str(exc)) from exc
    except Exception as exc:  # JWKS fetch/network failures, etc.
        jwks_hint = _jwks_url(config)
        raise OIDCError(f"failed to verify token (jwks={jwks_hint}): {exc}") from exc

    return claims


def require_scan_scope(claims: dict[str, Any]) -> None:
    if SCOPE_SCAN not in token_scopes(claims):
        raise InsufficientScopeError(SCOPE_SCAN)


def validate_oidc_configuration(config: ShadowConfig) -> None:
    """Fail fast when OIDC is enabled but the issuer JWKS cannot be reached."""
    if not oidc_enabled(config):
        return
    issuer = normalize_oidc_url(config.oidc_issuer)
    if not issuer:
        raise OIDCError("OIDC issuer is not configured")
    keys = _jwks_client(config).get_signing_keys()
    if not keys:
        raise OIDCError(f"JWKS at {_jwks_url(config)} contains no keys")


__all__ = [
    "DEFAULT_OIDC_AUDIENCE",
    "DEFAULT_OIDC_ISSUER",
    "InsufficientScopeError",
    "OIDCError",
    "SCOPE_SCAN",
    "caller_id_from_claims",
    "decode_oidc_token",
    "looks_like_jwt",
    "normalize_oidc_url",
    "oidc_enabled",
    "require_scan_scope",
    "token_scopes",
    "validate_oidc_configuration",
]
