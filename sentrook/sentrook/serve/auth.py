"""Scan HTTP API authentication: FIDU ID OIDC bearer tokens, or explicitly open.

- `oidc`: every scan route needs a valid FIDU ID bearer token (RS256, configured issuer and audience)
  carrying the `sentrook.scan` scope. A missing or invalid token is 401, a valid token without the
  scope is 403.
- `open`: no authentication, for a local sidecar or a test-mode server. Refused in production by
  `ServeConfig`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .config import AUTH_OPEN, ServeConfig
from .oidc import (
    SCOPE_SCAN,
    InsufficientScopeError,
    OIDCError,
    caller_id_from_claims,
    decode_oidc_token,
    looks_like_jwt,
    require_scan_scope,
)


@dataclass(frozen=True)
class ScanAuthResult:
    ok: bool
    method: str | None = None  # oidc | None (open mode)
    caller_id: str | None = None
    error: str | None = None  # unauthorized | insufficient_scope


def extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    authorization = headers.get("Authorization") or headers.get("authorization") or ""
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        return token or None
    return None


def verify_scan_auth(config: ServeConfig, headers: Mapping[str, str]) -> ScanAuthResult:
    if config.scan_auth_mode == AUTH_OPEN:
        return ScanAuthResult(ok=True)
    bearer = extract_bearer_token(headers)
    if bearer is None or not looks_like_jwt(bearer):
        return ScanAuthResult(ok=False, error="unauthorized")
    try:
        claims = decode_oidc_token(config, bearer)
        require_scan_scope(claims)
    except InsufficientScopeError:
        return ScanAuthResult(ok=False, error="insufficient_scope")
    except OIDCError:
        return ScanAuthResult(ok=False, error="unauthorized")
    return ScanAuthResult(ok=True, method="oidc", caller_id=caller_id_from_claims(claims))


def www_authenticate(result: ScanAuthResult) -> str:
    """The `WWW-Authenticate` challenge for a refused request (RFC 6750)."""
    if result.error == "insufficient_scope":
        return f'Bearer realm="sentrook", error="insufficient_scope", scope="{SCOPE_SCAN}"'
    return 'Bearer realm="sentrook"'
