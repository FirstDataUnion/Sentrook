"""Scan HTTP API authentication (carried from 1.x): OIDC JWT and/or a static API key.

- `auto` (default): open when no API key is configured (local sidecar); a JWT is still accepted when
  presented and an issuer is configured.
- `apikey`: `X-Sentrook-Scan-API-Key` (or a non-JWT bearer) must match `SENTROOK_SCAN_API_KEY`.
- `oidc`: a valid FIDU ID bearer token with the `sentrook.scan` scope is required.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass

from .config import ServeConfig
from .oidc import (
    InsufficientScopeError,
    OIDCError,
    caller_id_from_claims,
    decode_oidc_token,
    looks_like_jwt,
    normalize_oidc_url,
    require_scan_scope,
)

SCAN_API_KEY_HEADER = "X-Sentrook-Scan-API-Key"


@dataclass(frozen=True)
class ScanAuthResult:
    ok: bool
    method: str | None = None  # oidc | apikey | None
    caller_id: str | None = None
    error: str | None = None  # unauthorized | insufficient_scope


def scan_api_key_enabled(config: ServeConfig) -> bool:
    if config.scan_auth_mode == "oidc":
        return False
    return bool(config.scan_api_key)


def oidc_available(config: ServeConfig) -> bool:
    if config.scan_auth_mode == "apikey":
        return False
    return bool(normalize_oidc_url(config.oidc_issuer))


def scan_auth_required(config: ServeConfig) -> bool:
    if config.scan_auth_mode == "oidc":
        return True
    return scan_api_key_enabled(config)


def extract_bearer_token(headers: Mapping[str, str]) -> str | None:
    authorization = headers.get("Authorization") or headers.get("authorization") or ""
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        return token or None
    return None


def _verify_api_key(config: ServeConfig, headers: Mapping[str, str]) -> bool:
    if not scan_api_key_enabled(config) or not config.scan_api_key:
        return False
    header_key = headers.get(SCAN_API_KEY_HEADER) or headers.get(SCAN_API_KEY_HEADER.lower())
    if header_key:
        return secrets.compare_digest(header_key.strip(), config.scan_api_key)
    bearer = extract_bearer_token(headers)
    if bearer and not looks_like_jwt(bearer):
        return secrets.compare_digest(bearer, config.scan_api_key)
    return False


def verify_scan_auth(config: ServeConfig, headers: Mapping[str, str]) -> ScanAuthResult:
    bearer = extract_bearer_token(headers)
    if oidc_available(config) and bearer is not None and looks_like_jwt(bearer):
        try:
            claims = decode_oidc_token(config, bearer)
            require_scan_scope(claims)
            return ScanAuthResult(ok=True, method="oidc", caller_id=caller_id_from_claims(claims))
        except InsufficientScopeError:
            return ScanAuthResult(ok=False, error="insufficient_scope")
        except OIDCError:
            return ScanAuthResult(ok=False, error="unauthorized")
    if _verify_api_key(config, headers):
        return ScanAuthResult(ok=True, method="apikey")
    if scan_auth_required(config):
        return ScanAuthResult(ok=False, error="unauthorized")
    return ScanAuthResult(ok=True, method=None)


def scan_auth_health_label(config: ServeConfig) -> str:
    if not scan_auth_required(config) and not oidc_available(config):
        return "off"
    if not scan_auth_required(config):
        return f"{config.scan_auth_mode}:optional_oidc"
    parts = []
    if oidc_available(config):
        parts.append("oidc")
    if scan_api_key_enabled(config):
        parts.append("apikey")
    return f"{config.scan_auth_mode}:{'+'.join(parts) if parts else 'required'}"
