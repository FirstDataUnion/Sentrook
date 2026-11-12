"""Scan auth: OIDC client_credentials against the identity service.

The client id and secret come only through Hermes: `agent.secret_scope.get_secret`, which honours the
active profile on a multiplexed gateway. The plugin never opens a `.env` file. Hermes stores the values
(`hermes config set SENTROOK_SCAN_CLIENT_ID ...`, the install prompt, or the Desktop plugin settings) and
loads them when it starts, so a changed credential applies after Hermes reloads its environment.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

DEFAULT_SCAN_AUDIENCE = "sentrook"
DEFAULT_SCAN_SCOPE = "sentrook.scan"
DEFAULT_AUTH_TIMEOUT_S = 30.0
TOKEN_EXPIRY_SKEW_S = 60
CLIENT_ID_VAR = "SENTROOK_SCAN_CLIENT_ID"
CLIENT_SECRET_VAR = "SENTROOK_SCAN_CLIENT_SECRET"
CREDENTIAL_VARS = (CLIENT_ID_VAR, CLIENT_SECRET_VAR)


@dataclass(frozen=True)
class OidcCredentials:
    client_id: str
    client_secret: str
    issuer: str
    audience: str
    scope: str


_cache: dict[str, Any] = {}
_cache_lock = threading.Lock()


def clear_scan_token_cache() -> None:
    with _cache_lock:
        _cache.clear()


def get_secret(name: str) -> str | None:
    """A credential through Hermes's route, `agent.secret_scope.get_secret`; None when unset.

    Outside Hermes (unit tests, tooling) the module is missing and the process env is read instead. Any
    error from Hermes (an unscoped read on a multiplexed gateway raises) reads as unset, so the scan
    fails closed rather than borrowing another profile's value.
    """
    try:
        from agent.secret_scope import get_secret as hermes_get_secret
    except ImportError:
        value: Any = os.environ.get(name)
    else:
        try:
            value = hermes_get_secret(name)
        except Exception:  # noqa: BLE001 - UnscopedSecretError and friends: treated as unset
            value = None
    return value.strip() if isinstance(value, str) and value.strip() else None


def missing_credentials(secret: Callable[[str], str | None] = get_secret) -> list[str]:
    """The credential variables Hermes has no value for, in a fixed order."""
    return [name for name in CREDENTIAL_VARS if not secret(name)]


def _setting(raw: Any, env: dict[str, str], var: str) -> str | None:
    """A non-secret value: the plugin setting, then the process env."""
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return env.get(var, "").strip() or None


def resolve_oidc_credentials(
    settings: dict[str, Any],
    env: dict[str, str],
    issuer: str,
    secret: Callable[[str], str | None] = get_secret,
) -> OidcCredentials | None:
    """None when either credential is missing. The audience and scope are not secrets: settings, then
    env, then the defaults."""
    client_id, client_secret = secret(CLIENT_ID_VAR), secret(CLIENT_SECRET_VAR)
    if not client_id or not client_secret:
        return None
    return OidcCredentials(
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer.rstrip("/"),
        audience=_setting(settings.get("oidc_audience"), env, "SENTROOK_OIDC_AUDIENCE")
        or DEFAULT_SCAN_AUDIENCE,
        scope=_setting(settings.get("oidc_scope"), env, "SENTROOK_OIDC_SCOPE")
        or DEFAULT_SCAN_SCOPE,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http_json(
    url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None, timeout: float
) -> tuple[int, Any, dict[str, str]]:
    """POST when `data` is given, else GET. Returns (status, parsed JSON or text, headers); no redirects."""
    req = urllib.request.Request(
        url, data=data, headers=headers or {}, method="POST" if data is not None else "GET"
    )
    try:
        with _opener.open(req, timeout=timeout) as resp:
            status, body, hdrs = resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        status, body, hdrs = e.code, e.read(), dict(e.headers or {})
    text = body.decode("utf-8", errors="replace")
    try:
        return status, json.loads(text), hdrs
    except ValueError:
        return status, text, hdrs


def _jwt_exp(token: str) -> float | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = "=" * (-len(parts[1]) % 4)
        exp = json.loads(base64.urlsafe_b64decode(parts[1] + pad)).get("exp")
        return float(exp) if isinstance(exp, (int, float)) else None
    except (ValueError, TypeError):
        return None


def get_scan_access_token(oidc: OidcCredentials, timeout: float = DEFAULT_AUTH_TIMEOUT_S) -> str:
    """Discovery from the issuer; the token endpoint must be on the issuer's origin, so a tampered
    discovery document cannot send the client secret elsewhere."""
    key = f"{oidc.issuer}|{oidc.client_id}|{oidc.audience}|{oidc.scope}"
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[1] > now + TOKEN_EXPIRY_SKEW_S:
            return hit[0]

    status, doc, _ = http_json(f"{oidc.issuer}/.well-known/openid-configuration", timeout=timeout)
    if status != 200 or not isinstance(doc, dict):
        raise RuntimeError(f"OIDC discovery failed: HTTP {status}")
    endpoint = doc.get("token_endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        raise RuntimeError("OIDC discovery missing token_endpoint")
    a, b = urllib.parse.urlsplit(endpoint), urllib.parse.urlsplit(oidc.issuer)
    if (a.scheme, a.netloc) != (b.scheme, b.netloc):
        raise RuntimeError("OIDC token_endpoint is not on the issuer's origin")

    form = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": oidc.client_id,
            "client_secret": oidc.client_secret,
            "scope": oidc.scope,
            "audience": oidc.audience,
        }
    ).encode()
    status, payload, _ = http_json(
        endpoint,
        data=form,
        headers={"content-type": "application/x-www-form-urlencoded"},
        timeout=timeout,
    )
    if status != 200:
        hint = (json.dumps(payload) if not isinstance(payload, str) else payload)[:200]
        raise RuntimeError(f"client_credentials token mint failed: HTTP {status}: {hint}")
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise RuntimeError("token response missing access_token")
    token = str(payload["access_token"])
    expires_in = (
        payload.get("expires_in") if isinstance(payload.get("expires_in"), (int, float)) else 1800
    )
    exp = _jwt_exp(token) or now + float(expires_in)
    with _cache_lock:
        _cache[key] = (token, exp)
    return token
