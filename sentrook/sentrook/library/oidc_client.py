"""FIDU ID OAuth client for Sentrook (device-code login + client-credentials).

Sentrook is the OAuth *client* in this relationship — it's the only side that
authenticates directly against the identity-service. Rookery never talks to
the identity-service beyond fetching its public JWKS; it just verifies the
access tokens Sentrook presents. See ``rookery/rookery/oidc.py`` for that side.

Endpoint URLs are resolved from the issuer's OIDC discovery document
(``/.well-known/openid-configuration``).

Two credential paths, matching the identity-service's seeded OAuth clients:

- Interactive/local (``sentrook library login``): RFC 8628 device authorization
  grant against the ``sentrook-cli`` public client, with the resulting token
  pair cached on disk or the OS keychain and silently refreshed by
  ``get_access_token()``.
- CI/automation: client-credentials grant against the ``sentrook-ci``
  confidential client, activated by ``SENTROOK_ROOKERY_CI_CLIENT_SECRET`` in
  the environment, or the same value loaded into process memory from OpenBao
  when ``SENTROOK_OPENBAO_ENABLED=1``. Minted fresh on demand — short-lived and
  not persisted to disk.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sentrook.library import http_client
from sentrook.library.token_store import (
    clear_cached_tokens,
    load_cached_tokens,
    save_tokens,
    token_cache_path,
)
from sentrook.library.tokens import EXPIRY_SKEW_SECONDS, TokenSet

DEFAULT_IDENTITY_ISSUER = "https://identity.firstdataunion.org"
DEFAULT_CLIENT_ID = "sentrook-cli"
DEFAULT_CI_CLIENT_ID = "sentrook-ci"
DEFAULT_SCOPE = "openid profile sentrook.library.read sentrook.submissions.write"
DEFAULT_CI_SCOPE = "sentrook.library.read sentrook.submissions.write"

SCOPE_LABELS: dict[str, str] = {
    "sentrook.library.read": "pull Rookery library updates",
    "sentrook.library.key.read": "read library signing keys",
    "sentrook.submissions.write": "submit corpus feedback",
    "openid": "OpenID Connect sign-in",
    "profile": "basic profile",
}

# Fallback paths when discovery is unavailable (previous FIDU identity-service layout).
_FALLBACK_DEVICE_PATH = "/oauth/device/code"
_FALLBACK_TOKEN_PATH = "/oauth/token"


class OIDCClientError(Exception):
    """Raised when a device-flow or token-endpoint call fails."""


@dataclass(frozen=True)
class OIDCDiscovery:
    issuer: str
    token_endpoint: str
    device_authorization_endpoint: str


@dataclass(frozen=True)
class DeviceAuthorization:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


_discovery_cache: dict[str, OIDCDiscovery] = {}


def identity_issuer() -> str:
    # Treat unset *or* empty (e.g. docker-compose ${VAR:-}) as "use default".
    raw = os.environ.get("SENTROOK_IDENTITY_ISSUER") or DEFAULT_IDENTITY_ISSUER
    return normalize_issuer(raw)


def normalize_issuer(url: str) -> str:
    """Return an absolute https issuer base URL."""
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


def issuers_match(left: str, right: str) -> bool:
    return normalize_issuer(left) == normalize_issuer(right)


def fetch_oidc_discovery(issuer: str) -> OIDCDiscovery:
    """Load and cache OIDC metadata for an identity-service issuer."""
    normalized = normalize_issuer(issuer)
    if not normalized:
        raise OIDCClientError("identity issuer is not configured")

    cached = _discovery_cache.get(normalized)
    if cached is not None:
        return cached

    discovery_url = f"{normalized}/.well-known/openid-configuration"
    request = urllib.request.Request(discovery_url, method="GET")
    try:
        with http_client.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise OIDCClientError(
            f"failed to load OIDC discovery from {discovery_url}: HTTP {exc.code}: {body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise OIDCClientError(f"failed to reach {discovery_url}: {exc}") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise OIDCClientError(f"invalid OIDC discovery document at {discovery_url}") from exc

    try:
        discovery = OIDCDiscovery(
            issuer=str(payload["issuer"]).rstrip("/"),
            token_endpoint=str(payload["token_endpoint"]),
            device_authorization_endpoint=str(
                payload.get("device_authorization_endpoint")
                or f"{normalized}{_FALLBACK_DEVICE_PATH}"
            ),
        )
    except KeyError as exc:
        raise OIDCClientError(
            f"OIDC discovery document at {discovery_url} is missing required fields"
        ) from exc

    if not discovery.token_endpoint:
        discovery = OIDCDiscovery(
            issuer=discovery.issuer,
            token_endpoint=f"{normalized}{_FALLBACK_TOKEN_PATH}",
            device_authorization_endpoint=discovery.device_authorization_endpoint,
        )

    _discovery_cache[normalized] = discovery
    return discovery


def _oauth_post(url: str, form: dict[str, str]) -> dict[str, Any]:
    data = urllib.parse.urlencode(form).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with http_client.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            error_payload = json.loads(body)
        except ValueError:
            error_payload = {}
        error_code = error_payload.get("error", f"http_{exc.code}")
        description = error_payload.get("error_description", body or str(exc))
        raise OIDCClientError(f"{error_code}: {description}") from exc
    except urllib.error.URLError as exc:
        raise OIDCClientError(f"failed to reach {url}: {exc}") from exc


def start_device_login(
    *,
    issuer: str,
    client_id: str = DEFAULT_CLIENT_ID,
    scope: str = DEFAULT_SCOPE,
) -> DeviceAuthorization:
    discovery = fetch_oidc_discovery(issuer)
    payload = _oauth_post(
        discovery.device_authorization_endpoint,
        {"client_id": client_id, "scope": scope},
    )
    return DeviceAuthorization(
        device_code=payload["device_code"],
        user_code=payload["user_code"],
        verification_uri=payload["verification_uri"],
        verification_uri_complete=payload.get(
            "verification_uri_complete", payload["verification_uri"]
        ),
        expires_in=int(payload.get("expires_in", 600)),
        interval=int(payload.get("interval", 5)),
    )


def describe_scopes(scope: str) -> list[str]:
    """Map token scope tokens to short human-readable capability labels."""
    labels: list[str] = []
    for part in scope.split():
        labels.append(SCOPE_LABELS.get(part, part))
    return labels


def poll_device_token(
    *,
    issuer: str,
    client_id: str,
    device_code: str,
    interval: int = 5,
    expires_in: int = 600,
    sleep: Any = time.sleep,
    on_wait: Callable[[int], None] | None = None,
) -> TokenSet:
    """Poll the token endpoint per RFC 8628 until the user approves or it expires."""
    discovery = fetch_oidc_discovery(issuer)
    deadline = time.time() + expires_in
    poll_interval = max(interval, 1)

    while True:
        remaining = int(max(0, deadline - time.time()))
        if remaining <= 0:
            raise OIDCClientError("device code expired before approval")
        if on_wait is not None:
            on_wait(remaining)

        sleep(poll_interval)
        try:
            payload = _oauth_post(
                discovery.token_endpoint,
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": client_id,
                    "device_code": device_code,
                },
            )
        except OIDCClientError as exc:
            message = str(exc)
            if message.startswith("authorization_pending"):
                continue
            if message.startswith("slow_down"):
                poll_interval += 5
                continue
            raise
        return TokenSet.from_token_response(payload)


def refresh_tokens(*, issuer: str, client_id: str, refresh_token: str) -> TokenSet:
    discovery = fetch_oidc_discovery(issuer)
    payload = _oauth_post(
        discovery.token_endpoint,
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        },
    )
    tokens = TokenSet.from_token_response(payload)
    if tokens.refresh_token is None:
        tokens = TokenSet(
            access_token=tokens.access_token,
            refresh_token=refresh_token,
            expires_at=tokens.expires_at,
            scope=tokens.scope,
        )
    return tokens


def client_credentials_token(
    *,
    issuer: str,
    client_id: str,
    client_secret: str,
    scope: str = DEFAULT_CI_SCOPE,
) -> TokenSet:
    discovery = fetch_oidc_discovery(issuer)
    payload = _oauth_post(
        discovery.token_endpoint,
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
    return TokenSet.from_token_response(payload)


def get_access_token() -> str | None:
    """Best-effort, non-interactive OIDC access token for outgoing Rookery calls.

    Never prompts and never raises — any failure (misconfiguration, network
    error, no cached login) falls back to ``None`` so callers can fall back to
    a static API key or an unauthenticated request, matching Rookery's
    hybrid auth model.
    """
    issuer = identity_issuer()

    # Prefer in-memory OpenBao load (prod) over process env (local/staging).
    ci_secret: str | None = None
    from sentrook.openbao import (
        OpenBaoError,
        ensure_sentrook_secrets_loaded,
        openbao_enabled,
        runtime_ci_client_secret,
    )

    if openbao_enabled():
        try:
            ensure_sentrook_secrets_loaded()
            ci_secret = runtime_ci_client_secret()
        except OpenBaoError:
            ci_secret = None
    if not ci_secret:
        ci_secret = os.environ.get("SENTROOK_ROOKERY_CI_CLIENT_SECRET")
    if ci_secret:
        ci_client_id = os.environ.get("SENTROOK_ROOKERY_CI_CLIENT_ID", DEFAULT_CI_CLIENT_ID)
        scope = os.environ.get("SENTROOK_ROOKERY_SCOPE", DEFAULT_CI_SCOPE)
        try:
            tokens = client_credentials_token(
                issuer=issuer, client_id=ci_client_id, client_secret=ci_secret, scope=scope
            )
            return tokens.access_token
        except OIDCClientError:
            return None

    tokens = load_cached_tokens()
    if tokens is None:
        return None

    if not tokens.is_expired():
        return tokens.access_token

    if not tokens.refresh_token:
        return None

    client_id = os.environ.get("SENTROOK_ROOKERY_CLIENT_ID", DEFAULT_CLIENT_ID)
    try:
        refreshed = refresh_tokens(
            issuer=issuer, client_id=client_id, refresh_token=tokens.refresh_token
        )
    except OIDCClientError:
        return None

    try:
        save_tokens(refreshed)
    except OSError:
        pass
    return refreshed.access_token


__all__ = [
    "DEFAULT_CI_CLIENT_ID",
    "DEFAULT_CI_SCOPE",
    "DEFAULT_CLIENT_ID",
    "DEFAULT_IDENTITY_ISSUER",
    "DEFAULT_SCOPE",
    "DeviceAuthorization",
    "OIDCClientError",
    "OIDCDiscovery",
    "SCOPE_LABELS",
    "EXPIRY_SKEW_SECONDS",
    "TokenSet",
    "clear_cached_tokens",
    "client_credentials_token",
    "describe_scopes",
    "fetch_oidc_discovery",
    "get_access_token",
    "identity_issuer",
    "issuers_match",
    "load_cached_tokens",
    "normalize_issuer",
    "poll_device_token",
    "refresh_tokens",
    "save_tokens",
    "start_device_login",
    "token_cache_path",
]
