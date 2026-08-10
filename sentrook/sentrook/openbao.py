"""Load Sentrook scan secrets from OpenBao / Vault-compatible KV (prod).

Enabled when ``SENTROOK_OPENBAO_ENABLED=1`` (or ``SENTROOK_OPENBAO``). Reads a
short-lived token from ``OPENBAO_TOKEN`` or ``OPENBAO_TOKEN_FILE`` (agent sink),
then fetches ``sentrook/data/prod`` (override with ``SENTROOK_OPENBAO_SECRET_PATH``).

Secrets are returned as a dict for merging into ``ServeConfig`` — they are never
written back to ``os.environ``. A process-level cache also feeds
``get_access_token()`` for the CI client secret (read lazily, not only at serve).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentrook.openbao")

DEFAULT_ADDR = "http://127.0.0.1:8200"
DEFAULT_SECRET_PATH = "sentrook/data/prod"

# Required OpenBao KV keys → ServeConfig / runtime field names
_REQUIRED_KEY_MAP = {
    "rookery_ci_client_secret": "rookery_ci_client_secret",
    "rookery_api_key": "rookery_api_key",
}

# Optional: omit when scan auth is OIDC-only
_OPTIONAL_KEY_MAP = {
    "scan_api_key": "scan_api_key",
}

_cached_secrets: dict[str, str] | None = None
_runtime_ci_client_secret: str | None = None


class OpenBaoError(RuntimeError):
    """Failed to authenticate to OpenBao or read Sentrook secrets."""


def openbao_enabled(environ: dict[str, str] | None = None) -> bool:
    env = environ if environ is not None else os.environ
    raw = (env.get("SENTROOK_OPENBAO_ENABLED") or env.get("SENTROOK_OPENBAO") or "").strip()
    # Strip inline comments (Compose / .env habit)
    raw = raw.split("#", 1)[0].strip().lower()
    return raw in {"1", "true", "yes", "on"}


def runtime_ci_client_secret() -> str | None:
    """CI client secret from the last successful OpenBao load (not ``os.environ``)."""
    return _runtime_ci_client_secret


def reset_openbao_cache() -> None:
    """Clear process cache (tests)."""
    global _cached_secrets, _runtime_ci_client_secret
    _cached_secrets = None
    _runtime_ci_client_secret = None


def _apply_runtime_cache(secrets: dict[str, str]) -> None:
    global _cached_secrets, _runtime_ci_client_secret
    _cached_secrets = dict(secrets)
    _runtime_ci_client_secret = secrets.get("rookery_ci_client_secret")


def _read_token(environ: dict[str, str] | None = None) -> str:
    env = environ if environ is not None else os.environ
    token = (env.get("OPENBAO_TOKEN") or "").strip()
    if token:
        return token
    path_raw = (env.get("OPENBAO_TOKEN_FILE") or "").strip()
    if not path_raw:
        raise OpenBaoError(
            "OpenBao enabled but neither OPENBAO_TOKEN nor OPENBAO_TOKEN_FILE is set"
        )
    path = Path(path_raw)
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise OpenBaoError(f"cannot read OpenBao token file {path}: {exc}") from exc
    if not token:
        raise OpenBaoError(f"OpenBao token file is empty: {path}")
    return token


def fetch_sentrook_secrets(
    *,
    environ: dict[str, str] | None = None,
    client: Any | None = None,
) -> dict[str, str]:
    """Return Sentrook secrets from KV (required + optional keys present).

    ``client`` is an optional pre-configured ``hvac.Client`` (tests).
    """
    env = environ if environ is not None else os.environ
    if client is None:
        try:
            import hvac
        except ImportError as exc:
            raise OpenBaoError(
                "hvac is required when SENTROOK_OPENBAO_ENABLED=1 (pip install 'hvac>=2.4.0')"
            ) from exc
        addr = (env.get("BAO_ADDR") or env.get("VAULT_ADDR") or DEFAULT_ADDR).strip()
        token = _read_token(env)
        client = hvac.Client(url=addr, token=token)
        if not client.is_authenticated():
            raise OpenBaoError(f"OpenBao token rejected by {addr}")

    path = (env.get("SENTROOK_OPENBAO_SECRET_PATH") or DEFAULT_SECRET_PATH).strip().lstrip("/")
    # hvac secrets.kv.v2 expects mount + path without "data/"
    # Accept either "sentrook/data/prod" or "sentrook/prod"
    mount, secret_path = _split_kv_v2_path(path)

    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=secret_path,
            mount_point=mount,
        )
    except Exception as exc:  # noqa: BLE001 — surface as OpenBaoError
        raise OpenBaoError(f"failed to read OpenBao secret {mount}/{secret_path}: {exc}") from exc

    data = ((response or {}).get("data") or {}).get("data") or {}
    if not isinstance(data, dict):
        raise OpenBaoError(f"unexpected OpenBao payload for {path}")

    out: dict[str, str] = {}
    missing: list[str] = []
    for bao_key, field in _REQUIRED_KEY_MAP.items():
        value = data.get(bao_key)
        if value is None or str(value) == "":
            missing.append(bao_key)
            continue
        out[field] = str(value)
    if missing:
        raise OpenBaoError(f"OpenBao secret {path} missing required keys: {', '.join(missing)}")

    for bao_key, field in _OPTIONAL_KEY_MAP.items():
        value = data.get(bao_key)
        if value is None or str(value) == "":
            continue
        out[field] = str(value)

    loaded = ", ".join(sorted(out))
    logger.info("OpenBao secrets loaded from %s (%s)", path, loaded)
    _apply_runtime_cache(out)
    return out


def ensure_sentrook_secrets_loaded(
    *,
    environ: dict[str, str] | None = None,
    client: Any | None = None,
) -> dict[str, str]:
    """Fetch once per process; subsequent calls return the cache."""
    global _cached_secrets
    if _cached_secrets is not None:
        return _cached_secrets
    return fetch_sentrook_secrets(environ=environ, client=client)


def _split_kv_v2_path(path: str) -> tuple[str, str]:
    """Split ``mount/data/secret`` or ``mount/secret`` into (mount, secret)."""
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise OpenBaoError(f"SENTROOK_OPENBAO_SECRET_PATH must be mount[/data]/name, got {path!r}")
    mount = parts[0]
    rest = parts[1:]
    if rest and rest[0] == "data":
        rest = rest[1:]
    if not rest:
        raise OpenBaoError(f"SENTROOK_OPENBAO_SECRET_PATH missing secret name: {path!r}")
    return mount, "/".join(rest)
