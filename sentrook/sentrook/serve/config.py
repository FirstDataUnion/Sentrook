"""Serve configuration from `SENTROOK_*` environment variables (build plan 6.9).

Operators configure one image through the environment. Secrets (`SENTROOK_JEV_API_KEY`,
`SENTROOK_STATE_KEY`, `SENTROOK_SCAN_API_KEY`, `SENTROOK_ORACLE_API_KEY`) only ever come from here.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..jev.client import DEFAULT_BASE_URL, DEFAULT_MODEL

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org"
DEFAULT_OIDC_AUDIENCE = "sentrook"


def _bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = (env.get(key) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _float(env: Mapping[str, str], key: str, default: float) -> float:
    try:
        return float(env.get(key) or default)
    except ValueError:
        return default


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    try:
        return int(env.get(key) or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class ServeConfig:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    environment: str = "development"  # development | production
    log_content: str = "metadata"  # metadata | content (development only)
    log_level: str = "INFO"

    # scan auth (carried from 1.x)
    scan_auth_mode: str = "auto"  # auto | apikey | oidc
    scan_api_key: str | None = None
    oidc_issuer: str = DEFAULT_OIDC_ISSUER
    oidc_audience: str = DEFAULT_OIDC_AUDIENCE
    oidc_jwks_url: str = ""
    oidc_jwks_cache_seconds: int = 600

    # rate limiting (per caller after auth)
    rate_limit_enabled: bool = False
    rate_limit_scan_rate: float = 5.0
    rate_limit_scan_burst: int = 20

    # pipeline
    state_key: str = ""
    deployment: str | None = None
    jev_base_url: str = DEFAULT_BASE_URL
    jev_api_key: str | None = None
    jev_model: str = DEFAULT_MODEL
    jev_timeout_s: float = 20.0
    oracle_url: str | None = None
    oracle_api_key: str | None = None
    probes: tuple[str, ...] = field(default_factory=tuple)  # empty = all
    packs_default: tuple[str, ...] = ("tier1",)
    convergence: str = "conv-v1"
    lists_dir: str | None = None

    # test mode
    test_mode: bool = False

    @property
    def production(self) -> bool:
        return self.environment == "production"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServeConfig:
        env = os.environ if env is None else env
        environment = (env.get("SENTROOK_ENV") or "development").strip().lower()
        environment = "production" if environment in ("prod", "production") else "development"
        log_content = (env.get("SENTROOK_LOG_CONTENT") or "metadata").strip().lower()
        if environment == "production":
            log_content = "metadata"
        state_key = (env.get("SENTROOK_STATE_KEY") or "").strip()
        if not state_key:
            # A missing key would make every token invalid across restarts; in development mint one so
            # the local loop works, but never in production.
            if environment == "production":
                raise RuntimeError("SENTROOK_STATE_KEY is required in production")
            state_key = secrets.token_hex(32)
        probes_raw = (env.get("SENTROOK_PROBES") or "").strip()
        packs_raw = (env.get("SENTROOK_PACKS_DEFAULT") or "tier1").strip()
        test_mode = _bool(env, "SENTROOK_TEST_MODE", False)
        if test_mode and environment == "production":
            raise RuntimeError("SENTROOK_TEST_MODE cannot be enabled in production")
        return cls(
            host=env.get("SENTROOK_SCAN_HOST", DEFAULT_HOST),
            port=_int(env, "SENTROOK_SCAN_PORT", DEFAULT_PORT),
            environment=environment,
            log_content=log_content,
            log_level=(env.get("SENTROOK_LOG_LEVEL") or "INFO").upper(),
            scan_auth_mode=(env.get("SENTROOK_SCAN_AUTH_MODE") or "auto").strip().lower(),
            scan_api_key=(env.get("SENTROOK_SCAN_API_KEY") or "").strip() or None,
            oidc_issuer=(env.get("SENTROOK_OIDC_ISSUER") or DEFAULT_OIDC_ISSUER).strip(),
            oidc_audience=(env.get("SENTROOK_OIDC_AUDIENCE") or DEFAULT_OIDC_AUDIENCE).strip(),
            oidc_jwks_url=(env.get("SENTROOK_OIDC_JWKS_URL") or "").strip(),
            oidc_jwks_cache_seconds=_int(env, "SENTROOK_OIDC_JWKS_CACHE_SECONDS", 600),
            rate_limit_enabled=_bool(env, "SENTROOK_RATE_LIMIT_ENABLED", False),
            rate_limit_scan_rate=_float(env, "SENTROOK_RATE_LIMIT_SCAN_RATE", 5.0),
            rate_limit_scan_burst=_int(env, "SENTROOK_RATE_LIMIT_SCAN_BURST", 20),
            state_key=state_key,
            deployment=(env.get("SENTROOK_DEPLOYMENT") or "").strip() or None,
            jev_base_url=(env.get("SENTROOK_JEV_BASE_URL") or DEFAULT_BASE_URL).strip(),
            jev_api_key=(env.get("SENTROOK_JEV_API_KEY") or "").strip() or None,
            jev_model=(env.get("SENTROOK_JEV_MODEL") or DEFAULT_MODEL).strip(),
            jev_timeout_s=_float(env, "SENTROOK_JEV_TIMEOUT_MS", 20_000.0) / 1000.0,
            oracle_url=(env.get("SENTROOK_ORACLE_URL") or "").strip() or None,
            oracle_api_key=(env.get("SENTROOK_ORACLE_API_KEY") or "").strip() or None,
            probes=tuple(p.strip() for p in probes_raw.split(",") if p.strip())
            if probes_raw
            else (),
            packs_default=tuple(p.strip() for p in packs_raw.split(",") if p.strip()) or ("tier1",),
            convergence=(env.get("SENTROOK_CONVERGENCE") or "conv-v1").strip(),
            lists_dir=(env.get("SENTROOK_LISTS_DIR") or "").strip() or None,
            test_mode=test_mode,
        )
