"""In-process token-bucket limiter and ServeConfig defaults."""

from __future__ import annotations

from sentrook.serve.auth import ScanAuthResult
from sentrook.serve.config import ServeConfig
from sentrook.serve.rate_limit import (
    MemoryTokenBucketLimiter,
    check_request,
    rate_limit_headers,
    rate_limit_key,
)


def test_rate_limit_key_oidc_and_apikey() -> None:
    oidc = ScanAuthResult(ok=True, method="oidc", caller_id="user-1")
    assert rate_limit_key(oidc) == "oidc:user-1"
    apikey = ScanAuthResult(ok=True, method="apikey")
    assert rate_limit_key(apikey) == "apikey:shared"
    anon = ScanAuthResult(ok=True, method=None)
    assert rate_limit_key(anon) is None


def test_token_bucket_allows_burst_then_429() -> None:
    limiter = MemoryTokenBucketLimiter()
    allowed = 0
    denied = 0
    last = None
    for _ in range(4):
        last = limiter.allow("oidc:u:scan", rate=1.0, burst=2)
        if last.allowed:
            allowed += 1
        else:
            denied += 1
    assert allowed == 2
    assert denied == 2
    assert last is not None and last.allowed is False
    headers = rate_limit_headers(last)
    assert headers["Retry-After"]
    assert headers["RateLimit-Remaining"] == "0"


def test_from_env_enables_limiter_for_oidc_and_production() -> None:
    oidc = ServeConfig.from_env({"SENTROOK_SCAN_AUTH_MODE": "oidc"})
    assert oidc.rate_limit_enabled is True
    prod = ServeConfig.from_env({"SENTROOK_ENV": "production", "SENTROOK_SCAN_AUTH_MODE": "auto"})
    assert prod.rate_limit_enabled is True
    local = ServeConfig.from_env({"SENTROOK_SCAN_AUTH_MODE": "auto"})
    assert local.rate_limit_enabled is False
    off = ServeConfig.from_env(
        {"SENTROOK_SCAN_AUTH_MODE": "oidc", "SENTROOK_RATE_LIMIT_ENABLED": "0"}
    )
    assert off.rate_limit_enabled is False
    custom = ServeConfig.from_env(
        {"SENTROOK_RATE_LIMIT_SCAN_RATE": "7", "SENTROOK_RATE_LIMIT_SCAN_BURST": "9"}
    )
    assert custom.rate_limit_scan_rate == 7.0
    assert custom.rate_limit_scan_burst == 9


def test_check_request_skips_anonymous_even_when_enabled() -> None:
    limiter = MemoryTokenBucketLimiter()
    decision = check_request(
        limiter,
        ScanAuthResult(ok=True, method=None),
        "/scan",
        enabled=True,
        scan_rate=1.0,
        scan_burst=1,
        aux_rate=1.0,
        aux_burst=1,
    )
    assert decision is None
