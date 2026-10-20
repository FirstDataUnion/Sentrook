"""POST /scan transport. Token mint happens outside the scan deadline; one 429 is retried when
`Retry-After` fits in the deadline."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .auth import OidcCredentials, get_scan_access_token, http_json
from .scan_error_policy import ScanFailure, parse_retry_after_seconds, scan_auth_error_to_failure


@dataclass(frozen=True)
class ScanOk:
    response: dict[str, Any]
    latency_ms: int
    ok: bool = True


def parse_scan_response(body: Any, status: int) -> dict[str, Any] | ScanFailure:
    """Usable when it is Response 2.0 with a numeric risk and a non-error status."""
    if not isinstance(body, dict):
        return ScanFailure(
            ok=False, kind="http", status=status, detail="scan response is not an object"
        )
    if body.get("response_version") != "2.0":
        return ScanFailure(
            ok=False,
            kind="http",
            status=status,
            detail=f"unexpected response_version {body.get('response_version')!r}",
        )
    risk = body.get("risk")
    if (
        body.get("status") == "error"
        or not isinstance(risk, (int, float))
        or isinstance(risk, bool)
    ):
        err = body.get("error") if isinstance(body.get("error"), dict) else {}
        detail = f"{err.get('code') or 'no_score'}: {err.get('message') or 'scan returned no usable score'}"
        return ScanFailure(ok=False, kind="scan_error", status=status, detail=detail[:200])
    enforced = body.get("enforced")
    if enforced not in (None, "block", "review"):
        return ScanFailure(
            ok=False, kind="http", status=status, detail=f"unknown enforced value {enforced!r}"
        )
    return body


def post_scan(
    *, scan_url: str, oidc: OidcCredentials | None, body: bytes, timeout_ms: int
) -> ScanOk | ScanFailure:
    if oidc is None:
        return ScanFailure(
            ok=False,
            kind="config",
            detail="no scan credentials (set SENTROOK_SCAN_CLIENT_ID and SENTROOK_SCAN_CLIENT_SECRET)",
        )
    try:
        token = get_scan_access_token(oidc)
    except Exception as exc:  # noqa: BLE001 - every mint failure maps to a scan failure
        return scan_auth_error_to_failure(exc)

    headers = {"content-type": "application/json", "authorization": f"Bearer {token}"}
    started = time.monotonic()
    deadline = started + timeout_ms / 1000
    retried = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ScanFailure(
                ok=False, kind="timeout", detail=f"scan timed out after {timeout_ms}ms"
            )
        try:
            status, parsed, hdrs = http_json(
                f"{scan_url}/scan", data=body, headers=headers, timeout=remaining
            )
        except TimeoutError as exc:
            return ScanFailure(ok=False, kind="timeout", detail=str(exc)[:200])
        except OSError as exc:
            kind = "timeout" if "timed out" in str(exc).lower() else "network"
            return ScanFailure(ok=False, kind=kind, detail=str(exc)[:200])
        # 422 carries the Response 2.0 error shape (preparation failed).
        if 200 <= status < 300 or status == 422:
            result = parse_scan_response(parsed, status)
            if isinstance(result, ScanFailure):
                return result
            return ScanOk(response=result, latency_ms=int((time.monotonic() - started) * 1000))
        detail = (parsed if isinstance(parsed, str) else str(parsed))[:200]
        if status == 429:
            retry_after = (
                parse_retry_after_seconds(hdrs.get("Retry-After") or hdrs.get("retry-after")) or 1.0
            )
            if not retried and deadline - time.monotonic() > retry_after + 0.05:
                retried = True
                time.sleep(retry_after)
                continue
            return ScanFailure(
                ok=False,
                kind="rate_limited",
                status=429,
                retry_after_sec=retry_after,
                detail=detail or "rate limited",
            )
        return ScanFailure(ok=False, kind="http", status=status, detail=detail or f"HTTP {status}")
