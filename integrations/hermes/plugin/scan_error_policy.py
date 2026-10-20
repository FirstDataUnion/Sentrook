"""Scan-error policy when Sentrook does not return a usable score (unreachable, timed out, rate
limited, rejected, or `status: error`). Defaults to `review`: ask when attended, block when
unattended. Auth and configuration failures never fail open."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

OnScanError = Literal["allow", "deny", "review"]
ScanFailureKind = Literal["rate_limited", "http", "timeout", "network", "config", "scan_error"]

AUTH_STATUSES = frozenset({401, 403})


@dataclass(frozen=True)
class ScanFailure:
    ok: Literal[False]
    kind: ScanFailureKind
    detail: str
    status: int | None = None
    retry_after_sec: float | None = None


@dataclass(frozen=True)
class HermesDirective:
    action: Literal["block", "approve"]
    message: str
    rule_key: str | None = None


def parse_on_scan_error(raw: Any, fallback: OnScanError = "review") -> OnScanError:
    if raw in ("allow", "deny", "review"):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in ("allow", "deny", "review"):
            return normalized
    return fallback


def is_scan_failure(value: Any) -> bool:
    return isinstance(value, ScanFailure) and value.ok is False


def is_auth_failure(failure: ScanFailure) -> bool:
    if failure.kind == "config":
        return True
    return failure.kind == "http" and failure.status in AUTH_STATUSES


def scan_auth_error_to_failure(err: object) -> ScanFailure:
    """Map OIDC mint / discovery errors to a scan failure."""
    detail = str(err).replace("\n", " ").strip()[:200]
    lower = detail.lower()
    status_match = re.search(r"\bHTTP (\d{3})\b", detail, flags=re.IGNORECASE)
    status = int(status_match.group(1)) if status_match else None
    if (status in AUTH_STATUSES) or "unauthorized" in lower:
        return ScanFailure(
            ok=False,
            kind="http",
            status=status if status in AUTH_STATUSES else 401,
            detail=detail or "scan auth failed",
        )
    if "timed out" in lower or "timeout" in lower or "abort" in lower:
        return ScanFailure(ok=False, kind="timeout", detail=detail or "scan auth timed out")
    return ScanFailure(ok=False, kind="network", detail=detail or "scan auth failed")


def _detail_snippet(failure: ScanFailure, limit: int = 100) -> str:
    raw = (failure.detail or "").strip().replace("\n", " ")
    if not raw:
        return ""
    if len(raw) <= limit:
        return raw
    return f"{raw[: max(0, limit - 3)]}..."


def scan_error_copy(failure: ScanFailure) -> str:
    """Operator-facing body for interactive scan-error review cards."""
    if failure.kind == "rate_limited":
        return "Sentrook rate-limited this scan. Continue this tool without a security scan?"
    if failure.kind == "config":
        return (
            "Sentrook's endpoint or credentials are not configured correctly "
            "(configuration error, not a security policy block). Continue this tool without scanning?"
        )
    if is_auth_failure(failure):
        return (
            "Sentrook could not authenticate to the scan service "
            "(configuration error — not a security policy block). "
            "Continue this tool without scanning?"
        )
    return "Sentrook is unreachable. Continue without scanning?"


def _block_reason_for(failure: ScanFailure) -> str:
    """Agent-facing block message when the tool must not run."""
    snippet = _detail_snippet(failure)
    if is_auth_failure(failure):
        base = (
            (
                "Sentrook is not configured correctly "
                if failure.kind == "config"
                else "Sentrook could not authenticate to the scan service "
            )
            + "(configuration error, not a security policy deny). "
            "Run `hermes sentrook verify` and check SENTROOK_SCAN_URL, SENTROOK_OIDC_ISSUER and the "
            "SENTROOK_SCAN_CLIENT_* credentials. "
            "The tool was not scanned or run."
        )
        return f"{base} Detail: {snippet}" if snippet else base
    if failure.kind == "rate_limited":
        base = "Sentrook rate-limited this scan; the tool was not scanned or run."
        return f"{base} Detail: {snippet}" if snippet else base
    base = (
        "Sentrook did not scan this tool call (unreachable or timed out). "
        "This is a connectivity/service issue, not a security policy deny. "
        "The tool was not run."
    )
    return f"{base} Detail: {snippet}" if snippet else base


def scan_error_to_directive(
    failure: ScanFailure,
    *,
    on_scan_error: OnScanError,
    unattended: bool,
    rule_key: str,
) -> HermesDirective | None:
    """Map a failed /scan attempt to a Hermes pre_tool_call directive.

    Auth and configuration failures never fail open: ``on_scan_error=allow`` still
    blocks. ``deny`` and ``review`` follow the same policy as other scan
    errors so operators get a clear config-error card instead of a silent
    hard block that looks like a policy deny.
    """
    if is_auth_failure(failure) and on_scan_error == "allow":
        return HermesDirective(action="block", message=_block_reason_for(failure))

    policy = on_scan_error
    if policy == "allow":
        return None
    if policy == "deny":
        return HermesDirective(action="block", message=_block_reason_for(failure))

    # review
    if unattended:
        return HermesDirective(action="block", message=_block_reason_for(failure))

    return HermesDirective(
        action="approve",
        message=scan_error_copy(failure),
        rule_key=rule_key,
    )


def parse_retry_after_seconds(header: str | None) -> float | None:
    if not header:
        return None
    trimmed = header.strip()
    try:
        as_number = float(trimmed)
        if as_number >= 0:
            return as_number
    except ValueError:
        pass
    try:
        when = datetime.fromisoformat(trimmed.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        delta = when.timestamp() - datetime.now(UTC).timestamp()
        return max(0.0, delta)
    except ValueError:
        return None
