"""Scan-error policy — Hermes defaults (onScanError review)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

OnScanError = Literal["allow", "deny", "review"]
ScanFailureKind = Literal["rate_limited", "http", "timeout", "network"]

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


def resolve_on_scan_error(
    *,
    plugin_config: Any = None,
    env: dict[str, str] | None = None,
) -> OnScanError:
    env = env or dict(os.environ)
    raw = plugin_config if plugin_config is not None else env.get("SENTROOK_ON_SCAN_ERROR")
    return parse_on_scan_error(raw, fallback="review")


def is_scan_failure(value: Any) -> bool:
    return isinstance(value, ScanFailure) and value.ok is False


def is_auth_failure(failure: ScanFailure) -> bool:
    return failure.kind == "http" and failure.status in AUTH_STATUSES


def scan_error_copy(failure: ScanFailure) -> str:
    if failure.kind == "rate_limited":
        return "Sentrook rate-limited this scan. Continue this tool without a security scan?"
    if is_auth_failure(failure):
        return "Sentrook rejected the scan credentials. The tool will not run."
    return "Sentrook is unreachable. Continue without scanning?"


def _block_reason_for(failure: ScanFailure) -> str:
    if failure.kind == "rate_limited":
        return "Sentrook rate-limited this scan; the tool was not scanned"
    return "Sentrook did not scan this tool call (unreachable or timed out)"


def scan_error_to_directive(
    failure: ScanFailure,
    *,
    on_scan_error: OnScanError,
    unattended: bool,
    rule_key: str,
) -> HermesDirective | None:
    """Map a failed /scan attempt to a Hermes pre_tool_call directive."""
    if is_auth_failure(failure):
        return HermesDirective(
            action="block",
            message="Sentrook rejected scan credentials",
        )

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
        delta = (when.timestamp() - datetime.now(UTC).timestamp())
        return max(0.0, delta)
    except ValueError:
        return None
