"""Scan-error policy when Sentrook does not return a usable score (unreachable, timed out, rate
limited, rejected, or `status: error`). Defaults to `review`: ask when attended, block when
unattended. Auth and configuration failures never fail open."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from . import skill_review
from .auth import ConsentWithdrawn
from .card import error_cause, hermes_error_message

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
    #: Why the credentials did not work, when that is known: `not_signed_in` (none stored), `sign_in_rejected`
    #: (the identity service refused them: revoked or wrong) or `consent_withdrawn` (refused because the owner
    #: withdrew consent on the FIDU portal). The fix is `hermes sentrook login`.
    setup: str | None = None


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
    if isinstance(err, ConsentWithdrawn):
        return ScanFailure(
            ok=False,
            kind="http",
            status=err.status,
            detail="consent withdrawn on the FIDU portal",
            setup="consent_withdrawn",
        )
    detail = str(err).replace("\n", " ").strip()[:200]
    lower = detail.lower()
    status_match = re.search(r"\bHTTP (\d{3})\b", detail, flags=re.IGNORECASE)
    status = int(status_match.group(1)) if status_match else None
    if (status in AUTH_STATUSES) or "unauthorized" in lower or "invalid_client" in lower:
        return ScanFailure(
            ok=False,
            kind="http",
            status=status if status in AUTH_STATUSES else 401,
            detail=detail or "scan auth failed",
            setup="sign_in_rejected" if "invalid_client" in lower else None,
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


def failure_cause(failure: ScanFailure) -> str:
    """The card's cause (`card.error_cause`). Under `plugins.isolation: host` Hermes has no `hermes sentrook`
    command line, so the sign-in causes name the manual route instead."""
    return error_cause(
        failure.kind,
        is_auth_failure(failure),
        setup=failure.setup,
        by_hand=skill_review.host_isolated(),
    )


def scan_error_copy(failure: ScanFailure) -> str:
    """The review card for a call that could not be scanned (`card.hermes_error_message`)."""
    return hermes_error_message(failure_cause(failure))


#: What the agent is told when the scan could not run for want of a working sign-in, by `ScanFailure.setup`.
_SETUP = "This is a setup problem, not a security finding."
_LOGIN_ON_HERMES = "in a terminal on the machine Hermes runs on."
SIGN_IN_FIXES = {
    "not_signed_in": {
        "login": "Sentrook is not signed in on this machine, so this tool call was not scanned or run. "
        f"{_SETUP} Tell the owner to run `hermes sentrook login` {_LOGIN_ON_HERMES} "
        "Do not try to run it yourself or work around this.",
        "by_hand": "Sentrook is not signed in on this machine, so this tool call was not scanned or run. "
        f"{_SETUP} Tell the owner to set Sentrook's credentials in Hermes (see the Sentrook install guide) and "
        "restart Hermes. Do not try to set them yourself or work around this.",
    },
    "sign_in_rejected": {
        "login": "Sentrook's sign-in was revoked or is wrong, so this tool call was not scanned or run. "
        f"{_SETUP} Tell the owner to run `hermes sentrook login` again {_LOGIN_ON_HERMES} "
        "Do not try to run it yourself or work around this.",
        "by_hand": "Sentrook's sign-in was revoked or is wrong, so this tool call was not scanned or run. "
        f"{_SETUP} Tell the owner to set new Sentrook credentials in Hermes (see the Sentrook install guide) "
        "and restart Hermes. Do not try to set them yourself or work around this.",
    },
    "consent_withdrawn": {
        "login": "The owner withdrew consent for Sentrook on the FIDU portal, so this tool call was not scanned or "
        f"run. {_SETUP} Tell the owner to reconnect by running `hermes sentrook login` in a terminal on the "
        "machine Hermes runs on, or to switch Sentrook to observe mode. Do not try to run it yourself or work around this.",
        "by_hand": "The owner withdrew consent for Sentrook on the FIDU portal, so this tool call was not scanned or "
        f"run. {_SETUP} Tell the owner to set new Sentrook credentials in Hermes (see the Sentrook install guide) "
        "and restart Hermes, or to switch Sentrook to observe mode. Do not try to set them yourself or work around "
        "this.",
    },
}


def _block_reason_for(failure: ScanFailure) -> str:
    """Agent-facing block message when the tool must not run."""
    snippet = _detail_snippet(failure)
    if failure.setup in SIGN_IN_FIXES:
        return SIGN_IN_FIXES[failure.setup]["by_hand" if skill_review.host_isolated() else "login"]
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
