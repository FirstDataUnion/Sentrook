"""scan_error_policy unit tests."""

from __future__ import annotations

from ..scan_error_policy import (
    ScanFailure,
    parse_on_scan_error,
    resolve_on_scan_error,
    scan_auth_error_to_failure,
    scan_error_to_directive,
)


def test_parse_on_scan_error_defaults_review() -> None:
    assert parse_on_scan_error(None) == "review"
    assert resolve_on_scan_error() == "review"


def test_resolve_on_scan_error_reads_config_and_env() -> None:
    assert resolve_on_scan_error(plugin_config="deny") == "deny"
    assert resolve_on_scan_error(env={"SENTROOK_ON_SCAN_ERROR": "allow"}) == "allow"


def test_allow_returns_none() -> None:
    failure = ScanFailure(ok=False, kind="timeout", detail="aborted")
    assert (
        scan_error_to_directive(
            failure,
            on_scan_error="allow",
            unattended=False,
            rule_key="sentrook:scan_error:abc",
        )
        is None
    )


def test_deny_blocks() -> None:
    failure = ScanFailure(ok=False, kind="timeout", detail="aborted")
    directive = scan_error_to_directive(
        failure,
        on_scan_error="deny",
        unattended=False,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "block"
    assert "did not scan" in directive.message
    assert "not a security policy deny" in directive.message.lower()


def test_review_interactive_escalates() -> None:
    failure = ScanFailure(ok=False, kind="timeout", detail="aborted")
    directive = scan_error_to_directive(
        failure,
        on_scan_error="review",
        unattended=False,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "approve"
    assert directive.rule_key == "sentrook:scan_error:abc"
    assert "unreachable" in directive.message.lower()


def test_review_unattended_blocks() -> None:
    failure = ScanFailure(ok=False, kind="timeout", detail="aborted")
    directive = scan_error_to_directive(
        failure,
        on_scan_error="review",
        unattended=True,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "block"
    assert directive.rule_key is None
    assert "connectivity" in directive.message.lower() or "timed out" in directive.message.lower()


def test_auth_failure_never_fail_open() -> None:
    failure = ScanFailure(
        ok=False,
        kind="http",
        status=401,
        detail='client_credentials token mint failed: HTTP 401: {"error":"invalid_client"}',
    )
    directive = scan_error_to_directive(
        failure,
        on_scan_error="allow",
        unattended=False,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "block"
    assert "configuration error" in directive.message.lower()
    assert "not a security policy deny" in directive.message.lower()
    assert "invalid_client" in directive.message


def test_auth_failure_review_interactive_escalates() -> None:
    failure = ScanFailure(ok=False, kind="http", status=401, detail="unauthorized")
    directive = scan_error_to_directive(
        failure,
        on_scan_error="review",
        unattended=False,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "approve"
    assert directive.rule_key == "sentrook:scan_error:abc"
    assert "configuration error" in directive.message.lower()
    assert "continue" in directive.message.lower()


def test_auth_failure_review_unattended_blocks_clearly() -> None:
    failure = ScanFailure(ok=False, kind="http", status=403, detail="forbidden")
    directive = scan_error_to_directive(
        failure,
        on_scan_error="review",
        unattended=True,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "block"
    assert "configuration error" in directive.message.lower()
    assert "forbidden" in directive.message


def test_auth_failure_deny_blocks() -> None:
    failure = ScanFailure(ok=False, kind="http", status=401, detail="unauthorized")
    directive = scan_error_to_directive(
        failure,
        on_scan_error="deny",
        unattended=False,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "block"
    assert "configuration error" in directive.message.lower()


def test_scan_auth_error_to_failure_maps_401() -> None:
    failure = scan_auth_error_to_failure(
        RuntimeError('client_credentials token mint failed: HTTP 401: {"error":"invalid_client"}')
    )
    assert failure.kind == "http"
    assert failure.status == 401
    assert "invalid_client" in failure.detail


def test_scan_auth_error_to_failure_maps_timeout() -> None:
    failure = scan_auth_error_to_failure(TimeoutError("OIDC request timed out after 30s"))
    assert failure.kind == "timeout"


def test_scan_auth_error_to_failure_maps_network() -> None:
    failure = scan_auth_error_to_failure(OSError("ECONNREFUSED"))
    assert failure.kind == "network"
