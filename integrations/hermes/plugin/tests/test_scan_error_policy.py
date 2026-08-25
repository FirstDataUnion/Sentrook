"""scan_error_policy unit tests."""

from __future__ import annotations

from ..scan_error_policy import (
    ScanFailure,
    parse_on_scan_error,
    resolve_on_scan_error,
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


def test_auth_failure_always_blocks() -> None:
    failure = ScanFailure(ok=False, kind="http", status=401, detail="unauthorized")
    directive = scan_error_to_directive(
        failure,
        on_scan_error="allow",
        unattended=False,
        rule_key="sentrook:scan_error:abc",
    )
    assert directive is not None
    assert directive.action == "block"
    assert "credentials" in directive.message.lower()
