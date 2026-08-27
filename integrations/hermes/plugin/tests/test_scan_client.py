"""scan_client parse / 200-body failure tests (mocked HTTP)."""

from __future__ import annotations

import time

from .. import scan_client as scan_client_mod
from ..auth import ScanAuthConfig
from ..planir import build_planir_snapshot
from ..scan_client import _parse_scan_response, post_scan
from ..scan_error_policy import is_scan_failure


def test_parse_allow_and_block() -> None:
    allow = _parse_scan_response(b'{"decision":"allow","block":false}')
    assert not is_scan_failure(allow)
    assert allow.decision == "allow"
    block = _parse_scan_response(b'{"decision":"BLOCK","block":true}')
    assert not is_scan_failure(block)
    assert block.decision == "block"


def test_parse_block_flag_without_decision() -> None:
    parsed = _parse_scan_response(b'{"block":true}')
    assert not is_scan_failure(parsed)
    assert parsed.decision == "block"


def test_parse_unknown_decision_is_failure() -> None:
    parsed = _parse_scan_response(b'{"decision":"maybe","block":false}')
    assert is_scan_failure(parsed)
    assert parsed.kind == "http"
    assert parsed.status == 200
    assert "unknown" in parsed.detail


def test_parse_missing_decision_is_failure() -> None:
    parsed = _parse_scan_response(b'{"block":false}')
    assert is_scan_failure(parsed)
    assert "missing" in parsed.detail


def test_parse_invalid_json_is_failure() -> None:
    parsed = _parse_scan_response(b"<html>nope")
    assert is_scan_failure(parsed)
    assert "invalid scan JSON" in parsed.detail


def test_parse_non_object_is_failure() -> None:
    parsed = _parse_scan_response(b'["allow"]')
    assert is_scan_failure(parsed)


def test_post_scan_invalid_json_200(monkeypatch) -> None:
    monkeypatch.setattr(
        scan_client_mod,
        "_http_request",
        lambda *a, **k: (200, {}, b"not-json"),
    )
    monkeypatch.setattr(scan_client_mod, "build_scan_auth_headers", lambda *a, **k: {})
    plan = build_planir_snapshot(
        executed=[],
        pending={"tool": "terminal", "args": {"command": "ls"}},
        run_id="r",
    )
    result = post_scan(
        "https://example.invalid",
        1000,
        plan,
        ScanAuthConfig(api_key="k", oidc=None),
    )
    assert is_scan_failure(result)
    assert "invalid scan JSON" in result.detail


def _plan():
    return build_planir_snapshot(
        executed=[],
        pending={"tool": "terminal", "args": {"command": "ls"}},
        run_id="r",
    )


def test_post_scan_oidc_mint_401_does_not_post_scan(monkeypatch) -> None:
    urls: list[str] = []

    def fake_mint(*_a, **_k):
        raise RuntimeError('client_credentials token mint failed: HTTP 401: {"error":"invalid_client"}')

    def fake_http(url, *a, **k):
        urls.append(url)
        return (200, {}, b'{"decision":"allow","block":false}')

    monkeypatch.setattr(scan_client_mod, "build_scan_auth_headers", fake_mint)
    monkeypatch.setattr(scan_client_mod, "_http_request", fake_http)
    result = post_scan(
        "https://example.invalid",
        1000,
        _plan(),
        ScanAuthConfig(api_key=None, oidc=None),
    )
    assert is_scan_failure(result)
    assert result.kind == "http"
    assert result.status == 401
    assert urls == []


def test_post_scan_does_not_spend_scan_timeout_on_mint(monkeypatch) -> None:
    seen: list[float] = []

    def slow_mint(*_a, **_k):
        time.sleep(0.08)
        return {}

    def fake_http(*_a, **k):
        seen.append(float(k.get("timeout_sec") or 0))
        return (200, {}, b'{"decision":"allow","block":false}')

    monkeypatch.setattr(scan_client_mod, "build_scan_auth_headers", slow_mint)
    monkeypatch.setattr(scan_client_mod, "_http_request", fake_http)
    result = post_scan(
        "https://example.invalid",
        20,
        _plan(),
        ScanAuthConfig(api_key="k", oidc=None),
    )
    assert not is_scan_failure(result)
    assert result.scan.decision == "allow"
    assert seen
    assert seen[0] >= 0.015
