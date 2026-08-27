"""Mocked /feedback wire-shape tests (no Rookery)."""

from __future__ import annotations

import json
import logging

from .. import scan_client as scan_client_mod
from ..auth import ScanAuthConfig
from ..planir import SnapshotCall, build_planir_snapshot, planir_to_dict
from ..scan_client import post_feedback
from ..sanitize import sanitize_planir_dict


def test_post_feedback_sends_expected_wire_body(monkeypatch) -> None:
    captured: dict = {}

    def fake_http(url, method="GET", headers=None, body=None, timeout_sec=10.0):
        captured["url"] = url
        captured["method"] = method
        captured["headers"] = headers or {}
        captured["body"] = json.loads(body.decode("utf-8")) if body else None
        return 200, {}, json.dumps({"status": "skipped", "reason": "feedback disabled"}).encode()

    monkeypatch.setattr(scan_client_mod, "_http_request", fake_http)
    monkeypatch.setattr(
        scan_client_mod,
        "build_scan_auth_headers",
        lambda auth: {"Authorization": "Bearer test"},
    )

    plan = build_planir_snapshot(
        executed=[],
        pending=SnapshotCall(
            tool="terminal",
            args={"command": "getent hosts telegram.webhook; echo test"},
        ),
        run_id="sess:run_1",
        intent_kind="user",
        session_id="sess",
        tool_call_id="tc-1",
        step_seq=1,
    )
    sanitized = sanitize_planir_dict(planir_to_dict(plan))

    post_feedback(
        "https://dev.sentrook.example",
        ScanAuthConfig(api_key="k", oidc=None),
        plan=sanitized,
        resolution="allow-once",
        log={"matched_rules": ["AIRA-010"]},
        provenance={
            "adapter": "hermes",
            "rule_key": "sentrook:exec:abc",
            "hermes_choice": "once",
        },
    )

    assert captured["method"] == "POST"
    assert captured["url"].endswith("/feedback")
    body = captured["body"]
    assert body["resolution"] == "allow-once"
    assert body["provenance"]["adapter"] == "hermes"
    assert body["provenance"]["hermes_choice"] == "once"
    assert isinstance(body["plan"], dict)
    assert body["plan"].get("version") == "1.0"
    steps = body["plan"].get("steps") or []
    assert any(s.get("tool") == "exec" for s in steps)


def test_post_feedback_warns_on_host_skipped(monkeypatch, caplog) -> None:
    monkeypatch.setattr(
        scan_client_mod,
        "_http_request",
        lambda *a, **k: (
            200,
            {},
            json.dumps({"status": "skipped", "reason": "feedback disabled"}).encode(),
        ),
    )
    monkeypatch.setattr(scan_client_mod, "build_scan_auth_headers", lambda auth: {})

    with caplog.at_level(logging.WARNING, logger="sentrook"):
        post_feedback(
            "https://dev.sentrook.example",
            ScanAuthConfig(api_key="k", oidc=None),
            plan={"schema": "planir", "version": "1.0", "steps": []},
            resolution="deny",
        )

    assert any("feedback disabled" in r.message for r in caplog.records)
