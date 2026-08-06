from __future__ import annotations

from unittest.mock import patch

from sentrook.serve.verify import (
    VerifyReport,
    format_verify_text,
    run_scan_verify,
    verify_plugin_runtime,
    verify_sidecar_health,
)


def test_verify_sidecar_health_ok():
    assert verify_sidecar_health({"status": "ok", "rules_loaded": 22, "corpus_examples": 223}) == []


def test_verify_sidecar_health_errors():
    errors = verify_sidecar_health({"status": "degraded", "rules_loaded": 0})
    assert any("status" in e for e in errors)
    assert any("rules_loaded" in e for e in errors)
    assert any("corpus_examples" in e for e in errors)


def test_verify_plugin_runtime_requires_before_tool_call():
    runtime = {
        "status": "loaded",
        "hookCount": 4,
        "typedHooks": [
            {"name": "after_tool_call"},
            {"name": "before_tool_call", "priority": 10},
        ],
    }
    assert verify_plugin_runtime(runtime, plugin_id="sentrook-openclaw") == []

    bad = dict(runtime)
    bad["typedHooks"] = [{"name": "after_tool_call"}]
    errors = verify_plugin_runtime(bad, plugin_id="sentrook-openclaw")
    assert any("before_tool_call" in e for e in errors)


def test_run_scan_verify_sidecar_only():
    health = {"status": "ok", "rules_loaded": 22, "corpus_examples": 10}
    with patch("sentrook.serve.verify.fetch_sidecar_health", return_value=health):
        report = run_scan_verify(url="http://127.0.0.1:9099")
    assert report.ok
    assert report.sidecar_ok
    assert report.plugin_ok is None


def test_run_scan_verify_sidecar_failure():
    with patch(
        "sentrook.serve.verify.fetch_sidecar_health",
        side_effect=OSError("connection refused"),
    ):
        report = run_scan_verify(url="http://127.0.0.1:9099")
    assert not report.ok
    assert not report.sidecar_ok
    assert report.errors


def test_format_verify_text_pass():
    report = VerifyReport(
        sidecar_url="http://sentrook-scan:9099",
        sidecar_ok=True,
        sidecar_health={
            "status": "ok",
            "rules_loaded": 22,
            "corpus_examples": 192,
            "scanner_version": "0.2.0",
        },
        plugin_ok=True,
        plugin_runtime={"hookCount": 4},
        gateway_reachable=True,
    )
    text = format_verify_text(report)
    assert "PASS" in text
    assert "hookCount=4" in text


def test_run_scan_verify_with_openclaw_plugin(tmp_path):
    openclaw_dir = tmp_path / "openclaw"
    openclaw_dir.mkdir()
    (openclaw_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")

    health = {"status": "ok", "rules_loaded": 22, "corpus_examples": 10}
    plugin_runtime = {
        "status": "loaded",
        "hookCount": 4,
        "typedHooks": [{"name": "before_tool_call"}],
    }

    with (
        patch("sentrook.serve.verify.fetch_sidecar_health_via_compose", return_value=health),
        patch("sentrook.serve.verify.gateway_fetch_health", return_value=True),
        patch(
            "sentrook.serve.verify.inspect_openclaw_plugin_runtime",
            return_value=plugin_runtime,
        ),
    ):
        report = run_scan_verify(
            url="http://sentrook-scan:9099",
            openclaw_dir=openclaw_dir,
            sidecar_service="sentrook-scan",
        )

    assert report.ok
    assert report.plugin_ok
    assert report.gateway_reachable


def test_run_scan_verify_missing_compose_project(tmp_path):
    health = {"status": "ok", "rules_loaded": 22, "corpus_examples": 10}
    with patch("sentrook.serve.verify.fetch_sidecar_health_via_compose", return_value=health):
        report = run_scan_verify(
            url="http://sentrook-scan:9099",
            openclaw_dir=tmp_path,
            sidecar_service="sentrook-scan",
        )
    assert not report.ok
    assert report.plugin_ok is False
