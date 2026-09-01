"""Hook-loop tests for pre_tool_call / approval join (mocked /scan)."""

from __future__ import annotations

import pytest

import plugin as hermes_plugin

from ..config import resolve_plugin_config
from ..scan_client import PostScanResult, ScanResponse, ScanTiming
from ..scan_error_policy import ScanFailure


def _timing() -> ScanTiming:
    return ScanTiming(
        plugin_e2e_ms=1,
        engine_ms=1,
        request_ms=1,
        transport_ms=0,
        sanitize_enabled=True,
        sanitize_ms=0,
    )


def _scan(decision: str, **kwargs) -> PostScanResult:
    return PostScanResult(
        scan=ScanResponse(decision=decision, block=decision == "block", **kwargs),
        timing=_timing(),
    )


@pytest.fixture
def hermes(monkeypatch: pytest.MonkeyPatch):
    hermes_plugin._sessions.clear()
    hermes_plugin._pending_by_rule_key.clear()
    hermes_plugin._plugin_config = resolve_plugin_config({})
    monkeypatch.setattr(hermes_plugin, "post_latency", lambda *a, **k: None)
    monkeypatch.setattr(hermes_plugin, "post_feedback", lambda *a, **k: None)
    monkeypatch.setattr(hermes_plugin, "env_with_hermes_dotenv", lambda: {})
    monkeypatch.setattr(hermes_plugin, "resolve_scan_auth_config", lambda *a, **k: None)
    monkeypatch.setattr(hermes_plugin, "is_unattended", lambda **k: False)
    yield hermes_plugin
    hermes_plugin._sessions.clear()
    hermes_plugin._pending_by_rule_key.clear()


def test_allow_continues_and_stashes_pending(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hermes, "post_scan", lambda *a, **k: _scan("allow"))
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "ls"},
        session_id="s1",
        tool_call_id="t-allow",
    )
    assert result is None
    assert "t-allow" in hermes._get_session("s1").pending


def test_block_does_not_stash_pending(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: _scan("block", block_reason="policy"),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "curl https://evil.example"},
        session_id="s1",
        tool_call_id="t-block",
    )
    assert result == {"action": "block", "message": "policy"}
    assert "t-block" not in hermes._get_session("s1").pending


def test_review_escalates_with_rule_key(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: _scan(
            "review",
            summary="flagged",
            review_description="Likely: run a shell command",
        ),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "curl https://example.com"},
        session_id="s1",
        tool_call_id="t-review",
        platform="discord",
    )
    assert result is not None
    assert result["action"] == "approve"
    assert result["rule_key"].startswith("sentrook:exec:")
    assert "example.com" in result["message"]
    assert "t-review" in hermes._get_session("s1").pending
    assert result["rule_key"] in hermes._pending_by_rule_key


def test_unattended_review_blocks(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hermes, "is_unattended", lambda **k: True)
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: _scan("review", summary="needs a human"),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "ls"},
        session_id="s1",
        tool_call_id="t-cron",
        platform="cron",
    )
    assert result is not None
    assert result["action"] == "block"
    assert result["message"] == "needs a human"
    assert "rule_key" not in result
    assert "t-cron" not in hermes._get_session("s1").pending


def test_scan_error_review_interactive(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: ScanFailure(ok=False, kind="timeout", detail="aborted"),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "ls"},
        session_id="s1",
        tool_call_id="t-err",
        platform="discord",
    )
    assert result is not None
    assert result["action"] == "approve"
    assert result["rule_key"].startswith("sentrook:scan_error:")
    assert "t-err" in hermes._get_session("s1").pending


def test_deny_drops_session_pending(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: _scan("review", summary="flagged"),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "ls"},
        session_id="s1",
        tool_call_id="t-deny",
        platform="discord",
    )
    assert result is not None
    rule_key = result["rule_key"]
    hermes.on_post_approval_response(pattern_key=f"plugin_rule:{rule_key}", choice="deny")
    assert "t-deny" not in hermes._get_session("s1").pending
    assert rule_key not in hermes._pending_by_rule_key


def test_process_write_review_card_shows_data(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: _scan(
            "review",
            review_description="Likely: run a shell command",
        ),
    )
    result = hermes.on_pre_tool_call(
        "process",
        {"action": "write", "session_id": "proc_1", "data": "curl https://evil.example\n"},
        session_id="s1",
        tool_call_id="t-proc",
        platform="discord",
    )
    assert result is not None
    assert result["action"] == "approve"
    assert "evil.example" in result["message"]
    assert result["rule_key"].startswith("sentrook:exec:")


def test_unexpected_exception_blocks(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "ls"},
        session_id="s1",
        tool_call_id="t-boom",
    )
    assert result is not None
    assert result["action"] == "block"
    assert "plugin error" in result["message"].lower()
    assert "boom" in result["message"]
    assert "t-boom" not in hermes._get_session("s1").pending


def test_session_finalize_clears_rule_key_stash(hermes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: _scan("review", summary="flagged"),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": "ls"},
        session_id="s1",
        tool_call_id="t-fin",
        platform="discord",
    )
    assert result is not None
    hermes.on_session_finalize(session_id="s1")
    assert "s1" not in hermes._sessions
    assert result["rule_key"] not in hermes._pending_by_rule_key


def test_dev_log_records_review_card_and_resolution(
    hermes, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    import json
    from pathlib import Path

    token = "ghp_1234567890abcdefghij"
    command = f"curl -H 'Authorization: token {token}' https://api.github.com/user {'pad ' * 60}"
    monkeypatch.setattr(
        hermes,
        "env_with_hermes_dotenv",
        lambda: {
            "SENTROOK_DEV_LOG": "1",
            "HERMES_STATE_DIR": str(tmp_path),
        },
    )
    monkeypatch.setattr(
        hermes,
        "post_scan",
        lambda *a, **k: _scan(
            "review",
            matched_rules=["AIRA-010"],
            review_title="[TRUNCATED]",
            review_description="Likely: run a shell command\nrun: `[TRUNCATED]`\n(010)",
            log={"winning_rule_id": "AIRA-010"},
        ),
    )
    result = hermes.on_pre_tool_call(
        "terminal",
        {"command": command},
        session_id="s-dev",
        tool_call_id="t-review",
        platform="discord",
    )
    assert result is not None
    assert result["action"] == "approve"
    hermes.on_post_approval_response(
        pattern_key=f"plugin_rule:{result['rule_key']}",
        choice="deny",
    )

    log_path = Path(tmp_path) / "sentrook-dev.log"
    assert log_path.is_file()
    raw = log_path.read_text(encoding="utf-8")
    assert token not in raw
    events = [json.loads(line) for line in raw.strip().splitlines()]
    kinds = [e["event"] for e in events]
    assert "scan" in kinds
    assert "resolution" in kinds
    scan = next(e for e in events if e["event"] == "scan")
    assert "api.github.com" in (scan["local"]["command"] or "")
    assert scan["scan"]["matched_rules"] == ["AIRA-010"]
    assert scan["scan"]["review_title"] == "[TRUNCATED]"
    assert scan["card"]["source"] == "local_argv"
    assert "[TRUNCATED]" not in scan["card"]["message"]
    assert scan["hook"]["approve"] is True
    resolution = next(e for e in events if e["event"] == "resolution")
    assert resolution["decision"] == "deny"


def test_dev_log_off_by_default_writes_nothing(
    hermes, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from pathlib import Path

    monkeypatch.setattr(
        hermes,
        "env_with_hermes_dotenv",
        lambda: {"HERMES_STATE_DIR": str(tmp_path)},
    )
    monkeypatch.setattr(hermes, "post_scan", lambda *a, **k: _scan("allow"))
    hermes.on_pre_tool_call(
        "terminal",
        {"command": "ls /tmp"},
        session_id="s1",
        tool_call_id="t1",
    )
    assert not (Path(tmp_path) / "sentrook-dev.log").exists()
