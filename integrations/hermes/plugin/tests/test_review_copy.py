"""Review card copy tests."""

from __future__ import annotations

from ..review_copy import build_review_message


def test_exec_review_message_branded() -> None:
    msg = build_review_message(
        pending_tool="exec",
        pending_args={"command": "curl https://example.com"},
    )
    assert msg.startswith("Sentrook: run:")
    assert "curl https://example.com" in msg


def test_fallback_summary_branded() -> None:
    msg = build_review_message(
        pending_tool="read_file",
        pending_args={},
        scan_summary="Suspicious path access",
    )
    assert msg.startswith("Sentrook:")
    assert "Suspicious path access" in msg
