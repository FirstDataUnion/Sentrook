"""Operator-facing review copy for Hermes approve directives."""

from __future__ import annotations

from typing import Any

from .planir import EXEC_TOOLS
from .sanitize import pack_signal_excerpt, scrub_secrets

REVIEW_MESSAGE_MAX = 256
TRUNCATED_TOKEN = "[TRUNCATED]"


def pending_display_command(args: dict[str, Any] | None) -> str | None:
    if not args:
        return None
    for key in ("command", "cmd"):
        value = args.get(key)
        if not isinstance(value, str):
            continue
        text = value.strip()
        if text and text != TRUNCATED_TOKEN:
            return text
    return None


def _clip(text: str, limit: int) -> str:
    trimmed = text.strip()
    if len(trimmed) <= limit:
        return trimmed
    if limit <= 3:
        return trimmed[:limit]
    return f"{trimmed[: limit - 3]}..."


def build_review_message(
    *,
    pending_tool: str,
    pending_args: dict[str, Any] | None = None,
    scan_summary: str | None = None,
    scan_description: str | None = None,
) -> str:
    """Build Hermes ``message`` from local pending args (scrubbed excerpt).

    The host shows ``<tool> (plugin approval rule)`` as the card title; this
    string is the operator-facing reason body. Prefix with ``Sentrook:`` so
    Discord cards are distinguishable from Hermes native approvals.
    """
    local_command = pending_display_command(pending_args)
    if local_command:
        scrubbed = scrub_secrets(local_command)
        # Leave room for "Sentrook: run: " prefix.
        excerpt = pack_signal_excerpt(scrubbed, REVIEW_MESSAGE_MAX - 28)
        if pending_tool in EXEC_TOOLS:
            return _clip(f"Sentrook: run: {excerpt}", REVIEW_MESSAGE_MAX)
        return _clip(f"Sentrook: {pending_tool}: {excerpt}", REVIEW_MESSAGE_MAX)

    for candidate in (scan_description, scan_summary):
        if isinstance(candidate, str) and candidate.strip():
            body = candidate.strip()
            if not body.lower().startswith("sentrook"):
                body = f"Sentrook: {body}"
            return _clip(body, REVIEW_MESSAGE_MAX)

    return _clip(
        scan_summary or "Sentrook flagged this tool call for human review",
        REVIEW_MESSAGE_MAX,
    )
