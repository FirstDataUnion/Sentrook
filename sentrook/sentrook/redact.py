"""Backward-compatible re-exports; implementation in ``sentrook.sanitize.core``."""

from __future__ import annotations

from sentrook.sanitize.core import redact_args, redact_value

__all__ = ["redact_args", "redact_value"]
