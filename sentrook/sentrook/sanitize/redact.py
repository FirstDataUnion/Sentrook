"""Lightweight arg redaction for the scan pipeline."""

from sentrook.sanitize.core import redact_args, redact_value

__all__ = ["redact_args", "redact_value"]
