"""Shadow-mode live scanning: observe-only ``before_tool_call`` gating.

This package exposes a host-agnostic shadow scanning surface. A host (e.g. an
OpenClaw plugin) sends a normalized snapshot (``sentrook.shadow.snapshot/v1``) of
the executed trajectory plus the pending tool call; Sentrook scans it, appends a
structured log line, and returns the decision *without ever blocking* the host.

The HTTP daemon (:mod:`sentrook.shadow.server`) keeps the Layer 3 scorer, rules,
and corpus warm so per-call latency stays low; the same pipeline is reachable as
a single-shot library/CLI call for debugging and replay-parity checks.
"""

from sentrook.shadow.config import ShadowConfig
from sentrook.shadow.log import ShadowLogRecord, append_shadow_log, build_log_record
from sentrook.shadow.service import ShadowScanner
from sentrook.shadow.snapshot import ShadowCall, ShadowResult, ShadowSnapshot

__all__ = [
    "ShadowConfig",
    "ShadowScanner",
    "ShadowSnapshot",
    "ShadowCall",
    "ShadowResult",
    "ShadowLogRecord",
    "append_shadow_log",
    "build_log_record",
]
