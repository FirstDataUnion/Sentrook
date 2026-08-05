"""Observe-mode live scanning: ``before_tool_call`` gating via the serve sidecar.

This package exposes a host-agnostic scan surface. A host (e.g. an OpenClaw
plugin) sends PlanIR 1.0 (``version: \"1.0\"``) for the executed trajectory plus
the pending tool call; Sentrook scans it, appends a structured scan log line,
and returns the decision. In observe mode the host is never blocked; enforce
mode may block when configured.

The HTTP daemon (:mod:`sentrook.serve.server`) keeps the Layer 3 scorer, rules,
and corpus warm so per-call latency stays low; the same pipeline is reachable as
a single-shot library/CLI call for debugging and replay-parity checks.
"""

from sentrook.serve.config import ServeConfig
from sentrook.serve.log import ScanLogRecord, append_scan_log, build_log_record
from sentrook.serve.service import ScanService

__all__ = [
    "ServeConfig",
    "ScanService",
    "ScanLogRecord",
    "append_scan_log",
    "build_log_record",
]
