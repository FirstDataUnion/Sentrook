"""Adapter helpers shared by replay and live hosts.

The functions here are agent-agnostic: they assemble PlanIR snapshots and result
summaries from already-normalized inputs. Host-specific parsing (OpenClaw session
JSONL, live hook events, etc.) lives in the per-host adapters that call into these
helpers, so every host produces byte-identical PlanIR for the same trajectory.
"""

from sentrook.adapters.snapshot import (
    SnapshotCall,
    build_planir_snapshot,
    build_result_summary,
    make_plan_step,
)

__all__ = [
    "SnapshotCall",
    "build_planir_snapshot",
    "build_result_summary",
    "make_plan_step",
]
