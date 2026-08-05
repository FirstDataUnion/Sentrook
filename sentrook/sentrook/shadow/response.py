"""Build HTTP scan responses for shadow vs enforce mode."""

from __future__ import annotations

from typing import Any

from sentrook.result import ScanResult
from sentrook.shadow.config import ShadowConfig
from sentrook.shadow.log import ShadowLogRecord
from sentrook.shadow.review_copy import (
    build_block_reason,
    build_review_description,
    build_review_title,
)


def _review_severity(result: ScanResult) -> str:
    if not result.matched_rules:
        return "warning"
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    worst = max(result.matched_rules, key=lambda m: order.get(m.severity, 1))
    if worst.severity in ("high", "critical"):
        return "critical"
    if worst.severity == "medium":
        return "warning"
    return "info"


def build_scan_response(
    config: ShadowConfig,
    result: ScanResult,
    record: ShadowLogRecord,
    *,
    error: str | None = None,
    request_ms: int | None = None,
) -> dict[str, Any]:
    """Shape the ``POST /scan`` JSON body for the OpenClaw plugin."""
    decision = result.decision
    enforce = config.mode == "enforce"
    block = enforce and decision == "block" and error is None

    payload: dict[str, Any] = {
        "block": block,
        "decision": decision,
        "risk": result.risk,
        "summary": result.summary,
        "pending_tool": result.plan.pending_tool,
        "matched_rules": [m.id for m in result.matched_rules],
        "log": record.model_dump(mode="json"),
        "timing": {
            "engine_ms": result.timing.total_ms,
            "request_ms": request_ms,
        },
    }
    if error:
        payload["error"] = error
        payload["block"] = False
        payload["decision"] = "allow"
        return payload

    if block:
        payload["block_reason"] = build_block_reason(record, result)
    if decision == "review":
        payload["review_title"] = build_review_title(record, result)
        payload["review_description"] = build_review_description(record, result)
        payload["review_severity"] = _review_severity(result)
    return payload
