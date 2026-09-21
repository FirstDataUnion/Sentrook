"""Build HTTP scan responses for observe vs enforce mode."""

from __future__ import annotations

from typing import Any

from sentrook.result import ScanResult
from sentrook.serve.config import ServeConfig
from sentrook.serve.log import ScanLogRecord
from sentrook.serve.review_copy import (
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


def _review_authority(result: ScanResult, authority_by_rule_id: dict[str, str] | None) -> str:
    """`hard` when any surviving review is hard-authority, else `soft`.

    This exists because `authority` was, until now, invisible to the only
    component that can act on it. Three places in the codebase stated that
    "hard authority exists so an operator's lenient floor cannot waive a rule"
    and none of them was true: the floor is applied in the plugin, keyed on
    `review_severity`, which is derived from `meta.severity` alone. Authority
    governed L3 downgrade and allow-rule suppression and nothing else, so a
    hard review was waived by a lenient floor exactly like a soft one.

    Aggregated with `any`, not `worst`, and defaulting to `hard` for a rule the
    server cannot resolve: an unwaivable review costs a prompt, a wrongly
    waivable one costs the detection. `block` rules are excluded because a
    block is not waivable by this path at all.
    """
    mapping = authority_by_rule_id or {}
    for matched in result.matched_rules:
        if matched.action != "review":
            continue
        if mapping.get(matched.id, "hard") == "hard":
            return "hard"
    return "soft"


def build_scan_response(
    config: ServeConfig,
    result: ScanResult,
    record: ScanLogRecord,
    *,
    error: str | None = None,
    request_ms: int | None = None,
    authority_by_rule_id: dict[str, str] | None = None,
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
        payload["review_authority"] = _review_authority(result, authority_by_rule_id)
    return payload
