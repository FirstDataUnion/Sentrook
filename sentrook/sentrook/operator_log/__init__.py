"""Local operator log contract (``sentrook.operator.log/v1``).

Host plugins append PlanIR-shaped JSONL. This package is the schema, models,
unbounded secret/PII scrub, and a rebuild helper — not a hosted scan path.
"""

from sentrook.operator_log.models import (
    SCHEMA_VERSION,
    Effect,
    HookAction,
    HookBody,
    LabelSource,
    OperatorLogEvent,
    ResolutionBody,
    ResolutionKind,
    ScanBody,
    ScanErrorBody,
    SkipReason,
    mint_event_id,
)
from sentrook.operator_log.rebuild import rebuild_planir_snapshot
from sentrook.operator_log.scrub import scrub_operator_text, scrub_operator_value

__all__ = [
    "SCHEMA_VERSION",
    "Effect",
    "HookAction",
    "HookBody",
    "LabelSource",
    "OperatorLogEvent",
    "ResolutionBody",
    "ResolutionKind",
    "ScanBody",
    "ScanErrorBody",
    "SkipReason",
    "mint_event_id",
    "rebuild_planir_snapshot",
    "scrub_operator_text",
    "scrub_operator_value",
]
