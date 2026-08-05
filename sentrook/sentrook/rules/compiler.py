from __future__ import annotations

from typing import Any

from sentrook.rules.models import (
    AllCondition,
    AnyCondition,
    ConditionNode,
    IntentKindCondition,
    NoneCondition,
    OwaspRefs,
    PendingToolCondition,
    Rule,
    RuleMeta,
    SequenceCondition,
    SequenceSlot,
    SequenceWithGapCondition,
)


def _compile_slot(slot: Any) -> SequenceSlot:
    if isinstance(slot, str):
        return SequenceSlot(tool=slot)
    return SequenceSlot(
        tool=str(slot["tool"]),
        status=slot.get("status", "any"),
        args_match=slot.get("args_match"),
        result_flags=slot.get("result_flags"),
    )


def _compile_condition(node: dict[str, Any]) -> ConditionNode:
    if "intent_kind" in node:
        return IntentKindCondition(kind=node["intent_kind"])
    if "pending_tool" in node:
        return PendingToolCondition(tool=str(node["pending_tool"]))
    if "sequence" in node:
        return SequenceCondition(
            steps=[_compile_slot(slot) for slot in node["sequence"]]
        )
    if "sequence_with_gap" in node:
        raw = node["sequence_with_gap"]
        max_gap: int | None = None
        slots_raw: list[Any]
        if isinstance(raw, dict):
            max_gap = raw.get("max_gap")
            slots_raw = raw.get("steps") or raw.get("sequence") or []
        elif isinstance(raw, list):
            slots_raw = raw
        else:
            raise ValueError(f"sequence_with_gap must be a list or mapping, got {raw!r}")

        slots: list[SequenceSlot] = [_compile_slot(slot) for slot in slots_raw]
        return SequenceWithGapCondition(steps=slots, max_gap=max_gap)
    if "all" in node:
        return AllCondition(
            conditions=[_compile_condition(child) for child in node["all"]]
        )
    if "any" in node:
        return AnyCondition(
            conditions=[_compile_condition(child) for child in node["any"]]
        )
    if "none" in node:
        return NoneCondition(condition=_compile_condition(node["none"]))
    raise ValueError(f"Unsupported condition node: {node!r}")


def compile_rule(doc: dict[str, Any], source_path: str | None = None) -> Rule:
    rule_id = str(doc.get("rule") or doc.get("id") or "")
    if not rule_id:
        raise ValueError(f"Rule missing id in {source_path or 'document'}")

    meta_raw = doc.get("meta") or {}
    owasp_raw = meta_raw.get("owasp")
    owasp = None
    if isinstance(owasp_raw, dict):
        owasp = OwaspRefs(
            asi=[str(x) for x in owasp_raw.get("asi", [])],
            llm=[str(x) for x in owasp_raw.get("llm", [])],
        )

    meta = RuleMeta(
        name=str(meta_raw.get("name", rule_id)),
        severity=meta_raw.get("severity", "medium"),
        action=meta_raw.get("action", "block"),
        description=meta_raw.get("description"),
        owasp=owasp,
        authority=meta_raw.get("authority"),
    )

    condition_raw = doc.get("condition")
    if not isinstance(condition_raw, dict):
        raise ValueError(f"Rule {rule_id}: condition must be a mapping")

    return Rule(
        id=rule_id,
        meta=meta,
        condition=_compile_condition(condition_raw),
        raw=doc,
    )
