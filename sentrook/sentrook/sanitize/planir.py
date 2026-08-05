"""Sanitize PlanIR 1.0 payloads before egress or persistence."""

from __future__ import annotations

import hashlib
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from sentrook.planir import PlanIR
from sentrook.sanitize.core import (
    is_credential_field,
    scrub_string as _scrub_string,
)
from sentrook.sanitize.rules import SanitizeRules, load_rules


@dataclass(frozen=True)
class SanitizePlanIRResult:
    """Sanitized PlanIR plus wall-clock processing time."""

    plan: PlanIR
    sanitize_ms: int


def hash_session_id(session_id: str, rules: SanitizeRules) -> str:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"{rules.session_hash_prefix}{digest[: rules.session_hash_hex_chars]}"


def _sanitize_value(
    value: Any,
    rules: SanitizeRules,
    *,
    parent_key: str | None,
    pii: bool,
    max_chars: int,
) -> Any:
    if parent_key is not None and is_credential_field(parent_key, rules):
        return rules.redacted

    if isinstance(value, str):
        return _scrub_string(
            value, rules, pii=pii, max_chars=max_chars, key=parent_key
        )
    if isinstance(value, dict):
        return _sanitize_mapping(value, rules, pii=False, max_chars=max_chars)
    if isinstance(value, list):
        return [
            _sanitize_value(item, rules, parent_key=None, pii=False, max_chars=max_chars)
            for item in value
        ]
    return value


def _sanitize_mapping(
    mapping: dict[str, Any],
    rules: SanitizeRules,
    *,
    pii: bool,
    max_chars: int,
    pii_keys: frozenset[str] | None = None,
) -> dict[str, Any]:
    pii_keys = pii_keys or frozenset()
    out: dict[str, Any] = {}
    for key, value in mapping.items():
        key_pii = pii or key in pii_keys
        out[key] = _sanitize_value(
            value,
            rules,
            parent_key=key,
            pii=key_pii,
            max_chars=max_chars,
        )
    return out


def _sanitize_result_summary(
    summary: dict[str, Any], rules: SanitizeRules
) -> dict[str, Any]:
    out = dict(summary)
    excerpt = summary.get("excerpt")
    if isinstance(excerpt, str):
        out["excerpt"] = _scrub_string(
            excerpt,
            rules,
            pii=False,
            max_chars=rules.result_text_max_chars,
            key="excerpt",
        )
    extracted = summary.get("extracted")
    if isinstance(extracted, dict):
        cleaned_extracted: dict[str, Any] = {}
        for key, value in extracted.items():
            if key == "commands" and isinstance(value, list):
                cleaned_extracted[key] = [
                    _scrub_string(
                        str(item),
                        rules,
                        pii=True,
                        max_chars=rules.string_leaf_max_chars,
                        key="command",
                    )
                    if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                cleaned_extracted[key] = value
        out["extracted"] = cleaned_extracted
    return out


def _sanitize_step(step: dict[str, Any], rules: SanitizeRules) -> dict[str, Any]:
    out = dict(step)
    args = step.get("args")
    if isinstance(args, dict):
        out["args"] = _sanitize_mapping(
            args,
            rules,
            pii=False,
            max_chars=rules.string_leaf_max_chars,
            pii_keys=rules.pii_arg_keys,
        )
    result_summary = step.get("result_summary")
    if isinstance(result_summary, dict):
        out["result_summary"] = _sanitize_result_summary(result_summary, rules)
    return out


def _rewrite_run_id(run_id: str, original_session_id: str, hashed_session_id: str) -> str:
    prefix = f"{original_session_id}:"
    if run_id.startswith(prefix):
        return f"{hashed_session_id}:{run_id[len(prefix):]}"
    return run_id


def sanitize_planir_dict(
    payload: dict[str, Any],
    rules: SanitizeRules | None = None,
) -> dict[str, Any]:
    """Return a deep-copied, sanitized PlanIR dict."""
    rules = rules or load_rules()
    data = deepcopy(payload)

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        data["metadata"] = metadata

    original_session_id = metadata.get("session_id")
    if isinstance(original_session_id, str) and original_session_id:
        hashed = hash_session_id(original_session_id, rules)
        metadata["session_id"] = hashed
        run_id = data.get("run_id")
        if isinstance(run_id, str):
            data["run_id"] = _rewrite_run_id(run_id, original_session_id, hashed)

    intent = data.get("intent")
    if isinstance(intent, str):
        data["intent"] = _scrub_string(
            intent,
            rules,
            pii=True,
            max_chars=rules.intent_max_chars,
        )

    steps = data.get("steps")
    if isinstance(steps, list):
        data["steps"] = [
            _sanitize_step(item, rules) for item in steps if isinstance(item, dict)
        ]

    return data


def sanitize_planir(
    plan: PlanIR | dict[str, Any],
    *,
    rules: SanitizeRules | None = None,
) -> SanitizePlanIRResult:
    """Sanitize a PlanIR body and return processing time in milliseconds."""
    started = time.perf_counter()
    rules = rules or load_rules()

    if isinstance(plan, PlanIR):
        payload = plan.model_dump(mode="json")
        cleaned = sanitize_planir_dict(payload, rules)
        result = PlanIR.model_validate(cleaned)
    else:
        cleaned = sanitize_planir_dict(plan, rules)
        result = PlanIR.model_validate(cleaned)

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return SanitizePlanIRResult(plan=result, sanitize_ms=elapsed_ms)
