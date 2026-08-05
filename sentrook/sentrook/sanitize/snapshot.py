"""Sanitize ``sentrook.shadow.snapshot/v1`` payloads before egress or persistence."""

from __future__ import annotations

import hashlib
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sentrook.sanitize.core import (
    is_credential_field,
    scrub_string as _scrub_string,
)
from sentrook.sanitize.rules import SanitizeRules, load_rules

if TYPE_CHECKING:
    from sentrook.shadow.snapshot import ShadowCall, ShadowResult, ShadowSnapshot


@dataclass(frozen=True)
class SanitizeSnapshotResult:
    """Sanitized snapshot plus wall-clock processing time."""

    snapshot: ShadowSnapshot
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


def _sanitize_result(result: dict[str, Any], rules: SanitizeRules) -> dict[str, Any]:
    allowed = rules.allowed_result_keys
    trimmed = {key: value for key, value in result.items() if key in allowed}
    out: dict[str, Any] = {}
    for key, value in trimmed.items():
        if key == "text" and isinstance(value, str):
            out[key] = _scrub_string(
                value,
                rules,
                pii=False,
                max_chars=rules.result_text_max_chars,
                key=key,
            )
        elif key == "command" and isinstance(value, str):
            out[key] = _scrub_string(
                value,
                rules,
                pii=True,
                max_chars=rules.string_leaf_max_chars,
                key=key,
            )
        elif isinstance(value, str):
            out[key] = _scrub_string(
                value,
                rules,
                pii=False,
                max_chars=rules.string_leaf_max_chars,
                key=key,
            )
        else:
            out[key] = value
    return out


def _sanitize_call(call: dict[str, Any], rules: SanitizeRules) -> dict[str, Any]:
    out = dict(call)
    args = call.get("args")
    if isinstance(args, dict):
        out["args"] = _sanitize_mapping(
            args,
            rules,
            pii=False,
            max_chars=rules.string_leaf_max_chars,
            pii_keys=rules.pii_arg_keys,
        )
    result = call.get("result")
    if isinstance(result, dict):
        out["result"] = _sanitize_result(result, rules)
    return out


def _rewrite_run_id(run_id: str, original_session_id: str, hashed_session_id: str) -> str:
    prefix = f"{original_session_id}:"
    if run_id.startswith(prefix):
        return f"{hashed_session_id}:{run_id[len(prefix):]}"
    return run_id


def sanitize_snapshot_dict(
    payload: dict[str, Any],
    rules: SanitizeRules | None = None,
) -> dict[str, Any]:
    """Return a deep-copied, sanitized snapshot dict."""
    rules = rules or load_rules()
    data = deepcopy(payload)

    original_session_id = data.get("session_id")
    if isinstance(original_session_id, str) and original_session_id:
        hashed = hash_session_id(original_session_id, rules)
        data["session_id"] = hashed
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

    executed = data.get("executed")
    if isinstance(executed, list):
        data["executed"] = [_sanitize_call(item, rules) for item in executed if isinstance(item, dict)]

    co_pending = data.get("co_pending")
    if isinstance(co_pending, list):
        data["co_pending"] = [
            _sanitize_call(item, rules) for item in co_pending if isinstance(item, dict)
        ]

    pending = data.get("pending")
    if isinstance(pending, dict):
        data["pending"] = _sanitize_call(pending, rules)

    return data


def sanitize_snapshot(
    snapshot: ShadowSnapshot | dict[str, Any],
    *,
    rules: SanitizeRules | None = None,
) -> SanitizeSnapshotResult:
    """Sanitize a snapshot and return processing time in milliseconds."""
    from sentrook.shadow.snapshot import ShadowSnapshot

    started = time.perf_counter()
    rules = rules or load_rules()

    if isinstance(snapshot, ShadowSnapshot):
        payload = snapshot.model_dump(mode="json", by_alias=True)
        cleaned = sanitize_snapshot_dict(payload, rules)
        result = ShadowSnapshot.model_validate(cleaned)
    else:
        cleaned = sanitize_snapshot_dict(snapshot, rules)
        result = ShadowSnapshot.model_validate(cleaned)

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return SanitizeSnapshotResult(snapshot=result, sanitize_ms=elapsed_ms)


def sanitize_shadow_result(result: ShadowResult, rules: SanitizeRules | None = None) -> ShadowResult:
    """Sanitize a single result object (helper for tests and adapters)."""
    from sentrook.shadow.snapshot import ShadowResult

    rules = rules or load_rules()
    cleaned = _sanitize_result(result.model_dump(mode="json"), rules)
    return ShadowResult.model_validate(cleaned)


def sanitize_shadow_call(call: ShadowCall, rules: SanitizeRules | None = None) -> ShadowCall:
    """Sanitize a single call object (helper for tests)."""
    from sentrook.shadow.snapshot import ShadowCall

    rules = rules or load_rules()
    cleaned = _sanitize_call(call.model_dump(mode="json"), rules)
    return ShadowCall.model_validate(cleaned)
