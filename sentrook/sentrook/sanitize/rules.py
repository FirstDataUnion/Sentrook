"""Load and compile sanitization rules from ``rules.yaml``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

RULES_PATH = Path(__file__).with_name("rules.yaml")


@dataclass(frozen=True)
class SanitizeRules:
    """Compiled sanitization policy."""

    version: int
    redacted: str
    truncated: str
    result_text_max_chars: int
    intent_max_chars: int
    string_leaf_max_chars: int
    session_hash_prefix: str
    session_hash_hex_chars: int
    credential_field: re.Pattern[str]
    secret_value_patterns: tuple[tuple[str, re.Pattern[str]], ...]
    pii_patterns: tuple[tuple[str, re.Pattern[str]], ...]
    pii_arg_keys: frozenset[str]
    allowed_result_keys: frozenset[str]


def _compile_patterns(
    items: list[dict[str, Any]],
    *,
    flags: int = 0,
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for item in items:
        name = str(item["name"])
        pattern = re.compile(str(item["pattern"]), flags)
        compiled.append((name, pattern))
    return tuple(compiled)


@lru_cache(maxsize=1)
def load_rules(path: Path | None = None) -> SanitizeRules:
    """Load and compile rules from ``rules.yaml`` (cached)."""
    rules_path = path or RULES_PATH
    raw = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Invalid rules file (expected mapping): {rules_path}")

    placeholders = raw.get("placeholders") or {}
    limits = raw.get("limits") or {}
    session_id = raw.get("session_id") or {}

    secret_items = raw.get("secret_value_patterns") or []
    pii_items = raw.get("pii_patterns") or []
    if not isinstance(secret_items, list) or not isinstance(pii_items, list):
        raise ValueError("secret_value_patterns and pii_patterns must be lists")

    return SanitizeRules(
        version=int(raw.get("version", 1)),
        redacted=str(placeholders.get("redacted", "[REDACTED]")),
        truncated=str(placeholders.get("truncated", "[TRUNCATED]")),
        result_text_max_chars=int(limits.get("result_text_max_chars", 500)),
        intent_max_chars=int(limits.get("intent_max_chars", 1000)),
        string_leaf_max_chars=int(limits.get("string_leaf_max_chars", 500)),
        session_hash_prefix=str(session_id.get("hash_prefix", "sess_")),
        session_hash_hex_chars=int(session_id.get("hash_hex_chars", 12)),
        credential_field=re.compile(
            str(raw.get("credential_field_pattern", "")),
            re.IGNORECASE,
        ),
        secret_value_patterns=_compile_patterns(secret_items, flags=re.IGNORECASE),
        pii_patterns=_compile_patterns(pii_items),
        pii_arg_keys=frozenset(str(k) for k in (raw.get("pii_arg_keys") or [])),
        allowed_result_keys=frozenset(
            str(k) for k in (raw.get("allowed_result_keys") or [])
        ),
    )
