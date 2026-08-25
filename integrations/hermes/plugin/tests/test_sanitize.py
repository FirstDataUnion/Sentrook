"""Sanitize fixture parity against OpenClaw golden files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ..sanitize import DEFAULT_RULES, hash_session_id, sanitize_planir, sanitize_planir_dict

FIXTURES_DIR = (
    Path(__file__).resolve().parents[3]
    / "openclaw"
    / "plugin"
    / "fixtures"
    / "sanitize"
)


def _assert_subset(actual, expected, label: str = "") -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict), label
        for key, exp_val in expected.items():
            assert key in actual, f"{label}.{key} missing"
            _assert_subset(actual[key], exp_val, f"{label}.{key}" if label else key)
        return
    if isinstance(expected, list):
        assert isinstance(actual, list), label
        assert len(actual) == len(expected), f"{label} length"
        for index, item in enumerate(expected):
            _assert_subset(actual[index], item, f"{label}[{index}]")
        return
    assert actual == expected, label


def _load_fixtures() -> list[tuple[str, dict]]:
    docs: list[tuple[str, dict]] = []
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        docs.append((path.stem, doc))
    return docs


@pytest.mark.parametrize("name,doc", _load_fixtures())
def test_sanitize_fixture_parity(name: str, doc: dict) -> None:
    result = sanitize_planir(doc["input"])
    _assert_subset(result.plan, doc["expected"])


def test_hash_session_id_stable() -> None:
    assert hash_session_id("sess-raw-abc") == "sess_6a6cbcb803b1"


def test_sanitize_planir_dict_does_not_mutate_input() -> None:
    payload = {
        "version": "1.0",
        "run_id": "sess-1:run_1",
        "steps": [
            {
                "id": "s1",
                "tool": "exec",
                "status": "pending",
                "args": {"command": "echo", "api_key": "secret"},
            }
        ],
        "metadata": {"adapter": "openclaw", "hook": "before_tool_call"},
    }
    original = json.loads(json.dumps(payload))
    cleaned = sanitize_planir_dict(payload)
    assert payload == original
    assert cleaned["steps"][0]["args"]["api_key"] == DEFAULT_RULES.redacted
