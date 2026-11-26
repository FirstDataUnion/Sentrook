"""Context limits for evaluation runs: a request cut down as if the plugin had sent less, in test mode only."""

from __future__ import annotations

import copy
from datetime import UTC, datetime

import pytest
from test_jev_probes import ATTACK_ANSWERS, FakeDecider

from sentrook.enums import ScanStatus
from sentrook.prepare.context_limits import (
    NO_LIMITS,
    ContextLimits,
    apply_context_limits,
    cap_head_tail,
)
from sentrook.scan import Scanner, ScannerConfig, ScanOptions
from sentrook.serve.config import ConfigError, ServeConfig
from sentrook.serve.runtime import ServeRuntime

KEY = "unit-test-state-key-" * 2
CLOCK = datetime(2026, 10, 5, 10, 28, tzinfo=UTC)


def _step(n: int) -> dict:
    return {
        "step": n,
        "turn": 1,
        "call_id": f"h_{n}",
        "tool": "read",
        "tool_kind": "file_read",
        "arguments": {"path": f"/work/notes-{n}.md"},
        "result": {"status": "ok", "size_bytes": 10},
        "decision": "allowed",
    }


def _result(seq: int, call: int, content: str) -> dict:
    return {
        "input_seq": seq,
        "kind": "tool_result",
        "call_id": f"h_{call}",
        "tool": "read",
        "tool_kind": "file_read",
        "status": "ok",
        "content_type": "text",
        "content": content,
        "size_bytes": len(content.encode("utf-8")),
        "truncated": False,
    }


def long_request(attack_case: dict, steps: int = 6) -> dict:
    """The worked attack with `steps` earlier reads, each with its result among the new inputs."""
    raw = copy.deepcopy(attack_case["fixture"])
    raw["history"] = [_step(n) for n in range(1, steps + 1)]
    raw["new_inputs"] = [_result(n, n, f"line {n}\n" * 200) for n in range(1, steps + 1)]
    raw["session"]["step"] = steps + 1
    return raw


def save_request(attack_case: dict) -> dict:
    raw = copy.deepcopy(attack_case["fixture"])
    raw["self_edit"] = {
        "kind": "background_review",
        "store": "memory",
        "conversation": [
            {
                "role": "user",
                "turn": 1,
                "text": "please remember my sister's birthday",
                "chars": 36,
            },
            {"role": "assistant", "turn": 1, "text": "Noted.", "chars": 6},
            {"role": "tool", "turn": 1, "tool": "read", "arguments": {}, "content": "é" * 2000},
        ],
    }
    return raw


# ---------------------------------------------------------------- the cut itself


def test_no_limits_is_the_request_itself(attack_case):
    raw = attack_case["fixture"]
    assert NO_LIMITS.unlimited and apply_context_limits(raw, NO_LIMITS) is raw


def test_cap_head_tail_matches_the_plugins_cut():
    text = "a" * 600 + "b" * 400
    cut, was_cut = cap_head_tail(text, 300)
    marker = "\n…[sentrook: 700 bytes cut]…\n"
    budget = 300 - len(marker.encode())
    assert was_cut and cut == "a" * (budget * 2 // 3) + marker + "b" * (budget - budget * 2 // 3)
    assert len(cut.encode()) <= 300
    assert cap_head_tail("short", 300) == ("short", False)


def test_input_cap_cuts_each_input_head_and_tail(attack_case):
    raw = long_request(attack_case)
    out = apply_context_limits(raw, ContextLimits(input_cap_bytes=512))
    for before, after in zip(raw["new_inputs"], out["new_inputs"], strict=True):
        assert len(after["content"].encode()) <= 512 and "bytes cut]" in after["content"]
        assert after["truncated"] is True and after["size_bytes"] == before["size_bytes"]
        assert after["content"].startswith(before["content"][:100])
        assert after["content"].endswith(before["content"][-50:])
    assert raw == long_request(attack_case)  # never mutates


def test_input_cap_leaves_short_inputs_and_the_pending_call(attack_case):
    raw = copy.deepcopy(attack_case["fixture"])
    raw["pending_call"]["arguments"]["padding"] = "x" * 5000
    out = apply_context_limits(raw, ContextLimits(input_cap_bytes=4096))
    assert out["new_inputs"] == raw["new_inputs"]
    assert out["pending_call"] == raw["pending_call"]


def test_history_window_keeps_the_last_steps_and_their_results(attack_case):
    raw = long_request(attack_case, steps=6)
    out = apply_context_limits(raw, ContextLimits(history_steps=2))
    assert [h["step"] for h in out["history"]] == [5, 6]
    assert [i["call_id"] for i in out["new_inputs"]] == ["h_5", "h_6"]


def test_history_window_keeps_inputs_that_are_not_tool_results(attack_case):
    raw = long_request(attack_case, steps=4)
    raw["new_inputs"].append(
        {"input_seq": 9, "kind": "message", "content": "hi", "channel": "discord"}
    )
    out = apply_context_limits(raw, ContextLimits(history_steps=1))
    assert [i.get("call_id") for i in out["new_inputs"]] == ["h_4", None]


def test_dropping_bodies_keeps_the_shape_of_the_conversation(attack_case):
    raw = save_request(attack_case)
    out = apply_context_limits(raw, ContextLimits(self_edit_bodies=False))
    conv = out["self_edit"]["conversation"]
    assert [e["role"] for e in conv] == ["user", "assistant", "tool"]
    assert all("text" not in e and e["truncated"] is True for e in conv[:2])
    assert conv[0]["chars"] == 36 and conv[2] == raw["self_edit"]["conversation"][2]


def test_input_cap_bounds_tool_results_in_a_saves_conversation(attack_case):
    out = apply_context_limits(save_request(attack_case), ContextLimits(input_cap_bytes=1024))
    tool = out["self_edit"]["conversation"][2]
    assert len(tool["content"].encode()) <= 1024 and tool["truncated"] is True
    assert out["self_edit"]["conversation"][0]["text"].startswith("please")


@pytest.mark.parametrize("kwargs", [{"input_cap_bytes": 100}, {"history_steps": 0}])
def test_limits_out_of_range_are_refused(kwargs):
    with pytest.raises(ValueError):
        ContextLimits(**kwargs)


# ---------------------------------------------------------------- in a scan


def _scan(raw: dict, limits: ContextLimits, case: dict) -> tuple:
    decider = FakeDecider(ATTACK_ANSWERS)
    scanner = Scanner(ScannerConfig(token_key=KEY, decider=decider, context_limits=limits))
    res = scanner.scan(
        raw,
        ScanOptions(
            deterministic=True,
            clock=CLOCK,
            salt="testnest",
            state_seed=case["state_seed"],
            oracle_seed=case["oracle_seed"],
        ),
    )
    return res, decider


def _sent_inputs(decider: FakeDecider) -> list[dict]:
    return [i for b in decider.bodies for i in b["state"].get("new_inputs") or []]


def test_a_limited_scan_sends_the_judge_only_what_is_left(attack_case):
    raw = long_request(attack_case, steps=6)
    res, decider = _scan(raw, ContextLimits(input_cap_bytes=512, history_steps=2), attack_case)
    # a cut input is reported as it would be from a plugin: the scan is degraded, never an error
    assert res.response.status is ScanStatus.DEGRADED
    assert all(e.status.value == "ok" for e in res.envelopes)
    sent = _sent_inputs(decider)
    assert sent and {i["input_seq"] for i in sent} <= {5, 6}
    assert all(len(i["content"].encode()) <= 512 for i in sent)
    assert all(len(b["state"].get("history") or []) <= 2 for b in decider.bodies)


def test_a_shorter_history_alone_is_still_a_whole_scan(attack_case):
    res, decider = _scan(
        long_request(attack_case, steps=6), ContextLimits(history_steps=3), attack_case
    )
    assert res.response.status is ScanStatus.OK
    assert {i["input_seq"] for i in _sent_inputs(decider)} == {4, 5, 6}


def test_an_unlimited_scan_is_unchanged(attack_case):
    raw = long_request(attack_case, steps=6)
    plain, d1 = _scan(raw, NO_LIMITS, attack_case)
    again, d2 = _scan(raw, ContextLimits(), attack_case)
    assert plain.response.status is ScanStatus.OK
    assert d1.bodies == d2.bodies and plain.response.risk == again.response.risk
    assert {i["input_seq"] for i in _sent_inputs(d1)} == set(range(1, 7))


# ---------------------------------------------------------------- configuration


def test_limits_from_the_environment_in_test_mode():
    cfg = ServeConfig.from_env(
        {
            "SENTROOK_TEST_MODE": "1",
            "SENTROOK_EVAL_INPUT_CAP_BYTES": "4096",
            "SENTROOK_EVAL_HISTORY_STEPS": "5",
            "SENTROOK_EVAL_SELF_EDIT_BODIES": "drop",
        }
    )
    assert cfg.context_limits == ContextLimits(4096, 5, False)
    rt = ServeRuntime.build(cfg)
    assert rt.scanner.config.context_limits == cfg.context_limits
    assert rt.health_payload()["context_limits"] == {
        "input_cap_bytes": 4096,
        "history_steps": 5,
        "self_edit_bodies": "drop",
    }


def test_no_limits_by_default_and_no_health_key():
    cfg = ServeConfig.from_env({"SENTROOK_TEST_MODE": "1"})
    assert cfg.context_limits.unlimited
    assert "context_limits" not in ServeRuntime.build(cfg).health_payload()


@pytest.mark.parametrize(
    "env",
    [
        {"SENTROOK_EVAL_INPUT_CAP_BYTES": "4096"},
        {"SENTROOK_EVAL_HISTORY_STEPS": "5"},
        {"SENTROOK_EVAL_SELF_EDIT_BODIES": "drop"},
    ],
)
def test_limits_need_test_mode(env):
    with pytest.raises(ConfigError, match="SENTROOK_TEST_MODE"):
        ServeConfig.from_env(env)


@pytest.mark.parametrize(
    "env",
    [
        {"SENTROOK_EVAL_INPUT_CAP_BYTES": "4k"},
        {"SENTROOK_EVAL_INPUT_CAP_BYTES": "10"},
        {"SENTROOK_EVAL_HISTORY_STEPS": "0"},
        {"SENTROOK_EVAL_SELF_EDIT_BODIES": "maybe"},
    ],
)
def test_bad_limits_are_refused_not_defaulted(env):
    with pytest.raises(ConfigError):
        ServeConfig.from_env({"SENTROOK_TEST_MODE": "1", **env})
