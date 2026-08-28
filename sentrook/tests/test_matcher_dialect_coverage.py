"""High-coverage YAIRA dialect regression tests (pipe-OR, key-OR, MCP globs)."""

from __future__ import annotations

import pytest

from sentrook.config import MatcherConfig
from sentrook.layers.l1_index import build_l1_index, l1_candidates
from sentrook.layers.l2_match import _args_match, evaluate_rule
from sentrook.layers.tool_pattern import (
    InvalidToolPatternError,
    tool_pattern_matches,
    validate_tool_pattern,
)
from sentrook.planir import PlanIR, PlanStep
from sentrook.rules.compiler import compile_rule
from sentrook.scan import scan_plan


def _plan(*tools_and_args: tuple[str, dict] | str) -> PlanIR:
    steps: list[PlanStep] = []
    items = list(tools_and_args)
    for i, item in enumerate(items):
        tool, args = (item, {}) if isinstance(item, str) else item
        status = "pending" if i == len(items) - 1 else "executed"
        steps.append(PlanStep(id=f"s{i + 1}", tool=tool, status=status, args=args))
    return PlanIR(version="1.0", run_id="dialect", steps=steps)


def _rule(doc: dict):
    return compile_rule(doc)


# --- tool_pattern edges -------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "tool", "expected"),
    [
        ("mcp__filesystem__*", "mcp__filesystem__write_file", True),
        ("mcp__filesystem__*", "mcp__filesystem__read_file", True),
        ("mcp__filesystem__*", "mcp__github__write_file", False),
        ("mcp__shell__*", "mcp__shell__run_command", True),
        ("mcp__sqlite__*", "mcp__sqlite__write_query", True),
        ("mcp__postgres__*", "mcp__postgres__write_query", True),
        ("*__edit_file", "mcp__x__edit_file", True),
        ("*__delete_file", "mcp__x__delete_file", True),
        ("*__push_files", "mcp__x__push_files", True),
        ("*__create_pull_request", "mcp__x__create_pull_request", True),
        ("*__create_or_update_file", "mcp__x__create_or_update_file", True),
        ("*__execute", "mcp__x__execute", True),
        ("*__write_query", "mcp__x__write_query", True),
        ("*__write_file", "mcp__x__write_file_extra", False),  # not a suffix
        ("*__write_file", "write_file", False),  # missing mcp prefix segment ok if ends
        ("mcp__", "mcp__github__x", False),  # not a glob; exact only
        ("mcp__*", "mcp__", True),
        ("mcp__*", "mcp", False),
        ("*__write_file", "mcp__a__b__write_file", True),
        ("exec|process|mcp__shell__*", "mcp__shell__run_command", True),
        ("exec|process|mcp__shell__*", "process", True),
        ("exec|process|mcp__shell__*", "write", False),
    ],
)
def test_mcp_and_mixed_pattern_matrix(pattern: str, tool: str, expected: bool):
    assert tool_pattern_matches(pattern, tool) is expected


@pytest.mark.parametrize(
    "bad",
    ["**", "mcp__**", "*a*", "foo*bar", "mcp__*__*"],
)
def test_validate_rejects_more_bad_shapes(bad: str):
    with pytest.raises(InvalidToolPatternError):
        validate_tool_pattern(bad)


def test_match_fail_closed_on_mid_string_even_if_unvalidated():
    # Defense in depth if a pattern bypasses compile validation.
    assert not tool_pattern_matches("a*b", "axb")
    assert not tool_pattern_matches("mcp__*__write*", "mcp__x__write_y")


# --- args key-OR edges --------------------------------------------------------


def test_args_key_or_whitespace_around_pipes():
    assert _args_match({"command | data": r"curl"}, {"data": "curl x"})


def test_args_key_or_empty_segment_ignored():
    assert _args_match({"command||data": r"curl"}, {"command": "curl x"})


def test_args_key_or_first_key_empty_value_tries_second():
    # Empty stringified value fails that key; OR should try the other.
    assert _args_match({"command|data": r"curl"}, {"command": "", "data": "curl x"})


def test_args_key_or_both_present_either_may_match():
    assert _args_match(
        {"command|data": r"wget"},
        {"command": "echo", "data": "wget https://x"},
    )


def test_args_multiple_groups_and_key_or():
    patterns = {"command|data": r"curl", "path|file": r"/tmp"}
    assert _args_match(patterns, {"data": "curl", "file": "/tmp/a"})
    assert not _args_match(patterns, {"data": "curl", "other": "/tmp/a"})


# --- pending_tool + sequence + any() + L1 -------------------------------------


def test_pending_tool_glob_suffix():
    rule = _rule(
        {
            "rule": "T-PEND-SUFFIX",
            "meta": {"name": "s", "action": "review"},
            "condition": {"pending_tool": "*__write_file|*__run_command"},
        }
    )
    cfg = MatcherConfig()
    assert evaluate_rule(rule, _plan("mcp__v__write_file"), cfg).matched
    assert not evaluate_rule(rule, _plan("mcp__v__list_resources"), cfg).matched


def test_any_prefix_or_suffix_branches():
    """Mirrors AIRA-081 shape: any of server-prefix OR verb-suffix."""
    rule = _rule(
        {
            "rule": "T-AIRA081-SHAPE",
            "meta": {"name": "mcp", "action": "review", "authority": "soft"},
            "condition": {
                "any": [
                    {
                        "sequence": [
                            {
                                "tool": "mcp__github__*|mcp__filesystem__*|mcp__shell__*",
                                "status": "pending",
                            }
                        ]
                    },
                    {
                        "sequence": [
                            {
                                "tool": "*__write_file|*__run_command|*__write_query",
                                "status": "pending",
                            }
                        ]
                    },
                ]
            },
        }
    )
    cfg = MatcherConfig()
    assert evaluate_rule(rule, _plan("mcp__github__get_file_contents"), cfg).matched
    assert evaluate_rule(rule, _plan("mcp__filesystem__read_file"), cfg).matched
    assert evaluate_rule(rule, _plan("mcp__shell__run_command"), cfg).matched
    assert evaluate_rule(rule, _plan("mcp__vendor__write_file"), cfg).matched
    assert evaluate_rule(rule, _plan("mcp__vendor__write_query"), cfg).matched
    assert not evaluate_rule(rule, _plan("mcp__vendor__list_resources"), cfg).matched
    assert not evaluate_rule(rule, _plan("mcp__weather__get_forecast"), cfg).matched


def test_l1_glob_finds_aira081_shape_without_exact_keys():
    rule = _rule(
        {
            "rule": "T-GLOB-L1",
            "meta": {"name": "g", "action": "review"},
            "condition": {
                "sequence": [{"tool": "mcp__github__*|*__write_file", "status": "pending"}]
            },
        }
    )
    index = build_l1_index([rule])
    assert index.by_tool == {}
    assert rule in l1_candidates({"mcp__github__create_issue"}, index)
    assert rule in l1_candidates({"mcp__z__write_file"}, index)
    assert rule not in l1_candidates({"mcp__z__list_resources"}, index)
    # Satisfies check requires the plan tool to match the full pattern
    assert rule not in l1_candidates({"exec"}, index)


def test_l1_does_not_candidate_on_executed_only_when_pending_required():
    """L1 indexes by any plan tool name; candidacy still requires pattern match.

    A plan with only ``message`` must not pull in an MCP-glob rule.
    """
    rule = _rule(
        {
            "rule": "T-MCP-ONLY",
            "meta": {"name": "m", "action": "review"},
            "condition": {"pending_tool": "mcp__*"},
        }
    )
    index = build_l1_index([rule])
    assert rule not in l1_candidates({"message"}, index)
    assert rule in l1_candidates({"mcp__x__y"}, index)


def test_sequence_status_pending_ignores_executed_mcp():
    rule = _rule(
        {
            "rule": "T-PEND-ONLY",
            "meta": {"name": "p", "action": "review"},
            "condition": {"sequence": [{"tool": "mcp__github__*", "status": "pending"}]},
        }
    )
    cfg = MatcherConfig()
    # Pending is message; executed github MCP must not satisfy pending slot.
    plan = _plan(
        "mcp__github__create_or_update_file",
        ("message", {"text": "hi"}),
    )
    assert not evaluate_rule(rule, plan, cfg).matched


def test_scan_plan_end_to_end_with_glob_rule():
    rule = _rule(
        {
            "rule": "T-SCAN-MCP",
            "meta": {"name": "s", "action": "review", "severity": "high", "authority": "soft"},
            "condition": {"pending_tool": "*__write_file"},
        }
    )
    result = scan_plan(_plan("mcp__u__write_file"), [rule])
    assert result.decision == "review"
    assert result.matched_rules[0].id == "T-SCAN-MCP"
    assert "mcp__u__write_file" in result.debug.plan_tools
    # Glob-only rule: exact L1 keys empty; still a candidate via glob path
    assert "T-SCAN-MCP" in result.debug.l1_candidate_ids


def test_compile_rejects_mid_glob_in_sequence_slot():
    with pytest.raises(ValueError, match="unsupported"):
        _rule(
            {
                "rule": "T-BAD-SEQ",
                "meta": {"name": "b"},
                "condition": {"sequence": [{"tool": "mcp__*__write*", "status": "pending"}]},
            }
        )


def test_pending_tool_pipe_or_reason_mentions_actual_tool():
    rule = _rule(
        {
            "rule": "T-REASON",
            "meta": {"name": "r", "action": "review"},
            "condition": {"pending_tool": "exec|process"},
        }
    )
    out = evaluate_rule(rule, _plan("process"), MatcherConfig())
    assert out.matched
    assert "process" in out.reason
