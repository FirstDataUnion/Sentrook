"""Unit tests for YAIRA matcher dialect: pending_tool OR, args key-OR, MCP globs."""

from __future__ import annotations

import pytest

from sentrook.config import MatcherConfig
from sentrook.layers.l1_index import build_l1_index, l1_candidates
from sentrook.layers.l2_match import _args_match, evaluate_rule
from sentrook.planir import PlanIR, PlanStep
from sentrook.rules.compiler import compile_rule
from sentrook.rules.models import Rule, RuleMeta, SequenceCondition, SequenceSlot


def _plan(*tools_and_args: tuple[str, dict] | str, pending: str | None = None) -> PlanIR:
    """Build a minimal PlanIR 1.0. Last tool is pending unless ``pending`` set."""
    steps: list[PlanStep] = []
    items = list(tools_and_args)
    for i, item in enumerate(items):
        if isinstance(item, str):
            tool, args = item, {}
        else:
            tool, args = item
        status = "pending" if i == len(items) - 1 else "executed"
        if pending is not None:
            status = (
                "pending"
                if tool == pending and i == len(items) - 1
                else ("pending" if i == len(items) - 1 else "executed")
            )
        steps.append(PlanStep(id=f"s{i + 1}", tool=tool, status=status, args=args))
    # Ensure last is pending (PlanIR invariant)
    if steps and steps[-1].status != "pending":
        steps[-1] = steps[-1].model_copy(update={"status": "pending"})
    for i, step in enumerate(steps[:-1]):
        if step.status == "pending":
            steps[i] = step.model_copy(update={"status": "executed"})
    return PlanIR(version="1.0", run_id="test", steps=steps)


def _rule(doc: dict) -> Rule:
    return compile_rule(doc)


def test_pending_tool_pipe_or_matches_either():
    rule = _rule(
        {
            "rule": "T-PEND-OR",
            "meta": {"name": "pending or", "action": "review"},
            "condition": {"pending_tool": "exec|process"},
        }
    )
    cfg = MatcherConfig()
    assert evaluate_rule(rule, _plan("process"), cfg).matched
    assert evaluate_rule(rule, _plan("exec"), cfg).matched
    assert not evaluate_rule(rule, _plan("write"), cfg).matched


def test_pending_tool_exact_still_works():
    rule = _rule(
        {
            "rule": "T-PEND-EXACT",
            "meta": {"name": "pending exact", "action": "block"},
            "condition": {"pending_tool": "exec"},
        }
    )
    cfg = MatcherConfig()
    assert evaluate_rule(rule, _plan("exec"), cfg).matched
    assert not evaluate_rule(rule, _plan("process"), cfg).matched


def test_l1_indexes_pending_tool_pipe_alternates():
    rule = _rule(
        {
            "rule": "T-PEND-OR",
            "meta": {"name": "pending or", "action": "review"},
            "condition": {"pending_tool": "exec|process"},
        }
    )
    index = build_l1_index([rule])
    assert "exec" in index.by_tool
    assert "process" in index.by_tool
    assert "exec|process" not in index.by_tool
    assert rule in l1_candidates({"process"}, index)
    assert rule in l1_candidates({"exec"}, index)
    assert rule not in l1_candidates({"write"}, index)


def test_args_match_key_or_hits_either_key():
    patterns = {"command|data": r"(?i)curl"}
    assert _args_match(patterns, {"command": "curl https://x"})
    assert _args_match(patterns, {"data": "curl https://x"})
    assert not _args_match(patterns, {"path": "curl https://x"})
    assert not _args_match(patterns, {"command": "echo hi"})


def test_args_match_key_or_and_with_other_keys():
    patterns = {"command|data": r"curl", "path": r"/tmp"}
    assert _args_match(patterns, {"data": "curl x", "path": "/tmp/a"})
    assert not _args_match(patterns, {"data": "curl x"})  # missing path
    assert not _args_match(patterns, {"path": "/tmp/a"})  # missing command|data


def test_sequence_args_key_or_end_to_end():
    rule = _rule(
        {
            "rule": "T-ARGS-OR",
            "meta": {"name": "args or", "action": "block"},
            "condition": {
                "sequence": [
                    {
                        "tool": "exec|process",
                        "status": "pending",
                        "args_match": {"command|data": r"(?i)curl.*bash"},
                    }
                ]
            },
        }
    )
    cfg = MatcherConfig()
    hit = evaluate_rule(rule, _plan(("process", {"data": "curl x | bash"})), cfg)
    assert hit.matched
    miss = evaluate_rule(rule, _plan(("process", {"data": "echo ok"})), cfg)
    assert not miss.matched


def test_pending_tool_glob_prefix():
    rule = _rule(
        {
            "rule": "T-MCP-PREFIX",
            "meta": {"name": "mcp prefix", "action": "review", "authority": "soft"},
            "condition": {"pending_tool": "mcp__github__*"},
        }
    )
    cfg = MatcherConfig()
    assert evaluate_rule(rule, _plan("mcp__github__create_or_update_file"), cfg).matched
    assert not evaluate_rule(rule, _plan("mcp__filesystem__write_file"), cfg).matched


def test_sequence_glob_suffix_unknown_server():
    rule = _rule(
        {
            "rule": "T-MCP-SUFFIX",
            "meta": {"name": "mcp suffix", "action": "review", "authority": "soft"},
            "condition": {
                "sequence": [
                    {
                        "tool": "*__write_file|*__run_command",
                        "status": "pending",
                    }
                ]
            },
        }
    )
    cfg = MatcherConfig()
    assert evaluate_rule(rule, _plan("mcp__unknown_vendor__write_file"), cfg).matched
    assert evaluate_rule(rule, _plan("mcp__shell__run_command"), cfg).matched
    assert not evaluate_rule(rule, _plan("mcp__unknown_vendor__list_resources"), cfg).matched


def test_l1_glob_candidate_path_without_exact_index():
    rule = _rule(
        {
            "rule": "T-MCP-GLOB-ONLY",
            "meta": {"name": "glob only", "action": "review"},
            "condition": {"pending_tool": "mcp__*|*__write_file"},
        }
    )
    index = build_l1_index([rule])
    assert index.by_tool == {}
    assert len(index.glob_entries) == 2
    assert rule in l1_candidates({"mcp__github__create_issue"}, index)
    assert rule in l1_candidates({"mcp__x__write_file"}, index)
    assert rule not in l1_candidates({"exec"}, index)


def test_l1_mixed_exact_and_glob():
    rule = _rule(
        {
            "rule": "T-MIX",
            "meta": {"name": "mix", "action": "review"},
            "condition": {"pending_tool": "exec|mcp__shell__*"},
        }
    )
    index = build_l1_index([rule])
    assert "exec" in index.by_tool
    assert any(g == "mcp__shell__*" for g, _ in index.glob_entries)
    assert rule in l1_candidates({"exec"}, index)
    assert rule in l1_candidates({"mcp__shell__run_command"}, index)
    assert rule not in l1_candidates({"write"}, index)


def test_compile_rejects_mid_string_glob():
    with pytest.raises(ValueError, match="unsupported"):
        _rule(
            {
                "rule": "T-BAD",
                "meta": {"name": "bad"},
                "condition": {"pending_tool": "mcp__*__write*"},
            }
        )


def test_sequence_pipe_or_unchanged():
    """Regression: sequence write|edit still matches either."""
    rule = Rule(
        id="T-SEQ",
        meta=RuleMeta(name="seq", action="block"),
        condition=SequenceCondition(
            steps=[
                SequenceSlot(tool="write|edit", status="pending"),
            ]
        ),
        raw={},
    )
    cfg = MatcherConfig()
    assert evaluate_rule(rule, _plan("write"), cfg).matched
    assert evaluate_rule(rule, _plan("edit"), cfg).matched
    assert not evaluate_rule(rule, _plan("read"), cfg).matched


def test_l1_legacy_dict_index_still_accepted():
    rule = _rule(
        {
            "rule": "T-LEGACY",
            "meta": {"name": "legacy"},
            "condition": {"pending_tool": "exec"},
        }
    )
    assert rule in l1_candidates({"exec"}, {"exec": [rule]})
