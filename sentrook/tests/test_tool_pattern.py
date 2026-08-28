"""Unit tests for YAIRA tool-pattern dialect (exact, pipe-OR, prefix/suffix *)."""

from __future__ import annotations

import pytest

from sentrook.layers.tool_pattern import (
    InvalidToolPatternError,
    exact_index_keys,
    glob_alternates,
    pattern_matches_any_plan_tool,
    split_tool_alternates,
    tool_pattern_matches,
    validate_tool_pattern,
)


@pytest.mark.parametrize(
    ("pattern", "tool", "expected"),
    [
        ("exec", "exec", True),
        ("exec", "process", False),
        ("write|edit", "write", True),
        ("write|edit", "edit", True),
        ("write|edit", "read", False),
        ("write | edit", "edit", True),
        ("mcp__*", "mcp__github__create_issue", True),
        ("mcp__*", "exec", False),
        ("mcp__github__*", "mcp__github__create_or_update_file", True),
        ("mcp__github__*", "mcp__filesystem__write_file", False),
        ("*__write_file", "mcp__unknown_vendor__write_file", True),
        ("*__write_file", "mcp__github__get_file_contents", False),
        ("mcp__github__*|*__run_command", "mcp__github__push_files", True),
        ("mcp__github__*|*__run_command", "mcp__shell__run_command", True),
        ("mcp__github__*|*__run_command", "mcp__weather__get_forecast", False),
        ("*", "anything", True),
    ],
)
def test_tool_pattern_matches(pattern: str, tool: str, expected: bool):
    assert tool_pattern_matches(pattern, tool) is expected


def test_exact_index_keys_exclude_globs():
    assert exact_index_keys("exec|process") == frozenset({"exec", "process"})
    assert exact_index_keys("mcp__*") == frozenset()
    assert exact_index_keys("exec|mcp__*") == frozenset({"exec"})
    assert glob_alternates("exec|mcp__*| *__write_file") == frozenset(
        {"mcp__*", "*__write_file"}
    )


def test_pattern_matches_any_plan_tool():
    assert pattern_matches_any_plan_tool("write|edit", {"read", "edit"})
    assert not pattern_matches_any_plan_tool("write|edit", {"read", "exec"})
    assert pattern_matches_any_plan_tool("mcp__*", {"exec", "mcp__x__y"})


def test_split_drops_empty_segments():
    assert split_tool_alternates("a||b|") == ("a", "b")


@pytest.mark.parametrize(
    "bad",
    [
        "mcp__*__write*",
        "*write*",
        "a*b",
        "",
        "|||",
    ],
)
def test_validate_rejects_unsupported(bad: str):
    with pytest.raises(InvalidToolPatternError):
        validate_tool_pattern(bad)


@pytest.mark.parametrize(
    "ok",
    ["exec", "write|edit", "mcp__*", "*__write_file", "mcp__github__*|*__run_command", "*"],
)
def test_validate_accepts_v1(ok: str):
    validate_tool_pattern(ok)
