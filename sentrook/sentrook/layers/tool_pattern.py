"""YAIRA tool-name pattern matching (exact, pipe-OR, prefix/suffix globs).

PlanIR ``steps[].tool`` remains an exact string. This module is the YAIRA
matcher dialect for how rules refer to those strings — not a PlanIR change.

v1 grammar (narrow by design):
- Exact: ``exec``
- Pipe OR: ``write|edit`` (whitespace around alternates is ignored)
- Trailing ``*``: prefix match (``mcp__*``, ``mcp__github__*``)
- Leading ``*``: suffix match (``*__write_file``)
- Compose: ``mcp__github__*|*__run_command``

Out of scope for v1: mid-string globs, ``?``, character classes, regex-in-tool.
"""

from __future__ import annotations


class InvalidToolPatternError(ValueError):
    """Raised when a YAIRA tool pattern uses unsupported glob shape."""


def split_tool_alternates(pattern: str) -> tuple[str, ...]:
    """Split a tool pattern on ``|`` into alternates (empty segments dropped)."""
    return tuple(part.strip() for part in pattern.split("|") if part.strip())


def is_glob_alternate(alternate: str) -> bool:
    """True if this single alternate (no pipes) contains a glob ``*``."""
    return "*" in alternate


def validate_tool_pattern(pattern: str) -> None:
    """Reject unsupported tool patterns at rule compile time.

    Raises:
        InvalidToolPatternError: mid-string / multi-star / empty pattern.
    """
    alternates = split_tool_alternates(pattern)
    if not alternates:
        raise InvalidToolPatternError(f"empty tool pattern: {pattern!r}")
    for alt in alternates:
        _validate_single_alternate(alt)


def _validate_single_alternate(alternate: str) -> None:
    if "*" not in alternate:
        return
    if alternate.count("*") != 1:
        raise InvalidToolPatternError(
            f"unsupported tool glob (at most one '*'): {alternate!r}"
        )
    if alternate == "*":
        return
    if alternate.startswith("*") ^ alternate.endswith("*"):
        # Exactly one of prefix (foo*) or suffix (*foo).
        return
    raise InvalidToolPatternError(
        f"unsupported mid-string tool glob: {alternate!r}"
    )


def exact_index_keys(pattern: str) -> frozenset[str]:
    """Exact tool names to put in the L1 exact index (glob alternates excluded)."""
    return frozenset(
        alt for alt in split_tool_alternates(pattern) if not is_glob_alternate(alt)
    )


def glob_alternates(pattern: str) -> frozenset[str]:
    """Glob alternates that need the L1 parallel glob candidate path."""
    return frozenset(
        alt for alt in split_tool_alternates(pattern) if is_glob_alternate(alt)
    )


def tool_pattern_matches(pattern: str, tool: str) -> bool:
    """Return whether ``tool`` matches YAIRA ``pattern`` (any alternate)."""
    return any(_single_alternate_matches(alt, tool) for alt in split_tool_alternates(pattern))


def pattern_matches_any_plan_tool(pattern: str, plan_tools: set[str]) -> bool:
    """True if any tool in ``plan_tools`` matches ``pattern``."""
    return any(tool_pattern_matches(pattern, tool) for tool in plan_tools)


def _single_alternate_matches(alternate: str, tool: str) -> bool:
    if "*" not in alternate:
        return tool == alternate
    if alternate.count("*") != 1:
        return False
    if alternate == "*":
        return True
    if alternate.startswith("*") and alternate.endswith("*"):
        return False
    if alternate.endswith("*"):
        return tool.startswith(alternate[:-1])
    if alternate.startswith("*"):
        return tool.endswith(alternate[1:])
    return False
