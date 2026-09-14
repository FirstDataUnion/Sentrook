"""Parity: sentrook.serve.skeleton must match plugin/localAllowlist.ts exactly.

``fixtures/skeleton_golden.jsonl`` is generated from the TypeScript
implementation and loaded by both test suites. A divergence here means the two
lanes disagree about what a command *is*, which would make the Phase 0 three-lane
counterfactual wrong and (Phase 3b) let the host allowlist and the shipped allow
families drift apart. Add a fixture row before changing either side.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentrook.serve.skeleton import (
    allowlist_command_skeleton,
    is_high_risk_command,
    parse_bindable_script,
    skeletonize_command,
    tokenize_argv,
)

GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "skeleton_golden.jsonl"


def _rows() -> list[dict]:
    with GOLDEN.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_golden_fixture_present_and_populated() -> None:
    rows = _rows()
    assert len(rows) >= 50, "golden fixture lost cases; regenerate from the TS side"
    assert {r["name"] for r in rows}.__len__() == len(rows), "duplicate fixture case names"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r["name"])
def test_matches_typescript(row: dict) -> None:
    command = row["command"]
    assert tokenize_argv(command.strip()) == row["tokens"]
    assert is_high_risk_command(command) is row["high_risk"]
    assert skeletonize_command(command) == row["skeleton"]
    assert allowlist_command_skeleton(command) == row["allowlist_skeleton"]

    bindable = parse_bindable_script(command)
    expected = row["bindable_script"]
    if expected is None:
        assert bindable is None
    else:
        assert bindable is not None
        assert bindable.interpreter == expected["interpreter"]
        assert bindable.script_path == expected["script_path"]
        assert list(bindable.trailing_args) == expected["trailing_args"]


def test_high_risk_fails_closed_on_unskeletonisable() -> None:
    """Anything high-risk yields no skeleton at all, never a permissive one."""
    for command in ("", "   ", "ls | sh", "python3 -c 'x'", "a && b"):
        assert is_high_risk_command(command) is True
        assert skeletonize_command(command) is None
        assert allowlist_command_skeleton(command) is None


def test_dangerous_bin_needs_literal_structure() -> None:
    """Dangerous bins must retain literal structure once volatiles are stripped.

    Note the deliberate asymmetry for fetch bins: a URL is *pinned*, not
    replaced, because for ``curl``/``wget`` the URL **is** the identity of the
    action rather than a volatile. So a bare fetch still skeletonises, while an
    interpreter whose only argument is a volatile does not.
    """
    assert skeletonize_command("python3 1234") is None
    assert skeletonize_command("curl https://example.com/x") == "curl https://example.com/x"
    assert skeletonize_command("curl https://example.com") == "curl https://example.com/"
    assert (
        skeletonize_command("wget -O /tmp/out.bin https://example.com/a")
        == "wget -O /tmp/out.bin https://example.com/a"
    )


def test_fetch_url_pinning_normalises_host_and_default_port() -> None:
    """Mirrors JS ``URL.origin``: host lowercased, default port dropped."""
    assert (
        skeletonize_command("curl -o /tmp/f https://Example.COM:443/p")
        == "curl -o /tmp/f https://example.com/p"
    )
    assert (
        skeletonize_command("curl -o /tmp/f http://example.com:8080/p?q=1")
        == "curl -o /tmp/f http://example.com:8080/p"
    )


def test_unicode_digits_are_not_ints() -> None:
    """JS \\d is ASCII-only; the twin must not widen it via Python's Unicode \\d."""
    assert skeletonize_command("kill 12345") == "kill <int>"
    assert skeletonize_command("kill ١٢٣") == "kill ١٢٣"
