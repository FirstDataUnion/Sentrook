"""The over-budget fill sends an input whole when it fits whole.

The fill bisected for the largest contents total that fits the budget, assuming the view grows with the total. It does
not where an input becomes whole: its `scanner_truncated` record and, on the call-v5 view, its head-and-tail marker drop
out, so the view shrinks. The bisection could settle below that point and send the input cut, with a marker, when the
next total up fit and sent it whole. The call-v5 view (`trim-v7`) now searches the points where each input becomes whole
first, most recent input first, and bisects only between the largest one that fits and the next. The older call views
fill as before.
"""

from __future__ import annotations

import copy

import pytest

from sentrook.jev.chunking import est_tokens
from sentrook.prepare.views import (
    CALL_INPUT_CAP_CHARS,
    CALL_V3,
    CALL_V5,
    VIEW_VERSIONS,
    _call_view_with_inputs,
    build_views,
    cap_inputs,
    fill_inputs,
    trim,
    view,
)


def _raw(case: dict, sizes: list[int], *, seqs: list | None = None) -> dict:
    """The case with no history and one input per size (`input_seq` 1, 2, … unless `seqs` says otherwise)."""
    raw = copy.deepcopy(case["fixture"])
    raw["history"] = []
    template = raw["new_inputs"][0]
    raw["new_inputs"] = []
    for n, size in enumerate(sizes):
        entry = copy.deepcopy(template)
        entry["input_seq"] = (seqs or list(range(1, len(sizes) + 1)))[n]
        if entry["input_seq"] is None:
            del entry["input_seq"]
        entry["content"] = (f"row {n} of the listing\n" * size)[:size]
        raw["new_inputs"].append(entry)
    return raw


def _kept(inputs: list) -> list[int]:
    return [(e.get("scanner_truncated") or {}).get("kept_chars", len(e["content"])) for e in inputs]


def test_an_input_that_fits_whole_is_sent_whole(attack_case):
    """Must fire: three 3,000-character inputs and a budget the two latest fit whole in."""
    raw = _raw(attack_case, [3000, 3000, 3000])
    built = _call_view_with_inputs(raw, CALL_V5, budget_tokens=3185)
    inputs = built.state["new_inputs"]
    assert est_tokens(built.state) <= 3185
    assert _kept(inputs) == [0, 3000, 3000]
    assert [i["content"] for i in inputs[1:]] == [e["content"] for e in raw["new_inputs"][1:]]
    assert all("scanner_truncated" not in i for i in inputs[1:])


def test_call_v3_fills_as_before(attack_case):
    """Must stay silent: the older views keep the old search, dip included, byte for byte."""
    raw = _raw(attack_case, [3000, 3000, 3000])
    built = _call_view_with_inputs(raw, CALL_V3, budget_tokens=3185)
    assert _kept(built.state["new_inputs"]) == [0, 2946, 3000]


def _largest_fitting_total(v: dict, arrived: list, budget: int, total: int) -> int:
    best = 0
    for t in range(total + 1):
        inputs = copy.deepcopy(arrived)
        cap_inputs(inputs, total=t, head_tail=True)
        if est_tokens(dict(v, new_inputs=inputs)) <= budget:
            best = t
    return best


@pytest.mark.parametrize(
    ("sizes", "seqs"),
    [
        ([400, 900, 650], None),
        ([1200, 300, 300, 800], None),
        ([700, 700], [None, 2]),  # an input without input_seq counts as earliest
        ([7000, 500], None),  # over the per-input cap
    ],
)
def test_the_fill_takes_the_largest_total_that_fits(attack_case, sizes, seqs):
    """Checked against every total from 0 to the capped sum, over budgets across the whole range."""
    raw = _raw(attack_case, sizes, seqs=seqs)
    v = view(trim(raw), CALL_V5)
    arrived = copy.deepcopy(v["new_inputs"])
    total = sum(min(s, CALL_INPUT_CAP_CHARS) for s in sizes)
    sizes_at = []
    for t in range(total + 1):
        inputs = copy.deepcopy(arrived)
        cap_inputs(inputs, total=t, head_tail=True)
        sizes_at.append(est_tokens(dict(v, new_inputs=inputs)))
    low, high = sizes_at[0], sizes_at[-1]
    assert sizes_at != sorted(sizes_at), "the view should shrink where an input becomes whole"
    for budget in range(low, high, max(1, (high - low) // 60)):
        expected = max(t for t, size in enumerate(sizes_at) if size <= budget)
        w = copy.deepcopy(v)
        fill_inputs(w, arrived, budget, head_tail=True)
        assert est_tokens(w) <= budget
        assert sum(_kept(w["new_inputs"])) == expected, budget


def test_the_fill_still_keeps_the_most_recent_input_longest(attack_case):
    raw = _raw(attack_case, [2000, 2000, 2000, 2000])
    for budget in (1500, 2100, 2600, 3000):
        kept = _kept(_call_view_with_inputs(raw, CALL_V5, budget_tokens=budget).state["new_inputs"])
        assert kept == sorted(kept) and kept[-1] > 0, (budget, kept)


def test_views_within_the_budget_are_untouched(attack_case):
    views = build_views(copy.deepcopy(attack_case["fixture"]), exposure_input_seqs=None)
    assert views[CALL_V5].state == views[CALL_V3].state


def test_the_call_v5_views_version_moves_and_the_older_ones_stay():
    assert VIEW_VERSIONS[CALL_V5] == "trim-v7"
    assert VIEW_VERSIONS[CALL_V3] == "trim-v3"
