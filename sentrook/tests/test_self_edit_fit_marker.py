"""The self-edit fitter's drop count is inside the budget it fits to.

`fit_self_edit` drops history steps, then tool, assistant and user entries of the conversation, while the view is over
its budget, and counts what it dropped in `self_edit.scanner_dropped`. The count was written after the loops, outside
the size checks, so a view that stopped just under its budget ended over it by the count's size. It is now written
before each size check, as the call view's fitter marks its dropped history.
"""

from __future__ import annotations

import copy

import pytest
from conftest import load_fixture

from sentrook.jev.chunking import est_tokens
from sentrook.prepare.views import SELFEDIT_V2, fit_self_edit, strip_inputs, trim, view


def _raw(steps: int = 20, *, tool: int = 0, assistant: int = 0, user: int = 1) -> dict:
    raw = copy.deepcopy(load_fixture("worked-example-attack.json")["fixture"])
    raw["history"] = [
        {
            "step": i,
            "turn": 1,
            "tool": "exec",
            "tool_kind": "exec",
            "arguments": {"api_token": "x", "pin": i},
        }
        for i in range(1, steps + 1)
    ]
    raw["session"]["step"] = steps + 1
    conv = []
    for i in range(max(tool, assistant, user)):
        if i < user:
            conv.append({"role": "user", "text": f"remember item {i} " + "u" * 40})
        if i < assistant:
            conv.append({"role": "assistant", "text": f"noted {i} " + "a" * 40})
        if i < tool:
            conv.append({"role": "tool", "tool": "memory", "content": f"saved {i} " + "t" * 40})
    raw["self_edit"] = {"kind": "memory", "conversation": conv}
    return raw


def _view(raw: dict) -> dict:
    v = view(trim(raw), SELFEDIT_V2)
    strip_inputs(v["new_inputs"])
    return v


def _droppable(v: dict) -> bool:
    return bool(v.get("history")) or bool(v["self_edit"]["conversation"])


def test_the_reproducer_ends_within_its_budget():
    """Must fire: dropping one step used to leave the view at 1,180 against 1,172."""
    v = _view(_raw())
    assert fit_self_edit(v, 1172)
    assert est_tokens(v) <= 1172
    assert v["self_edit"]["scanner_dropped"]["history"] >= 1


@pytest.mark.parametrize("shape", [(20, 0, 0, 1), (60, 5, 5, 5), (5, 12, 12, 3), (0, 15, 0, 15)])
def test_every_budget_is_kept_while_anything_is_left_to_drop(shape):
    """Must fire: across every budget where the fitter drops something, the fitted view, count included, fits."""
    steps, tool, assistant, user = shape
    full = _view(_raw(steps, tool=tool, assistant=assistant, user=user))
    size = est_tokens(full)
    checked = 0
    for budget in range(size - 1, 0, -1):
        v = copy.deepcopy(full)
        assert fit_self_edit(v, budget)
        if not _droppable(v):
            break
        assert est_tokens(v) <= budget, budget
        dropped = v["self_edit"]["scanner_dropped"]
        assert sum(dropped.values()) == (
            len(full.get("history") or [])
            - len(v.get("history") or [])
            + len(full["self_edit"]["conversation"])
            - len(v["self_edit"]["conversation"])
        )
        checked += 1
    assert checked > 20


def test_a_view_within_its_budget_is_untouched():
    """Must stay silent: nothing dropped, no count, the view as it was."""
    v = _view(_raw(5, tool=2, assistant=2, user=2))
    before = copy.deepcopy(v)
    assert not fit_self_edit(v, est_tokens(v))
    assert v == before and "scanner_dropped" not in v["self_edit"]
