"""The call view's token budget follows the question set it is sent with.

The call probe sends one request: the call view plus the set's questions, which repeat the preamble per question.
The view is built to the room the configured set leaves in the chunking budget, so a request at the limit has its
input contents stripped rather than being sent over the model's context, and a larger question set shrinks the view
instead of overrunning it. Small requests are not affected.
"""

from __future__ import annotations

import copy
import json

import pytest
from test_jev_probes import FakeDecider, prepared_for

from sentrook.enums import ProbeStep
from sentrook.jev.chunking import BUDGET_TOKENS, est_tokens
from sentrook.jev.client import JevConfig
from sentrook.jev.questions import QUESTIONS_DIR, load_question_set
from sentrook.prepare.views import (
    CALL,
    CALL_INPUT_CAP_CHARS,
    CALL_QUESTIONS_RESERVE_TOKENS,
    CALL_STATE_BUDGET_TOKENS,
    CALL_V2,
    CALL_V3,
    CALL_V5,
    SELFEDIT_QUESTIONS_RESERVE_TOKENS,
    SELFEDIT_V1,
    VIEW_KIND,
    build_views,
    state_budget_tokens,
)
from sentrook.scan import Scanner, ScannerConfig, ScanOptions, view_budgets

KEY = "unit-test-state-key-" * 2


def _shipped(kind: str) -> list[str]:
    """Every shipped question set whose view serves `kind` ('call' or 'selfedit')."""
    names = []
    for path in sorted(QUESTIONS_DIR.glob("*.json")):
        view = json.loads(path.read_text(encoding="utf-8")).get("state_view", "trimmed")
        if VIEW_KIND.get(view) != CALL:
            continue
        if (view == SELFEDIT_V1) == (kind == "selfedit"):
            names.append(path.stem)
    return names


CALL_SETS = _shipped("call")
SELFEDIT_SETS = _shipped("selfedit")


def test_the_shipped_sets_are_found():
    assert {"call-v2", "call-v5", "call-v6"} <= set(CALL_SETS)
    assert {"selfedit-v1", "selfedit-v2"} <= set(SELFEDIT_SETS)


def _questions_tokens(name: str) -> int:
    return est_tokens(load_question_set(name).built_questions())


def _scanner(call_set: str, selfedit_set: str | None = None, decider=None) -> Scanner:
    return Scanner(
        ScannerConfig(
            token_key=KEY,
            decider=decider,
            jev=JevConfig(
                exposure_question_set="exposure-v2",
                call_question_set=call_set,
                selfedit_question_set=selfedit_set,
            ),
        )
    )


# ---- every shipped set fits ------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", CALL_SETS)
def test_every_shipped_call_set_fits_the_default_reserve(name):
    assert _questions_tokens(name) <= CALL_QUESTIONS_RESERVE_TOKENS
    assert CALL_STATE_BUDGET_TOKENS + _questions_tokens(name) <= BUDGET_TOKENS


@pytest.mark.parametrize("name", SELFEDIT_SETS)
def test_every_shipped_self_edit_set_fits_its_reserve(name):
    assert _questions_tokens(name) <= SELFEDIT_QUESTIONS_RESERVE_TOKENS


@pytest.mark.parametrize("name", CALL_SETS)
def test_the_scanner_sizes_the_call_view_from_its_call_set(name):
    sc = _scanner(name)
    assert sc.call_budget_tokens + _questions_tokens(name) <= BUDGET_TOKENS
    assert sc.call_budget_tokens == state_budget_tokens(load_question_set(name).built_questions())
    assert sc.selfedit_budget_tokens is None


@pytest.mark.parametrize("name", SELFEDIT_SETS)
def test_the_scanner_sizes_the_self_edit_view_from_its_self_edit_set(name):
    sc = _scanner("call-v5", name)
    assert sc.selfedit_budget_tokens + _questions_tokens(name) <= BUDGET_TOKENS
    assert sc.call_budget_tokens + _questions_tokens("call-v5") <= BUDGET_TOKENS


def test_a_set_that_leaves_no_room_stops_startup():
    qs = load_question_set("call-v5")
    huge = copy.deepcopy(qs.questions)
    first = next(iter(huge))
    huge[first]["instructions"] = "x" * (BUDGET_TOKENS * 3)
    oversize = type(qs)(**{**qs.__dict__, "name": "oversize", "questions": huge})
    with pytest.raises(ValueError, match="leaves no room"):
        view_budgets([oversize])
    assert view_budgets([None]) == (None, None)


# ---- a request at the budget is stripped, not sent oversize ---------------------------------------------------


def _big_inputs(attack_case, n: int = 7) -> dict:
    """Inputs that fill the per-input and total caps: about 17k estimated tokens of content, which fits the old
    fixed budget but leaves no room for call-v5's questions."""
    case = copy.deepcopy(attack_case)
    raw = case["fixture"]
    template = raw["new_inputs"][0]
    raw["new_inputs"] = []
    for seq in range(1, n + 1):
        entry = copy.deepcopy(template)
        entry["input_seq"] = seq
        entry["content"] = (f"line {seq} of a long listing\n" * 400)[:CALL_INPUT_CAP_CHARS]
        entry["size_bytes"] = len(entry["content"])
        raw["new_inputs"].append(entry)
    return case


def _scan(case, sc: Scanner):
    return sc.scan(
        case["fixture"],
        ScanOptions(
            deterministic=True,
            salt="testnest",
            state_seed=case["state_seed"],
            oracle_seed=case["oracle_seed"],
        ),
    )


@pytest.mark.parametrize("name", ["call-v4", "call-v5", "call-v6"])
def test_a_request_at_the_budget_is_fitted_within_the_context(attack_case, name):
    case = _big_inputs(attack_case)
    qs_tokens = _questions_tokens(name)
    view = load_question_set(name).state_view
    # the capped view alone, unstripped, plus the questions would not fit
    unstripped = build_views(
        case["fixture"], exposure_input_seqs=None, call_budget_tokens=BUDGET_TOKENS
    )[view]
    assert not unstripped.inputs_stripped
    assert est_tokens(unstripped.state) + qs_tokens > BUDGET_TOKENS

    dec = FakeDecider()
    res = _scan(case, _scanner(name, decider=dec))
    [body] = [
        b for b in dec.bodies if b["questions"].keys() == load_question_set(name).questions.keys()
    ]
    assert est_tokens(body["state"]) + est_tokens(body["questions"]) <= BUDGET_TOKENS
    # filled to the budget: the latest input keeps its content, the earliest lose theirs first
    sent = body["state"]["new_inputs"]
    assert sent[-1]["content"] == case["fixture"]["new_inputs"][-1]["content"]
    assert len(sent[0]["content"]) < CALL_INPUT_CAP_CHARS
    assert sent[0]["scanner_truncated"]["of_chars"] == CALL_INPUT_CAP_CHARS
    env = next(e for e in res.envelopes if e.step is ProbeStep.JEV_CALL)
    assert env.evidence["inputs_stripped"] is False and env.evidence["inputs_truncated"] is True


def test_a_smaller_set_keeps_contents_a_larger_set_cuts_them(attack_case):
    """Between the two budgets: call-v2's questions leave room for the inputs, call-v5's do not."""
    case = _big_inputs(attack_case, n=6)
    small = _scanner("call-v2").call_budget_tokens
    large = _scanner("call-v5").call_budget_tokens
    built = build_views(case["fixture"], exposure_input_seqs=None, call_budget_tokens=BUDGET_TOKENS)
    size = est_tokens(built[CALL_V3].state)
    assert large < size <= small
    assert not build_views(case["fixture"], exposure_input_seqs=None, call_budget_tokens=small)[
        CALL_V3
    ].inputs_truncated
    fitted = build_views(case["fixture"], exposure_input_seqs=None, call_budget_tokens=large)[
        CALL_V5
    ]
    assert fitted.inputs_truncated and not fitted.inputs_stripped
    assert est_tokens(fitted.state) <= large


# ---- small requests are unchanged ------------------------------------------------------------------------------


@pytest.mark.parametrize("name", CALL_SETS)
def test_small_requests_build_the_same_views_whatever_the_set(attack_case, name):
    default = prepared_for(attack_case)
    budget = _scanner(name).call_budget_tokens
    built = build_views(attack_case["fixture"], exposure_input_seqs={1}, call_budget_tokens=budget)
    for view in (CALL_V2, CALL_V3, CALL_V5):
        assert built[view].state == default.views[view]
        assert not built[view].inputs_stripped and not built[view].inputs_truncated
    assert built[CALL].state == default.views[CALL]
