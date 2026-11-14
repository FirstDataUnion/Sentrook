"""The call and self-edit view budgets reserve a shipped question set's measured token cost.

A view was fitted to the chunking budget less the set's questions estimated at 2.5 characters per token. The questions
are prose and cost far less: call-v6's questions plus Jev's own prompt measure about 7,000 tokens, while 11,476 were
reserved, so 85 of 1,338 beta scans lost history or input content to room the model never used. A shipped set's
reserve is now its measured cost (`MEASURED_QUESTION_TOKENS`), pinned to the set's sha; a set without a measurement,
or one edited since it was measured, keeps its character estimate. The state is still estimated at 2.5 characters per
token.
"""

from __future__ import annotations

import copy
import dataclasses
import math

import pytest

from sentrook.jev.chunking import BUDGET_TOKENS, CHARS_PER_TOKEN, est_tokens
from sentrook.jev.client import CONTEXT_TOKENS
from sentrook.jev.questions import load_question_set
from sentrook.prepare.views import (
    CALL_V3,
    CALL_V5,
    MEASURED_DENSEST_STATE_CHARS_PER_TOKEN,
    MEASURED_OUTPUT_TOKENS,
    MEASURED_QUESTION_TOKENS,
    MEASURED_STATE_RESIDUAL_TOKENS,
    build_views,
    question_reserve_tokens,
    set_state_budget_tokens,
    state_budget_tokens,
)
from sentrook.scan import view_budgets
from sentrook.serve.config import ServeConfig


def test_call_v6_and_selfedit_v3_get_their_measured_room():
    call, selfedit = view_budgets([load_question_set("call-v6"), load_question_set("selfedit-v3")])
    assert call == BUDGET_TOKENS - 7_100 == 20_100
    assert selfedit == BUDGET_TOKENS - 8_800 == 18_400


def test_the_served_sets_are_measured_at_their_current_sha():
    """Editing a served set without measuring it again fails here (its budget would fall back to the estimate)."""
    cfg = ServeConfig()
    for name in (cfg.jev_call_question_set, cfg.jev_selfedit_question_set):
        qs = load_question_set(name)
        assert (qs.name, qs.sha[:12]) in MEASURED_QUESTION_TOKENS, name


@pytest.mark.parametrize(("name", "sha"), sorted(MEASURED_QUESTION_TOKENS))
def test_every_measurement_is_sound(name, sha):
    """A measurement is for a shipped set at that sha and never above its character estimate."""
    qs = load_question_set(name)
    assert qs.sha[:12] == sha
    cost = MEASURED_QUESTION_TOKENS[(name, sha)]
    assert 0 < cost <= est_tokens(qs.built_questions())
    assert set_state_budget_tokens(qs) == BUDGET_TOKENS - cost


@pytest.mark.parametrize(("name", "sha"), sorted(MEASURED_QUESTION_TOKENS))
def test_a_full_budget_state_fits_the_context_at_the_densest_measured_rate(name, sha):
    """The state budget is in estimated tokens (2.5 characters each). A state at its full budget, as dense as the
    densest large state measured, plus the set's measured cost, the largest residual and the longest answer, must
    still fit the model's context. This fails if the chunking budget, the state estimate or a reserve grows too far."""
    qs = load_question_set(name)
    state_chars = set_state_budget_tokens(qs) * CHARS_PER_TOKEN
    state_tokens = math.ceil(state_chars / MEASURED_DENSEST_STATE_CHARS_PER_TOKEN)
    body = MEASURED_QUESTION_TOKENS[(name, sha)] + MEASURED_STATE_RESIDUAL_TOKENS + state_tokens
    assert body + MEASURED_OUTPUT_TOKENS <= CONTEXT_TOKENS


def test_an_edited_or_unmeasured_set_keeps_its_estimate():
    qs = load_question_set("call-v6")
    edited = dataclasses.replace(qs, sha="0" * 64)
    assert question_reserve_tokens(edited) == est_tokens(qs.built_questions())
    assert set_state_budget_tokens(edited) == state_budget_tokens(qs.built_questions())
    v5 = load_question_set("call-v5")
    assert (v5.name, v5.sha[:12]) not in MEASURED_QUESTION_TOKENS
    assert view_budgets([v5]) == (state_budget_tokens(v5.built_questions()), None)


def test_the_tightest_set_still_decides_the_shared_view():
    """call-v5 (unmeasured) and call-v6 share the call-v5 view: the view is built to the smaller room."""
    sets = [load_question_set("call-v6"), load_question_set("call-v5")]
    assert view_budgets(sets)[0] == state_budget_tokens(sets[1].built_questions())


def test_a_view_under_the_old_budget_is_byte_identical(attack_case, twin_case):
    """Must hold: a larger budget changes nothing for a view that fitted the old one."""
    for case in (attack_case, twin_case):
        raw = copy.deepcopy(case["fixture"])
        old = build_views(raw, exposure_input_seqs=None, call_budget_tokens=15_724)
        new = build_views(raw, exposure_input_seqs=None, call_budget_tokens=20_100)
        for name in (CALL_V3, CALL_V5):
            assert old[name].state == new[name].state and not new[name].fitted
