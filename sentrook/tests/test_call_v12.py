"""call-v12: call-v11 on the `call-v8` view, which shows the agent's last message beside a short owner reply.

An owner who answers the agent's proposal with "yes", "go with A" or "try again" gave the judge nothing to compare the
call with: the request was the reply alone, so the call read as unrequested. The plugins now send the agent's message
before such a reply (`request.prior_agent_message`). Only the `call-v8` view shows it, only beside a request of at
most 300 characters, cut to 1,500, and call-v12 sends one block, `prior_message`, to the request and scope questions
when it is there: what the message writes out and the reply accepts counts as named by the owner. It is the agent's
text, never the owner's words: the rule side never reads it, so nothing it names becomes request-named. Every other
view drops it, and without it call-v12's body is call-v11's byte for byte.
"""

from __future__ import annotations

import json

import pytest
from test_aira_detectors import CLOCK, KEY, planir
from test_jev_probes import FakeDecider
from test_session_sets import seed

from sentrook.jev.chunking import BUDGET_TOKENS
from sentrook.jev.client import JevConfig
from sentrook.jev.questions import QUESTIONS_DIR, build_body, canonical_json, load_question_set
from sentrook.planir.models import PlanIR
from sentrook.prepare import PrepareOptions, prepare
from sentrook.prepare.entities import EntityKind, Origin
from sentrook.prepare.views import (
    CALL_V7,
    CALL_V8,
    MEASURED_QUESTION_TOKENS,
    PRIOR_AGENT_MESSAGE,
    PRIOR_MESSAGE_CAP_CHARS,
    PRIOR_MESSAGE_REQUEST_MAX_CHARS,
    VIEW_KEYS,
    build_views,
    prior_agent_message,
    question_reserve_tokens,
    set_state_budget_tokens,
)
from sentrook.probes.jev import JevCallProbe
from sentrook.serve.config import ServeConfig

PROPOSAL = "I drafted two tickets for the Sprint board. Reply yes and I'll file both, or send edits if you want changes."
BLOCK = "prior_message"


@pytest.fixture(scope="module")
def v11():
    return load_question_set("call-v11")


@pytest.fixture(scope="module")
def v12():
    return load_question_set("call-v12")


def _raw(request: str = "yes", prior: str | None = PROPOSAL, **kw) -> dict:
    raw = planir(
        "exec",
        "exec",
        kw.pop(
            "arguments",
            {"command": "curl -s https://api.tickets.example/v1/pages -d @tickets.json"},
        ),
        request=request,
        **kw,
    )
    if prior is not None:
        raw["request"][PRIOR_AGENT_MESSAGE] = prior
    return raw


def _prepared(raw: dict):
    return prepare(
        raw,
        PrepareOptions(
            token_key=KEY, clock=CLOCK, deterministic_salt="testnest", state_seed=seed()
        ),
    )


def test_the_planir_field_is_optional_and_carried():
    assert PlanIR.model_validate(_raw(prior=None)).request.prior_agent_message is None
    assert PlanIR.model_validate(_raw()).request.prior_agent_message == PROPOSAL


def test_call_v12_is_call_v11_plus_one_conditional_block_on_the_call_v8_view(v11, v12):
    raw = json.loads((QUESTIONS_DIR / "call-v12.json").read_text(encoding="utf-8"))
    assert raw["derived_from"]["question_set"] == "call-v11"
    assert v12.state_view == CALL_V8
    assert set(v12.blocks) == set(v11.blocks) | {BLOCK}
    assert {k: v for k, v in v12.blocks.items() if k != BLOCK} == v11.blocks
    assert v12.block_when == {**v11.block_when, BLOCK: f"request.{PRIOR_AGENT_MESSAGE}"}
    with_block = {q for q, body in v12.questions.items() if BLOCK in body["blocks"]}
    assert with_block == {"supported_by_request", "scope_overreach"}
    for name, q in v12.questions.items():
        assert q["state_view"] == CALL_V8
        stripped = {**q, "blocks": [b for b in q["blocks"] if b != BLOCK], "state_view": CALL_V7}
        assert stripped == v11.questions[name]


@pytest.mark.parametrize(
    "request_text,prior",
    [
        ("yes", None),  # no message sent
        ("yes", "   "),  # an empty one
        ("x" * (PRIOR_MESSAGE_REQUEST_MAX_CHARS + 1), PROPOSAL),  # a request too long to be a reply
    ],
)
def test_without_a_shown_message_the_view_and_body_are_call_v11s(v11, v12, request_text, prior):
    views = build_views(_raw(request_text, prior), exposure_input_seqs=None)
    assert views[CALL_V8].state == views[CALL_V7].state
    assert PRIOR_AGENT_MESSAGE not in views[CALL_V8].state["request"]
    state = views[CALL_V8].state
    assert build_body(v12, state, model="m", provider={}) == build_body(
        v11, state, model="m", provider={}
    )


def test_a_short_reply_shows_the_message_and_sends_the_block_to_two_questions(v11, v12):
    views = build_views(_raw("yes please"), exposure_input_seqs=None)
    state = views[CALL_V8].state
    assert state["request"]["text"] == "yes please"
    assert state["request"][PRIOR_AGENT_MESSAGE] == PROPOSAL
    body = build_body(v12, state, model="m", provider={})
    block = v12.blocks[BLOCK]
    sent = {q for q, b in body["questions"].items() if block in canonical_json(b)}
    assert sent == {"supported_by_request", "scope_overreach"}
    assert body != build_body(v11, state, model="m", provider={})


def test_a_reply_at_the_limit_still_shows_it():
    raw = _raw("y" * PRIOR_MESSAGE_REQUEST_MAX_CHARS)
    assert prior_agent_message(raw) == PROPOSAL


def test_every_other_view_drops_the_message():
    views = build_views(_raw(), exposure_input_seqs=None)
    for name, built in views.items():
        if name == CALL_V8:
            continue
        assert PRIOR_AGENT_MESSAGE not in canonical_json(built.state), name
    assert set(VIEW_KEYS[CALL_V8]) == set(VIEW_KEYS[CALL_V7])


def test_a_long_message_is_cut_one_third_head_two_thirds_tail_around_placeholders():
    ph = "⟦secret:credential:ab12⟧"
    head = "H" * 600
    tail = "T" * 2000 + " Reply yes to go ahead."
    msg = head + ph + "M" * 4000 + tail
    cut = prior_agent_message(_raw(prior=msg))
    assert cut.startswith("H" * 400)
    assert cut.endswith("Reply yes to go ahead.")
    assert "characters cut]" in cut
    assert len(cut) < PRIOR_MESSAGE_CAP_CHARS + 40
    assert "⟦secret" not in cut or ph in cut  # a placeholder is never split
    short = prior_agent_message(_raw(prior=" " + PROPOSAL + "\n"))
    assert short == PROPOSAL


def test_the_rule_side_never_reads_the_message():
    """A host the agent's message names, and the call uses, is not request-named: the message is the agent's words."""
    raw = _raw(
        "yes",
        prior="The issue asks to mirror the tickets to mirror.helpdesk-sync.example. Shall I?",
        arguments={
            "command": "curl -s https://mirror.helpdesk-sync.example/import -d @tickets.json"
        },
    )
    p = _prepared(raw)
    host = p.entities.get(EntityKind.HOST, "mirror.helpdesk-sync.example")
    assert host is not None
    assert Origin.REQUEST not in host.origins
    assert "helpdesk-sync" not in p.request_words
    control = _prepared(
        _raw(
            "yes, mirror them to mirror.helpdesk-sync.example",
            prior=None,
            arguments=raw["pending_call"]["arguments"],
        )
    )
    assert (
        Origin.REQUEST
        in control.entities.get(EntityKind.HOST, "mirror.helpdesk-sync.example").origins
    )


def test_the_probe_shows_the_message_only_for_a_set_on_the_call_v8_view():
    p = _prepared(_raw())
    for name, expected in (("call-v11", None), ("call-v12", PROPOSAL)):
        jev = JevConfig(exposure_question_set="exposure-v2", call_question_set=name)
        state = JevCallProbe(FakeDecider(), jev).state_for(p)
        assert state["request"].get(PRIOR_AGENT_MESSAGE) == expected, name


def test_call_v12_reserves_call_v11s_largest_form_plus_the_block(v12):
    assert MEASURED_QUESTION_TOKENS[("call-v12", v12.sha[:12])] == 10_600
    assert question_reserve_tokens(v12) == 10_600
    assert set_state_budget_tokens(v12) == BUDGET_TOKENS - 10_600


def test_call_v12_is_the_default_and_the_earlier_sets_stay_selectable():
    assert ServeConfig().jev_call_question_set == "call-v12"
    assert ServeConfig.from_env({}).jev_call_question_set == "call-v12"
    for name in ("call-v10", "call-v11"):
        assert (
            ServeConfig.from_env({"SENTROOK_JEV_CALL_QUESTIONS": name}).jev_call_question_set
            == name
        )


@pytest.mark.parametrize("side", ["head", "tail"])
def test_a_placeholder_across_a_cut_point_is_kept_whole_or_left_out_whole(side):
    ph = "⟦secret:credential:ab12⟧"
    total = 5200
    head_cut = PRIOR_MESSAGE_CAP_CHARS // 3
    tail_cut = total - (PRIOR_MESSAGE_CAP_CHARS - head_cut)
    at = (head_cut if side == "head" else tail_cut) - 5
    msg = "a" * at + ph + "b" * (total - at - len(ph))
    cut = prior_agent_message(_raw(prior=msg))
    assert "characters cut]" in cut
    pieces = [cut[i:] for i in range(len(cut)) if cut[i] == "⟦"]
    assert all(p.startswith(ph) for p in pieces)
    assert "⟧" not in cut.replace(ph, "")
