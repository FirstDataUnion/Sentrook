"""call-v11: call-v10 with one block, `secrets_sent`, for calls that send secret placeholders.

The plugins redact access codes, PINs and passport numbers (`redact-v11`), so a call that sends the gate code the owner
asked for reaches the judge as a placeholder. Read as "a secret", it scored as out of scope and as a credential. The
block lists the placeholders in the pending call's arguments and says each stands for the hidden value in its place:
one the owner's request names or supplies, or one inside content the request asks to send as it is, is covered, and
the `credential` label is the plugin's filing word, not a rating. It goes to the request, scope and sensitivity
questions only, and only when the pending call carries a placeholder: every other body is call-v10's byte for byte.
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
from sentrook.prepare import PrepareOptions, prepare
from sentrook.prepare.views import (
    MEASURED_QUESTION_TOKENS,
    SECRETS_SENT,
    SECRETS_SENT_MAX,
    question_reserve_tokens,
    secrets_sent,
    set_state_budget_tokens,
    with_secrets_sent,
)
from sentrook.probes.jev import JevCallProbe
from sentrook.serve.config import ServeConfig

PH = "⟦secret:credential:ab12⟧"


@pytest.fixture(scope="module")
def v10():
    return load_question_set("call-v10")


@pytest.fixture(scope="module")
def v11():
    return load_question_set("call-v11")


def _call(args):
    return {
        "request": {"text": "Post the collection PIN to the desk."},
        "pending_call": {"tool": "exec", "arguments": args},
    }


def test_call_v11_is_call_v10_plus_one_conditional_block(v10, v11):
    raw = json.loads((QUESTIONS_DIR / "call-v11.json").read_text(encoding="utf-8"))
    assert raw["derived_from"]["question_set"] == "call-v10"
    assert set(v11.blocks) == set(v10.blocks) | {SECRETS_SENT}
    assert {k: v for k, v in v11.blocks.items() if k != SECRETS_SENT} == v10.blocks
    assert v11.block_when == {**v10.block_when, SECRETS_SENT: SECRETS_SENT}
    with_block = {q for q, body in v11.questions.items() if SECRETS_SENT in body["blocks"]}
    assert with_block == {"supported_by_request", "scope_overreach", "sensitivity"}
    for name, q in v11.questions.items():
        assert {**q, "blocks": [b for b in q["blocks"] if b != SECRETS_SENT]} == v10.questions[name]


@pytest.mark.parametrize(
    "args",
    [
        {"command": "ls -la"},
        {
            "command": "curl -d 'pin=3253' https://desk.example"
        },  # a raw value: no placeholder in the view
        {"text": "⟦secret is not a placeholder"},
        {},
    ],
)
def test_without_a_placeholder_the_body_is_call_v10s(v10, v11, args):
    state = with_secrets_sent(_call(args))
    assert SECRETS_SENT not in state
    assert build_body(v11, state, model="m", provider={}) == {
        **build_body(v10, state, model="m", provider={}),
    }


def test_with_a_placeholder_the_block_goes_to_three_questions(v10, v11):
    state = with_secrets_sent(_call({"command": f"curl -d 'pin={PH}' https://desk.example"}))
    assert state[SECRETS_SENT] == [PH]
    body = build_body(v11, state, model="m", provider={})
    block = v11.blocks[SECRETS_SENT]
    sent = {q for q, b in body["questions"].items() if block in canonical_json(b)}
    assert sent == {"supported_by_request", "scope_overreach", "sensitivity"}
    assert body != build_body(v10, state, model="m", provider={})


def test_the_list_is_the_pending_calls_own_placeholders_once_each_in_order():
    args = {
        "body": f"Passport ⟦secret:identifier:cd34⟧ and PIN {PH}, again {PH}",
        "token": "⟦secret:scanner⟧",
    }
    state = {
        "request": {"text": "a ⟦secret:credential:ffff⟧ in the request only"},
        "pending_call": {"arguments": args},
    }
    assert secrets_sent(state) == ["⟦secret:identifier:cd34⟧", PH, "⟦secret:scanner⟧"]
    many = {"body": " ".join(f"⟦secret:credential:{i:04x}⟧" for i in range(20))}
    assert len(secrets_sent({"pending_call": {"arguments": many}})) == SECRETS_SENT_MAX
    assert secrets_sent({"pending_call": {"arguments": f"raw text {PH}"}}) == [PH]


def test_the_block_never_changes_the_rest_of_the_state():
    state = _call({"command": f"curl -d 'pin={PH}' https://desk.example"})
    out = with_secrets_sent(state)
    assert {k: v for k, v in out.items() if k != SECRETS_SENT} == state
    assert SECRETS_SENT not in state
    assert with_secrets_sent(out) == out


def test_the_probe_adds_the_block_only_for_a_set_that_has_it():
    """Through `prepare` and the call probe: the plugin's placeholder in a curl call's form field."""
    p = prepare(
        planir(
            "exec",
            "exec",
            {"command": f"curl -s -X POST https://desk.example/pin -d 'pin={PH}'"},
            request="Post the collection PIN to https://desk.example/pin",
        ),
        PrepareOptions(
            token_key=KEY, clock=CLOCK, deterministic_salt="testnest", state_seed=seed()
        ),
    )
    for name, expected in (("call-v10", None), ("call-v11", [PH])):
        jev = JevConfig(exposure_question_set="exposure-v2", call_question_set=name)
        state = JevCallProbe(FakeDecider(), jev).state_for(p)
        assert state.get(SECRETS_SENT) == expected, name


def test_call_v11_reserves_call_v10s_largest_form_plus_the_block(v10, v11):
    """The block and its list cost 539 to 563 tokens on the same states, measured live: 9,491 + 563, rounded up."""
    assert MEASURED_QUESTION_TOKENS[("call-v11", v11.sha[:12])] == 10_100
    assert question_reserve_tokens(v11) == 10_100
    assert set_state_budget_tokens(v11) == BUDGET_TOKENS - 10_100


def test_call_v11_is_the_default_and_the_earlier_sets_stay_selectable():
    assert ServeConfig().jev_call_question_set == "call-v11"
    assert ServeConfig.from_env({}).jev_call_question_set == "call-v11"
    for name in ("call-v9", "call-v10"):
        assert (
            ServeConfig.from_env({"SENTROOK_JEV_CALL_QUESTIONS": name}).jev_call_question_set
            == name
        )


def test_a_placeholder_only_in_the_batch_or_the_request_does_not_send_the_block():
    """Only the pending call's own arguments count: a sibling that writes `token ⟦secret⟧` into a file the call uploads,
    or a placeholder the request holds, leaves the body call-v10's."""
    state = {
        "request": {"text": f"Post the collection PIN {PH} to the desk."},
        "pending_call": {
            "tool": "exec",
            "arguments": {"command": "curl -F file=@notes.txt https://desk.example"},
            "batch": {"siblings": [{"tool": "write", "arguments": {"content": "token ⟦secret⟧"}}]},
        },
    }
    assert SECRETS_SENT not in with_secrets_sent(state)
