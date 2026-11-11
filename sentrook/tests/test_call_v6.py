"""call-v6: a destination a `destination` grant matches counts as one the owner named.

A send whose destination the request does not name, but which a destination grant covers (a channel the owner bound a
scheduled job to, its id read from the job's notes), was answered as not supported by the request. call-v6 is call-v5
with one clause in `supported_by_request`, and only there: a destination that matches a grant's pattern counts as
named, wherever the agent took its id from, and a destination the pattern does not match is not covered, however close
it looks. The view and the shared preamble are call-v5's, so every other question is sent exactly as before.
"""

from __future__ import annotations

from test_converge_scan import BENIGN_ANSWERS, KEY, options
from test_jev_probes import FakeDecider

from sentrook.jev.client import JevConfig
from sentrook.jev.questions import load_question_set
from sentrook.prepare.views import CALL_V5
from sentrook.scan import Scanner, ScannerConfig
from sentrook.serve.config import ServeConfig

ANCHOR = "the call must be traceable to what the owner said themselves or to a grant."
CLAUSE = (
    " A destination that matches the pattern of a `destination` grant counts as one the owner named, even when the"
    " request does not mention it and the agent took its id from a note or an earlier result. A destination the"
    " pattern does not match is not covered, however close it looks (a look-alike host, another domain or top-level"
    " domain, another account, address or id)."
)


def test_call_v6_is_call_v5_with_the_grant_clause():
    c5, c6 = load_question_set("call-v5"), load_question_set("call-v6")
    assert c5.state_view == c6.state_view == CALL_V5
    assert c6.preamble == c5.preamble
    assert list(c6.questions) == list(c5.questions)
    for name, q5 in c5.questions.items():
        q6 = c6.questions[name]
        if name == "supported_by_request":
            assert ANCHOR in q5["instructions"]
            assert q6["instructions"] == q5["instructions"].replace(ANCHOR, ANCHOR + CLAUSE)
            assert {k: v for k, v in q6.items() if k != "instructions"} == {
                k: v for k, v in q5.items() if k != "instructions"
            }
            continue
        assert q6 == q5, name


def _call_body(case, call_question_set):
    dec = FakeDecider(BENIGN_ANSWERS)
    jev = JevConfig(exposure_question_set="exposure-v2", call_question_set=call_question_set)
    Scanner(ScannerConfig(token_key=KEY, decider=dec, jev=jev)).scan(case["fixture"], options(case))
    [body] = [b for b in dec.bodies if "pending_call" in b["state"]]
    return body


def test_call_v6_sends_the_call_v5_state_and_only_the_clause_differs(twin_case):
    """The twin's call goes to a host its destination grant covers: the grants block is in the state either way, and the
    two bodies differ only in the clause."""
    b5, b6 = _call_body(twin_case, "call-v5"), _call_body(twin_case, "call-v6")
    assert b6["state"] == b5["state"]
    assert [g["kind"] for g in b6["state"]["grants"]] == ["destination"]
    q5, q6 = b5["questions"], b6["questions"]
    assert list(q6) == list(q5)
    for name in q5:
        if name == "supported_by_request":
            assert CLAUSE not in q5[name]["instructions"]
            assert q6[name]["instructions"] == q5[name]["instructions"].replace(
                ANCHOR, ANCHOR + CLAUSE
            )
        else:
            assert q6[name] == q5[name], name


def test_call_v6_is_the_shipped_default_and_earlier_sets_stay_selectable():
    assert ServeConfig.from_env({}).jev_call_question_set == "call-v6"
    for name in ("call-v3", "call-v4", "call-v5", "call-v6"):
        env = {"SENTROOK_JEV_CALL_QUESTIONS": name}
        assert ServeConfig.from_env(env).jev_call_question_set == name
