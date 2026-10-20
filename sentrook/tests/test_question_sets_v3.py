"""call-v3: the call-v2 view plus the entity library's verdicts (`reputation`), filled by the call probe
from the oracle probe, which the scan runs first; and the call-v3 wording (keyword selections of a
different kind of item, agent-added content in a sent file). call-v2 and the v1 sets stay frozen."""

from __future__ import annotations

import copy

from test_converge_scan import BENIGN_ANSWERS, KEY, options
from test_jev_probes import ATTACK_ANSWERS, FakeDecider, prepared_for
from test_question_sets_v2 import V2_ANSWERS, harm_case  # noqa: F401 (fixture)

from sentrook.enums import ProbeStatus, ProbeStep
from sentrook.jev.client import JevConfig
from sentrook.jev.questions import load_question_set
from sentrook.prepare.views import CALL_V2, CALL_V3, REPUTATION, VIEW_KEYS, with_reputation
from sentrook.probes.jev import JevCallProbe
from sentrook.probes.oracle import verdicts_for_view
from sentrook.scan import Scanner, ScannerConfig
from sentrook.serve.config import ServeConfig

CALL_V3_KEYS = [*VIEW_KEYS[CALL_V2], REPUTATION]


def v3_config(**kw) -> JevConfig:
    return JevConfig(exposure_question_set="exposure-v2", call_question_set="call-v3", **kw)


def _scan(case, jev, answers=None, probes=None):
    dec = FakeDecider(answers or V2_ANSWERS)
    sc = Scanner(ScannerConfig(token_key=KEY, decider=dec, jev=jev))
    kw = {"probes_enabled": probes} if probes else {}
    res = sc.scan(case["fixture"], options(case, **kw))
    call_bodies = [b for b in dec.bodies if "pending_call" in b["state"]]
    return res, call_bodies


def test_call_v3_view_is_call_v2_plus_reputation(harm_case):  # noqa: F811
    p = prepared_for(harm_case)
    assert VIEW_KEYS[CALL_V3] == tuple(CALL_V3_KEYS)
    # prepared without verdicts: the same keys as call-v2 (the block is filled by the probe)
    assert list(p.views[CALL_V3]) == list(VIEW_KEYS[CALL_V2])
    assert p.views[CALL_V3] == p.views[CALL_V2]
    assert p.views_version[CALL_V3] == "trim-v3" and p.views_version[CALL_V2] == "trim-v2"
    assert p.oracle_verdicts == []
    state = with_reputation(p.views[CALL_V3], [])
    assert REPUTATION not in state
    state = with_reputation(
        p.views[CALL_V3], [{"kind": "host", "value": "a.example", "verdict": "known_good"}]
    )
    assert list(state) == CALL_V3_KEYS and state[REPUTATION][0]["verdict"] == "known_good"


def test_call_v3_derives_from_call_v2():
    c2, c3 = load_question_set("call-v2"), load_question_set("call-v3")
    assert c3.state_view == CALL_V3 and c3.sha != c2.sha
    assert list(c3.questions) == list(c2.questions)
    assert c3.preamble.startswith(c2.preamble) and "`reputation`" in c3.preamble
    for name in (
        "concealment",
        "sensitivity",
        "reach",
        "irreversibility",
        "self_modification",
        "action_category",
    ):
        assert c3.questions[name]["instructions"] == c2.questions[name]["instructions"]
        assert c3.questions[name]["criteria"] == c2.questions[name]["criteria"]
    sbr2, sbr3 = c2.questions["supported_by_request"], c3.questions["supported_by_request"]
    assert (
        sbr3["instructions"].startswith(sbr2["instructions"])
        and "`known_good`" in sbr3["instructions"]
    )
    assert sbr3["criteria"]["false"] == sbr2["criteria"]["false"]
    # draft 2: the scope question is call-v2 word for word (draft 1's two clauses were dropped)
    so2, so3 = c2.questions["scope_overreach"], c3.questions["scope_overreach"]
    assert so3["instructions"] == so2["instructions"] and so3["criteria"] == so2["criteria"]
    assert c3.levels("scope_overreach") == 3
    assert all(q["state_view"] == CALL_V3 for q in c3.questions.values())
    assert (
        c3.questions["untrusted_origin"]["criteria"]["true"]
        == c2.questions["untrusted_origin"]["criteria"]["true"]
    )


def test_verdicts_for_view_keeps_known_good_and_known_bad_sorted():
    from sentrook.probes.base import Envelope

    env = Envelope(
        step=ProbeStep.ENTITY_ORACLE,
        versions={},
        status=ProbeStatus.OK,
        latency_ms=0.0,
        evidence={
            "entities": {
                "E3": {
                    "kind": "host",
                    "value": "z.example",
                    "verdict": "known_good",
                    "tier": "org",
                },
                "E1": {"kind": "host", "value": "u.example", "verdict": "unknown"},
                "E2": {
                    "kind": "package",
                    "value": "left-pad",
                    "verdict": "known_bad",
                    "tier": None,
                },
            }
        },
    )
    assert verdicts_for_view(env) == [
        {"kind": "host", "value": "z.example", "verdict": "known_good", "tier": "org"},
        {"kind": "package", "value": "left-pad", "verdict": "known_bad"},
    ]
    failed = Envelope.failed(ProbeStep.ENTITY_ORACLE, ProbeStatus.ERROR, "down", {})
    assert verdicts_for_view(failed) == []


def test_scan_runs_the_oracle_first_and_the_call_probe_sends_the_verdicts(twin_case, attack_case):
    # The twin's backup host is known_good in the seed: the call body carries it under `reputation`.
    case = copy.deepcopy(twin_case)
    case["fixture"]["grants"] = []
    res, [body] = _scan(case, v3_config(), BENIGN_ANSWERS)
    state = body["state"]
    assert list(state) == CALL_V3_KEYS
    assert state[REPUTATION] == [
        {"kind": "host", "value": "backup.mycorp.com", "verdict": "known_good"}
    ]
    assert res.prepared.oracle_verdicts == state[REPUTATION]
    call_env = next(e for e in res.envelopes if e.step is ProbeStep.JEV_CALL)
    assert call_env.evidence["view"] == CALL_V3 and call_env.evidence["reputation_entries"] == 1
    assert res.response.metadata.versions["views"] == "exposure:trim-v2,call:trim-v3"
    assert res.prepared_views["views"]["call"] == CALL_V3

    # Nothing known about the attack's host: the key is absent and the body is the call-v2 state.
    res, [body] = _scan(attack_case, v3_config(), ATTACK_ANSWERS)
    assert REPUTATION not in body["state"] and list(body["state"]) == list(VIEW_KEYS[CALL_V2])

    # The oracle disabled: no verdicts, no block, the scan still completes.
    res, [body] = _scan(
        case, v3_config(), BENIGN_ANSWERS, probes=("jev_exposure", "jev_call", "context")
    )
    assert REPUTATION not in body["state"] and res.prepared.oracle_verdicts == []

    # call-v2 keeps its view even with a known_good host.
    res, [body] = _scan(
        case,
        JevConfig(exposure_question_set="exposure-v2", call_question_set="call-v2"),
        BENIGN_ANSWERS,
    )
    assert REPUTATION not in body["state"] and res.prepared.oracle_verdicts == []


def test_call_probe_on_call_v3_without_a_scan_sends_no_block(harm_case):  # noqa: F811
    p = prepared_for(harm_case)
    dec = FakeDecider(V2_ANSWERS)
    env = JevCallProbe(dec, v3_config()).run(p)
    assert env.status is ProbeStatus.OK
    [body] = dec.bodies
    assert REPUTATION not in body["state"]
    assert list(body["questions"]) == list(load_question_set("call-v3").questions)
    assert env.versions["question_set"] == "call-v3" and env.evidence["reputation_entries"] == 0


def test_call_v3_is_a_valid_call_question_set_for_the_server():
    cfg = ServeConfig.from_env({"SENTROOK_JEV_CALL_QUESTIONS": "call-v3"})
    assert cfg.jev_call_question_set == "call-v3"
    assert ServeConfig.from_env({}).jev_call_question_set == "call-v3"  # the shipped default
    assert (
        ServeConfig.from_env({"SENTROOK_JEV_CALL_QUESTIONS": "call-v2"}).jev_call_question_set
        == "call-v2"
    )
