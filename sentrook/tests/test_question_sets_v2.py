"""The question-set pass: the `trim-v2` views (`call-v2` with the turn's inputs, `exposure-v2`), the second
redaction pass on them, the `exposure-v2` and `call-v2` question sets, `suspicion.overreach`, and the
configuration that selects them. The v1 views and question sets stay frozen (see test_jev_probes.py).

The scenario is invented: an owner asks clawbot to tidy a task list, the agent lists the tasks, and the
pending call deletes all of them. Secret-shaped values are built at runtime from low-entropy parts."""

from __future__ import annotations

import copy

import httpx
import pytest
from test_jev_probes import ATTACK_ANSWERS, FakeDecider, prepared_for

from sentrook.converge import converge, load_params
from sentrook.converge.registry import REASONS, SIGNALS
from sentrook.enums import ProbeStatus, ProbeStep
from sentrook.jev.client import JevConfig
from sentrook.jev.questions import build_body, load_question_set
from sentrook.prepare.redact import PLACEHOLDER
from sentrook.prepare.views import (
    CALL,
    CALL_INPUT_CAP_CHARS,
    CALL_INPUTS_TOTAL_CAP_CHARS,
    CALL_V2,
    EXPOSURE,
    EXPOSURE_V2,
    call_view,
    call_view_v2,
    cap_inputs,
    exposure_view,
)
from sentrook.probes.base import Contribution, Envelope
from sentrook.probes.jev import JevCallProbe, JevExposureProbe
from sentrook.response.models import SuspicionTier
from sentrook.scan import Scanner, ScannerConfig, ScanOptions, views_label
from sentrook.serve.config import ServeConfig
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import ScanServer

KEY = "unit-test-state-key-" * 2  # 40 chars, low entropy on purpose
FAKE_TOKEN = "ghp_" + "x" * 36
LISTING = (
    "1 [done] renew the clawbot test certificate\n"
    "2 [open] Q4 board deck (shared with the finance team)\n"
    "3 [open] tenant move-in checklist for unit 4B\n"
    f"note: deploy token {FAKE_TOKEN}\n"
)
SCOPE_ANSWER = {
    "type": "score",
    "score": 1.6,
    "probabilities": {"0": 0.1, "1": 0.2, "2": 0.7},
    "confidence": 0.75,
}
V2_ANSWERS = {**ATTACK_ANSWERS, "scope_overreach": SCOPE_ANSWER}
CALL_V2_KEYS = [
    "planir_version",
    "host",
    "session",
    "trigger",
    "request",
    "history",
    "new_inputs",
    "pending_call",
    "grants",
]


@pytest.fixture
def harm_case(attack_case) -> dict:
    case = copy.deepcopy(attack_case)
    fx = case["fixture"]
    fx["request"]["text"] = "Clean up my task list"
    fx["new_inputs"][0]["content"] = LISTING
    fx["new_inputs"][0]["size_bytes"] = len(LISTING)
    fx["pending_call"]["agent_narration"] = "Clearing the list."
    fx["pending_call"]["arguments"] = {"command": "todo delete --all", "cwd": "~/workspace"}
    return case


def v2_config(**kw) -> JevConfig:
    return JevConfig(exposure_question_set="exposure-v2", call_question_set="call-v2", **kw)


# --------------------------------------------------------------------------- views


def test_call_v2_view_adds_the_inputs_between_history_and_pending_call(harm_case):
    p = prepared_for(harm_case)
    raw = harm_case["fixture"]
    state = p.views[CALL_V2]
    assert list(state) == CALL_V2_KEYS
    [inp] = state["new_inputs"]
    assert "call_id" not in inp and inp["input_seq"] == 1 and "scanner_truncated" not in inp
    # the v1 views are untouched: no inputs in `call`, no redaction in either
    assert p.views[CALL] == call_view(raw) and "new_inputs" not in p.views[CALL]
    assert p.views[EXPOSURE] == exposure_view(raw, only_input_seqs={1})
    assert FAKE_TOKEN in p.views[EXPOSURE]["new_inputs"][0]["content"]
    assert p.views_version == {
        EXPOSURE: "trim-v1",
        CALL: "trim-v1",
        EXPOSURE_V2: "trim-v2",
        CALL_V2: "trim-v2",
    }


def test_v2_views_carry_the_second_redaction_pass(harm_case):
    p = prepared_for(harm_case)
    for name in (CALL_V2, EXPOSURE_V2):
        content = p.views[name]["new_inputs"][0]["content"]
        assert FAKE_TOKEN not in content and f"deploy token {PLACEHOLDER}" in content
        assert p.view_meta[name]["redactions"] == 1
    assert p.view_meta[CALL]["redactions"] == 0 and p.redactions == 2
    assert FAKE_TOKEN in harm_case["fixture"]["new_inputs"][0]["content"]  # raw never mutated


def _inputs_raw(attack_case, sizes: list[int]) -> dict:
    raw = copy.deepcopy(attack_case["fixture"])
    template = raw["new_inputs"][0]
    raw["new_inputs"] = []
    for seq, size in enumerate(sizes, start=1):
        entry = copy.deepcopy(template)
        entry["input_seq"] = seq
        entry["content"] = chr(ord("a") + seq) * size
        raw["new_inputs"].append(entry)
    return raw


def test_call_v2_caps_each_input_and_the_total(attack_case):
    sizes = [100, 6000, 6000, 6000, 6000, 6000, 6000, 6000, 7000, 50]
    built = call_view_v2(_inputs_raw(attack_case, sizes))
    inputs = built.state["new_inputs"]
    assert built.inputs_truncated and not built.inputs_stripped
    assert inputs[8]["scanner_truncated"] == {"kept_chars": CALL_INPUT_CAP_CHARS, "of_chars": 7000}
    assert len(inputs[8]["content"]) == CALL_INPUT_CAP_CHARS
    assert "scanner_truncated" not in inputs[9] and len(inputs[9]["content"]) == 50
    kept = [len(i["content"]) for i in inputs]
    assert sum(kept) == CALL_INPUTS_TOTAL_CAP_CHARS
    # the latest inputs keep their content, the earliest lose theirs first; metadata stays
    assert kept == [0, 0, 3950, 6000, 6000, 6000, 6000, 6000, 6000, 50]
    assert inputs[0]["scanner_truncated"] == {"kept_chars": 0, "of_chars": 100}
    assert inputs[1]["scanner_truncated"] == {"kept_chars": 0, "of_chars": 6000}
    assert inputs[2]["scanner_truncated"] == {"kept_chars": 3950, "of_chars": 6000}
    assert all("scanner_truncated" not in i for i in inputs[3:8])
    assert all(i["input_seq"] == n for n, i in enumerate(inputs, start=1))


def test_total_cap_empties_only_the_earliest_input(attack_case):
    inputs = _inputs_raw(attack_case, [5000, 6000, 6000])["new_inputs"]
    assert cap_inputs(inputs, total=12_000)
    assert [len(i["content"]) for i in inputs] == [0, 6000, 6000]
    assert inputs[0]["scanner_truncated"] == {"kept_chars": 0, "of_chars": 5000}
    assert all("scanner_truncated" not in i for i in inputs[1:])
    assert [i["input_seq"] for i in inputs] == [1, 2, 3]
    # recency follows `input_seq`, not list position
    shuffled = _inputs_raw(attack_case, [5000, 6000, 6000])["new_inputs"][::-1]
    assert cap_inputs(shuffled, total=12_000)
    assert [(i["input_seq"], len(i["content"])) for i in shuffled] == [(3, 6000), (2, 6000), (1, 0)]


def test_call_v2_strips_every_content_when_still_over_budget(attack_case):
    built = call_view_v2(_inputs_raw(attack_case, [500, 800]), budget_tokens=100)
    assert built.inputs_stripped and built.inputs_truncated
    assert [i["content"] for i in built.state["new_inputs"]] == ["", ""]
    assert [i["scanner_truncated"]["of_chars"] for i in built.state["new_inputs"]] == [500, 800]


def test_small_inputs_are_not_cut(harm_case):
    p = prepared_for(harm_case)
    assert p.view_meta[CALL_V2] == {
        "redactions": 1,
        "inputs_truncated": False,
        "inputs_stripped": False,
    }


# --------------------------------------------------------------------------- question sets


def test_question_sets_v2_derive_from_v1():
    e1, e2 = load_question_set("exposure-v1"), load_question_set("exposure-v2")
    assert e2.state_view == EXPOSURE_V2 and e2.preamble == e1.preamble
    assert e2.built_questions() == e1.built_questions()  # same body questions, same cache key
    c1, c2 = load_question_set("call-v1"), load_question_set("call-v2")
    assert c2.state_view == CALL_V2
    assert list(c2.questions) == [
        "supported_by_request",
        "untrusted_origin",
        "scope_overreach",
        "concealment",
        "sensitivity",
        "reach",
        "irreversibility",
        "self_modification",
        "action_category",
    ]
    assert c2.preamble.startswith(c1.preamble.split(" `grants` are")[0])
    assert "Use `new_inputs` to see what the pending call's targets" in c2.preamble
    for name in ("concealment", "self_modification", "action_category"):
        assert c2.built_questions()[name]["instructions"].endswith(
            c1.questions[name]["instructions"]
        )
        assert c2.questions[name]["criteria"] == c1.questions[name]["criteria"]
    # supported_by_request keeps the v1 wording and adds the rule that pointing at a document does
    # not make its instructions the owner's (draft 2 of the live dev pass)
    assert (
        c1.questions["supported_by_request"]["instructions"]
        in c2.questions["supported_by_request"]["instructions"]
    )
    assert (
        "does not make that content's instructions the owner's"
        in c2.questions["supported_by_request"]["instructions"]
    )
    assert (
        c2.questions["supported_by_request"]["criteria"]["true"]
        == c1.questions["supported_by_request"]["criteria"]["true"]
    )
    assert c2.questions["supported_by_request"]["criteria"]["false"].startswith(
        c1.questions["supported_by_request"]["criteria"]["false"].rstrip(".")
    )
    assert (
        c2.questions["untrusted_origin"]["criteria"] == c1.questions["untrusted_origin"]["criteria"]
    )
    assert c2.questions["sensitivity"]["instructions"].startswith(
        c1.questions["sensitivity"]["instructions"]
    )
    assert c2.levels("scope_overreach") == 3 and c2.levels("sensitivity") == 4
    for name in ("sensitivity", "reach", "irreversibility"):
        assert c2.questions[name]["criteria"][0] == c1.questions[name]["criteria"][0]
    assert all(q["state_view"] == CALL_V2 for q in c2.questions.values())


# --------------------------------------------------------------------------- probes


def test_call_probe_on_call_v2_sends_the_inputs_and_maps_overreach(harm_case):
    p = prepared_for(harm_case)
    dec = FakeDecider(V2_ANSWERS)
    env = JevCallProbe(dec, v2_config()).run(p)
    assert env.status is ProbeStatus.OK
    [body] = dec.bodies
    assert body["state"] == p.views[CALL_V2] and list(body["state"]) == CALL_V2_KEYS
    assert list(body["questions"]) == list(load_question_set("call-v2").questions)
    by = {c.signal: c for c in env.contributions}
    assert abs(by["suspicion.overreach"].value - 0.8) < 1e-9  # 1.6 / (3 - 1)
    assert by["suspicion.overreach"].reason == "jev.scope_overreach"
    certainty = (0.9 + 0.95 + 0.8 + 0.7 + 0.85 + 0.75) / 6
    assert abs(by["confidence.model_certainty"].value - certainty) < 1e-9
    assert env.versions["question_set"] == "call-v2"
    ev = env.evidence
    assert ev["view"] == CALL_V2 and ev["views_version"] == "trim-v2" and ev["redactions"] == 1
    assert ev["inputs_truncated"] is False and ev["inputs_stripped"] is False
    assert ev["p_level_ge_2"]["scope_overreach"] == 0.7


def test_call_v1_needs_no_scope_answer(harm_case):
    p = prepared_for(harm_case)
    env = JevCallProbe(FakeDecider(ATTACK_ANSWERS), JevConfig()).run(p)
    assert env.status is ProbeStatus.OK
    assert "suspicion.overreach" not in {c.signal for c in env.contributions}
    assert env.evidence["view"] == CALL and env.evidence["views_version"] == "trim-v1"
    assert "inputs_truncated" not in env.evidence

    class NoScope(FakeDecider):
        def decide(self, body, *, repeat=None):
            res = super().decide(body, repeat=repeat)
            res.response["answers"].pop("scope_overreach", None)
            return res

    env = JevCallProbe(NoScope(), v2_config()).run(p)
    assert env.status is ProbeStatus.ERROR and "scope_overreach" in env.evidence["error"]


def test_exposure_probe_on_exposure_v2(attack_case, harm_case):
    # nothing to redact: the body is byte-identical to exposure-v1's, so the cache key does not move
    p = prepared_for(attack_case)
    d1, d2 = FakeDecider(ATTACK_ANSWERS), FakeDecider(ATTACK_ANSWERS)
    JevExposureProbe(d1, JevConfig()).run(p)
    env = JevExposureProbe(d2, v2_config()).run(p)
    assert d1.bodies == d2.bodies and env.status is ProbeStatus.OK
    assert env.evidence["view"] == EXPOSURE_V2 and env.evidence["redactions"] == 0
    # a secret the plugin missed: only the redacted bytes differ
    p = prepared_for(harm_case)
    dec = FakeDecider(ATTACK_ANSWERS)
    env = JevExposureProbe(dec, v2_config()).run(p)
    content = dec.bodies[0]["state"]["new_inputs"][0]["content"]
    assert FAKE_TOKEN not in content and PLACEHOLDER in content
    assert env.evidence["redactions"] == 1 and env.evidence["views_version"] == "trim-v2"


def test_a_view_that_was_not_prepared_is_an_error_not_a_raise(harm_case):
    p = prepared_for(harm_case)
    del p.views[CALL_V2], p.views[EXPOSURE_V2]
    for probe in (JevCallProbe, JevExposureProbe):
        dec = FakeDecider(V2_ANSWERS)
        env = probe(dec, v2_config()).run(p)
        assert env.status is ProbeStatus.ERROR and "not prepared" in env.evidence["error"]
        assert dec.bodies == []


# --------------------------------------------------------------------------- scan and convergence


def _scan(case, jev: JevConfig, probes=None):
    sc = Scanner(ScannerConfig(token_key=KEY, decider=FakeDecider(V2_ANSWERS), jev=jev))
    opts = ScanOptions(
        deterministic=True,
        salt="testnest",
        state_seed=case["state_seed"],
        oracle_seed=case["oracle_seed"],
        probes_enabled=probes,
    )
    return sc.scan(case["fixture"], opts)


def test_scan_reports_the_views_it_used(harm_case):
    res = _scan(harm_case, v2_config())
    pv = res.prepared_views
    assert list(pv["jev_call_state"]) == CALL_V2_KEYS
    assert pv["views"] == {"exposure": EXPOSURE_V2, "call": CALL_V2}
    assert pv["views_version"] == {"exposure": "trim-v2", "call": "trim-v2"}
    assert pv["redaction"] == {
        "version": "redact-v2",
        "shapes": "1;gitleaks=v8.30.1",
        "count": 2,
    }
    r = res.response
    assert r.metadata.versions["views"] == "trim-v2"
    assert r.tree.suspicion.overreach == 0.8
    assert any(x.code == "jev.scope_overreach" for x in r.reasons)
    # the configured views are reported even when the Jev probes did not run
    res = _scan(harm_case, v2_config(), probes=("aira", "context"))
    assert list(res.prepared_views["jev_call_state"]) == CALL_V2_KEYS
    assert res.prepared_views["views"]["call"] == CALL_V2


def test_scan_defaults_stay_on_trim_v1(harm_case):
    res = _scan(harm_case, JevConfig())
    pv = res.prepared_views
    assert pv["views"] == {"exposure": EXPOSURE, "call": CALL}
    assert pv["views_version"] == {"exposure": "trim-v1", "call": "trim-v1"}
    assert pv["redaction"] == {
        "version": "redact-v2",
        "shapes": "1;gitleaks=v8.30.1",
        "count": 0,
    }
    assert "new_inputs" not in pv["jev_call_state"]
    assert res.response.metadata.versions["views"] == "trim-v1"
    assert res.response.tree.suspicion.overreach is None
    mixed = {"exposure": EXPOSURE, "call": CALL_V2}
    assert views_label(mixed) == "exposure:trim-v1,call:trim-v2"


def test_overreach_is_registered_and_feeds_suspicion(harm_case):
    spec = SIGNALS["suspicion.overreach"]
    assert spec.tier == "suspicion" and spec.higher_is_worse
    assert "jev.scope_overreach" in REASONS
    assert "overreach" in SuspicionTier.model_json_schema()["properties"]

    def run(overreach: float | None):
        contribs = [
            Contribution(signal="consequence.reach", value=0.8, reason="jev.reach"),
            Contribution(signal="consequence.sensitivity", value=0.7, reason="jev.sensitivity"),
        ]
        if overreach is not None:
            contribs.append(
                Contribution(
                    signal="suspicion.overreach", value=overreach, reason="jev.scope_overreach"
                )
            )
        env = Envelope(step=ProbeStep.JEV_CALL, contributions=contribs)
        return converge(
            prepared_for(harm_case),
            [env],
            params=load_params(),
            scanner_version="t",
            token_key=KEY,
        ).tiers

    assert run(None).suspicion == 0.0
    t = run(0.6)
    assert abs(t.suspicion - 0.6) < 1e-9 and run(0.9).risk > t.risk
    # model-only: one probe's claim is never a split
    assert t.agreement == 1.0 and t.disagreements == []


# --------------------------------------------------------------------------- configuration


def test_question_set_env_round_trip_and_health():
    cfg = ServeConfig.from_env(
        {
            "SENTROOK_JEV_EXPOSURE_QUESTIONS": "exposure-v2",
            "SENTROOK_JEV_CALL_QUESTIONS": "call-v2",
        }
    )
    assert cfg.jev_exposure_question_set == "exposure-v2" and cfg.jev_call_question_set == "call-v2"
    default = ServeConfig.from_env({})
    assert (default.jev_exposure_question_set, default.jev_call_question_set) == (
        "exposure-v1",
        "call-v1",
    )
    runtime = ServeRuntime.build(
        ServeConfig(
            state_key=KEY,
            jev_exposure_question_set="exposure-v2",
            jev_call_question_set="call-v2",
        ),
        decider=FakeDecider(V2_ANSWERS),
    )
    assert runtime.scanner.config.jev.call_question_set == "call-v2"
    srv = ScanServer(runtime, host="127.0.0.1", port=0)
    srv.start()
    try:
        jev = httpx.get(srv.url + "/healthz").json()["jev"]
    finally:
        srv.stop()
    assert jev["question_sets"] == {"exposure": "exposure-v2", "call": "call-v2"}
    assert jev["views"] == {"exposure": EXPOSURE_V2, "call": CALL_V2}


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("SENTROOK_JEV_CALL_QUESTIONS", "call-v9", "unknown question set"),
        ("SENTROOK_JEV_EXPOSURE_QUESTIONS", "nope", "unknown question set"),
        ("SENTROOK_JEV_EXPOSURE_QUESTIONS", "call-v2", "not a exposure view"),
        ("SENTROOK_JEV_CALL_QUESTIONS", "exposure-v1", "not a call view"),
    ],
)
def test_bad_question_set_names_stop_startup(key, value, message):
    with pytest.raises(RuntimeError, match=message):
        ServeConfig.from_env({key: value})


def test_bodies_on_v2_keep_the_runner_shape(harm_case):
    p = prepared_for(harm_case)
    body = build_body(load_question_set("call-v2"), p.views[CALL_V2], model="m", provider={})
    assert set(body) == {"model", "state", "questions", "provider"}
    assert all("state_view" not in q for q in body["questions"].values())
