"""Jev routes: every failed call is classed (the provider refused us, rate limited us, or is down), and a second,
OpenAI-compatible route can answer behind the same typed-answer interface.

The default (`primary` mode) behaves exactly as a scanner wired straight to the Decisions API. A fallback mode hands
only its own failure class to the secondary. A secondary reply that is not the typed answer degrades the scan.
"""

from __future__ import annotations

import dataclasses
import json
import re

import httpx
import pytest
from test_converge_scan import options
from test_jev_health import API_KEY, KEY
from test_jev_probes import ATTACK_ANSWERS, FakeDecider

from sentrook.enums import ScanStatus
from sentrook.jev.client import (
    CONTEXT_LIMIT,
    INVALID,
    OK,
    OUTAGE,
    PROVIDER_REJECTED,
    RATE_LIMITED,
    ApiError,
    DecisionResult,
    InvalidAnswer,
    classify_failure,
)
from sentrook.jev.health import JevHealth, TrackedDecider
from sentrook.jev.questions import load_question_set
from sentrook.jev.routing import (
    MODE_FALLBACK_ON_OUTAGE,
    MODE_FALLBACK_ON_REJECTED,
    MODE_PRIMARY,
    MODE_SECONDARY,
    RoutedDecider,
)
from sentrook.jev.secondary import (
    ChatCompletionsClient,
    SecondaryConfig,
    answer_schema,
    chat_body,
    typed_answers,
)
from sentrook.scan import Scanner
from sentrook.serve.config import ConfigError, ServeConfig
from sentrook.serve.runtime import ServeRuntime
from sentrook.serve.server import ScanServer

SECONDARY_URL = "http://10.0.0.9:8000/v1"
SECONDARY_MODEL = "open-judge-test"


def _rejected(status: int = 403) -> ApiError:
    return ApiError(status, '{"error":{"message":"refused"}}')


def _outage() -> ApiError:
    return ApiError(503, "service unavailable")


def _timeout() -> ApiError:
    return ApiError(None, "timeout: ReadTimeout('timed out')")


class Recorder:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    def __call__(self, route: str, outcome: str) -> None:
        self.calls.append((route, outcome))


def _route_config(mode: str, **kw) -> ServeConfig:
    return ServeConfig(
        state_key=KEY,
        test_mode=True,
        scan_auth_mode="open",
        jev_api_key=API_KEY,
        jev_route=mode,
        jev_secondary_base_url=SECONDARY_URL,
        jev_secondary_model=SECONDARY_MODEL,
        **kw,
    )


def _scan(runtime: ServeRuntime, case: dict):
    return runtime.scanner.scan(case["fixture"], options(case))


def _jev_versions(result) -> dict[str, dict]:
    return {p.step: p.versions for p in result.response.metadata.probes if p.step.startswith("jev")}


# --- classification ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "outcome"),
    [
        (ApiError(401, "User not found."), PROVIDER_REJECTED),
        (ApiError(402, "Insufficient credits"), PROVIDER_REJECTED),
        (ApiError(403, "forbidden"), PROVIDER_REJECTED),
        (ApiError(451, "unavailable for legal reasons"), PROVIDER_REJECTED),
        (ApiError(404, "model not found"), PROVIDER_REJECTED),
        (ApiError(400, "bad request"), PROVIDER_REJECTED),
        (ApiError(429, "rate limited"), RATE_LIMITED),
        (ApiError(500, "boom"), OUTAGE),
        (ApiError(502, "bad gateway"), OUTAGE),
        (ApiError(503, "unavailable"), OUTAGE),
        (ApiError(524, "timeout at the edge"), OUTAGE),
        (ApiError(529, "overloaded"), OUTAGE),
        (ApiError(499, "client closed request"), OUTAGE),
        (ApiError(None, "timeout: ReadTimeout('timed out')"), OUTAGE),
        (ApiError(None, "ConnectError('connection refused')"), OUTAGE),
        (ApiError(400, '{"error":"max_tokens_exceeded"}'), CONTEXT_LIMIT),
        (InvalidAnswer("invalid answer: no answers object"), INVALID),
        (ValueError("Expecting value"), INVALID),
    ],
)
def test_each_failure_is_classed(exc, outcome):
    assert classify_failure(exc) == outcome


def test_invalid_answer_is_not_a_timeout():
    assert InvalidAnswer("invalid answer: timeout field missing").timeout is False


# --- routing modes -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "primary_error", "answered_by", "calls"),
    [
        # fallback on outage: outages fall back, refusals and rate limits do not
        (MODE_FALLBACK_ON_OUTAGE, None, "primary", [("primary", OK)]),
        (
            MODE_FALLBACK_ON_OUTAGE,
            _outage(),
            "secondary",
            [("primary", OUTAGE), ("secondary", OK)],
        ),
        (
            MODE_FALLBACK_ON_OUTAGE,
            _timeout(),
            "secondary",
            [("primary", OUTAGE), ("secondary", OK)],
        ),
        (MODE_FALLBACK_ON_OUTAGE, _rejected(), None, [("primary", PROVIDER_REJECTED)]),
        (MODE_FALLBACK_ON_OUTAGE, ApiError(429, "slow down"), None, [("primary", RATE_LIMITED)]),
        # fallback on provider refusal: refusals fall back, outages do not
        (
            MODE_FALLBACK_ON_REJECTED,
            _rejected(402),
            "secondary",
            [("primary", PROVIDER_REJECTED), ("secondary", OK)],
        ),
        (
            MODE_FALLBACK_ON_REJECTED,
            _rejected(451),
            "secondary",
            [("primary", PROVIDER_REJECTED), ("secondary", OK)],
        ),
        (MODE_FALLBACK_ON_REJECTED, _outage(), None, [("primary", OUTAGE)]),
        (
            MODE_FALLBACK_ON_REJECTED,
            ApiError(400, '{"error":"max_tokens_exceeded"}'),
            None,
            [("primary", CONTEXT_LIMIT)],
        ),
        # secondary only: the primary is never called
        (MODE_SECONDARY, None, "secondary", [("secondary", OK)]),
        (MODE_SECONDARY, _rejected(), "secondary", [("secondary", OK)]),
    ],
)
def test_modes_route_to_the_right_decider(mode, primary_error, answered_by, calls):
    primary = FakeDecider(ATTACK_ANSWERS, error=primary_error)
    secondary = FakeDecider(ATTACK_ANSWERS)
    seen = Recorder()
    router = RoutedDecider(primary, secondary, mode=mode, observer=seen)
    body = {"questions": {"q": {"type": "noul"}}}
    if answered_by is None:
        with pytest.raises(ApiError) as info:
            router.decide(body)
        assert info.value is primary_error
        assert secondary.bodies == []
    else:
        result = router.decide(body)
        assert result.route == answered_by
    assert seen.calls == calls
    assert len(primary.bodies) == (0 if mode == MODE_SECONDARY else 1)


def test_fallback_that_also_fails_raises_the_primary_error():
    primary_error = _rejected(401)
    seen = Recorder()
    router = RoutedDecider(
        FakeDecider(error=primary_error),
        FakeDecider(error=_outage()),
        mode=MODE_FALLBACK_ON_REJECTED,
        observer=seen,
    )
    with pytest.raises(ApiError) as info:
        router.decide({"questions": {}})
    assert info.value is primary_error
    assert seen.calls == [("primary", PROVIDER_REJECTED), ("secondary", OUTAGE)]


def test_router_refuses_a_mode_without_a_secondary():
    with pytest.raises(ValueError):
        RoutedDecider(FakeDecider(), None, mode=MODE_FALLBACK_ON_OUTAGE)
    with pytest.raises(ValueError):
        RoutedDecider(FakeDecider(), FakeDecider(), mode="round_robin")


def test_fallback_answer_keeps_the_scan_ok_and_records_the_route(attack_case):
    runtime = ServeRuntime.build(
        _route_config(MODE_FALLBACK_ON_REJECTED),
        decider=FakeDecider(error=_rejected(403)),
        secondary=FakeDecider(ATTACK_ANSWERS),
    )
    res = _scan(runtime, attack_case)
    assert res.response.status is ScanStatus.OK
    versions = _jev_versions(res)
    assert versions and all(v["route"] == "secondary" for v in versions.values())
    assert runtime.jev_health.snapshot()["state"] == "ok"
    jev = runtime.health_payload()["jev"]
    assert jev["route"] == MODE_FALLBACK_ON_REJECTED
    assert jev["secondary"] == {"model": SECONDARY_MODEL, "key_configured": False}


def test_primary_answer_in_a_fallback_mode_is_recorded_as_primary(attack_case):
    runtime = ServeRuntime.build(
        _route_config(MODE_FALLBACK_ON_OUTAGE),
        decider=FakeDecider(ATTACK_ANSWERS),
        secondary=FakeDecider(ATTACK_ANSWERS),
    )
    versions = _jev_versions(_scan(runtime, attack_case))
    assert versions and all(v["route"] == "primary" for v in versions.values())


# --- the default is unchanged ------------------------------------------------------------------------------


def _strip_latency(obj):
    if isinstance(obj, dict):
        return {k: _strip_latency(v) for k, v in obj.items() if k != "latency_ms"}
    if isinstance(obj, list):
        return [_strip_latency(v) for v in obj]
    return obj


@pytest.mark.parametrize(
    "error", [None, _rejected(401), _outage(), _timeout(), ApiError(429, "slow down")]
)
def test_default_config_behaves_as_a_scanner_wired_straight_to_the_decisions_api(
    attack_case, error
):
    config = ServeConfig(state_key=KEY, test_mode=True, scan_auth_mode="open", jev_api_key=API_KEY)
    assert config.jev_route == MODE_PRIMARY
    routed = FakeDecider(ATTACK_ANSWERS, error=error)
    runtime = ServeRuntime.build(config, decider=routed)
    # the wiring before a second route existed: the decider behind the health tracker, nothing between
    direct = FakeDecider(ATTACK_ANSWERS, error=error)
    before = Scanner(
        dataclasses.replace(
            runtime.scanner.config,
            decider=TrackedDecider(direct, JevHealth(key_configured=True)),
        )
    )
    got = _scan(runtime, attack_case)
    want = before.scan(attack_case["fixture"], options(attack_case))
    assert json.dumps(_strip_latency(got.response.model_dump(mode="json")), sort_keys=True) == (
        json.dumps(_strip_latency(want.response.model_dump(mode="json")), sort_keys=True)
    )
    assert routed.bodies == direct.bodies and routed.repeats == direct.repeats
    assert all("route" not in v for v in _jev_versions(got).values())
    assert "route" not in runtime.health_payload()["jev"]


def test_primary_mode_passes_results_and_errors_through_untouched():
    result = DecisionResult({"answers": {}}, 1.0)

    class Fixed:
        def decide(self, body, *, repeat=None):
            return result

    assert RoutedDecider(Fixed()).decide({}) is result
    assert result.route is None
    error = _rejected(402)
    with pytest.raises(ApiError) as info:
        RoutedDecider(FakeDecider(error=error)).decide({"questions": {}})
    assert info.value is error


# --- the OpenAI-compatible secondary -----------------------------------------------------------------------


def _questions() -> dict:
    return load_question_set("call-v11").built_questions(None)


def _good_reply(questions: dict) -> dict:
    out = {}
    for name, q in questions.items():
        if q["type"] == "noul":
            out[name] = {"answer": 0.1, "confidence": 0.9}
        elif q["type"] == "score":
            out[name] = {"answer": len(q["criteria"]) - 1, "confidence": 0.8}
        else:
            out[name] = {"answer": next(iter(q["criteria"])), "confidence": 0.7}
    return {"answers": out}


def _chat_response(content) -> dict:
    return {
        "model": SECONDARY_MODEL,
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def _client(handler, **kw) -> ChatCompletionsClient:
    client = ChatCompletionsClient(
        SecondaryConfig(base_url=SECONDARY_URL, model=SECONDARY_MODEL, retries=1, **kw)
    )
    client._http = httpx.Client(base_url=SECONDARY_URL, transport=httpx.MockTransport(handler))
    return client


def test_secondary_turns_a_valid_reply_into_the_typed_answer():
    questions = _questions()
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=_chat_response(json.dumps(_good_reply(questions))))

    res = _client(handler).decide({"model": "x", "state": {"a": 1}, "questions": questions})
    assert set(res.answers) == set(questions)
    assert res.answers["supported_by_request"] == {"type": "noul", "noul": 0.1}
    reach = res.answers["reach"]
    top = len(questions["reach"]["criteria"]) - 1
    assert reach == {
        "type": "score",
        "score": float(top),
        "probabilities": {str(top): 1.0},
        "confidence": 0.8,
    }
    assert res.answers["action_category"]["type"] == "choice"
    assert res.model == SECONDARY_MODEL
    body = sent[0]
    assert body["model"] == SECONDARY_MODEL and "provider" not in body
    schema = body["response_format"]["json_schema"]["schema"]
    assert schema == answer_schema(questions)
    assert set(schema["properties"]["answers"]["required"]) == set(questions)
    assert json.loads(body["messages"][1]["content"])["state"] == {"a": 1}


def test_unstructured_secondary_sends_no_schema_but_is_still_validated():
    body = chat_body(
        SecondaryConfig(base_url=SECONDARY_URL, model=SECONDARY_MODEL, structured=False),
        {"state": {}, "questions": _questions()},
    )
    assert "response_format" not in body


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: "not json at all",
        lambda r: json.dumps({"verdict": "fine"}),
        lambda r: json.dumps({"answers": {k: v for k, v in r["answers"].items() if k != "reach"}}),
        lambda r: json.dumps(
            {"answers": {**r["answers"], "reach": {"answer": 99, "confidence": 1}}}
        ),
        lambda r: json.dumps(
            {"answers": {**r["answers"], "concealment": {"answer": 1.5, "confidence": 1}}}
        ),
        lambda r: json.dumps(
            {"answers": {**r["answers"], "supported_by_request": {"answer": 2, "confidence": 1}}}
        ),
        lambda r: json.dumps(
            {"answers": {**r["answers"], "supported_by_request": {"answer": True, "confidence": 1}}}
        ),
        lambda r: json.dumps(
            {"answers": {**r["answers"], "action_category": {"answer": "x", "confidence": 1}}}
        ),
        lambda r: json.dumps(
            {"answers": {**r["answers"], "reach": {"answer": 1, "confidence": 7}}}
        ),
        lambda r: None,
    ],
)
def test_secondary_rejects_a_reply_that_is_not_the_typed_answer(mutate):
    questions = _questions()

    def handler(request):
        return httpx.Response(200, json=_chat_response(mutate(_good_reply(questions))))

    with pytest.raises(InvalidAnswer):
        _client(handler).decide({"state": {}, "questions": questions})


def test_secondary_non_json_body_is_invalid():
    with pytest.raises(InvalidAnswer):
        _client(lambda req: httpx.Response(200, text="<html>")).decide(
            {"state": {}, "questions": _questions()}
        )


def test_typed_answers_ignores_unasked_extras_but_needs_every_asked_question():
    questions = {"q": {"type": "noul", "criteria": {"true": "a", "false": "b"}}}
    out = typed_answers(questions, {"answers": {"q": {"answer": 0.5, "confidence": 1}, "x": 1}})
    assert out == {"q": {"type": "noul", "noul": 0.5}}


@pytest.mark.parametrize("mode", [MODE_SECONDARY, MODE_FALLBACK_ON_OUTAGE])
def test_invalid_secondary_output_degrades_the_scan(attack_case, mode):
    seen: list[str] = []

    def handler(request):
        seen.append("call")
        return httpx.Response(200, json=_chat_response("I think it is fine."))

    secondary = _client(handler)
    primary = FakeDecider(error=_outage())
    runtime = ServeRuntime.build(_route_config(mode), decider=primary, secondary=secondary)
    res = _scan(runtime, attack_case)
    assert seen, "the secondary was asked"
    assert res.response.status is ScanStatus.DEGRADED
    statuses = {p.step: p.status.value for p in res.response.metadata.probes}
    assert statuses["jev_call"] == "error"


def test_valid_secondary_output_scores_the_scan(attack_case):
    def handler(request):
        questions = json.loads(json.loads(request.content)["messages"][1]["content"])["questions"]
        return httpx.Response(200, json=_chat_response(json.dumps(_good_reply(questions))))

    runtime = ServeRuntime.build(
        _route_config(MODE_SECONDARY),
        decider=FakeDecider(error=_rejected()),
        secondary=_client(handler),
    )
    res = _scan(runtime, attack_case)
    assert res.response.status is ScanStatus.OK
    call = _jev_versions(res)["jev_call"]
    assert call["route"] == "secondary" and call["model"] == SECONDARY_MODEL


# --- configuration -----------------------------------------------------------------------------------------


def test_config_defaults_to_primary_and_reads_the_secondary_keys(tmp_path):
    base = {"SENTROOK_STATE_KEY": KEY}
    assert ServeConfig.from_env(base).jev_route == MODE_PRIMARY
    key = tmp_path / "secondary_key"
    key.write_text("sk-secondary-test\n", encoding="utf-8")
    cfg = ServeConfig.from_env(
        {
            **base,
            "SENTROOK_JEV_ROUTE": "Fallback_On_Outage",
            "SENTROOK_JEV_SECONDARY_BASE_URL": SECONDARY_URL,
            "SENTROOK_JEV_SECONDARY_MODEL": SECONDARY_MODEL,
            "SENTROOK_JEV_SECONDARY_API_KEY_FILE": str(key),
            "SENTROOK_JEV_SECONDARY_TIMEOUT_MS": "45000",
            "SENTROOK_JEV_SECONDARY_STRUCTURED": "0",
        }
    )
    assert cfg.jev_route == MODE_FALLBACK_ON_OUTAGE
    assert (cfg.jev_secondary_base_url, cfg.jev_secondary_model) == (SECONDARY_URL, SECONDARY_MODEL)
    assert cfg.jev_secondary_api_key == "sk-secondary-test"
    assert cfg.jev_secondary_timeout_s == 45.0 and cfg.jev_secondary_structured is False


def test_config_refuses_an_unknown_mode_or_a_mode_without_a_secondary():
    with pytest.raises(ConfigError, match="SENTROOK_JEV_ROUTE"):
        ServeConfig.from_env({"SENTROOK_STATE_KEY": KEY, "SENTROOK_JEV_ROUTE": "both"})
    with pytest.raises(ConfigError, match="SECONDARY_BASE_URL"):
        ServeConfig.from_env({"SENTROOK_STATE_KEY": KEY, "SENTROOK_JEV_ROUTE": "secondary"})


def test_secondary_settings_alone_change_nothing():
    cfg = ServeConfig.from_env(
        {"SENTROOK_STATE_KEY": KEY, "SENTROOK_JEV_SECONDARY_BASE_URL": SECONDARY_URL}
    )
    assert cfg.jev_route == MODE_PRIMARY


# --- metrics -----------------------------------------------------------------------------------------------


def _calls(text: str, route: str, outcome: str) -> float:
    m = re.search(
        rf'^sentrook_jev_calls_total\{{outcome="{outcome}",route="{route}"\}} (\S+)$',
        text,
        re.MULTILINE,
    )
    assert m, f"sentrook_jev_calls_total{{route={route},outcome={outcome}}} not exported"
    return float(m.group(1))


def test_metrics_tell_a_provider_refusal_from_an_outage(attack_case):
    cfg = ServeConfig(state_key=KEY, test_mode=True, scan_auth_mode="open", jev_api_key=API_KEY)
    srv = ScanServer(
        ServeRuntime.build(cfg, decider=FakeDecider(error=_rejected(403))), host="127.0.0.1", port=0
    )
    srv.start()
    try:
        with httpx.Client(base_url=srv.url) as c:
            text = c.get("/metrics").text
            before = {o: _calls(text, "primary", o) for o in (PROVIDER_REJECTED, OUTAGE)}
            c.post("/scan", json=attack_case["fixture"])
            text = c.get("/metrics").text
            assert _calls(text, "primary", PROVIDER_REJECTED) > before[PROVIDER_REJECTED]
            assert _calls(text, "primary", OUTAGE) == before[OUTAGE]
    finally:
        srv.stop()


def test_secondary_only_mode_needs_no_primary_key():
    runtime = ServeRuntime.build(
        ServeConfig(
            state_key=KEY,
            test_mode=True,
            scan_auth_mode="open",
            jev_route=MODE_SECONDARY,
            jev_secondary_base_url=SECONDARY_URL,
            jev_secondary_model=SECONDARY_MODEL,
        ),
        decider=FakeDecider(error=_rejected(401)),
        secondary=FakeDecider(ATTACK_ANSWERS),
    )
    assert runtime.jev_health.key_configured is True
