"""The `relaxable` mark: in every parameter set, a block on the score alone in a chat the owner attends is marked.

The mark is the attended-owner check without the ceiling: the owner attends the chat, the scan is fully informed,
no strong signal and no `enforced` decision. It changes no score. A plugin reads it only while the owner has
snoozed reviews, to turn such a block into a review it always asks about. Where a parameter set turns the
ceiling on, the ceiling is set exactly where the mark is.
"""

from __future__ import annotations

import copy
import json

import pytest
from test_attended_owner_cap import (
    _credential_upload,
    _high_selfmod,
    _judged,
    _run,
    _strong_origin,
    _with_trigger,
    decide,
)
from test_converge_scan import ATTACK_ANSWERS, KEY, _prepared, options, scanner

from sentrook.converge import converge, load_params
from sentrook.enums import Enforce, ProbeStatus, ProbeStep
from sentrook.probes.base import Contribution, Envelope, Floor
from sentrook.serve.config import ServeConfig

V5, V6, V7 = load_params("conv-v5"), load_params("conv-v6"), load_params("conv-v7")
DEFAULT = load_params(ServeConfig().convergence)
SETS = pytest.mark.parametrize("params", [V5, V6, V7], ids=lambda p: p.name)
NO_CEILING = pytest.mark.parametrize("params", [V5, V7], ids=lambda p: p.name)


def _c(signal: str, value: float, reason: str, subject: str | None = None) -> Contribution:
    return Contribution(signal=signal, value=value, subject=subject, reason=reason)


def _mark(res) -> bool | None:
    return res.response.relaxable


def assert_marked(case, envs, params) -> None:
    res = _run(case, envs, params)
    r = res.response
    assert r.relaxable is True and r.enforced is None
    assert res.response.metadata.versions["attended_owner"]["relaxable"] is True
    # the ceiling follows the mark only where the parameters turn it on
    assert r.ceiling == ("review" if params.attended_owner_cap else None)


def assert_unmarked(case, envs, params) -> None:
    res = _run(case, envs, params)
    assert res.response.relaxable is None and res.response.ceiling is None
    assert res.response.metadata.versions["attended_owner"]["relaxable"] is False


# ---- marked ---------------------------------------------------------------------------------------------------


@SETS
def test_an_owner_asked_setup_change_that_blocks_is_marked(twin_case, params):
    assert_marked(twin_case, _high_selfmod(), params)


@NO_CEILING
def test_the_mark_changes_no_score_and_no_verdict(twin_case, params):
    """Without the ceiling the response blocks as before: only a plugin under a snooze reads the mark."""
    r = _run(twin_case, _high_selfmod(), params).response
    assert r.relaxable is True and r.ceiling is None
    assert r.risk == _run(twin_case, _high_selfmod(), V6).response.risk >= 80
    assert decide(r) == "block"
    assert "cap.attended_owner" not in [x.code for x in r.reasons]


def test_the_serve_default_marks_without_a_ceiling(twin_case):
    assert DEFAULT.attended_owner_cap is False
    assert_marked(twin_case, _high_selfmod(), DEFAULT)


@SETS
def test_a_credential_sent_where_a_grant_covers_the_destination_is_marked(twin_case, params):
    assert_marked(twin_case, _credential_upload(), params)


# ---- not marked: not attended ---------------------------------------------------------------------------------


@SETS
@pytest.mark.parametrize(
    ("kind", "relation", "role"),
    [
        ("scheduled", "owner", "main"),
        ("heartbeat", "owner", "main"),
        ("hook", "owner", "main"),
        ("subagent", "unknown", "main"),
        ("message", "owner", "subagent"),
        ("message", "other", "main"),
        ("unknown", "unknown", "main"),
    ],
)
def test_an_unattended_run_is_not_marked(twin_case, params, kind, relation, role):
    case = _with_trigger(twin_case, kind=kind, relation=relation, role=role)
    assert_unmarked(case, _high_selfmod(), params)


@SETS
@pytest.mark.parametrize("basis", [["group_chat"], ["host_open_access"]])
def test_a_group_chat_or_open_host_is_not_marked(attack_case, params, basis):
    assert_unmarked(_with_trigger(attack_case, basis=basis), _high_selfmod(), params)


@SETS
def test_a_self_edit_is_not_marked(attack_case, params):
    case = copy.deepcopy(attack_case)
    case["fixture"]["self_edit"] = {"kind": "memory_review", "store": "memory", "conversation": []}
    assert_unmarked(case, _high_selfmod(), params)


@SETS
def test_an_unrecognised_channel_is_not_marked(attack_case, params):
    case = copy.deepcopy(attack_case)
    case["fixture"]["trigger"]["channel"] = "other"
    assert_unmarked(case, _high_selfmod(), params)


# ---- not marked: a strong signal ------------------------------------------------------------------------------


def _plus(envs: list[Envelope], idx: int, contribution: Contribution) -> list[Envelope]:
    envs[idx].contributions.append(contribution)
    return envs


STRONG = {
    "untrusted_origin": lambda: _strong_origin(),
    "known_bad": lambda: [
        *_high_selfmod(),
        Envelope(
            step=ProbeStep.ENTITY_ORACLE,
            contributions=[_c("suspicion.distrust", 1.0, "reputation.known_bad_host", "E1")],
        ),
    ],
    "steered_code": lambda: _plus(
        _high_selfmod(), 2, _c("consequence.sensitivity", 0.8, "code.steered_source", "E1")
    ),
    "injected_content": lambda: _plus(
        _high_selfmod(),
        2,
        _c("consequence.sensitivity", 0.8, "exposure.session_injected_content", "E1"),
    ),
    "pushed_secret": lambda: _plus(
        _high_selfmod(), 2, _c("consequence.sensitivity", 0.8, "artefact.push_with_secret", "E1")
    ),
    "lookalike": lambda: _plus(
        _high_selfmod(), 1, _c("suspicion.overreach", 0.9, "reputation.near_miss_host", "E1")
    ),
    "code_lookalike": lambda: _plus(
        _high_selfmod(), 1, _c("suspicion.overreach", 0.9, "code.lookalike_provider", "E1")
    ),
    "retry": lambda: _plus(
        _high_selfmod(), 1, _c("suspicion.retry_after_denial", 0.8, "retry.same_action")
    ),
}


@SETS
@pytest.mark.parametrize("signal", list(STRONG))
def test_a_strong_signal_is_not_marked(attack_case, params, signal):
    assert_unmarked(attack_case, STRONG[signal](), params)


@SETS
def test_a_credential_sent_to_an_unknown_host_is_not_marked(attack_case, params):
    assert_unmarked(attack_case, _credential_upload(), params)


@SETS
@pytest.mark.parametrize(
    ("floor", "enforce"),
    [
        ("guardrail_tampering", Enforce.BLOCK),
        ("known_bad_entity", Enforce.BLOCK),
        ("sensitive_data_sent", None),
        ("injected_content_used", None),
        ("lookalike_code_source", None),
    ],
)
def test_a_floor_or_an_enforced_decision_is_not_marked(attack_case, params, floor, enforce):
    envs = _high_selfmod()
    envs[2].floors.append(Floor(floor=floor, min_risk=0.6, enforce=enforce))
    res = _run(attack_case, envs, params)
    assert res.response.enforced is enforce
    assert_unmarked(attack_case, envs, params)


# ---- not marked: a scan that is not fully informed ------------------------------------------------------------


@SETS
@pytest.mark.parametrize("step", [ProbeStep.CONTEXT, ProbeStep.AIRA, ProbeStep.JEV_CALL])
def test_a_failed_probe_is_not_marked(attack_case, params, step):
    envs = _high_selfmod()
    idx = next(i for i, e in enumerate(envs) if e.step is step)
    envs[idx] = Envelope.failed(step, ProbeStatus.ERROR, "down")
    assert_unmarked(attack_case, envs, params)


@SETS
def test_an_unavailable_oracle_is_not_marked(attack_case, params):
    envs = [*_high_selfmod(), Envelope(step=ProbeStep.ENTITY_ORACLE, evidence={"available": False})]
    assert_unmarked(attack_case, envs, params)


@SETS
@pytest.mark.parametrize("status", [ProbeStatus.SKIPPED, ProbeStatus.ERROR])
def test_a_disabled_or_failed_oracle_is_not_marked(attack_case, params, status):
    envs = [*_high_selfmod(), Envelope.failed(ProbeStep.ENTITY_ORACLE, status, "off")]
    assert_unmarked(attack_case, envs, params)
    res = _run(attack_case, envs, params)
    assert "oracle_unavailable" in res.response.metadata.versions["attended_owner"]["withheld"]


@SETS
def test_unjudged_new_content_is_not_marked(attack_case, params):
    envs = [
        *_high_selfmod(),
        Envelope.failed(ProbeStep.JEV_EXPOSURE, ProbeStatus.SKIPPED, "not configured"),
    ]
    assert_unmarked(attack_case, envs, params)


@SETS
def test_a_degraded_scan_is_not_marked(attack_case, params):
    from sentrook.prepare import CoverageNote

    prepared = _prepared(attack_case)
    prepared.coverage.append(CoverageNote(code="content_dropped", detail="test"))
    res = converge(
        prepared, _judged(_high_selfmod()), params=params, scanner_version="t", token_key=KEY
    )
    assert res.response.status.value == "degraded" and res.response.relaxable is None


@SETS
def test_a_lost_session_state_is_not_marked(attack_case, params):
    from sentrook.state.token import TokenStatus

    prepared = _prepared(attack_case)
    prepared.state.status = TokenStatus.STALE
    res = converge(
        prepared, _judged(_high_selfmod()), params=params, scanner_version="t", token_key=KEY
    )
    assert res.response.relaxable is None


# ---- end to end -----------------------------------------------------------------------------------------------


def _cron_edit(twin_case: dict) -> tuple[dict, dict]:
    case = copy.deepcopy(twin_case)
    fx = case["fixture"]
    fx["request"]["text"] = "Take a look at the scheduled job and make sure it is set up correctly"
    fx["new_inputs"] = []
    fx["history"] = []
    fx["session"]["step"] = 1
    fx["grants"] = []
    fx["pending_call"]["arguments"] = {
        "command": "openclaw cron edit nightly-digest --every 6h",
        "cwd": "~/workspace",
    }
    answers = {
        **ATTACK_ANSWERS,
        "exposure_instructions": {"type": "noul", "noul": 0.05},
        "self_modification": {"type": "noul", "noul": 0.95},
    }
    return case, answers


@SETS
def test_an_owner_asked_cron_change_in_attended_chat_is_marked_end_to_end(twin_case, params):
    case, answers = _cron_edit(twin_case)
    r = scanner(answers, params=params).scan(case["fixture"], options(case, probes_enabled=None))
    r = r.response
    assert r.relaxable is True and r.enforced is None and r.risk >= 80
    assert json.loads(r.model_dump_json())["relaxable"] is True
    if not params.attended_owner_cap:
        assert r.ceiling is None and decide(r) == "block"


@SETS
def test_the_same_cron_change_on_a_scheduled_run_is_not_marked_end_to_end(twin_case, params):
    case, answers = _cron_edit(twin_case)
    case["fixture"]["trigger"]["kind"] = "scheduled"
    r = scanner(answers, params=params).scan(case["fixture"], options(case, probes_enabled=None))
    assert r.response.relaxable is None
    assert json.loads(r.response.model_dump_json())["relaxable"] is None


@SETS
def test_the_worked_attack_is_not_marked_end_to_end(attack_case, params):
    res = scanner(ATTACK_ANSWERS, params=params).scan(
        attack_case["fixture"], options(attack_case, probes_enabled=None)
    )
    assert res.response.relaxable is None and decide(res.response) == "block"
