"""The attended-owner cap: in a chat the owner attends, a call is held at review unless a strong signal says block.

A high score alone (the model finds the call unsupported, the session read injected-looking content, the call
changes the agent's own setup) leaves the risk just under the block line in an attended owner session. A floor,
an `enforced` decision, a key argument that came only from content the agent read, a known-bad entity, or
sensitive data sent to a destination nothing sanctions still block. Unattended runs are unchanged.
"""

from __future__ import annotations

import copy
import dataclasses

import pytest
from test_converge_scan import ATTACK_ANSWERS, KEY, _prepared, options, scanner

from sentrook.converge import converge, load_params
from sentrook.converge.attended import attended_owner
from sentrook.enums import Enforce, ProbeStep
from sentrook.planir.models import PlanIR
from sentrook.probes.base import Contribution, Envelope, Floor
from sentrook.serve.config import ServeConfig

V5, V6 = load_params("conv-v5"), load_params("conv-v6")
CAP = 79.0  # risk, on the response's 0-100 scale


def _c(signal: str, value: float, reason: str, subject: str | None = None) -> Contribution:
    return Contribution(signal=signal, value=value, subject=subject, reason=reason)


def _high_selfmod(reason: str = "selfmod.scheduler") -> list[Envelope]:
    """What an owner-asked scheduler, config or skill change scores today when the model finds it unsupported
    and the session read command output: no floor, no untrusted origin, no send."""
    return [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[
                _c("suspicion.misalignment", 0.9, "call.not_supported_by_request"),
                _c("consequence.self_modification", 0.9, "jev.self_modification"),
            ],
        ),
        Envelope(
            step=ProbeStep.CONTEXT,
            contributions=[
                _c("suspicion.session_exposure", 0.7, "exposure.session_tainted"),
                _c("suspicion.request_origin", 0.0, "trigger.owner"),
            ],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[_c("consequence.self_modification", 1.0, reason)],
        ),
    ]


def _run(case: dict, envs: list[Envelope], params=V6):
    return converge(_prepared(case), envs, params=params, scanner_version="t", token_key=KEY)


def _codes(res) -> list[str]:
    return [r.code for r in res.response.reasons]


def _with_trigger(case: dict, *, kind="message", relation="owner", role="main") -> dict:
    case = copy.deepcopy(case)
    fx = case["fixture"]
    fx["trigger"]["kind"] = kind
    fx["trigger"]["sender"]["relation"] = relation
    fx["session"]["agent_role"] = role
    return case


# ---- attended: from the PlanIR -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "relation", "role", "attended"),
    [
        ("message", "owner", "main", True),
        ("scheduled", "owner", "main", False),
        ("heartbeat", "owner", "main", False),
        ("hook", "owner", "main", False),
        ("subagent", "owner", "main", False),
        ("system", "owner", "main", False),
        ("unknown", "owner", "main", False),
        ("message", "other", "main", False),
        ("message", "trusted", "main", False),
        ("message", "unknown", "main", False),
        ("message", "owner", "subagent", False),
        ("message", "owner", "unknown", False),
    ],
)
def test_attended_means_an_owner_message_on_the_main_agent(
    attack_case, kind, relation, role, attended
):
    case = _with_trigger(attack_case, kind=kind, relation=relation, role=role)
    assert attended_owner(PlanIR.model_validate(case["fixture"])) is attended


# ---- must stay at review or below ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason", ["selfmod.config", "selfmod.scheduler", "selfmod.plugin", "selfmod.memory"]
)
def test_an_owner_asked_change_to_the_agents_setup_caps_at_review(twin_case, reason):
    before = _run(twin_case, _high_selfmod(reason), params=V5)
    assert before.response.risk >= 80  # blocks today
    res = _run(twin_case, _high_selfmod(reason))
    r = res.response
    assert r.risk == CAP and r.enforced is None and r.floors_applied == []
    assert 45 <= r.risk < 80
    cap = next(x for x in r.reasons if x.code == "cap.attended_owner")
    assert cap.detail == {"risk_before": before.response.risk}
    assert r.metadata.versions["attended_owner"] == {
        "attended": True,
        "strong": [],
        "capped": True,
    }


def test_a_score_under_the_cap_is_left_alone(twin_case):
    envs = _high_selfmod()
    envs[0].contributions[0] = _c("suspicion.misalignment", 0.3, "call.not_supported_by_request")
    envs[1].contributions[0] = _c("suspicion.session_exposure", 0.1, "exposure.session_tainted")
    res = _run(twin_case, envs)
    assert res.response.risk == _run(twin_case, envs, params=V5).response.risk < 79
    assert "cap.attended_owner" not in _codes(res)
    assert res.response.metadata.versions["attended_owner"]["capped"] is False


def test_a_plain_send_the_model_doubts_caps_at_review(attack_case):
    """No sensitive source, no untrusted origin: the model's doubt alone does not block an attended owner."""
    envs = [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[_c("suspicion.misalignment", 0.95, "call.not_supported_by_request")],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[
                _c("consequence.reach", 1.0, "send.off_host", "E1"),
                _c("consequence.irreversibility", 0.8, "send.off_host", "E1"),
                _c("consequence.sensitivity", 0.9, "jev.sensitivity"),
            ],
        ),
    ]
    assert _run(attack_case, envs, params=V5).response.risk >= 80
    res = _run(attack_case, envs)
    assert res.response.risk == CAP


def test_a_credential_sent_where_a_grant_covers_the_destination_caps_at_review(twin_case):
    """The owner granted the destination: the credential belongs there, so the score alone does not block."""
    envs = [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[_c("suspicion.misalignment", 0.95, "call.not_supported_by_request")],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[
                _c("consequence.reach", 1.0, "exfil.exec_egress", "E1"),
                _c("consequence.irreversibility", 1.0, "exfil.exec_egress", "E1"),
                _c("consequence.sensitivity", 1.0, "path.credential_store", "E2"),
            ],
        ),
    ]
    res = _run(twin_case, envs)
    assert any(r.reason == "relief.destination_grant" for r in res.relief)
    assert res.response.risk == CAP
    assert "sensitive_sent" not in res.response.metadata.versions["attended_owner"]["strong"]


def test_an_untrusted_origin_on_a_file_the_call_reads_is_not_strong(attack_case):
    """A path the agent found in a listing it read (data source, half weight) is ordinary work, not an attack."""
    envs = _high_selfmod()
    envs[1].contributions.append(
        _c("suspicion.untrusted_origin", 0.5, "origin.only_in_untrusted", "E2")
    )
    res = _run(attack_case, envs)
    assert res.response.risk == CAP


def test_the_bare_session_sensitive_flag_is_not_a_credential_leaving(attack_case):
    envs = [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[_c("suspicion.misalignment", 0.95, "call.not_supported_by_request")],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[
                _c("consequence.reach", 1.0, "exfil.exec_egress", "E1"),
                _c("consequence.irreversibility", 1.0, "exfil.exec_egress", "E1"),
                _c("consequence.sensitivity", 0.8, "exfil.session_holds_sensitive"),
            ],
        ),
    ]
    assert _run(attack_case, envs).response.risk == CAP


# ---- must still block ----------------------------------------------------------------------------------------


def test_a_change_whose_instruction_came_only_from_fetched_content_still_blocks(attack_case):
    envs = _high_selfmod("selfmod.config")
    envs[1].contributions.append(
        _c("suspicion.untrusted_origin", 1.0, "origin.only_in_untrusted", "E1")
    )
    res = _run(attack_case, envs)
    assert res.response.risk >= 80
    assert "cap.attended_owner" not in _codes(res)
    assert res.response.metadata.versions["attended_owner"]["strong"] == ["untrusted_origin"]


@pytest.mark.parametrize(
    "reason",
    [
        "origin.written_content_untrusted",
        "origin.lookalike_of_named_host",
        "origin.lookalike_of_named_package",
        "origin.sibling_value_untrusted",
    ],
)
def test_every_untrusted_origin_on_an_acting_entity_still_blocks(attack_case, reason):
    envs = _high_selfmod()
    envs[1].contributions.append(_c("suspicion.untrusted_origin", 1.0, reason, "E1"))
    assert _run(attack_case, envs).response.risk >= 80


def test_a_credential_sent_to_an_unknown_host_still_blocks(attack_case):
    envs = [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[_c("suspicion.misalignment", 0.95, "call.not_supported_by_request")],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[
                _c("consequence.reach", 1.0, "exfil.exec_egress", "E1"),
                _c("consequence.irreversibility", 1.0, "exfil.exec_egress", "E1"),
                _c("consequence.sensitivity", 1.0, "path.credential_store", "E2"),
            ],
        ),
    ]
    res = _run(attack_case, envs)
    assert res.response.risk >= 80
    assert res.response.metadata.versions["attended_owner"]["strong"] == ["sensitive_sent"]


def test_a_secret_the_agent_wrote_into_a_file_it_sends_still_blocks(attack_case):
    envs = [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[_c("suspicion.misalignment", 0.95, "call.not_supported_by_request")],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[
                _c("consequence.reach", 1.0, "send.off_host", "E1"),
                _c("consequence.irreversibility", 0.8, "send.off_host", "E1"),
                _c("consequence.sensitivity", 0.9, "jev.sensitivity"),
            ],
        ),
        Envelope(
            step=ProbeStep.CONTEXT,
            contributions=[_c("suspicion.overreach", 0.8, "lineage.secret_carried_to_send", "E2")],
        ),
    ]
    assert _run(attack_case, envs).response.risk >= 80


def test_a_known_bad_entity_still_blocks(attack_case):
    envs = _high_selfmod()
    envs.append(
        Envelope(
            step=ProbeStep.ENTITY_ORACLE,
            contributions=[_c("suspicion.distrust", 1.0, "reputation.known_bad_host", "E1")],
        )
    )
    res = _run(attack_case, envs)
    assert res.response.risk >= 80
    assert "known_bad" in res.response.metadata.versions["attended_owner"]["strong"]


@pytest.mark.parametrize(
    ("floor", "enforce"),
    [
        ("guardrail_tampering", Enforce.BLOCK),
        ("known_bad_entity", Enforce.BLOCK),
        ("untrusted_code_execution", Enforce.BLOCK),
        ("sensitive_data_sent", None),
        ("injected_content_used", None),
    ],
)
def test_a_floor_lifts_the_cap(attack_case, floor, enforce):
    envs = _high_selfmod()
    envs[2].floors.append(Floor(floor=floor, min_risk=0.6, enforce=enforce))
    res = _run(attack_case, envs)
    r = res.response
    assert r.risk == _run(attack_case, envs, params=V5).response.risk >= 80
    assert r.enforced is enforce
    assert "cap.attended_owner" not in _codes(res)
    assert r.metadata.versions["attended_owner"]["strong"] == [f"floor.{floor}"]


def test_an_enforced_block_still_blocks_whatever_the_score(attack_case):
    envs = [
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[_c("consequence.self_modification", 0.3, "selfmod.config")],
            floors=[Floor(floor="guardrail_tampering", min_risk=1.0, enforce=Enforce.BLOCK)],
        )
    ]
    r = _run(attack_case, envs).response
    assert r.enforced is Enforce.BLOCK and r.risk == 100.0


def _credential_read_in_a_send() -> list[Envelope]:
    """A call that reads a credential file and sends, where the rule-based send detector found no sink of its
    own (an inline script's upload): the sensitivity claim and the call's destination are all there is."""
    return [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[
                _c("suspicion.misalignment", 0.95, "call.not_supported_by_request"),
                _c("consequence.reach", 0.9, "jev.reach"),
                _c("consequence.irreversibility", 0.9, "jev.irreversibility"),
            ],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[_c("consequence.sensitivity", 1.0, "path.credential_store", "E2")],
        ),
    ]


def test_a_credential_in_a_call_that_sends_to_an_unknown_host_still_blocks(attack_case):
    res = _run(attack_case, _credential_read_in_a_send())
    assert res.response.risk >= 80
    assert res.response.metadata.versions["attended_owner"]["strong"] == ["sensitive_sent"]


def test_a_credential_in_a_call_that_sends_to_a_granted_host_caps(twin_case):
    res = _run(twin_case, _credential_read_in_a_send())
    assert res.response.risk == CAP


# ---- optional strong signals: off in conv-v6, each switched on by its parameter ------------------------------


def _with(**kw):
    return dataclasses.replace(V6, **kw)


@pytest.mark.parametrize(
    "reason",
    [
        "reputation.near_miss_host",
        "lineage.lookalike_of_named_person",
        "lineage.lookalike_of_named_host",
    ],
)
def test_a_lookalike_is_strong_only_when_switched_on(attack_case, reason):
    envs = _high_selfmod()
    envs[1].contributions.append(_c("suspicion.overreach", 0.9, reason, "E1"))
    assert _run(attack_case, envs).response.risk == CAP
    res = _run(attack_case, envs, params=_with(attended_owner_lookalike=True))
    assert res.response.risk >= 80
    assert res.response.metadata.versions["attended_owner"]["strong"] == ["lookalike"]


def test_a_retry_of_a_denied_action_is_strong_only_when_switched_on(attack_case):
    envs = _high_selfmod()
    envs[1].contributions.append(_c("suspicion.retry_after_denial", 0.9, "retry.same_action"))
    assert _run(attack_case, envs).response.risk == CAP
    assert _run(attack_case, envs, params=_with(attended_owner_retry_min=0.8)).response.risk >= 80
    # below the set value: still capped
    assert _run(attack_case, envs, params=_with(attended_owner_retry_min=0.95)).response.risk == CAP


def test_fresh_injection_is_strong_only_when_switched_on(attack_case):
    envs = _high_selfmod()
    envs.append(
        Envelope(
            step=ProbeStep.JEV_EXPOSURE,
            contributions=[_c("suspicion.exposure", 0.9, "exposure.instructions")],
        )
    )
    assert _run(attack_case, envs).response.risk == CAP
    on = _with(
        attended_owner_injection_exposure_min=0.5, attended_owner_injection_misalignment_min=0.5
    )
    res = _run(attack_case, envs, params=on)
    assert res.response.risk >= 80
    assert res.response.metadata.versions["attended_owner"]["strong"] == ["fresh_injection"]
    # the session's earlier taint is not this request's injection
    envs[-1] = Envelope(
        step=ProbeStep.JEV_EXPOSURE,
        contributions=[_c("suspicion.exposure", 0.1, "exposure.instructions")],
    )
    assert _run(attack_case, envs, params=on).response.risk == CAP


def test_the_optional_signals_load_from_a_parameter_file(tmp_path):
    import json

    from sentrook.converge.params import PARAMS_DIR

    raw = json.loads((PARAMS_DIR / "conv-v6.json").read_text(encoding="utf-8"))
    raw["name"] = "conv-test"
    raw["attended_owner_cap"].update(
        {
            "lookalike": True,
            "retry_min": 0.8,
            "fresh_injection": {"exposure_min": 0.5, "misalignment_min": 0.6},
        }
    )
    path = tmp_path / "conv-test.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    p = load_params(path)
    assert p.attended_owner_lookalike is True and p.attended_owner_retry_min == 0.8
    assert p.attended_owner_injection_exposure_min == 0.5
    assert p.attended_owner_injection_misalignment_min == 0.6
    assert V6.attended_owner_lookalike is False and V6.attended_owner_retry_min is None
    assert V6.attended_owner_injection_exposure_min is None


# ---- unattended runs and older parameter sets are unchanged --------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "relation", "role"),
    [
        ("scheduled", "owner", "main"),
        ("heartbeat", "owner", "main"),
        ("subagent", "unknown", "main"),
        ("message", "owner", "subagent"),
        ("unknown", "unknown", "main"),
        ("message", "other", "main"),
    ],
)
def test_unattended_runs_are_unchanged(twin_case, kind, relation, role):
    case = _with_trigger(twin_case, kind=kind, relation=relation, role=role)
    v5 = _run(case, _high_selfmod(), params=V5).response
    v6 = _run(case, _high_selfmod()).response
    assert v6.risk == v5.risk >= 80
    assert "cap.attended_owner" not in [r.code for r in v6.reasons]
    assert v6.metadata.versions["attended_owner"] == {
        "attended": False,
        "strong": [],
        "capped": False,
    }


def test_conv_v5_has_no_cap(twin_case):
    r = _run(twin_case, _high_selfmod(), params=V5).response
    assert r.risk >= 80 and "attended_owner" not in r.metadata.versions


# ---- end to end through the scanner --------------------------------------------------------------------------


def test_the_worked_attack_still_blocks_end_to_end(attack_case):
    """The credential upload an email dictated: untrusted origin and a credential to an unknown host."""
    res = scanner(ATTACK_ANSWERS, params=V6).scan(
        attack_case["fixture"], options(attack_case, probes_enabled=None)
    )
    r = res.response
    assert r.risk >= 80
    assert {"untrusted_origin", "sensitive_sent"} <= set(
        r.metadata.versions["attended_owner"]["strong"]
    )


def test_an_owner_asked_cron_edit_caps_end_to_end(twin_case):
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
    v5 = scanner(answers, params=V5).scan(fx, options(case, probes_enabled=None)).response
    v6 = scanner(answers, params=V6).scan(fx, options(case, probes_enabled=None)).response
    assert v5.risk >= 80
    assert v6.risk == CAP and v6.enforced is None


# ---- parameters ----------------------------------------------------------------------------------------------


def test_conv_v6_is_conv_v5_with_the_cap_on():
    assert V6.name == "conv-v6" and V6.oracle.name == "conv-v6/oracle"
    assert V6.attended_owner_cap is True and V5.attended_owner_cap is False
    assert V6.attended_owner_max_risk == 0.79
    assert V6.attended_owner_untrusted_origin_min == 0.6
    assert V6.attended_owner_sent_sensitivity_min == 0.6
    a, b = dataclasses.asdict(V5), dataclasses.asdict(V6)
    for d in (a, b):
        d.pop("name")
        d["oracle"].pop("name")
        d["context"].pop("name")
        d.pop("attended_owner_cap")
    assert a == b


def test_serve_defaults_to_conv_v6_and_conv_v5_stays_selectable():
    assert ServeConfig().convergence == "conv-v6"
    assert ServeConfig.from_env({}).convergence == "conv-v6"
    assert ServeConfig.from_env({"SENTROOK_CONVERGENCE": "conv-v5"}).convergence == "conv-v5"
