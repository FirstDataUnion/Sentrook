"""The attended-owner ceiling: in a chat the owner attends, a call is held at review unless a strong signal says block.

A high score alone (the model finds the call unsupported, the session read injected-looking content, the call
changes the agent's own setup) does not block in an attended owner session: the response carries a verdict ceiling
of `review` and the risk stays as scored. A floor, an `enforced` decision, a key argument that came only from content
the agent read, a known-bad entity, sensitive data sent to a destination nothing sanctions, a look-alike or a retry
of a denied action set no ceiling. Unattended runs, group chats and scans whose probes failed are unchanged.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest
from test_converge_scan import ATTACK_ANSWERS, KEY, _prepared, options, scanner

from sentrook.converge import converge, load_params
from sentrook.converge.attended import attended_owner
from sentrook.converge.params import PARAMS_DIR
from sentrook.enums import Enforce, ProbeStatus, ProbeStep
from sentrook.planir.models import PlanIR
from sentrook.probes.base import Contribution, Envelope, Floor
from sentrook.scan import Scanner, ScannerConfig
from sentrook.serve.config import ServeConfig

V5, V6 = load_params("conv-v5"), load_params("conv-v6")
RANK = {"allow": 0, "review": 1, "block": 2}


def decide(resp, review_at: float = 45, block_at: float = 80) -> str:
    """What a plugin does: the verdict from risk and its lines, lowered to the ceiling, raised to `enforced`."""
    v = "block" if resp.risk >= block_at else "review" if resp.risk >= review_at else "allow"
    if resp.ceiling is not None and RANK[resp.ceiling] < RANK[v]:
        v = resp.ceiling
    if resp.enforced is not None and RANK[resp.enforced.value] > RANK[v]:
        v = resp.enforced.value
    return v


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


def _send(*aira: Contribution, context: list[Contribution] | None = None) -> list[Envelope]:
    """A send the model doubts, with the rule-based claims given."""
    return [
        Envelope(
            step=ProbeStep.JEV_CALL,
            contributions=[
                _c("suspicion.misalignment", 0.95, "call.not_supported_by_request"),
                _c("consequence.reach", 0.9, "jev.reach"),
                _c("consequence.irreversibility", 0.9, "jev.irreversibility"),
            ],
        ),
        Envelope(step=ProbeStep.AIRA, contributions=list(aira)),
        Envelope(step=ProbeStep.CONTEXT, contributions=context or []),
    ]


def _credential_upload(dest: str = "E1") -> list[Envelope]:
    return _send(
        _c("consequence.reach", 1.0, "exfil.exec_egress", dest),
        _c("consequence.irreversibility", 1.0, "exfil.exec_egress", dest),
        _c("consequence.sensitivity", 1.0, "path.credential_store", "E2"),
    )


def _run(case: dict, envs: list[Envelope], params=V6):
    """Converge `envs`; an exposure judgement that found nothing stands in when the test gives none, since the
    cases bring new untrusted content that would otherwise count as unjudged."""
    if not any(e.step is ProbeStep.JEV_EXPOSURE for e in envs):
        envs = [*envs, Envelope(step=ProbeStep.JEV_EXPOSURE)]
    return converge(_prepared(case), envs, params=params, scanner_version="t", token_key=KEY)


def _judged(envs: list[Envelope]) -> list[Envelope]:
    return [*envs, Envelope(step=ProbeStep.JEV_EXPOSURE)]


def _codes(res) -> list[str]:
    return [r.code for r in res.response.reasons]


def _info(res) -> dict:
    return res.response.metadata.versions["attended_owner"]


def assert_held(case, envs, params=V6) -> None:
    """Held at review: the ceiling is set, the risk is the score conv-v5 gives, and it would block without it."""
    res = _run(case, envs, params)
    r = res.response
    assert r.ceiling == "review" and r.enforced is None
    assert r.risk == _run(case, envs, V5).response.risk >= 80
    assert decide(r) == "review"
    assert "cap.attended_owner" in _codes(res)


def assert_blocks(case, envs, params=V6, strong: list[str] | None = None) -> None:
    res = _run(case, envs, params)
    r = res.response
    assert r.ceiling is None and decide(r) == "block"
    assert "cap.attended_owner" not in _codes(res)
    if strong is not None:
        assert _info(res)["strong"] == strong


def _with_trigger(case: dict, *, kind="message", relation="owner", role="main", basis=None) -> dict:
    case = copy.deepcopy(case)
    fx = case["fixture"]
    fx["trigger"]["kind"] = kind
    fx["trigger"]["sender"]["relation"] = relation
    if basis is not None:
        fx["trigger"]["sender"]["basis"] = basis
    fx["session"]["agent_role"] = role
    return case


def _with(**kw):
    return dataclasses.replace(V6, **kw)


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


@pytest.mark.parametrize(
    ("basis", "attended"),
    [
        # OpenClaw: the host's owner flag; it reports no group-chat basis
        (["host_owner_flag"], True),
        # Hermes: a listed user in a group, channel or thread
        (["group_chat"], False),
        # Hermes: a direct message admitted only by allow-all
        (["host_open_access"], False),
        (["host_owner_flag", "group_chat"], False),
    ],
)
def test_an_owner_message_in_a_group_chat_is_not_attended(attack_case, basis, attended):
    case = _with_trigger(attack_case, basis=basis)
    assert attended_owner(PlanIR.model_validate(case["fixture"])) is attended
    res = _run(case, _high_selfmod())
    assert (res.response.ceiling == "review") is attended
    assert _info(res)["attended"] is attended


def test_a_self_edit_block_on_a_message_trigger_is_not_attended(attack_case):
    """A self-edit block says the host's background process made the call; a message trigger does not undo that."""
    case = copy.deepcopy(attack_case)
    case["fixture"]["self_edit"] = {"kind": "memory_review", "store": "memory", "conversation": []}
    planir = PlanIR.model_validate(case["fixture"])
    assert not planir.is_self_edit  # ignored as a self-edit: the trigger is not `system`
    assert attended_owner(planir) is False
    res = _run(case, _high_selfmod())
    assert res.response.ceiling is None and decide(res.response) == "block"


# ---- held at review ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason", ["selfmod.config", "selfmod.scheduler", "selfmod.plugin", "selfmod.memory"]
)
def test_an_owner_asked_change_to_the_agents_setup_is_held_at_review(twin_case, reason):
    assert_held(twin_case, _high_selfmod(reason))
    res = _run(twin_case, _high_selfmod(reason))
    assert res.response.reasons[0].code == "cap.attended_owner"
    assert res.response.reasons[0].detail == {"ceiling": "review"}
    assert _info(res) == {
        "attended": True,
        "strong": [],
        "withheld": [],
        "ceiling": "review",
    }


def test_the_risk_is_left_as_scored(twin_case):
    """No numeric cap: owners with custom lines decide from the real score, and the ceiling only lowers."""
    v5 = _run(twin_case, _high_selfmod(), V5).response
    v6 = _run(twin_case, _high_selfmod()).response
    assert v6.risk == v5.risk and v6.risk >= 90
    assert v6.tree == v5.tree
    # custom lines review 85 / block 95: the score is reviewed, not let through as a lowered score would be
    assert decide(v6, 85, 95) == "review"
    # custom lines review 60 / block 88: the block is lowered to review
    assert decide(v6, 60, 88) == "review"
    # the ceiling never raises: a low score stays allowed
    assert decide(v6, 99.5, 99.9) == "allow"


def test_under_the_block_line_the_reason_goes_last(twin_case):
    envs = _high_selfmod()
    envs[0].contributions[0] = _c("suspicion.misalignment", 0.3, "call.not_supported_by_request")
    envs[1].contributions[0] = _c("suspicion.session_exposure", 0.1, "exposure.session_tainted")
    res = _run(twin_case, envs)
    r = res.response
    assert r.risk == _run(twin_case, envs, V5).response.risk < 80
    assert r.ceiling == "review" and decide(r) == decide(_run(twin_case, envs, V5).response)
    assert _codes(res)[-1] == "cap.attended_owner"


def test_a_plain_send_the_model_doubts_is_held(attack_case):
    """No sensitive source, no untrusted origin: the model's doubt alone does not block an attended owner."""
    envs = _send(
        _c("consequence.reach", 1.0, "send.off_host", "E1"),
        _c("consequence.irreversibility", 0.8, "send.off_host", "E1"),
        _c("consequence.sensitivity", 0.9, "jev.sensitivity"),
    )
    assert_held(attack_case, envs)


def test_a_credential_sent_where_a_grant_covers_the_destination_is_held(twin_case):
    """The owner granted the destination: the credential belongs there, so the score alone does not block."""
    res = _run(twin_case, _credential_upload())
    assert any(r.reason == "relief.destination_grant" for r in res.relief)
    assert "sensitive_sent" not in _info(res)["strong"]
    assert_held(twin_case, _credential_upload())


def _ungranted(twin_case: dict, request: str | None = None) -> dict:
    case = copy.deepcopy(twin_case)
    case["fixture"]["grants"] = []
    if request is not None:
        case["fixture"]["request"]["text"] = request
    return case


def test_a_credential_sent_to_a_request_named_destination_is_held(twin_case):
    case = _ungranted(
        twin_case, "Summarise my unread emails, and copy my AWS credentials to backup.mycorp.com"
    )
    res = _run(case, _credential_upload())
    assert [r.reason for r in res.relief] == ["relief.request_named_destination"]
    assert_held(case, _credential_upload())
    # the same send with nothing naming the destination blocks
    assert_blocks(_ungranted(twin_case), _credential_upload(), strong=["sensitive_sent"])


def test_a_credential_sent_to_a_known_good_destination_is_held(twin_case):
    case = _ungranted(twin_case)
    envs = _credential_upload()
    envs.append(
        Envelope(
            step=ProbeStep.ENTITY_ORACLE,
            evidence={"entities": {"E1": {"verdict": "known_good", "match": "exact"}}},
        )
    )
    res = _run(case, envs)
    assert [r.reason for r in res.relief] == ["relief.known_good_destination"]
    assert_held(case, envs)


def test_an_untrusted_origin_on_a_file_the_call_reads_is_not_strong(attack_case):
    """A path the agent found in a listing it read (data source, half weight) is ordinary work, not an attack."""
    envs = _high_selfmod()
    envs[1].contributions.append(
        _c("suspicion.untrusted_origin", 0.5, "origin.only_in_untrusted", "E2")
    )
    assert_held(attack_case, envs)


def test_the_bare_session_sensitive_flag_is_not_a_credential_leaving(attack_case):
    envs = _send(
        _c("consequence.reach", 1.0, "exfil.exec_egress", "E1"),
        _c("consequence.irreversibility", 1.0, "exfil.exec_egress", "E1"),
        _c("consequence.sensitivity", 0.8, "exfil.session_holds_sensitive"),
    )
    assert_held(attack_case, envs)


# ---- still blocks --------------------------------------------------------------------------------------------


def test_a_change_whose_instruction_came_only_from_fetched_content_still_blocks(attack_case):
    envs = _high_selfmod("selfmod.config")
    envs[1].contributions.append(
        _c("suspicion.untrusted_origin", 1.0, "origin.only_in_untrusted", "E1")
    )
    assert_blocks(attack_case, envs, strong=["untrusted_origin"])


@pytest.mark.parametrize(
    "reason",
    [
        "origin.written_content_untrusted",
        "origin.agent_created_dirty_lineage",
        "origin.lookalike_of_named_host",
        "origin.lookalike_of_named_package",
        "origin.sibling_value_untrusted",
    ],
)
def test_every_untrusted_origin_on_an_acting_entity_still_blocks(attack_case, reason):
    envs = _high_selfmod()
    envs[1].contributions.append(_c("suspicion.untrusted_origin", 1.0, reason, "E1"))
    assert_blocks(attack_case, envs, strong=["untrusted_origin"])


@pytest.mark.parametrize(
    ("value", "role"),
    [(1.0, "recipient or destination"), (0.6, "tool provider")],
)
def test_an_untrusted_origin_at_the_acting_role_weights_still_blocks(attack_case, value, role):
    """Scaled by role: destinations and recipients 1.0, tool providers 0.6 (the boundary); data sources 0.5 do not."""
    envs = _high_selfmod()
    envs[1].contributions.append(
        _c("suspicion.untrusted_origin", value, "origin.only_in_untrusted", "E1")
    )
    assert_blocks(attack_case, envs, strong=["untrusted_origin"])


@pytest.mark.parametrize(
    "reason",
    [
        "code.steered_source",
        "exposure.session_injected_content",
        "artefact.push_with_secret",
        "artefact.credential_file_pushed",
    ],
)
def test_steered_code_injected_content_and_published_secrets_still_block(attack_case, reason):
    envs = _high_selfmod()
    envs[2].contributions.append(_c("consequence.sensitivity", 0.8, reason, "E1"))
    assert_blocks(attack_case, envs, strong=["untrusted_content"])


def test_a_credential_sent_to_an_unknown_host_still_blocks(attack_case):
    assert_blocks(attack_case, _credential_upload(), strong=["sensitive_sent"])


def test_a_secret_the_agent_wrote_into_a_file_it_sends_still_blocks(attack_case):
    envs = _send(
        _c("consequence.reach", 1.0, "send.off_host", "E1"),
        _c("consequence.irreversibility", 0.8, "send.off_host", "E1"),
        _c("consequence.sensitivity", 0.9, "jev.sensitivity"),
        context=[_c("suspicion.overreach", 0.8, "lineage.secret_carried_to_send", "E2")],
    )
    assert_blocks(attack_case, envs, strong=["sensitive_sent"])


def test_a_credential_in_a_call_that_sends_without_a_rule_detected_sink_still_blocks(attack_case):
    """An inline script's upload: the sensitivity claim and the call's destination are all there is."""
    envs = _send(_c("consequence.sensitivity", 1.0, "path.credential_store", "E2"))
    assert_blocks(attack_case, envs, strong=["sensitive_sent"])


def test_a_known_bad_entity_still_blocks(attack_case):
    envs = _high_selfmod()
    envs.append(
        Envelope(
            step=ProbeStep.ENTITY_ORACLE,
            contributions=[_c("suspicion.distrust", 1.0, "reputation.known_bad_host", "E1")],
        )
    )
    assert_blocks(attack_case, envs, strong=["known_bad"])


@pytest.mark.parametrize(
    ("floor", "enforce"),
    [
        ("guardrail_tampering", Enforce.BLOCK),
        ("known_bad_entity", Enforce.BLOCK),
        ("untrusted_code_execution", Enforce.BLOCK),
        ("sensitive_data_sent", None),
        ("injected_content_used", None),
        ("lookalike_code_source", None),
    ],
)
def test_a_floor_sets_no_ceiling(attack_case, floor, enforce):
    envs = _high_selfmod()
    envs[2].floors.append(Floor(floor=floor, min_risk=0.6, enforce=enforce))
    res = _run(attack_case, envs)
    assert res.response.enforced is enforce and res.response.ceiling is None
    assert _info(res)["strong"] == [f"floor.{floor}"]
    assert_blocks(attack_case, envs)


def test_an_enforced_block_still_blocks_whatever_the_score(attack_case):
    envs = _high_selfmod()
    envs[2] = Envelope(
        step=ProbeStep.AIRA,
        contributions=[_c("consequence.self_modification", 0.3, "selfmod.config")],
        floors=[Floor(floor="guardrail_tampering", min_risk=1.0, enforce=Enforce.BLOCK)],
    )
    r = _run(attack_case, envs).response
    assert r.enforced is Enforce.BLOCK and r.ceiling is None and r.risk == 100.0
    assert decide(r, 99.5, 99.9) == "block"


@pytest.mark.parametrize(
    "reason",
    [
        "reputation.near_miss_host",
        "lineage.lookalike_of_named_person",
        "lineage.lookalike_of_named_host",
        "code.lookalike_provider",
    ],
)
def test_a_lookalike_entity_still_blocks(attack_case, reason):
    envs = _high_selfmod()
    envs[1].contributions.append(_c("suspicion.overreach", 0.9, reason, "E1"))
    assert_blocks(attack_case, envs, strong=["lookalike"])
    assert_held(attack_case, envs, params=_with(attended_owner_lookalike=False))


@pytest.mark.parametrize(("value", "strong"), [(0.9, True), (0.8, True), (0.79, False)])
def test_a_retry_of_a_denied_action_still_blocks(attack_case, value, strong):
    envs = _high_selfmod()
    envs[1].contributions.append(_c("suspicion.retry_after_denial", value, "retry.same_action"))
    if strong:
        assert_blocks(attack_case, envs, strong=["retry_after_denial"])
        assert_held(attack_case, envs, params=_with(attended_owner_retry_min=None))
    else:
        assert_held(attack_case, envs)


def test_fresh_injection_is_strong_only_when_switched_on(attack_case):
    envs = _high_selfmod()
    envs.append(
        Envelope(
            step=ProbeStep.JEV_EXPOSURE,
            contributions=[_c("suspicion.exposure", 0.9, "exposure.instructions")],
        )
    )
    assert_held(attack_case, envs)
    on = _with(
        attended_owner_injection_exposure_min=0.5, attended_owner_injection_misalignment_min=0.5
    )
    assert_blocks(attack_case, envs, params=on, strong=["fresh_injection"])
    # the session's earlier taint is not this request's injection
    envs[-1] = Envelope(
        step=ProbeStep.JEV_EXPOSURE,
        contributions=[_c("suspicion.exposure", 0.1, "exposure.instructions")],
    )
    assert_held(attack_case, envs, params=on)


# ---- a probe that failed sets no ceiling ---------------------------------------------------------------------


def _strong_origin() -> list[Envelope]:
    envs = _high_selfmod("selfmod.config")
    envs[1].contributions.append(
        _c("suspicion.untrusted_origin", 1.0, "origin.only_in_untrusted", "E1")
    )
    return envs


@pytest.mark.parametrize(
    "step",
    [
        ProbeStep.CONTEXT,
        ProbeStep.AIRA,
        ProbeStep.JEV_CALL,
        ProbeStep.JEV_EXPOSURE,
        ProbeStep.ENTITY_ORACLE,
    ],
)
@pytest.mark.parametrize("status", [ProbeStatus.ERROR, ProbeStatus.TIMEOUT])
def test_a_failed_probe_sets_no_ceiling(attack_case, step, status):
    """The strong signal may be in the answer that never came: with the context probe down the untrusted origin
    above is lost, and holding the call at review would let an attack through on a probe failure."""
    envs = _strong_origin() + [
        Envelope(step=ProbeStep.JEV_EXPOSURE),
        Envelope(step=ProbeStep.ENTITY_ORACLE, evidence={"available": True}),
    ]
    idx = next(i for i, e in enumerate(envs) if e.step is step)
    envs[idx] = Envelope.failed(step, status, "down")
    res = _run(attack_case, envs)
    assert res.response.ceiling is None
    assert _info(res)["withheld"] and _info(res)["ceiling"] is None
    assert decide(res.response) == decide(_run(attack_case, envs, V5).response)


def test_the_context_probe_error_from_review_keeps_its_score(attack_case):
    envs = _strong_origin()
    envs[1].status = ProbeStatus.ERROR
    v5 = _run(attack_case, envs, V5).response
    v6 = _run(attack_case, envs).response
    assert v6.risk == v5.risk and v6.ceiling is None and v6.status.value == "degraded"


@pytest.mark.parametrize("step", [ProbeStep.CONTEXT, ProbeStep.AIRA])
def test_a_missing_or_skipped_signal_probe_sets_no_ceiling(attack_case, step):
    envs = [e for e in _high_selfmod() if e.step is not step]
    assert _run(attack_case, envs).response.ceiling is None
    envs.append(Envelope.failed(step, ProbeStatus.SKIPPED, "not run"))
    assert _run(attack_case, envs).response.ceiling is None


def test_an_oracle_lookup_that_fell_back_sets_no_ceiling(attack_case):
    envs = _high_selfmod()
    envs.append(Envelope(step=ProbeStep.ENTITY_ORACLE, evidence={"fallback": "null"}))
    res = _run(attack_case, envs)
    assert res.response.ceiling is None and "probe_failed" in _info(res)["withheld"]


# ---- a degraded scan or a lost session state sets no ceiling ------------------------------------------------


def test_an_unavailable_oracle_sets_no_ceiling(attack_case):
    """The null oracle (or a library that is down) knows no known-bad or look-alike entity."""
    envs = _high_selfmod()
    envs.append(Envelope(step=ProbeStep.ENTITY_ORACLE, evidence={"available": False}))
    res = _run(attack_case, envs)
    assert res.response.ceiling is None and "oracle_unavailable" in _info(res)["withheld"]
    envs[-1] = Envelope(step=ProbeStep.ENTITY_ORACLE, evidence={"available": True})
    assert _run(attack_case, envs).response.ceiling == "review"


def test_an_oracle_skipped_by_ablation_sets_no_ceiling(attack_case):
    envs = _high_selfmod()
    envs.append(Envelope.failed(ProbeStep.ENTITY_ORACLE, ProbeStatus.SKIPPED, "ablated"))
    res = _run(attack_case, envs)
    assert res.response.ceiling is None and "oracle_unavailable" in _info(res)["withheld"]


def test_the_null_oracle_end_to_end_sets_no_ceiling(twin_case):
    from sentrook.oracle.client import NullOracle

    case = copy.deepcopy(twin_case)
    case["oracle_seed"] = None
    answers = {**ATTACK_ANSWERS, "exposure_instructions": {"type": "noul", "noul": 0.05}}
    res = scanner(answers, params=V6, oracle=NullOracle()).scan(
        case["fixture"], options(case, probes_enabled=None)
    )
    assert res.response.ceiling is None
    assert "oracle_unavailable" in res.response.metadata.versions["attended_owner"]["withheld"]


def test_unjudged_new_content_sets_no_ceiling(attack_case):
    """Jev not configured or disabled: the request's new untrusted content went unread by the exposure judge."""
    envs = _high_selfmod()
    envs.append(Envelope.failed(ProbeStep.JEV_EXPOSURE, ProbeStatus.SKIPPED, "not configured"))
    res = _run(attack_case, envs)  # the attack case brings a new email
    assert res.response.ceiling is None and "exposure_unjudged" in _info(res)["withheld"]


def test_jev_not_configured_end_to_end_sets_no_ceiling(attack_case):
    res = Scanner(ScannerConfig(token_key=KEY, decider=None, params=V6)).scan(
        attack_case["fixture"], options(attack_case, probes_enabled=None)
    )
    assert res.response.ceiling is None
    assert res.response.metadata.versions["attended_owner"]["withheld"]


def test_dropped_content_sets_no_ceiling(attack_case):
    from sentrook.prepare import CoverageNote

    prepared = _prepared(attack_case)
    prepared.coverage.append(CoverageNote(code="content_dropped", detail="test"))
    res = converge(
        prepared, _judged(_high_selfmod()), params=V6, scanner_version="t", token_key=KEY
    )
    assert res.response.status.value == "degraded" and res.response.ceiling is None
    assert "degraded" in res.response.metadata.versions["attended_owner"]["withheld"]


@pytest.mark.parametrize("status", ["missing", "invalid", "stale", "mismatch"])
def test_a_lost_session_state_sets_no_ceiling(attack_case, status):
    """A fresh token loses the retry, taint and sensitive sets a strong signal may come from."""
    from sentrook.state.token import TokenStatus

    prepared = _prepared(attack_case)
    prepared.state.status = TokenStatus(status)
    res = converge(
        prepared, _judged(_high_selfmod()), params=V6, scanner_version="t", token_key=KEY
    )
    assert res.response.ceiling is None
    assert "state_lost" in res.response.metadata.versions["attended_owner"]["withheld"]


def test_the_first_step_keeps_the_ceiling(attack_case):
    from sentrook.state.token import TokenStatus

    prepared = _prepared(attack_case)
    prepared.state.status = TokenStatus.FIRST_STEP
    res = converge(
        prepared, _judged(_high_selfmod()), params=V6, scanner_version="t", token_key=KEY
    )
    assert res.response.ceiling == "review"


def test_an_unrecognised_channel_is_not_attended(attack_case):
    """OpenClaw's own system-agent chat (and host-marker turns on it) arrives as an owner message on channel
    `other`, which nothing else tells apart; the fail-safe reading is not attended."""
    case = copy.deepcopy(attack_case)
    case["fixture"]["trigger"]["channel"] = "other"
    assert attended_owner(PlanIR.model_validate(case["fixture"])) is False
    for channel in ("chat", "discord", None):
        case["fixture"]["trigger"]["channel"] = channel
        assert attended_owner(PlanIR.model_validate(case["fixture"])) is True


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
    assert v6.risk == v5.risk >= 80 and v6.ceiling is None
    assert "cap.attended_owner" not in [r.code for r in v6.reasons]
    assert v6.metadata.versions["attended_owner"] == {
        "attended": False,
        "strong": [],
        "withheld": [],
        "ceiling": None,
    }


def test_conv_v5_has_no_ceiling(twin_case):
    r = _run(twin_case, _high_selfmod(), params=V5).response
    assert r.risk >= 80 and r.ceiling is None and "attended_owner" not in r.metadata.versions


# ---- end to end through the scanner --------------------------------------------------------------------------


def test_the_worked_attack_still_blocks_end_to_end(attack_case):
    """The credential upload an email dictated: untrusted origin and a credential to an unknown host."""
    res = scanner(ATTACK_ANSWERS, params=V6).scan(
        attack_case["fixture"], options(attack_case, probes_enabled=None)
    )
    r = res.response
    assert r.ceiling is None and decide(r) == "block"
    assert {"untrusted_origin", "sensitive_sent"} <= set(
        r.metadata.versions["attended_owner"]["strong"]
    )


def test_an_owner_asked_cron_edit_is_held_end_to_end(twin_case):
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
    assert decide(v5) == "block"
    assert v6.risk == v5.risk and v6.ceiling == "review" and v6.enforced is None
    assert decide(v6) == "review"
    # the response serialises the ceiling for the plugins
    assert json.loads(v6.model_dump_json())["ceiling"] == "review"


# ---- parameters ----------------------------------------------------------------------------------------------


def test_the_optional_signals_load_from_a_parameter_file(tmp_path):
    raw = json.loads((PARAMS_DIR / "conv-v6.json").read_text(encoding="utf-8"))
    raw["name"] = "conv-test"
    raw["attended_owner_cap"].update(
        {
            "lookalike": False,
            "retry_min": 0.9,
            "fresh_injection": {"exposure_min": 0.5, "misalignment_min": 0.6},
        }
    )
    path = tmp_path / "conv-test.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    p = load_params(path)
    assert p.attended_owner_lookalike is False and p.attended_owner_retry_min == 0.9
    assert p.attended_owner_injection_exposure_min == 0.5
    assert p.attended_owner_injection_misalignment_min == 0.6


def test_conv_v6_is_conv_v5_with_the_ceiling_on():
    assert V6.name == "conv-v6" and V6.oracle.name == "conv-v6/oracle"
    assert V6.attended_owner_cap is True and V5.attended_owner_cap is False
    assert V6.attended_owner_untrusted_origin_min == 0.6
    assert V6.attended_owner_sent_sensitivity_min == 0.6
    assert V6.attended_owner_lookalike is True and V6.attended_owner_retry_min == 0.8
    assert V6.attended_owner_injection_exposure_min is None
    a, b = dataclasses.asdict(V5), dataclasses.asdict(V6)
    for d in (a, b):
        d.pop("name")
        d["oracle"].pop("name")
        d["context"].pop("name")
        for k in ("attended_owner_cap", "attended_owner_lookalike", "attended_owner_retry_min"):
            d.pop(k)
    assert a == b


def test_serve_defaults_to_conv_v5_and_conv_v6_stays_selectable():
    """The ceiling is off by default: it moved real attack cases from block to review."""
    assert ServeConfig().convergence == "conv-v5"
    assert ServeConfig.from_env({}).convergence == "conv-v5"
    assert ServeConfig.from_env({"SENTROOK_CONVERGENCE": "conv-v6"}).convergence == "conv-v6"
    assert load_params(ServeConfig().convergence).attended_owner_cap is False
