"""Response 2.0 and the probe envelope: shape, bounds, helpers."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentrook.enums import Enforce, ProbeStatus, ProbeStep, ScanStatus, SessionFlag
from sentrook.probes import Contribution, Envelope, Floor
from sentrook.response.models import (
    CONFIDENCE_SIGNALS,
    CONSEQUENCE_SIGNALS,
    SUSPICION_SIGNALS,
    Response,
    RiskTree,
    SuspicionTier,
)


def test_empty_response_has_every_signal_absent():
    resp = Response.empty("r1", "2.0.0a1")
    tree = resp.model_dump()["tree"]
    assert all(v is None for v in tree["suspicion"].values())
    assert all(v is None for v in tree["consequence"].values())
    assert all(v is None for v in tree["confidence"].values())
    assert resp.status is ScanStatus.OK and resp.risk is None and resp.enforced is None
    assert resp.metadata.scanner_version == "2.0.0a1"


def test_tree_fields_match_signal_registry():
    tree = RiskTree().model_dump()
    assert set(tree["suspicion"]) == {"score", *SUSPICION_SIGNALS}
    assert set(tree["consequence"]) == {"score", *CONSEQUENCE_SIGNALS}
    assert set(tree["confidence"]) == {"score", *CONFIDENCE_SIGNALS}


def test_errored_response_shape():
    resp = Response.errored(
        "r1", "2.0.0a1", "invalid_planir", "session.step must be max(history.step)+1"
    )
    assert resp.status is ScanStatus.ERROR
    assert resp.risk is None
    assert resp.error is not None and resp.error.code == "invalid_planir"


@pytest.mark.parametrize("risk", [-1, 100.5])
def test_risk_is_bounded(risk):
    with pytest.raises(ValidationError):
        Response(request_id="r1", risk=risk, metadata={"scanner_version": "x"})


def test_tier_scores_are_unit_interval():
    with pytest.raises(ValidationError):
        SuspicionTier(exposure=1.2)


def test_envelope_round_trip():
    env = Envelope(
        step=ProbeStep.AIRA,
        versions={"probe": "2.0.0a1", "ruleset": "lists-v1"},
        latency_ms=4,
        contributions=[
            Contribution(
                signal="consequence.reach", value=1.0, subject="E1", reason="sink.exec_egress"
            )
        ],
        floors=[
            Floor(
                floor="guardrail_tampering",
                min_risk=1.0,
                enforce=Enforce.BLOCK,
                reason="guardrail.plugin_disable",
            )
        ],
        flags_set=[SessionFlag.HOLDS_SENSITIVE],
        evidence={"classes": ["C2"]},
    )
    again = Envelope.model_validate(env.model_dump(mode="json"))
    assert again == env
    assert again.status is ProbeStatus.OK


def test_failed_and_skipped_envelopes():
    failed = Envelope.failed(
        ProbeStep.JEV_CALL, ProbeStatus.TIMEOUT, "upstream 504", {"probe": "x"}, latency_ms=900
    )
    assert failed.status is ProbeStatus.TIMEOUT and failed.contributions == []
    assert failed.evidence["error"] == "upstream 504"
    with pytest.raises(ValueError):
        Envelope.failed(ProbeStep.JEV_CALL, ProbeStatus.OK, "not a failure")
    skipped = Envelope.skipped(ProbeStep.ENTITY_ORACLE, "disabled by SENTROOK_PROBES")
    assert skipped.status is ProbeStatus.SKIPPED


def test_contribution_value_is_unit_interval():
    with pytest.raises(ValidationError):
        Contribution(signal="suspicion.exposure", value=1.5)
    with pytest.raises(ValidationError):
        Contribution(signal="suspicion.exposure", value=0.5, unexpected="no")  # type: ignore[call-arg]
