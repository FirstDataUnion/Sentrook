"""A tainted session's sticky exposure is its own signal, `suspicion.session_exposure`.

The context probe's sticky claim covers the whole session; the exposure probe reads only this scan's new untrusted
inputs. They measure different things, so a tainted session whose latest input is clean is not a disagreement
between probes. The taint still reaches suspicion through `taint_link`, exactly as before.
"""

from __future__ import annotations

import copy

import pytest
from test_converge_scan import BENIGN_ANSWERS, KEY, _prepared, options, scanner

from sentrook.converge import converge, load_params
from sentrook.enums import ProbeStep
from sentrook.probes.base import Contribution, Envelope


def _codes(response) -> list[str]:
    return [r.code for r in response.reasons]


def _splits(response) -> list[dict]:
    return [r.detail for r in response.reasons if r.code.startswith("agreement.")]


# ---- must stay silent ------------------------------------------------------------------------------------------


def test_a_tainted_session_with_a_clean_new_input_is_not_a_split(attack_case):
    case = copy.deepcopy(attack_case)
    case["state_seed"]["tainted"] = True
    res = scanner(BENIGN_ANSWERS).scan(case["fixture"], options(case))
    r = res.response
    assert r.tree.suspicion.exposure == pytest.approx(0.05)  # this scan's new input, from the model
    assert r.tree.suspicion.session_exposure == pytest.approx(0.7)  # the session's taint
    assert "exposure.session_tainted" in _codes(r)
    assert _splits(r) == []
    assert r.tree.confidence.agreement == 1.0
    # confidence comes from coverage and model certainty only
    certainty = r.tree.confidence.model_certainty
    expected = min([r.tree.confidence.coverage] + ([certainty] if certainty is not None else []))
    assert r.tree.confidence.score == pytest.approx(expected)


def test_the_sticky_claim_and_the_exposure_probe_never_share_a_signal(attack_case):
    """The unit reproduction: a sticky 0.7 from the context probe, a clean 0.05 from the exposure probe and a full
    self-modification consequence. The claims used to share `suspicion.exposure`, which gave agreement 0 and pinned
    risk at consequence x u = 50."""
    envs = [
        Envelope(
            step=ProbeStep.CONTEXT,
            contributions=[
                Contribution(
                    signal="suspicion.session_exposure",
                    value=0.7,
                    reason="exposure.session_tainted",
                )
            ],
        ),
        Envelope(
            step=ProbeStep.JEV_EXPOSURE,
            contributions=[
                Contribution(
                    signal="suspicion.exposure", value=0.05, reason="exposure.instructions"
                )
            ],
        ),
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[
                Contribution(
                    signal="consequence.self_modification", value=1.0, reason="selfmod.plugin"
                )
            ],
        ),
    ]
    res = converge(
        _prepared(attack_case),
        envs,
        params=load_params("conv-v3"),
        scanner_version="t",
        token_key=KEY,
    )
    assert res.response.tree.suspicion.session_exposure == 0.7
    assert res.tiers.agreement == 1.0 and res.tiers.disagreements == []
    assert res.tiers.confidence == 1.0
    assert "agreement.suspicion_split" not in _codes(res.response)
    assert res.response.risk < 50.0
    # the same two values on one signal are a split, and pin risk at consequence x u
    envs[0].contributions[0] = Contribution(
        signal="suspicion.exposure", value=0.7, reason="exposure.session_tainted"
    )
    shared = converge(
        _prepared(attack_case),
        envs,
        params=load_params("conv-v3"),
        scanner_version="t",
        token_key=KEY,
    )
    assert shared.tiers.agreement == 0.0 and shared.response.risk == 50.0


# ---- must still fire -------------------------------------------------------------------------------------------


def test_two_probes_reading_the_same_new_input_still_disagree(attack_case):
    """A rule-based exposure claim and a model exposure claim on the same new input are one signal: a split lowers
    agreement and names the signal, and the session's taint does not mask it."""
    envs = [
        Envelope(
            step=ProbeStep.AIRA,
            contributions=[
                Contribution(signal="suspicion.exposure", value=0.8, reason="exposure.rule_match")
            ],
        ),
        Envelope(
            step=ProbeStep.JEV_EXPOSURE,
            contributions=[
                Contribution(signal="suspicion.exposure", value=0.1, reason="exposure.instructions")
            ],
        ),
        Envelope(
            step=ProbeStep.CONTEXT,
            contributions=[
                Contribution(
                    signal="suspicion.session_exposure",
                    value=0.7,
                    reason="exposure.session_tainted",
                )
            ],
        ),
    ]
    res = converge(
        _prepared(attack_case),
        envs,
        params=load_params("conv-v3"),
        scanner_version="t",
        token_key=KEY,
    )
    assert res.tiers.agreement == 0.0
    assert [d[0] for d in res.tiers.disagreements] == ["suspicion.exposure"]
    assert _splits(res.response) == [{"signal": "suspicion.exposure", "low": 0.1, "high": 0.8}]


# ---- unchanged -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("new_input", [0.05, 0.5])  # below the sticky 0.7, so the session's value decides
@pytest.mark.parametrize("origin", [0.4, 1.0])  # with no untrusted origin taint_link is 0 either way
def test_taint_link_and_suspicion_match_the_shared_signal(attack_case, new_input, origin):
    """The session's taint reaches suspicion exactly as it did when it shared `suspicion.exposure` with the
    exposure probe: `taint_link` takes the larger of the two."""

    def run(sticky_signal: str):
        envs = [
            Envelope(
                step=ProbeStep.CONTEXT,
                contributions=[
                    Contribution(
                        signal=sticky_signal, value=0.7, reason="exposure.session_tainted"
                    ),
                    Contribution(
                        signal="suspicion.untrusted_origin", value=origin, subject="E1", reason="o"
                    ),
                ],
            ),
            Envelope(
                step=ProbeStep.JEV_EXPOSURE,
                contributions=[
                    Contribution(
                        signal="suspicion.exposure", value=new_input, reason="exposure.instructions"
                    )
                ],
            ),
        ]
        return converge(
            _prepared(attack_case),
            envs,
            params=load_params("conv-v3"),
            scanner_version="t",
            token_key=KEY,
        ).tiers

    shared, separate = run("suspicion.exposure"), run("suspicion.session_exposure")
    assert separate.taint_link == pytest.approx(origin * 0.7)
    assert separate.taint_link == pytest.approx(shared.taint_link)
    assert separate.suspicion == pytest.approx(shared.suspicion)


def test_a_tainted_session_with_no_new_input_scores_as_before(attack_case):
    """No new untrusted input: the exposure probe is skipped, the sticky claim alone feeds taint_link."""
    case = copy.deepcopy(attack_case)
    case["state_seed"]["tainted"] = True
    case["fixture"]["new_inputs"] = []
    res = scanner(BENIGN_ANSWERS).scan(case["fixture"], options(case))
    t = res.converge.tiers
    origin = res.converge.merged.value_or("suspicion.untrusted_origin", 0.0)
    assert res.response.tree.suspicion.exposure is None
    assert t.taint_link == pytest.approx(origin * 0.7)
