"""A tool the session already used, now served by a provider nothing vouches for.

An MCP server or plugin the library does not know is normally scored as a bystander: the host's
configuration supplies it, so its unknown-provider distrust is low. When an earlier step of the session
called the same tool name through a different provider, the host did not simply hand this one over,
and an unknown provider then takes at least `unknown_switched_provider` (off at 0) with its own reason.
The same provider, another version of its package, the first use of a tool, a provider the library
vouches for and a provider a grant covers keep today's values; known-bad and look-alike providers keep
their own, higher distrust.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from test_converge_scan import BENIGN_ANSWERS, options, scanner
from test_jev_probes import prepared_for
from test_provider_origin import EARLIER, LOCAL, REMOTE, _provider, _switch_case

from sentrook.converge import load_params
from sentrook.converge.registry import REASONS
from sentrook.oracle.client import NullOracle, SeedOracle
from sentrook.probes.oracle import EntityOracleProbe

V4 = load_params("conv-v4")
OFF = V4.oracle
ON = replace(OFF, unknown_switched_provider=0.3)
TODAY = (0.1, "reputation.unknown_mcp_server_as_tool_provider")
SWITCHED = (0.3, "reputation.switched_provider")


def _claim(case, params=ON, seed: list[dict] | None = None, client=None, identity: str = LOCAL):
    p = prepared_for(case)
    oracle = client or SeedOracle({"entities": case["oracle_seed"]["entities"] + (seed or [])})
    env = EntityOracleProbe(oracle, params).run(p)
    provider = _provider(p, identity)
    (claim,) = [
        c
        for c in env.contributions
        if c.signal == "suspicion.distrust" and c.subject == provider.id
    ]
    return (claim.value, claim.reason), env


# --------------------------------------------------------------------------- must fire


def test_an_unknown_provider_the_session_switched_to_takes_the_switched_distrust(twin_case):
    for identity in (LOCAL, REMOTE):
        claim, _ = _claim(_switch_case(twin_case, identity, EARLIER), identity=identity)
        assert claim == SWITCHED, identity
    assert "reputation.switched_provider" in REASONS


def test_an_unchecked_provider_counts_as_one_nothing_vouches_for(twin_case):
    claim, _ = _claim(_switch_case(twin_case, LOCAL, EARLIER), client=NullOracle())
    assert claim == SWITCHED


def test_a_switch_from_a_plugin_is_a_switch(twin_case):
    case = _switch_case(twin_case, LOCAL, "fold-runner")
    case["fixture"]["history"][0]["provider"]["kind"] = "plugin"
    claim, _ = _claim(case)
    assert claim == SWITCHED


def test_off_at_zero_leaves_todays_claims(twin_case):
    assert OFF.unknown_switched_provider == 0.0
    case = _switch_case(twin_case, LOCAL, EARLIER)
    claim, env_off = _claim(case, params=OFF)
    assert claim == TODAY
    # on, a call that is not a switch carries exactly the claims it carries with the parameter off
    first = _switch_case(twin_case, LOCAL, None)
    _, on = _claim(first)
    _, off = _claim(first, params=OFF)
    assert on.contributions == off.contributions
    # a value below the provider's own weight changes nothing
    claim, _ = _claim(case, params=replace(OFF, unknown_switched_provider=0.05))
    assert claim == TODAY


def test_the_parameter_loads_from_a_file(tmp_path):
    path = tmp_path / "conv-x.json"
    path.write_text(
        json.dumps({"name": "conv-x", "oracle": {"unknown_switched_provider": 0.25}}),
        encoding="utf-8",
    )
    assert load_params(path).oracle.unknown_switched_provider == 0.25


@pytest.mark.parametrize(("sole", "expected"), [(0.5, 0.5), (0.2, 0.3)])
def test_with_the_sole_destination_arm_the_higher_value_wins(twin_case, sole, expected):
    case = _switch_case(twin_case, LOCAL, EARLIER, tool="post_digest")
    case["fixture"]["pending_call"]["tool"] = "post_digest"
    case["fixture"]["pending_call"]["arguments"] = {"channel": "desk", "text": "Build is green."}
    params = replace(ON, unknown_sole_destination_provider=sole)
    (value, reason), env = _claim(case, params=params)
    assert env.evidence.get("sole_destination_provider")  # both arms apply
    assert value == expected  # the larger one, never the sum
    assert reason == (
        "reputation.unknown_mcp_server_as_data_destination"
        if sole > 0.3
        else "reputation.switched_provider"
    )


# --------------------------------------------------------------------------- must stay silent


def test_the_same_provider_or_another_version_of_it_keeps_todays_value(twin_case):
    for identity in (EARLIER, "npm:@pellmoor/runner-mcp@1.3.1"):
        claim, _ = _claim(_switch_case(twin_case, identity, EARLIER), identity=identity)
        assert claim == TODAY, identity


def test_the_first_use_of_a_tool_keeps_todays_value(twin_case):
    for case in (
        _switch_case(twin_case, LOCAL, None),
        _switch_case(twin_case, LOCAL, EARLIER, tool="list_folds"),
    ):
        claim, _ = _claim(case)
        assert claim == TODAY


def test_a_switch_to_a_provider_the_library_vouches_for_carries_no_distrust(twin_case):
    case = _switch_case(twin_case, LOCAL, EARLIER)
    case["oracle_seed"]["entities"][0]["verdict"] = "known_good"
    (value, reason), _ = _claim(case)
    assert value == 0.0 and reason.startswith("reputation.known_good_mcp_server")


def test_known_bad_and_look_alike_providers_keep_their_own_higher_distrust(twin_case):
    case = _switch_case(twin_case, LOCAL, EARLIER)
    case["oracle_seed"]["entities"][0]["verdict"] = "known_bad"
    assert _claim(case)[0] == (1.0, "reputation.known_bad_mcp_server")

    good = "npm:@quayfern/runner-mcpp@2.1.0"
    case = _switch_case(twin_case, LOCAL, EARLIER)
    claim, _ = _claim(case, seed=[{"kind": "mcp_server", "value": good, "verdict": "known_good"}])
    assert claim == (OFF.near_miss_distrust, "reputation.near_miss_mcp_server")


def test_a_granted_provider_is_relieved_of_the_switched_distrust(twin_case):
    params = replace(V4, oracle=ON)
    case = _switch_case(twin_case, LOCAL, EARLIER)

    def scan(grants):
        case["fixture"]["grants"] = grants
        return scanner(BENIGN_ANSWERS, params=params).scan(case["fixture"], options(case))

    res = scan([])
    provider = _provider(res.prepared, LOCAL)
    claims = res.converge.merged.claims["suspicion.distrust"]
    assert {(c.subject, c.value, c.reason) for c in claims} >= {(provider.id, *SWITCHED)}

    res = scan(
        [
            {
                "grant_ref": "g0",
                "kind": "provider",
                "pattern": "npm:@quayfern/",
                "scope": "persistent",
            }
        ]
    )
    provider = _provider(res.prepared, LOCAL)
    assert any(r.subject == provider.id for r in res.converge.relief)
    claims = res.converge.merged.claims.get("suspicion.distrust", [])
    assert provider.id not in {c.subject for c in claims}
    assert all(x.code != "reputation.switched_provider" for x in res.response.reasons)
