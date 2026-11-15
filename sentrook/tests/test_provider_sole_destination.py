"""An unknown tool provider that is the only place a send's data goes.

A send tool on an MCP server or plugin usually names where the data goes: a recipient, a channel entity,
a host. When it names none, the provider itself is the only known destination, and an unknown one is an
unknown party receiving data, not a bystander that merely supplies a tool. The oracle probe can score it
at a destination-grade distrust (`unknown_sole_destination_provider`, off by default). A provider the
library vouches for, a call that names its recipient or host, and a tool that does not send keep today's
values.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from test_aira_detectors import planir, run

from sentrook.converge import load_params
from sentrook.converge.registry import REASONS
from sentrook.oracle.client import SeedOracle
from sentrook.prepare.entities import EntityKind
from sentrook.probes.oracle import EntityOracleProbe

IDENTITY = "npm:@fernlock/desk-mcp@0.3.0"
PROVIDER = {"kind": "mcp", "name": "desk-relay", "identity": IDENTITY, "transport": "stdio"}
V4 = load_params("conv-v4").oracle
ON = replace(V4, unknown_sole_destination_provider=0.3)


def scored(tool: str, arguments: dict, params=ON, seed: list[dict] | None = None):
    p, aira = run(planir(tool, "mcp", arguments, provider=PROVIDER, request="Post the digest."))
    env = EntityOracleProbe(SeedOracle({"entities": seed or []}), params).run(p)
    ent = p.entities.get(EntityKind.MCP_SERVER, IDENTITY)
    claim = next(c for c in env.contributions if c.subject == ent.id)
    return claim, env, aira


def test_an_unknown_provider_that_is_the_only_destination_takes_destination_distrust():
    claim, env, aira = scored("post_digest", {"channel": "desk", "text": "Build is green."})
    assert (claim.value, claim.reason) == (0.3, "reputation.unknown_mcp_server_as_data_destination")
    assert claim.reason in REASONS
    # AIRA names the provider as the send's destination, and the coverage loss is a destination's
    (finding,) = [f for f in aira.evidence["findings"] if f["class"] == "C2"]
    assert finding["destinations"] == [IDENTITY]
    coverage = [c.value for c in env.contributions if c.signal == "confidence.coverage"]
    assert coverage == [V4.coverage_unknown_risky]
    assert env.evidence["sole_destination_provider"] == claim.subject


@pytest.mark.parametrize(
    "tool, arguments",
    [
        # the call names who receives it
        ("send_mail", {"to": "desk@yarrowmill.example", "body": "Build is green."}),
        # the call names the host it posts to
        (
            "post_page",
            {"url": "https://board.yarrowmill.example/ops", "content": "Build is green."},
        ),
        # not a send
        ("list_digests", {"channel": "desk"}),
        ("read_digest", {"id": "41"}),
    ],
)
def test_a_provider_that_is_not_the_only_destination_stays_a_tool_provider(tool, arguments):
    claim, env, _ = scored(tool, arguments)
    assert (claim.value, claim.reason) == (0.1, "reputation.unknown_mcp_server_as_tool_provider")
    assert "sole_destination_provider" not in env.evidence


def test_the_library_verdict_still_decides():
    args = {"channel": "desk", "text": "Build is green."}
    good = [{"kind": "mcp_server", "value": IDENTITY, "verdict": "known_good"}]
    claim, _, _ = scored("post_digest", args, seed=good)
    assert claim.value == 0.0 and claim.reason.startswith("reputation.known_good_mcp_server")
    listed = [{"kind": "mcp_server", "value": IDENTITY, "verdict": "unknown", "distrust": 0.6}]
    claim, _, _ = scored("post_digest", args, seed=listed)
    assert claim.value == 0.6


def test_off_by_default_never_lowers_and_loads_from_a_parameter_file(tmp_path):
    args = {"channel": "desk", "text": "Build is green."}
    claim, env, _ = scored("post_digest", args, params=V4)
    assert (claim.value, claim.reason) == (0.1, "reputation.unknown_mcp_server_as_tool_provider")
    assert V4.unknown_sole_destination_provider == 0.0
    # a value below the provider's own weight changes nothing
    claim, _, _ = scored(
        "post_digest", args, params=replace(V4, unknown_sole_destination_provider=0.05)
    )
    assert (claim.value, claim.reason) == (0.1, "reputation.unknown_mcp_server_as_tool_provider")
    path = tmp_path / "conv-x.json"
    path.write_text(
        json.dumps({"name": "conv-x", "oracle": {"unknown_sole_destination_provider": 0.2}}),
        encoding="utf-8",
    )
    assert load_params(path).oracle.unknown_sole_destination_provider == 0.2
