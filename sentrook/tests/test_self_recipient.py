"""A message addressed to the owner by a self-reference is not a send to an unknown third party.

`to: "me"`, `"self"`, `"myself"` or `"owner"` is a bare word, not an address: the tool resolves it to the
account it runs as. Such a recipient takes no unknown-recipient distrust, no coverage loss and no "the agent
chose it" origin. Anything that is an address, a handle, a channel or another name keeps its scoring.
"""

from __future__ import annotations

import pytest
from test_aira_detectors import planir, run

from sentrook.converge.registry import REASONS
from sentrook.oracle.client import SeedOracle
from sentrook.prepare.entities import EntityKind
from sentrook.probes.context import ContextProbe
from sentrook.probes.oracle import EntityOracleProbe

MAIL = {"kind": "mcp", "name": "mail", "identity": "npm:@quayfern/mail-mcp@1.2.0"}


def _mail(to: str) -> dict:
    return planir(
        "send_mail",
        "mcp",
        {"to": to, "subject": "Standup", "body": "Shipped the notes build."},
        provider=MAIL,
        request="Send me the standup note.",
    )


def _scores(raw: dict, value: str):
    p, _ = run(raw)
    ent = p.entities.get(EntityKind.RECIPIENT, value)
    assert ent is not None, [(e.kind, e.value) for e in p.entities]
    orc = EntityOracleProbe(SeedOracle({"entities": []})).run(p)
    ctx = ContextProbe().run(p)
    distrust = [
        c for c in orc.contributions if c.signal == "suspicion.distrust" and c.subject == ent.id
    ]
    origin = [
        c
        for c in ctx.contributions
        if c.signal == "suspicion.untrusted_origin" and c.subject == ent.id
    ]
    coverage = [c.value for c in orc.contributions if c.signal == "confidence.coverage"]
    return ent, distrust, origin, coverage, orc


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize("to", ["owner", "me", "self", "myself", "Me", " OWNER "])
def test_a_self_reference_is_not_an_unknown_recipient(to):
    ent, distrust, origin, coverage, orc = _scores(_mail(to), to.strip())
    assert ent.self_recipient
    assert [(c.value, c.reason) for c in distrust] == [(0.0, "reputation.self_recipient")]
    assert [(c.value, c.reason) for c in origin] == [(0.0, "origin.self_recipient")]
    assert all(v == 1.0 for v in coverage)
    assert orc.evidence["entities"][ent.id]["verdict"] == "self"


def test_the_reasons_have_owner_facing_text():
    assert "reputation.self_recipient" in REASONS and "origin.self_recipient" in REASONS


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize(
    "to",
    ["mara.quill@linnetpost.example", "me@linnetpost.example", "@owner", "ownerdesk", "Mara Quill"],
)
def test_an_address_a_handle_or_a_name_is_still_scored(to):
    ent, distrust, origin, coverage, _ = _scores(_mail(to), to.lower() if "@" in to[1:] else to)
    assert not ent.self_recipient
    assert (
        distrust and distrust[0].value > 0 and distrust[0].reason.startswith("reputation.unknown")
    )
    assert origin and origin[0].value > 0


def test_a_self_reference_next_to_a_third_party_leaves_the_third_party_scored():
    raw = _mail("me")
    raw["pending_call"]["arguments"]["cc"] = "desk@coppicedown.example"
    p, _ = run(raw)
    other = p.entities.get(EntityKind.RECIPIENT, "desk@coppicedown.example")
    orc = EntityOracleProbe(SeedOracle({"entities": []})).run(p)
    ctx = ContextProbe().run(p)
    assert any(c.subject == other.id and c.value > 0 for c in orc.contributions)
    assert any(
        c.subject == other.id and c.value > 0
        for c in ctx.contributions
        if c.signal == "suspicion.untrusted_origin"
    )


def test_a_self_reference_the_session_holds_as_untrusted_keeps_that_origin():
    p, _ = run(_mail("owner"))
    ent = p.entities.get(EntityKind.RECIPIENT, "owner")
    ent.in_session_untrusted = True
    ctx = ContextProbe().run(p)
    [origin] = [
        c
        for c in ctx.contributions
        if c.signal == "suspicion.untrusted_origin" and c.subject == ent.id
    ]
    assert origin.reason == "origin.only_in_untrusted" and origin.value == 1.0
