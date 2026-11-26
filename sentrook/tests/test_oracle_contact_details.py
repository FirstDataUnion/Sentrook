"""The remote oracle is asked about public names only: an email recipient goes as its mail domain, and a
person's other contact details (a phone number, a chat handle, a direct-message id) are never sent."""

from __future__ import annotations

import json

import httpx

from sentrook.oracle.client import (
    EntityQuery,
    HttpOracle,
    Match,
    VerdictKind,
    mail_domain,
    wire_query,
)

# Invented addresses: the reserved example domains, nobody's real contact details.
ADDRESS = "Quillon.Marsh@Bramblecourt.example"
DOMAIN = "bramblecourt.example"


class FakeRookery:
    """A stand-in for Rookery's lookup: records every request body and answers from a small table that
    matches a recipient written `@domain` by the domain's host verdict, as the oracle does."""

    def __init__(self, bad_domains: tuple[str, ...] = ()):
        self.bodies: list[dict] = []
        self.bad = set(bad_domains)

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.bodies.append(body)
        verdicts = []
        for q in body["entities"]:
            v = {"kind": q["kind"], "value": q["value"], "verdict": "unknown", "match": "none"}
            target = q["value"].lstrip("@").lower()
            if q["kind"] in ("host", "recipient") and target in self.bad:
                v.update(verdict="known_bad", match="exact")
            verdicts.append(v)
        return httpx.Response(200, json={"verdicts": verdicts, "library_snapshot": "lib-v1-test"})

    def sent_values(self) -> list[str]:
        return [q["value"] for body in self.bodies for q in body["entities"]]


def _oracle(fake: FakeRookery) -> HttpOracle:
    o = HttpOracle("http://rookery.test")
    o._http = httpx.Client(
        base_url="http://rookery.test", transport=httpx.MockTransport(fake.handler)
    )
    return o


def test_an_email_recipient_is_sent_as_its_mail_domain_only():
    fake = FakeRookery()
    r = _oracle(fake).lookup(
        [EntityQuery("recipient", ADDRESS, ("recipient",)), EntityQuery("host", DOMAIN)]
    )
    sent = fake.sent_values()
    assert sent == ["@" + DOMAIN, DOMAIN]
    raw = json.dumps(fake.bodies)
    assert "quillon" not in raw.lower() and "marsh" not in raw.lower()
    # no value with a local part reaches the oracle
    assert all(not v.partition("@")[0] for v in sent if "@" in v)
    v = r.get("recipient", ADDRESS)
    assert v.value == ADDRESS and v.verdict is VerdictKind.UNKNOWN and v.match is Match.NONE


def test_a_known_bad_mail_domain_still_taints_the_address():
    fake = FakeRookery(bad_domains=(DOMAIN,))
    r = _oracle(fake).lookup([EntityQuery("recipient", ADDRESS, ("recipient",))])
    v = r.get("recipient", ADDRESS)
    assert v.verdict is VerdictKind.KNOWN_BAD and v.match is Match.EXACT
    assert v.value == ADDRESS and v.source == "library"
    assert fake.sent_values() == ["@" + DOMAIN]


def test_two_addresses_at_one_domain_go_once_with_their_roles_merged():
    fake = FakeRookery(bad_domains=(DOMAIN,))
    r = _oracle(fake).lookup(
        [
            EntityQuery("recipient", "ana@" + DOMAIN, ("recipient",)),
            EntityQuery("recipient", "bo@" + DOMAIN.upper(), ("mentioned",)),
        ]
    )
    assert fake.bodies[0]["entities"] == [
        {"kind": "recipient", "value": "@" + DOMAIN, "roles": ["mentioned", "recipient"]}
    ]
    assert r.get("recipient", "ana@" + DOMAIN).verdict is VerdictKind.KNOWN_BAD
    assert r.get("recipient", "bo@" + DOMAIN.upper()).verdict is VerdictKind.KNOWN_BAD


def test_other_contact_details_are_never_sent():
    fake = FakeRookery()
    personal = [
        EntityQuery("recipient", "+44 7700 900123", ("recipient",)),  # a phone number
        EntityQuery("recipient", "@quillon_m", ("recipient",)),  # a chat handle
        EntityQuery("recipient", "Quillon Marsh", ("recipient",)),  # a name
        EntityQuery("channel", "user:U0QUILLON1", ("recipient",)),  # a direct message
        EntityQuery("channel", "slack:dm:D0QUILLON1", ("recipient",)),
        EntityQuery(
            "channel", "447700900123@s.whatsapp.net", ("recipient",)
        ),  # a phone-number chat id
    ]
    public = [
        EntityQuery("channel", "channel:C0OPSYARD1", ("recipient",)),
        EntityQuery("host", DOMAIN),
    ]
    r = _oracle(fake).lookup(personal + public)
    assert fake.sent_values() == ["channel:C0OPSYARD1", DOMAIN]
    for q in personal:
        v = r.get(q.kind, q.value)
        assert v.verdict is VerdictKind.UNKNOWN and v.match is Match.NONE


def test_nothing_to_send_makes_no_request():
    fake = FakeRookery()
    r = _oracle(fake).lookup([EntityQuery("recipient", "+44 7700 900123", ("recipient",))])
    assert fake.bodies == [] and r.available
    assert r.get("recipient", "+44 7700 900123").verdict is VerdictKind.UNKNOWN


def test_wire_query_and_mail_domain():
    assert mail_domain(ADDRESS) == DOMAIN
    assert mail_domain("@handle") is None and mail_domain("no-at.example") is None
    assert mail_domain("x@localhost") is None
    assert wire_query(EntityQuery("recipient", ADDRESS)) == EntityQuery("recipient", "@" + DOMAIN)
    assert wire_query(EntityQuery("host", "pypi.org")) == EntityQuery("host", "pypi.org")
    assert wire_query(EntityQuery("package", "npm:@scope/pkg")) == EntityQuery(
        "package", "npm:@scope/pkg"
    )
    assert wire_query(EntityQuery("channel", "#ops-yard")) == EntityQuery("channel", "#ops-yard")
