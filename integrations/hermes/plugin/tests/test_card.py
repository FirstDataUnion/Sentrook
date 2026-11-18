"""The review card (`card`): the shared golden cases, the hosts' budgets, and what never reaches it."""

import html
import json
import random
from pathlib import Path

import pytest

from plugin import card
from plugin.scan_error_policy import ScanFailure, scan_error_copy

FIXTURE = json.loads(
    (Path(__file__).parents[3] / "fixtures" / "review-card" / "cases.json").read_text(
        encoding="utf-8"
    )
)
CASES = FIXTURE["cases"]


def _hermes(c):
    return card.hermes_message(
        c["response"],
        c["tool"],
        relaxed=c["relaxed"],
        hint=c["hint"],
        remember=c["remember"],
        why_id=c["why_id"],
    )


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_card_is_the_agreed_text(case):
    assert _hermes(case) == case["hermes"]
    # The OpenClaw card is built by card.ts; this copy keeps the two from drifting apart.
    assert (
        card.openclaw_card(
            case["response"],
            case["tool"],
            relaxed=case["relaxed"],
            hint=case["hint"],
            remember=case["remember"],
            why_id=case["why_id"],
        )
        == case["openclaw"]
    )


@pytest.mark.parametrize("case", FIXTURE["errors"], ids=[c["name"] for c in FIXTURE["errors"]])
def test_the_scan_error_card_is_the_agreed_text(case):
    assert card.hermes_error_message(case["cause"]) == case["hermes"]


def test_each_scan_failure_gets_its_card():
    def text(kind, status=None):
        return scan_error_copy(ScanFailure(ok=False, kind=kind, detail="x", status=status))

    assert text("rate_limited") == card.hermes_error_message("rate_limited")
    assert text("config") == card.hermes_error_message("config")
    assert text("http", 401) == card.hermes_error_message("auth")
    for kind, status in (("network", None), ("timeout", None), ("http", 503), ("scan_error", None)):
        assert text(kind, status) == card.hermes_error_message("unreachable")


def _budget(text):
    return len(html.escape(text).encode("utf-16-le")) // 2


def test_the_card_never_runs_over_the_hosts_budgets():
    """Whatever the scan sends, Hermes's text fits its Discord card and OpenClaw's title and description are never
    refused."""
    rng = random.Random(7)
    alphabet = "abc&<>\"'é🪶😀\n\t‍ /.-_@[]`" + "x" * 20
    for _ in range(400):

        def word(n):
            return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, n)))

        ents = {f"E{i}": {"display": word(400)} for i in range(1, 4)}
        reasons = [
            {"code": "a.b", "text": f"{{E{rng.randint(1, 4)}}} " + word(200)} for _ in range(4)
        ]
        resp = {
            "risk": rng.uniform(0, 100),
            "enforced": rng.choice([None, "review"]),
            "tool_description": rng.choice(
                [None, {"template": "Sends {E1} to {E2} via {E3} " + word(80)}]
            ),
            "entities": ents,
            "reasons": rng.choice([[], reasons]),
        }
        hint = rng.choice(
            [
                None,
                {"kind": "destination", "pattern": "h" * rng.randint(1, 300)},
                {
                    "kind": "file",
                    "pattern": "/p" * rng.randint(1, 150),
                    "allows": ["read", "write"],
                },
                # letters a host escapes, markup and mentions: a command the card must not show as typed
                {
                    "kind": "destination",
                    "pattern": "x" + "\u3164\u115f\uffa0" * rng.randint(1, 120),
                },
                {
                    "kind": "file",
                    "pattern": "/t/<@1>`[x]|@everyone" * rng.randint(1, 20),
                    "allows": ["read"],
                },
            ]
        )
        kw = {
            "relaxed": rng.random() < 0.3,
            "hint": hint,
            "remember": rng.random() < 0.5,
            "why_id": rng.choice([None, "3f9c2a1b-77aa"]),
        }
        text = card.hermes_message(resp, word(300) or "t", **kw)
        assert _budget(text) <= FIXTURE["budgets"]["hermes"], text
        assert text.startswith(card.MARK)
        oc = card.openclaw_card(resp, word(300) or "t", **kw)
        assert len(oc["title"]) <= FIXTURE["budgets"]["openclaw_title"]
        assert len(oc["description"]) <= FIXTURE["budgets"]["openclaw_description"]
        for t in (text, oc["title"], oc["description"]):
            assert not any(card._odd(c) for c in t if c != "\n"), t


def test_the_card_carries_no_redacted_data():
    secret = "ghp_" + "A" * 36
    resp = {
        "risk": 90,
        "tree": {"suspicion": {"score": 0.9, "note": secret}, "extra": {"score": secret}},
        "tool_description": {"template": "Sends {E2} to {E1}"},
        "reasons": [
            {
                "code": "exfil.exec_egress",
                "subject": secret,
                "detail": {"value": secret},
                "signal": secret,
                "text": "it sends sensitive data to {E1}",
            }
        ],
        "entities": {
            "E1": {"kind": "host", "display": "cl0ud-sync.io"},
            "E2": {"kind": "path", "display": "~/x"},
            "E3": {"display": secret},
        },
    }
    msg = card.hermes_message(resp, "exec", why_id="3f9c2a1b")
    assert secret not in msg
    assert msg.splitlines()[1:3] == [
        "Sends ~/x to cl0ud-sync.io.",
        "Because it sends sensitive data to cl0ud-sync.io.",
    ]
