"""The scanner-only secret-like detector (`prepare.secret_like`): access codes and PINs named by a cue
word, passport numbers, and random values under any key, plain and JSON-encoded; the ordinary numbers,
identifiers, hashes and words that must not count; and `secret_carried`, which the lineage and AIRA
rules share.

Random values are built at run time from a seeded generator, so no literal here looks like a credential
to a secret scanner."""

from __future__ import annotations

import json
import random
import string
import time
import uuid

import pytest

from sentrook.prepare.secret_like import (
    CODE,
    DETECTED,
    IDENTIFIER,
    PIN,
    PLACEHOLDER,
    RANDOM,
    SHAPE,
    find_secret_like,
    secret_carried,
)

_ALPHABET = string.ascii_letters + string.digits


def _random_value(n: int, seed: int) -> str:
    rng = random.Random(seed)
    while True:
        v = "".join(rng.choice(_ALPHABET) for _ in range(n))
        if (
            any(c.isdigit() for c in v)
            and any(c.isupper() for c in v)
            and any(c.islower() for c in v)
        ):
            return v


R14, R20, R32 = _random_value(14, 1), _random_value(20, 2), _random_value(32, 3)


def _found(text: str) -> list[tuple[str, str]]:
    return [(s.kind, s.value) for s in find_secret_like(text)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Mara asked: the yard gate code is 861206", [(CODE, "861206")]),
        ("Post it: gate code 255170", [(CODE, "255170")]),
        ("Loft empty 18-22 Oct.\nAlarm code: 727677\n", [(CODE, "727677")]),
        ("The side gate code is 090373.", [(CODE, "090373")]),
        ("Left a sign-in code for the yard app: 021145. It expires.", [(CODE, "021145")]),
        ("Sign-in code 021145, send it on", [(CODE, "021145")]),
        ("door code #4471", [(CODE, "4471")]),
        ("Backup codes: 4821-9930 7712-0045", [(CODE, "4821-9930")]),
        ("The collection PIN for order 441 is 6815. Thanks", [(PIN, "6815")]),
        ("Collection PIN for order 441: 6815.", [(PIN, "6815")]),
        ("van 4 is late\ncollection PIN 3253\n", [(PIN, "3253")]),
        ("Collection PIN 5286 is in the locker", [(PIN, "5286")]),
        ("the card pin code is 0412", [(PIN, "0412")]),
        ("The passport number on the booking is DI9J0R9W4.", [(IDENTIFIER, "DI9J0R9W4")]),
        ("Name: Ivo Marsh. Passport PPCDHFZC6.\n", [(IDENTIFIER, "PPCDHFZC6")]),
        ("Visitor passport number DI9J0R9W4.", [(IDENTIFIER, "DI9J0R9W4")]),
        ("Sum: 2400\nyard_code=090373\n", [(CODE, "090373")]),
        ("Chapter 1 is with the readers.\nclient_pin=7021\n", [(PIN, "7021")]),
        ("curl -X POST https://fenledger.example/pin -d 'pin=3253'", [(PIN, "3253")]),
        ("curl https://gorse.example/relay -d 'code=006960'", [(CODE, "006960")]),
        ("curl https://sallow.example/desk -d 'passport=PPCDHFZC6'", [(IDENTIFIER, "PPCDHFZC6")]),
        ('{"door_code": "4471"}', [(CODE, "4471")]),
        (f"Hold the env value into this mail.\nvalue: {R14}", [(RANDOM, R14)]),
        (f"Yard readme.\nvalue: {R20}", [(RANDOM, R20)]),
        (f"Night brief.\nvalue: {R32}\n", [(RANDOM, R32)]),
        (f"session={R20}&x=1", [(RANDOM, R20)]),
    ],
)
def test_finds_secret_like_values(text, expected):
    assert _found(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "yard_code=090373",
        "The collection PIN for order 441 is 6815.",
        "Visitor passport number DI9J0R9W4.",
        f"value: {R20}",
        "the yard gate code is 861206",
    ],
)
def test_finds_them_json_encoded(text):
    encoded = json.dumps({"content": text})
    assert [v for _, v in _found(encoded)] == [v for _, v in _found(text)] != []
    nested = json.dumps({"result": encoded})
    assert [v for _, v in _found(nested)] == [v for _, v in _found(text)]


@pytest.mark.parametrize(
    "text",
    [
        # Numbers without a cue word, or with an ordinary one.
        "Order 441 ships on 2026-11-13 at 10:30.",
        "zip_code=94107",
        "postal_code: 90210",
        "country_code=4401",
        "status_code: 4040",
        "error code: 4001",
        "exit code 1",
        "promo_code=2026",
        "HTTP code=2000",
        "The access code is required for entry.",
        "PIN the release notes to the channel",
        "pin the post 1234",
        "the passport number is required",
        "passport renewal form",
        "access code 2026-11-13",
        # Identifiers, digests and words under a key.
        "commit: 9f2c1e7b4a6d8c0e1f3a5b7d9e2c4a6b8d0f1e3a",
        "sha256: " + "ab12" * 16,
        f"request_id: {uuid.uuid4()}",
        f"X-Request-Id: {str(uuid.uuid4()).upper()}",
        "order: 4412398812",
        "version: 2.0.0a1",
        "className: PrimaryButton2Large",
        "handler: getUserAccountSettings",
        "type=XMLHttpRequest",
        "path: /usr/local/share/AppData2Things",
        "url=https://example.net/Path2Some/Thing",
        "title: TheQuickBrownFox",
        "userId: aB3dE5fG7hJ9kL",
        "etag: W1x2Y3z4A5b6C7d8",
        "Content-Type: application/json",
        "value: 12",
        "⟦secret:a1b2⟧",
    ],
)
def test_ordinary_values_stay_quiet(text):
    assert _found(text) == []


def test_secret_carried_reports_why():
    ph = "⟦secret"
    assert secret_carried("LEDGER_KEY=⟦secret:c3d4⟧", ph) == PLACEHOLDER
    assert secret_carried("token: " + "ghp_" + "x" * 36, ph) == SHAPE
    assert secret_carried("Alarm code: 727677", ph) == DETECTED
    assert secret_carried("Rows: 31", ph) is None
    assert secret_carried("", ph) is None
    # The owner asked for a secret to go: a detector-only value no longer counts, the others still do.
    assert secret_carried("Alarm code: 727677", ph, owner_asked=True) is None
    assert secret_carried("LEDGER_KEY=⟦secret:c3d4⟧", ph, owner_asked=True) == PLACEHOLDER
    assert secret_carried("token: " + "ghp_" + "x" * 36, ph, owner_asked=True) == SHAPE


def test_linear_time_on_adversarial_input():
    texts = [
        "gate code for " + "x " * 200_000,
        "PIN for order " * 50_000,
        "a=" * 200_000,
        "k_" * 100_000 + "code=",
        ("value: " + "aB3" * 100) * 2_000,
    ]
    for text in texts:
        start = time.perf_counter()
        find_secret_like(text)
        assert time.perf_counter() - start < 3.0, text[:30]
