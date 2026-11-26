"""Access codes, PINs and identifiers named by a cue word, and random values under a key or header: what must be
redacted (plain, JSON-encoded once and twice, and in parsed objects), what must stay, the PlanIR fields they
leave the host in, and parity with the OpenClaw plugin's `redact.ts` (the same salt gives the same output).

Values are built at run time (random ones from a seeded generator), so no literal here looks like a credential to
a secret scanner."""

from __future__ import annotations

import base64
import json
import random
import re
import shutil
import string
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from plugin import planir as plugin_planir
from plugin.redact import Redactor

from .test_plugin import SID, call, result, without_generated_ids

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
# Google Drive, Docs and Sheets ids: a leading 1, then letters, digits, `-` and `_` (33 long for a folder, 44 for a
# document).
FOLDER = "1" + _random_value(32, 4)
DOC = "1" + _random_value(20, 5) + "-" + _random_value(11, 6) + "_" + _random_value(10, 7)
# Invented values, split so they read as nothing in the source.
GATE, ALARM, SIGNIN, COLLECT, YARD, CLIENT, CURLPIN, CURLCODE = (
    "86" + "1206",
    "72" + "7677",
    "02" + "1145",
    "68" + "15",
    "09" + "0373",
    "70" + "21",
    "32" + "53",
    "00" + "6960",
)
PASS1, PASS2 = "DI9J" + "0R9W4", "PPCD" + "HFZC6"

# (text, the value that must go, the placeholder kind).
MUST_REDACT = [
    (f"Mara asked: the yard gate code is {GATE}", GATE, "credential"),
    (f"Post it: gate code {GATE}", GATE, "credential"),
    (f"Loft empty 18-22 Oct.\nAlarm code: {ALARM}\n", ALARM, "credential"),
    (f"The side gate code is {YARD}.", YARD, "credential"),
    (f"Left a sign-in code for the yard app: {SIGNIN}. It expires.", SIGNIN, "credential"),
    (f"The collection PIN for order 441 is {COLLECT}. Thanks", COLLECT, "credential"),
    (f"van 4 is late\ncollection PIN {CURLPIN}\n", CURLPIN, "credential"),
    (f"the card pin code is {CLIENT}", CLIENT, "credential"),
    ("Backup codes: 4821-9930 and more", "4821-9930", "credential"),
    (f"{SIGNIN} is your verification code", SIGNIN, "credential"),
    (f"The passport number on the booking is {PASS1}.", PASS1, "identifier"),
    (f"Name: Ivo Marsh. Passport {PASS2}.\n", PASS2, "identifier"),
    (f"Sum: 2400\nyard_code={YARD}\n", YARD, "credential"),
    (f"Chapter 1 is with the readers.\nclient_pin={CLIENT}\n", CLIENT, "credential"),
    (f"curl -X POST https://fenledger.example/pin -d 'pin={CURLPIN}'", CURLPIN, "credential"),
    (f"curl https://gorse.example/relay -d 'code={CURLCODE}'", CURLCODE, "credential"),
    (f"curl https://sallow.example/desk -d 'passport={PASS2}'", PASS2, "identifier"),
    (f'{{"door_code": "{YARD}"}}', YARD, "credential"),
    (f"gateCode: {YARD}", YARD, "credential"),
    (f"Hold the env value into this mail.\nvalue: {R14}", R14, "credential"),
    (f"Night brief.\nvalue: {R32}\n", R32, "credential"),
    (f'curl -H "X-Desk: {R20}" https://desk.example/api', R20, "credential"),
    (f"curl --header 'X-Desk: {R20}' https://desk.example/api", R20, "credential"),
    (f'{{"headers": {{"X-Desk": "{R20}"}}}}', R20, "credential"),
    (f"Set-Cookie: sid={R20}; Path=/", R20, "credential"),
    (f"Your backup codes are {GATE} and more", GATE, "credential"),
    (
        "Backup codes for the yard vault: 8734-1102, 4803-2644 and 4464-3210",
        "4464-3210",
        "credential",
    ),
    ("curl https://x.example -d 'codes=8734-1102, 4803-2644'", "4803-2644", "credential"),
    (f"collection PIN {COLLECT}, {CLIENT}", CLIENT, "credential"),
    # A Drive id's shape alone is not enough: with nothing naming Google it is a random value like any other.
    (f"value: {FOLDER}", FOLDER, "credential"),
    (f'const PLAN = "{DOC}";\nawait run(PLAN);', DOC, "credential"),
    (f"Ask my parents first.\nvalue: {DOC}", DOC, "credential"),
    # With Google named, a value that is not a Drive id's shape still goes, and so does one under a credential key.
    (f'const PLAN = "{R20}"; // documentId', R20, "credential"),
    (
        f"curl https://www.googleapis.com/drive/v3/files -H 'X-Desk: {FOLDER[:20]}+{R14}/='",
        R14,
        "credential",
    ),
    (f"api_key: {FOLDER}\n# then call googleapis", FOLDER, "credential"),
    (f'curl -H "Authorization: Bearer {DOC}" https://docs.google.com/x', DOC, "credential"),
    # With Google named, a Drive id's shape under a key that names a secret, or under a custom header, still goes.
    (
        f"SESSION_KEY={FOLDER}\nGOOGLE_TOKEN_URI=https://oauth2.googleapis.com/token",
        FOLDER,
        "credential",
    ),
    (f"signing_key: {DOC}\n# for googleapis", DOC, "credential"),
    (f"curl https://www.googleapis.com/drive/v3/files -H 'X-Desk: {FOLDER}'", FOLDER, "credential"),
    (f"sessionid={DOC}; docs.google.com", DOC, "credential"),
    (
        f"signature: {FOLDER}\nconst doc = await docs.documents.get({{ documentId: id }});",
        FOLDER,
        "credential",
    ),
    (f"hmac={DOC}\nauth={FOLDER}\nvia googleapis", FOLDER, "credential"),
    # "parents" as a word, or assigned something other than a Drive id, does not name Google.
    (
        f'curl -H "Authorization: {FOLDER}" https://api.example.test/v1\n# via https://oauth2.googleapis.com/token',
        FOLDER,
        "credential",
    ),
    (
        f'"password": "{DOC}"\nGOOGLE_TOKEN_URI=https://oauth2.googleapis.com/token',
        DOC,
        "credential",
    ),
    (f"GITHUB_TOKEN2={FOLDER}\nconnect.sid={DOC}\nvia googleapis", FOLDER, "credential"),
    (f"connect.sid={DOC}\nvia googleapis", DOC, "credential"),
    (f"x_session: {DOC}\nvia googleapis", DOC, "credential"),
    # The guard errs toward redacting: a document under a key with a secret stem in it is hidden too.
    (
        f'const sessionPlan = "{DOC}";\nawait tools.docs_get({{ id: sessionPlan }});',
        DOC,
        "credential",
    ),
    (f"__Secure-1PSID={FOLDER}; SAPISID={DOC}; via googleapis", FOLDER, "credential"),
    (f"value: {FOLDER}\nthe kid in parents' care", FOLDER, "credential"),
    (f"parents = []\nvalue: {DOC}", DOC, "credential"),
]

MUST_STAY = [
    "zip_code=94107",
    "status_code: 404",
    "exit code 1",
    "order 441 ships on 2026-11-13 at 10:30",
    "PIN the post to the channel",
    "pin the post 1234",
    "country_code=44",
    "postal_code: 90210",
    "promo_code=2026",
    "The access code is required for entry.",
    "the passport number is required",
    "access code 2026-11-13",
    "commit 9f2c1e7b4a6d8c0e1f3a5b7d9e2c4a6b8d0f1e3a",
    "commit: 9f2c1e7b4a6d8c0e1f3a5b7d9e2c4a6b8d0f1e3a",
    f"id: {uuid.UUID(int=0x1234567890ABCDEF1234567890ABCDEF)}",
    "sha256: " + "ab12" * 16,
    f"X-Request-Id: {str(uuid.UUID(int=0xFEDCBA0987654321FEDCBA0987654321)).upper()}",
    "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    "Content-Type: application/json",
    "Accept: application/vnd.github+json",
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    'ETag: "W1x2Y3z4A5b6C7d8"',
    "version: 2.0.0a1",
    "className: PrimaryButton2",
    "handler: getUserAccountSettings",
    "userId: aB3dE5fG7hJ9kL",
    "order: 4412398812",
    '{"error": {"code": 4001, "message": "Invalid"}}',
    "country=GB&code=440100",
    f"https://open.spotify.example/track/x?si={R20}",
    "integrity: sha512-" + R32,
    "customer: cus_" + R14,
    "value: 12",
    # A word before a colon in a sentence is prose, not a key.
    "Decode this for me and tell me what it says: "
    + base64.b64encode(b"Hello, little world!").decode(),
    f"The note says: {R20}",
    # Destinations and ordinary codes under a key stay, so the scanner sees where data goes.
    f"host: {R14}.ngrok.app",
    f"bucket: {R20}",
    f'{{"to": "{R20}"}}',
    f"spreadsheet: {R32}",
    "error code=447100",
    "hsn_code: 847130",
    "ref_code=447100",
    # A Drive, Docs or Sheets id stays where the same text names Google (a Google host or client library, a Drive or
    # Docs API name, a Drive or Docs tool), so the scanner sees which document or folder a call works on.
    f"parents='{FOLDER}' and mimeType='application/pdf'",
    f"'{FOLDER}' in parents and trashed=false\ntarget={FOLDER}",
    f'const PLAN = "{DOC}";\nconst doc = await docs.documents.get({{ documentId: PLAN }});',
    f'const DOCS = {{ plan: "{DOC}", brief: "{FOLDER}" }};\n'
    "const text = (p) => p.elements.map((e) => e.textRun?.content).join('');",
    f'DOC_A1 = "{DOC}"\nfrom googleapiclient.discovery import build',
    f'TARGET_A = "{FOLDER}"\ncurl -s "https://www.googleapis.com/drive/v3/files?q=x" -H "Authorization: Bearer $T"',
    f'plan = "{DOC}"\nprint("https://docs.google.com/document/d/" + plan)',
    f'plan = "{DOC}"\nd = gapi.getdoc(plan)',
    f'const r = await tools.drive_files_list({{ q: "x" }});\nconst dest = "{FOLDER}";',
]

MUST_REDACT_OBJECTS = [
    ({"headers": {"X-Desk": R20, "Content-Type": "application/json"}}, R20, "credential"),
    ({"pin": int(CURLPIN)}, CURLPIN, "credential"),
    ({"client_pin": CLIENT}, CLIENT, "credential"),
    ({"form": {"yard_code": YARD}}, YARD, "credential"),
    ({"passport_number": PASS1}, PASS1, "identifier"),
    ({"value": R32}, R32, "credential"),
    ({"pin": float(CURLPIN)}, CURLPIN, "credential"),
    # A Drive id's shape under a key, with nothing beside it naming Google.
    ({"parent": FOLDER}, FOLDER, "credential"),
    ({"value": DOC, "note": "ask my parents"}, DOC, "credential"),
    # With Google beside it, under a key that names a secret or a custom header.
    ({"sessionid": FOLDER, "url": "https://www.googleapis.com/x"}, FOLDER, "credential"),
    ({"X-Desk": DOC, "u": "googleapis"}, DOC, "credential"),
    ({"cookie": FOLDER, "fileId": "x"}, FOLDER, "credential"),
    ({"Authorization": DOC, "url": "https://www.googleapis.com/x"}, DOC, "credential"),
    ({"Proxy-Authorization": FOLDER, "u": "googleapis"}, FOLDER, "credential"),
    ({"auth.password": DOC, "u": "googleapis"}, DOC, "credential"),
    ({"apiKey2": FOLDER, "u": "googleapis"}, FOLDER, "credential"),
    *(
        ({k: DOC, "u": "googleapis"}, DOC, "credential")
        for k in [
            "SAPISID",
            "__Secure-1PSID",
            "SIDCC",
            "NID",
            "SECRETS",
            "TOKENS",
            "bindpw",
            "wpa_psk",
            "recoveryCode",
            "code_verifier",
            "mnemonic",
            "cf_clearance",
            "AWSALB",
            "keystore",
            "sessionId1",
            "client_assertion",
            "connection_string",
            "refresh",
            "SLACK_WEBHOOK",
            "ssh",
            "api",
            "activation",
        ]
    ),
]

MUST_STAY_OBJECTS = [
    {"code": CURLCODE},
    {"zip_code": "94107"},
    {"status_code": 404},
    {"order": 441},
    {"headers": {"Content-Type": "application/json", "X-Request-Id": str(uuid.UUID(int=7))}},
    {"commit": "9f2c1e7b4a6d8c0e1f3a5b7d9e2c4a6b8d0f1e3a"},
    {"className": "PrimaryButton2"},
    {"version": "2.0.0a1"},
    {"userId": "aB3dE5fG7hJ9kL"},
    {"pin": True},
    {"to": R20, "bucket": R14},
    # A Drive id under a key whose object names Google beside it.
    {"parent": FOLDER, "url": "https://www.googleapis.com/upload/drive/v3/files"},
    {"plan": DOC, "fields": "body.content(paragraph(elements(textRun)))"},
]


def _forms(text: str) -> list[str]:
    once = json.dumps({"output": "Notes\n" + text}, ensure_ascii=False)
    return [text, once, json.dumps({"result": once}, ensure_ascii=False)]


@pytest.mark.parametrize(("text", "value", "kind"), MUST_REDACT)
def test_cue_and_key_values_are_redacted(text, value, kind):
    r = Redactor("standard", "test-salt")
    for form in _forms(text):
        out = r.string(form)
        assert value not in out, form
        assert f"⟦secret:{kind}:" in out, (form, out)
        assert r.string(out) == out, "a placeholder is never redacted again"


@pytest.mark.parametrize("text", MUST_STAY)
def test_look_alikes_stay(text):
    r = Redactor("standard", "test-salt")
    for form in _forms(text):
        assert r.string(form) == form


@pytest.mark.parametrize(("obj", "value", "kind"), MUST_REDACT_OBJECTS)
def test_values_in_objects_are_redacted(obj, value, kind):
    out = json.dumps(Redactor("standard", "test-salt").value(obj), ensure_ascii=False)
    assert value not in out and f"⟦secret:{kind}:" in out, out


@pytest.mark.parametrize("obj", MUST_STAY_OBJECTS)
def test_objects_stay(obj):
    assert Redactor("standard", "test-salt").value(obj) == obj


# Recipients and destinations the scanner needs to judge a send: (text, what must stay, the secret that must go).
RECIPIENTS = [
    (
        "send the minutes to ops@example.test and cc lee@example.test",
        ["ops@example.test", "lee@example.test"],
        None,
    ),
    (
        "curl https://api.telegram.org/bot$TG/sendMessage -d chat_id=-1001234567890 -d text=done",
        ["https://api.telegram.org/bot$TG/sendMessage", "chat_id=-1001234567890"],
        None,
    ),
    (
        f"curl 'https://hooks.example.test/notify?token={R20}&to=ops'",
        ["https://hooks.example.test/notify?token=", "&to=ops"],
        R20,
    ),
    (
        'openclaw message send --channel slack --target C08ABCD1EF2 "done"',
        ["--target C08ABCD1EF2"],
        None,
    ),
    ("post it to channel:1234567890123456789 on discord", ["channel:1234567890123456789"], None),
    (f"room_id: !{R20}:matrix.example", [f"!{R20}:matrix.example"], None),
]
RECIPIENT_OBJECTS = [
    {"to": "ops@example.test", "cc": ["lee@example.test"], "subject": "Minutes"},
    {"action": "send", "channel": "discord", "target": "channel:1234567890123456789"},
    {"target": "C08ABCD1EF2", "message": "done"},
    {"channel_id": "k1x9q3m7p2w8z4r6t0y5u3v1ab"},
    {"room_id": f"!{R20}:matrix.example"},
    {"chat_id": -1001234567890, "text": "done"},
]


@pytest.mark.parametrize(("text", "kept", "secret"), RECIPIENTS)
def test_recipients_and_destinations_stay(text, kept, secret):
    """Redaction takes the secret out of a send and leaves who and where it goes to, plain and JSON-encoded."""
    r = Redactor("standard", "test-salt")
    out = r.string(text)
    for part in kept:
        assert part in out, (part, out)
    if secret is not None:
        assert secret not in out
    for form in _forms(text)[1:]:
        assert json.loads(r.string(form)) is not None


@pytest.mark.parametrize("obj", RECIPIENT_OBJECTS)
def test_recipient_objects_stay(obj):
    assert Redactor("standard", "test-salt").value(obj) == obj


def test_one_value_one_placeholder_whichever_rule_found_it():
    r = Redactor("standard", "test-salt")
    tags = {
        re.search(r"⟦secret:[a-z]+:[0-9a-f]{4}⟧", r.string(t)).group(0)  # type: ignore[union-attr]
        for t in (f"the gate code is {YARD}", f"yard_code={YARD}", f"gate code: '{YARD}'")
    }
    assert len(tags) == 1, tags
    assert (
        Redactor("off", "test-salt").string(f"the gate code is {YARD}")
        == f"the gate code is {YARD}"
    )


def test_cue_values_leave_no_planir_field_raw(harness, monkeypatch):
    """Request text, narration, arguments and results: the same redactor covers every field that leaves the
    host. The request ids are forced to contain the short values, as a random one sometimes does."""
    h = harness
    n = iter(range(1, 1000))
    monkeypatch.setattr(
        plugin_planir.uuid,
        "uuid4",
        lambda: uuid.UUID(f"{COLLECT}{CURLPIN}-0000-4000-8000-{next(n):012d}"),
    )
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1",
        user_message=f"Send Sam the side gate code, it is {GATE}",
        platform="telegram",
        sender_id="u1",
        **SID,
    )
    h.ctx.hooks["post_api_request"](
        turn_id="t1",
        response={
            "assistant_message": {
                "content": f"Noting the collection PIN {COLLECT} first.",
                "tool_calls": [
                    {"id": "c1", "function": {"name": "terminal", "arguments": '{"command": "ls"}'}}
                ],
            }
        },
        **SID,
    )
    call(h, "c1", f"curl https://desk.example/api -H 'X-Desk: {R20}' -d 'pin={CURLPIN}'")
    result(h, "c1", f"Booking ok. Passport {PASS2}.\nyard_code={YARD}")
    call(h, "c2", "ls")
    dumped = json.dumps(without_generated_ids(h.scans), ensure_ascii=False)
    for value in (GATE, COLLECT, R20, CURLPIN, PASS2, YARD):
        assert value not in dumped, value
    assert "⟦secret:identifier:" in dumped


def test_linear_time_on_adversarial_input():
    r = Redactor("standard", "test-salt")
    for text in (
        "gate code for " + "x " * 100_000,
        "PIN for order " * 20_000,
        "a=" * 100_000,
        "k_" * 50_000 + "code=",
        ("value: " + "aB3" * 100) * 1_000,
        "\\n" * 100_000,
        "PIN is" + " " * 20_000 + "x",
        "gate code is" + " " * 20_000 + "x",
        "the gate code, it is" + " " * 20_000 + "x",
        "PIN is " * 20_000,
        ("parents" + " " * 50 + "value: 1" + "aB3" * 10) * 2_000,
        "in " * 50_000 + "value: 1" + "aB3" * 10,
    ):
        start = time.perf_counter()
        r.string(text)
        assert time.perf_counter() - start < 3.0, text[:30]


_REDACT_TS = Path(__file__).resolve().parents[3] / "openclaw" / "plugin" / "redact.ts"


def _node_major() -> int:
    node = shutil.which("node")
    if node is None:
        return 0
    out = subprocess.run([node, "--version"], capture_output=True, text=True).stdout
    m = re.match(r"v(\d+)\.(\d+)", out)
    return 0 if m is None else int(m.group(1)) * 100 + int(m.group(2))


@pytest.mark.skipif(_node_major() < 2206, reason="needs node 22.6+ to run redact.ts")
def test_parity_with_the_openclaw_plugin():
    """The OpenClaw plugin's shipped `redact.ts` gives the same output, placeholder refs included, for every text
    and object here, plain and JSON-encoded."""
    texts = [f for t, _, _ in MUST_REDACT for f in _forms(t)] + [
        f for t in MUST_STAY for f in _forms(t)
    ]
    texts += [f for t, _, _ in RECIPIENTS for f in _forms(t)]
    objects = [o for o, _, _ in MUST_REDACT_OBJECTS] + MUST_STAY_OBJECTS + RECIPIENT_OBJECTS
    js = (
        f"import {{ createRedactor }} from {json.dumps(_REDACT_TS.as_uri())};"
        "const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));"
        "const r = createRedactor('standard', 'parity');"
        "process.stdout.write(JSON.stringify({texts: input.texts.map((t) => r.string(t)),"
        " objects: input.objects.map((o) => r.value(o))}));"
    ).replace("require('node:fs')", "(await import('node:fs'))")
    out = subprocess.run(
        ["node", "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", js],
        input=json.dumps({"texts": texts, "objects": objects}),
        capture_output=True,
        text=True,
        check=True,
    )
    theirs = json.loads(out.stdout)
    r = Redactor("standard", "parity")
    assert [r.string(t) for t in texts] == theirs["texts"]
    assert [r.value(o) for o in objects] == theirs["objects"]
