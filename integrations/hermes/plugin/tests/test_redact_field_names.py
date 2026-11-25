"""A key's value that is plainly not a secret stays (redact-v12): a credential field's name or a placeholder for one,
as docs, templates and code write it (`api_key:api_secret`, `password: your_password`), or a short lower-case word.
Real values under the same keys are still redacted, and the OpenClaw plugin's `redact.ts` gives the same output.

Values are built at run time, so no literal here looks like a credential to a secret scanner."""

from __future__ import annotations

import json
import subprocess

import pytest

from plugin.redact import Redactor

from .test_redact_cues import _REDACT_TS, _forms, _node_major, _random_value

R36, R40 = _random_value(36, 11), _random_value(40, 12)
LIVE = "sk-" + "live-" + _random_value(24, 13)
GHP = "gh" + "p_" + R36
TROUBADOR = "Tr0ub4" + "dor&3"

# Docs prose, templates and code that name a field: nothing in them is a secret.
MUST_STAY = [
    "api_key:api_secret",
    "password: your_password",
    "token=<token>",
    '"Authorization: Bearer YOUR_TOKEN"',
    "api_key:api_secret as basic auth",
    "Admin API takes api_key:api_secret as basic auth",
    "api_key = your_api_key",
    '"api_key": "your_api_key_here"',
    "apiKey=apiSecret",
    "client_secret=client_secret",
    "token: xxxxxxxx",
    "API_KEY=YOUR_API_KEY_HERE",
    "password=changeme",
    "the password: your_password",
    "SENTROOK_SECRET_TOKEN=your_secret_token",
]

# (text, the value that must go): real values under the same keys.
MUST_REDACT = [
    (f"api_key: {LIVE}", LIVE),
    (f"password: {TROUBADOR}", TROUBADOR[:9]),
    (f"token={GHP}", GHP),
    (f"secret={R40}", R40),
    (f'"api_key": "{R40}"', R40),
    (f"client_secret={R36}", R36),
    # Words with a digit or mixed case are a value, and so is a lower-case word longer than a short one.
    ("password=hunter2hunter2", "hunter2hunter2"),
    ("password=Sunshine", "Sunshine"),
    ("token=correcthorsebattery", "correcthorsebattery"),
    ("api_key=api_secret2", "api_secret2"),
    ("token=xxxxxxx9", "xxxxxxx9"),
]


@pytest.mark.parametrize("text", MUST_STAY)
def test_field_names_and_placeholders_stay(text):
    r = Redactor("standard", "test-salt")
    for form in _forms(text):
        assert r.string(form) == form


@pytest.mark.parametrize(("text", "value"), MUST_REDACT)
def test_real_values_under_the_same_keys_are_redacted(text, value):
    r = Redactor("standard", "test-salt")
    for form in _forms(text):
        out = r.string(form)
        assert value not in out, form
        assert "⟦secret:" in out, (form, out)


def test_an_object_value_under_a_credential_key_is_still_replaced_whole():
    """A parsed object's value under a credential key is what the call sends, whatever it looks like."""
    out = Redactor("standard", "test-salt").value({"api_key": "api_secret", "password": "sunshine"})
    assert all(v.startswith("⟦secret:credential:") for v in out.values()), out


@pytest.mark.skipif(_node_major() < 2206, reason="needs node 22.6+ to run redact.ts")
def test_parity_with_the_openclaw_plugin():
    texts = [f for t in MUST_STAY for f in _forms(t)] + [
        f for t, _ in MUST_REDACT for f in _forms(t)
    ]
    js = (
        f"import {{ createRedactor }} from {json.dumps(_REDACT_TS.as_uri())};"
        "const input = JSON.parse((await import('node:fs')).readFileSync(0, 'utf8'));"
        "const r = createRedactor('standard', 'parity');"
        "process.stdout.write(JSON.stringify(input.map((t) => r.string(t))));"
    )
    out = subprocess.run(
        ["node", "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", js],
        input=json.dumps(texts),
        capture_output=True,
        text=True,
        check=True,
    )
    r = Redactor("standard", "parity")
    assert [r.string(t) for t in texts] == json.loads(out.stdout)
