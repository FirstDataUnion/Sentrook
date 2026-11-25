"""A quoted key's value that plainly stands in for a secret stays: the word REDACTED or a mask (`********`) under any
key, and under a token or key (not a password) a token cut short with an ellipsis, as docs abridge one
(`"access_token": "ya29.a0..."`), or a phrase that says what it is (`"short-lived token"`). A full token, a short
password before an ellipsis, a passphrase and any command-line value are still redacted, and the OpenClaw plugin's
`redact.ts` gives the same output.

Values are built at run time, so no literal here looks like a credential to a secret scanner."""

from __future__ import annotations

import json
import subprocess

import pytest

from plugin.redact import Redactor

from .test_redact_cues import _REDACT_TS, _forms, _node_major, _random_value

R20, R40 = _random_value(20, 21), _random_value(40, 22)
R10, R11, R15 = _random_value(10, 23), _random_value(11, 24), _random_value(15, 25)
TROUB = "Tr0ub4" + "dor&3"
HUNTER = "hun" + "ter2"
GOOGLE = "ya" + "29."
REFRESH = "1/" + "/0"

# Docs that show a token file's shape with its values abridged or masked: nothing in them is a secret.
MUST_STAY = [
    f'"access_token": "{GOOGLE}a0..."',
    f'"refresh_token": "{REFRESH}g..."',
    '"api_key": "xxxxxxxx"',
    '"token": "REDACTED"',
    '"access_token": "short-lived token"',
    f'"access_token": "{GOOGLE}<...>"',
    f'"refresh_token": "{REFRESH}g…"',
    '"client_secret": "••••••••"',
    '"password": "(redacted)"',
    "token: REDACTED",
    "API_KEY=REDACTED",
    '"api_key": "paste your key here"',
    '"api_key": "your api key"',
    '"access_token": "access token"',
    f'"api_key": "{R10}..."',
    '"password": "••••••••"',
    '"password": "REDACTED"',
    f'{{"access_token": "{GOOGLE}a0...", "refresh_token": "{REFRESH}g...", "token_type": "Bearer", '
    '"expires_in": 3599}',
]

# (text, the value that must go): real values under the same keys.
MUST_REDACT = [
    # A full-length token, and the same token with an ellipsis after it.
    (f'"access_token": "{GOOGLE}a0{R40}"', R40),
    (f'"access_token": "{GOOGLE}a0{R40}..."', R40),
    # Twenty or more random characters before an ellipsis are a value, not an abridged example.
    (f'"api_key": "{R20}..."', R20),
    (f'"api_key": "{R20}…"', R20),
    # An unquoted value before an ellipsis may be prose ("the password is X..."): still a value.
    (f"the password is {R20[:9]}...", R20[:9]),
    (f"access_token={GOOGLE}a0...", GOOGLE + "a0"),
    # A run of one digit or letter is a password people use; a phrase with no stand-in word may be a passphrase.
    ('"password": "' + "1" * 8 + '"', "1" * 8),
    ('"password": "' + " ".join(["correct", "horse", "battery", "staple"]) + '"', "horse battery"),
    (f'"token": "my token is {R20}"', R20),
    ('"password": "your new password is ' + "Tr0ub4" + 'dor9"', "Tr0ub4dor9"),
    # Under a password, a phrase is a passphrase whatever words it has, and a short value before an ellipsis is the
    # password.
    ('"password": "here comes the sun"', "here comes the sun"),
    ('"password": "secret garden"', "secret garden"),
    ('"password": "keys to the kingdom"', "keys to the kingdom"),
    ('"password": "your key is sunshine"', "your key is sunshine"),
    ('"password": "my secret key is purple monkey"', "purple monkey"),
    ('"password": "Here Comes The Sun 1969"', "Here Comes The Sun"),
    ('"password": "token Kx"', "token Kx"),
    (f'"password": "{HUNTER}..."', HUNTER),
    (f'"password": "{TROUB}..."', TROUB[:9]),
    ('"password": "p@' + 'ssw0rd…"', "ssw0rd"),
    # Under a token or key, a phrase that does not say what the value is may be the value.
    ('"api_key": "nobody knows this secret"', "nobody knows this secret"),
    ('"api_key": "token Kx"', "token Kx"),
    ('"api_key": "here comes the sun"', "here comes the sun"),
    ('"api_key": "your mom"', "your mom"),
    # A token cut short shows at most ten token characters; more, or another symbol, may be the secret.
    (f'"api_key": "{R11}..."', R11),
    (f'"api_key": "{R15}…"', R15),
    (f'"api_key": "{R10[:8]}<...>{R10[8:]}"', R10[:8]),
    ('"session_token": "s%3A' + 'abc..."', "s%3Aabc"),
    # A run of another symbol may be a password.
    ('"password": "' + "!" * 10 + '"', "!" * 10),
    ('"password": "' + "-" * 8 + '"', "-" * 8),
    # A command-line value is what the command runs with.
    (f'--token "{HUNTER}..."', HUNTER),
    (f'--password "{TROUB}..."', TROUB[:9]),
    (f'--api-key "{R15}…"', R15),
    ('--password "my secret key is purple monkey"', "purple monkey"),
    (f'mysql -u root -p"{TROUB}..."', TROUB[:9]),
]
# Forms these rules catch only as written, not JSON-encoded.
MUST_REDACT_PLAIN = [
    (f'the password is "{TROUB}..."', TROUB[:9]),
    (f"sshpass -p '{TROUB}...' ssh host", TROUB[:9]),
]


@pytest.mark.parametrize("text", MUST_STAY)
def test_stand_ins_stay(text):
    r = Redactor("standard", "test-salt")
    for form in _forms(text):
        assert r.string(form) == form


@pytest.mark.parametrize(("text", "value"), MUST_REDACT_PLAIN)
def test_real_values_written_plainly_are_redacted(text, value):
    out = Redactor("standard", "test-salt").string(text)
    assert value not in out and "⟦secret:" in out, out


@pytest.mark.parametrize(("text", "value"), MUST_REDACT)
def test_real_values_under_the_same_keys_are_redacted(text, value):
    """Plain and JSON-encoded once, as a tool result carries it."""
    r = Redactor("standard", "test-salt")
    for form in _forms(text)[:2]:
        out = r.string(form)
        assert value not in out, form
        assert "⟦secret:" in out, (form, out)


def test_an_object_value_under_a_credential_key_is_still_replaced_whole():
    """A parsed object's value under a credential key is what the call sends, whatever it looks like."""
    out = Redactor("standard", "test-salt").value(
        {"access_token": GOOGLE + "a0...", "token": "REDACTED"}
    )
    assert all(v.startswith("⟦secret:credential:") for v in out.values()), out


@pytest.mark.skipif(_node_major() < 2206, reason="needs node 22.6+ to run redact.ts")
def test_parity_with_the_openclaw_plugin():
    texts = [f for t in MUST_STAY for f in _forms(t)] + [
        f for t, _ in MUST_REDACT + MUST_REDACT_PLAIN for f in _forms(t)
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
