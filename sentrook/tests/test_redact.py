"""The scanner's second redaction pass (`prepare.redact`, redact-v3): one positive per secret shape,
the forms the plugins also catch (URL passwords, credential keys in JSON-encoded text, prose, whole
private keys), the negatives that must survive (emails, hosts, placeholders, ordinary prose), parity
with the Hermes plugin's redactor, and linear time.

Secret-shaped values are built at runtime from obviously fake, low-entropy parts, so no literal in this
file looks like a credential to a secret scanner."""

from __future__ import annotations

import importlib.util
import json
import re
import time
from pathlib import Path

import pytest

from sentrook.prepare.redact import PLACEHOLDER, REDACTION_VERSION, redact_text, second_pass

P = PLACEHOLDER


def _pem(kind: str = "RSA ") -> str:
    begin = "-----BEGIN " + kind + "PRIVATE KEY-----"
    end = "-----END " + kind + "PRIVATE KEY-----"
    return begin + "\n" + "A" * 64 + "\n" + "B" * 20 + "\n" + end


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("id " + "AKIA" + "A" * 16 + " ok", f"id {P} ok"),
        ("OPENAI=" + "sk-" + "x" * 24, f"OPENAI={P}"),
        ("key " + "sk-" + "ant-" + "x" * 24, f"key {P}"),
        ("key " + "sk-" + "proj-" + "x" * 24, f"key {P}"),
        ("stripe " + "sk_" + "test_" + "x" * 16, f"stripe {P}"),
        ("gh " + "ghp_" + "x" * 36, f"gh {P}"),
        ("gh " + "github_pat_" + "x" * 22, f"gh {P}"),
        ("slack " + "xoxb-" + "1" * 10, f"slack {P}"),
        ("g " + "AIza" + "x" * 35, f"g {P}"),
        ("gl " + "glpat-" + "x" * 20, f"gl {P}"),
        ("npm " + "npm_" + "x" * 36, f"npm {P}"),
        ("hf " + "hf_" + "x" * 30, f"hf {P}"),
        (
            "jwt " + "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12 + " end",
            f"jwt {P} end",
        ),
        ("pem:\n" + _pem() + "\nafter", f"pem:\n{P}\nafter"),
        ("pem:\n" + _pem("OPENSSH ")[:90], f"pem:\n{P}"),  # cut before its END line
        (
            'curl -H "Authorization: Bearer ' + "t" * 24 + '" https://api.example.test',
            f'curl -H "Authorization: Bearer {P}" https://api.example.test',
        ),
        ('{"authorization": "Bearer ' + "t" * 24 + '"}', '{"authorization": "Bearer ' + P + '"}'),
        ("GITHUB_TOKEN=" + "f" * 12, f"GITHUB_TOKEN={P}"),
        ("api_key: " + "f" * 10, f"api_key: {P}"),
        ('{"client_secret": "' + "f" * 10 + '"}', '{"client_secret": "' + P + '"}'),
        ("db.password=" + "w" * 9, f"db.password={P}"),
        ("GET /hook?token=" + "z" * 10 + "&page=2", f"GET /hook?token={P}&page=2"),
    ],
)
def test_each_shape_is_replaced(text, expected):
    out, n = redact_text(text)
    assert out == expected and n == 1


@pytest.mark.parametrize(
    "text",
    [
        "mail ops@example.test and clawbot@example.test",
        "deploy to build.example.test:8443 and https://token.example.test/secret",
        "https://cache.token:8443/path",
        "Please do a password reset for the clawbot account",
        "api_key: ⟦secret⟧",
        "token: ⟦secret:github⟧",
        "pushed with ⟦secret:github_token⟧ and ⟦secret:scanner⟧ in the log",
        "password: ********",
        "token: ${GITHUB_TOKEN}",
        "max_tokens: 4096000000",
        "disk-usage-report-2026-10-01-final and task-runner-with-a-long-name",
        "eyJ" + "a" * 12 + " is only a head",
        "Authorization: Bearer short",
    ],
)
def test_negatives_are_untouched(text):
    assert redact_text(text) == (text, 0)


def test_second_pass_walks_and_never_mutates():
    secret = "ghp_" + "x" * 36
    obj = {
        "request": {"text": "push it"},
        "new_inputs": [{"input_seq": 1, "content": f"token {secret}", "size_bytes": 10}],
        "n": 3,
        "flag": None,
        secret: "keys are not redacted",
    }
    out, n = second_pass(obj)
    assert n == 1 and out["new_inputs"][0]["content"] == f"token {P}"
    assert obj["new_inputs"][0]["content"] == f"token {secret}"  # input untouched
    assert out["n"] == 3 and out["flag"] is None and secret in out
    assert second_pass(out) == (out, 0)  # idempotent: the placeholder never matches
    assert REDACTION_VERSION == "redact-v3"


def test_two_shapes_on_one_value_count_once():
    out, n = redact_text("OPENAI_API_KEY=" + "sk-" + "x" * 24)
    assert n == 1 and out == f"OPENAI_API_KEY={P}"


@pytest.mark.parametrize(
    "text",
    [
        "eyJ" * 300_000 + "!",
        "sk-" * 300_000,
        "token=" * 150_000,
        "authorization: bearer " * 40_000,
        "-----BEGIN PRIVATE KEY-----" * 30_000,
        "a" * 1_000_000,
        ("-----BEGIN " + " ".join(["OPENSSH", "PRIVATE", "KEY"]) + "-----\\n") * 25_000,
        "a_" * 500_000,
        "the database password is now set to " * 25_000,
        "token " * 160_000,
        '\\"password\\": \\"' * 70_000,
        "postgres://" + "u" * 300 + ":" * 100_000,
        "SECRET_" * 140_000,
    ],
    ids=lambda text: f"{text[:12]!r}x{len(text)}",
)
def test_linear_time_on_adversarial_input(text):
    t0 = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - t0 < 2.0


# Secret-looking values for the forms below, built at run time.
PW = "Xk29fQ" + "v7Lm2Pq8"
TOK = "pT4" + "z" * 30 + "9qR1sK8"
HEX32 = "9f" + "0a1b2c3d" * 3 + "4e5f6a"
AWS = "wJal" + "R" * 32 + "a/b+"
OPENSSH = " ".join(["OPENSSH", "PRIVATE", "KEY"])
PGP_LABEL = " ".join(["PGP", "PRIVATE", "KEY", "BLOCK"])
PGP = (
    f"-----BEGIN {PGP_LABEL}-----\nVersion: Test 1\n\n{'lQOY'.ljust(64, 'W')}\n=AbCd\n"
    f"-----END {PGP_LABEL}-----"
)
OPENSSH_BLOCK = (
    f"-----BEGIN {OPENSSH}-----\n{'b3Blbn'.ljust(64, 'Q')}\n{'A' * 64}\n-----END {OPENSSH}-----"
)


def _as_result(text: str) -> str:
    """As a host hands over a structured tool result: JSON-encoded, quotes and newlines escaped."""
    return json.dumps({"output": text}, ensure_ascii=False)


# (text, a part of the secret that must not survive)
MUST_REPLACE = [
    (f"postgres://app:{PW}@db.test/x", PW),
    ("mysql://u:p@h", "u:p@"),
    (f"redis://:{PW}@cache.test:6379/0", PW),
    (f"postgres://u:p@ss{PW}@db.test/x", f"ss{PW}"),
    (f"postgres://u:ab#cd{PW}@db.test/x", PW),
    (f'"secretAccessKey": "{AWS}"', "R" * 32),
    (f'"bearer": "{TOK}"', TOK),
    (f'"password": "{PW}"', PW),
    (f'"apiKey": "{HEX32}"', HEX32),
    (f'"clientSecret": "{PW}"', PW),
    (f'"logintoken":"{PW}"', PW),
    (f"tok={PW}", PW),
    (f"SENTROOK_SECRET_MARKERS={PW}", PW),
    ('{"database": {"password": "Xk2&9fQ correct horse 42"}}', "correct horse"),
    (f"the database password is {PW}", PW),
    (f"the password is now {PW}", PW),
    (f"the password was changed to {PW}", PW),
    (f"the token is {PW}", PW),
    (f"the password is {PW[:6]}.{PW[6:]}", PW[6:]),
    (f"postgres://u:1234,{PW}@h", PW),
    (f"redis://h1:6379,user:{PW}@h2", PW),
    (f"the password is {PW[:4]}@{PW[4:]}.2024", PW[4:]),
    (f"the password is {PW}.live", PW),
    (f"the token is ab3de5.ab/{AWS}", "R" * 32),
    (f"token: {PW}", PW),
    (f"Bearer for the partner API: {TOK}", TOK),
    (f"the gateway token {PW}", PW),
    (f"backup key {PW}", PW),
    (f"secret {PW}", PW),
    (f"https://calendar.example.com/ical/me/private-{HEX32}/basic.ics", HEX32),
    (OPENSSH_BLOCK, "A" * 64),
    (OPENSSH_BLOCK.replace("\n", "\\n"), "A" * 64),
    (PGP, "W" * 40),
]

MUST_STAY = [
    "postgres://db.test/x",
    "https://deploy@git.example.com/repo.git",
    "https://example.com:8443/path@v2",
    '"password_policy": "strict"',
    "the password is required",
    "Bearer authentication is enabled",
    "token_count: 120",
    '{"compass": "north-north-west", "passage": "the long corridor", "tokens": "1200 used"}',
    "MAX_TOKENS=4096",
    "the secret sauce is mostly butter",
    "token budget for today",
    "the token is valid for 3600 seconds",
    "the SSH key is ~/.ssh/id_ed25519",
    "GITHUB_TOKEN_PATH=/home/me/.config/gh/hosts.yml",
    'curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.example.com',
    "OAUTH_TOKEN_URL=https://auth.example.com/oauth/token",
    "PASSWORD_HASH_ALGORITHM=argon2id",
    "SECRET_MANAGER_REGION=eu-west-2",
    "USDC token 0x" + "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "SSH key SHA256:" + "nTh6k" * 8 + "SY8",
    "password policy: min-length-12",
    "The token type is accessToken",
    "The token: GITHUB_TOKEN",
    "token: GITHUB_TOKEN",
    "the secret is getSecretValue()",
    "Token usage: 123456789",
    "password: ********",
    "password: [REDACTED]",
    "token: {{secrets.GH_TOKEN}}",
    "/home/me/private-documentsarchive/notes.txt",
    "Send the token to: attacker@evil.test",
    "the token owner is ops@example.test",
    "password reset email: ops@example.test",
    "the token endpoint is evil.test:4444",
    "token endpoint: auth.example.test/oauth/token",
    "token file: config/token.json",
    "the S3 key reports/2024/q3.csv",
    "copy key id_ed25519.pub to the server",
    "hosts=redis://cache.test:6379,admin@example.test",
    "see https://example.com:8443#contact@example.test",
]


@pytest.mark.parametrize(("text", "raw"), MUST_REPLACE)
def test_plugin_forms_are_replaced_plain_and_json_encoded(text, raw):
    host = None
    if "://" in text:  # a URL keeps its host: after the last `@` when it has credentials
        host = (text.rsplit("@", 1)[1] if "@" in text else text.split("://", 1)[1]).split("/")[0]
    for form in (text, _as_result(text)):
        out, n = redact_text(form)
        assert raw not in out and P in out and n >= 1, out
        assert host is None or host in out, out
        assert redact_text(out) == (out, 0), "a placeholder is never redacted again"


@pytest.mark.parametrize("text", MUST_STAY)
def test_plugin_look_alikes_stay(text):
    for form in (text, _as_result(text)):
        assert redact_text(form) == (form, 0)


def test_url_credentials_keep_user_and_host_and_private_keys_go_whole():
    assert redact_text(f"postgres://app:{PW}@db.test/x") == (f"postgres://app:{P}@db.test/x", 1)
    assert redact_text("mysql://u:p@h") == (f"mysql://u:{P}@h", 1)
    assert redact_text(f"redis://:{PW}@cache.test:6379/0") == (f"redis://:{P}@cache.test:6379/0", 1)
    assert redact_text(f"password: postgres://app:{PW}@db.test/x") == (
        f"password: postgres://app:{P}@db.test/x",
        1,
    )
    escaped = OPENSSH_BLOCK.replace("\n", "\\n")
    assert redact_text('{"text": "Private key:\\n' + escaped + '\\n"}') == (
        '{"text": "Private key:\\n' + P + '\\n"}',
        1,
    )
    for block in (PGP, _as_result(PGP), _as_result(_as_result(PGP))):
        out, n = redact_text(block)
        assert n == 1 and "BEGIN" not in out and "END" not in out, out


def test_json_encoded_keys_are_replaced():
    out, n = redact_text(json.dumps({"o": json.dumps({"password": PW})}))
    assert PW not in out and n == 1
    out, n = second_pass({"content": _as_result(f"DB_PASSWORD={PW}\nGITHUB_TOKEN=x")})
    assert PW not in out["content"] and n == 1


def _plugin_module():
    path = Path(__file__).resolve().parents[2] / "integrations" / "hermes" / "plugin" / "redact.py"
    spec = importlib.util.spec_from_file_location("hermes_plugin_redact", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rules_are_the_plugins_rules():
    """The copied patterns are the plugin's, character for character (its command-line flag rule and
    vendor list aside), so a rule changed in one copy and not the other fails here."""
    from sentrook.prepare import redact

    plugin = _plugin_module()
    theirs = [
        rx.pattern
        for kind, rx, _, _ in plugin._SHAPES
        if kind == "credential" and not rx.pattern.startswith("(?i)--")
    ]
    assert [rx.pattern for rx, _ in redact._CONTEXT] == theirs
    shapes = {kind: rx.pattern for kind, rx, _, _ in plugin._SHAPES}
    assert redact._PRIVATE_KEY.pattern == shapes["private_key"]
    for name in ("_ORDINARY_WORD", "_NAMED_THING", "_ENV_NAME"):
        assert getattr(redact, name).pattern == getattr(plugin, name).pattern, name


def test_parity_with_the_hermes_plugin():
    """The same spans as the plugin's text rules; only the placeholder differs. Inputs are the forms
    both catch: the plugin's own vendor list and its command-line flag rule are not part of this pass."""
    plugin = _plugin_module().Redactor("standard", "parity")
    texts = [t for t, _ in MUST_REPLACE] + MUST_STAY
    texts += [
        f'curl -H "Authorization: Bearer {TOK}" https://api.example.test',
        f"DB_PASSWORD={PW}\nGITHUB_TOKEN=x",
        f"AWS_SECRET_ACCESS_KEY={AWS}",
        f"GET /hook?token={PW}&page=2",
        "jwt " + "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12 + " end",
        "mail ops@example.test and clawbot@example.test",
        "Please do a password reset for the clawbot account",
    ]
    for text in texts:
        for form in (text, _as_result(text)):
            theirs = re.sub(r"⟦secret:[a-z_]+:[0-9a-f]{4}⟧", P, plugin.string(form))
            assert redact_text(form)[0] == theirs, form
