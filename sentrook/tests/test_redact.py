"""The scanner's second redaction pass (`prepare.redact`, redact-v1): one positive per secret shape,
the negatives that must survive (emails, hosts, placeholders, ordinary prose), and linear time.

Secret-shaped values are built at runtime from obviously fake, low-entropy parts, so no literal in this
file looks like a credential to a secret scanner."""

from __future__ import annotations

import time

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
    assert REDACTION_VERSION == "redact-v1"


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
    ],
)
def test_linear_time_on_adversarial_input(text):
    t0 = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - t0 < 2.0
