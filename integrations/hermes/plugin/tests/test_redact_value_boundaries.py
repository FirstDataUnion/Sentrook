"""Where a key's value ends. `&`, `,` and `;` end a link's query value (`?password=X&page=2`), a list item (`a=1,b=2`)
and a shell command (`cmd; next`, `&&`), but inside an assignment, an `.env` line or a quoted value they are part of
the value (`password=Tr0ub4dor&3`), so no part of it leaves the host, and one value gets one placeholder however it
is written. The OpenClaw plugin's `redact.ts` gives the same output.

Values are built at run time, so no literal here looks like a credential to a secret scanner."""

from __future__ import annotations

import json
import re
import subprocess
import time

import pytest

from plugin.redact import Redactor

from .test_redact_cues import _REDACT_TS, _forms, _node_major, _random_value

AMP = "Tr0ub4" + "dor&3"
SEMI = "Xy7kQ" + ";9pLm2Wz"
COMMA = "Pa55" + ",word99"
SHORT_HEAD = "ab" + "&cdefgh12"
DIGIT_HEAD = "12" + "&Tr0ub4dor"
P9 = "Tr0ub4" + "dor"
R = _random_value(11, 31)
PH = r"⟦secret:credential:[0-9a-f]{4}⟧"

# (text, the value that must be replaced whole: nothing of it left, one placeholder in its place).
WHOLE = [
    (f"password={AMP}", AMP),
    (f"password='{AMP}'", AMP),
    (f'password="{AMP}"', AMP),
    (f"export DB_PASSWORD={AMP}", AMP),
    (f"password={SHORT_HEAD}", SHORT_HEAD),
    (f"token={SEMI}", SEMI),
    (f"password={COMMA}", COMMA),
    (f"password: {AMP}", AMP),
    (f'"password": "{AMP}"', AMP),
    (f"password={DIGIT_HEAD}", DIGIT_HEAD),
    (f"SENTROOK_SECRET_TOKEN={AMP}xyz", AMP + "xyz"),
    (f"SENTROOK_SECRET_TOKEN='{AMP}xyz'", AMP + "xyz"),
    # A separator at the end of a shell line, or before a space, is not part of the value.
    (f"password={AMP};", AMP),
    (f"export DB_PASSWORD={AMP}; echo ok", AMP),
    (f"DB_PASSWORD={AMP} && echo ok", AMP),
]

# (text, the value replaced): what follows the value stays as it is.
BOUNDED = [
    (f"GET /login?password={P9}&page=2", P9),
    (f"curl -d 'user=a&password={P9}&remember=1'", P9),
    (f"curl -d 'password={P9}&remember=1'", P9),
    (f"a=1,b=2,token={R},c=3", R),
    (f"export TOKEN={R}; echo ok", R),
    (f"export TOKEN={R};", R),
    (f"token={R}, next", R),
    (f"TOKEN={R}&&echo ok", R),
    (f"https://app.example/cb#access_token={R}&token_type=Bearer&expires_in=3600", R),
    (f'href="https://x.example/?token={R}&amp;page=2"', R),
]


def _replaced(text: str, value: str) -> re.Pattern[str]:
    head, tail = text.split(value, 1)
    return re.compile(re.escape(head) + PH + re.escape(tail))


@pytest.mark.parametrize(("text", "value"), WHOLE + BOUNDED)
def test_the_value_is_replaced_whole_and_only_the_value(text, value):
    r = Redactor("standard", "test-salt")
    out = r.string(text)
    assert _replaced(text, value).fullmatch(out), out


@pytest.mark.parametrize(("text", "value"), WHOLE)
def test_nothing_of_the_value_leaves_in_a_tool_result(text, value):
    r = Redactor("standard", "test-salt")
    for form in _forms(text)[:2]:
        out = r.string(form)
        # Each part with the separator before it (`&3`), and a first part long enough not to be in a placeholder.
        for part in re.findall(r"[&,;]?[^&,;]+", value):
            if part[0] in "&,;" or len(part) >= 4:
                assert part not in out, (form, out)


def test_one_value_gets_one_placeholder_however_it_is_written():
    r = Redactor("standard", "test-salt")
    for value in (AMP, SEMI, COMMA, SHORT_HEAD):
        outs = {
            re.search(PH, r.string(text)).group()
            for text in (
                f"password={value}",
                f"password: {value}",
                f'"password": "{value}"',
                f"password='{value}'",
                f"export DB_PASSWORD={value}",
                f"the password is {value}",
            )
        }
        assert len(outs) == 1, (value, outs)


def test_code_after_a_key_stays():
    """`;` after code's closing bracket ends the statement, not the value."""
    r = Redactor("standard", "test-salt")
    for text in ("var token=getToken();fetch(u)", "token = creds.get('token');next()"):
        assert r.string(text) == text


def test_separators_in_values_stay_linear_on_adversarial_input():
    r = Redactor("standard", "test-salt")
    for text in (
        "token=" + "a&" * 50_000,
        "token=a" + "&b" * 50_000 + "&",
        "password=x" + "&k=" * 30_000,
        "MY_SECRET_TOKEN=" + "ab&" * 30_000,
        "token=" + ("a" * 39 + "&") * 2_000,
        "token=ab" + ")&" * 30_000,
        "password='" + "a&" * 50_000,
    ):
        start = time.perf_counter()
        r.string(text)
        assert time.perf_counter() - start < 3.0, text[:30]


@pytest.mark.skipif(_node_major() < 2206, reason="needs node 22.6+ to run redact.ts")
def test_parity_with_the_openclaw_plugin():
    texts = [f for t, _ in WHOLE + BOUNDED for f in _forms(t)]
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
