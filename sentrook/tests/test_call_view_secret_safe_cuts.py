"""A cut in the call-v5 view never splits a secret.

The call-v5 view cuts long strings (an input's content, an over-budget request text, long history argument strings)
before the second redaction pass runs over the finished view. A cut point inside a secret left a fragment that no
longer had the shape the pass knows, so it reached the judge in clear. The call-v5 view (`trim-v8`) moves each cut
point out of anything the pass would replace, together with the context that identifies it (the cue word or key
before a value, and the closing quote after it): a secret is kept whole, and replaced, or cut away whole.
`scanner_truncated.kept_chars` reports what was really kept. With no secret near a cut point every cut is as before;
the older call views are unchanged.
"""

from __future__ import annotations

import copy
import json

import pytest

from sentrook.prepare import views
from sentrook.prepare.redact import PLACEHOLDER, protected_spans
from sentrook.prepare.views import (
    CALL_INPUT_CAP_CHARS,
    CALL_V3,
    CALL_V5,
    HISTORY_ARG_KEEP_CHARS,
    REQUEST_KEEP_CHARS,
    VIEW_VERSIONS,
    build_views,
)

TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
VALUE = "Zq9vT4mK8pW2xL"  # caught only by its context: a cue word or a credential key


def _filler(size: int) -> str:
    line = "notes from the weekly sync, nothing sensitive here at all.\n"
    return (line * (size // len(line) + 2))[:size]


def _place(size: int, secret: str, at: int) -> str:
    """`size` characters of filler with `secret` starting at `at`, a space on each side."""
    text = _filler(size)
    return text[: at - 1] + " " + secret + " " + text[at + len(secret) + 1 :]


def _fragments(value: str, n: int = 6) -> set[str]:
    return {value[i : i + n] for i in range(len(value) - n + 1)}


def _leaks(state: dict, value: str) -> bool:
    dumped = json.dumps(state, ensure_ascii=False)
    return any(f in dumped for f in _fragments(value))


def _with_request(case: dict, text: str) -> dict:
    raw = copy.deepcopy(case["fixture"])
    raw["request"]["text"] = text
    return raw


def _with_input(case: dict, content: str) -> dict:
    raw = copy.deepcopy(case["fixture"])
    raw["new_inputs"][0]["content"] = content
    return raw


def _v5(raw: dict, budget: int | None = None):
    return build_views(raw, exposure_input_seqs=None, call_budget_tokens=budget)


REQ_LEN = 20_000
REQ_HEAD = REQUEST_KEEP_CHARS * 2 // 3  # where the request's head ends
REQ_TAIL = REQ_LEN - (REQUEST_KEEP_CHARS - REQ_HEAD)  # where its tail starts


@pytest.mark.parametrize(
    ("secret", "at", "value"),
    [
        (TOKEN, REQ_HEAD - 20, TOKEN),  # a token across the head's end
        (TOKEN, REQ_TAIL - 20, TOKEN),  # a token across the tail's start
        (
            f"password: {VALUE} ok",
            REQ_TAIL - 4,
            VALUE,
        ),  # the tail would start inside the cue, keeping the bare value
        (
            f'{{"apiKey": "{VALUE}"}}',
            REQ_HEAD - 13 - len(VALUE),
            VALUE,
        ),  # the head would end before the closing quote
    ],
)
def test_a_request_cut_never_sends_part_of_a_secret(attack_case, secret, at, value):
    """Must fire: the request cut used to send a fragment the second pass could not recognise."""
    raw = _with_request(attack_case, _place(REQ_LEN, secret, at))
    views_ = _v5(raw, budget=4000)
    built = views_[CALL_V5]
    assert built.request_cut
    assert not _leaks(built.state, value)
    req = built.state["request"]
    rec = req["scanner_truncated"]
    assert rec["kept_chars"] < REQUEST_KEEP_CHARS and rec["of_chars"] == REQ_LEN
    assert f"[sentrook: {REQ_LEN - rec['kept_chars']} characters cut]" in req["text"]


@pytest.mark.parametrize(
    ("secret", "offset"),
    [(f"/usr/bin/mysql -u root -p{VALUE}", off) for off in range(1, 12)]
    + [(f"echo hi\\nmysql -u root -p{VALUE}", off) for off in range(1, 14)],
)
def test_a_tail_never_drops_the_context_a_secret_needs(attack_case, secret, offset):
    """The mysql rule reads the characters before `mysql`: a tail starting there kept the password without them."""
    raw = _with_request(attack_case, _place(REQ_LEN, secret, REQ_TAIL - offset))
    for target in (raw, _with_input(attack_case, _place(12_000, secret, 12_000 - 2000 - offset))):
        built = _v5(target, budget=4000 if target is raw else None)[CALL_V5]
        assert not _leaks(built.state, VALUE), offset


def test_a_cut_never_lets_a_new_match_swallow_a_secrets_cue(attack_case):
    """Whole, `fooXpassword is …` is no cue (a letter before it) and the second `password is now X` is redacted. A tail
    starting after `fooX` made the first cue live; its match ran over the second cue and the value went out in clear."""
    phrase = f"fooXpassword is ab-cd-ef,password is now {VALUE}r7 bar"
    raw = _with_request(attack_case, _place(REQ_LEN, phrase, REQ_TAIL - 4))
    assert not _leaks(_v5(raw, budget=4000)[CALL_V5].state, VALUE)
    raw = _with_input(attack_case, _place(12_000, phrase, 12_000 - 2000 - 4))
    assert not _leaks(_v5(raw)[CALL_V5].state, VALUE)


def test_an_input_cut_never_sends_part_of_a_secret(attack_case):
    length = 12_000
    head_end = CALL_INPUT_CAP_CHARS * 2 // 3
    tail_start = length - (CALL_INPUT_CAP_CHARS - head_end)
    for at in (head_end - 15, tail_start - 25):
        raw = _with_input(attack_case, _place(length, TOKEN, at))
        entry = _v5(raw)[CALL_V5].state["new_inputs"][0]
        assert TOKEN[:6] not in entry["content"] or PLACEHOLDER in entry["content"]
        assert not _leaks({"c": entry["content"]}, TOKEN), at
        assert entry["scanner_truncated"]["kept_chars"] < CALL_INPUT_CAP_CHARS


def test_a_history_argument_cut_never_sends_part_of_a_secret(attack_case):
    raw = copy.deepcopy(attack_case["fixture"])
    template = raw["history"][0]
    raw["history"] = []
    for n in range(1, 21):
        step = copy.deepcopy(template)
        step.update(step=n, call_id=f"call_{n}", tool="write_file", tool_kind="file_write")
        content = _place(6000, TOKEN, HISTORY_ARG_KEEP_CHARS - 10) if n == 1 else _filler(6000)
        if n == 1:
            placed = content
        step["arguments"] = {"path": f"notes/day-{n}.md", "content": content}
        raw["history"].append(step)
    raw["session"]["step"] = 21
    built = _v5(raw, budget=15_000)[CALL_V5]
    first = built.state["history"][0]
    assert built.history_cut and "scanner_truncated" in first
    assert not _leaks(first, TOKEN)
    assert first["scanner_truncated"]["kept_chars"] == HISTORY_ARG_KEEP_CHARS - 10
    assert first["arguments"]["content"] == placed[: HISTORY_ARG_KEEP_CHARS - 10]


@pytest.mark.parametrize("at", [100, REQ_LEN - 300])
def test_a_secret_inside_the_kept_part_is_still_replaced(attack_case, at):
    raw = _with_request(attack_case, _place(REQ_LEN, TOKEN, at))
    built = _v5(raw, budget=4000)[CALL_V5]
    assert PLACEHOLDER in built.state["request"]["text"] and not _leaks(built.state, TOKEN)
    assert built.state["request"]["scanner_truncated"]["kept_chars"] == REQUEST_KEEP_CHARS
    assert built.redactions >= 1


def test_with_no_secret_near_a_cut_point_every_cut_is_as_before(attack_case):
    """Must stay silent: the cut keeps exactly the head and tail it kept before."""
    text = _place(REQ_LEN, TOKEN, 9_000)  # in the cut-away middle
    req = _v5(_with_request(attack_case, text), budget=4000)[CALL_V5].state["request"]
    tail = REQUEST_KEEP_CHARS - REQ_HEAD
    assert req["text"].startswith(text[:REQ_HEAD]) and req["text"].endswith(text[-tail:])
    assert req["scanner_truncated"]["kept_chars"] == REQUEST_KEEP_CHARS
    content = _filler(12_000)
    entry = _v5(_with_input(attack_case, content))[CALL_V5].state["new_inputs"][0]
    assert entry["scanner_truncated"]["kept_chars"] == CALL_INPUT_CAP_CHARS


def test_the_older_call_views_are_unchanged(attack_case):
    content = _place(12_000, TOKEN, 5_990)  # across the head-only cut at 6,000
    entry = _v5(_with_input(attack_case, content))[CALL_V3].state["new_inputs"][0]
    assert entry["content"] == content[:CALL_INPUT_CAP_CHARS]
    assert entry["scanner_truncated"] == {"kept_chars": CALL_INPUT_CAP_CHARS, "of_chars": 12_000}


def test_protected_spans_cover_the_context_and_merge():
    text = f"x password: {VALUE} and {TOKEN} end"
    spans = protected_spans(text)
    cue = text.index("password")
    assert any(s <= cue and e >= text.index(VALUE) + len(VALUE) for s, e in spans)
    assert any(s <= text.index(TOKEN) and e >= text.index(TOKEN) + len(TOKEN) for s, e in spans)
    assert spans == sorted(spans) and all(
        a[1] <= b[0] for a, b in zip(spans, spans[1:], strict=False)
    )
    assert protected_spans("short") == []


def test_spans_are_found_once_per_string_during_the_fill(attack_case, monkeypatch):
    """The over-budget fill cuts each input many times; its secret spans are found once."""
    calls: list[int] = []
    real = views.protected_spans

    def counting(text: str):
        calls.append(len(text))
        return real(text)

    monkeypatch.setattr(views, "protected_spans", counting)
    views._protected_spans.cache_clear()
    raw = copy.deepcopy(attack_case["fixture"])
    raw["history"] = []
    template = raw["new_inputs"][0]
    raw["new_inputs"] = []
    for seq in (1, 2, 3):
        entry = copy.deepcopy(template)
        entry.update(input_seq=seq, content=_filler(9000 + seq))
        raw["new_inputs"].append(entry)
    raw["pending_call"]["arguments"]["command"] = "echo " + "p" * 30_000
    built = _v5(raw, budget=15_000)[CALL_V5]
    assert built.inputs_truncated
    assert len(calls) == len(set(calls)) <= 3
    views._protected_spans.cache_clear()


def test_the_call_v5_views_version_moves_and_the_older_ones_stay():
    assert VIEW_VERSIONS[CALL_V5] == "trim-v8"
    assert VIEW_VERSIONS[CALL_V3] == "trim-v3"
