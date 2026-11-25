"""The vendor key shapes of the second redaction pass as data (`prepare.redact_shapes`) and the importer
that regenerates them from the gitleaks rules (`prepare.redact_import`).

Every shape is checked against an example built at runtime from its own regex (the shortest
alternative, each repeat at its minimum count, each character class giving `x`, `0` or `X` where it
can), so the values are invented, low in
entropy, and no literal in this file looks like a credential to a secret scanner. The importer is
tested on a small invented rules file; nothing here fetches."""

from __future__ import annotations

import re
from pathlib import Path
from re import _parser as sre_parse  # type: ignore[attr-defined]

import pytest
from linear_time import FACTOR, assert_linear

from sentrook.cli import main as cli_main
from sentrook.prepare import redact_import
from sentrook.prepare.redact import PLACEHOLDER, redact_text, second_pass
from sentrook.prepare.redact_shapes import (
    SHAPES_PATH,
    clear_cache,
    load_shapes,
    load_shapes_from,
    read_file,
)

P = PLACEHOLDER
DATA = read_file(SHAPES_PATH)
SHAPES = load_shapes_from(SHAPES_PATH).shapes
IDS = [s.name for s in SHAPES]

_CATEGORIES = {
    "CATEGORY_DIGIT": r"\d",
    "CATEGORY_NOT_DIGIT": r"\D",
    "CATEGORY_WORD": r"\w",
    "CATEGORY_NOT_WORD": r"\W",
    "CATEGORY_SPACE": r"\s",
    "CATEGORY_NOT_SPACE": r"\S",
}


def _in_class(items, ch: str) -> bool:
    negate, hit = False, False
    for op, av in items:
        name = str(op)
        if name == "NEGATE":
            negate = True
        elif name == "LITERAL":
            hit |= ord(ch) == av
        elif name == "RANGE":
            hit |= av[0] <= ord(ch) <= av[1]
        elif name == "CATEGORY":
            hit |= re.fullmatch(_CATEGORIES[str(av)], ch) is not None
    return hit != negate


def _pick(items) -> str:
    for ch in "x0X-_. ":
        if _in_class(items, ch):
            return ch
    for op, av in items:
        if str(op) == "LITERAL":
            return chr(av)
        if str(op) == "RANGE":
            return chr(av[0])
    raise AssertionError(f"no example character for {items}")


def _gen(items) -> str:
    out: list[str] = []
    for op, av in items:
        name = str(op)
        if name == "LITERAL":
            out.append(chr(av))
        elif name == "IN":
            out.append(_pick(av))
        elif name == "ANY":
            out.append("x")
        elif name in ("MAX_REPEAT", "MIN_REPEAT"):
            out.append(_gen(av[2]) * av[0])
        elif name == "SUBPATTERN":
            out.append(_gen(av[-1]))
        elif name == "BRANCH":
            out.append(_gen(min(av[1], key=lambda alt: alt.getwidth()[0])))
        elif name not in ("AT", "ASSERT"):
            raise AssertionError(f"no example for {name}")
    return "".join(out)


def example(regex: str) -> str:
    return _gen(sre_parse.parse(regex))


# --------------------------------------------------------------------------- the list


def test_list_loads_with_its_upstream_source_and_version():
    up = DATA["upstream"]
    assert up["name"] == "gitleaks" and up["path"] == "config/gitleaks.toml"
    assert up["license"] == "MIT" and redact_import.TAG_RE.fullmatch(up["tag"])
    assert load_shapes_from(SHAPES_PATH).version == f"{DATA['version']};gitleaks={up['tag']}"
    assert "Copyright (c) 2019 Zachary Rice" in SHAPES_PATH.read_text(encoding="utf-8")
    assert len(IDS) == len(set(IDS))
    sources = {s.source for s in SHAPES}
    assert sources == {"sentrook", "gitleaks"}
    assert all(s.source_version == up["tag"] for s in SHAPES if s.source == "gitleaks")
    assert sum(s.source == "gitleaks" for s in SHAPES) >= 100


def test_hand_kept_shapes_are_the_redact_v1_set():
    local = [s.name for s in SHAPES if s.source == "sentrook"]
    assert local == [
        "aws_access_key_id",
        "openai_anthropic",
        "stripe",
        "github_token",
        "github_pat",
        "slack",
        "google_api_key",
        "gitlab_pat",
        "npm_token",
        "huggingface",
    ]
    assert all(s.source_version == "redact-v1" for s in SHAPES if s.source == "sentrook")


def test_generic_shapes_are_not_in_the_list():
    skipped = DATA["skipped"]
    assert set(skipped["generic"]) == set(redact_import.GENERIC)
    assert not {"generic-api-key", "private-key", "jwt"} & set(IDS)


@pytest.mark.parametrize("shape", SHAPES, ids=IDS)
def test_each_shape_compiles_and_masks_its_own_example(shape):
    assert re.compile(shape.regex).pattern == shape.regex
    assert shape.min_length == redact_import.min_length(shape.regex)
    value = example(shape.regex)
    assert shape.compiled.fullmatch(value), value
    assert len(value) == shape.min_length
    assert redact_text("id " + value + " end") == (f"id {P} end", 1)
    # a prefix inside a longer word does not match
    assert not any(True for _ in _bounded(shape, "q" + value))


def _bounded(shape, text: str):
    from sentrook.prepare.redact_shapes import spans

    return spans(shape.compiled, text)


def test_placeholder_is_unchanged_and_never_matches():
    assert P == "⟦secret:scanner⟧"
    for shape in SHAPES:
        assert not shape.compiled.search(P)
    value = example(next(s.regex for s in SHAPES if s.name == "github-pat"))
    out, n = second_pass({"content": f"push with {value}", "label": P})
    assert n == 1 and out == {"content": f"push with {P}", "label": P}
    assert second_pass(out) == (out, 0)


def test_no_shape_matches_the_shapes_file_itself():
    text = SHAPES_PATH.read_text(encoding="utf-8")
    assert redact_text(text) == (text, 0)


#: A repeat with an upper limit, `{100,4096}`, caps each match attempt at that many characters. Where
#: match attempts start every few characters inside a run the shape can match (a prefix made of its
#: own body characters, `EAAM` in `EAA[MC](?i:[a-z0-9]{100,4096})`), each one scans up to the cap: the
#: cost grows with the square of the run while the run is a few caps long and linearly (run x cap) once
#: it is much longer. The growth check compares 1/4 and full size, so a run that is under a few caps at
#: 1/4 size reads 5-12x by where the cap falls, not by super-linear matching. Every part of the
#: adversarial input is at least this many caps long at 1/4 size, which keeps such a part near 5x.
CAP_RUNS = 6


def _largest_cap(regex: str) -> int:
    """The largest upper limit of a repeat in `regex`; 0 when it has no bounded repeat."""
    largest = 0

    def walk(items) -> None:
        nonlocal largest
        for op, av in items:
            name = str(op)
            if name in ("MAX_REPEAT", "MIN_REPEAT"):
                if av[1] != sre_parse.MAXREPEAT:
                    largest = max(largest, av[1])
                walk(av[2])
            elif name == "SUBPATTERN":
                walk(av[-1])
            elif name == "BRANCH":
                for alt in av[1]:
                    walk(alt)
            elif name in ("ASSERT", "ASSERT_NOT"):
                walk(av[1])

    walk(sre_parse.parse(regex))
    return largest


def _repeats(base: int, floor: int, unit: str) -> int:
    """How many times `unit` repeats at full size: `base`, or more when that is under `floor`
    characters, then rounded up to a multiple of FACTOR so the quarter size is not short of it."""
    return max(base, -(-floor // (len(unit) * FACTOR)) * FACTOR)


def _adversarial_texts(regex: str, divisor: int) -> list[str]:
    """Near-misses apart and back to back, the shape's prefix repeated, and a long run of its body that
    never ends the way the shape needs; at 1/`divisor` of the full size. Each part is at least
    `CAP_RUNS` caps long at 1/4 size; the sizes depend on the shape, never on `divisor`."""
    value = example(regex)
    cut = value[:-1]
    floor = CAP_RUNS * FACTOR * _largest_cap(regex)  # characters at full size
    near = 20_000 // len(value)
    run = _repeats(6_000, floor, value[-2])
    return [
        (cut + " ") * (_repeats(near, floor, cut + " ") // divisor),
        cut * (_repeats(near, floor, cut) // divisor),
        value[:6] * (_repeats(6_000, floor, value[:6]) // divisor),
        (cut + value[-2] * (run // divisor) + "!") * max(1, 36_000 // run),
    ]


def _adversarial(regex: str, divisor: int) -> None:
    for text in _adversarial_texts(regex, divisor):
        redact_text(text)


@pytest.mark.parametrize(
    ("regex", "cap"),
    [
        (r"EAA[MC](?i:[a-z0-9]{100,4096})", 4096),
        (r"(?:fo1_[\w-]{43}|fm2_[a-zA-Z0-9+\/]{100,4096}={0,3})", 4096),
        (r"(?:ab{2,5}){1,7}", 7),
        (r"x(?=[a-z]{1,9})", 9),
        (r"QQ\w*?z", 0),
        (r"ghp_[0-9a-zA-Z]{36}", 36),
    ],
)
def test_largest_cap(regex: str, cap: int):
    assert _largest_cap(regex) == cap


@pytest.mark.parametrize("shape", SHAPES, ids=IDS)
def test_adversarial_parts_are_several_caps_long_at_quarter_size(shape):
    """Both sizes the growth check times sit well past the shape's cap, so it reads how the matching
    grows and not where the cap falls."""
    cap = _largest_cap(shape.regex)
    texts = _adversarial_texts(shape.regex, FACTOR)
    assert all(len(text) >= CAP_RUNS * cap for text in texts)
    cut = example(shape.regex)[:-1]
    body_run = texts[-1].split("!")[0].removeprefix(cut)
    assert len(body_run) >= CAP_RUNS * cap


def test_bounded_time_on_adversarial_input():
    """Per shape, the time grows linearly with the adversarial input (see linear_time.py), whatever
    the runner's speed."""
    for shape in SHAPES:
        assert_linear(lambda d, regex=shape.regex: _adversarial(regex, d), what=shape.name)


def test_bounded_time_check_catches_a_quadratic_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A shape that backtracks over its whole input (each start scans to the end) fails the check.
    Quadratic rather than exponential, so the test itself finishes."""
    regex = r"QQ\w*?z"
    (tmp_path / "redact_shapes.yaml").write_text(
        f"version: 1\nshapes:\n  - {{name: test-quadratic, regex: '{regex}'}}\n", encoding="utf-8"
    )
    monkeypatch.setenv("SENTROOK_LISTS_DIR", str(tmp_path))
    clear_cache()
    try:
        assert load_shapes().shapes[-1].name == "test-quadratic"
        with pytest.raises(AssertionError, match="super-linear"):
            assert_linear(lambda d: _adversarial(regex, d), what="test-quadratic")
    finally:
        monkeypatch.delenv("SENTROOK_LISTS_DIR")
        clear_cache()


def test_file_is_current_for_its_tag(tmp_path: Path):
    """Re-rendering the packaged file from its own entries changes nothing (the import's output is a
    function of the rules, the tag and the hand-kept entries)."""
    gitleaks = [dict(s) for s in DATA["shapes"] if s["source"] == "gitleaks"]
    local = [s for s in DATA["shapes"] if s["source"] != "gitleaks"]
    text = redact_import.render(
        DATA["version"], DATA["upstream"]["tag"], local + gitleaks, DATA["skipped"]
    )
    assert text == SHAPES_PATH.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- the importer

RULES = r"""
title = "invented rules"

[[rules]]
id = "acme-api-token"
regex = '''\b(acme_(?i)[a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)'''
entropy = 3

[[rules]]
id = "acme-keyword"
regex = '''(?i)[\w.-]{0,50}?(?:acme)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)'''

[[rules]]
id = "acme-long-token"
regex = '''widget-[[:alnum:]]{40,}'''

[[rules]]
id = "acme-second-group"
regex = '''(acme)-(wkey_[a-f0-9]{24})'''
secretGroup = 2

[[rules]]
id = "acme-marker"
regex = '''acme-marker-abcdefghijklmnop'''

[[rules]]
id = "acme-two-letters"
regex = '''AC[0-9a-f]{32}'''

[[rules]]
id = "jwt"
regex = '''\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.)'''

[[rules]]
id = "acme-file"
path = '''\.acme$'''
"""


def test_convert_selects_fixed_prefix_rules_and_translates_them():
    shapes, skipped = redact_import.convert(RULES, "v1.2.3")
    by = {s["name"]: s for s in shapes}
    assert list(by) == ["acme-api-token", "acme-long-token", "acme-second-group"]
    assert by["acme-api-token"]["regex"] == "acme_(?i:[a-z0-9]{32})"
    assert by["acme-long-token"]["regex"] == "widget-[A-Za-z0-9]{40,4096}"
    assert by["acme-second-group"]["regex"] == "wkey_[a-f0-9]{24}"
    assert all(s["source"] == "gitleaks" and s["source_version"] == "v1.2.3" for s in shapes)
    assert by["acme-api-token"]["min_length"] == 37
    assert skipped == {
        "generic": ["jwt"],
        "no_regex": ["acme-file"],
        "no_fixed_prefix": ["acme-keyword", "acme-two-letters"],
        "no_variable_body": ["acme-marker"],
    }


@pytest.mark.parametrize(
    ("regex", "expected"),
    [
        (r"(?i)\b(pfx_(?i)[a-z]{20})", "(?i:pfx_(?i:[a-z]{20}))"),
        (r"\b((?:ab|cd)x_(?i)[a-z]{20}\.[a-z]{4})\b", r"(?:ab|cd)x_(?i:[a-z]{20}\.[a-z]{4})"),
        (r"pfx-[a-z]+-[0-9]*\z", r"pfx-[a-z]{1,4096}-[0-9]{0,4096}\Z"),
        (r"pfx-[+*]{3}\+", r"pfx-[+*]{3}\+"),
    ],
)
def test_translate(regex, expected):
    assert redact_import.translate({"regex": regex}) == expected


def test_refresh_keeps_hand_kept_entries_and_is_a_no_op_on_rerun(tmp_path: Path):
    path = tmp_path / "redact_shapes.yaml"
    path.write_text(
        "version: 3\nshapes:\n"
        "  - {name: local_one, regex: 'loc_[a-z]{20}', source: sentrook, source_version: x}\n",
        encoding="utf-8",
    )
    first = redact_import.refresh(path, RULES, "v1.2.3")
    assert first.changed and "acme-api-token" in first.added and not first.removed
    path.write_text(first.text, encoding="utf-8")
    again = redact_import.refresh(path, RULES, "v1.2.3")
    assert not again.changed and again.text == first.text
    assert not (again.added or again.removed or again.modified)
    loaded = load_shapes_from(path)
    assert loaded.version == "3;gitleaks=v1.2.3"
    assert [s.name for s in loaded.shapes][0] == "local_one"
    assert loaded.shapes[0].min_length == 24
    with pytest.raises(ValueError):
        redact_import.refresh(path, RULES, "main")


def test_cli_import_from_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    rules = tmp_path / "gitleaks.toml"
    rules.write_text(RULES, encoding="utf-8")
    out = tmp_path / "redact_shapes.yaml"
    out.write_text("version: 1\nshapes: []\n", encoding="utf-8")
    args = ["redact-shapes", "import", "--tag", "v1.2.3", "--from", str(rules), "--out", str(out)]
    assert cli_main([*args, "--check"]) == 1
    assert cli_main(args) == 0
    assert "REDACTION_VERSION" in capsys.readouterr().out
    assert cli_main([*args, "--check"]) == 0
    assert "is current" in capsys.readouterr().out


def test_cli_import_summary(tmp_path: Path):
    rules = tmp_path / "gitleaks.toml"
    rules.write_text(RULES, encoding="utf-8")
    out = tmp_path / "redact_shapes.yaml"
    out.write_text(
        "version: 1\nshapes:\n  - {name: gone_key, regex: 'gk1_[a-z]{24}', source: gitleaks}\n",
        encoding="utf-8",
    )
    summary = tmp_path / "summary.md"
    args = ["redact-shapes", "import", "--tag", "v1.2.3", "--from", str(rules), "--out", str(out)]
    assert cli_main([*args, "--summary", str(summary)]) == 0
    text = summary.read_text(encoding="utf-8")
    assert "- Added: `" in text
    assert "- Removed: `gone_key`" in text
    assert cli_main([*args, "--check", "--summary", str(summary)]) == 0
    assert summary.read_text(encoding="utf-8") == "- No shape added, removed or changed.\n"


# --------------------------------------------------------------------------- the overlay


def test_overlay_adds_shapes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "redact_shapes.yaml").write_text(
        "version: 7\nshapes:\n  - {name: house_key, regex: 'hk1_[a-z]{24}'}\n", encoding="utf-8"
    )
    value = "hk1_" + "q" * 24
    assert redact_text("k " + value) == ("k " + value, 0)
    monkeypatch.setenv("SENTROOK_LISTS_DIR", str(tmp_path))
    clear_cache()
    try:
        shapes = load_shapes()
        assert shapes.version.endswith("+7") and shapes.shapes[-1].name == "house_key"
        assert redact_text("k " + value) == (f"k {P}", 1)
    finally:
        monkeypatch.delenv("SENTROOK_LISTS_DIR")
        clear_cache()


@pytest.mark.parametrize(
    "body",
    [
        "version: 1\nshapes:\n  - {name: github-pat, regex: 'x_[a-z]{30}'}\n",
        "version: 1\nshapes:\n  - {name: bad, regex: 'x_[a-z'}\n",
        "version: 1\nshapes:\n  - {name: no_regex}\n",
    ],
)
def test_overlay_rejects_duplicates_and_bad_entries(tmp_path: Path, body: str):
    (tmp_path / "redact_shapes.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        load_shapes_from(SHAPES_PATH, tmp_path)
