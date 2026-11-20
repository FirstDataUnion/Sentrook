"""More long calls that scan in well under the probe timeout, each read in linear time with the same
answer as before.

Each shape below took the whole scan seconds to minutes at 95,000 characters (some at 4,000): a
listed pattern whose match the regex took long to build, a per-host check that re-read the line before
each host, written-text patterns that retry a run of words from every head in it, and rule and
context probes searched as plain regexes. Each is timed at the parse limit and at 95,000 characters,
and each rewritten extraction is checked against the regex it replaces on generated texts.
"""

from __future__ import annotations

import json
import random

import pytest
from test_aira_detectors import ex, planir
from test_large_calls import FAST, scan
from test_long_option_runs import _repeat

from sentrook.aira.exec_shape import MAX_PARSE_CHARS
from sentrook.enums import ProbeStatus, ProbeStep
from sentrook.planir.bounds import MAX_CALL_CHARS
from sentrook.prepare import entities

SIZES = [MAX_PARSE_CHARS, 95_000]
HOME = "/home/me"


def _write(path: str, content: str) -> dict:
    return planir("write", "file_write", {"path": path, "content": content})


def _code(code: str) -> dict:
    return planir("execute_code", "exec", {"code": code}, platform="hermes")


#: name -> a call of about `size` characters.
SHAPES = {
    "registry line repeated before a matching one": lambda size: ex(
        _repeat("", "echo registry=https://r > x ", "; echo registry=https://r > .npmrc", size)
    ),
    "matching registry lines": lambda size: ex(
        _repeat("", "echo registry=https://r > .npmrc ", "", size)
    ),
    "many bare host-like words": lambda size: ex(_repeat("", "a.io ", "", size)),
    "ssh options and a host, repeated": lambda size: ex(_repeat("", "ssh -o x a.io ", "", size)),
    "a config set with many host-like words": lambda size: planir(
        "exec",
        "exec",
        {"command": _repeat("hermes config -x set approvals.mode ", "a.io b.co ", " yes", size)},
        platform="hermes",
    ),
    "an import list of host-like names": lambda size: ex(
        _repeat("python -c 'import ", "a.io, ", "b.io'", size)
    ),
}


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("name", list(SHAPES))
def test_a_long_call_of_this_shape_scans_fast(name, size):
    raw = SHAPES[name](size)
    assert len(json.dumps(raw["pending_call"]["arguments"])) < MAX_CALL_CHARS
    res, spent = scan(raw)
    assert spent < FAST, f"whole scan, {name} at {size}: {spent:.2f}s"
    aira = next(e for e in res.envelopes if e.step is ProbeStep.AIRA)
    assert aira.status is ProbeStatus.OK, aira.evidence


# --------------------------------------------------------------------------- code references

_CODE_WORDS = [
    *"import from as a.b x.io pkg.mod é.io a_b ximport importx from_ xfrom as_ _ . , ( [".split(),
    *"import import from from as as , , a.io a.io".split(),
]
_CODE_SEPARATORS = [" ", " ", "", "", "  ", "\t", "\n", " ", " ", ",", ", ", " ,", "\r"]


def test_code_references_agree_with_the_per_name_check():
    """Every position of generated texts, as the start of a name ending at the next whitespace."""
    rng = random.Random(20261120)
    seen = 0
    for _ in range(3000):
        text = "".join(
            rng.choice(_CODE_WORDS) + rng.choice(_CODE_SEPARATORS)
            for _ in range(rng.randint(0, 14))
        )
        refs = entities._CodeReferences(text)
        for start in range(len(text) + 1):
            end = start
            while end < len(text) and not text[end].isspace():
                end += 1
            for e in (start, end, min(end, start + 1)):
                want = entities._is_code_reference(text, start, e)
                assert refs(start, e) == want, (text, start, e)
                seen += want
    assert seen > 1000
