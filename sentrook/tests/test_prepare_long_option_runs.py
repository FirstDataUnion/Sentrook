"""Preparation reads a command with a long run of options, or one command name repeated, in linear time.

Before the probes run (and outside their deadline), preparation finds the hosts, inline programs,
config keys, search patterns, written files and argument vectors of a command. Several of those were
regexes of the form `<command>(?:<option>)*<end>`, which retry the options from every head in the run
(`-scp -scp …`, `-perl -perl …`: tens of seconds at 95,000 characters), or walks that re-read the rest
of a long word from every head in it (`hermes.hermes.…`), or dropped a repeated launcher by copying
the rest of the command (`npx npx …`). Each now reads the text once, with the same matches.
"""

from __future__ import annotations

import random
import re

import pytest
from linear_time import assert_fast_or_linear
from test_aira_detectors import ex
from test_large_calls import FAST, scan
from test_long_option_runs import SIZE, _repeat

from sentrook.aira import linear_search
from sentrook.enums import ProbeStatus, ProbeStep
from sentrook.prepare import entities, written_selfmod

# --------------------------------------------------------------------------- timing

UNITS = [
    "-nc ",
    "-ncat ",
    "-telnet ",
    "-scp ",
    "-ssh ",
    "-rsync ",
    "-perl ",
    "-ruby ",
    "-python ",
    "-python3 ",
    "-node ",
    "-php ",
    "-sed ",
    "sed -i ",
    "hermes.",
    "openclaw.",
    "git.",
    "grep.",
    "rg.",
    "npx ",
    "uv run ",
    "sudo ",
    "env ",
    "python -x ",
    "ssh -o x ",
    "nc -v ",
]


@pytest.mark.parametrize("unit", UNITS)
def test_a_repeated_command_or_option_prepares_fast(unit):
    res, spent = scan(ex(_repeat("", unit)))
    assert_fast_or_linear(
        spent, FAST, lambda d: scan(ex(_repeat("", unit, size=SIZE // d))), f"whole scan, {unit!r}"
    )
    aira = next(e for e in res.envelopes if e.step is ProbeStep.AIRA)
    assert aira.status is ProbeStatus.OK, aira.evidence


# --------------------------------------------------------------------------- the patterns, match for match

#: Per pattern: the words its texts are built from (heads, options, ends, hosts and decoys).
_WORDS = {
    entities._SSH_HOST_RE: [
        *"ssh scp rsync sftp xssh sshx -o -p -i -scp -ssh -a.io a.io b.co".split(),
        *"u@a.io u@ @ x.y a.b.c -x.yz 1.2.3.4 é.io a.é -- - .io a. ü@a.io".split(),
    ],
    entities._NC_HOST_RE: [
        *"nc ncat netcat telnet xnc ncx -v -z -nc -w1 -a.b a.io 1.2.3.4 1.2.3".split(),
        *"10.0.0.1:80 a.b.c -x.yz -é é.io a.é . - 300.1.1.1".split(),
    ],
    entities._PY_MODULE_RE: [
        *"python python3 python3.11 xpython -m -mfoo -c -u -x -python -m.a pkg.mod".split(),
        *"-é - -- é.x a.b".split(),
    ],
    entities._INLINE_PROGRAM_RE: [
        *"python python3 node nodejs bun perl ruby php deno eval -c -uc -e -E --eval -p".split(),
        *"--print -r -x -python -perl -php -node -ne -pe -lne x= = 'print(1)' \"x\"".split(),
        *"-é é -c= -e= --x=y".split(),
    ],
    written_selfmod._SUBST_RUN: [
        *"sh bash zsh xsh eval source . ;. (. -c -x -sh -bash -e -- $( ` <( \"$( '$( ".split(),
        *"curl wget fetch /usr/bin/curl a/curl curlx $(curl -é é".split(),
    ],
    written_selfmod._INLINE_PROGRAM: [
        *"python python2 python3 PYTHON node deno bun perl ruby php xnode -c -e -E -r".split(),
        *"--eval --evalx -x -u -node -python -ce -é é".split(),
    ],
    written_selfmod._WGET_COMBINED_O_RUN: [
        *"wget xwget WGET -q -qO -O -qqO -qO- -wget -x -é --out -aO1 O é-qO".split(),
    ],
    written_selfmod._SED_IN_PLACE: [
        *"sed xsed -i -i.bak --in-place --in-place=.b -n -e -sed -E s/a/b/ f.txt".split(),
        *"; & ;x x; a&b -é é".split(),
    ],
}
_SEPARATORS = [" ", " ", " ", "  ", "\t", "\n", " \n ", ";", "&", "|", " ; ", "=", "'", '"', ""]


def _text(rng: random.Random, words: list[str]) -> str:
    parts = []
    for _ in range(rng.randint(0, 14)):
        parts.append(rng.choice(words))
        parts.append(rng.choice(_SEPARATORS))
    return "".join(parts[: rng.randint(0, len(parts))] if rng.random() < 0.2 else parts)


def _all(matches) -> list:
    return [
        (m.span(), m.groups(), [m.span(g) for g in range(1, len(m.groups()) + 1)]) for m in matches
    ]


@pytest.mark.parametrize("rx", list(_WORDS), ids=lambda rx: rx.pattern[:24])
def test_option_runs_agree_with_their_patterns(rx):
    assert (rx.pattern, rx.flags) in linear_search.OPTION_RUNS
    rng = random.Random(20261120)
    words = _WORDS[rx]
    matched = 0
    for _ in range(4000):
        text = _text(rng, words)
        want = _all(rx.finditer(text))
        assert _all(linear_search.option_run_finditer(rx, text)) == want, text
        matched += bool(want)
    assert matched > 100


def test_long_option_runs_agree_with_their_patterns():
    """Runs long enough that heads share them, still small enough for the regex."""
    rng = random.Random(5)
    for rx, words in _WORDS.items():
        for _ in range(60):
            unit = "".join(rng.choice(words) + rng.choice(_SEPARATORS[:6]) for _ in range(3))
            text = _text(rng, words) + unit * rng.randint(20, 80) + _text(rng, words)
            assert _all(linear_search.option_run_finditer(rx, text)) == _all(rx.finditer(text)), (
                text
            )


@pytest.mark.parametrize("rx", list(_WORDS), ids=lambda rx: rx.pattern[:24])
def test_option_runs_are_fast_on_long_texts(rx):
    import time

    for unit in [w + " " for w in _WORDS[rx][:12]] + ["-x ", "a."]:

        def search(d: int, unit=unit) -> None:
            list(linear_search.option_run_finditer(rx, unit * (95_000 // len(unit) // d)))

        start = time.perf_counter()
        search(1)
        spent = time.perf_counter() - start
        assert_fast_or_linear(spent, FAST / 4, search, f"{rx.pattern[:30]} on {unit!r}")


# --------------------------------------------------------------------------- word walks


def _reference_config_key_spans(text: str) -> list[range]:
    """`_config_key_spans` as it was, reading the words after each head with a regex."""
    import itertools

    spans: list[range] = []
    for m in entities._CONFIG_HEAD_RE.finditer(text):
        head = m.group(1)
        toks = list(
            itertools.islice(
                entities._TOKEN_RE.finditer(text, m.end(), entities._line_end(text, m.end())), 32
            )
        )
        i = 0
        while head == "git" and i < len(toks) and toks[i].group(0) in ("-C", "-c"):
            i += 2
        if i >= len(toks) or toks[i].group(0) != "config":
            continue
        i += 1
        if i < len(toks) and toks[i].group(0) in entities._CONFIG_VERBS[head]:
            i += 1
        elif head == "openclaw":
            continue
        while i < len(toks) and toks[i].group(0).startswith("-"):
            i += 2 if toks[i].group(0) in entities._CONFIG_VALUE_FLAGS else 1
        if i < len(toks):
            key = entities._CONFIG_KEY_TOKEN_RE.match(toks[i].group(0))
            if key:
                spans.append(range(toks[i].start(), toks[i].start() + key.end()))
    return spans


def _reference_search_pattern_spans(text: str) -> list[range]:
    import itertools

    spans: list[range] = []
    for m in entities._SEARCH_HEAD_RE.finditer(text):
        toks = itertools.islice(
            entities._TOKEN_RE.finditer(text, m.end(), entities._line_end(text, m.end())), 32
        )
        explicit = False
        take: str | None = None
        for tok in toks:
            word = tok.group(0)
            if word in entities._SHELL_SEPARATORS:
                break
            if take is not None:
                if take == "pattern":
                    spans.append(range(*tok.span()))
                take = None
                continue
            if word in entities._SEARCH_PATTERN_FLAGS:
                take, explicit = "pattern", True
            elif word.startswith("--regexp="):
                spans.append(range(tok.start() + len("--regexp="), tok.end()))
                explicit = True
            elif word in entities._SEARCH_VALUE_FLAGS:
                take = "value"
            elif word.startswith("-") and word != "-":
                continue
            else:
                if not explicit:
                    spans.append(range(*tok.span()))
                break
    return spans


_WALK_WORDS = [
    *"openclaw hermes git config set get unset edit show -C -c --file -f --blob -x -".split(),
    *"grep egrep rg ag ack -e --regexp --regexp=a.b -A 3 --glob -i | || && ; & a.b k.v".split(),
    *"hermes.x openclaw.config git.grep xgrep -é é.k approvals.mode 1a _k".split(),
]


def test_config_keys_and_search_patterns_agree_with_the_word_regex():
    rng = random.Random(11)
    seps = [" ", " ", "  ", "\t", "\n", "\r\n", "\x0b", " ", ".", ""]
    for _ in range(6000):
        n = rng.randint(0, 40)
        text = "".join(rng.choice(_WALK_WORDS) + rng.choice(seps) for _ in range(n))
        assert entities._config_key_spans(text) == _reference_config_key_spans(text), text
        assert entities._search_pattern_spans(text) == _reference_search_pattern_spans(text), text


def _reference_drop_launchers(argv: list[str]) -> list[str]:
    """The launcher loop of `_argv_pipeline` as it was, copying the rest at each word dropped."""
    while argv:
        if re.match(r"^[A-Za-z_]\w*=", argv[0]):
            argv = argv[1:]
        elif (
            argv[0] in written_selfmod._LAUNCHERS
            or tuple(argv[:2]) in written_selfmod._LAUNCHER_PAIRS
        ):
            argv = argv[1:] if argv[0] in written_selfmod._LAUNCHERS else argv[2:]
            while argv and argv[0].startswith("-"):
                argv = argv[2:] if argv[0] in ("-u", "-g", "-C", "--with", "-p") else argv[1:]
        else:
            break
    return argv


def _reference_wrappers(tokens: list[str]) -> list[str]:
    while tokens and (
        tokens[0] in entities._WRAPPER_HEADS or entities._ENV_ASSIGN_RE.match(tokens[0])
    ):
        tokens = tokens[1:]
    return tokens


def test_launchers_and_wrappers_are_dropped_as_before():
    words = [
        *"sudo env exec nohup npx bunx uv run poetry pnpm exec dlx npm -u -g -C --with -p".split(),
        *"-x -- A=1 _a=b 1a=b x= ls rm".split(),
    ]
    rng = random.Random(3)
    for _ in range(6000):
        argv = [rng.choice(words) for _ in range(rng.randint(0, 10))]
        assert written_selfmod._drop_launchers(argv) == _reference_drop_launchers(argv), argv
        assert entities._drop_wrappers(argv) == _reference_wrappers(argv), argv


def test_wget_combined_flags_are_split_as_the_regex_splits_them():
    rng = random.Random(11)
    words = _WORDS[written_selfmod._WGET_COMBINED_O_RUN] + ["a", "f"]
    split = 0
    for _ in range(4000):
        text = _text(rng, words)
        want = written_selfmod._WGET_COMBINED_O.sub(r"wget \1-\2 -O ", text)
        assert written_selfmod._split_wget_o(text) == want, text
        split += want != text
    assert split > 50


def test_a_fetch_piped_to_source_is_found_as_the_regex_finds_it():
    rng = random.Random(12)
    words = [*"curl wget fetch xcurl curlx | |source | . |. source . ; & -x a /dev/stdin".split()]
    found = 0
    for _ in range(4000):
        text = _text(rng, words)
        want = written_selfmod._PIPE_SOURCE.search(text) is not None
        assert written_selfmod._pipes_to_source(text) == want, text
        found += want
    assert found > 100
