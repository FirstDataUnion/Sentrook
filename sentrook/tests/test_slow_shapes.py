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
import re
import time

import pytest
from test_aira_detectors import ex, planir
from test_large_calls import FAST, scan
from test_long_option_runs import _repeat

from sentrook.aira.exec_shape import MAX_PARSE_CHARS
from sentrook.enums import ProbeStatus, ProbeStep
from sentrook.planir.bounds import MAX_CALL_CHARS
from sentrook.prepare import entities, written_selfmod

SIZES = [MAX_PARSE_CHARS, 95_000]
HOME = "/home/me"
AGENTS = f"{HOME}/.openclaw/workspace/AGENTS.md"
BASHRC = f"{HOME}/.bashrc"


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
    # written into an agent instruction file: prose read for where code comes from
    "fetch, then many ands": lambda size: _write(AGENTS, _repeat("fetch a.io ", "and ", "", size)),
    "many runs, then a host": lambda size: _write(AGENTS, _repeat("", "run ", " a.io", size)),
    "many pipes, then a host": lambda size: _write(AGENTS, _repeat("", "pipe ", " a.io", size)),
    "a run of distinct hosts": lambda size: _write(
        AGENTS, "".join(f"run a{i}.io " for i in range(size // 13))
    ),
    # shell text written to a shell startup file
    "a shell with many options": lambda size: _write(BASHRC, _repeat("sh ", "-sh ", "", size)),
    "wget with many options": lambda size: _write(BASHRC, _repeat("wget ", "-wget ", "", size)),
    "node with many options": lambda size: _write(
        BASHRC, _repeat("node ", "-node ", " fetch( exec", size)
    ),
    # a command writing a shell startup file, with many echoes before the write
    "many echoes, then tee": lambda size: ex(_repeat("", "echo ", "\ntee ~/.bashrc", size)),
    "many echoes, then sed": lambda size: ex(_repeat("", "echo ", "; sed -i s ~/.bashrc", size)),
    "an echo of much text into the file": lambda size: ex(
        _repeat("echo ", "a ", " >> ~/.bashrc", size)
    ),
    # a docker remote removal whose only removal word is inside the host word
    "docker -H with the removal inside a long host word": lambda size: ex(
        "docker -H x.rm." + "a" * (size // 2) + " " + "b " * (size // 4 - 10)
    ),
    # a fetch piped to sudo with a long run of option words, each holding a pipe
    "a fetch piped to sudo with many options": lambda size: ex(
        _repeat("curl |sudo ", "-curl|sudo ", "", size)
    ),
    "execute_code with many opens": lambda size: _code(_repeat("", "open(", "", size)),
    "mail to many addresses": lambda size: _write(
        AGENTS, "".join(f"send to u{i}@a.io " for i in range(size // 19))
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


# --------------------------------------------------------------------------- written prose


def _reference_prose_roles(text: str, *, home: str | None, workspace_root: str | None) -> list:
    """`_prose_roles` as it read each host's words before the sentence was read once."""
    w = written_selfmod
    out: list = []
    commands = w._commands(text)
    if commands:
        out.extend(
            w._shell_roles(
                "\n".join(commands), home=home, workspace_root=workspace_root, contacts=False
            )
        )
    words = w._CODE.sub(lambda m: " " * len(m.group(0)), text)
    for sentence in w._SENTENCE.split(words):
        if not sentence.strip():
            continue
        for host in w._hosts_in(sentence, emails=False):
            if w._local(host):
                continue
            at = w._position(sentence, host)
            if at < 0:
                continue
            before = re.sub(r"\S*$", "", sentence[:at])
            after = sentence[at:].split(None, 1)[1] if " " in sentence[at:] else ""
            if w._DONT.search(w._CLAUSE_BREAK.split(before)[-1]):
                continue
            fetch_before = re.search(rf"\b{w._FETCH_VERB}\b", before, re.I)
            if w._RUN_FROM.search(before) or (fetch_before and w._RUN_AFTER.search(after)):
                out.append(w.Found(w.EntityKind.HOST, host, host, w.Role.CODE_SOURCE))
            elif (
                not w._DOC_LEAD.search(before)
                and not w._FROM_HOST.search(before)
                and (w._SEND.search(before) or (not before.strip() and w._SEND_THERE.search(after)))
            ):
                out.append(w.Found(w.EntityKind.HOST, host, host, w.Role.DATA_DESTINATION))
        for m in w._EMAIL_RE.finditer(sentence):
            before = sentence[: m.start()]
            if w._SEND.search(before) and not w._DONT.search(w._CLAUSE_BREAK.split(before)[-1]):
                addr = w.normalise_recipient(m.group(1))
                out.append(w.Found(w.EntityKind.RECIPIENT, addr, addr, w.Role.RECIPIENT))
    return out


_PROSE_WORDS = [
    *"fetch download Get curl wget read run execute exec install source bash sh RUN".split(),
    *"and then && pipe feed to into a shell python node from at hosted on From AT".split(),
    *"see docs documentation reference guide details read more learn here at in".split(),
    *"send upload post backing back-up there it that sync mail e-mail emailed".split(),
    *"never don't dont do not must should ever instead Instead follow obey apply carry out".split(),
    *"what , . ; ! ? : ( [ x y the".split(),
    *"a.io b.co A.IO x.a.io a.io/x https://c.io/x bob@d.io e.io: a.io. -a.io xa.io a.io-".split(),
    *"ſh.io K.io k.io sh.io a.io,b.io localhost 127.0.0.1 1.2.3.4 é.io".split(),
]
_PROSE_SEPARATORS = [" ", " ", " ", "  ", "\t", "\n", " ", " ", ". ", "! ", "", " \n"]


def _prose(rng: random.Random) -> str:
    return "".join(
        rng.choice(_PROSE_WORDS) + rng.choice(_PROSE_SEPARATORS) for _ in range(rng.randint(0, 18))
    )


#: Phrases that make the questions asked of the words around a host come out either way.
_PROSE_PHRASES = [
    "never run",
    "do not ever download the",
    "don't x run",
    "mustn't fetch",
    "never, run",
    "never instead run",
    "run it from",
    "execute what is hosted at",
    "install from",
    "run. from",
    "pipe it to a shell",
    "feed it into python",
    "pipe it to a  sh",
    "fetch",
    "download the file from",
    "and then run it",
    "and follow it",
    "then carry out",
    "and. run",
    "upload logs there",
    "send it to it",
    "back up to that",
    "see the docs at",
    "read  more on",
    "reference: (",
    "docs [",
    "copy the example from",
    "of",
    "send to",
    "mail",
    "ſend",
    "Kelvin",
]


def _phrased(rng: random.Random) -> str:
    words = _PROSE_PHRASES * 3 + _PROSE_WORDS
    return "".join(
        rng.choice(words) + rng.choice(_PROSE_SEPARATORS[:8]) for _ in range(rng.randint(1, 12))
    )


def _roles(fn, text: str):
    try:
        return fn(text, home=HOME, workspace_root=None)
    except IndexError as e:
        return ("IndexError", str(e))


def test_prose_roles_agree_with_the_per_host_reading():
    rng = random.Random(20261120)
    found = 0
    for i in range(6000):
        text = _prose(rng) if i % 2 else _phrased(rng)
        want = _roles(_reference_prose_roles, text)
        assert _roles(written_selfmod._prose_roles, text) == want, text
        found += bool(want) and not isinstance(want, tuple)
    assert found > 300


# --------------------------------------------------------------------------- echoes written to a file

_ECHO_WORDS = [
    *"echo printf xecho echox -n -e -E -nE -x a b ~/.bashrc > >> >>> < | ; & ' \" x=1 é".split(),
    *["\n", " ", "  ", "\t", "\u00a0", "\n\n", ""],
]
_ECHO_SEPARATORS = [" ", " ", "", "\t", "\n", "  ", "\u2003", " \n "]


def test_unquoted_echoes_agree_with_the_regex():
    rng = random.Random(20261120)
    matched = 0
    for _ in range(8000):
        text = "".join(
            rng.choice(_ECHO_WORDS) + rng.choice(_ECHO_SEPARATORS)
            for _ in range(rng.randint(0, 14))
        )
        want = [m.group(1) for m in written_selfmod._UNQUOTED_ECHO.finditer(text)]
        assert written_selfmod._unquoted_echoes(text) == want, text
        matched += bool(want)
    assert matched > 300


# --------------------------------------------------------------------------- context probe


@pytest.mark.parametrize("size", SIZES)
def test_a_long_kubectl_run_is_read_fast_for_unnamed_roles(attack_case, size):
    """The arm that looks for a privileged role the owner did not name, switched on, reads the grant
    patterns over a long run of `kubectl apply` in linear time."""
    from test_context_oracle_probes import _lineage_run

    command = _repeat("", "kubectl apply ", "", size)
    start = time.perf_counter()
    _lineage_run(
        attack_case,
        [],
        {"command": command},
        "Apply the manifests.",
        params={"lineage_unnamed_role_overreach": 0.6},
    )
    assert time.perf_counter() - start < FAST
