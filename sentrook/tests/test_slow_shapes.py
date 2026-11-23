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
import sys
import threading
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


def _post(path: str, body: str) -> dict:
    return planir(
        "web_fetch",
        "web_fetch",
        {"url": f"https://api.example.invalid{path}", "method": "POST", "body": body},
    )


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
    # a host of many labels, looked up with each of its parent domains
    "a fetch from a host of many labels": lambda size: ex(
        _repeat("curl https://", "a.", "io", size)
    ),
    "a ping of a host of many labels": lambda size: ex(_repeat("ping ", "a.", "io", size)),
    "docker -H with a host of many labels": lambda size: ex(
        _repeat("docker -H ", "x.rm.", "", size)
    ),
    # a body sent to a read-shaped path, read for a query document and for writes
    "a graphql body of many open query brackets": lambda size: _post(
        "/graphql", _repeat("", "query (", "", size)
    ),
    "a graphql body of query and many spaces": lambda size: _post(
        "/graphql", _repeat("query", " ", "x", size)
    ),
    "a query body of many update words": lambda size: _post(
        "/v1/query", _repeat("", "update a ", "", size)
    ),
    "a query body of a statement key and many spaces": lambda size: _post(
        "/v1/query", _repeat('"q":', " ", "x", size)
    ),
    "a query body of many escapes": lambda size: _post(
        "/v1/query", _repeat("", "\\u0041%41", "", size * 4 // 5)
    ),
    "code with many request calls": lambda size: _code(_repeat("", "requests.post(u, ", "", size)),
    "code with many import lines": lambda size: _code(
        _repeat("", "import json, os\n", "", size * 9 // 10)
    ),
    "code with many from words": lambda size: _code(_repeat("", "from  ", "'x'", size)),
    "code with many request calls to a name set at the end": lambda size: _code(
        _repeat("", "fetch(u, {}); ", "const u = 'https://api.example.invalid/v1/search';", size)
    ),
}

#: Cloud IAM grants, whose patterns the regex read back from the end of the command after every head.
#: The context probe reads them too when its unnamed-role arm is on (`conv-v7`).
GRANT_SHAPES = {
    "az role assignments repeated": lambda size: _repeat(
        "", "az role assignment create --role a ", "", size
    ),
    "an az role assignment with many roles": lambda size: _repeat(
        "az role assignment create ", "--role a ", "", size
    ),
    "aws policy attachments repeated": lambda size: _repeat(
        "", "aws iam attach-user-policy ", "", size
    ),
    "iam grants with a role repeated": lambda size: _repeat("", "iam grant --role x ", "", size),
    "iam grants repeated": lambda size: _repeat("", "iam grant ", "", size),
    "policy bindings repeated": lambda size: _repeat("", "add-iam-policy-binding ", "", size),
    "mixed grant verbs": lambda size: _repeat(
        "",
        "iam grant x; iam bind-role --role a ; add-iam-policy-binding --role b ; "
        "aws iam attach-role-policy x\n",
        "",
        size,
    ),
}
SHAPES.update({name: lambda size, f=f: ex(f(size)) for name, f in GRANT_SHAPES.items()})
#: Grants with a privileged role, read with the unnamed-role arm on.
GRANT_SHAPES_MATCHED = {
    "an az role assignment, the role after many words": lambda size: _repeat(
        "az role assignment create --role ", "a ", "admin", size
    ),
    "privileged iam grants repeated": lambda size: _repeat(
        "", "iam grant --role roles/x.admin ", "", size
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


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("name", [*GRANT_SHAPES, *GRANT_SHAPES_MATCHED])
def test_a_long_grant_call_scans_fast_with_the_unnamed_role_arm_on(name, size):
    from test_aira_detectors import CLOCK, KEY
    from test_converge_scan import BENIGN_ANSWERS
    from test_jev_probes import FakeDecider

    from sentrook.converge.params import load_params
    from sentrook.scan import Scanner, ScannerConfig, ScanOptions

    params = load_params("conv-v7")
    assert params.context.lineage_unnamed_role_overreach > 0
    sc = Scanner(ScannerConfig(token_key=KEY, decider=FakeDecider(BENIGN_ANSWERS), params=params))
    raw = ex({**GRANT_SHAPES, **GRANT_SHAPES_MATCHED}[name](size))
    start = time.perf_counter()
    res = sc.scan(raw, ScanOptions(deterministic=True, clock=CLOCK, salt="testnest"))
    spent = time.perf_counter() - start
    assert spent < FAST, f"whole scan, {name} at {size}: {spent:.2f}s"
    context = next(e for e in res.envelopes if e.step is ProbeStep.CONTEXT)
    assert context.status is ProbeStatus.OK, context.evidence
    if name in GRANT_SHAPES_MATCHED:
        assert context.evidence["lineage"].get("unnamed_roles") == ["admin"], context.evidence


# --------------------------------------------------------------------------- grant patterns

_GRANT_HEADS = [
    *["iam grant", "iam grant-role", "iam add-roles", "IAM  bind-Role", "iam set-role", "iam bind"],
    *["xiam grant", "iam granted", "add-iam-policy-binding", "add-iam-policy-bindingx"],
    *["aws iam attach-user-policy", "aws  IAM attach-group-policy", "aws iam put-role-policy"],
    *["aws iam create-access-keyx", "az role assignment create", "AZ role\tassignment create"],
    "az role assignment created",
]
_GRANT_GAPS = [
    "",
    " ",
    " x ",
    " a b ",
    " --role a ",
    " ; ",
    " | ",
    " & ",
    "\n",
    " -x ",
    " --roles a ",
]
_GRANT_LEADS = ["--role", "--roles", "--ROLE", "--role\u017f", "--rolex", "-role", "--rol"]
_GRANT_SEPS = ["=", " ", "  ", "\t", "\u00a0", "\u2003", "= ", " =", "", "==", "\n", ";"]
_GRANT_QUOTES = ["", "", "'", '"', "''"]
_GRANT_RUNS = ["", "", "roles/", "a", "x.y", "a/b", "my-", "custom", "a b ", "a  b ", "roles/x."]
_GRANT_RUNS += ["a=b", "\u00e4", "-"]
_GRANT_ROLES = [
    *"owner admin administrator adminx Admin editor root superuser contributor".split(),
    *"fullaccess PowerUser ownerx _owner x".split(),
]
_GRANT_AFTER = ["", " ", "x", "-", ".", ";", "\n", " admin", "|", "&"]
_GRANT_JOINS = [" ", "", "  ", "\t", "\u00a0", "\u2003", "\n", ";", "|", "&", "'", "-", "/"]


def _grant_text(rng: random.Random) -> str:
    def unit() -> str:
        return "".join(
            rng.choice(pieces)
            for pieces in (
                _GRANT_HEADS,
                _GRANT_GAPS,
                [" ", "", "\t"],
                _GRANT_LEADS,
                _GRANT_SEPS,
                _GRANT_QUOTES,
                _GRANT_RUNS,
                _GRANT_ROLES,
                _GRANT_AFTER,
            )
        )

    return "".join(unit() + rng.choice(_GRANT_JOINS) for _ in range(rng.randint(1, 4)))


def test_grant_matches_agree_with_the_regex():
    """Matches, spans and groups, from the start and from any position."""
    from sentrook.aira import linear_search
    from sentrook.aira.lists import load_lists

    grants = [
        r.regex
        for r in load_lists().rules("remote_destructive", "cli")
        if r.get("reason") == "remote.grant" and r.regex.groups
    ]
    assert len(grants) == 4 and all(rx.pattern in linear_search.BOUNDED_END for rx in grants)
    rng = random.Random(20261122)
    matched = 0
    for _ in range(12000):
        text = _grant_text(rng)
        for rx in grants:
            want = [(m.span(), m.groupdict()) for m in rx.finditer(text)]
            assert [(m.span(), m.groupdict()) for m in linear_search.finditer(rx, text)] == want, (
                rx.pattern,
                text,
            )
            pos = rng.randint(0, len(text))
            a, b = rx.search(text, pos), linear_search.search(rx, text, pos)
            assert (a and (a.span(), a.groupdict())) == (b and (b.span(), b.groupdict())), (
                rx.pattern,
                text,
                pos,
            )
            matched += len(want)
    assert matched > 2000


# --------------------------------------------------------------------------- threads

#: Texts for each family of linear searches that reads a text once for all its matches: the scan
#: server runs scans, and a scan its probes, on several threads at once.
_THREADED = {
    "grant": (
        r"""\baz\s+role\s+assignment\s+create\b[^;&|\n]*--role[=\s]+["']?[\w\s-]*?"""
        r"(?P<role>owner|contributor|administrator|admin)\b",
        [
            "x " * 40
            + "az role assignment create --role owner ; az role assignment create --role admin",
            "az role assignment create --assignee u --role contributor && ls ; " * 3 + "y" * 30,
            "echo hi",
            "az role assignment create --role reader ; " * 5
            + "az role assignment create --role Owner",
        ],
    ),
    "docker remote removal": (
        r"\b(?:DOCKER_HOST=\S+\s+)?docker\s+(?:-H|--host)[\s=]\S+[^;&|\n]*"
        r"\b(?:rm|rmi|system\s+prune|volume\s+rm)\b",
        [
            "docker -H x.rm.a b c rm d ; docker -H y rm",
            "x " * 30 + "docker -H tcp://h rmi z && docker --host=h volume rm v",
            "DOCKER_HOST=a docker -H h.rm.rm.rm " + "b " * 20,
            "docker -H q system prune ; " * 4 + "docker -H r rm",
        ],
    ),
}


@pytest.mark.parametrize("family", list(_THREADED))
def test_searches_on_several_threads_give_each_text_its_own_matches(family):
    from sentrook.aira import linear_search

    pattern, texts = _THREADED[family]
    rx = re.compile(pattern, re.IGNORECASE)
    assert linear_search._linear(rx) is not None

    def matches(text: str) -> list:
        return [(m.span(), m.groupdict()) for m in linear_search.finditer(rx, text)]

    want = {t: [(m.span(), m.groupdict()) for m in rx.finditer(t)] for t in texts}
    wrong: list = []

    def work(i: int) -> None:
        for k in range(1500):
            text = "".join(list(texts[(i + k) % len(texts)]))  # a new object, as a new segment is
            try:
                got = matches(text)
            except Exception as e:  # noqa: BLE001 - a failure on one thread is a wrong answer
                got = repr(e)
            if got != want[text]:
                wrong.append((text[:40], got))

    switch = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(switch)
    assert not wrong, (len(wrong), wrong[:3])


# --------------------------------------------------------------------------- parent domains


def _reference_parent_hit(oracle, host: str):
    """The parent-domain lookup as it joined the labels of each parent."""
    parts = host.split(".")
    for i in range(1, len(parts) - 1):
        hit = oracle._by_key.get(("host", ".".join(parts[i:])))
        if hit is not None:
            return hit
    return None


_LABELS = ["a", "b", "io", "co", "", "x-y", "1", "127", "0", "\u00e9", "com", "github", "A", "IO"]


def test_parent_domains_agree_with_joining_the_labels():
    from sentrook.oracle.client import EntityQuery, SeedOracle

    rng = random.Random(20261122)

    def host(most: int) -> str:
        return ".".join(rng.choice(_LABELS) for _ in range(rng.randint(1, most)))

    for _ in range(60):
        seeded = {host(4).lower().strip() for _ in range(rng.randint(0, 6))}
        seeded |= {"a.io", "b.co", "1.0.0.127", "github.com"} if rng.random() < 0.5 else set()
        oracle = SeedOracle(
            {"entities": [{"kind": "host", "value": h, "verdict": "known_bad"} for h in seeded]}
        )
        queries = []
        for _ in range(100):
            h = host(rng.choice([3, 8, 30]))
            h = h + "." if rng.random() < 0.2 else h
            h = "." + h if rng.random() < 0.1 else h
            assert oracle._parent_hit(h) is _reference_parent_hit(oracle, h), (seeded, h)
            queries.append(EntityQuery("host", h))
        verdicts = oracle.lookup(queries).verdicts
        for q in queries:
            norm = q.value.strip().lower()
            want = oracle._by_key.get(("host", norm)) or _reference_parent_hit(oracle, norm)
            got = verdicts[("host", q.value)]
            assert (got.verdict, got.value) == (
                (want.verdict, want.value) if want else (got.verdict, q.value)
            )


def test_a_host_of_many_labels_is_looked_up_fast():
    from sentrook.oracle.client import EntityQuery, SeedOracle

    oracle = SeedOracle({"entities": [{"kind": "host", "value": "a.io", "verdict": "known_bad"}]})
    host = "a." * 47_000 + "io"
    start = time.perf_counter()
    got = oracle.lookup([EntityQuery("host", host), EntityQuery("host", host + "x")]).verdicts
    assert time.perf_counter() - start < 0.5
    assert got[("host", host)].value == "a.io"
    assert got[("host", host + "x")].value == host + "x"


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
            rest = sentence[at:].split(None, 1)
            after = rest[1] if " " in sentence[at:] and len(rest) > 1 else ""
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
    return fn(text, home=HOME, workspace_root=None)


def test_prose_roles_agree_with_the_per_host_reading():
    rng = random.Random(20261120)
    found = 0
    for i in range(6000):
        text = _prose(rng) if i % 2 else _phrased(rng)
        want = _roles(_reference_prose_roles, text)
        assert _roles(written_selfmod._prose_roles, text) == want, text
        found += bool(want)
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
