"""A command with a very long run of options, or a long chain of one command name, scans in well under the
probe timeout, and a guardrail verb hidden behind such a run still takes the floor.

The guardrail CLI matchers try every word that can follow a run of options as the subcommand and as the
verb, because which options take a value is not known. Done naively that is cubic in the run's length:
16,000 characters of `curl -H x -H x …` took about 40 s. The words that can follow are worked out once
per command now, so the work is linear in the words, with no cap on the run.

Listed patterns of the form `<command>[^;&|\n]*<…>` (and chains of them) were quadratic or cubic in a
long simple command with many heads (`systemctl stop systemctl stop …`); they are searched in linear time
with the same answer (`sentrook.aira.linear_search`).

A probe that stalls between calls does not hold the response: the scan answers at the probe timeout,
degraded. The timeout cannot cut one long regex search short (the search holds the interpreter until it
returns), which is why each search has to stay linear.
"""

from __future__ import annotations

import json
import random
import threading
import time

import pytest
from linear_time import assert_fast_or_linear
from test_aira_detectors import ex, floor_reasons, hist_step, planir, run
from test_large_calls import FAST, scan

from sentrook import scan as scan_module
from sentrook.aira import detectors, linear_search
from sentrook.aira.exec_shape import MAX_PARSE_CHARS
from sentrook.aira.lists import load_lists
from sentrook.enums import ProbeStatus, ProbeStep, ScanStatus
from sentrook.planir.bounds import MAX_CALL_CHARS

#: Below the character bound, so the command is analysed whole.
SIZE = 95_000


def _repeat(prefix: str, unit: str, suffix: str = "", size: int = SIZE) -> str:
    n = (size - len(prefix) - len(suffix)) // len(unit)
    command = prefix + unit * n + suffix
    assert len(command) < MAX_CALL_CHARS
    return command


def hx(command: str):
    return ex(command, platform="hermes")


# --------------------------------------------------------------------------- timing

#: name -> make(d): the call at 1/d of its full size (d = 1 when timed against the bound, 4 for the
#: growth check, which stays on the same side of `MAX_PARSE_CHARS`).
LONG = [
    ("curl -H x", lambda d=1: ex(_repeat("curl ", "-H x ", "https://example.com", size=SIZE // d))),
    ("git -c a=b", lambda d=1: ex(_repeat("git ", "-c a=b ", "status", size=SIZE // d))),
    ("ls -l (a head in no guardrail entry)", lambda d=1: ex(_repeat("ls ", "-l ", size=SIZE // d))),
    (
        "openclaw -v (a guardrail head)",
        lambda d=1: ex(_repeat("openclaw ", "-v ", "status", size=SIZE // d)),
    ),
    (
        "hermes -p x (a guardrail head)",
        lambda d=1: hx(_repeat("hermes ", "-p x ", "status", size=SIZE // d)),
    ),
    (
        "openclaw config with every word a possible verb",
        lambda d=1: ex(_repeat("openclaw ", "-x config -x set ", "a b", size=SIZE // d)),
    ),
    (
        "openclaw config set with many read-from flags",
        lambda d=1: ex(
            _repeat("openclaw config ", "-x patch --batch-file f --file g ", "a b", size=SIZE // d)
        ),
    ),
    (
        "openclaw approvals with many file flags",
        lambda d=1: ex(
            _repeat("openclaw approvals ", "-x set --file /tmp/a ", "a", size=SIZE // d)
        ),
    ),
    (
        "openclaw exec-policy with many presets and flags",
        lambda d=1: ex(
            _repeat(
                "openclaw exec-policy ", "-x preset -x set --ask off yolo ", "a", size=SIZE // d
            )
        ),
    ),
    (
        "openclaw approvals allowlist add with many entries",
        lambda d=1: ex(
            _repeat(
                "openclaw approvals -x allowlist ", "-x allowlist add '*' ", "a", size=SIZE // d
            )
        ),
    ),
    (
        "npx launcher with many launchable values",
        lambda d=1: ex(_repeat("npx ", "-p openclaw ", size=SIZE // d)),
    ),
    # A long dotted word before or after the verb: the approval patterns are only searched in the
    # words after a verb, and in linear time.
    (
        "openclaw config, a long dotted option value before the verb",
        lambda d=1: ex(_repeat("openclaw config -x ", "approvals.", " set y z", size=SIZE // d)),
    ),
    (
        "hermes config, a long dotted option value before the verb",
        lambda d=1: hx(_repeat("hermes config -x ", "approval.", " set y z", size=SIZE // d)),
    ),
    (
        "openclaw config set of a long dotted key",
        lambda d=1: ex(_repeat("openclaw config set ", "approvals.", " y", size=SIZE // d)),
    ),
    (
        "openclaw config, many verbs then a long dotted option value",
        lambda d=1: ex(
            "openclaw config "
            + "-x set " * (3000 // d)
            + "-x "
            + "approvals." * ((SIZE - 21_022) // 10 // d)
            + " set y"
        ),
    ),
    # An approval loosening behind options, past the parse limit: its words are read whole, also
    # in the quote-aware split, and each command of a chain.
    (
        "openclaw config set behind options",
        lambda d=1: ex(
            _repeat("openclaw ", "-x y ", " config set tools.exec.security full", size=SIZE // d)
        ),
    ),
    (
        "openclaw config set of quoted JSON behind options",
        lambda d=1: ex(
            _repeat(
                "openclaw ", "-x y ", ' config set tools.exec \'{"security": "full"}\'', SIZE // d
            )
        ),
    ),
    (
        "a chain of openclaw config sets",
        lambda d=1: ex(_repeat("", "openclaw -x y config set a.b c; ", size=SIZE // d)),
    ),
    # A command is parsed up to `MAX_PARSE_CHARS`, and the approval-loosening routes read a parsed
    # command's segments (a longer one's words, as the shapes above): the same shapes at that length.
    *(
        (f"{name}, parsed", lambda d=1, make=make: ex(make(MAX_PARSE_CHARS // d)))
        for name, make in [
            ("openclaw -v", lambda size: _repeat("openclaw ", "-v ", "status", size)),
            (
                "openclaw config",
                lambda size: _repeat("openclaw ", "-x config -x set ", "a b", size),
            ),
            (
                "openclaw config read-from flags",
                lambda size: _repeat(
                    "openclaw config ", "-x patch --batch-file f --file g ", "a b", size
                ),
            ),
            (
                "openclaw approvals file flags",
                lambda size: _repeat("openclaw approvals ", "-x set --file /tmp/a ", "a", size),
            ),
            (
                "openclaw exec-policy presets and flags",
                lambda size: _repeat(
                    "openclaw exec-policy ", "-x preset -x set --ask off yolo ", "a", size
                ),
            ),
            (
                "openclaw approvals allowlist entries",
                lambda size: _repeat(
                    "openclaw approvals -x allowlist ", "-x allowlist add '*' ", "a", size
                ),
            ),
        ]
    ),
    # Listed command patterns with many heads in one simple command, and chains of them.
    *(
        (f"{unit.strip()} chain", lambda d=1, unit=unit: ex(_repeat("", unit, size=SIZE // d)))
        for unit in [
            "systemctl stop ",
            "launchctl unload ",
            "chown root ",
            "chown.root.chmod.",
            "pkill ",
            "uvx ",
            "az ",
            "DOCKER_HOST=",
            "echo registry=https://r > ",
        ]
    ),
    (
        "inline code with a long run of path characters",
        lambda d=1: planir(
            "execute_code",
            "exec",
            {"code": "open('x', 'w')\n" + "a/" * ((SIZE - 20) // 2 // d)},
            platform="hermes",
        ),
    ),
    ("rsync chain", lambda d=1: ex(_repeat("", "rsync ", size=SIZE // d))),
    ("scp chain", lambda d=1: ex(_repeat("", "scp a b ", size=SIZE // d))),
    ("rsync chain with hosts", lambda d=1: ex(_repeat("", "rsync a b@ ", size=SIZE // d))),
    ("scp of a long dotted word", lambda d=1: ex(_repeat("scp ", "a.", size=SIZE // d))),
    ("sftp of a long word with @", lambda d=1: ex(_repeat("sftp ", "a@", size=SIZE // d))),
]


@pytest.mark.parametrize("name, make", LONG, ids=[n for n, _ in LONG])
def test_a_long_option_run_or_command_chain_scans_fast(name, make):
    raw = make()
    assert len(json.dumps(raw["pending_call"]["arguments"])) < MAX_CALL_CHARS
    res, spent = scan(raw)
    assert_fast_or_linear(spent, FAST, lambda d: scan(make(d)), f"whole scan, {name}")
    aira = next(e for e in res.envelopes if e.step is ProbeStep.AIRA)
    assert aira.status is ProbeStatus.OK, aira.evidence


def test_a_long_chain_inside_a_shell_script_scans_fast():
    def make(d: int) -> dict:
        return ex("bash -c '" + _repeat("", "-x config -x set ", size=(SIZE - 30) // d) + "'")

    start = time.perf_counter()
    run(make(1))
    spent = time.perf_counter() - start
    assert_fast_or_linear(spent, FAST, lambda d: run(make(d)), "a chain inside a shell script")


# --------------------------------------------------------------------------- fail closed

RUNS = [1, 10, 1000, 5000]


@pytest.mark.parametrize("n", RUNS)
def test_a_plugin_disable_behind_a_long_option_run_takes_the_floor(n):
    command = "openclaw " + "-v " * n + "plugins " + "-p w " * n + "disable sentrook-openclaw"
    _, env = run(ex(command))
    assert "guardrail.plugin_disable" in floor_reasons(env)


@pytest.mark.parametrize("n", RUNS)
def test_a_gateway_stop_behind_a_long_option_run_takes_the_floor(n):
    _, env = run(hx("hermes " + "--profile w " * n + "gateway " + "-q " * n + "stop"))
    assert "guardrail.gateway_stop" in floor_reasons(env)


@pytest.mark.parametrize("n", RUNS)
def test_a_plugin_command_behind_a_long_option_run_takes_the_floor(n):
    _, env = run(ex("openclaw " + "-x y " * n + "sentrook " + "-x status " * n + "grant x"))
    assert "guardrail.plugin_command" in floor_reasons(env)


@pytest.mark.parametrize("n", RUNS)
def test_a_config_set_behind_a_long_option_run_takes_the_floor(n):
    command = (
        "openclaw " + "-x y " * n + "config " + "-x set " * n + "set plugins.disabled sentrook"
    )
    _, env = run(ex(command))
    assert "guardrail.config_entry" in floor_reasons(env)


@pytest.mark.parametrize("n", RUNS)
def test_an_approvals_config_set_behind_a_long_option_run_is_found(n):
    """Scored, not floored: the rule is still found however long the run."""
    command = "hermes " + "-x y " * n + "config " + "-x set " * n + "set command_allowlist '*'"
    _, env = run(hx(command))
    assert "selfmod.host_approvals" in {c.reason for c in env.contributions}


@pytest.mark.parametrize("n", RUNS)
def test_an_approval_loosening_behind_a_long_option_run_takes_the_floor(n):
    """Parsed up to `MAX_PARSE_CHARS`, read as words past it: the floor either way."""
    command = "openclaw " + "-x y " * n + "config " + "-x set " * n + "set tools.exec.security full"
    _, env = run(ex(command))
    assert "guardrail.approval_loosening" in floor_reasons(env)


@pytest.mark.parametrize("n", RUNS)
def test_an_exec_policy_preset_behind_a_long_option_run_takes_the_floor(n):
    command = "openclaw " + "-x y " * n + "exec-policy " + "-x preset " * n + "preset yolo"
    _, env = run(ex(command))
    assert "guardrail.approval_loosening" in floor_reasons(env)


@pytest.mark.parametrize("n", RUNS)
def test_a_launcher_with_a_long_option_run_is_still_peeled(n):
    _, env = run(ex("npx " + "-p openclaw " * n + "openclaw plugins disable sentrook-openclaw"))
    assert "guardrail.plugin_disable" in floor_reasons(env)


def test_reads_behind_a_long_option_run_stay_quiet():
    for command in (
        "openclaw " + "-v " * 5000 + "plugins " + "-p w " * 5000 + "list",
        "openclaw " + "-x y " * 5000 + "config " + "-x get " * 5000 + "get plugins.disabled",
        "openclaw " + "-x y " * 5000 + "sentrook " + "-x status " * 5000 + "status",
        "hermes " + "-x y " * 5000 + "gateway restart",
    ):
        _, env = run(ex(command))
        assert not {r for r in floor_reasons(env) if r.startswith("guardrail.")}, command[-40:]


# --------------------------------------------------------------------------- the matcher, word for word


def _reference_cli_reasons(tokens: list[str], lists) -> list[str]:
    """The guardrail CLI matcher as it was written before it was made linear: every word that can follow
    the options tried as the subcommand, and every word after that as the verb, with the words after it
    joined. Cubic in the words; the oracle for small commands."""
    plugin_ids = [s.lower() for s in lists.strings("guardrail", "plugin_ids")]
    entries = {
        name: lists.get("guardrail", name, default=[]) or []
        for name in ("plugin_cli", "plugin_command_cli", "config_cli", "gateway_cli")
    }
    found: list[str] = []

    def emit(reason: str) -> None:
        if reason not in found:
            found.append(reason)

    head = tokens[0]
    for at in detectors._after_options(tokens, 1):
        sub = tokens[at].lower()
        verbs = [
            (tokens[v].lower(), " ".join(tokens[v + 1 :]))
            for v in detectors._after_options(tokens, at + 1)
        ]
        for entry in entries["plugin_cli"]:
            if head == entry.get("head") and sub == entry.get("subcommand"):
                blocked = {v.lower() for v in entry.get("blocked_verbs", [])}
                if any(
                    verb in blocked and any(p in rest.lower() for p in plugin_ids)
                    for verb, rest in verbs
                ):
                    emit("guardrail.plugin_disable")
        for entry in entries["plugin_command_cli"]:
            if head == entry.get("head") and sub == entry.get("subcommand"):
                allowed = {v.lower() for v in entry.get("allowed_verbs", [])}
                if any(not verb.startswith("-") and verb not in allowed for verb, _ in verbs):
                    emit("guardrail.plugin_command")
        for entry in entries["config_cli"]:
            if head == entry.get("head") and sub == entry.get("subcommand"):
                mutating = {v.lower() for v in entry.get("mutating_verbs", [])}
                for verb, rest in verbs:
                    if verb not in mutating:
                        continue
                    if detectors._match_any(
                        lists.patterns("guardrail", "host_approvals", "config_set_patterns"), rest
                    ):
                        emit("guardrail.host_approvals")
                    elif detectors._match_any(
                        lists.patterns("guardrail", "config_key_patterns"), rest
                    ):
                        emit("guardrail.config_entry")
        for entry in entries["gateway_cli"]:
            if head == entry.get("head") and sub == entry.get("subcommand"):
                blocked = {v.lower() for v in entry.get("blocked_verbs", [])}
                if any(verb in blocked for verb, _ in verbs):
                    emit("guardrail.gateway_stop")
    return found


_WORDS = [
    "openclaw",
    "hermes",
    "plugins",
    "sentrook",
    "config",
    "gateway",
    "disable",
    "remove",
    "list",
    "status",
    "grant",
    "set",
    "unset",
    "get",
    "stop",
    "restart",
    "plugins.disabled",
    "approvals.mode",
    "auto",
    "command_allowlist",
    "x",
    "-p",
    "-v",
    "--profile",
    "--profile=w",
    "--",
    "-",
    "-x=1",
    "SENTROOK",
    "Sentrook-openclaw",
    "approvals.approvals.approvals",
    "approval.x.y.z",
    "approvals.",
    "approvals.mode",
    "always",
    "'auto'",
    "plugins.plugins.disabled",
]


def test_the_linear_matcher_agrees_with_the_reference_word_for_word():
    lists = load_lists()
    rng = random.Random(20261120)
    for _ in range(6000):
        head = rng.choice(["openclaw", "hermes", "ls"])
        tokens = [head, *(rng.choice(_WORDS) for _ in range(rng.randint(0, 9)))]
        assert detectors._cli_guardrail_reasons(tokens, lists) == _reference_cli_reasons(
            tokens, lists
        ), tokens


def test_the_guardrail_cli_patterns_grow_with_the_words_after_the_verb():
    """The linear matcher reads a pattern once for the longest run of words after a verb, which is only
    right for a pattern that, matching some words, matches any longer run ending in them: no start anchor
    and no negative lookbehind."""
    lists = load_lists()
    for key in (("host_approvals", "config_set_patterns"), ("config_key_patterns",)):
        for rx in lists.patterns("guardrail", *key):
            assert detectors._grows_with_rest(rx), rx.pattern


# --------------------------------------------------------------------------- a stalled probe


def test_a_stalled_probe_does_not_hold_the_response(monkeypatch):
    release = threading.Event()
    original = scan_module.Scanner._run_probe

    def stalled(self, step, probe, prepared, options):
        if step is ProbeStep.AIRA:
            release.wait(30)
        return original(self, step, probe, prepared, options)

    monkeypatch.setattr(scan_module, "PROBE_TIMEOUT_S", 0.3)
    monkeypatch.setattr(scan_module.Scanner, "_run_probe", stalled)
    try:
        res, spent = scan(ex("ls"))
    finally:
        release.set()
    assert spent < 0.3 + FAST / 2, f"{spent:.2f}s"
    aira = next(e for e in res.envelopes if e.step is ProbeStep.AIRA)
    assert aira.status is ProbeStatus.TIMEOUT
    assert res.response.status is ScanStatus.DEGRADED


def test_the_probe_timeout_is_one_deadline_for_all_probes(monkeypatch):
    """Two stalled probes take one timeout between them, not one each."""
    release = threading.Event()
    original = scan_module.Scanner._run_probe

    def stalled(self, step, probe, prepared, options):
        if step in (ProbeStep.AIRA, ProbeStep.CONTEXT):
            release.wait(30)
        return original(self, step, probe, prepared, options)

    monkeypatch.setattr(scan_module, "PROBE_TIMEOUT_S", 0.5)
    monkeypatch.setattr(scan_module.Scanner, "_run_probe", stalled)
    try:
        res, spent = scan(ex("ls"))
    finally:
        release.set()
    assert spent < 0.9, f"{spent:.2f}s"
    stalled_steps = {e.step for e in res.envelopes if e.status is ProbeStatus.TIMEOUT}
    assert stalled_steps == {ProbeStep.AIRA, ProbeStep.CONTEXT}


def test_a_fast_scan_is_unchanged():
    res, _ = scan(ex("openclaw plugins disable sentrook-openclaw"))
    assert all(e.status is not ProbeStatus.TIMEOUT for e in res.envelopes)
    assert "guardrail_tampering" in [f.floor for f in res.response.floors_applied]


def test_history_with_a_long_option_run_scans_fast():
    # At 1/4 size (15,000) the command is under MAX_PARSE_CHARS, but a history command is never parsed.
    def make(d: int) -> dict:
        command = _repeat("curl ", "-H x ", "https://example.com", size=60_000 // d)
        return ex("ls", history=[hist_step(1, "exec", "exec", {"command": command})])

    _, spent = scan(make(1))
    assert_fast_or_linear(spent, FAST, lambda d: scan(make(d)), "history with a long option run")


# --------------------------------------------------------------------------- list patterns, piece for piece

#: Words and forms the listed patterns are built from, so random texts match them often.
_PHRASES = [
    *"scp rsync sftp a@b: x.io: rsync://h sftp://h aws s3 cp sync gsutil rclone copy r: s3://b".split(),
    *"gs://b approvals.mode approval.x.y approvals. auto 'allow' \"always\" pkill killall".split(),
    *"systemctl stop mask launchctl unload bootout docker kill rm rmi openclaw hermes chmod u+s".split(),
    *"4755 +s chown root base64 -d --decode xxd -r sh sudo bash python3 node curl wget pip pip3".split(),
    *"install npm i add pnpm yarn bun pipx run uv tool uvx npx https://x git+ssh github:a/b cargo".split(),
    *"--git =command= &command= command= python echo printf registry=https://r index-url".split(),
    *"= http://r > >> .npmrc pip.conf .pypirc find -exec -delete -execdir xargs shred git clean".split(),
    *"-fdx -f dd of=/dev/sda of=~/x gcloud delete az push --force --mirror :branch -H --host=".split(),
    *"DOCKER_HOST=tcp://h system prune volume kubectl create apply clusterrolebinding rbac".split(),
    *"x a.b @ : = ( ) ' / . - -x".split(),
    *"|sudo -u -curl|sudo |sudo\t-E -sh |sh SUDO python3 node| -|bash -a\nb".split(),
    *"open( open\n( OPEN( ) 'w' \"a+\" 'x' 'r' 'w+\" \"wb\" f,".split(),
    *"iam grant grant-role add-roles bind-role --role --roles= roles/ owner admin editor root".split(),
    *"administrator add-iam-policy-binding attach-user-policy put-role-policy poweruser".split(),
    *"az role assignment create contributor".split(),
]
_NOISE = [" ", " ", "  ", "\t", "\n", ";", "&", "|", " | ", " > ", "-x "]


def _text(rng: random.Random, words: list[str]) -> str:
    return "".join(rng.choice(words) for _ in range(rng.randint(0, 16)))


def test_every_linear_search_is_a_listed_pattern():
    lists = load_lists()
    listed = {rx.pattern for rxs in lists._patterns.values() for rx in rxs} | {
        r.regex.pattern for rules in lists._rules.values() for r in rules
    }
    assert set(linear_search.LINEAR) <= listed


def test_the_linear_searches_agree_with_their_patterns():
    """Whether there is a match, the match itself (span and groups), and every match in turn."""
    import re

    rng = random.Random(20261121)
    for pattern in linear_search.LINEAR:
        rx = re.compile(pattern, re.IGNORECASE)
        mine = [w for w in _PHRASES if w.lower().strip("-.:=/") in pattern.lower()]
        words = _NOISE * 2 + mine * 4 + _PHRASES
        for _ in range(1500):
            text = _text(rng, words)
            want = rx.search(text)
            got = linear_search.search(rx, text)
            assert linear_search.found(rx, text) == (want is not None), (pattern, text)
            assert (got is None) == (want is None), (pattern, text)
            if want is not None:
                assert (got.span(), got.groups()) == (want.span(), want.groups()), (pattern, text)
            assert [m.span() for m in linear_search.finditer(rx, text)] == [
                m.span() for m in rx.finditer(text)
            ], (pattern, text)


_CHAINS = {
    r"\bchown\b[^;&|\n]*\broot\b[^;&|\n]*\bchmod\b[^;&|\n]*\+s": [
        ["chown", "Chown", "xchown"],
        ["root", "ROOT", "roots"],
        ["chmod", "chmodx"],
        ["+s", "u+s", "+x"],
    ],
    r"\bsystemctl\b[^;&|\n]*\b(?:stop|disable|mask|kill)\b[^;&|\n]*\b(?:openclaw|hermes)": [
        ["systemctl"],
        ["stop", "mask", "stopx"],
        ["openclaw", "hermes", "xhermes"],
    ],
    r"\b(?:echo|printf)\b[^;&|\n]*(?:registry|index-url)\s*=\s*https?://[^;&|\n]*>>?\s*"
    r"[^;&|\n]*(?:\.npmrc|pip\.conf|\.pypirc)": [
        ["echo", "printf"],
        [
            "registry=https://r",
            "index-url = http://r",
            "registry =\nhttps://r",
            "registry=http:/",
            "REGISTRY\u2003=\u00a0https://r",
        ],
        [">", ">>", "> \n", ">\n", ">>\n\n", ">\u00a0", "> >", ">>>", ">\t\n "],
        [".npmrc", "pip.conf", ".pypirc", "npmrc", ".npmrc.npmrc"],
    ],
    r"\bDOCKER_HOST=\S+\s+docker\s+(?:rm|rmi|system\s+prune|volume\s+rm)\b": [
        ["DOCKER_HOST=", "docker_host=", "xDOCKER_HOST="],
        ["tcp://h", "a;b", "", "DOCKER_HOST=x"],
        [" ", "\n", "  "],
        ["docker"],
        [" rm", " rmi", " system prune", " volume\nrm", " rmx"],
    ],
    r"\b(?:DOCKER_HOST=\S+\s+)?docker\s+(?:-H|--host)[\s=]\S+[^;&|\n]*"
    r"\b(?:rm|rmi|system\s+prune|volume\s+rm)\b": [
        ["", "DOCKER_HOST=a ", "DOCKER_HOST=DOCKER_HOST=b ", "xDOCKER_HOST=c ", "DOCKER_HOST= "],
        ["docker", "Docker", "xdocker"],
        [" -H ", " --host=", " -H\n", "-H "],
        ["tcp://h", "a;b", "a|b", "", "x.rm.a", "rm", "x.rmi;rm.", "a.system\nprune", "rm.rm"],
        [" x ", " ", ";", "\n", ""],
        ["rm", "rmi", "system prune", "volume rm", "rmx"],
    ],
}


@pytest.mark.parametrize("pattern", list(_CHAINS), ids=range(len(_CHAINS)))
def test_chains_agree_with_their_patterns_piece_by_piece(pattern):
    """The pieces in order with separators, newlines and decoys between them: a piece may end past a
    newline (`registry =\\nhttps://`), or match more than one length (`>>?\\s*`)."""
    import re

    assert pattern in linear_search.LINEAR
    rx = re.compile(pattern, re.IGNORECASE)
    rng = random.Random(7)
    matched = 0
    for _ in range(3000):
        parts: list[str] = []
        for _rep in range(rng.randint(1, 3)):
            for slot in _CHAINS[pattern]:
                if rng.random() < 0.85:
                    parts.append(rng.choice(slot))
                parts.extend(rng.choice(_NOISE) for _ in range(rng.choice([0, 0, 1, 1, 2, 3])))
        text = "".join(parts)
        want = rx.search(text)
        assert linear_search.found(rx, text) == (want is not None), text
        got = linear_search.search(rx, text)
        assert (got is None) == (want is None) and (want is None or got.span() == want.span()), text
        assert [m.span() for m in linear_search.finditer(rx, text)] == [
            m.span() for m in rx.finditer(text)
        ], text
        if want is not None:
            assert got.group(0) == want.group(0) and got.groups() == want.groups() == ()
        matched += want is not None
    assert matched > 5


#: Per listed pattern with a linear search, the repeated texts its regex was slowest on.
_SLOW_UNITS = {
    "scp": ["rsync ", "a@", "a.", "scp a b "],
    "aws": ["aws s3 cp "],
    "gsutil": ["gsutil cp "],
    "rclone": ["rclone copy "],
    "approvals": ["approvals.", "approval."],
    "pkill": ["pkill "],
    "systemctl": ["systemctl stop ", "systemctl.stop."],
    "launchctl": ["launchctl unload "],
    "docker\\s+(?:stop": ["docker stop "],
    "bchmod": ["chmod "],
    "chown": ["chown root ", "chown.root.chmod."],
    "base64": ["base64 -d "],
    "xxd": ["xxd -r "],
    "curl|wget": ["curl ", "curl.wget.", "wget/", "-curl|sudo ", "|sudo -x "],
    "pip3": ["pip3 install "],
    "npm": ["npm install "],
    "pnpm": ["bun add "],
    "pipx": ["pipx run "],
    "\\buv\\s": ["uv run "],
    "uvx": ["uvx "],
    "npx": ["npx "],
    "cargo": ["cargo install "],
    "command=": ["=command=", "command="],
    "echo|printf": ["echo ", "echo registry=https://r ", "echo@"],
    "bfind": ["find ", "find.", "find="],
    "xargs": ["xargs "],
    "git\\s+clean": ["git clean "],
    "bdd": ["dd ", "dd:"],
    "gcloud": ["gcloud "],
    "baz": ["az "],
    "git\\s+push": ["git push "],
    "DOCKER_HOST": ["DOCKER_HOST=", "docker -H x "],
    "kubectl": ["kubectl create "],
    "assignment": ["az role assignment create --role a ", "az role assignment create ", "--role "],
    "add-roles": ["iam grant ", "iam grant --role x ", "--roles=a ", "iam grant --role a=b "],
    "add-iam-policy": ["add-iam-policy-binding ", "add-iam-policy-binding --role a "],
    "attach-": ["aws iam attach-user-policy ", "aws iam put-role-policy x ", "admin "],
    "open\\s": ["open(", "open (", "open('", "open(x, 'r'"],
}


def test_every_linear_search_is_fast_on_long_texts():
    """Each listed pattern with a linear search, on 95,000 characters of the texts its regex was slowest
    on (seconds to minutes each), and on chains whose pieces all occur but never in order."""
    import re

    # key -> (head, unit, count, tail): head + unit * count + tail, built at 1/d of the count
    texts = {
        "systemctl": ("openclaw; ", "systemctl stop ", 6300, ""),
        "chown": ("+s; ", "chown root chmod ", 5500, ""),
        "echo|printf": (".npmrc; ", "echo registry=https://r > ", 3600, ""),
        # matching chains: the regex builds each match from many ways to make it
        "echo|printf ": (
            "",
            "echo registry=https://r > x ",
            3300,
            "; echo registry=https://r > .npmrc",
        ),
        "echo|printf  ": ("", "echo registry=https://r > .npmrc ", 2700, ""),
        "echo|printf   ": ("", "echo registry=https://r >> pip.conf; ", 2600, ""),
        "systemctl ": ("", "systemctl stop openclaw ", 3900, ""),
        "chown ": ("", "chown root chmod +s ", 4700, ""),
    }

    def searches(rx: re.Pattern[str], text: str) -> None:
        linear_search.found(rx, text)
        linear_search.search(rx, text)
        list(linear_search.finditer(rx, text))

    for pattern in linear_search.LINEAR:
        rx = re.compile(pattern, re.IGNORECASE)
        units = [u for key, us in _SLOW_UNITS.items() if key in pattern for u in us]
        assert units, pattern
        for head, unit, count, tail in [("", u, SIZE // len(u), "") for u in units] + [
            t for key, t in texts.items() if key.strip() in pattern
        ]:

            def build(d: int, head=head, unit=unit, count=count, tail=tail) -> str:
                return head + unit * (count // d) + tail

            start = time.perf_counter()
            searches(rx, build(1))
            spent = time.perf_counter() - start
            assert_fast_or_linear(
                spent,
                FAST / 4,
                lambda d, rx=rx, build=build: searches(rx, build(d)),
                f"{pattern[:40]} on {build(1)[:20]!r}",
            )


def test_inline_code_paths_are_found_as_the_regex_finds_them():
    words = [
        "a",
        "/",
        "sentrook",
        "/sentrook",
        "Sentrook",
        "x.y",
        "~",
        "$",
        "-",
        " ",
        "\n",
        "(",
        ".",
    ]
    words += ["sentrookx", "/sentrook/", "_"]
    rng = random.Random(1)
    for _ in range(20000):
        text = "".join(rng.choice(words) for _ in range(rng.randint(0, 12)))
        want = [m.span() for m in detectors._SENTROOK_PATH.finditer(text)]
        assert [m.span() for m in detectors._sentrook_paths(text)] == want, text


def test_inline_code_that_writes_into_sentrook_state_still_takes_the_floor():
    code = "open('/home/me/.openclaw/sentrook/grants.json', 'w')\n" + "a/" * 20000
    _, env = run(planir("execute_code", "exec", {"code": code}, platform="hermes"))
    assert "guardrail.state_dir_write" in floor_reasons(env)


def test_a_listed_pattern_compiled_with_other_flags_is_searched_as_the_plain_regex():
    import re

    from sentrook.aira import linear_search

    pattern = next(iter(linear_search.LINEAR))
    assert linear_search._linear(re.compile(pattern, re.IGNORECASE)) is not None
    for flags in (re.IGNORECASE | re.MULTILINE, re.IGNORECASE | re.ASCII, 0):
        assert linear_search._linear(re.compile(pattern, flags)) is None
