"""A command with a very long run of options, or a long chain of one command name, scans in well under the
probe timeout, and a guardrail verb hidden behind such a run still takes the floor.

The guardrail CLI matchers try every word that can follow a run of options as the subcommand and as the
verb, because which options take a value is not known. Done naively that is cubic in the run's length:
16,000 characters of `curl -H x -H x …` took about 40 s. The words that can follow are worked out once
per command now, so the work is linear in the words, with no cap on the run.

A probe that stalls anyway does not hold the response: the scan answers at the probe timeout, degraded.
"""

from __future__ import annotations

import random
import threading
import time

import pytest
from test_aira_detectors import ex, floor_reasons, hist_step, run
from test_large_calls import FAST, scan

from sentrook import scan as scan_module
from sentrook.aira import detectors
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

LONG = [
    ("curl -H x", lambda: ex(_repeat("curl ", "-H x ", "https://example.com"))),
    ("git -c a=b", lambda: ex(_repeat("git ", "-c a=b ", "status"))),
    ("ls -l (a head in no guardrail entry)", lambda: ex(_repeat("ls ", "-l "))),
    ("openclaw -v (a guardrail head)", lambda: ex(_repeat("openclaw ", "-v ", "status"))),
    ("hermes -p x (a guardrail head)", lambda: hx(_repeat("hermes ", "-p x ", "status"))),
    (
        "openclaw config with every word a possible verb",
        lambda: ex(_repeat("openclaw ", "-x config -x set ", "a b")),
    ),
    (
        "openclaw config set with many read-from flags",
        lambda: ex(_repeat("openclaw config ", "-x patch --batch-file f --file g ", "a b")),
    ),
    (
        "openclaw approvals with many file flags",
        lambda: ex(_repeat("openclaw approvals ", "-x set --file /tmp/a ", "a")),
    ),
    (
        "openclaw exec-policy with many presets and flags",
        lambda: ex(_repeat("openclaw exec-policy ", "-x preset -x set --ask off yolo ", "a")),
    ),
    (
        "openclaw approvals allowlist add with many entries",
        lambda: ex(_repeat("openclaw approvals -x allowlist ", "-x allowlist add '*' ", "a")),
    ),
    ("npx launcher with many launchable values", lambda: ex(_repeat("npx ", "-p openclaw "))),
    # The approval-loosening routes read a parsed command, and a command is parsed up to
    # `MAX_PARSE_CHARS`: the same shapes at that length.
    *(
        (f"{name}, parsed", lambda make=make: ex(make(MAX_PARSE_CHARS)))
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
    ("rsync chain", lambda: ex(_repeat("", "rsync "))),
    ("scp chain", lambda: ex(_repeat("", "scp a b "))),
    ("rsync chain with hosts", lambda: ex(_repeat("", "rsync a b@ "))),
    ("scp of a long dotted word", lambda: ex(_repeat("scp ", "a."))),
    ("sftp of a long word with @", lambda: ex(_repeat("sftp ", "a@"))),
]


@pytest.mark.parametrize("name, make", LONG, ids=[n for n, _ in LONG])
def test_a_long_option_run_or_command_chain_scans_fast(name, make):
    raw = make()
    start = time.perf_counter()
    run(raw)
    spent = time.perf_counter() - start
    assert spent < FAST, f"rule probe, {name}: {spent:.2f}s"
    res, spent = scan(raw)
    assert spent < FAST, f"whole scan, {name}: {spent:.2f}s"
    aira = next(e for e in res.envelopes if e.step is ProbeStep.AIRA)
    assert aira.status is ProbeStatus.OK, aira.evidence


def test_a_long_chain_inside_a_shell_script_scans_fast():
    raw = ex("bash -c '" + _repeat("", "-x config -x set ", size=SIZE - 30) + "'")
    start = time.perf_counter()
    run(raw)
    assert time.perf_counter() - start < FAST


# --------------------------------------------------------------------------- fail closed

RUNS = [1, 10, 1000, 5000]
#: The approval-loosening routes read a parsed command: these runs stay under `MAX_PARSE_CHARS`.
PARSED_RUNS = [1, 10, 100, 1000]


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


@pytest.mark.parametrize("n", PARSED_RUNS)
def test_an_approval_loosening_behind_a_long_option_run_takes_the_floor(n):
    command = "openclaw " + "-x y " * n + "config " + "-x set " * n + "set tools.exec.security full"
    assert len(command) <= MAX_PARSE_CHARS
    _, env = run(ex(command))
    assert "guardrail.approval_loosening" in floor_reasons(env)


@pytest.mark.parametrize("n", PARSED_RUNS)
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
    command = _repeat("curl ", "-H x ", "https://example.com", size=60_000)
    res, spent = scan(ex("ls", history=[hist_step(1, "exec", "exec", {"command": command})]))
    assert spent < FAST, f"{spent:.2f}s"


# --------------------------------------------------------------------------- exec markers, piece for piece

_MARKER_PIECES = [
    "scp",
    "rsync",
    "SFTP",
    "aws",
    "s3",
    "cp",
    "sync",
    "gsutil",
    "rclone",
    "copy",
    "s3://",
    "gs://",
    "rsync://",
    "sftp://",
    "remote",
    "a",
    "x.io",
    "example.COM",
    "ſt",
    "@",
    ":",
    ".",
    "-",
    "_",
    "/",
    " ",
    " ",
    "\t",
    "\n",
    ";",
    "&",
    "|",
]


def test_every_linear_marker_is_a_shipped_pattern():
    shipped = {r.regex.pattern for r in load_lists().rules("egress", "exec_markers")}
    assert set(detectors._LINEAR_MARKERS) <= shipped


def test_the_linear_markers_agree_with_their_patterns():
    import re

    rng = random.Random(20261121)
    for pattern in detectors._LINEAR_MARKERS:
        rx = re.compile(pattern, re.IGNORECASE)
        for _ in range(4000):
            text = "".join(rng.choice(_MARKER_PIECES) for _ in range(rng.randint(0, 14)))
            assert detectors._marker_found(rx, text) == (rx.search(text) is not None), (
                pattern,
                text,
            )
