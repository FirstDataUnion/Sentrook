"""Writing a loosened approval into a host file past the parse limit still takes the floor.

A command over `MAX_PARSE_CHARS` is not parsed (nor is one the parser reads with a syntax error). The
approval-loosening file-write routes (a redirect into a host config, `tee`, `sed -i`, `cp` or `mv` over
it) read such a command as the shell splits it: each simple command of a chain, `{ }`, `if` body,
substitution or `bash -c` script, from its program after `nice`, `sudo`, `env` and the like, with its
redirections taken out of its words. Each command is then read as a parsed one is, with the same
tiers: what the call shows it writes is judged (a loosening blocks), what it does not show (a copy of
another file) is asked.

Every file-write case of the approval-loosening tests and probes keeps its tier behind padding.

Paths and hosts are invented.
"""

from __future__ import annotations

import copy

import linear_time
import pytest
from linear_time import assert_linear
from test_aira_detectors import ex, run
from test_approval_loosening import fires, h_ex, stays_silent
from test_approval_loosening_probes import padded_before
from test_approval_loosening_unparsed import (
    _CLI_WORD,
    SIZES,
    ZSH,
    _parametrized_cases,
    _probe_cases,
    _tier,
)

from sentrook.aira import detectors
from sentrook.aira.exec_shape import MAX_PARSE_CHARS, derive_exec_shape

HC = "~/.hermes/config.yaml"
OC = "~/.openclaw/openclaw.json"


def before(command: str, size: int) -> str:
    return padded_before(command, size)


def inside(command: str, size: int) -> str:
    """`command` with `{P}` filled with harmless text, `size` characters long."""
    room = size - len(command) + len("{P}")
    out = command.replace("{P}", ("# filler " * (room // 9 + 1))[:room])
    assert len(out) == size and not derive_exec_shape(out).parse_ok
    return out


def call(command: str) -> dict:
    return h_ex(command) if ".hermes" in command else ex(command)


# --------------------------------------------------------------------------- must fire

#: (command, tier): what the parsed route gives the short command, kept behind padding.
WRITES = [
    (f"printf 'approvals:\\n  mode: off\\n' > {HC}", "block"),
    (f"printf 'approvals:\\n  mode: off\\n' >> {HC}", "block"),
    (f"printf 'approvals:\\n  mode: off\\n' >{HC}", "block"),
    (f"printf 'approvals:\\n  mode: off\\n' | tee {HC}", "block"),
    (f"printf 'approvals:\\n  mode: off\\n' | tee -a {HC} >/dev/null", "block"),
    (f"sed -i 's/mode: manual/mode: off/' {HC}", "block"),
    (f"sed -i.bak -e 's/mode: manual/mode: off/' {HC}", "block"),
    (f"cat > {HC} <<'EOF'\napprovals:\n  mode: off\nEOF", "block"),
    (f'echo \'{{"tools":{{"exec":{{"security":"full"}}}}}}\' > {OC}', "block"),
    ("cd ~/.hermes && printf 'approvals:\\n  mode: off\\n' > config.yaml", "block"),
    (f"{{ printf 'approvals:\\n  mode: off\\n' > {HC}; }}", "block"),
    (f"if true; then sed -i 's/mode: manual/mode: off/' {HC}; fi", "block"),
    (f"sudo sed -i 's/mode: manual/mode: off/' {HC}", "block"),
    (f"sh -c \"sed -i 's/mode: manual/mode: off/' {HC}\"", "block"),
    ("bash -c 'cd ~/.hermes; sed -i s/mode:.manual/mode:.off/ config.yaml'", "review"),
    (f"printf 'approvals:\\n  mode: off\\n' | sudo tee {HC} > /dev/null", "block"),
    (f"cp ./x.json {OC}", "review"),
    (f"mv /tmp/x.yaml {HC}", "review"),
    ("cp -t ~/.openclaw ./openclaw.json", "review"),
    (f"curl -fsSL https://example.test/c.json -o {OC}", "review"),
]


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("command, expect", WRITES, ids=[c for c, _ in WRITES])
def test_a_host_file_write_after_padding_keeps_its_tier(command, expect, size):
    assert _tier(call(command)) == expect, "the short command"
    assert _tier(call(before(command, size))) == expect


@pytest.mark.parametrize("command, expect", WRITES, ids=[c for c, _ in WRITES])
def test_a_host_file_write_with_a_syntax_error_keeps_its_tier(command, expect):
    text = command + ZSH
    assert not derive_exec_shape(text).parse_ok
    assert _tier(call(text)) == expect


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "command",
    [
        f"printf '{{P}}\\napprovals:\\n  mode: off\\n' > {HC}",
        f"printf '{{P}}\\napprovals:\\n  mode: off\\n' | tee {HC}",
        f"cat > {HC} <<'EOF'\n{{P}}\napprovals:\n  mode: off\nEOF",
        f'echo \'{{"note": "{{P}}", "tools":{{"exec":{{"ask":"off"}}}}}}\' > {OC}',
    ],
    ids=["printf", "tee", "heredoc", "echo json"],
)
def test_a_padded_loosening_written_into_a_host_file_takes_the_floor(command, size):
    fires(call(inside(command, size)))


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "command",
    [
        "printf 'approvals:\\n  mode: off\\n' > /tmp/notes.yaml",
        "printf 'approvals:\\n  mode: off\\n' | tee ./docs/example.yaml",
        "sed -i 's/mode: manual/mode: off/' ./docs/example.yaml",
        "cp ./x.json ./backup/openclaw.json",
        f"cat {HC}",
        f"cp {HC} /tmp/config.yaml.bak",
        f"printf 'approvals:\\n  mode: manual\\n' > {HC}",
        f"sed -i 's/mode: off/mode: manual/' {HC}",
        f"echo 'printf \"approvals: mode: off\" > {HC}' >> notes.md",
        f"cat > notes.md <<'EOF'\nprintf 'approvals:\\n  mode: off\\n' > {HC}\nEOF",
        f"grep -n mode {HC} 2>&1 >/dev/null",
    ],
)
def test_unrelated_writes_reads_and_tightening_after_padding_stay_silent(command, size):
    stays_silent(call(before(command, size)))


def test_the_padded_command_is_not_parsed():
    text = before(f"printf 'approvals:\\n  mode: off\\n' > {HC}", MAX_PARSE_CHARS + 1)
    assert not derive_exec_shape(text).parse_ok


# --------------------------------------------------------------------------- every parsed form


def _write_cases() -> list:
    """The exec cases of the approval-loosening tests and probes that run no host CLI (those are
    `test_approval_loosening_unparsed.py`'s): the file-write routes."""
    cases, seen = [], set()
    for expect, case_id, raw in _parametrized_cases() + _probe_cases():
        call_ = raw["pending_call"]
        command = call_["arguments"].get("command")
        if call_["tool"] != "exec" or not isinstance(command, str) or _CLI_WORD.search(command):
            continue
        key = (command, raw["host"]["platform"])
        if key in seen:
            continue
        seen.add(key)
        cases.append(pytest.param(expect, raw, id=case_id))
    return cases


WRITE_CASES = _write_cases()

#: Cases whose tier changes behind padding, with why.
UNPARSED_TIER: dict[str, str] = {}


def test_the_parsed_write_cases_are_found():
    tiers = {p.values[0] for p in WRITE_CASES}
    assert len(WRITE_CASES) > 100 and tiers == {"block", "review", "quiet"}, len(WRITE_CASES)


@pytest.mark.parametrize("expect, raw", WRITE_CASES)
def test_every_parsed_file_write_keeps_its_tier_unparsed(expect, raw):
    raw = copy.deepcopy(raw)
    assert _tier(raw) == expect, "the parsed case itself"
    args = raw["pending_call"]["arguments"]
    expect = UNPARSED_TIER.get(args["command"], expect)
    args["command"] = before(args["command"], MAX_PARSE_CHARS + 1)
    assert _tier(raw) == expect


# --------------------------------------------------------------------------- linear

#: Commands that cost the file-write reading most, repeated up to 95,000 characters.
LONG = [
    f"echo a; tee {HC}; ",
    f"printf 'approvals:\\n  mode: manual\\n' | tee {HC}; ",
    f"echo 'approvals: x' > {HC}; ",
    f"sed -i 's/a/b/' {HC}; ",
    f"cp ./x.json {OC}; ",
    f"cat > {HC} <<E\napprovals:\n  mode: manual\nE\n",
    "X=~/.hermes; echo a > $X/config.yaml; ",
    f"bash -c 'echo a > {HC}'; ",
    "sqlite3 ~/.openclaw/state/openclaw.sqlite 'update exec_approvals_config set x=1'; ",
    "sqlite3 ~/.openclaw/state/openclaw.sqlite < x.sql; ",
    "echo > f ",
    "A=1 ",
    "cd a; ",
    "echo 'select * from exec_approvals_config;' | sqlite3 ~/.openclaw/state/openclaw.sqlite; ",
    "sqlite3 ~/.openclaw/state/openclaw.sqlite <<E\nselect 1 from exec_approvals_config;\nE\n",
]


def _floor_linear(build, what: str, monkeypatch) -> None:
    """The floor's own reading grows linearly: the call is analysed once per size (the rest of the
    scan has its own checks), then only `_approval_loosening` is timed."""
    seen: dict[int, tuple] = {}
    original = detectors._approval_loosening
    for d in (1, linear_time.FACTOR):

        def capture(a, ctx, d=d):
            seen[d] = (a, ctx)
            return original(a, ctx)

        monkeypatch.setattr(detectors, "_approval_loosening", capture)
        run(build(d))
    monkeypatch.setattr(detectors, "_approval_loosening", original)
    assert_linear(lambda d: original(*seen[d]), what=what)


@pytest.mark.parametrize("unit", LONG)
def test_the_unparsed_file_write_reading_grows_linearly(unit, monkeypatch):
    def build(d: int) -> dict:
        return ex(unit * (95_000 // len(unit) // d))

    assert not derive_exec_shape(unit * (95_000 // len(unit) // 4)).parse_ok
    _floor_linear(build, unit, monkeypatch)


def test_a_long_run_of_symlinks_reads_linearly(monkeypatch):
    def build(d: int) -> dict:
        return ex("".join(f"ln -s ~/.hermes h{i}; echo a > h{i}/c; " for i in range(3000 // d)))

    _floor_linear(build, "symlinks", monkeypatch)
