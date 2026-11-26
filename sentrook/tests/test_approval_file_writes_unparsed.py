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
from test_approval_loosening import fires, h_ex, reviews, stays_silent
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
    # A redirect that clobbers, on a compound command, or after a pass-through stage.
    (f"printf 'approvals:\\n  mode: off\\n' >| {HC}", "block"),
    (f"{{ printf 'approvals:\\n  mode: off\\n'; }} > {HC}", "block"),
    (f"( printf 'approvals:\\n  mode: off\\n' ) > {HC}", "block"),
    (f"for i in 1; do printf 'approvals:\\n  mode: off\\n'; done > {HC}", "block"),
    (f"if true; then printf 'approvals:\\n  mode: off\\n'; fi > {HC}", "block"),
    (f"{{ cat /tmp/x; }} > {HC}", "review"),
    (f"printf 'approvals:\\n  mode: off\\n' | cat | tee {HC}", "block"),
    (f"printf 'approvals:\\n  mode: off\\n' | tee /tmp/x | tee {HC}", "block"),
    (f"printf 'approvals:\\n  mode: off\\n' | tee >(cat > {HC})", "block"),
    (f"env -i printf 'approvals:\\n  mode: off\\n' > {HC}", "block"),
    (
        "sqlite3 /tmp/a.db <<E\nselect 1;\nE\nsqlite3 ~/.openclaw/state/openclaw.sqlite <<F\n"
        "update exec_approvals_config set default_security='full';\nF",
        "block",
    ),
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


@pytest.mark.parametrize("length", ["padded", "syntax error"])
def test_an_unreadable_pipe_into_a_host_file_is_asked_when_not_parsed(length):
    """Parsed, the pipe's writer is checked as a script; unparsed, a host file written from a pipe
    the scan cannot read is asked, never left quiet."""
    command = f"sort /tmp/x | tee {HC}"
    text = before(command, MAX_PARSE_CHARS + 1) if length == "padded" else command + ZSH
    reviews(call(text))


#: Nine folder names of 250 characters, as one `cd` argument.
_DEEP = "/".join(["d" * 250] * 9)


_UP = "/".join([".."] * 18)
_DEEP_CDS = f"cd ~/.hermes && cd {_DEEP} && cd {_DEEP}"
_L = "printf 'approvals:\\n  mode: off\\n'"
#: Long runs of relative `cd`s that end back in a host tree, each argument under the path limit:
#: the shell takes them all.
LONG_CDS = [
    f"{_DEEP_CDS} && cd {_UP} && {_L} > config.yaml",
    f"{_DEEP_CDS} && " + " && ".join(["cd .."] * 18) + f" && {_L} > config.yaml",
    f"{_DEEP_CDS} && cd {'/'.join(['..'] * 16)} && {_L} > ../../config.yaml",
    f"{_DEEP_CDS} && cd {_UP} && {_L} | tee config.yaml",
    f"cd ~/.openclaw && cd {_DEEP} && cd {_DEEP} && cd {_UP} && "
    'echo \'{"tools":{"exec":{"security":"full"}}}\' > openclaw.json',
]


@pytest.mark.parametrize("command", LONG_CDS)
def test_a_long_run_of_relative_cds_keeps_its_folder_when_parsed(command):
    """A parsed command is under the parse limit, which bounds the paths it can build: its folder
    is followed exactly."""
    assert derive_exec_shape(command).parse_ok
    fires(call(command))


@pytest.mark.parametrize("command", LONG_CDS)
def test_a_long_run_of_relative_cds_never_leaves_a_host_write_quiet_unparsed(command):
    """Unparsed, a folder whose path grows past the limit is no longer placed (a long run of `cd a`
    would make each later path longer to read): a write there that names a host config is asked,
    never left quiet."""
    assert _tier(call(before(command, MAX_PARSE_CHARS + 1))) in ("block", "review")


def test_a_cd_argument_over_the_path_limit_does_not_move_the_folder():
    command = (
        f"cd ~/.hermes && cd {'d' * 5000} && printf 'approvals:\\n  mode: off\\n' > config.yaml"
    )
    fires(h_ex(command))


@pytest.mark.parametrize("length", ["padded", "syntax error"])
def test_a_write_in_a_heredoc_with_no_closing_line_is_asked_not_blocked(length):
    """The shell runs nothing of such a body: what it would write is only asked about."""
    command = f"cat > docs/guide.md <<'EOF'\n# Guide\nprintf 'approvals:\\n  mode: off\\n' > {HC}\n"
    text = before(command, MAX_PARSE_CHARS + 1) if length == "padded" else command + ZSH
    assert not derive_exec_shape(text).parse_ok
    reviews(call(text))


@pytest.mark.parametrize("length", ["short", "padded"])
def test_a_shell_fed_a_heredoc_with_no_closing_line_writes_its_body(length):
    """A shell reading its commands from a heredoc runs the body even with no closing line."""
    command = f"bash <<EOF\n{_L} > {HC}\n"
    text = command if length == "short" else before(command, MAX_PARSE_CHARS + 1)
    assert not derive_exec_shape(text).parse_ok
    fires(call(text))


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


@pytest.mark.parametrize("links", [0, 1], ids=["no link", "a link"])
def test_a_long_path_word_reads_linearly(links, monkeypatch):
    def build(d: int) -> dict:
        word = "a/" * (45_000 // d)
        return ex("ln -s ~/.hermes h; " * links + f"echo x > {word}")

    _floor_linear(build, "a long path word", monkeypatch)


def test_a_long_run_of_symlinks_reads_linearly(monkeypatch):
    def build(d: int) -> dict:
        return ex("".join(f"ln -s ~/.hermes h{i}; echo a > h{i}/c; " for i in range(3000 // d)))

    _floor_linear(build, "symlinks", monkeypatch)
