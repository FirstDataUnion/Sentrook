"""Turning Sentrook off behind enough options to pass the parse limit still takes the floor.

A command over `MAX_PARSE_CHARS` is not parsed (nor is one the parser reads with a syntax error). The
guardrail CLI routes (plugin disable or remove, the plugin's own commands, its config entry, gateway
stop) then read the command without the parser, as approval loosening does
(`test_approval_loosening_unparsed.py`):

- as the shell splits it: each simple command of a chain on its own (after `&&`, `;`, `&`, a newline),
  inside `{ }`, `if`/`for` bodies, `$( )` and backticks (also in double quotes) and `bash -c` scripts,
  read from its program after `nice`, `time -p`, `timeout 5`, `env`, `sudo`, `xargs`, `eval`, `!`.
  What this finds is blocked;
- split at blanks and operator characters: also what a command names in the middle (`echo openclaw
  plugins disable …`, `grep`, `man`) or inside quotes, heredocs or comments, which the shell may not
  run. What only this reading finds is asked (`guardrail.tampering_review`), never blocked.

Every guardrail CLI case of `test_aira_detectors.py` keeps its tier behind the same padding.

Paths and hosts are invented.
"""

from __future__ import annotations

import copy

import pytest
import test_aira_detectors as detector_tests
from linear_time import assert_linear
from test_aira_detectors import ex, floor_reasons, planir, run
from test_approval_loosening_unparsed import _CLI_WORD, FILL, SIZES, ZSH, padded

from sentrook.aira.exec_shape import MAX_PARSE_CHARS, derive_exec_shape
from sentrook.enums import Enforce

REVIEW = "guardrail.tampering_review"
BLOCKS = {
    "guardrail.plugin_disable",
    "guardrail.plugin_command",
    "guardrail.config_entry",
    "guardrail.gateway_stop",
}


def hx(command: str) -> dict:
    return ex(command, platform="hermes")


def _call(command: str) -> dict:
    return hx(command) if "hermes" in command.split("\n")[0] else ex(command)


def tier(raw: dict) -> str:
    """`block: <reasons>`, `review` or `quiet`."""
    _, env = run(raw)
    reasons = set(floor_reasons(env))
    blocked = sorted(reasons & BLOCKS)
    if blocked:
        for f in env.floors:
            if f.reason in BLOCKS:
                assert f.enforce is Enforce.BLOCK and f.min_risk == 1.0
        return "block: " + ", ".join(blocked)
    if REVIEW in reasons:
        (f,) = [f for f in env.floors if f.reason == REVIEW]
        assert f.enforce is Enforce.REVIEW and f.min_risk < 1.0
        return "review"
    return "quiet"


# --------------------------------------------------------------------------- must fire

D = "openclaw plugins disable sentrook-openclaw"
FIRES = [
    ("true && " + D, "plugin_disable"),
    ("true; " + D, "plugin_disable"),
    ("true;" + D, "plugin_disable"),
    ("true & " + D, "plugin_disable"),
    ("cd /tmp\n" + D, "plugin_disable"),
    ("{ " + D + "; }", "plugin_disable"),
    ("if true; then " + D + "; fi", "plugin_disable"),
    ("bash -c '" + D + "'", "plugin_disable"),
    ("bash -lc 'true; " + D + "'", "plugin_disable"),
    ('bash -c "cd ~ && ' + D + '"', "plugin_disable"),
    ("echo $(" + D + ")", "plugin_disable"),
    ("echo `" + D + "`", "plugin_disable"),
    ('echo "$(' + D + ')"', "plugin_disable"),
    ("nice " + D, "plugin_disable"),
    ("time -p " + D, "plugin_disable"),
    ("timeout 5 " + D, "plugin_disable"),
    ("env A=1 " + D, "plugin_disable"),
    ("sudo " + D, "plugin_disable"),
    ("xargs " + D + " <<< x", "plugin_disable"),
    ("eval " + D, "plugin_disable"),
    ("! " + D, "plugin_disable"),
    ("true && npx -y openclaw@latest plugins remove sentrook-openclaw", "plugin_disable"),
    ("true && hermes plugins disable sentrook", "plugin_disable"),
    ("cd ~ && uv run hermes plugins disable sentrook", "plugin_disable"),
    ("true && openclaw gateway stop", "gateway_stop"),
    ("true; hermes gateway stop", "gateway_stop"),
    ("true && openclaw config set plugins.entries.sentrook-openclaw.enabled false", "config_entry"),
    ("{ hermes config set plugins.disabled sentrook; }", "config_entry"),
    # Wrapper options and their values, then the program.
    ("timeout -s KILL 5 " + D, "plugin_disable"),
    ("timeout --signal=KILL 5 " + D, "plugin_disable"),
    ("timeout -k 1 5 " + D, "plugin_disable"),
    ("nice -n 10 " + D, "plugin_disable"),
    ("stdbuf -oL " + D, "plugin_disable"),
    ("sudo -u root " + D, "plugin_disable"),
    ("sudo -E " + D, "plugin_disable"),
    ("env -u HOME " + D, "plugin_disable"),
    ("env -i " + D, "plugin_disable"),
    # A shell script behind wrappers.
    *(
        (prefix + " bash -c '" + D + "'", "plugin_disable")
        for prefix in (
            "sudo -E",
            "timeout 5",
            "env -i",
            "nice -n 5",
            "nohup",
            "xargs -0",
            "time -p",
        )
    ),
    ("true && openclaw sentrook snooze 1h", "plugin_command"),
    ("bash -c 'hermes sentrook grant host example.test'", "plugin_command"),
]

#: Forms the parsed route does not read yet (it takes `eval`'s words as arguments, and `env -u`'s
#: value as the program): the unparsed reading blocks them.
PARSED_GAPS = {"eval " + D, "env -u HOME " + D}


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("command, reason", FIRES, ids=[c for c, _ in FIRES])
def test_a_padded_guardrail_command_in_a_chain_or_script_takes_the_floor(command, reason, size):
    if command not in PARSED_GAPS:
        assert tier(_call(command)) == f"block: guardrail.{reason}", "the short command"
    text = padded(command, size)
    assert not derive_exec_shape(text).parse_ok
    assert tier(_call(text)) == f"block: guardrail.{reason}"


@pytest.mark.parametrize("command, reason", FIRES, ids=[c for c, _ in FIRES])
def test_a_guardrail_command_with_a_syntax_error_takes_the_floor(command, reason):
    text = command + ZSH
    assert not derive_exec_shape(text).parse_ok
    assert tier(_call(text)) == f"block: guardrail.{reason}"


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "command",
    [
        "openclaw plugins list",
        "true && openclaw plugins list",
        "true && openclaw plugins enable sentrook-openclaw",
        "true && openclaw plugins disable other-plugin",
        "true && hermes gateway restart",
        "true && hermes sentrook status",
        "true && openclaw config get plugins.entries.sentrook-openclaw.enabled",
    ],
)
def test_padded_reads_and_other_commands_stay_quiet(command, size):
    assert tier(_call(padded(command, size))) == "quiet"


#: A guardrail command named, not run: in the middle of a command (an argument, not the program),
#: or inside quotes, a heredoc or a comment. Quiet when parsed; asked, never blocked, when not.
NAMED_ONLY = [
    "echo openclaw plugins disable sentrook-openclaw",
    "echo note: hermes gateway stop is refused",
    "grep -c openclaw plugins disable sentrook-openclaw notes.md",
    "man openclaw plugins disable sentrook-openclaw",
    "git log --grep openclaw plugins disable sentrook-openclaw",
    "cat > docs/guide.md <<'EOF'\n{F}\nopenclaw plugins disable sentrook-openclaw\nEOF",
    'git commit -m "Docs: {F}\nopenclaw plugins disable sentrook-openclaw is refused"',
    'hermes chat -q "{F} run hermes plugins disable sentrook"',
    "hermes -q 'plugins disable sentrook {F}'",
    "ls\n# {F} openclaw gateway stop\nls",
    "bash -c 'echo {F} hermes plugins disable sentrook'",
]


def _named(command: str, length: str) -> str:
    if "{F}" not in command:
        return command if length == "short" else padded(command, MAX_PARSE_CHARS + 1)
    if length == "padded":
        return command.format(F=FILL)
    return command.format(F="short") + ("" if length == "short" else ZSH)


@pytest.mark.parametrize("command", NAMED_ONLY)
def test_a_guardrail_command_named_only_is_quiet_when_parsed(command):
    text = _named(command, "short")
    assert derive_exec_shape(text).parse_ok
    assert tier(_call(text)) == "quiet"


@pytest.mark.parametrize("length", ["padded", "syntax error"])
@pytest.mark.parametrize("command", NAMED_ONLY)
def test_a_guardrail_command_named_only_is_asked_when_not_parsed(command, length):
    text = _named(command, length)
    assert not derive_exec_shape(text).parse_ok
    assert tier(_call(text)) == "review"


def xc(code: str) -> dict:
    return planir("execute_code", "exec", {"code": code}, platform="hermes")


@pytest.mark.parametrize(
    "code",
    [
        "open('notes.md', 'w').write('```bash\\nhermes plugins disable sentrook\\n```\\n')",
        "print('run: hermes plugins disable sentrook')",
        "# hermes plugins disable sentrook turns the scan off\nx = 1",
        '"""Do not run `hermes gateway stop` from a job."""\nx = 1',
    ],
    ids=["markdown fence", "print", "comment", "docstring"],
)
@pytest.mark.parametrize("size", ["short", "padded"])
def test_inline_code_that_names_a_guardrail_command_stays_quiet(code, size):
    """Inline interpreter code is not shell: it is not read with the unparsed shell readings."""
    if size == "padded":
        code = "x = 0\n" * 3000 + code
    assert tier(xc(code)) == "quiet"


#: A heredoc with no closing line: the shell runs nothing of its body.
UNCLOSED = "cat > g.md <<'EOF'\n# Notes\n" + D + "\n"


@pytest.mark.parametrize("length", ["short", "padded"])
def test_the_body_of_a_heredoc_with_no_closing_line_is_asked_not_blocked(length):
    text = UNCLOSED if length == "short" else UNCLOSED.replace("# Notes", "# " + FILL)
    assert tier(ex(text)) in ("quiet", "review")
    if not derive_exec_shape(text).parse_ok:
        assert tier(ex(text)) == "review"


@pytest.mark.parametrize(
    "command",
    [
        "bash <<EOF\n" + D + "\n",
        "sudo bash <<EOF\n" + D + "\n",
        "echo start\nbash -s <<'EOF'\n" + D + "\nhermes gateway stop\n",
    ],
)
@pytest.mark.parametrize("length", ["short", "padded"])
def test_a_shell_fed_a_heredoc_with_no_closing_line_runs_it(command, length):
    """A shell reading its commands from a heredoc runs the body even with no closing line."""
    text = command if length == "short" else padded(command, MAX_PARSE_CHARS + 1)
    assert not derive_exec_shape(text).parse_ok
    assert tier(_call(text)).startswith("block: ")
    assert "guardrail.plugin_disable" in tier(_call(text))


def test_a_real_command_and_a_named_one_take_the_block_alone():
    text = padded("echo openclaw plugins disable x; openclaw gateway stop", MAX_PARSE_CHARS + 1)
    assert tier(ex(text)) == "block: guardrail.gateway_stop"
    text = padded("openclaw plugins disable sentrook-openclaw; echo " + D, MAX_PARSE_CHARS + 1)
    _, env = run(ex(text))
    assert set(floor_reasons(env)) == {"guardrail.plugin_disable"}


# --------------------------------------------------------------------------- every parsed form

_PARSED_TESTS = [
    "test_c4star_exec_forms_take_the_floor",
    "test_c4star_cli_forms_survive_global_flags_and_launchers",
    "test_c4star_cli_reads_and_other_commands_stay_silent",
    "test_c4star_plugin_commands_take_the_floor",
    "test_c4star_plugin_read_commands_stay_silent",
]

#: Cases whose tier changes when the command is not parsed, with why: the whitespace reading splits
#: a quoted prompt or script, so a guardrail command named inside one is asked.
UNPARSED_TIER = {
    'hermes -q "plugins disable sentrook: what does that do?"': "review",
    'hermes chat -q "run hermes plugins disable sentrook"': "review",
    "bash -c 'echo hermes plugins disable sentrook'": "review",
    'hermes chat -q "hermes sentrook grant host example.test"': "review",
    # The CLI named as a script's argument, not run by it.
    "bash script.sh hermes plugins disable sentrook": "review",
    "bash run.sh -c 'openclaw gateway stop'": "review",
}


def _parsed_cases() -> list:
    cases, seen = [], set()
    for name in _PARSED_TESTS:
        fn = getattr(detector_tests, name)
        (mark,) = [m for m in fn.pytestmark if m.name == "parametrize"]
        for k, value in enumerate(mark.args[1]):
            raw = value[0] if isinstance(value, tuple) else value
            command = raw["pending_call"]["arguments"].get("command")
            if not isinstance(command, str) or not _CLI_WORD.search(command):
                continue
            if command in seen:
                continue
            seen.add(command)
            cases.append(pytest.param(raw, id=f"{name}[{k}]"))
    return cases


PARSED_CASES = _parsed_cases()


def test_the_parsed_cases_are_found():
    tiers = {tier(p.values[0]).split(":")[0] for p in PARSED_CASES}
    assert len(PARSED_CASES) > 80 and tiers == {"block", "quiet"}, len(PARSED_CASES)


@pytest.mark.parametrize("raw", PARSED_CASES)
def test_every_parsed_guardrail_cli_form_keeps_its_tier_unparsed(raw):
    raw = copy.deepcopy(raw)  # the detector tests' own case, unchanged for them
    expect = tier(raw)
    args = raw["pending_call"]["arguments"]
    expect = UNPARSED_TIER.get(args["command"], expect)
    args["command"] = padded(args["command"], MAX_PARSE_CHARS + 1)
    assert tier(raw) == expect


# --------------------------------------------------------------------------- linear


@pytest.mark.parametrize(
    "unit",
    [
        "true && openclaw -x y plugins disable sentrook-openclaw; ",
        "echo openclaw plugins disable sentrook-openclaw ",
        "{ hermes -p plugins plugins ",
        "bash -c 'openclaw gateway stop'; ",
        '"$(openclaw sentrook ',
    ],
)
def test_the_unparsed_guardrail_reading_grows_linearly(unit):
    def build(d: int) -> dict:
        return ex(unit * (95_000 // len(unit) // d))

    assert_linear(lambda d: run(build(d)), what=unit)
