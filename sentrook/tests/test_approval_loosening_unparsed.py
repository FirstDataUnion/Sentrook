"""Loosening the host's approvals behind enough options to pass the parse limit still takes the floor.

A command over `MAX_PARSE_CHARS` is not parsed (nor is one the parser reads with a syntax error, such
as zsh's `${(j:,:)arr}`). The approval-loosening CLI route then reads the command without the parser,
so padding a command with options (`openclaw -x y -x y … config set tools.exec.security full`) does
not take it past the floor:

- as the shell splits it: words after quote removal (a quoted value such as `'{"security": "full"}'`
  stays one word), each simple command of a chain on its own, `$(…)` and backticks (also inside
  double quotes) and `bash -c` scripts read as commands, comments and heredoc bodies left out, and
  arithmetic and parameters kept whole (a `<<` in them is no heredoc). A command is read from its
  program, after `nice`, `time -p`, `eval`, `{`, `!` or `then`. What this finds is blocked;
- split at blanks and operator characters: also what a command names in the middle (`echo run
  openclaw …`) or inside quotes, heredocs or comments (a prompt, a commit message, a document),
  which the shell may not run. What only this reading finds is asked, not blocked.

Every host CLI form the parsed route finds is checked behind the same padding: the cases of
`test_approval_loosening.py` and the pinned probes, each with its expected tier.

Paths and hosts are invented.
"""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import pytest
import test_approval_loosening as parsed
from test_aira_detectors import ex, floor_reasons, run
from test_approval_loosening import REASON, REVIEW_REASON, fires, h_ex, reviews, stays_silent

from sentrook.aira.exec_shape import MAX_PARSE_CHARS, derive_exec_shape
from sentrook.planir.bounds import MAX_CALL_CHARS

#: Just over the parse limit, well over it, and near the bound on what a call analyses.
SIZES = [MAX_PARSE_CHARS + 1, 24_000, 95_000]

#: A host CLI's name as a word, also the first of a quoted script or a command substitution:
#: `openclaw`, `/usr/local/bin/openclaw`, `openclaw@latest`, `hermes`, `hermes_cli.main` (after `python -m`).
_CLI_WORD = re.compile(
    r"""(?:(?<=[\s'"`({!&;|])|^)(?:\S*/)?(?:openclaw(?:@\S*)?|hermes(?:_cli\.main)?)(?=\s)""",
    re.IGNORECASE,
)
_UNIT = " -x y"


def padded(command: str, size: int) -> str:
    """`command` with options after its first host CLI word, `size` characters long."""
    m = _CLI_WORD.search(command)
    assert m is not None, command
    room = size - len(command)
    n, rest = divmod(room, len(_UNIT))
    # One longer option takes up what the units leave, so the length is exact.
    pad = (" -" + "z" * (rest + len(_UNIT) - 2) if rest else "") + _UNIT * (n - (1 if rest else 0))
    out = command[: m.end()] + pad + command[m.end() :]
    assert len(out) == size and size > MAX_PARSE_CHARS and size < MAX_CALL_CHARS
    return out


def oc(size: int, rest: str) -> dict:
    return ex(padded("openclaw " + rest, size))


def hc(size: int, rest: str) -> dict:
    return h_ex(padded("hermes " + rest, size))


# --------------------------------------------------------------------------- must fire


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "rest",
    [
        "config set tools.exec.security full",
        "config set tools.exec.ask off",
        "config unset tools.exec.security",
        "exec-policy preset yolo",
        "exec-policy set --security full --ask off",
        "exec-policy set --ask-fallback full",
        'approvals allowlist add "*"',
        'approvals allowlist add --agent main "**"',
        'config set tools.exec \'{"security": "full"}\' --strict-json --merge',
    ],
)
def test_openclaw_loosening_behind_padding_takes_the_floor(rest, size):
    fires(oc(size, rest))


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "command",
    [
        "cd /tmp && openclaw config set tools.exec.security full",
        "cd /tmp &&openclaw config set tools.exec.security full",
        "cd /tmp\nopenclaw config set tools.exec.security full",
        "openclaw status; openclaw config set tools.exec.security full",
        "true & openclaw config set tools.exec.security full",
        "{ openclaw config set tools.exec.security full; }",
        "if true; then openclaw config set tools.exec.security full; fi",
        "for i in 1; do openclaw config set tools.exec.security full; done",
        "echo $(openclaw config set tools.exec.security full)",
        "echo `openclaw config set tools.exec.security full`",
        "! openclaw config set tools.exec.security full",
        "nice openclaw config set tools.exec.security full",
        "time -p openclaw config set tools.exec.security full",
        "eval openclaw config set tools.exec.security full",
        "xargs openclaw config set tools.exec.security <<< full",
        "FOO='a b' openclaw config set tools.exec.security full",
        "cd /tmp && FOO='a b' openclaw config set tools.exec.security full",
        "cd /tmp && openclaw -x a#b config set tools.exec.security full",
        "cd /tmp && openclaw config set tools.exec.security full >/dev/null 2>&1",
        "cd /tmp && openclaw config set tools.exec.security 'full' # it's fine",
        "openclaw config set tools.exec.security $'full'",
        "bash -lc 'openclaw config set tools.exec.ask off'",
        "bash -lc 'true; openclaw config set tools.exec.ask off'",
        'bash -lc "true; openclaw config set tools.exec.ask off"',
        "cat > notes.md <<'EOF'\nnot run\nEOF\nopenclaw config set tools.exec.security full",
        "function f { openclaw config set tools.exec.security full; }; f",
        'echo "$(openclaw config set tools.exec.security full)"',
        'echo "`openclaw config set tools.exec.security full`"',
        'x="`openclaw config set tools.exec.security full`"',
        'echo "`openclaw config unset tools.exec.security`"',
        'echo "$(true;openclaw config set tools.exec.ask off)"',
        'echo "`true;openclaw config set tools.exec.security full`"',
        'echo "Run `openclaw config set tools.exec.security full` to see"',
    ],
    ids=[
        "after cd",
        "after && unspaced",
        "after a newline",
        "second command",
        "after a background job",
        "brace group",
        "if then",
        "for do",
        "command substitution",
        "backticks",
        "negated",
        "nice",
        "time -p",
        "eval",
        "xargs with a here-string",
        "quoted assignment before",
        "quoted assignment after cd",
        "hash inside an option",
        "redirects after",
        "comment after",
        "ansi-c quoted value",
        "shell script",
        "second command of a script",
        "second command of a double-quoted script",
        "after a heredoc",
        "function body",
        "substitution in double quotes",
        "backticks in double quotes",
        "backticks in a quoted assignment",
        "unset in backticks in double quotes",
        "second command of a substitution in double quotes",
        "second command of backticks in double quotes",
        "backticks inside a double-quoted sentence",
    ],
)
def test_a_padded_loosening_in_a_chain_or_script_takes_the_floor(command, size):
    fires(ex(padded(command, size)))


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "rest",
    [
        "config set approvals.mode off",
        "config set approvals.cron_mode approve",
        "config set command_allowlist '[\"*\"]'",
        'chat --yolo -q "tidy the repo"',
    ],
)
def test_hermes_loosening_behind_padding_takes_the_floor(rest, size):
    fires(hc(size, rest))


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "command",
    [
        'echo "`hermes config set approvals.mode off`"',
        'echo "$(hermes config set approvals.mode off)"',
        'x="`hermes chat --yolo`"',
    ],
)
def test_a_padded_hermes_loosening_in_a_substitution_takes_the_floor(command, size):
    fires(h_ex(padded(command, size)))


@pytest.mark.parametrize("size", SIZES)
def test_a_patch_file_behind_padding_gets_the_review_tier(size):
    reviews(oc(size, "config patch --file ./openclaw.patch.json5"))


def test_the_padded_command_is_not_parsed():
    """The cases above are past the parse limit: the route under test is the unparsed one."""
    command = padded("openclaw config set tools.exec.security full", MAX_PARSE_CHARS + 1)
    assert not derive_exec_shape(command).parse_ok
    assert derive_exec_shape("openclaw config set tools.exec.security full").parse_ok


# --------------------------------------------------------------------------- must stay silent


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize(
    "raw",
    [
        # Reads.
        lambda size: oc(size, "config get tools.exec.security"),
        lambda size: oc(size, "status"),
        lambda size: oc(size, "approvals get"),
        lambda size: hc(size, "config show"),
        lambda size: hc(size, "status"),
        # Tightening.
        lambda size: oc(size, "config set tools.exec.security allowlist"),
        lambda size: oc(size, "config set tools.exec.ask always"),
        lambda size: oc(size, "exec-policy preset cautious"),
        lambda size: oc(size, "exec-policy set --ask-fallback deny --security allowlist"),
        lambda size: oc(size, 'approvals allowlist add "/usr/bin/uptime"'),
        lambda size: hc(size, "config set approvals.mode manual"),
        lambda size: hc(size, "config set approvals.cron_mode deny"),
        # Unrelated keys, and a dry run.
        lambda size: oc(size, "config set tools.exec.timeoutSec 1800"),
        lambda size: oc(size, "config patch --file ./openclaw.patch.json5 --dry-run"),
    ],
    ids=[
        "config get",
        "openclaw status",
        "approvals get",
        "hermes config show",
        "hermes status",
        "security allowlist",
        "ask always",
        "preset cautious",
        "exec-policy tighten",
        "narrow allowlist add",
        "hermes mode manual",
        "hermes cron deny",
        "unrelated key",
        "patch dry run",
    ],
)
def test_reads_and_tightening_behind_padding_stay_silent(raw, size):
    stays_silent(raw(size))


#: Filler that takes a command past the parse limit.
FILL = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 300
#: A zsh form the parser reads with a syntax error: a short command with it is not parsed either.
ZSH = "\nprint -r -- ${(j:,:)arr}"

#: Commands that only name a loosening (in a document, a commit message, a prompt, a script's
#: string): asked when the command is not parsed, never blocked; quiet when it is.
NAMED_ONLY = [
    (
        "heredoc document",
        "cat > docs/guide.md <<'EOF'\n# Guide\n{F}\nTo turn approvals off:\n\n"
        "openclaw config set tools.exec.security full\n\nDon't.\nEOF",
    ),
    (
        "heredoc document, mid-line",
        "cat > docs/guide.md <<'EOF'\n{F}\nRun `openclaw config set tools.exec.ask off` to stop "
        "prompts.\nEOF",
    ),
    (
        "commit message",
        'git commit -m "Docs: {F}\nopenclaw config set tools.exec.ask off is refused"',
    ),
    ("echo to a file", 'echo "{F}; openclaw config set tools.exec.security full" > notes.txt'),
    ("hermes prompt", 'hermes chat -q "{F}; then hermes config set approvals.mode off"'),
    ("hermes prompt naming --yolo", 'hermes chat -q "{F} never pass --yolo"'),
    ("hermes prompt naming --accept-hooks", 'hermes chat -q "{F} what does --accept-hooks do"'),
    (
        "python heredoc string",
        "python3 - <<'PY'\nprint('''{F}\nopenclaw exec-policy preset yolo\n''')\nPY",
    ),
    (
        "issue body",
        "gh issue create --title x --body \"{F}\n\nSteps: openclaw approvals allowlist add '*'\"",
    ),
    ("comment", "ls\n# {F} openclaw config set tools.exec.security full\nls"),
]


@pytest.mark.parametrize("name, command", NAMED_ONLY, ids=[n for n, _ in NAMED_ONLY])
def test_a_loosening_named_only_in_quotes_is_quiet_when_parsed(name, command):
    short = command.format(F="short")
    assert derive_exec_shape(short).parse_ok
    stays_silent(ex(short))


@pytest.mark.parametrize(
    "length", ["padded", "short with a syntax error"], ids=["padded", "syntax error"]
)
@pytest.mark.parametrize("name, command", NAMED_ONLY, ids=[n for n, _ in NAMED_ONLY])
def test_a_loosening_named_only_in_quotes_is_asked_when_not_parsed(name, command, length):
    text = command.format(F=FILL) if length == "padded" else command.format(F="short") + ZSH
    assert not derive_exec_shape(text).parse_ok
    reviews(ex(text))


#: A host CLI named in the middle of a command (an argument, not the program): asked when the
#: command is not parsed, quiet when it is.
MENTIONS = [
    "echo to loosen run openclaw config set tools.exec.security full >> notes.md",
    "echo note: openclaw config set tools.exec.security full is refused",
    "printf '%s\\n' x | grep -c openclaw config set tools.exec.security full",
    "echo Do not run openclaw config set tools.exec.ask off without asking",
    "echo hermes config set approvals.mode off >> notes.md",
    "man openclaw config set tools.exec.security full",
    "git log --grep openclaw config set tools.exec.security full",
    "sed -e 's/a/b/' file ; echo note: openclaw config set tools.exec.security full",
]


@pytest.mark.parametrize("command", MENTIONS)
def test_a_cli_named_mid_command_is_quiet_when_parsed(command):
    assert derive_exec_shape(command).parse_ok
    stays_silent(ex(command))


@pytest.mark.parametrize("length", ["padded", "syntax error"])
@pytest.mark.parametrize("command", MENTIONS)
def test_a_cli_named_mid_command_is_asked_when_not_parsed(command, length):
    text = padded(command, MAX_PARSE_CHARS + 1) if length == "padded" else command + ZSH
    assert not derive_exec_shape(text).parse_ok
    reviews(ex(text))


def test_a_short_command_with_a_syntax_error_still_blocks_a_real_loosening():
    command = "openclaw config set tools.exec.security full" + ZSH
    assert not derive_exec_shape(command).parse_ok
    fires(ex(command))


@pytest.mark.parametrize(
    "command",
    [
        # Arithmetic is no heredoc; a heredoc with no closing line is no body.
        "x=$((1<<EOF))\nopenclaw config set tools.exec.security full\nEOF",
        "x=$(( 1 << 2 ))\nopenclaw config set tools.exec.security full\n2",
        "x=$(( 1 << 2 ))\ntrue;openclaw config set tools.exec.security full\n2",
        "x=$(( 1 << 2 ))\ntrue&&openclaw config set tools.exec.security full\n2",
        "(( y = 1 << EOF ))\nopenclaw config set tools.exec.security full\nEOF",
        "(( x <<= y ))\nopenclaw config set tools.exec.security full\ny",
        "echo $[ 1 << 2 ]\nopenclaw config set tools.exec.security full\n2",
        "echo $[ 1 << 2 ]\n:|openclaw config set tools.exec.security full\n2",
        "echo ${x:- <<EOF }\nopenclaw config set tools.exec.security full\nEOF",
        "echo ${x:- <<EOF }\ntrue;openclaw config set tools.exec.security full\nEOF",
        "cat <<EOF\nopenclaw config set tools.exec.security full",
        'echo "<<EOF"\nopenclaw config set tools.exec.security full\nEOF',
        "echo '<<EOF'\nopenclaw config set tools.exec.security full\nEOF",
        'echo "$(echo \'"\')" ;openclaw config set tools.exec.security full',
        'echo "$(echo \'"\')" &&openclaw config set tools.exec.security full',
        'echo "$(echo # "\n)";openclaw config set tools.exec.security full',
    ],
    ids=[
        "arithmetic shift",
        "arithmetic shift by a number",
        "arithmetic shift, then after ;",
        "arithmetic shift, then after &&",
        "arithmetic command",
        "arithmetic shift-assign",
        "old arithmetic",
        "old arithmetic, then after a pipe",
        "parameter default",
        "parameter default, then after ;",
        "unclosed heredoc",
        "double-quoted heredoc marker",
        "single-quoted heredoc marker",
        "quote inside a substitution",
        "quote inside a substitution, then &&",
        "comment inside a substitution",
    ],
)
def test_a_command_after_a_shift_or_quote_is_not_taken_for_a_heredoc_body(command):
    """No heredoc and no quote is open where the command starts, so it is blocked (a misread could
    only move it to the whitespace reading, the review tier)."""
    fires(ex(padded(command, MAX_PARSE_CHARS + 1)))


# --------------------------------------------------------------------------- every parsed form


def _parametrized_cases() -> list[tuple[str, str, dict]]:
    """(expected tier, id, call) of the one-argument parametrised tests in
    `test_approval_loosening.py`, the tier read from the helper each test calls."""
    out: list[tuple[str, str, dict]] = []
    for name, fn in inspect.getmembers(parsed, inspect.isfunction):
        if not name.startswith("test_"):
            continue
        source = inspect.getsource(fn)
        body = source[source.index("def ") :]
        expect = next(
            (t for t, call in (("review", "reviews("), ("quiet", "stays_silent(")) if call in body),
            "block" if "fires(" in body else None,
        )
        for mark in getattr(fn, "pytestmark", []):
            if mark.name != "parametrize" or "," in mark.args[0]:
                continue
            ids = mark.kwargs.get("ids") or [None] * len(mark.args[1])
            for k, (value, case_id) in enumerate(zip(mark.args[1], ids, strict=True)):
                if isinstance(value, str):
                    raw = h_ex(value) if "h_ex(" in body else ex(value) if "ex(" in body else None
                else:
                    raw = value
                if expect and isinstance(raw, dict):
                    out.append((expect, f"{name}[{case_id or k}]", raw))
    return out


def _probe_cases() -> list[tuple[str, str, dict]]:
    probes = json.loads(
        (Path(__file__).parent / "fixtures" / "approval_loosening_probes.json").read_text()
    )["cases"]
    out = []
    for case in probes:
        kind, args, kw = case["call"]
        if kind not in ("ex", "hx") or set(case) - {"name", "call", "expect"}:
            continue
        raw = ex(args[0], **kw) if kind == "ex" else h_ex(args[0])
        out.append((case["expect"], f"probe {case['name']}", raw))
    return out


#: Cases whose tier changes when the command is not parsed, with why.
UNPARSED_TIER = {
    # The whitespace reading splits a quoted prompt or entry, so what is named inside one is
    # asked: a command the scan cannot parse is held, not blocked.
    'hermes chat -q "explain what --yolo and approvals.mode off do"': "review",
    'hermes chat -q "what does --accept-hooks do"': "review",
    'openclaw approvals allowlist add "/usr/bin/python3 /opt/tools/report.py"': "review",
}


def _cli_cases() -> list:
    cases = []
    seen: set[tuple[str, str]] = set()
    for expect, case_id, raw in _parametrized_cases() + _probe_cases():
        call = raw["pending_call"]
        command = call["arguments"].get("command")
        if call["tool"] != "exec" or not isinstance(command, str) or not _CLI_WORD.search(command):
            continue
        key = (command, raw["host"]["platform"])
        if key in seen:
            continue
        seen.add(key)
        cases.append(pytest.param(expect, raw, id=case_id))
    return cases


CLI_CASES = _cli_cases()


def _tier(raw: dict) -> str:
    _, env = run(raw)
    reasons = floor_reasons(env)
    return "block" if REASON in reasons else "review" if REVIEW_REASON in reasons else "quiet"


def test_the_parsed_cases_are_found():
    tiers = {p.values[0] for p in CLI_CASES}
    assert len(CLI_CASES) > 60 and tiers == {"block", "review", "quiet"}, len(CLI_CASES)


@pytest.mark.parametrize("expect, raw", CLI_CASES)
def test_every_parsed_cli_form_keeps_its_tier_unparsed(expect, raw):
    assert _tier(raw) == expect, "the parsed case itself"
    args = raw["pending_call"]["arguments"]
    expect = UNPARSED_TIER.get(args["command"], expect)
    args["command"] = padded(args["command"], MAX_PARSE_CHARS + 1)
    assert _tier(raw) == expect
