"""Loosening the host's approvals behind enough options to pass the parse limit still takes the floor.

A command over `MAX_PARSE_CHARS` is not parsed. The approval-loosening CLI route then reads the
command's words split on whitespace, as the other guardrail CLI routes (plugin disable, gateway stop,
config entry) do, so padding a command with options (`openclaw -x y -x y … config set
tools.exec.security full`) does not take it past the floor.

It also reads the words as preparation's light split does, which keeps a quoted value whole
(`config set tools.exec '{"security": "full"}'`) and reads each command of a chain (`cd x && openclaw
…`) and of a `bash -c` script on its own. Every host CLI form the parsed route finds is checked
behind the same padding: the cases of `test_approval_loosening.py` and the pinned probes, each with
its expected tier.

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

#: A host CLI's name as a word, also the first of a quoted script: `openclaw`,
#: `/usr/local/bin/openclaw`, `openclaw@latest`, `hermes`, `hermes_cli.main` (after `python -m`).
_CLI_WORD = re.compile(
    r"""(?:(?<=[\s'"])|^)(?:\S*/)?(?:openclaw(?:@\S*)?|hermes(?:_cli\.main)?)(?=\s)""",
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
        "openclaw status; openclaw config set tools.exec.security full",
        "bash -lc 'openclaw config set tools.exec.ask off'",
    ],
    ids=["after cd", "second command", "shell script"],
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
    # The whitespace reading splits a quoted prompt, so a flag named inside one counts: the
    # stricter reading of a command the scan cannot parse.
    'hermes chat -q "explain what --yolo and approvals.mode off do"': "block",
    'hermes chat -q "what does --accept-hooks do"': "block",
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
