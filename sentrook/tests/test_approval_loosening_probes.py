"""Pinned probe cases for the approval-loosening floor.

Every case in `fixtures/approval_loosening_probes.json` carries its expected tier (`block`,
`review` or `quiet`), so a later rewrite of the detector cannot move one silently. The large
inputs below are built in code; for each, the floor's own analysis must stay well under a
second whatever the rest of the scan costs.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from test_aira_detectors import ex, floor_reasons, planir, run

from sentrook.aira import detectors
from sentrook.aira.exec_shape import derive_exec_shape
from sentrook.aira.lists import load_lists

BLOCK = "guardrail.approval_loosening"
REVIEW = BLOCK + "_review"
PROBES = json.loads(
    (Path(__file__).parent / "fixtures" / "approval_loosening_probes.json").read_text()
)["cases"]

OC = "~/.openclaw/openclaw.json"
HC = "~/.hermes/config.yaml"


def build(kind: str, args: list[Any], kw: dict[str, Any]) -> dict:
    if kind == "planir":
        return planir(*args, **kw)
    if kind == "ex":
        return ex(*args, **kw)
    if kind == "hx":
        return ex(args[0], platform="hermes")
    if kind == "hw":
        return planir(
            "write_file", "file_write", {"path": args[0], "content": args[1]}, platform="hermes"
        )
    if kind == "hp":
        return planir(
            "patch",
            "file_edit",
            {"path": args[0], "old_string": args[1], "new_string": args[2]},
            platform="hermes",
        )
    if kind == "ow":
        return planir("write", "file_write", {"path": args[0], "content": args[1]})
    if kind == "oe":
        return planir(
            "edit",
            "file_edit",
            {"path": args[0], "edits": [{"oldText": args[1], "newText": args[2]}]},
        )
    if kind == "xc":
        return planir("execute_code", "exec", {"code": args[0]}, platform="hermes")
    raise ValueError(kind)


def tier(raw: dict) -> str:
    _, env = run(raw)
    reasons = floor_reasons(env)
    return "block" if BLOCK in reasons else "review" if REVIEW in reasons else "quiet"


@pytest.mark.parametrize("case", PROBES, ids=[c["name"] for c in PROBES])
def test_probe_keeps_its_tier(case):
    raw = build(*case["call"])
    if "workspace_root" in case:
        raw["host"]["workspace_root"] = case["workspace_root"]
    if "cwd" in case:
        raw["pending_call"]["arguments"]["cwd"] = case["cwd"]
    if "pad" in case:
        args = raw["pending_call"]["arguments"]
        args["command"] = padded_before(args["command"], case["pad"])
    assert tier(raw) == case["expect"]


def padded_before(command: str, size: int) -> str:
    """`command` after a line of harmless padding, `size` characters long: past the parse limit, so
    the command is read without the parser."""
    room = size - len(command) - len("true\n")
    out = "true" + " -x" * (room // 3) + " " * (room % 3) + "\n" + command
    assert len(out) == size and not derive_exec_shape(out).parse_ok
    return out


def test_probe_names_are_unique():
    assert len({c["name"] for c in PROBES}) == len(PROBES)


def test_a_case_insensitive_file_system_matches_any_case():
    raw = build("ow", ["~/.OpenClaw/openclaw.json", '{"tools":{"exec":{"security":"full"}}}'], {})
    assert tier(raw) == "quiet"
    raw["host"]["os"] = "macos"
    assert tier(raw) == "block"


def _xc(code: str) -> dict:
    return build("xc", [code], {})


def _ow(path: str, content: str) -> dict:
    return build("ow", [path, content], {})


def _hw(path: str, content: str) -> dict:
    return build("hw", [path, content], {})


LARGE: list[tuple[str, Callable[[], dict], str]] = [
    (
        "big json",
        lambda: _ow(
            OC,
            "{"
            + ",".join(f'"k{i}":{{"a":1}}' for i in range(20000))
            + ',"tools":{"exec":{"security":"full"}}}',
        ),
        "block",
    ),
    ("many yaml", lambda: _hw(HC, "approvals:\n" + "  mode: off\n" * 3000), "block"),
    (
        "list of exec objects",
        lambda: _ow(OC, "[" + ",".join(['{"x":{"ask":"off"}}'] * 4000) + "]"),
        "quiet",
    ),
    ("code assignment spaces", lambda: ex('python3 -c "x=a' + " " * 20000 + 'b"'), "quiet"),
    ("execute_code assignment spaces", lambda: _xc("x = 1" + " " * 20000 + "#\n"), "quiet"),
    (
        "unclosed allowlist lists",
        lambda: _ow("~/.openclaw/x.json", "allowlist: [" * 30000),
        "quiet",
    ),
    ("deep exec keys", lambda: _ow(OC, "{exec:" * 5000 + '"mode":"full",' * 5000), "block"),
    ("deep json list", lambda: _ow(OC, "[" * 200000), "quiet"),
    ("deep json object", lambda: _ow(OC, '{"a":' * 100000), "quiet"),
    ("binary-ish", lambda: _ow(OC, bytes(range(256)).decode("latin-1") * 200), "quiet"),
    (
        "yaml 50k lines",
        lambda: _hw(HC, "".join(f"k{i}:\n  mode: off\n" for i in range(50000))),
        "quiet",
    ),
    (
        "yaml deep indent",
        lambda: _hw(
            HC, "".join(" " * i + f"k{i}:\n" for i in range(3000)) + " " * 3000 + "mode: off\n"
        ),
        "quiet",
    ),
    (
        "many cd",
        lambda: ex("; ".join(['cd ~/.openclaw && echo \'{"ask":"off"}\' > a.json'] * 2000)),
        "quiet",
    ),
    (
        "heredoc to config",
        lambda: ex("cat > ~/.openclaw/openclaw.json <<'EOF'\n" + '{"k":"v"},\n' * 50000 + "EOF"),
        "quiet",
    ),
    (
        "heredoc to scratch",
        lambda: ex(
            "cat > /tmp/x.json <<'EOF'\n"
            + 'mode: full ask: off s/a/b/ open(x,"w")\n' * 20000
            + "EOF"
        ),
        "quiet",
    ),
    ("many open calls", lambda: _xc("open(" * 20000), "quiet"),
    ("many nested open calls", lambda: _xc("open(a(" * 5000 + "))"), "quiet"),
    (
        "sed many substitutions",
        lambda: ex("sed -i " + " s@a" * 20000 + " ~/.openclaw/openclaw.json"),
        "quiet",
    ),
    (
        "perl many substitutions",
        lambda: ex("perl -pi -e '" + "s/x/" * 20000 + "' ~/.openclaw/openclaw.json"),
        "quiet",
    ),
    (
        "huge patch",
        lambda: planir(
            "apply_patch",
            "file_edit",
            {
                "input": "*** Begin Patch\n*** Update File: /home/me/.openclaw/openclaw.json\n"
                + '+  "mode": "full",\n' * 30000
                + "*** End Patch"
            },
        ),
        "quiet",
    ),
    (
        "many edits",
        lambda: planir(
            "edit",
            "file_edit",
            {"path": OC, "edits": [{"oldText": '"ask":"on"', "newText": '"ask":"off"'}] * 3000},
        ),
        "block",
    ),
]


@pytest.mark.parametrize("name, make, expect", LARGE, ids=[n for n, _, _ in LARGE])
def test_large_input_keeps_its_tier_and_the_floor_stays_fast(name, make, expect, monkeypatch):
    spent = [0.0]
    original = detectors._approval_loosening

    def timed(a, ctx):
        start = time.perf_counter()
        try:
            return original(a, ctx)
        finally:
            spent[0] += time.perf_counter() - start

    monkeypatch.setattr(detectors, "_approval_loosening", timed)
    assert tier(make()) == expect
    assert spent[0] < 1.0, f"{name}: {spent[0]:.2f}s"


# --------------------------------------------------------------------------- backtracking

DELIMITERS = ["/", "|", "#", ",", ":", "@"]


def _floor_time(raw: dict, monkeypatch) -> tuple[str, float]:
    spent = [0.0]
    original = detectors._approval_loosening

    def timed(a, ctx):
        start = time.perf_counter()
        try:
            return original(a, ctx)
        finally:
            spent[0] += time.perf_counter() - start

    monkeypatch.setattr(detectors, "_approval_loosening", timed)
    return tier(raw), spent[0]


@pytest.mark.parametrize("delimiter", DELIMITERS)
def test_an_unterminated_substitution_of_escapes_is_fast(delimiter, monkeypatch):
    """A substitution's text alternates escapes and other characters; a long run of escapes with no
    closing delimiter must not backtrack exponentially."""
    escapes = "\\a" * 5000
    start = time.perf_counter()
    assert detectors._SED_SUBST.search("s" + delimiter + escapes) is None
    assert time.perf_counter() - start < 0.1
    raw = ex(f"sed -i 's{delimiter}{escapes}' ~/.openclaw/exec-approvals.json")
    result, spent = _floor_time(raw, monkeypatch)
    assert result == "quiet" and spent < 1.0


@pytest.mark.parametrize(
    "text, groups",
    [
        ("s/a\\/b/c/", [("/", "a\\/b")]),
        ("s#x#y#", [("#", "x")]),
        ("s|a\\|b|c|", [("|", "a\\|b")]),
        ("sed -e 's/deny/full/' -e 's@on@off@'", [("/", "deny"), ("@", "on")]),
    ],
)
def test_substitution_captures_are_unchanged(text, groups):
    assert [m.groups() for m in detectors._SED_SUBST.finditer(text)] == groups


def _fast(fn: Callable[[], object], limit: float = 0.2) -> None:
    start = time.perf_counter()
    fn()
    assert time.perf_counter() - start < limit


def test_broad_entry_patterns_do_not_backtrack():
    rules = detectors._loosening_rules(load_lists())
    for entry in (
        "bash " + "--a " * 1000 + "!",
        "s/" + "//" * 2000,
        "/" + "a/" * 2000 + "!",
        "x" + " | x" * 1000 + " !",
    ):
        _fast(lambda e=entry: detectors._broad(e, rules))


def test_script_and_patch_patterns_do_not_backtrack():
    _fast(lambda: list(detectors._PATCH_FILE.finditer("+++ " + "a " * 20000 + "\n")))
    _fast(lambda: list(detectors._MEMBER_ASSIGN.finditer("a" + ".a" * 50000)))
    _fast(lambda: detectors._heredocs("cat <<EOF\n" * 20000))
    _fast(lambda: detectors._YAML_OPENER.match("!!a " * 20000 + "x"))
    _fast(lambda: detectors._YAML_BLOCK_SCALAR.match("&a " * 20000 + "x"))
    rules = detectors._loosening_rules(load_lists())
    _fast(lambda: detectors._code_commands("subprocess.run([" + "'a', " * 20000 + "])", rules, {}))


def test_heredoc_bodies_are_unchanged():
    command = "cat > a <<'EOF'\nx: 1\nEOF\ncat > b <<-END\n  y: 2\n  END\necho done"
    assert detectors._heredocs(command) == "x: 1\n  y: 2"
