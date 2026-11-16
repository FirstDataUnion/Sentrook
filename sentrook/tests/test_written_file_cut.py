"""A file the agent wrote and then runs counts as cut only when the plugin's cut marker says so.

The plugins cap each history argument object at 4 KB by giving every string a share of it and cutting longer
strings head and tail around a marker. A write's content that fills most of the cap is whole; a cut one is much
shorter and carries the marker in the middle.
"""

from __future__ import annotations

import copy
import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from sentrook.converge import _DEGRADING_COVERAGE
from sentrook.prepare import PLUGIN_CUT_MARKER, PrepareOptions, prepare

KEY = "unit-test-state-key-" * 2
CLOCK = datetime(2026, 10, 5, 10, 28, tzinfo=UTC)
HISTORY_ARGS_CAP_BYTES = 4 * 1024  # both plugins' default
SCRIPT = "/home/me/workspace/tools/report.sh"
SEED = {
    "tainted": False,
    "holds_sensitive": False,
    "escalating": False,
    "untrusted_entities": [],
    "max_input_seq": 1,
}
ROOT = Path(__file__).resolve().parents[2]


def _plugin():
    path = ROOT / "integrations" / "hermes" / "plugin" / "redact.py"
    spec = importlib.util.spec_from_file_location("hermes_plugin_redact_cap", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _script(chars: int) -> str:
    """A benign shell script of exactly `chars` characters."""
    head = "#!/bin/sh\nset -eu\ndu -sh /home/me/workspace\n"
    body, i = [], 0
    while len(head) + sum(map(len, body)) < chars:
        body.append(f"# report section {i}: totals per folder, sorted by size, largest first\n")
        i += 1
    return (head + "".join(body))[:chars]


def _step(step: int, tool_kind: str, arguments: dict) -> dict:
    return {
        "step": step,
        "turn": 1,
        "call_id": f"c{step}",
        "tool": tool_kind,
        "tool_kind": tool_kind,
        "provider": {"kind": "host"},
        "arguments": _plugin().cap_args(arguments, HISTORY_ARGS_CAP_BYTES),
        "decision": "allowed",
    }


def _prepare(attack_case, history: list[dict]):
    raw = copy.deepcopy(attack_case["fixture"])
    raw["request"]["text"] = "Write a disk usage report script in my tools folder and run it."
    raw["new_inputs"] = []
    raw["history"] = history
    raw["session"]["step"] = len(history) + 1
    raw["pending_call"]["call_id"] = f"c{len(history) + 1}"
    raw["pending_call"]["arguments"] = {"command": SCRIPT}
    opts = PrepareOptions(
        token_key=KEY,
        deployment="dep-test",
        clock=CLOCK,
        deterministic_salt="testnest",
        state_seed=SEED,
    )
    return prepare(raw, opts)


def _codes(p) -> set[str]:
    return {c.code for c in p.coverage}


def test_whole_file_at_the_cap_is_not_cut(attack_case):
    """Must stay silent: content that fills most of the plugin cap arrives whole and stays whole."""
    content = _script(3_950)
    step = _step(1, "file_write", {"path": SCRIPT, "content": content})
    assert step["arguments"]["content"] == content  # the plugin kept it whole
    p = _prepare(attack_case, [step])
    assert p.written_file is not None and p.written_file.step == 1
    assert not p.written_file.truncated
    assert "written_file_truncated" not in _codes(p)
    assert not _codes(p) & _DEGRADING_COVERAGE


def test_file_the_plugin_cut_is_cut(attack_case):
    """Must fire: a write the plugin cut carries its marker, and running that file lowers coverage."""
    step = _step(1, "file_write", {"path": SCRIPT, "content": _script(8_000)})
    kept = step["arguments"]["content"]
    assert PLUGIN_CUT_MARKER.search(kept) and len(kept) < 3_000  # cut to a share of the cap
    p = _prepare(attack_case, [step])
    assert p.written_file is not None and p.written_file.truncated
    assert "written_file_truncated" in _codes(p)


def test_edit_after_a_cut_write_is_still_cut(attack_case):
    """The edit's text joins the cut write's; the file as a whole is still partly unseen."""
    history = [
        _step(1, "file_write", {"path": SCRIPT, "content": _script(8_000)}),
        _step(2, "file_edit", {"path": SCRIPT, "content": "echo done\n"}),
    ]
    p = _prepare(attack_case, history)
    assert p.written_file is not None and p.written_file.step == 2 and p.written_file.truncated
    assert "written_file_truncated" in _codes(p)


def test_whole_rewrite_after_a_cut_write_is_whole(attack_case):
    """A later full write replaces the file, so the earlier cut no longer matters."""
    history = [
        _step(1, "file_write", {"path": SCRIPT, "content": _script(8_000)}),
        _step(2, "file_write", {"path": SCRIPT, "content": _script(1_200)}),
    ]
    p = _prepare(attack_case, history)
    assert p.written_file is not None and p.written_file.step == 2
    assert not p.written_file.truncated
    assert "written_file_truncated" not in _codes(p)


def test_marker_is_the_plugins_marker():
    """Both plugins write the marker this pattern reads; a format changed in a plugin fails here."""
    text, cut, _ = _plugin().cap_head_tail("x" * 5_000, 1_000)
    assert cut and PLUGIN_CUT_MARKER.search(text)
    ts = (ROOT / "integrations" / "openclaw" / "plugin" / "redact.ts").read_text()
    assert "`\\n…[sentrook: ${sizeBytes - capBytes} bytes cut]…\\n`" in ts
    assert PLUGIN_CUT_MARKER.search("\n…[sentrook: 123 bytes cut]…\n")
