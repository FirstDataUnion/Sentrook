"""An over-budget call view is fitted, not emptied.

A call view over its token budget used to lose every input's content while its history stayed whole. On long sessions
the history is most of the view (each earlier step carries its full arguments: files written, commands run), so the
call was judged blind to the listing or read right before it. Fitting now goes from least to most useful:

1. the history steps' long argument strings are cut to a short head, oldest step first (the step stays: tool, kind,
   decision);
2. if that is not enough, the oldest steps are dropped, keeping the most recent few; the earliest step left says how
   many the scanner dropped before it;
3. then the inputs are filled to the room that is left: the most recent input keeps its content, the earliest lose
   theirs first;
4. last, the remaining steps are dropped and the inputs refilled into the room that frees.

Small requests are not touched.
"""

from __future__ import annotations

import copy

import pytest

from sentrook.jev.chunking import est_tokens
from sentrook.prepare.views import (
    CALL_V2,
    CALL_V3,
    CALL_V5,
    HISTORY_ARG_KEEP_CHARS,
    HISTORY_KEEP_STEPS,
    build_views,
    cap_inputs,
)

BUDGET = 15_000
LONG = 6000  # characters in each history step's written file


def _raw(
    attack_case,
    *,
    steps: int = 20,
    step_chars: list[int] | None = None,
    inputs: list[int] | None = None,
    input_text: str | None = None,
    pending_chars: int = 0,
) -> dict:
    """A long session: `steps` earlier steps each writing a file of `step_chars[i]` characters (LONG by default),
    then one input per entry of `inputs` (its content length), then the pending call."""
    raw = copy.deepcopy(attack_case["fixture"])
    sizes = step_chars if step_chars is not None else [LONG] * steps
    template = raw["history"][0]
    raw["history"] = []
    for n, size in enumerate(sizes, start=1):
        step = copy.deepcopy(template)
        step.update(step=n, call_id=f"call_{n}", tool="write_file", tool_kind="file_write")
        step["arguments"] = {
            "path": f"notes/day-{n}.md",
            "content": (f"entry {n}: " + "w" * size)[:size],
        }
        raw["history"].append(step)
    template_in = raw["new_inputs"][0]
    raw["new_inputs"] = []
    for seq, size in enumerate(inputs if inputs is not None else [3000], start=1):
        entry = copy.deepcopy(template_in)
        text = input_text if input_text is not None else f"listing {seq}\n"
        entry.update(input_seq=seq, call_id=f"call_{len(sizes)}", content=(text * size)[:size])
        entry["size_bytes"] = size
        raw["new_inputs"].append(entry)
    raw["session"]["step"] = len(sizes) + 1
    raw["pending_call"]["call_id"] = f"call_{len(sizes) + 1}"
    if pending_chars:
        raw["pending_call"]["arguments"]["command"] = "echo " + "p" * pending_chars
    return raw


def _view(raw, budget=BUDGET, name=CALL_V5):
    return build_views(raw, exposure_input_seqs=None, call_budget_tokens=budget)[name]


def _steps(state) -> list[int]:
    return [s["step"] for s in state.get("history") or []]


def _cut_steps(state) -> list[int]:
    return [s["step"] for s in state.get("history") or [] if "scanner_truncated" in s]


def test_history_arguments_are_cut_oldest_first_and_the_inputs_keep_their_content(attack_case):
    raw = _raw(attack_case)
    before = copy.deepcopy(raw)
    built = _view(raw)
    state = built.state
    assert est_tokens(state) <= BUDGET
    assert built.history_cut and not built.history_dropped
    assert not built.inputs_truncated and not built.inputs_stripped
    # every step is still there; the input keeps its content
    assert _steps(state) == list(range(1, 21))
    assert state["new_inputs"][0]["content"] == raw["new_inputs"][0]["content"]
    cut = _cut_steps(state)
    assert cut == list(range(1, len(cut) + 1)) and len(cut) == built.history_cut < 20
    first = state["history"][0]
    assert len(first["arguments"]["content"]) == HISTORY_ARG_KEEP_CHARS
    assert (
        first["arguments"]["content"]
        == raw["history"][0]["arguments"]["content"][:HISTORY_ARG_KEEP_CHARS]
    )
    assert first["arguments"]["path"] == "notes/day-1.md"  # short strings stay whole
    assert first["scanner_truncated"] == {"kept_chars": HISTORY_ARG_KEEP_CHARS, "of_chars": LONG}
    assert first["tool"] == "write_file" and first["decision"] == "allowed"
    assert "scanner_dropped_earlier" not in first
    assert raw == before  # the raw request is never mutated


def test_a_huge_recent_step_is_cut_before_any_older_step_is_dropped(attack_case):
    raw = _raw(attack_case, step_chars=[100] * 19 + [40_000])
    built = _view(raw)
    assert est_tokens(built.state) <= BUDGET
    assert _steps(built.state) == list(range(1, 21))
    assert _cut_steps(built.state) == [20] and not built.history_dropped


def test_oldest_steps_are_dropped_when_cutting_is_not_enough_and_the_gap_is_recorded(attack_case):
    raw = _raw(attack_case, steps=60)
    built = _view(raw)
    state = built.state
    assert est_tokens(state) <= BUDGET
    steps = _steps(state)
    assert steps == list(range(steps[0], 61)) and steps[0] > 1  # a contiguous recent window
    assert state["history"][0]["scanner_dropped_earlier"] == steps[0] - 1 == built.history_dropped
    assert all("scanner_dropped_earlier" not in s for s in state["history"][1:])
    assert state["new_inputs"][0]["content"] == raw["new_inputs"][0]["content"]
    assert not built.inputs_truncated


def test_recent_steps_are_cut_before_the_latest_input_loses_content(attack_case):
    raw = _raw(attack_case, step_chars=[12_000, 12_000, 12_000], inputs=[3000])
    built = _view(raw, budget=15_871)
    assert built.state["new_inputs"][0]["content"] == raw["new_inputs"][0]["content"]
    assert _cut_steps(built.state) and not built.inputs_truncated


def test_inputs_are_filled_to_the_room_most_recent_first(attack_case):
    raw = _raw(attack_case, inputs=[6000] * 6)
    built = _view(raw)
    state = built.state
    assert est_tokens(state) <= BUDGET
    # the oldest steps go before any input content, down to the recent steps kept, all cut
    assert _steps(state) == list(range(21 - HISTORY_KEEP_STEPS, 21))
    assert _cut_steps(state) == _steps(state)
    kept = [len(i["content"]) for i in state["new_inputs"]]
    assert (
        kept[-1] == 6000 and kept[0] < 6000
    )  # the latest keeps its content, the earliest loses first
    assert kept == sorted(kept)
    assert not built.inputs_stripped and built.inputs_truncated
    # the original sizes are recorded, not the capped ones
    for entry in state["new_inputs"]:
        if "scanner_truncated" in entry:
            assert entry["scanner_truncated"]["of_chars"] == 6000


@pytest.mark.parametrize("name", [CALL_V3, CALL_V5])
def test_the_latest_input_is_cut_when_it_cannot_fit_whole(attack_case, name):
    """call-v3 keeps the head; call-v5 keeps head and tail (test_call_view_input_cap covers its shape)."""
    raw = _raw(attack_case, steps=3, inputs=[6000] * 4, pending_chars=30_000)
    built = _view(raw, name=name)
    sent = built.state["new_inputs"]
    assert est_tokens(built.state) <= BUDGET
    assert [i["content"] for i in sent[:-1]] == ["", "", ""]
    latest = raw["new_inputs"][-1]["content"]
    kept = sent[-1]["scanner_truncated"]["kept_chars"]
    assert 0 < kept < 6000
    if name == CALL_V3:
        assert latest.startswith(sent[-1]["content"]) and len(sent[-1]["content"]) == kept
        assert sent[-1]["scanner_truncated"] == {"kept_chars": kept, "of_chars": 6000}
    else:
        assert sent[-1]["content"].startswith(latest[: kept * 2 // 3])
        assert sent[-1]["content"].endswith(latest[-(kept - kept * 2 // 3) :])
        assert sent[-1]["scanner_truncated"] == {
            "kept_chars": kept,
            "of_chars": 6000,
            "kept": "head_tail",
        }
    assert not built.inputs_stripped


def test_escaped_content_fills_the_room_rather_than_being_stripped(attack_case):
    """A newline is two characters of the request; the fill still uses the room it has."""
    raw = _raw(attack_case, steps=3, inputs=[6000] * 6, input_text="\n")
    built = _view(raw)
    assert not built.inputs_stripped and built.inputs_truncated
    assert BUDGET - 2 <= est_tokens(built.state) <= BUDGET  # as full as one more character allows
    assert built.state["new_inputs"][-1]["content"] == "\n" * 6000


def test_a_view_too_big_without_contents_is_emptied_and_left_without_history(attack_case):
    raw = _raw(attack_case, steps=5, pending_chars=60_000)
    built = _view(raw)
    state = built.state
    assert built.inputs_stripped and built.history_dropped == 5
    assert state["new_inputs"][0]["content"] == ""
    assert state["history"] == []
    assert (
        state["pending_call"]["arguments"]["command"] == raw["pending_call"]["arguments"]["command"]
    )


@pytest.mark.parametrize("name", [CALL_V2, CALL_V3, CALL_V5])
def test_every_call_view_is_fitted(attack_case, name):
    built = _view(_raw(attack_case), name=name)
    assert est_tokens(built.state) <= BUDGET and built.history_trimmed


def test_a_view_within_the_budget_is_untouched(attack_case):
    raw = _raw(attack_case, steps=3)
    built = _view(raw)
    assert not built.history_trimmed and not built.inputs_truncated
    assert [s["arguments"] for s in built.state["history"]] == [
        s["arguments"] for s in raw["history"]
    ]


def test_a_malformed_cut_marker_on_an_input_does_not_break_the_caps():
    inputs = [{"input_seq": 1, "content": "x" * 7000, "scanner_truncated": "yes"}]
    assert cap_inputs(inputs)
    assert inputs[0]["scanner_truncated"] == {"kept_chars": 6000, "of_chars": 7000}


@pytest.mark.parametrize("pending", range(30_200, 30_400, 7))
def test_a_view_without_inputs_fits_while_any_history_is_left(attack_case, pending):
    """The drop marker counts toward the budget, so it cannot push the view over."""
    raw = _raw(attack_case, step_chars=[300] * 10, pending_chars=pending)
    del raw["new_inputs"]
    built = _view(raw, budget=13_000)
    state = built.state
    assert state["history"], "the case should keep some history"
    assert est_tokens(state) <= 13_000
    assert (
        state["history"][0]["scanner_dropped_earlier"]
        == built.history_dropped
        == state["history"][0]["step"] - 1
    )
