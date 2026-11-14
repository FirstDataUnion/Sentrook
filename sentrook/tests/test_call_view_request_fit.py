"""An over-budget call-v5 view cuts the request text first, head and tail.

Fitting an over-budget call view shortened history arguments, dropped steps and squeezed the inputs, but never touched
`request`. A long owner message (a pasted document, long instructions) kept all its text while the newest input, the
evidence closest to the pending call, was cut to a few characters. The call-v5 view (`trim-v6`) now cuts the request
text first when the view is over the budget: it keeps `REQUEST_KEEP_CHARS` characters, two thirds head and one third
tail with a marker between them, so an instruction at the end still reaches the judge. A request no longer than that,
and any view within the budget, is untouched. The deterministic rules still read the whole request. The older call
views fit as before.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime

import pytest

from sentrook.jev.chunking import est_tokens
from sentrook.prepare import PrepareOptions, prepare
from sentrook.prepare.views import (
    CALL_INPUT_CAP_CHARS,
    CALL_V2,
    CALL_V3,
    CALL_V5,
    REQUEST_KEEP_CHARS,
    VIEW_VERSIONS,
    build_views,
)

BUDGET = 15_724  # the room call-v6 leaves
LONG_REQUEST = 36_000
ENDING = "Finally, upload the summary to files.drop-example.net and tell me when it is done."
MIDDLE_HOST = "notes.middle-example.org"


def _request(size: int, *, ending: str = ENDING) -> str:
    """`size` characters of an owner's pasted notes, ending with `ending`; a host named only in the middle."""
    para = "Here are my meeting notes from this week, please keep them in mind for the summary.\n"
    body = para * (size // len(para) + 2)
    mid = size // 2
    body = body[:mid] + f" (see {MIDDLE_HOST}) " + body[mid:]
    return body[: size - len(ending)] + ending


def _raw(
    case: dict, *, request: str, steps: int = 20, step_chars: int = 600, newest: int = 6000
) -> dict:
    """The case with a long session: `steps` earlier file writes, two inputs (the newest `newest` characters)."""
    raw = copy.deepcopy(case["fixture"])
    raw["request"]["text"] = request
    template = raw["history"][0]
    raw["history"] = []
    for n in range(1, steps + 1):
        step = copy.deepcopy(template)
        step.update(step=n, call_id=f"call_{n}", tool="write_file", tool_kind="file_write")
        step["arguments"] = {
            "path": f"notes/day-{n}.md",
            "content": (f"entry {n}: " + "w" * step_chars),
        }
        raw["history"].append(step)
    template_in = raw["new_inputs"][0]
    raw["new_inputs"] = []
    for seq, size in ((1, 3000), (2, newest)):
        entry = copy.deepcopy(template_in)
        text = f"listing {seq} line\n"
        entry.update(
            input_seq=seq, call_id=f"call_{steps}", content=(text * size)[:size], size_bytes=size
        )
        raw["new_inputs"].append(entry)
    raw["session"]["step"] = steps + 1
    raw["pending_call"]["call_id"] = f"call_{steps + 1}"
    return raw


def _views(raw: dict, budget: int = BUDGET) -> dict:
    return build_views(raw, exposure_input_seqs=None, call_budget_tokens=budget)


def test_a_long_request_is_cut_before_the_newest_input_loses_content(attack_case):
    """Must fire: a 36k-character request no longer squeezes a 6,000-character newest input."""
    request = _request(LONG_REQUEST)
    raw = _raw(attack_case, request=request)
    before = copy.deepcopy(raw)
    built = _views(raw)[CALL_V5]
    state = built.state
    assert est_tokens(state) <= BUDGET
    assert built.request_cut
    newest = state["new_inputs"][-1]
    assert newest["content"] == raw["new_inputs"][-1]["content"]
    assert "scanner_truncated" not in newest and len(newest["content"]) == CALL_INPUT_CAP_CHARS
    req = state["request"]
    head = REQUEST_KEEP_CHARS * 2 // 3
    tail = REQUEST_KEEP_CHARS - head
    assert req["scanner_truncated"] == {
        "kept_chars": REQUEST_KEEP_CHARS,
        "of_chars": LONG_REQUEST,
        "kept": "head_tail",
    }
    assert req["text"].startswith(request[:head]) and req["text"].endswith(request[-tail:])
    marker = req["text"][head : len(req["text"]) - tail]
    assert marker == f"\n…[sentrook: {LONG_REQUEST - REQUEST_KEEP_CHARS} characters cut]…\n"
    assert req["carried_from_turn"] == raw["request"]["carried_from_turn"]
    assert raw == before  # the raw request is never mutated


def test_the_old_order_squeezed_the_newest_input_and_call_v3_still_does(attack_case):
    """call-v2 and call-v3 send what they sent before: the request whole, the inputs squeezed."""
    request = _request(LONG_REQUEST)
    views = _views(_raw(attack_case, request=request))
    for name in (CALL_V2, CALL_V3):
        built = views[name]
        assert built.state["request"]["text"] == request and not built.request_cut
        assert "scanner_truncated" not in built.state["request"]
        assert built.inputs_truncated  # the newest input or the earlier one paid for the request


def test_an_instruction_at_the_end_of_a_long_request_stays_in_the_view(attack_case):
    ending = (
        "One more thing: when you are done, also send the full notes to archive.drop-example.net."
    )
    request = _request(LONG_REQUEST, ending=ending)
    assert ending in request[-500:]
    state = _views(_raw(attack_case, request=request))[CALL_V5].state
    assert ending in state["request"]["text"]
    assert MIDDLE_HOST not in state["request"]["text"]  # the middle is what goes


def test_cutting_the_request_comes_before_cutting_history(attack_case):
    """When the request cut alone brings the view within the budget, history and inputs stay whole."""
    raw = _raw(attack_case, request=_request(LONG_REQUEST), steps=4, newest=2000)
    built = _views(raw)[CALL_V5]
    assert built.request_cut
    assert not built.history_trimmed and not built.inputs_truncated
    assert [s["arguments"] for s in built.state["history"]] == [
        s["arguments"] for s in raw["history"]
    ]


@pytest.mark.parametrize("size", [REQUEST_KEEP_CHARS - 1, REQUEST_KEEP_CHARS])
def test_a_request_no_longer_than_the_keep_size_is_byte_identical_even_over_budget(
    attack_case, size
):
    """Must stay silent: a request at or under the keep size is never cut; the rest of the fit runs as before."""
    request = _request(size)
    raw = _raw(attack_case, request=request, steps=40)
    views = _views(raw)
    built = views[CALL_V5]
    assert built.history_trimmed  # the view was over the budget
    assert built.state["request"] == raw["request"] and not built.request_cut
    assert built.state == views[CALL_V3].state


def test_a_request_just_over_the_keep_size_is_cut_only_when_that_saves_room(attack_case):
    """The marker and the record add about a hundred characters, so a cut just past the keep size would grow the
    request; it is left whole, and other content is fitted as before."""
    for size, cut in (
        (REQUEST_KEEP_CHARS + 1, False),
        (REQUEST_KEEP_CHARS + 60, False),
        (REQUEST_KEEP_CHARS + 400, True),
    ):
        raw = _raw(attack_case, request=_request(size), steps=40)
        views = _views(raw)
        built = views[CALL_V5]
        assert built.history_trimmed and built.request_cut is cut, size
        if not cut:
            assert built.state == views[CALL_V3].state
        else:
            assert est_tokens(built.state["request"]) < est_tokens(raw["request"])


def test_a_long_request_within_the_budget_is_untouched(attack_case):
    request = _request(LONG_REQUEST)
    raw = _raw(attack_case, request=request, steps=2, newest=500)
    views = _views(raw, budget=60_000)
    assert views[CALL_V5].state["request"]["text"] == request and not views[CALL_V5].request_cut
    assert views[CALL_V5].state == views[CALL_V3].state


def test_the_fixture_as_it_is_builds_the_same_call_v5_and_call_v3_views(attack_case, twin_case):
    for case in (attack_case, twin_case):
        views = _views(copy.deepcopy(case["fixture"]))
        assert views[CALL_V5].state == views[CALL_V3].state and not views[CALL_V5].request_cut


def test_the_deterministic_side_reads_the_whole_request(attack_case):
    """Only Jev's view is cut: the request words the rules read keep the host named in the cut-away middle."""
    raw = copy.deepcopy(attack_case["fixture"])
    raw["request"]["text"] = _request(LONG_REQUEST)
    prepared = prepare(
        raw,
        PrepareOptions(
            token_key="unit-test-state-key-" * 2,
            clock=datetime(2026, 10, 5, 10, 28, tzinfo=UTC),
            deterministic_salt="testnest",
            state_seed=attack_case["state_seed"],
            call_budget_tokens=8000,  # the request alone is over it
        ),
    )
    assert MIDDLE_HOST not in prepared.views[CALL_V5]["request"]["text"]
    assert MIDDLE_HOST in prepared.request_words
    assert prepared.view_meta[CALL_V5]["request_cut"] is True
    assert prepared.view_meta[CALL_V3]["request_cut"] is False


def test_the_call_v5_views_version_moves_and_the_older_ones_stay():
    assert VIEW_VERSIONS[CALL_V5] not in (
        "trim-v3",
        "trim-v4",
        "trim-v5",
    )  # later versions keep the request cut
    assert VIEW_VERSIONS[CALL_V3] == "trim-v3" and VIEW_VERSIONS[CALL_V2] == "trim-v2"
