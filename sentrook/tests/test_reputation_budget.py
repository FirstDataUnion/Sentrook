"""What the call probe adds after a view is fitted stays inside the view's budget.

The call view is fitted to its budget before the oracle runs; the call probe then appends the `reputation` block, and
the second redaction pass runs on the fitted view. The block is now capped (`REPUTATION_MAX_ENTRIES` entries within
`REPUTATION_CAP_CHARS`, known_bad kept first) and its room reserved in the budget, and a view the redaction grows past
its budget is fitted again. A view with no reputation entries and nothing to redact is unchanged.
"""

from __future__ import annotations

import copy

import pytest
from test_jev_probes import FakeDecider, prepared_for

from sentrook.jev.chunking import CHARS_PER_TOKEN, est_tokens
from sentrook.jev.client import JevConfig
from sentrook.jev.questions import canonical_json, load_question_set
from sentrook.prepare.views import (
    CALL_INPUT_CAP_CHARS,
    CALL_STATE_BUDGET_TOKENS,
    CALL_V3,
    CALL_V5,
    CALL_V7,
    REPUTATION,
    REPUTATION_CAP_CHARS,
    REPUTATION_MAX_ENTRIES,
    REPUTATION_OMITTED,
    REPUTATION_RESERVE_TOKENS,
    SELFEDIT_V2,
    build_views,
    cap_reputation,
    set_state_budget_tokens,
    trim,
    view,
    with_reputation,
)
from sentrook.probes.jev import JevCallProbe


def _entry(i: int, verdict: str, *, width: int = 40, near: bool = False) -> dict:
    value = f"user{i:04d}." + "x" * width + "@example.org"
    e = {"kind": "recipient", "value": value, "verdict": verdict}
    if near:
        e["near_miss"] = "x" + value
    return e


def _many(n: int = 300, *, width: int = 40) -> list[dict]:
    """A bulk send's worth of entries: mostly known_good, with known_bad and near misses spread through."""
    out = []
    for i in range(n):
        if i % 50 == 7:
            out.append(_entry(i, "known_bad", width=width))
        elif i % 40 == 3:
            out.append(_entry(i, "unknown", width=width, near=True))
        elif i % 30 == 11:
            out.append(_entry(i, "owner_config", width=width))
        else:
            out.append(_entry(i, "known_good", width=width))
    return out


# ---- the cap ---------------------------------------------------------------------------------------------------


def test_a_block_that_fits_is_unchanged():
    verdicts = _many(REPUTATION_MAX_ENTRIES, width=10)
    assert len(canonical_json(verdicts)) <= REPUTATION_CAP_CHARS
    state = with_reputation({"grants": []}, verdicts)
    assert state[REPUTATION] == verdicts and REPUTATION_OMITTED not in state
    assert canonical_json(state) == canonical_json({"grants": [], REPUTATION: verdicts})


def test_no_entries_means_no_block():
    state = {"grants": [], "request": {"text": "hi"}}
    assert with_reputation(state, []) == state


def test_a_bulk_block_is_capped_and_says_so():
    verdicts = _many()
    state = with_reputation({"grants": []}, verdicts)
    kept = state[REPUTATION]
    assert len(kept) <= REPUTATION_MAX_ENTRIES
    assert len(canonical_json(kept)) <= REPUTATION_CAP_CHARS
    assert state[REPUTATION_OMITTED] == len(verdicts) - len(kept)
    # the kept entries keep their order in the oracle's list
    assert kept == [v for v in verdicts if v in kept]


def test_known_bad_entries_are_never_the_ones_dropped():
    verdicts = _many()
    kept = cap_reputation(verdicts)
    bad = [v for v in verdicts if v["verdict"] == "known_bad"]
    assert bad and all(b in kept for b in bad)
    # then near misses, before any known_good or owner_config entry
    near = [v for v in verdicts if "near_miss" in v]
    room = REPUTATION_MAX_ENTRIES - len(bad)
    assert [v for v in kept if "near_miss" in v] == near[:room]
    if len(near) >= room:
        assert all(v["verdict"] == "known_bad" or "near_miss" in v for v in kept)


def test_more_known_bad_than_the_cap_keeps_only_known_bad():
    verdicts = [_entry(i, "known_good") for i in range(20)] + [
        _entry(i, "known_bad") for i in range(20, 40)
    ]
    kept = cap_reputation(verdicts)
    assert kept and all(v["verdict"] == "known_bad" for v in kept)


def test_a_long_known_bad_host_is_shortened_not_dropped():
    """A host of many long labels under a known_bad parent domain matches it; over the cap it is cut, not dropped,
    and the entries after it stay."""
    host = ".".join(["a" * 60] * 28) + ".evil.example"
    bad = {"kind": "host", "value": host, "verdict": "known_bad", "tier": "exfil_sink"}
    good = {"kind": "host", "value": "ok.example", "verdict": "known_good"}
    state = with_reputation({}, [bad, good])
    kept = state[REPUTATION]
    assert [e["verdict"] for e in kept] == ["known_bad", "known_good"]
    assert kept[0]["value"].endswith(".evil.example") and "…" in kept[0]["value"]
    assert kept[1] == good and REPUTATION_OMITTED not in state
    assert len(canonical_json(kept)) <= REPUTATION_CAP_CHARS


def test_any_eight_long_entries_fit_together():
    verdicts = [
        _entry(i, "known_bad", width=900, near=True) for i in range(REPUTATION_MAX_ENTRIES + 3)
    ]
    kept = cap_reputation(verdicts)
    assert len(kept) == REPUTATION_MAX_ENTRIES
    assert len(canonical_json(kept)) <= REPUTATION_CAP_CHARS


def test_long_values_are_capped_by_size():
    verdicts = [_entry(i, "known_good", width=400) for i in range(REPUTATION_MAX_ENTRIES)]
    kept = cap_reputation(verdicts)
    assert len(kept) == REPUTATION_MAX_ENTRIES
    assert len(canonical_json(kept)) <= REPUTATION_CAP_CHARS


def test_the_reserve_covers_the_largest_block_the_cap_allows():
    """The block's own key and the omitted count are inside the reserve, not only the entries."""
    worst = {REPUTATION: [{"v": "x" * (REPUTATION_CAP_CHARS - 10)}], REPUTATION_OMITTED: 10**6}
    assert est_tokens(worst) <= REPUTATION_RESERVE_TOKENS
    assert REPUTATION_RESERVE_TOKENS * CHARS_PER_TOKEN < REPUTATION_CAP_CHARS + 100


# ---- a full-budget view plus the largest block stays in its budget ---------------------------------------------


def _at_budget(attack_case, budget: int) -> dict:
    """A request whose call view is over `budget`, so it is fitted to it: inputs at the per-input cap and a command
    long enough that they no longer all fit."""
    case = copy.deepcopy(attack_case)
    raw = case["fixture"]
    template = raw["new_inputs"][0]
    raw["new_inputs"] = []
    for seq in range(1, 7):
        entry = copy.deepcopy(template)
        entry["input_seq"] = seq
        entry["content"] = (f"line {seq} of a long listing\n" * 400)[:CALL_INPUT_CAP_CHARS]
        entry["size_bytes"] = len(entry["content"])
        raw["new_inputs"].append(entry)
    raw["pending_call"]["arguments"]["command"] = "echo " + "p" * int(budget * CHARS_PER_TOKEN / 3)
    return case


@pytest.mark.parametrize("view_name", [CALL_V3, CALL_V5, CALL_V7])
def test_a_fitted_view_plus_the_largest_block_stays_in_its_budget(attack_case, view_name):
    budget = set_state_budget_tokens(load_question_set("call-v8"))
    case = _at_budget(attack_case, budget)
    built = build_views(case["fixture"], exposure_input_seqs=None, call_budget_tokens=budget)[
        view_name
    ]
    assert built.fitted and built.inputs_truncated
    # filled close to the budget the block leaves
    assert (
        budget - REPUTATION_RESERVE_TOKENS - 50
        <= est_tokens(built.state)
        <= budget - REPUTATION_RESERVE_TOKENS
    )
    sent = with_reputation(built.state, _many(500, width=150))
    assert est_tokens(sent) <= budget


def test_the_call_probe_sends_a_fitted_view_with_a_bulk_block_within_the_budget(attack_case):
    case = _at_budget(attack_case, CALL_STATE_BUDGET_TOKENS)
    prepared = prepared_for(case)
    prepared.oracle_verdicts = _many(400, width=120)
    probe = JevCallProbe(FakeDecider(), JevConfig(call_question_set="call-v8"))
    assert probe.view_name == CALL_V7
    state = probe.state_for(prepared)
    assert est_tokens(state) <= CALL_STATE_BUDGET_TOKENS
    assert state[REPUTATION_OMITTED] == 400 - len(state[REPUTATION])
    assert all(
        v in state[REPUTATION] for v in prepared.oracle_verdicts if v["verdict"] == "known_bad"
    )


# ---- a view the redaction grows is fitted again -----------------------------------------------------------------


def _short_secrets(attack_case, steps: int = 300) -> dict:
    """History steps whose credential arguments are one character long: the placeholder replacing each is longer."""
    case = copy.deepcopy(attack_case)
    raw = case["fixture"]
    raw["history"] = [
        {
            "step": i,
            "turn": 1,
            "tool": "exec",
            "tool_kind": "exec",
            "arguments": {"api_token": "x", "pin": i},
        }
        for i in range(1, steps + 1)
    ]
    raw["session"]["step"] = steps + 1
    return case


@pytest.mark.parametrize("view_name", [CALL_V3, CALL_V5, CALL_V7])
def test_a_view_that_grows_under_redaction_stays_within_its_budget(attack_case, view_name):
    case = _short_secrets(attack_case)
    raw = case["fixture"]
    unredacted = est_tokens(view(trim(raw), view_name))
    redacted = est_tokens(
        build_views(raw, exposure_input_seqs=None, call_budget_tokens=10**6)[view_name].state
    )
    assert redacted > unredacted + 200
    # a budget the view fits before the redaction and not after
    room = (unredacted + redacted) // 2
    budget = room + REPUTATION_RESERVE_TOKENS
    built = build_views(raw, exposure_input_seqs=None, call_budget_tokens=budget)[view_name]
    assert est_tokens(built.state) <= room
    assert built.fitted and built.history_trimmed
    assert "x" not in {h["arguments"].get("api_token") for h in built.state["history"]}


@pytest.mark.parametrize("view_name", [CALL_V3, CALL_V7])
@pytest.mark.parametrize("short_by", [1, 5, 20, 40])
def test_a_view_just_over_after_redaction_is_refitted(attack_case, view_name, short_by):
    """Room far above the unredacted view and just under the redacted one: the refit fits from the view's own size."""
    raw = _short_secrets(attack_case, steps=100)["fixture"]
    redacted = est_tokens(
        build_views(raw, exposure_input_seqs=None, call_budget_tokens=10**6)[view_name].state
    )
    room = redacted - short_by
    built = build_views(
        raw, exposure_input_seqs=None, call_budget_tokens=room + REPUTATION_RESERVE_TOKENS
    )[view_name]
    assert est_tokens(built.state) <= room and built.fitted


def test_a_self_edit_view_that_grows_under_redaction_stays_within_its_budget(attack_case):
    case = _short_secrets(attack_case)
    raw = case["fixture"]
    raw["self_edit"] = {
        "kind": "memory",
        "conversation": [{"role": "user", "text": "remember this"}],
    }
    redacted = est_tokens(
        build_views(raw, exposure_input_seqs=None, selfedit_budget_tokens=10**6)[SELFEDIT_V2].state
    )
    unredacted = est_tokens(view(trim(raw), SELFEDIT_V2))
    room = (unredacted + redacted) // 2
    built = build_views(
        raw, exposure_input_seqs=None, selfedit_budget_tokens=room + REPUTATION_RESERVE_TOKENS
    )[SELFEDIT_V2]
    assert est_tokens(built.state) <= room


# ---- small requests are unchanged ------------------------------------------------------------------------------


def test_a_view_with_room_to_spare_is_byte_identical(attack_case, twin_case):
    """The reserve only moves a view that was within `REPUTATION_RESERVE_TOKENS` of its budget."""
    for case in (attack_case, twin_case):
        raw = case["fixture"]
        built = build_views(
            raw, exposure_input_seqs=None, call_budget_tokens=CALL_STATE_BUDGET_TOKENS
        )
        for name in (CALL_V3, CALL_V5, CALL_V7):
            assert not built[name].fitted
            assert (
                built[name].state
                == build_views(raw, exposure_input_seqs=None, call_budget_tokens=10**6)[name].state
            )
