"""A retry of a review nobody answered may ask the owner, never block on its own.

A save the owner asks for again after its review timed out, or after the host's own review loop denied it unseen
(Hermes: `blocked` with `decided_by: review_loop`), carries a verdict ceiling of `review`; the risk stays as scored.
A retry of an action the owner refused, or the scanner blocked, is unchanged, and so is a call that would block
without the retry. Synthetic data, invented skill names.
"""

from __future__ import annotations

import copy

import pytest
from test_converge_scan import ATTACK_ANSWERS, BENIGN_ANSWERS, options, scanner

from sentrook.converge import load_params
from sentrook.planir.models import DecidedBy, PlanIR

PARAMS = load_params("conv-v7")
PROBES = ("jev_exposure", "jev_call", "entity_oracle", "context", "aira")
RANK = {"allow": 0, "review": 1, "block": 2}
LOOP = {"decided_by": "review_loop"}

SKILL = {
    "tool": "write_file",
    "tool_kind": "file_write",
    "arguments": {
        "path": "/home/me/.hermes/skills/tidy-downloads/SKILL.md",
        "content": "# tidy-downloads\nSort the downloads folder by month.",
    },
}
MEMORY = {
    "tool": "memory",
    "tool_kind": "memory_write",
    "arguments": {
        "action": "add",
        "target": "memory",
        "content": "The owner sorts downloads by month.",
    },
}


def decide(resp, review_at: float = 45, block_at: float = 80) -> str:
    """What a plugin does: the verdict from risk and its lines, lowered to the ceiling, raised to `enforced`."""
    v = "block" if resp.risk >= block_at else "review" if resp.risk >= review_at else "allow"
    if resp.ceiling is not None and RANK[resp.ceiling] < RANK[v]:
        v = resp.ceiling
    if resp.enforced is not None and RANK[resp.enforced.value] > RANK[v]:
        v = resp.enforced.value
    return v


def _step(n: int, call: dict, decision: str, **extra) -> dict:
    out = {
        "step": n,
        "turn": 1,
        "call_id": f"c{n}",
        "provider": {"kind": "host"},
        "decision": decision,
        **copy.deepcopy(call),
    }
    if decision != "allowed":
        out.update({"risk": 60, "tiers": {"suspicion": 0.6, "consequence": 1.0, "confidence": 0.8}})
    out.update(extra)
    return out


def scan(
    case: dict, denied: list[tuple[str, dict]], call: dict = SKILL, *, gap: int = 1, answers=None
):
    """`denied`: (decision, extra fields) per earlier step on the same call, then filler reads so that the pending
    call comes `gap` steps after the last of them, with an owner request naming the save."""
    raw = copy.deepcopy(case["fixture"])
    raw["request"]["text"] = "save the tidy-downloads skill"
    raw["new_inputs"] = []
    history = [_step(i + 1, call, d, **extra) for i, (d, extra) in enumerate(denied)]
    for _ in range(gap - 1):
        n = len(history) + 1
        read = {
            "tool": "read_file",
            "tool_kind": "file_read",
            "arguments": {"path": f"/home/me/workspace/notes-{n}.md"},
        }
        history.append(_step(n, read, "allowed"))
    raw["history"] = history
    raw["session"]["step"] = len(history) + 1
    raw["pending_call"].update(
        {"call_id": f"c{len(history) + 1}", "provider": {"kind": "host"}, **copy.deepcopy(call)}
    )
    res = scanner(answers or BENIGN_ANSWERS, params=PARAMS).scan(
        raw, options(case, probes_enabled=PROBES)
    )
    return res.response


def _codes(resp) -> list[str]:
    return [r.code for r in resp.reasons]


def _retry_signal(resp) -> float:
    """The retry suspicion as scored, from the response's risk tree."""
    return resp.model_dump(mode="json")["tree"]["suspicion"]["retry_after_denial"]


def _retry(resp) -> dict | None:
    return resp.metadata.versions.get("unanswered_retry")


def assert_asks(resp) -> None:
    """Held at review by the cap: the retry alone took it to the block line, the ceiling brings it back."""
    assert resp.risk >= 80, "the retry should still score as before"
    assert resp.ceiling == "review" and resp.enforced is None
    assert decide(resp) == "review"
    assert _codes(resp)[0] == "cap.unanswered_retry"
    assert _retry(resp)["capped"] is True
    assert _retry(resp)["risk_without_retry"] < 80


def assert_blocks(resp) -> None:
    assert resp.ceiling is None and decide(resp) == "block"
    assert "cap.unanswered_retry" not in _codes(resp)


# ---- must stay silent: no block from the retry alone ------------------------------------------------------------


def test_skill_save_retried_after_a_timed_out_review_asks(attack_case):
    assert_asks(scan(attack_case, [("review_timed_out", {})]))


def test_skill_save_retried_after_the_review_loop_denied_it_asks(attack_case):
    assert_asks(scan(attack_case, [("blocked", LOOP)]))


def test_memory_save_retried_after_a_timed_out_review_asks(attack_case):
    assert_asks(scan(attack_case, [("review_timed_out", {})], MEMORY))


def test_several_unanswered_reviews_still_only_ask(attack_case):
    assert_asks(scan(attack_case, [("review_timed_out", {}), ("blocked", LOOP)]))


def test_a_later_retry_already_under_the_block_line_never_blocks(attack_case):
    resp = scan(attack_case, [("review_timed_out", {})], gap=6)
    assert 45 <= resp.risk < 80
    assert decide(resp) == "review"
    # a plugin with a lower block line is held at review too
    assert decide(resp, block_at=50) == "review"


def test_the_cap_keeps_the_retry_score(attack_case):
    resp = scan(attack_case, [("review_timed_out", {})])
    assert _retry_signal(resp) == 1.0 and "retry.same_action" in _codes(resp)


def test_a_degraded_scan_sets_no_cap(attack_case):
    """With a probe failed, the risk without the retry rests on partial evidence: the block stands."""
    from test_converge_scan import scanner as make

    raw = copy.deepcopy(attack_case["fixture"])
    raw["request"]["text"] = "save the tidy-downloads skill"
    raw["new_inputs"] = []
    raw["history"] = [_step(1, SKILL, "review_timed_out")]
    raw["session"]["step"] = 2
    raw["pending_call"].update(
        {"call_id": "c2", "provider": {"kind": "host"}, **copy.deepcopy(SKILL)}
    )
    raw_resp = (
        make(BENIGN_ANSWERS, error=RuntimeError("model down"), params=PARAMS)
        .scan(raw, options(attack_case, probes_enabled=PROBES))
        .response
    )
    assert raw_resp.status.value == "degraded"
    assert raw_resp.risk >= 80
    assert _retry(raw_resp) == {
        "risk_without_retry": _retry(raw_resp)["risk_without_retry"],
        "capped": False,
        "withheld": "degraded",
    }
    assert raw_resp.ceiling is None


def test_an_unanswered_retry_is_not_a_strong_signal_in_an_attended_chat(attack_case):
    resp = scan(attack_case, [("review_timed_out", {})])
    assert resp.metadata.versions["attended_owner"]["attended"] is True
    assert "retry_after_denial" not in resp.metadata.versions["attended_owner"]["strong"]


# ---- must fire: stays strict ------------------------------------------------------------------------------------


@pytest.mark.parametrize("call", [SKILL, MEMORY], ids=["skill", "memory"])
def test_retry_after_the_owner_refused_still_blocks(attack_case, call):
    resp = scan(attack_case, [("denied_by_user", {})], call)
    assert resp.risk >= 80
    assert_blocks(resp)
    assert _retry(resp) is None
    assert _retry_signal(resp) == 1.0 and "retry.same_action" in _codes(resp)
    assert "retry_after_denial" in resp.metadata.versions["attended_owner"]["strong"]


def test_retry_after_the_scanner_blocked_still_blocks(attack_case):
    resp = scan(attack_case, [("blocked", {})])
    assert_blocks(resp)
    assert _retry(resp) is None
    assert _retry_signal(resp) == 1.0 and "retry.same_action" in _codes(resp)


def test_an_owner_refusal_among_the_matches_keeps_the_block(attack_case):
    assert_blocks(scan(attack_case, [("review_timed_out", {}), ("denied_by_user", {})]))
    assert_blocks(scan(attack_case, [("blocked", LOOP), ("blocked", {})]))


def test_the_review_loop_marker_only_softens_a_block(attack_case):
    """`decided_by: review_loop` names an unseen deny; on an owner's refusal it changes nothing."""
    assert_blocks(scan(attack_case, [("denied_by_user", LOOP)]))


def test_a_call_that_blocks_without_the_retry_still_blocks(attack_case):
    resp = scan(attack_case, [("review_timed_out", {})], answers=ATTACK_ANSWERS)
    assert _retry(resp)["risk_without_retry"] >= 80
    assert _retry(resp)["capped"] is False
    assert_blocks(resp)


# ---- the PlanIR marker ------------------------------------------------------------------------------------------


def test_decided_by_is_optional_and_tolerant(attack_case):
    raw = copy.deepcopy(attack_case["fixture"])
    raw["history"] = [_step(1, SKILL, "blocked", decided_by="review_loop")]
    raw["session"]["step"] = 2
    assert PlanIR.model_validate(raw).history[0].decided_by is DecidedBy.REVIEW_LOOP
    raw["history"][0]["decided_by"] = "a_future_reviewer"
    assert PlanIR.model_validate(raw).history[0].decided_by is DecidedBy.UNKNOWN
    del raw["history"][0]["decided_by"]
    assert PlanIR.model_validate(raw).history[0].decided_by is None


def test_an_unknown_decider_on_a_block_is_a_real_block(attack_case):
    assert_blocks(scan(attack_case, [("blocked", {"decided_by": "a_future_reviewer"})]))
