"""The background review's own auto-deny is not the owner's denial.

On the local terminal Hermes's background review answers every approval prompt itself: its thread's
approval callback says deny without asking anyone, because the fork cannot reach the terminal. Hermes
fires `post_approval_response` on that thread, so the write origin is still `background_review`, the
surface is `cli`, the thread's callback is the review's auto-deny, and no gateway notifier is registered.
That answer is recorded as `blocked` (what a review nobody can answer is), never `denied_by_user`, and
history says "auto-denied by the review loop". A denial a person could have given (another surface, a
gateway route, no auto-deny callback) or of an ordinary call is still the owner's.
"""

import io
import sys

import pytest

from plugin import history

SID = {"session_id": "S1", "task_id": "S1"}
SAVE = ("skill_manage", {"action": "create", "name": "tidy", "content": "# Tidy\nSteps."})
AUTO = "auto-denied by the review loop"


class Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def h(loop_h, review_fork, monkeypatch):
    """The local terminal, with a scanner that asks for a review; `.fork` is Hermes's approval plumbing."""
    monkeypatch.setattr(sys, "stdin", Tty())
    loop_h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="keep replies short", platform="cli", sender_id="u1", **SID
    )
    loop_h.reply.update(risk=55)
    loop_h.fork = review_fork
    return loop_h


def ask(h, tool, args):
    n = len(h.scans)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool, args=args, tool_call_id=f"c{n}", turn_id="t1", **SID
    )
    assert out["action"] == "approve"
    return out["rule_key"]


def answer(h, key, choice, surface="cli"):
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{key}",
        choice=choice,
        surface=surface,
        session_key="agent:main:cli:S1",
        **SID,
    )


def next_history(h):
    """The history the next scan sends."""
    h.reply.update(risk=5)
    h.ctx.hooks["pre_tool_call"](
        tool_name="read_file", args={"path": "notes.md"}, tool_call_id="last", turn_id="t1", **SID
    )
    return h.scans[-1]["history"]


def resolution(h):
    return [r for r in h.traffic() if r.get("kind") == "resolution"][-1]


def shown(h):
    path = h.dir / "sentrook" / "traffic.jsonl"
    scan, res = history.recent_scans(path, 10, None)[-1]
    return history.review_of(history.action_of(scan, res), res), history.format_why(scan, res)


# ---- must fire ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("attended", [False, True], ids=["loop", "refine"])
def test_the_review_loops_auto_deny_on_the_terminal_is_not_the_owners(h, attended):
    """The automatic review and an owner's /refine both run in the fork, whose callback denies unseen."""
    h.prov["attended"] = attended
    key = ask(h, *SAVE)
    answer(h, key, "deny")
    assert next_history(h)[0]["decision"] == "blocked"
    res = resolution(h)
    assert (res["resolution"], res["decision"], res["decided_by"]) == (
        "deny",
        "blocked",
        "review_loop",
    )
    review, why = shown(h)
    assert review == AUTO
    assert f"review: {AUTO}" in why.splitlines()


def test_any_call_the_fork_makes_is_covered_not_only_saves(h):
    """A terminal call the review fork makes is asked about the same way and auto-denied the same way."""
    key = ask(h, "terminal", {"command": "ls skills"})
    answer(h, key, "deny")
    assert next_history(h)[0]["decision"] == "blocked"
    assert shown(h)[0] == AUTO


def test_a_scan_error_review_auto_denied_is_labelled_too(h, monkeypatch):
    from plugin.scan_error_policy import ScanFailure

    monkeypatch.setattr(
        "plugin.post_scan",
        lambda **_kw: ScanFailure(ok=False, kind="http", status=500, detail="boom"),
    )
    key = ask(h, *SAVE)
    assert key.startswith("sentrook:error:")
    answer(h, key, "deny")
    res = resolution(h)
    assert (res["decision"], res["decided_by"]) == ("blocked_on_error", "review_loop")
    assert shown(h)[0] == AUTO


# ---- must stay silent --------------------------------------------------------------------------------------


def test_an_owner_denial_of_an_ordinary_call_is_still_denied_by_user(h):
    h.prov["origin"] = "assistant_tool"
    key = ask(h, "terminal", {"command": "rm -rf build"})
    answer(h, key, "deny")
    assert next_history(h)[0]["decision"] == "denied_by_user"
    res = resolution(h)
    assert res["decision"] == "denied_by_user" and "decided_by" not in res
    assert shown(h)[0] == "denied"


@pytest.mark.parametrize("surface", ["gateway", "transport:slack", "", None])
def test_a_denial_on_another_surface_is_the_owners(h, surface):
    """Off the terminal a person may have answered the fork's prompt: the denial stays theirs."""
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="keep replies short", platform="telegram", sender_id="u1", **SID
    )
    key = ask(h, *SAVE)
    if surface is None:
        h.ctx.hooks["post_approval_response"](
            pattern_key=f"plugin_rule:{key}", choice="deny", **SID
        )
    else:
        answer(h, key, "deny", surface)
    assert next_history(h)[0]["decision"] == "denied_by_user"
    assert "decided_by" not in resolution(h)
    assert shown(h)[0] == "denied"


def test_a_gateway_routed_prompt_answered_on_the_terminal_is_the_owners(h):
    """Hermes's managed local runtime routes the fork's prompt through a gateway notifier to the person at
    the terminal, and still reports the `cli` surface: their deny is theirs."""
    h.fork.notifiers.add("agent:main:cli:S1")
    key = ask(h, *SAVE)
    answer(h, key, "deny")
    assert next_history(h)[0]["decision"] == "denied_by_user"
    assert "decided_by" not in resolution(h)


@pytest.mark.parametrize("callback", [None, "other"], ids=["no-callback", "another-callback"])
def test_a_prompt_without_the_review_auto_deny_is_the_owners(h, callback):
    """`hermes curator run` in the foreground has no callback and asks on the terminal itself; any other
    callback is a person's prompt too."""
    h.fork.callback = callback
    key = ask(h, *SAVE)
    answer(h, key, "deny")
    assert next_history(h)[0]["decision"] == "denied_by_user"
    assert "decided_by" not in resolution(h)


def test_a_hook_without_a_session_key_is_the_owners(h):
    key = ask(h, *SAVE)
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{key}", choice="deny", surface="cli", **SID
    )
    assert next_history(h)[0]["decision"] == "denied_by_user"


@pytest.mark.parametrize(
    "missing", ["tools.approval", "tools.terminal_tool", "agent.background_review"]
)
def test_without_hermes_approval_plumbing_the_denial_is_the_owners(h, monkeypatch, missing):
    key = ask(h, *SAVE)
    monkeypatch.setitem(sys.modules, missing, None)
    answer(h, key, "deny")
    assert next_history(h)[0]["decision"] == "denied_by_user"


@pytest.mark.parametrize(
    ("choice", "decision", "review"),
    [("timeout", "review_timed_out", "timed out"), ("cancelled", "blocked", "cancelled")],
)
def test_other_unanswered_outcomes_in_the_fork_are_unchanged(h, choice, decision, review):
    key = ask(h, *SAVE)
    answer(h, key, choice)
    assert next_history(h)[0]["decision"] == decision
    assert "decided_by" not in resolution(h)
    assert shown(h)[0] == review


def test_an_unreadable_write_origin_leaves_the_denial_as_it_was(h, monkeypatch):
    """A host without the write origin has no review loop to recognise."""
    key = ask(h, *SAVE)
    monkeypatch.setitem(sys.modules, "tools.skill_provenance", None)
    answer(h, key, "deny")
    assert next_history(h)[0]["decision"] == "denied_by_user"


# ---- history ---------------------------------------------------------------------------------------------


def test_history_labels_only_the_review_loop():
    scan = {"verdict": "review", "decision": "review_timed_out", "response": {}, "mode": "enforce"}
    auto = {"resolution": "deny", "decided_by": "review_loop"}
    assert history.review_of(history.action_of(scan, auto), auto) == AUTO
    other = {"resolution": "deny", "decided_by": "someone_else"}
    assert history.review_of(history.action_of(scan, other), other) == "denied"
