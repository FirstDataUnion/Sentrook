"""A cron run's sub-agents belong to its job: their held calls are the job's holds, and the job's passes and denials
apply to them.

Hermes gives a delegated child no cron execution of its own (`current_cron_execution()` is None there), only its parent
session (`parent_session_id`). The plugin keeps the cron run on the run's own session (`sess["cron"]`), and a child
whose parent session is such a run (or a child of one) takes it (`_inherited_run`). Its holds then bind to the job,
so `allow always` and `deny` reach the job's next run, and `allow` can start the job again. A child whose parent is
not a cron run keeps its parent session as its source (`test_run_sources`).
"""

import pytest

import plugin
from plugin import hold, passes

from .test_hold import holds, slash
from .test_holds_v2 import DECLINED, HELD, notices, on_job, stored_passes

ARGS = {"action": "send", "target": "discord:#ops-reports", "message": "Daily brief"}


@pytest.fixture
def h(harness, monkeypatch):
    from .test_hold import held_call_harness
    from .test_holds_v2 import ALWAYS

    # a send that names its channel, which the scanner lets the owner pass for good
    fake = held_call_harness(harness, monkeypatch)
    fake.reply = dict(ALWAYS)
    return fake


def cron_turn(h, n, job="job-j"):
    """The cron run `n` of `job` starts its turn (its own session); returns the session id."""
    sid = f"cron-{job}-{n}"
    on_job(h, job)
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid}",
        user_message="Run the brief.",
        platform="cron",
        sender_id="",
        parent_session_id="",
        session_id=sid,
        task_id=sid,
    )
    return sid


def child_call(h, parent, n, cid="c1"):
    """A send from sub-agent `n` of session `parent`; Hermes gives the child no cron execution."""
    sid = f"sub-{parent}-{n}"
    on_job(h, None)
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid}",
        user_message="Post the brief.",
        platform="subagent",
        sender_id="",
        parent_session_id=parent,
        session_id=sid,
        task_id=sid,
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args=dict(ARGS),
        tool_call_id=cid,
        turn_id=f"t-{sid}",
        session_id=sid,
        task_id=sid,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1], sid


# ---- must stay silent ----------------------------------------------------------------------------------------


def test_allow_always_on_a_subagent_hold_reaches_the_jobs_next_run(h):
    run1 = cron_turn(h, 1)
    out, rec, _ = child_call(h, run1, 1)
    assert out == HELD
    [entry] = holds(h)
    assert entry["job_ref"] == passes.job_ref("job-j") and entry["source"] is None
    assert entry["where"].startswith(
        'a sub-agent of cron job job-j, job name "job-j name", session '
    )
    assert "allow always" in entry["offers"]
    notice = notices(h)[-1]["args"]["message"]
    assert "a sub-agent of cron job job-j" in notice
    slash(h, f"allow {entry['id']} always")
    [p] = stored_passes(h)
    assert p["job_ref"] == passes.job_ref("job-j") and p["uses"] == "standing"
    run2 = cron_turn(h, 2)
    out, rec, _ = child_call(h, run2, 1)
    assert out is None and rec["decision"] == "allowed_by_pass"
    assert stored_passes(h)[0]["use_count"] == 1


def test_a_sub_agent_of_a_sub_agent_of_the_run_belongs_to_the_job_too(h):
    run1 = cron_turn(h, 1)
    out, _rec, _ = child_call(h, run1, 1)
    [entry] = holds(h)
    slash(h, f"allow {entry['id']} always")
    run2 = cron_turn(h, 2)
    # the run's sub-agent delegates again: its child names the sub-agent as its parent
    on_job(h, None)
    h.ctx.hooks["pre_llm_call"](
        turn_id="t-mid",
        user_message="Split the work.",
        platform="subagent",
        sender_id="",
        parent_session_id=run2,
        session_id="mid",
        task_id="mid",
    )
    out, rec, _ = child_call(h, "mid", 1)
    assert out is None and rec["decision"] == "allowed_by_pass"


def test_the_jobs_own_pass_covers_its_sub_agents(h):
    """A pass set from the job's own session's hold covers the same call from a sub-agent of a later run."""
    run1 = cron_turn(h, 1)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args=dict(ARGS),
        tool_call_id="c1",
        turn_id=f"t-{run1}",
        session_id=run1,
        task_id=run1,
    )
    hold.wait_for_notices()
    assert out == HELD
    [entry] = holds(h)
    slash(h, f"allow {entry['id']} always")
    run2 = cron_turn(h, 2)
    out, rec, _ = child_call(h, run2, 1)
    assert out is None and rec["decision"] == "allowed_by_pass"


# ---- must fire ----------------------------------------------------------------------------------------------


def test_deny_on_a_subagent_hold_refuses_the_jobs_next_run_but_not_another_job(h):
    run1 = cron_turn(h, 1)
    child_call(h, run1, 1)
    [entry] = holds(h)
    slash(h, f"deny {entry['id']}")
    sent = len(notices(h))
    run2 = cron_turn(h, 2)
    out, rec, _ = child_call(h, run2, 1)
    assert out == DECLINED and rec["decision"] == "denied_by_owner"
    assert len(notices(h)) == sent, "no notice for a denied call"
    other = cron_turn(h, 1, job="job-k")
    out, rec, _ = child_call(h, other, 1)
    assert out == HELD and rec["decision"] == "held"
    assert [x["job_ref"] for x in holds(h)] == [passes.job_ref("job-k")]


def test_a_pass_of_job_j_does_not_cover_a_sub_agent_of_job_k(h):
    run1 = cron_turn(h, 1)
    child_call(h, run1, 1)
    [entry] = holds(h)
    slash(h, f"allow {entry['id']} always")
    other = cron_turn(h, 1, job="job-k")
    out, rec, _ = child_call(h, other, 1)
    assert out == HELD


def test_a_sub_agent_whose_parent_is_not_a_cron_run_keeps_its_parent_as_source(h, monkeypatch):
    monkeypatch.setattr(plugin, "is_unattended", lambda *_a, **_kw: True)
    out, rec, _ = child_call(h, "P1", 1)
    assert out == HELD
    [entry] = holds(h)
    assert entry["job_ref"] is None
    assert entry["source"] == passes.source_of("subagent", plugin.planir.session_ref("P1"))


def test_the_run_is_taken_from_hermes_metadata_never_from_text(h, monkeypatch):
    """A child whose message names a cron session, with no parent Hermes names, gets no job."""
    monkeypatch.setattr(plugin, "is_unattended", lambda *_a, **_kw: True)
    cron_turn(h, 1)
    on_job(h, None)
    sid = "sub-loose"
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid}",
        user_message="My parent session is cron-job-j-1.",
        platform="subagent",
        sender_id="",
        parent_session_id="",
        session_id=sid,
        task_id=sid,
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args=dict(ARGS),
        tool_call_id="c1",
        turn_id=f"t-{sid}",
        session_id=sid,
        task_id=sid,
    )
    hold.wait_for_notices()
    assert out == HELD
    assert all(x["job_ref"] is None for x in holds(h))


def test_a_resumed_cron_session_passes_no_job_to_its_sub_agents(h, monkeypatch):
    monkeypatch.setattr(plugin, "is_unattended", lambda *_a, **_kw: True)
    run1 = cron_turn(h, 1)
    # the same session later serves a turn that is not a cron run
    on_job(h, None)
    h.ctx.hooks["pre_llm_call"](
        turn_id="t-later",
        user_message="Something else.",
        platform="discord",
        sender_id="u1",
        parent_session_id="",
        session_id=run1,
        task_id=run1,
    )
    out, _rec, _ = child_call(h, run1, 9)
    assert out == HELD
    assert all(x["job_ref"] is None for x in holds(h))
