"""`allow` on a held call of a cron job runs the job again now, and the same call goes through once in that run.

The plugin never runs the held call itself: it starts the job (`hermes cron run <job>` through Hermes's launcher, or
Hermes's own `trigger_job`), and the one-use pass is bound to that run, Hermes's first run of the job that starts
after the answer and is not the held run. When the run ends the owner gets one line on how it went. Nothing is
started, and the pass waits for the job's next run, when a guard applies. The texts are shared with the OpenClaw
plugin (`integrations/fixtures/hold/cases.json`, `run_now`).
"""

import json
import types
from datetime import UTC, datetime, timedelta

import pytest

import plugin
from plugin import hold, passes, run_now

from .conftest import FAKE_LAUNCHER
from .test_hold import FIXTURES, held_call_harness, holds, slash, turn
from .test_holds_v2 import NAMED, stored_passes

RUN_NOW = FIXTURES["run_now"]
HELD = {"action": "block", "message": FIXTURES["held_text"]}
JOB = {
    "id": "job-j",
    "name": "Daily brief",
    "prompt": "Post the daily brief to the ops channel.",
    "schedule": {"kind": "cron", "expr": "0 9 * * *"},
    "deliver": "local",
    "enabled": True,
    "state": "scheduled",
    "next_run_at": "2026-11-25T09:00:00+00:00",
    "fire_claim": None,
}


@pytest.fixture
def h(harness, monkeypatch):
    """The held-call harness with job `job-j` in Hermes's job file and starts recorded, not run (`.started`)."""
    fake = held_call_harness(harness, monkeypatch)
    fake.reply = dict(NAMED)
    fake.started = []
    fake.start_result = (True, "hermes cron run", "")

    def start(job_id, state_dir):
        fake.started.append(job_id)
        return fake.start_result

    monkeypatch.setattr(run_now, "start", start)
    write_jobs(fake, [dict(JOB)])
    return fake


def write_jobs(h, jobs):
    (h.dir / "cron").mkdir(exist_ok=True)
    (h.dir / "cron" / "jobs.json").write_text(json.dumps({"jobs": jobs, "updated_at": None}))


def change_job(h, **fields):
    jobs = json.loads((h.dir / "cron" / "jobs.json").read_text())["jobs"]
    jobs[0].update(fields)
    write_jobs(h, jobs)


def in_run(h, n, job="job-j", started_at=None):
    """Hermes says the current code runs in execution `n` of cron job `job`, started at `started_at` (default now)."""
    at = started_at or datetime.now(UTC)
    run = types.SimpleNamespace(
        job_id=job,
        job_name=f"{job} name",
        execution_id=f"exec-{job}-{n}",
        source="direct",
        scheduled_instant=None,
        started_at=at.isoformat(),
        profile="default",
    )
    h.ctx.current_cron_execution = lambda: run


def call(
    h, n, job="job-j", cid="c1", target="discord:#ops-reports", tool="send_message", started_at=None
):
    """One call in run `n` of cron job `job` (each run its own session); the directive and the scan record."""
    sid = {"session_id": f"cron-{job}-{n}", "task_id": f"cron-{job}-{n}"}
    in_run(h, n, job, started_at)
    turn(h, sid=sid)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool,
        args={"action": "send", "target": target, "message": f"Daily brief {n}"},
        tool_call_id=cid,
        turn_id=f"t-{sid['session_id']}",
        **sid,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def end_run(h, n, job="job-j", started_at=None):
    """Hermes ends run `n` of `job` (`on_session_end` fires inside the run)."""
    in_run(h, n, job, started_at)
    h.ctx.hooks["on_session_end"](
        session_id=f"cron-{job}-{n}",
        completed=True,
        failed=False,
        interrupted=False,
        platform="cron",
    )
    hold.wait_for_notices()


def held(h, n=1):
    """A send held in run `n` of job-j: the hold's id."""
    out, rec = call(h, n)
    assert out == HELD
    return rec["hold"]["id"]


def notices(h):
    return [s["args"]["message"] for s in h.sent if s["name"] == "send_message"]


def runs_log(h):
    return [r for r in h.traffic() if r.get("kind") == "run_now"]


def reply_text(kind, **fields):
    return RUN_NOW["replies"][kind].format(passes="/sentrook passes", **fields)


def outcome(kind, **fields):
    return RUN_NOW["outcomes"][kind].format(**fields)


# ---- the shared texts --------------------------------------------------------------------------------------


def test_the_texts_are_the_shared_fixtures():
    assert hold.RUN_NOW_REASONS == RUN_NOW["reasons"]
    assert hold.RUN_NOW_REPLIES == RUN_NOW["replies"]
    assert hold.OUTCOMES == RUN_NOW["outcomes"]
    assert sorted(passes.ACTING_KINDS) == RUN_NOW["acting_kinds"]
    assert sorted(passes.ACTING_CATEGORIES) == RUN_NOW["acting_categories"]


@pytest.mark.parametrize("case", RUN_NOW["acts"], ids=lambda c: f"{c['tool_kind']}/{c['category']}")
def test_which_calls_act(case):
    resp = {"tool_description": {"category": case["category"]}} if case["category"] else {}
    assert passes.acts(case["tool_kind"], resp) is case["acts"]


# ---- must stay silent ----------------------------------------------------------------------------------------


def test_allow_starts_the_job_and_the_same_send_passes_once_in_that_run(h):
    hid = held(h, 1)
    [entry] = holds(h)
    assert entry["job_digest"] == run_now.digest(JOB) and entry["acted"] is False
    reply = slash(h, f"allow {hid}")
    [p] = stored_passes(h)
    assert reply == reply_text("started", job="job-j", **{"pass": p["id"]})
    assert h.started == ["job-j"]  # started at once, with no prompt of its own
    assert p["run_bound"] is True
    [start] = runs_log(h)
    assert (start["op"], start["started"], start["hold_id"], start["pass_id"]) == (
        "start",
        True,
        hid,
        p["id"],
    )
    # the started run: Hermes's next execution of the job
    out, rec = call(h, 2)
    assert out is None and rec["decision"] == "allowed_by_pass" and rec["pass"]["id"] == p["id"]
    assert stored_passes(h) == []
    end_run(h, 2)
    assert notices(h)[-1] == outcome("passed", job="job-j")
    ended = runs_log(h)[-1]
    assert (ended["op"], ended["passed"], ended["held"]) == ("ended", True, [])
    # only once: the next run is held again
    assert call(h, 3)[0] == HELD


def test_allow_on_a_hold_that_is_not_on_a_cron_job_starts_nothing(h):
    sid = {"session_id": "sub-1", "task_id": "sub-1"}
    h.ctx.current_cron_execution = lambda: None
    turn(h, platform="subagent", sid=sid)
    h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": "x"},
        tool_call_id="c1",
        turn_id="t-sub-1",
        **sid,
    )
    hold.wait_for_notices()
    [entry] = holds(h)
    reply = slash(h, f"allow {entry['id']}")
    assert reply.startswith("The next identical call from an unattended run may go through once")
    assert h.started == [] and runs_log(h) == []


def test_allow_later_starts_nothing_and_the_jobs_next_run_uses_the_pass(h):
    hid = held(h, 1)
    reply = slash(h, f"allow {hid} later")
    [p] = stored_passes(h)
    until = passes.show(passes.read_time(p["expires_at"]))
    assert reply == reply_text("later", job="job-j", until=until, **{"pass": p["id"]})
    assert h.started == [] and "run_bound" not in p
    out, rec = call(h, 2)
    assert out is None and rec["decision"] == "allowed_by_pass"


# ---- must fire ---------------------------------------------------------------------------------------------------


def test_a_started_run_that_sends_elsewhere_is_held_and_the_outcome_names_the_new_hold(h):
    hid = held(h, 1)
    slash(h, f"allow {hid}")
    h.reply = {**NAMED, "entities": {"E1": {"kind": "channel", "display": "discord:#general"}}}
    out, rec = call(h, 2, target="discord:#general")
    assert out == HELD
    new = rec["hold"]["id"]
    assert new != hid
    end_run(h, 2)
    assert notices(h)[-1] == outcome("held", job="job-j", hold=new)
    # the pass was bound to that run: it ended with it
    assert stored_passes(h) == []


def test_a_started_run_that_makes_the_call_and_another_held_one_says_both(h):
    hid = held(h, 1)
    slash(h, f"allow {hid}")
    assert call(h, 2)[0] is None
    h.reply = {**NAMED, "entities": {"E1": {"kind": "channel", "display": "discord:#general"}}}
    _out, rec = call(h, 2, cid="c2", target="discord:#general")
    end_run(h, 2)
    assert notices(h)[-1] == outcome("passed_held", job="job-j", hold=rec["hold"]["id"])


def test_a_started_run_that_does_not_make_the_call_says_so_and_drops_the_pass(h):
    hid = held(h, 1)
    slash(h, f"allow {hid}")
    end_run(h, 2)
    assert notices(h)[-1] == outcome("none", job="job-j")
    assert stored_passes(h) == []
    assert call(h, 3)[0] == HELD


def test_the_run_bound_pass_never_serves_the_held_run_or_another_job(h):
    hid = held(h, 1)
    slash(h, f"allow {hid}")
    # the held run retries: not the started run
    out, _rec = call(h, 1, cid="c2")
    assert out == HELD
    # another job's run
    out, _rec = call(h, 1, job="job-k")
    assert out == HELD
    # a run of the job that started before the answer
    out, _rec = call(h, 9, started_at=datetime.now(UTC) - timedelta(minutes=5))
    assert out == HELD
    assert len(stored_passes(h)) == 1


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda h: write_jobs(h, []), "missing"),
        (
            lambda h: change_job(
                h, enabled=False, state="paused", paused_at="2026-11-24T10:00:00+00:00"
            ),
            "paused",
        ),
        (lambda h: change_job(h, state="completed"), "terminal"),
        (
            lambda h: change_job(h, fire_claim={"at": datetime.now(UTC).isoformat(), "by": "m:1"}),
            "running",
        ),
        (lambda h: change_job(h, prompt="Post the daily brief to #general instead."), "changed"),
        (lambda h: change_job(h, deliver="discord:#general"), "changed"),
        (lambda h: (h.dir / "cron" / "jobs.json").write_text("{not json"), "unknown"),
    ],
    ids=[
        "removed",
        "paused",
        "finished",
        "running",
        "prompt edited",
        "delivery edited",
        "unreadable",
    ],
)
def test_a_job_that_cannot_be_run_now_is_not_started_and_the_reply_says_why(h, change, reason):
    hid = held(h, 1)
    change(h)
    reply = slash(h, f"allow {hid}")
    [p] = stored_passes(h)
    until = passes.show(passes.read_time(p["expires_at"]))
    assert reply == reply_text(
        "fallback", job="job-j", until=until, reason=RUN_NOW["reasons"][reason], **{"pass": p["id"]}
    )
    assert h.started == [] and "run_bound" not in p
    assert runs_log(h)[-1]["reason"] == reason
    # the pass waits for the job's next run
    change_job(h, fire_claim=None) if reason == "running" else None
    if reason not in ("unknown",):
        assert call(h, 2)[0] is None


def test_run_state_changes_do_not_count_as_a_changed_job(h):
    hid = held(h, 1)
    change_job(
        h,
        next_run_at="2026-11-26T09:00:00+00:00",
        last_run_at="2026-11-24T09:00:00+00:00",
        last_status="ok",
        fire_claim={"at": (datetime.now(UTC) - timedelta(minutes=20)).isoformat(), "by": "m:1"},
        repeat={"times": None, "completed": 3},
    )
    assert slash(h, f"allow {hid}").startswith("Running job job-j again now")
    assert h.started == ["job-j"]


def test_a_second_allow_on_the_same_hold_starts_no_second_run(h):
    hid = held(h, 1)
    slash(h, f"allow {hid}")
    assert slash(h, f"allow {hid}").startswith(f"No held call {hid}")
    assert slash(h, f"allow {hid} now").startswith(f"No held call {hid}")
    assert h.started == ["job-j"]


def test_a_hold_whose_run_had_already_sent_something_waits_unless_allow_now(h):
    # the run reads a file, then posts a status message, then makes the held send
    sid = {"session_id": "cron-job-j-1", "task_id": "cron-job-j-1"}
    h.reply = {**NAMED, "risk": 12, "tool_description": {"category": "sends_message_to_person"}}
    out, _rec = call(h, 1, cid="c0", target="discord:#status")
    assert out is None
    h.ctx.hooks["post_tool_call"](
        tool_name="send_message",
        args={},
        result='{"success": true}',
        tool_call_id="c0",
        status="ok",
        **sid,
    )
    h.reply = dict(NAMED)
    out, rec = call(h, 1, cid="c1")
    assert out == HELD
    assert rec["hold"]["offers"] == ["allow", "allow now", "deny"]
    [entry] = holds(h)
    assert entry["acted"] is True
    hid = entry["id"]
    reply = slash(h, f"allow {hid}")
    [p] = stored_passes(h)
    until = passes.show(passes.read_time(p["expires_at"]))
    assert reply == reply_text(
        "fallback",
        job="job-j",
        until=until,
        reason=RUN_NOW["reasons"]["acted"],
        **{"pass": p["id"]},
    )
    assert h.started == []


def test_allow_now_runs_the_whole_job_again_with_a_warning(h):
    sid = {"session_id": "cron-job-j-1", "task_id": "cron-job-j-1"}
    h.reply = {**NAMED, "risk": 12, "tool_description": {"category": "writes_local_files"}}
    call(h, 1, cid="c0", tool="write_file")
    h.ctx.hooks["post_tool_call"](
        tool_name="write_file", args={}, result="ok", tool_call_id="c0", status="ok", **sid
    )
    h.reply = dict(NAMED)
    _out, rec = call(h, 1, cid="c1")
    hid = rec["hold"]["id"]
    reply = slash(h, f"allow {hid} now")
    [p] = stored_passes(h)
    assert reply == reply_text("started_now", job="job-j", **{"pass": p["id"]})
    assert h.started == ["job-j"]


def test_an_earlier_call_that_did_not_run_does_not_count_as_acted(h):
    h.reply = {**NAMED, "tool_description": {"category": "sends_message_to_person"}}
    assert call(h, 1, cid="c0", target="discord:#status")[0] == HELD  # held: it never ran
    h.reply = {**NAMED, "entities": {"E1": {"kind": "channel", "display": "discord:#general"}}}
    _out, rec = call(h, 1, cid="c1", target="discord:#general")
    assert holds(h)[-1]["acted"] is False
    assert "allow later" in rec["hold"]["offers"]


def test_observe_mode_starts_nothing(h):
    hid = held(h, 1)
    h.ctx.settings["mode"] = "observe"
    reply = slash(h, f"allow {hid}")
    assert f"It was not run again now: {RUN_NOW['reasons']['observe']}." in reply
    assert h.started == []


@pytest.mark.parametrize(
    ("result", "reason"),
    [
        ((False, "trigger_job", "unavailable"), "unavailable"),
        ((False, "hermes cron run", "boom"), "failed"),
    ],
)
def test_a_run_that_cannot_be_started_leaves_the_pass_for_the_next_run(h, result, reason):
    hid = held(h, 1)
    h.start_result = result
    reply = slash(h, f"allow {hid}")
    assert f"It was not run again now: {RUN_NOW['reasons'][reason]}." in reply
    [p] = stored_passes(h)
    assert "run_bound" not in p
    assert passes.load(h.dir / "sentrook").get("runs") == []
    assert call(h, 2)[0] is None


def test_without_a_run_end_the_jobs_next_scan_sends_the_outcome(h):
    hid = held(h, 1)
    slash(h, f"allow {hid}")
    assert call(h, 2)[0] is None  # the started run, whose end Hermes never reported
    call(h, 3)
    assert outcome("passed", job="job-j") in notices(h)


# ---- starting the job ------------------------------------------------------------------------------------------


def test_the_job_starts_with_hermes_cron_run_through_the_launcher(tmp_path, monkeypatch):
    seen = {}

    class Popen:
        def __init__(self, argv, **kw):
            seen["argv"], seen["kw"] = argv, kw

        def poll(self):
            return None

        def wait(self, timeout=None):
            if timeout is not None:  # still running when the plugin stops waiting
                raise run_now.subprocess.TimeoutExpired("hermes", timeout)
            return 0

    monkeypatch.setattr(hold, "_hermes_launcher", lambda: FAKE_LAUNCHER)
    monkeypatch.setattr(hold, "_other_home", lambda: None)
    monkeypatch.setattr(run_now.subprocess, "Popen", Popen)
    monkeypatch.setenv("HERMES_CRON_AUTO_DELIVER_PLATFORM", "discord")
    assert run_now.start("job-j", tmp_path) == (True, "hermes cron run", "")
    assert seen["argv"] == [FAKE_LAUNCHER, "cron", "run", "job-j"]  # no prompt of its own
    env = seen["kw"]["env"]
    assert env["HERMES_GATEWAY_PROFILE_PIN"] == "1"
    assert not any(k.startswith("HERMES_CRON_AUTO_DELIVER_") for k in env)
    assert seen["kw"]["start_new_session"] is True


def test_without_the_launcher_hermes_trigger_job_marks_it_due(tmp_path, monkeypatch):
    calls = []
    fake = types.ModuleType("cron.jobs")
    fake.trigger_job = lambda job_id, extra_prompt=None: (
        calls.append((job_id, extra_prompt)) or {"id": job_id}
    )
    monkeypatch.setitem(__import__("sys").modules, "cron", types.ModuleType("cron"))
    monkeypatch.setitem(__import__("sys").modules, "cron.jobs", fake)
    monkeypatch.setattr(hold, "_hermes_launcher", lambda: None)
    assert run_now.start("job-j", tmp_path) == (True, "trigger_job", "")
    assert calls == [("job-j", None)]


def test_with_neither_it_cannot_start(tmp_path, monkeypatch):
    monkeypatch.setattr(hold, "_hermes_launcher", lambda: None)
    monkeypatch.setitem(__import__("sys").modules, "cron.jobs", None)
    assert run_now.start("job-j", tmp_path) == (False, "trigger_job", "unavailable")


def test_the_plugin_registers_the_run_end_hook(h):
    assert h.ctx.hooks["on_session_end"] is plugin.on_session_end


@pytest.mark.parametrize(
    ("code", "out", "want"),
    [
        (
            1,
            "Failed to run job: Job not found\n",
            (False, "hermes cron run exit 1: Failed to run job: Job not found"),
        ),
        (
            0,
            "Triggered job: x (job-j)\n  Already being fired by the scheduler; not run again.\n",
            (False, "running"),
        ),
        (0, "Triggered job: x (job-j)\n  Job is paused; not run.\n", (False, "paused")),
        (1, "Triggered job: x (job-j)\n  Ran now: failed.\n", (True, "")),
        (0, "Triggered job: x (job-j)\n  Ran now: succeeded.\n", (True, "")),
        (2, "Traceback: boom\n", (False, "hermes cron run exit 2: Traceback: boom")),
    ],
    ids=["refused", "already being fired", "paused", "ran and failed", "ran", "crashed"],
)
def test_what_hermes_cron_run_printed_decides_whether_the_run_started(
    tmp_path, monkeypatch, code, out, want
):
    """Hermes exits 0 for a skipped run and 1 for a run that ran and failed: the output decides."""

    class Popen:
        def __init__(self, argv, stdout=None, **kw):
            stdout.write(out.encode())
            stdout.flush()

        def wait(self, timeout=None):
            return code

        def poll(self):
            return code

    (tmp_path / "run-now.log").write_text(
        "Failed to run job: an earlier command\n"
    )  # not this command's output
    monkeypatch.setattr(hold, "_hermes_launcher", lambda: FAKE_LAUNCHER)
    monkeypatch.setattr(hold, "_other_home", lambda: None)
    monkeypatch.setattr(run_now.subprocess, "Popen", Popen)
    ok, how, why = run_now.start("job-j", tmp_path)
    assert (ok, why) == want and how == "hermes cron run"


def test_a_skipped_run_is_the_replys_reason(h):
    hid = held(h, 1)
    h.start_result = (False, "hermes cron run", "running")
    reply = slash(h, f"allow {hid}")
    assert f"It was not run again now: {RUN_NOW['reasons']['running']}." in reply


def test_a_job_unreadable_at_the_first_notice_stays_unknown_after_a_repeat(h):
    (h.dir / "cron" / "jobs.json").write_text("{not json")
    hid = held(h, 1)
    write_jobs(h, [dict(JOB)])
    _out, rec = call(h, 2)
    assert rec["hold"]["repeat"] is True
    reply = slash(h, f"allow {hid}")
    assert f"It was not run again now: {RUN_NOW['reasons']['unknown']}." in reply
    assert h.started == []


def test_a_started_run_whose_end_was_never_seen_does_not_capture_a_later_one(h):
    first = held(h, 1)
    slash(h, f"allow {first}")
    # the started run never reported its end; two hours later another answer starts the job again
    data = json.loads((h.dir / "sentrook" / "passes.json").read_text())
    for r in data["runs"]:
        r["requested_at"] = (datetime.now(UTC) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (h.dir / "sentrook" / "passes.json").write_text(json.dumps(data))
    h.reply = {**NAMED, "entities": {"E1": {"kind": "channel", "display": "discord:#general"}}}
    _out, rec = call(h, 3, target="discord:#general")
    second = rec["hold"]["id"]
    assert slash(h, f"allow {second}").startswith("Running job job-j again now")
    runs = json.loads((h.dir / "sentrook" / "passes.json").read_text())["runs"]
    assert [r["hold_id"] for r in runs if not r.get("ended")] == [second]
    # the new started run uses the new answer's pass
    out, rec = call(h, 4, target="discord:#general")
    assert out is None and rec["decision"] == "allowed_by_pass"


def test_two_holds_of_one_job_allowed_back_to_back_start_one_run(h):
    first = held(h, 1)
    h.reply = {**NAMED, "entities": {"E1": {"kind": "channel", "display": "discord:#general"}}}
    _out, rec = call(h, 1, cid="c2", target="discord:#general")
    second = rec["hold"]["id"]
    assert slash(h, f"allow {first}").startswith("Running job job-j again now")
    reply = slash(h, f"allow {second}")
    assert f"It was not run again now: {RUN_NOW['reasons']['running']}." in reply
    assert h.started == ["job-j"]
    # once the started run has ended, another answer may start the job again
    end_run(h, 2)
    h.reply = dict(NAMED)
    third = held(h, 3)
    assert slash(h, f"allow {third}").startswith("Running job job-j again now")
    assert h.started == ["job-j", "job-j"]


def test_a_job_edited_after_the_first_notice_counts_as_changed_even_after_a_repeat(h):
    hid = held(h, 1)
    change_job(h, prompt="Post the daily brief to #general instead.")
    _out, rec = call(h, 2)  # the same call held again: a repeat of the waiting hold
    assert rec["hold"]["repeat"] is True and rec["hold"]["id"] == hid
    reply = slash(h, f"allow {hid}")
    assert f"It was not run again now: {RUN_NOW['reasons']['changed']}." in reply
    assert h.started == []


# ---- a cron run's sub-agents ----------------------------------------------------------------------------------


def child_call(h, n, job="job-j", started_at=None):
    """A send from a sub-agent of run `n` of `job`: the run's session starts its turn in the run, then the child's
    own turn and call, where Hermes gives no cron execution."""
    parent = f"cron-{job}-{n}"
    in_run(h, n, job, started_at)
    turn(h, sid={"session_id": parent, "task_id": parent})
    h.ctx.current_cron_execution = lambda: None
    sid = f"sub-{parent}"
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
        args={"action": "send", "target": "discord:#ops-reports", "message": f"Daily brief {n}"},
        tool_call_id="c1",
        turn_id=f"t-{sid}",
        session_id=sid,
        task_id=sid,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def test_allow_on_a_sub_agents_hold_starts_the_job_and_its_sub_agent_passes_once(h):
    out, rec = child_call(h, 1)
    assert out == HELD
    hid = rec["hold"]["id"]
    assert "allow" in rec["hold"]["offers"]
    slash(h, f"allow {hid}")
    assert h.started == ["job-j"], "the job is started again"
    out, rec = child_call(h, 2, started_at=datetime.now(UTC) + timedelta(seconds=5))
    assert out is None and rec["decision"] == "allowed_by_pass"
    out, rec = child_call(h, 3, started_at=datetime.now(UTC) + timedelta(seconds=10))
    assert out == HELD, "the pass was used up in the started run"
