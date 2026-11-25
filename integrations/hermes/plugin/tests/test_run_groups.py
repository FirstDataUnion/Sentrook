"""One notice per cron run: the run's first hold sends the notice, later holds of other actions in the same run join its
group, and the run's end sends one line listing them. `allow <lead> all` answers the lead and every call a line
listed, in one started run; a call that itself sends or writes is left for its own answer. The texts are shared with
the OpenClaw plugin (`integrations/fixtures/hold/cases.json`, `run_group`).
"""

from datetime import UTC, datetime, timedelta

from plugin import hold

from . import test_run_now
from .test_hold import FIXTURES, holds, slash, turn
from .test_holds_v2 import HELD, NAMED
from .test_run_now import end_run, in_run, notices

#: The run-now harness (job `job-j` in Hermes's job file, starts recorded, not run).
h = test_run_now.h

GROUP = {k: v for k, v in FIXTURES["run_group"].items() if not k.startswith("_")}
#: The scanner's category for each tool's call: only the send's call itself sends or writes (`passes.acts`).
CATEGORY = {
    "terminal": "runs_code_or_installer",
    "web_extract": "fetches_remote_content",
    "read_file": "reads_local_data",
    "send_message": "sends_data_off_host",
}


def call(h, n, tool, cid, job="job-j", started_at=None):
    """One call of `tool` in run `n` of `job`; the directive and the scan record. Each tool is a different action."""
    sid = {"session_id": f"cron-{job}-{n}", "task_id": f"cron-{job}-{n}"}
    h.reply = {**NAMED, "tool_description": {"category": CATEGORY[tool], "template": "Runs {E1}"}}
    in_run(h, n, job, started_at)
    turn(h, sid=sid)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool,
        args={"command": f"step {cid}", "url": "https://example.test/a"},
        tool_call_id=cid,
        turn_id=f"t-{sid['session_id']}",
        **sid,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def three_holds(h, n=1, started_at=None):
    """Run `n` holds three different calls: an exec, a web fetch and a send. Returns their hold ids."""
    ids = []
    for i, tool in enumerate(("terminal", "web_extract", "send_message")):
        out, rec = call(h, n, tool, f"c{i}", started_at=started_at)
        assert out == HELD
        ids.append(rec["hold"]["id"])
    return ids


def test_the_texts_are_the_shared_fixtures():
    assert hold.RUN_GROUP == GROUP


# ---- must stay silent: one notice ------------------------------------------------------------------------------


def test_a_run_that_holds_three_calls_sends_one_notice_and_one_end_line(h):
    lead, second, third = three_holds(h)
    assert len(notices(h)) == 1, "only the run's first hold sends a notice"
    by_id = {x["id"]: x for x in holds(h)}
    assert by_id[second]["lead"] == lead and by_id[third]["lead"] == lead
    assert by_id[lead]["group"] == [second, third]
    assert by_id[third]["acts"] is True and by_id[second]["acts"] is False
    end_run(h, 1)
    sent = notices(h)
    assert len(sent) == 2
    line = sent[-1]
    assert line.splitlines()[0] == GROUP["head"].format(job="job-j", n=2, lead=lead)
    assert f"- {second}: web_extract: " in line
    assert f"- {third}: send_message: " in line and line.count(GROUP["own_answer"]) == 1
    assert GROUP["all"].format(allow="/sentrook allow", lead=lead) in line
    [rec] = [r for r in h.traffic() if r.get("kind") == "run_group"]
    assert rec["lead"] == lead and rec["listed"] == [second, third]
    end_run(h, 1)
    assert len(notices(h)) == 2, "a run's end line goes out once"


def test_allow_all_after_the_end_line_lets_the_listed_calls_through_in_one_started_run(h):
    lead, second, third = three_holds(h)
    end_run(h, 1)
    reply = slash(h, f"allow {lead} all")
    assert h.started == ["job-j"], "one run is started"
    assert GROUP["covered"].format(ids=second) in reply
    assert GROUP["left"].format(ids=third) in reply
    assert [x["id"] for x in holds(h)] == [third], "the send is left for its own answer"
    later = datetime.now(UTC) + timedelta(seconds=5)
    out, rec = call(h, 2, "terminal", "c0", started_at=later)
    assert out is None and rec["decision"] == "allowed_by_pass"
    out, rec = call(h, 2, "web_extract", "c1", started_at=later)
    assert out is None and rec["decision"] == "allowed_by_pass"
    out, rec = call(h, 2, "send_message", "c2", started_at=later)
    assert out == HELD, "not covered by all"


# ---- must fire --------------------------------------------------------------------------------------------------


def test_allow_before_the_end_line_covers_only_the_first_call(h):
    lead, second, _third = three_holds(h)
    reply = slash(h, f"allow {lead} all")
    assert GROUP["none_listed"].format(lead=lead) in reply
    later = datetime.now(UTC) + timedelta(seconds=5)
    out, rec = call(h, 2, "terminal", "c0", started_at=later)
    assert out is None and rec["decision"] == "allowed_by_pass"
    out, rec = call(h, 2, "web_extract", "c1", started_at=later)
    assert out == HELD, "never shown to the owner, so not covered"
    assert second in {x["id"] for x in holds(h)}


def test_a_call_held_after_the_end_line_gets_a_notice_of_its_own(h):
    three_holds(h)
    end_run(h, 1)
    before = len(notices(h))
    out, rec = call(h, 1, "read_file", "c9")
    assert out == HELD
    assert len(notices(h)) == before + 1
    assert "lead" not in {x["id"]: x for x in holds(h)}[rec["hold"]["id"]]


def test_a_group_member_cannot_answer_for_the_group(h):
    lead, second, _third = three_holds(h)
    end_run(h, 1)
    reply = slash(h, f"allow {second} all")
    assert reply == GROUP["not_lead"].format(id=second, lead=lead, allow="/sentrook allow")
    assert h.started == []


def test_the_next_run_gets_its_own_notice(h):
    three_holds(h)
    end_run(h, 1)
    before = len(notices(h))
    out, _rec = call(h, 2, "read_file", "c5", started_at=datetime.now(UTC) + timedelta(seconds=5))
    assert out == HELD
    assert len(notices(h)) == before + 1


def test_two_jobs_keep_separate_groups(h):
    call(h, 1, "terminal", "c0")
    call(h, 1, "terminal", "c0", job="job-k")
    assert len(notices(h)) == 2


def test_a_run_whose_end_was_not_seen_gets_its_end_line_when_the_next_run_holds(h):
    lead, second, third = three_holds(h)
    before = len(notices(h))
    call(h, 2, "read_file", "c5", started_at=datetime.now(UTC) + timedelta(seconds=5))
    sent = notices(h)[before:]
    assert len(sent) == 2, "the earlier run's end line, then the new run's notice"
    assert sent[0].splitlines()[0] == GROUP["head"].format(job="job-j", n=2, lead=lead)


def test_a_sub_agent_of_the_run_joins_the_runs_group(h):
    from .test_run_now import child_call

    lead_out, lead_rec = call(h, 1, "terminal", "c0")
    out, rec = child_call(h, 1)
    assert out == HELD
    assert {x["id"]: x for x in holds(h)}[rec["hold"]["id"]]["lead"] == lead_rec["hold"]["id"]
    assert len(notices(h)) == 1
