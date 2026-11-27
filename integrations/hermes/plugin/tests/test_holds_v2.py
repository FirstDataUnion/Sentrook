"""Answers to a held call each do something: `allow` lets the job's next run make the call once, `allow always` lets
the job make it for 30 days, `deny` refuses it on the job for 30 days with no more notices.

A pass or denial is bound to the cron job Hermes names for the run (`current_cron_execution().job_id`) and to the
action, matched on the same terms as a Session answer: same tool, same parties, risk no higher, no new warning, not
enforced, no floor, and the scan's `owner_pass` at or above the pass's level. The matching table is shared with the
OpenClaw plugin (`integrations/fixtures/hold/cases.json`, `passes`).
"""

import json
import types
from datetime import UTC, datetime, timedelta

import pytest

import plugin
from plugin import hold, passes, session_allow

from .conftest import refusals
from .test_hold import ABSENT, FIXTURES, held_call_harness, holds, resolutions, slash, turn

FP = "afp1:message_send|ch:discord:#ops-reports"
#: A scan the scanner lets the owner pass for good: a send that names its channel.
ALWAYS = {
    "risk": 47,
    "enforced": None,
    "owner_pass": "always",
    "approval_fingerprint": FP,
    "reasons": [{"code": "trigger.scheduled"}, {"code": "send.unbound_channel", "subject": "E1"}],
}
#: The same send when the scanner offers it once: allow once and deny.
NAMED = {**ALWAYS, "owner_pass": "once"}
#: The same send from a scanner that sends no `owner_pass` (it predates it): no pass, deny only.
MISSING = {**ALWAYS, "owner_pass": ABSENT}
OTHER_CHANNEL = {"E1": {"kind": "channel", "display": "discord:#general"}}


def on_job(h, job="job-j"):
    """The run Hermes says is cron job `job` (None: not a cron job)."""
    run = types.SimpleNamespace(job_id=job, job_name=f"{job} name") if job else None
    h.ctx.current_cron_execution = lambda: run


def run(h, n, job="job-j", cid="c1"):
    """One send in run `n` of cron job `job` (each run its own session); the directive and the scan record."""
    sid = {"session_id": f"cron-{job}-{n}", "task_id": f"cron-{job}-{n}"}
    on_job(h, job)
    turn(h, sid=sid)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": f"Daily brief {n}"},
        tool_call_id=cid,
        turn_id=f"t-{sid['session_id']}",
        **sid,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def stored_passes(h):
    path = h.dir / "sentrook" / "passes.json"
    return json.loads(path.read_text())["passes"] if path.exists() else []


def notices(h):
    return [s for s in h.sent if s["name"] == "send_message"]


HELD = {"action": "block", "message": FIXTURES["held_text"]}


@pytest.fixture
def h(harness, monkeypatch):
    """The held-call harness (`test_hold`), its scanner answering with a send that names its channel."""
    fake = held_call_harness(harness, monkeypatch)
    fake.reply = dict(NAMED)
    return fake


DECLINED = {"action": "block", "message": FIXTURES["declined_text"]}


# ---- must stay silent ----------------------------------------------------------------------------------------


def test_allow_lets_the_jobs_next_run_make_the_same_send_once(h):
    """With no job in Hermes's job file nothing is started (`test_run_now`): the pass waits for the next run."""
    out, rec = run(h, 1)
    assert out == HELD
    hid = rec["hold"]["id"]
    assert rec["hold"]["offers"] == [
        "allow",
        "allow later",
        "deny",
    ]  # the scanner offers it once: never always
    reply = slash(h, f"allow {hid}")
    assert reply.startswith("Job job-j may make this call once, on its next scheduled run, until ")
    assert "It was not run again now: the job no longer exists." in reply
    [p] = stored_passes(h)
    assert (p["kind"], p["uses"], p["level"], p["job_id"]) == ("allow", "once", "once", "job-j")
    assert holds(h) == []
    out, rec = run(h, 2)
    assert out is None and rec["decision"] == "allowed_by_pass"
    assert rec["pass"]["id"] == p["id"] and rec["pass"]["kind"] == "allow"
    assert stored_passes(h) == []  # used up
    out, rec = run(h, 3)
    assert out == HELD and rec["decision"] == "held"


def test_allow_later_waits_for_the_jobs_next_run(h):
    _out, rec = run(h, 1)
    reply = slash(h, f"allow {rec['hold']['id']} later")
    assert reply.startswith("Job job-j may make this call once, on its next scheduled run, until ")
    assert "not run again now" not in reply
    assert run(h, 2)[0] is None


def test_allow_always_lets_three_later_runs_through_and_counts_them(h):
    h.reply = dict(ALWAYS)
    _out, rec = run(h, 1)
    hid = rec["hold"]["id"]
    assert rec["hold"]["offers"] == ["allow", "allow later", "allow always", "deny"]
    reply = slash(h, f"allow {hid} always")
    [p] = stored_passes(h)
    assert reply.startswith("Job job-j may make this call until ")
    assert f"Undo: /sentrook passes revoke {p['id']}." in reply
    assert passes.read_time(p["expires_at"]) - passes.read_time(p["set_at"]) == timedelta(days=30)
    for n in (2, 3, 4):
        out, rec = run(h, n)
        assert out is None and rec["decision"] == "allowed_by_pass"
    [p] = stored_passes(h)
    assert p["use_count"] == 3
    assert "used 3 times" in slash(h, "passes")
    assert [r["resolution"] for r in resolutions(h)] == ["hold_allowed_always"]


def test_after_allow_a_retry_in_the_same_session_is_not_a_retry_after_a_denial(h):
    """The held call's history entry becomes approved_by_user: the next scan of the session sends it so, not as a
    review nobody answered."""
    sid = {"session_id": "cron-job-j-1", "task_id": "cron-job-j-1"}
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']}")
    session = json.loads((h.dir / "sentrook" / "sessions" / "cron-job-j-1.json").read_text())
    assert session["history"][-1]["decision"] == "approved_by_user"
    on_job(h)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": "Daily brief 1"},
        tool_call_id="c2",
        turn_id="t-cron-job-j-1",
        **sid,
    )
    assert out is None
    sent = [e["decision"] for e in h.scans[-1]["history"]]
    assert "approved_by_user" in sent and "review_timed_out" not in sent


# ---- must fire -----------------------------------------------------------------------------------------------


def test_after_allow_a_send_to_another_channel_is_held(h):
    h.reply = dict(ALWAYS)
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']}")
    h.reply = {**ALWAYS, "entities": OTHER_CHANNEL}
    out, rec = run(h, 2)
    assert out == HELD
    assert len(stored_passes(h)) == 1  # not used


def test_the_same_send_from_another_job_is_held(h):
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']}")
    out, _rec = run(h, 1, job="job-k")
    assert out == HELD


@pytest.mark.parametrize(
    "later",
    [
        {"risk": 52},
        {"reasons": [*ALWAYS["reasons"], {"code": "steer.uses_steering_content"}]},
        {"enforced": "review"},
        {"floors_applied": ["send.secret_off_host"]},
        {"owner_pass": "once"},
        {"owner_pass": None},
    ],
    ids=["higher risk", "new warning", "enforced", "floor", "owner_pass once", "owner_pass null"],
)
def test_a_standing_pass_never_passes_a_riskier_call(h, later):
    h.reply = dict(ALWAYS)
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']} always")
    h.reply = {**ALWAYS, **later}
    out, rec = run(h, 2)
    assert out == HELD and rec["decision"] == "held"
    assert stored_passes(h)[0]["use_count"] == 0


@pytest.mark.parametrize(
    ("reply", "why"),
    [
        ({"owner_pass": "once"}, "for this one it offers it once"),
        ({"owner_pass": None}, "Sentrook does not offer to let this call through"),
        (
            None,
            "Sentrook does not offer to let this call through",
        ),  # no owner_pass: an older scanner
    ],
    ids=["once", "null", "missing"],
)
def test_allow_always_is_refused_with_a_reason_unless_the_scanner_offers_it(h, reply, why):
    h.reply = {**ALWAYS, **reply} if reply is not None else dict(MISSING)
    _out, rec = run(h, 1)
    hid = rec["hold"]["id"]
    assert "allow always" not in rec["hold"]["offers"]
    assert "always" not in notices(h)[-1]["args"]["message"]
    answer = slash(h, f"allow {hid} always")
    assert answer.startswith("Not ") and why in answer
    assert [x["id"] for x in holds(h)] == [hid] and stored_passes(h) == []


@pytest.mark.parametrize(
    "later",
    [{"enforced": "review"}, {"floors_applied": ["send.secret_off_host"]}, {"status": "degraded"}],
    ids=["enforced", "floor", "degraded"],
)
def test_a_hold_no_pass_could_let_through_offers_only_deny(h, later):
    """A scan the scanner enforces, floors or did not finish is never passed, so allow is not offered for it."""
    h.reply = {**ALWAYS, **later}
    _out, rec = run(h, 1)
    assert rec["hold"]["offers"] == ["deny"]
    assert "allow" not in notices(h)[-1]["args"]["message"]
    assert "does not offer to let this call through" in slash(h, f"allow {rec['hold']['id']}")


def test_a_denied_call_counts_as_blocked_on_the_dashboard(h):
    from plugin import dashboard, history

    _out, rec = run(h, 1)
    slash(h, f"deny {rec['hold']['id']}")
    _out, rec = run(h, 2)
    action = history.action_of(rec, None)
    assert action == "declined (denied by owner)" and dashboard.bucket_of(rec, action) == "blocked"


def test_two_stores_of_one_directory_share_a_sessions_lock(tmp_path):
    """An answer's history update and a scan of the same session never interleave within a process."""
    from plugin.store import Store

    a, b = Store(tmp_path), Store(tmp_path)
    with a.session_lock("s1"):
        got = []
        t = __import__("threading").Thread(
            target=lambda: got.append(b.session_lock("s1").__enter__())
        )
        t.start()
        t.join(0.2)
        assert t.is_alive()  # waits for the first
    t.join(1)
    assert not t.is_alive()


def test_a_call_that_names_nothing_is_offered_allow_once_bound_to_its_arguments(h):
    h.reply = {**ALWAYS, "approval_fingerprint": "afp1:message_send"}
    _out, rec = run(h, 1)
    assert rec["hold"]["offers"] == ["allow", "allow later", "deny"]
    assert "names nothing" in slash(h, f"allow {rec['hold']['id']} always")
    slash(h, f"allow {rec['hold']['id']}")
    # run 2 sends other words ("Daily brief 2"): other arguments, so it is held
    out, _rec = run(h, 2)
    assert out == HELD


def test_deny_declines_the_jobs_call_with_no_notice_and_another_job_is_still_held(h):
    _out, rec = run(h, 1)
    reply = slash(h, f"deny {rec['hold']['id']}")
    assert (
        reply.startswith("Job job-j will not make this call until ")
        and "you won't be told again" in reply
    )
    before = len(notices(h))
    out, rec = run(h, 2)
    assert out == DECLINED and rec["decision"] == "denied_by_owner" and "hold" not in rec
    assert len(notices(h)) == before
    assert holds(h) == []
    out, rec = run(h, 1, job="job-k")
    assert out == HELD and len(notices(h)) == before + 1
    session = json.loads((h.dir / "sentrook" / "sessions" / "cron-job-j-1.json").read_text())
    assert session["history"][-1]["decision"] == "denied_by_user"


def test_a_denial_is_sent_to_the_scanner_as_a_denial_by_the_owner(h):
    _out, rec = run(h, 1)
    slash(h, f"deny {rec['hold']['id']}")
    sid = {"session_id": "cron-job-j-2", "task_id": "cron-job-j-2"}
    run(h, 2)
    on_job(h)
    h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": "Daily brief 2"},
        tool_call_id="c2",
        turn_id="t-cron-job-j-2",
        **sid,
    )
    assert h.scans[-1]["history"][-1]["decision"] == "denied_by_user"


@pytest.mark.parametrize("verb", ["allow", "deny", "approve", "passes", "dismiss"])
def test_a_non_owner_is_refused(h, monkeypatch, verb):
    _out, rec = run(h, 1)
    monkeypatch.setattr(
        plugin,
        "session_facts",
        lambda: {"platform": "telegram", "chat_type": "group", "user_id": "u9"},
    )
    monkeypatch.setattr(plugin, "session_surface", lambda: "telegram")
    arg = "" if verb == "passes" else f" {rec['hold']['id']}"
    assert slash(h, f"{verb}{arg}") in refusals(verb)
    assert len(holds(h)) == 1 and stored_passes(h) == []


@pytest.mark.parametrize(
    ("raw", "reply"),
    [
        ("allow", "usage: /sentrook allow <id> [now|later|always|all]"),
        ("allow h-zzzzzz", "usage: /sentrook allow <id> [now|later|always|all]"),
        ("allow h-1a2b3c sometimes", "usage: /sentrook allow <id> [now|later|always|all]"),
        ("deny h-1a2b3c always", "usage: /sentrook deny <id>"),
        ("deny p-1a2b3c", "usage: /sentrook deny <id>"),
        (
            "allow h-abcdef",
            "No held call h-abcdef: the id is unknown, already answered or expired.",
        ),
        ("deny h-abcdef", "No held call h-abcdef: the id is unknown, already answered or expired."),
        ("dismiss", "usage: /sentrook dismiss <id>|all"),
        ("dismiss h-zzzzzz", "usage: /sentrook dismiss <id>|all"),
        ("dismiss h-1a2b3c now", "usage: /sentrook dismiss <id>|all"),
        (
            "dismiss h-abcdef",
            "No held call h-abcdef: the id is unknown, already answered or expired.",
        ),
        (
            "passes revoke p-abcdef",
            "No pass or denial p-abcdef: the id is unknown, used up or expired.",
        ),
        ("passes revoke h-abcdef", "usage: passes revoke <id>"),
        ("passes frobnicate", "usage: /sentrook passes [revoke <id>]"),
    ],
)
def test_unknown_and_malformed_ids_get_clear_replies(h, raw, reply):
    assert slash(h, raw).startswith(reply)


def test_an_expired_hold_says_so(h):
    _out, rec = run(h, 1)
    hid = rec["hold"]["id"]
    path = h.dir / "sentrook" / "holds.json"
    data = json.loads(path.read_text())
    data["holds"][0]["expires_at"] = "2020-01-01T00:00:00Z"
    path.write_text(json.dumps(data))
    assert slash(h, f"deny {hid}").startswith(
        f"Held call {hid} expired: a hold can be answered for 7 days."
    )


def test_deny_on_a_run_that_is_not_a_cron_job_is_refused(h):
    on_job(h, None)
    turn(h)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": "x"},
        tool_call_id="c1",
        turn_id="t-cron-1",
        session_id="cron-1",
        task_id="cron-1",
    )
    hold.wait_for_notices()
    assert out == HELD
    rec = [r for r in h.traffic() if r.get("kind") == "scan"][-1]
    assert rec["hold"]["offers"] == ["allow"]
    assert "no cron job or other source" in slash(h, f"deny {rec['hold']['id']}")


# ---- dismiss -----------------------------------------------------------------------------------------------

DISMISS = {k: v for k, v in FIXTURES["dismiss"].items() if k != "_comment"}


def test_the_dismiss_replies_are_the_shared_fixtures():
    assert hold.DISMISS_TEXT == DISMISS


def test_dismiss_takes_a_jobs_hold_off_the_list_with_nothing_set(h):
    _out, rec = run(h, 1)
    hid = rec["hold"]["id"]
    assert slash(h, f"dismiss {hid}") == DISMISS["one"].format(id=hid)
    assert holds(h) == [] and stored_passes(h) == []
    assert [
        (r["request_id"], r["resolution"], r["decision"], r["hold_id"]) for r in resolutions(h)
    ] == [(rec["request_id"], "hold_dismissed", "held", hid)]
    assert not [r for r in h.traffic() if r.get("kind") == "passes"]
    # the session history is left as an expiry leaves it
    session = json.loads((h.dir / "sentrook" / "sessions" / "cron-job-j-1.json").read_text())
    assert session["history"][-1]["decision"] == "held"
    before = len(notices(h))
    out, again = run(h, 2)
    assert out == HELD and again["hold"]["id"] != hid
    assert len(notices(h)) == before + 1
    assert slash(h, f"dismiss {hid}").startswith(f"No held call {hid}:")


def test_dismiss_works_on_a_hold_that_offers_no_answer_and_on_one_from_before_version_2(h):
    h.reply = dict(MISSING)
    _out, rec = run(h, 1, job=None)
    assert rec["hold"]["offers"] == []
    hid = rec["hold"]["id"]
    assert slash(h, f"dismiss {hid}") == DISMISS["one"].format(id=hid)
    assert holds(h) == []
    h.reply = dict(NAMED)
    _out, old = run(h, 2, job="job-k")
    path = h.dir / "sentrook" / "holds.json"
    data = json.loads(path.read_text())
    del data["holds"][0]["v"]
    data["holds"][0].pop("offers", None)
    path.write_text(json.dumps(data))
    oid = old["hold"]["id"]
    assert slash(h, f"dismiss {oid}") == DISMISS["one"].format(id=oid)
    assert holds(h) == [] and stored_passes(h) == []
    assert not [r for r in h.traffic() if r.get("kind") == "grants"]


def test_dismiss_records_every_held_call_of_a_repeated_hold(h):
    _out, first = run(h, 1)
    _out, second = run(h, 2)
    assert second["hold"]["id"] == first["hold"]["id"]
    slash(h, f"dismiss {first['hold']['id']}")
    assert [(r["request_id"], r["resolution"]) for r in resolutions(h)] == [
        (first["request_id"], "hold_dismissed"),
        (second["request_id"], "hold_dismissed"),
    ]


def test_dismiss_all_takes_every_waiting_hold_off_the_list(h):
    ids = [run(h, 1, job=job)[1]["hold"]["id"] for job in ("job-j", "job-k", None)]
    assert len(holds(h)) == 3
    assert slash(h, "dismiss all") == DISMISS["all"].format(n=3, ids=", ".join(ids))
    assert holds(h) == [] and stored_passes(h) == []
    assert [(r["hold_id"], r["resolution"]) for r in resolutions(h)] == [
        (i, "hold_dismissed") for i in ids
    ]
    assert slash(h, "dismiss ALL") == DISMISS["none"]


def test_dismiss_on_an_expired_hold_says_so_and_records_only_the_expiry(h):
    _out, rec = run(h, 1)
    hid = rec["hold"]["id"]
    path = h.dir / "sentrook" / "holds.json"
    data = json.loads(path.read_text())
    data["holds"][0]["expires_at"] = "2020-01-01T00:00:00Z"
    path.write_text(json.dumps(data))
    assert slash(h, f"dismiss {hid}").startswith(
        f"Held call {hid} expired: a hold can be answered for 7 days."
    )
    assert [r["resolution"] for r in resolutions(h)] == ["hold_expired"]
    assert slash(h, "dismiss all") == DISMISS["none"]


# ---- holds repeat, passes list ---------------------------------------------------------------------------------


def test_a_repeat_of_a_waiting_hold_updates_it_and_sends_no_new_notice(h):
    _out, first = run(h, 1)
    _out, second = run(h, 2)
    assert second["hold"]["id"] == first["hold"]["id"] and second["hold"]["repeat"] is True
    assert second["hold"]["notice"]["status"] == "not_sent"
    assert len(notices(h)) == 1
    [entry] = holds(h)
    assert entry["count"] == 2 and len(entry["held"]) == 2
    assert f"{entry['id']} held 2 times since" in slash(h, "status")
    # answering it covers both held calls
    slash(h, f"allow {entry['id']}")
    assert [r["request_id"] for r in resolutions(h)] == [first["request_id"], second["request_id"]]


def test_a_riskier_repeat_is_a_new_hold_with_its_own_notice(h):
    _out, first = run(h, 1)
    h.reply = {**NAMED, "risk": 60}
    _out, second = run(h, 2)
    assert second["hold"]["id"] != first["hold"]["id"]
    assert len(notices(h)) == 2


def test_passes_lists_and_revokes(h):
    h.reply = dict(ALWAYS)
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']} always")
    [p] = stored_passes(h)
    listed = slash(h, "passes")
    assert listed.startswith(f"{p['id']}  allowed on job job-j until ") and "used 0 times" in listed
    assert "passes: 1 standing, 0 once, 0 denials" in slash(h, "status")
    assert slash(h, f"passes revoke {p['id']}") == f"Revoked pass {p['id']}."
    assert [r["op"] for r in h.traffic() if r.get("kind") == "passes"] == ["add", "revoke"]
    out, _rec = run(h, 2)
    assert out == HELD


def test_an_unreadable_passes_file_holds_as_before_and_verify_fails(h):
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']}")
    (h.dir / "sentrook" / "passes.json").write_text("{not json")
    out, _rec = run(h, 2)
    assert out == HELD
    from plugin import cli

    checks = {name: (ok, detail) for name, ok, detail in cli.run_verify(h.ctx.settings)}
    assert checks["held-call passes"] == (False, "passes file unreadable")


# ---- must stay the same --------------------------------------------------------------------------------------


def test_a_block_is_never_passed(h):
    h.reply = dict(ALWAYS)
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']} always")
    h.reply = {**ALWAYS, "risk": 85}
    out, rec = run(h, 2)
    assert out["action"] == "block" and out["message"] != FIXTURES["held_text"]
    assert rec["decision"] == "blocked"


def test_observe_mode_ignores_a_denial(h):
    _out, rec = run(h, 1)
    slash(h, f"deny {rec['hold']['id']}")
    h.ctx.settings["mode"] = "observe"
    out, rec = run(h, 2)
    assert out is None and rec["decision"] == "allowed"


def test_an_attended_review_is_still_a_prompt_whatever_the_passes(h, monkeypatch):
    h.reply = dict(ALWAYS)
    _out, rec = run(h, 1)
    slash(h, f"allow {rec['hold']['id']} always")
    on_job(h, None)
    monkeypatch.setattr(plugin, "is_unattended", lambda *_a, **_kw: False)
    h.ctx.hooks["pre_llm_call"](
        turn_id="t-owner",
        user_message="Post the brief.",
        platform="telegram",
        sender_id="u1",
        session_id="owner-1",
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": "x"},
        tool_call_id="c1",
        turn_id="t-owner",
        session_id="owner-1",
    )
    assert out["action"] == "approve"


def test_holds_json_is_version_2(h):
    run(h, 1)
    assert json.loads((h.dir / "sentrook" / "holds.json").read_text())["version"] == 2


# ---- the shared matching table ---------------------------------------------------------------------------------


@pytest.mark.parametrize("case", FIXTURES["passes"], ids=lambda c: c["name"])
def test_pass_matching(case):
    held = passes.match_of(case["tool"], case["held"], case["args"], "salt")
    later = passes.match_of(
        case.get("later_tool", case["tool"]), case["later"], case["later_args"], "salt"
    )
    got = (
        session_allow.eligible(case["later"])
        and passes.covers(held, later)
        and passes.level_covers(passes.level_of(case["later"]), case["pass_level"])
    )
    assert got is case["matches"]


def test_passes_expire_after_30_days(tmp_path):
    t0 = datetime(2026, 11, 24, tzinfo=UTC)
    entry = passes.add(
        tmp_path,
        kind="deny",
        uses="standing",
        level=None,
        hold={
            "id": "h-000000",
            "job_id": "j",
            "job_ref": passes.job_ref("j"),
            "match": {"key": "k"},
        },
        who={},
        now=t0,
    )
    assert passes.check(
        tmp_path, passes.job_ref("j"), {"key": "k"}, {"risk": 1}, t0 + timedelta(days=29)
    )
    assert (
        passes.check(
            tmp_path, passes.job_ref("j"), {"key": "k"}, {"risk": 1}, t0 + timedelta(days=30)
        )
        is None
    )
    assert entry["id"].startswith("p-")
