"""Holds: a review on an unattended run waits for the owner, who is told once and may approve it.

The agent is told the call is held and must not be retried in this run; the owner gets one notice on
a home channel; `/sentrook approve <id>` within 24 hours sets the suggested grant (persistent, 30
days). Blocks stay blocks, and attended runs still get a review prompt. The texts are shared with the
OpenClaw plugin's tests (`integrations/fixtures/hold`).
"""

import contextlib
import contextvars
import fcntl
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import plugin
from plugin import commands, config, grants, history, hold, store
from plugin.store import read_time

from .test_plugin import dump_planirs

FIXTURES = json.loads(
    (Path(__file__).resolve().parents[3] / "fixtures" / "hold" / "cases.json").read_text()
)
SEND = FIXTURES["notices"][0]
HINT = FIXTURES["hints"][0]["hint"]
CRON = {"session_id": "cron-1", "task_id": "cron-1"}
#: Stands in for the cron run's own delivery target, which Hermes binds to the run's context.
RUN_TARGET = contextvars.ContextVar("run_delivery_target", default="unset")


@pytest.fixture
def h(harness, monkeypatch):
    """The harness with a scanner whose reply each test sets (`.reply`), Discord as the only platform
    with a home channel and `owner_channel`, a `dispatch_tool` that records each send (`.sent`), and
    commands run from the local terminal."""
    fake = harness
    fake.reply = {"risk": 47, "enforced": None}

    def http(url, *, data=None, headers=None, timeout):
        if url != "http://scan.test/scan":
            return fake(url, data=data, headers=headers, timeout=timeout)
        p = json.loads(data)
        fake.scans.append(p)
        return 200, {**SEND["response"], **fake.reply, "request_id": p["request_id"]}, {}

    monkeypatch.setattr(plugin.scan_client, "http_json", http)
    monkeypatch.setattr(hold, "home_platforms", lambda: ["discord"])
    fake.sent = []

    def dispatch_tool(name, args, **_kw):
        fake.sent.append(
            {
                "name": name,
                "args": args,
                "run_target": RUN_TARGET.get(),
                "thread": threading.current_thread().name,
            }
        )
        return json.dumps({"success": True, "note": "Sent to discord home channel"})

    fake.ctx.dispatch_tool = dispatch_tool
    fake.ctx.settings["owner_channel"] = "discord"
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(plugin, "session_facts", lambda: {})
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    return fake


def turn(h, platform="cron", sid=CRON):
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid['session_id']}",
        user_message="Post the daily brief to the ops channel.",
        platform=platform,
        sender_id="u1",
        **sid,
    )


def send(h, cid="c1", sid=CRON):
    """One send to a channel: the directive and the scan's traffic record."""
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={
            "action": "send",
            "target": "discord:#ops-reports",
            "message": "Daily brief: 3 closed",
        },
        tool_call_id=cid,
        turn_id=f"t-{sid['session_id']}",
        **sid,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def slash(h, raw):
    return h.ctx.commands["sentrook"]["handler"](raw, session_id="")


def holds(h):
    return json.loads((h.dir / "sentrook" / "holds.json").read_text())["holds"]


def resolutions(h):
    return [r for r in h.traffic() if r.get("kind") == "resolution"]


# ---- must hold, not block -------------------------------------------------------------------------------


def test_a_scheduled_send_at_risk_47_is_held_and_the_owner_told_once(h):
    turn(h)
    out, rec = send(h)
    assert out == {"action": "block", "message": FIXTURES["held_text"]}
    assert (rec["verdict"], rec["decision"]) == ("review", "held")
    [entry] = holds(h)
    assert rec["hold"] == {
        "id": entry["id"],
        "expires_at": entry["expires_at"],
        "hint": False,
        "notice": {"status": "queued", "target": "discord"},
    }
    assert read_time(entry["expires_at"]) - read_time(entry["held_at"]) == timedelta(hours=24)
    assert entry["request_id"] == rec["request_id"]
    [notice] = h.sent
    assert notice["name"] == "send_message"
    assert notice["args"]["action"] == "send" and notice["args"]["target"] == "discord"
    where = f"cron job, session {rec['session_ref']}"
    assert entry["where"] == where
    text = hold.notice_text(
        SEND["response"] | h.reply, "send_message", where, entry["id"], "{approve}", "{why}"
    )
    assert notice["args"]["message"] == text.replace("{approve}", "/sentrook approve").replace(
        "{why}", "/sentrook why"
    )
    table = history.format_history(
        history.recent_scans(h.dir / "sentrook" / "traffic.jsonl", 1), "w"
    )
    assert re.search(r" held +no answer$", table, re.M)


def test_the_notice_names_the_cron_job_when_hermes_says_which(h):
    class Run:
        job_id = "9f1c2a"
        job_name = "daily-brief"

    h.ctx.current_cron_execution = lambda: Run()
    turn(h)
    _out, rec = send(h)
    where = f'cron job 9f1c2a, job name "daily-brief", session {rec["session_ref"]}'
    assert holds(h)[0]["where"] == where
    assert f"Run: {where}\n" in h.sent[0]["args"]["message"]


def test_the_notice_leaves_the_runs_context_behind(h):
    """Hermes skips a send to the cron run's own delivery target from inside the run; the notice goes
    from a worker thread with an empty context, so a job delivering to the home channel cannot swallow
    it."""
    turn(h)
    RUN_TARGET.set("discord:home")
    try:
        send(h)
    finally:
        RUN_TARGET.set("unset")
    [notice] = h.sent
    assert notice["run_target"] == "unset"
    assert notice["thread"] == "sentrook-hold-notice"


def test_the_held_call_did_not_run_and_is_sent_as_an_unanswered_review(h):
    turn(h)
    send(h, "c1")
    h.ctx.hooks["post_tool_call"](
        tool_name="send_message",
        args={},
        result="held",
        tool_call_id="c1",
        status="blocked",
        turn_id="t-cron-1",
        **CRON,
    )
    h.reply = {"risk": 5}
    send(h, "c2")
    [first] = h.scans[-1]["history"]
    assert first["decision"] == "review_timed_out"
    assert first["result"] == {"status": "error", "size_bytes": 0}
    assert h.scans[-1]["new_inputs"] == []
    dump_planirs("held_call", h.scans)


@pytest.mark.parametrize("setting", [None, "telegram"])
def test_with_no_home_channel_to_use_the_call_is_still_held_and_the_notice_logged_unsent(
    h, monkeypatch, setting
):
    """owner_channel is required: even with a single home channel, nothing is sent until it is set."""
    monkeypatch.setattr(hold, "home_platforms", lambda: ["discord"])
    if setting:
        h.ctx.settings["owner_channel"] = setting
    else:
        del h.ctx.settings["owner_channel"]
    turn(h)
    out, rec = send(h)
    assert out["message"] == FIXTURES["held_text"] and rec["decision"] == "held"
    assert rec["hold"]["notice"]["status"] == "unsent"
    assert h.sent == []
    why = hold.NO_OWNER_CHANNEL if setting is None else "owner_channel telegram has no home channel"
    assert rec["hold"]["notice"]["reason"] == why
    assert f"notices not sent ({why})" in slash(h, "status")
    from plugin import cli

    verify = dict((n, (ok, d)) for n, ok, d in cli.run_verify(dict(h.ctx.settings), timeout=0.01))
    assert verify["held-call notices"] == (True, f"not sent: {why}")


def test_owner_channel_picks_the_home_channel(h, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["discord", "telegram"])
    h.ctx.settings["owner_channel"] = "Telegram"
    assert config.resolve_config(dict(h.ctx.settings), {}).owner_channel == "telegram"
    turn(h)
    send(h)
    assert h.sent[0]["args"]["target"] == "telegram"
    assert "notices to the telegram home channel" in slash(h, "status")


# ---- approve -----------------------------------------------------------------------------------------------


def test_approve_sets_the_suggested_grant_persistent_for_30_days(h, monkeypatch):
    monkeypatch.setattr(hold, "grant_hint", lambda _resp: dict(HINT))
    turn(h)
    _out, rec = send(h)
    hid = rec["hold"]["id"]
    assert rec["hold"]["hint"] is True
    # The suggestion is for the owner's eyes: in `why`, never in the notice the agent may see.
    assert "discord:#ops-reports" not in h.sent[0]["args"]["message"].split("Tool:")[0]
    assert "grant" not in h.sent[0]["args"]["message"]
    assert "suggested grant: destination discord:#ops-reports (persistent, 30 days)" in slash(
        h, f"why {hid}"
    )
    reply = slash(h, f"approve {hid}")
    assert reply.startswith(f"Approved {hid}. Granted gr-")
    assert "(persistent, expires " in reply and "The held call is not run again" in reply
    [g] = grants.load(h.dir / "sentrook")["grants"]
    assert (g["kind"], g["pattern"], g["scope"], g["from_hold"]) == (
        "destination",
        "discord:#ops-reports",
        "persistent",
        hid,
    )
    assert read_time(g["expires_at"]) - read_time(g["granted_at"]) == timedelta(days=30)
    assert g["set_by"]["basis"] == ["local_terminal"]
    assert holds(h) == []
    [res] = resolutions(h)
    assert {k: res[k] for k in ("request_id", "resolution", "decision", "hold_id", "grant_id")} == {
        "request_id": rec["request_id"],
        "resolution": "hold_approved",
        "decision": "held",
        "hold_id": hid,
        "grant_id": g["id"],
    }
    assert [r["op"] for r in h.traffic() if r.get("kind") == "grants"] == ["grant"]
    # The next run sends the grant; whether it relieves the call is the scanner's to decide.
    turn(h, sid={"session_id": "cron-2", "task_id": "cron-2"})
    send(h, "c9", sid={"session_id": "cron-2", "task_id": "cron-2"})
    sent = [x for x in h.scans[-1]["grants"] if x["pattern"] == "discord:#ops-reports"]
    assert sent == [
        {
            "grant_ref": "g_1",
            "kind": "destination",
            "pattern": "discord:#ops-reports",
            "scope": "persistent",
            "granted_at": g["granted_at"],
            "expires_at": g["expires_at"],
        }
    ]
    # Answered: the id is gone.
    assert slash(h, f"approve {hid}").startswith(f"No held call {hid}")


def test_approve_without_a_suggestion_sets_nothing_and_says_so(h):
    turn(h)
    _out, rec = send(h)
    hid = rec["hold"]["id"]
    reply = slash(h, f"approve {hid}")
    assert reply == (
        f"Approved {hid}. Sentrook suggested no grant for this call, so nothing was set: the next run "
        "is scanned as before. To let it pass, add a grant with /sentrook grant. The held call is not "
        "run again."
    )
    assert grants.load(h.dir / "sentrook")["grants"] == []
    [res] = resolutions(h)
    assert (res["resolution"], res["hold_id"]) == ("hold_approved", hid) and "grant_id" not in res


@pytest.mark.parametrize("bad", ["", "h-zzzzzz", "gr-1a2b3c", "h-1a2b3c h-1a2b3c"])
def test_a_malformed_id_gets_the_usage(h, bad):
    assert slash(h, f"approve {bad}").startswith("usage: /sentrook approve <id>")


def test_an_unknown_id_is_refused(h):
    assert slash(h, "approve h-abcdef") == (
        "No held call h-abcdef: the id is unknown, already answered or expired."
    )
    assert resolutions(h) == []


def test_approve_is_for_the_owner_only(h, monkeypatch):
    turn(h)
    _out, rec = send(h)
    monkeypatch.setattr(
        plugin,
        "session_facts",
        lambda: {"platform": "telegram", "chat_type": "group", "user_id": "u9"},
    )
    monkeypatch.setattr(plugin, "session_surface", lambda: "telegram")
    assert "Only the owner" in slash(h, f"approve {rec['hold']['id']}")
    assert len(holds(h)) == 1


# ---- expiry ------------------------------------------------------------------------------------------------


def test_after_24_hours_the_hold_expires_and_approve_is_refused(h):
    turn(h)
    _out, rec = send(h)
    hid = rec["hold"]["id"]
    path = h.dir / "sentrook" / "holds.json"
    data = json.loads(path.read_text())
    data["holds"][0]["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    path.write_text(json.dumps(data))
    assert slash(h, f"approve {hid}") == (
        f"Held call {hid} expired: holds last 24 hours. Nothing was approved; the next run is "
        "scanned as before."
    )
    [res] = resolutions(h)
    assert (res["request_id"], res["resolution"], res["decision"], res["hold_id"]) == (
        rec["request_id"],
        "hold_expired",
        "held",
        hid,
    )
    assert holds(h) == []
    assert slash(h, f"approve {hid}").startswith(f"No held call {hid}")
    assert len(resolutions(h)) == 1  # recorded once


def test_expiry_is_exactly_24_hours_and_recorded_when_next_read(tmp_path):
    t0 = datetime(2026, 11, 16, 9, 0, tzinfo=UTC)
    log = []
    hid = hold.create(
        tmp_path,
        request_id="r1",
        session_ref="s_0a1b2c3d4e5f",
        tool="send_message",
        where="session s_0a1b2c3d4e5f",
        hint=None,
        notice={"status": "queued", "target": "discord"},
        now=t0,
        record=log.append,
    )
    cmd = commands.CMD
    who = {"basis": ["local_terminal"], "platform": "", "sender_ref": None}
    assert hold.waiting(tmp_path, t0 + timedelta(hours=24) - timedelta(seconds=1)) == 1
    assert hold.waiting(tmp_path, t0 + timedelta(hours=24)) == 0
    assert log == []  # nothing recorded until the holds are next changed
    hold.sweep(tmp_path, t0 + timedelta(hours=24), log.append)
    assert [(r["resolution"], r["hold_id"]) for r in log] == [("hold_expired", hid)]
    assert hold.approve(tmp_path, hid, who, t0 + timedelta(hours=25), cmd, log.append).startswith(
        f"No held call {hid}"
    )


def test_status_counts_waiting_holds(h):
    assert "held calls: 0 waiting; notices to the discord home channel" in slash(h, "status")
    turn(h)
    send(h)
    assert "held calls: 1 waiting;" in slash(h, "status")


# ---- must still block, and attended runs are unchanged -----------------------------------------------------


@pytest.mark.parametrize("case", [c for c in FIXTURES["outcomes"]], ids=lambda c: c["name"])
@pytest.mark.parametrize("attended", [True, False])
def test_what_each_verdict_becomes(h, monkeypatch, case, attended):
    monkeypatch.setattr(plugin, "is_unattended", lambda *_a, **_kw: not attended)
    h.reply = {"risk": case["risk"], "enforced": case["enforced"]}
    turn(h, platform="telegram" if attended else "cron")
    out, rec = send(h)
    want = case["attended" if attended else "unattended"]
    if want == "allow":
        assert out is None and rec["decision"] == "allowed"
    elif want == "review":
        assert out["action"] == "approve" and rec["decision"] == "review_timed_out"
    elif want == "block":
        assert out["action"] == "block" and rec["decision"] == "blocked"
        assert out["message"].startswith("Sentrook security block:")
    else:
        assert out == {"action": "block", "message": FIXTURES["held_text"]}
        assert rec["decision"] == "held"
    assert (rec["decision"] == "held") == ("hold" in rec)
    assert len(h.sent) == (1 if want == "held" else 0)


def test_observe_mode_holds_nothing(h):
    h.ctx.settings["mode"] = "observe"
    turn(h)
    out, rec = send(h)
    assert out is None and rec["decision"] == "allowed" and h.sent == []


# ---- the shared texts --------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", FIXTURES["notices"], ids=lambda c: c["name"])
def test_notice_text(case):
    w = case["where"]
    where = hold.where_text(w["run"], w["session_ref"], w["job_id"], w["job_name"])
    assert where == case["where_text"]
    assert (
        hold.notice_text(case["response"], case["tool"], where, case["id"], "{approve}", "{why}")
        == case["text"]
    )


@pytest.mark.parametrize("case", FIXTURES["hints"], ids=lambda c: json.dumps(c["hint"]))
def test_a_suggested_grant_passes_the_grant_commands_rules(case):
    assert grants.hint_grant(case["hint"]) == case["grant"]


@pytest.mark.parametrize("case", FIXTURES["history"], ids=lambda c: c["name"])
def test_history_columns(case):
    scan = {
        "verdict": "review",
        "decision": case["decision"],
        "mode": "enforce",
        "response": {"risk": 47},
    }
    res = {"resolution": case["resolution"]} if case["resolution"] else None
    action = history.action_of(scan, res)
    assert (action, history.review_of(action, res)) == (case["action"], case["review"])


# ---- two processes at once ---------------------------------------------------------------------------------

CHILD = """
import sys, time
from datetime import UTC, datetime
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from plugin import hold
state, label, count, start = Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
while time.time() < start:
    pass
for i in range(count):
    hold.create(state, request_id=f"{label}-{i}", session_ref="s_" + label, tool="t", where=label,
                hint=None, notice={}, now=datetime.now(UTC), record=lambda r: None)
"""


def test_two_processes_holding_calls_at_the_same_time_keep_every_hold(tmp_path):
    """The gateway and a `hermes cron run` process are separate processes: the in-process lock alone
    would let one overwrite the other's hold."""
    root = str(Path(__file__).resolve().parents[2])
    start = time.time() + 1.0
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", CHILD, root, str(tmp_path), label, "40", str(start)],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        for label in ("a", "b")
    ]
    assert [p.wait(60) for p in procs] == [0, 0]
    kept = sorted(
        h["request_id"] for h in json.loads((tmp_path / "holds.json").read_text())["holds"]
    )
    assert kept == sorted(f"{label}-{i}" for label in ("a", "b") for i in range(40))


WAITER = """
import sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from plugin.store import file_lock
target, log, label, start = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], float(sys.argv[5])
while time.time() < start:
    pass
for _ in range(5):
    with file_lock(target):
        with open(log, "a") as f:
            f.write(f"in {label}\\n")
        time.sleep(0.02)
        with open(log, "a") as f:
            f.write(f"out {label}\\n")
"""


def _children(script, *args):
    root = str(Path(__file__).resolve().parents[2])
    return [
        subprocess.Popen(
            [sys.executable, "-c", script, root, *[a(label) if callable(a) else a for a in args]],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        for label in ("a", "b")
    ]


def test_two_waiters_on_a_lock_left_over_never_both_enter(tmp_path):
    """A lock file left by a process that died is not held (the OS released it with the process), and
    two processes waiting on it take turns."""
    (tmp_path / "holds.json.lock").write_text("99999\\n")
    log = tmp_path / "log"
    procs = _children(
        WAITER, str(tmp_path / "holds.json"), str(log), lambda label: label, str(time.time() + 1.0)
    )
    assert [p.wait(60) for p in procs] == [0, 0]
    lines = log.read_text().splitlines()
    assert len(lines) == 20
    for i in range(0, 20, 2):
        assert lines[i].startswith("in ") and lines[i + 1] == "out " + lines[i][3:], lines


HOLDER = """
import sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from plugin.store import file_lock
with file_lock(Path(sys.argv[2])):
    print("held", flush=True)
    time.sleep(60)
"""


def test_a_lock_held_by_a_process_that_died_is_free_at_once(tmp_path):
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            HOLDER,
            str(Path(__file__).resolve().parents[2]),
            str(tmp_path / "holds.json"),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert holder.stdout.readline().strip() == "held"
    holder.kill()
    holder.wait(10)
    t0 = time.monotonic()
    with store.file_lock(tmp_path / "holds.json"):
        pass
    assert time.monotonic() - t0 < 0.5


@contextlib.contextmanager
def held_elsewhere(path):
    """Holds `path`'s lock through a separate open file, as another process would."""
    fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_a_hold_whose_file_is_locked_still_holds_and_logs_the_notice_unsent(h, monkeypatch):
    monkeypatch.setattr(store, "LOCK_WAIT_S", 0.05)
    turn(h)
    with held_elsewhere(h.dir / "sentrook" / "holds.json"):
        out, rec = send(h)
    assert out == {"action": "block", "message": FIXTURES["held_text"]}
    assert rec["decision"] == "held"
    assert rec["hold"] == {
        "id": None,
        "expires_at": None,
        "hint": False,
        "notice": {"status": "unsent", "target": None, "reason": "holds file locked"},
    }
    assert h.sent == []
    session = json.loads((h.dir / "sentrook" / "sessions" / "cron-1.json").read_text())
    assert session["history"][-1]["decision"] == "held"


def test_approve_keeps_the_hold_when_the_grant_cannot_be_written(h, monkeypatch):
    monkeypatch.setattr(hold, "grant_hint", lambda _resp: dict(HINT))
    turn(h)
    _out, rec = send(h)
    hid = rec["hold"]["id"]
    gfile = h.dir / "sentrook" / "grants.json"
    gfile.write_text("{not json")
    reply = slash(h, f"approve {hid}")
    assert reply.startswith("Not approved: The grants file ") and f"{hid} is still waiting" in reply
    assert [x["id"] for x in holds(h)] == [hid]
    assert resolutions(h) == []
    gfile.unlink()
    assert slash(h, f"approve {hid}").startswith(f"Approved {hid}. Granted gr-")
    assert holds(h) == []


def test_approve_keeps_the_hold_when_the_grants_file_is_locked(h, monkeypatch):
    monkeypatch.setattr(hold, "grant_hint", lambda _resp: dict(HINT))
    monkeypatch.setattr(store, "LOCK_WAIT_S", 0.05)
    turn(h)
    _out, rec = send(h)
    hid = rec["hold"]["id"]
    with held_elsewhere(h.dir / "sentrook" / "grants.json"):
        reply = slash(h, f"approve {hid}")
    assert reply.startswith("Not approved: The grants file could not be written")
    assert [x["id"] for x in holds(h)] == [hid]


# ---- what the notice carries --------------------------------------------------------------------------------

CANARY = "CANARY-not-a-real-secret-4471"


def test_the_notice_carries_only_the_minimal_fields(h):
    """Hermes copies the notice into the agent's own transcript: it names the run, the tool and its
    target, the category and the commands, and nothing a steered agent could use."""
    h.reply = {
        "risk": 47,
        "reasons": [{"code": "send.unbound_channel"}, {"code": "exfil.exec_egress"}],
        "entities": {
            "E1": {"kind": "channel", "display": "discord:#ops-reports"},
            "E2": {"kind": "path", "display": "~/.config/ops/token"},
        },
    }
    turn(h)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={
            "action": "send",
            "target": "discord:#ops-reports",
            "message": f"brief, key {CANARY}",
        },
        tool_call_id="c1",
        turn_id="t-cron-1",
        **CRON,
    )
    hold.wait_for_notices()
    rec = [r for r in h.traffic() if r.get("kind") == "scan"][-1]
    hid = rec["hold"]["id"]
    assert out["message"] == FIXTURES["held_text"]
    text = h.sent[0]["args"]["message"]
    assert text == (
        "Sentrook held a tool call on an unattended run; it did not run.\n"
        f"Run: cron job, session {rec['session_ref']}\n"
        "Tool: send_message: Sends a message to discord:#ops-reports\n"
        "Held because it sends data to a destination outside this machine.\n"
        f"To approve within 24 hours: /sentrook approve {hid}\n"
        f"For the reasons: /sentrook why {hid}"
    )
    for absent in (
        "47",
        "risk",
        "send.unbound_channel",
        "exfil",
        "Scores",
        "suspicion",
        "consequence",
        "~/.config/ops/token",
        "path",
        CANARY,
        "brief, key",
        "grant",
    ):
        assert absent not in text, absent


def test_why_with_a_hold_id_gives_the_owner_the_reasons(h):
    turn(h)
    _out, rec = send(h)
    hid = rec["hold"]["id"]
    why = slash(h, f"why {hid}")
    assert why.startswith(f"scan: {rec['request_id']}")
    assert "risk: 47" in why and "reasons: trigger.scheduled, send.unbound_channel" in why
    assert "action: held" in why and "review: no answer" in why
    assert "hold: waiting, until " in why and "suggested grant: none" in why
    slash(h, f"approve {hid}")
    assert slash(h, f"why {hid}").endswith("hold: answered or expired")
    assert slash(h, "why h-abcdef") == "No held call h-abcdef in the recent traffic log."


def test_why_with_a_hold_id_is_for_the_owner_only(h, monkeypatch):
    turn(h)
    _out, rec = send(h)
    monkeypatch.setattr(
        plugin,
        "session_facts",
        lambda: {"platform": "telegram", "chat_type": "group", "user_id": "u9"},
    )
    monkeypatch.setattr(plugin, "session_surface", lambda: "telegram")
    assert "Only the owner" in slash(h, f"why {rec['hold']['id']}")


def test_a_snooze_never_relieves_an_unattended_review(h):
    """Order: a block, then a hold on an unattended run, and only then an attended review's snooze."""
    assert slash(h, "snooze 1h --all").startswith("Snoozed")
    turn(h)
    out, rec = send(h)
    assert out == {"action": "block", "message": FIXTURES["held_text"]}
    assert rec["decision"] == "held" and "snoozed" not in rec
    assert len(h.sent) == 1
