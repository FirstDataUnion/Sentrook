"""A notice to a chat that `hermes send` cannot address yet is tried again (`notice_retry`).

Hermes reaches a chat on a platform without a target syntax (Mattermost, for one) only once its channel directory
lists it, which it rebuilds every few minutes, so the first notices to a chat set with `notify here` there fail with
"Could not resolve". They are tried again for up to 10 minutes, then sent to the platform's home channel when it has
one. A stand-in clock gives the times, and `run_due` is run at the time a test sets; nothing here sleeps.
"""

import json
import subprocess
import threading

import pytest

import plugin
from plugin import hold, notice_retry, owner_settings

from . import test_hold
from .test_hold import send, slash, turn
from .test_owner_settings import from_chat, source

h = test_hold.h

# A Mattermost id is 26 lower-case letters and digits; built here so no
# token-shaped literal sits in the source.
CHAT = "mattermost:" + "ownerdm" + "0" * 19
T0 = 1_800_000_000.0


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


class HermesSend:
    """Stands in for `subprocess.run` of `hermes send`: `answer(to)` gives (delivered, error) for each send."""

    def __init__(self, answer):
        self.answer, self.runs = answer, []

    def __call__(self, argv, **kw):
        to = argv[argv.index("--to") + 1]
        self.runs.append(
            {"to": to, "input": kw.get("input"), "thread": threading.current_thread().name}
        )
        ok, error = self.answer(to)
        body = {"success": True} if ok else {"error": error}
        return subprocess.CompletedProcess(argv, 0 if ok else 1, json.dumps(body), "")

    def to(self, target):
        return [r for r in self.runs if r["to"] == target]


def unresolved(to):
    return f"Could not resolve '{to.partition(':')[2]}' on mattermost. No channel-directory entry matched."


@pytest.fixture
def mm(h, notice_route, monkeypatch):
    """The `h` harness on a Hermes like 0.23 (`hermes send`, no send_message tool), the owner on Mattermost, and a
    clock the test moves."""
    notice_route["hermes_send"], notice_route["send_tool"] = True, False
    monkeypatch.setenv("MATTERMOST_ALLOWED_USERS", "u1")
    clock = Clock()
    monkeypatch.setattr(notice_retry, "clock", clock)
    h.clock = clock
    h.state = h.dir / "sentrook"

    def use(answer):
        run = HermesSend(answer)
        monkeypatch.setattr(hold.subprocess, "run", run)
        return run

    h.hermes = use
    return h


def notify_here(h, monkeypatch):
    chat_id = CHAT.partition(":")[2]
    reply = from_chat(
        h,
        monkeypatch,
        "notify here",
        src=source("mattermost", chat_id=chat_id),
        platform="mattermost",
    )
    hold.wait_for_notices()
    return reply


def status(h):
    return slash(h, "notify status")


def settings(h):
    return json.loads((h.state / "settings.json").read_text())


def due_at(h, t):
    """Runs the kept notices with the clock at `t`."""
    h.clock.t = t
    return notice_retry.run_due(h.state)


def retry_until(h, until):
    """Runs the kept notices at each time they fall due, up to `until` seconds after T0."""
    due = notice_retry.run_due(h.state)
    while due is not None and due <= T0 + until:
        due = due_at(h, due)
    return due


# ---- must fire ------------------------------------------------------------------------------------------------


def test_a_test_notice_hermes_cannot_resolve_yet_is_delivered_once_on_a_later_try(
    mm, monkeypatch, notice_retry_kicks
):
    tries = iter([False, True])
    run = mm.hermes(lambda to: (next(tries), unresolved(to)))
    notify_here(mm, monkeypatch)
    assert len(run.to(CHAT)) == 1
    assert notice_retry.pending(mm.state, CHAT)
    assert notice_retry_kicks, "the retry thread is started"
    waiting = status(mm)
    assert "has not been delivered yet" in waiting and "up to 10 minutes" in waiting
    assert CHAT.split(":", 1)[1] not in waiting

    assert due_at(mm, T0 + 29) == T0 + 30
    assert len(run.to(CHAT)) == 1
    assert due_at(mm, T0 + 30) is None
    assert [r["input"] for r in run.to(CHAT)] == [owner_settings.TEST_NOTICE] * 2
    assert not notice_retry.pending(mm.state, CHAT)
    assert settings(mm)[owner_settings.FAILED_KEY] is None
    assert owner_settings.failed_line(plugin._load()[0]) == ""
    # nothing is sent again
    assert due_at(mm, T0 + 3600) is None
    assert len(run.runs) == 2


def test_a_held_call_notice_hermes_cannot_resolve_yet_is_tried_again(mm, monkeypatch):
    mm.hermes(lambda to: (True, ""))
    notify_here(mm, monkeypatch)
    run = mm.hermes(lambda to: (False, unresolved(to)))
    turn(mm)
    send(mm)
    hold.wait_for_notices()
    [first] = run.to(CHAT)
    assert first["input"].startswith("Sentrook held")
    assert notice_retry.pending(mm.state, CHAT)
    assert "has not been delivered yet" in status(mm)

    run.answer = lambda to: (True, "")
    retry_until(mm, 60)
    assert [r["input"] for r in run.to(CHAT)] == [first["input"]] * 2
    assert not notice_retry.pending(mm.state, CHAT)
    assert owner_settings.failed_line(plugin._load()[0]) == ""


def test_backoff_runs_for_ten_minutes_then_the_notice_goes_to_the_home_channel_and_status_says_so(
    mm, monkeypatch
):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["discord", "mattermost"])
    run = mm.hermes(lambda to: (to == "mattermost", unresolved(to)))
    notify_here(mm, monkeypatch)
    assert "then sends it to the mattermost home channel" in status(mm)
    assert retry_until(mm, 10_000) is None
    times = [T0 + s for s in (30, 90, 210, 390, 570, 600)]
    assert len(run.to(CHAT)) == 1 + len(times)
    [home] = run.to("mattermost")
    assert home["input"].startswith(notice_retry.FALLBACK_NOTE.format(platform="mattermost"))
    assert home["input"].endswith(owner_settings.TEST_NOTICE)
    assert mm.clock.t == T0 + notice_retry.WINDOW
    assert not notice_retry.pending(mm.state, CHAT)
    line = status(mm)
    assert owner_settings.FELL_BACK_TEXT.format(platform="mattermost") in line
    assert "could not reach the mattermost chat" in slash(mm, "status")
    assert settings(mm)[owner_settings.FAILED_KEY]["home"] == "mattermost"


def test_the_tries_fall_due_at_the_backoff_times(mm, monkeypatch):
    mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    due, seen = T0 + 30, []
    while due is not None:
        seen.append(due - T0)
        due = due_at(mm, due)
    assert seen == [30, 90, 210, 390, 570, 600]


def test_with_no_home_channel_the_failure_is_kept_after_the_last_try(mm, monkeypatch):
    run = mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    retry_until(mm, 10_000)
    assert run.to("mattermost") == []
    assert not notice_retry.pending(mm.state, CHAT)
    assert owner_settings.FAILED_TEXT.format(where="mattermost chat") in status(mm)
    assert "home" not in settings(mm)[owner_settings.FAILED_KEY]


def test_a_failed_home_channel_send_keeps_the_failure(mm, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    run = mm.hermes(lambda to: (False, unresolved(to) if ":" in to else "Forbidden"))
    notify_here(mm, monkeypatch)
    retry_until(mm, 10_000)
    assert len(run.to("mattermost")) == 1
    assert owner_settings.FAILED_TEXT.format(where="mattermost chat") in status(mm)


def test_a_later_try_that_fails_otherwise_keeps_the_schedule_until_the_window_ends(mm, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    answers = iter([unresolved(CHAT)])
    run = mm.hermes(lambda to: (to == "mattermost", next(answers, "Forbidden")))
    notify_here(mm, monkeypatch)
    assert due_at(mm, T0 + 30) == T0 + 90
    assert run.to("mattermost") == []
    assert "has not been delivered yet" in status(mm)
    retry_until(mm, 10_000)
    assert len(run.to(CHAT)) == 7
    assert len(run.to("mattermost")) == 1
    assert owner_settings.FELL_BACK_TEXT.format(platform="mattermost") in status(mm)


def test_a_notice_another_process_is_trying_is_not_sent_twice(mm, monkeypatch):
    mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    mm.clock.t = T0 + 30
    claimed = notice_retry._claim(mm.state)
    assert claimed is not None and claimed["to"] == CHAT
    assert notice_retry._claim(mm.state) is None
    # the claim runs out if that process died during its send
    mm.clock.t += notice_retry.lease()
    assert notice_retry._claim(mm.state) is not None


def test_the_queue_is_bounded(mm, monkeypatch):
    monkeypatch.setattr(owner_settings, "notice_failed", lambda *a, **k: None)
    for i in range(notice_retry.MAX_PENDING + 5):
        notice_retry.keep(mm.state, CHAT, f"notice {i}", now=T0)
    kept = json.loads((mm.state / notice_retry.FILE).read_text())["notices"]
    assert len(kept) == notice_retry.MAX_PENDING
    assert kept[0]["text"] == "notice 5"


class Stepper:
    """The retry thread's sleep, under the test's control: a wait ends when the thread is woken (a notice kept in this
    process), or at `step`, which moves the clock on by what the thread asked for. Nothing sleeps for real."""

    def __init__(self, clock, state):
        self.clock, self.key, self.waits = clock, str(state), []
        self.go, self.cv, self.waiting = threading.Semaphore(0), threading.Condition(), False

    def __call__(self, event, seconds):
        with self.cv:
            self.waits.append(seconds)
            self.waiting = True
            self.cv.notify_all()
        try:
            while not event.is_set():
                if self.go.acquire(timeout=0.005):
                    self.clock.t += seconds
                    return
        finally:
            with self.cv:
                self.waiting = False
                self.cv.notify_all()

    def _idle(self):
        found = notice_retry._workers.get(self.key)
        return self.waiting and found is not None and not found[1].is_set()

    def ready(self, after=0):
        """Waits until the thread has waited more than `after` times and is waiting, not woken."""
        with self.cv:
            ok = self.cv.wait_for(lambda: len(self.waits) > after and self._idle(), timeout=10)
        assert ok, "the retry thread did not come back to wait"

    def step(self):
        n = len(self.waits)
        self.go.release()
        self.ready(after=n)

    def end(self):
        notice_retry._stopping.set()
        self.go.release()
        notice_retry.stop()


@pytest.fixture
def thread(mm, monkeypatch):
    """The real retry thread, as a process that keeps running has it, on the stand-in clock."""
    monkeypatch.setattr(notice_retry, "kick", REAL_KICK)
    monkeypatch.setattr(notice_retry, "_runs_retries", lambda: True)
    stepper = Stepper(mm.clock, mm.state)
    monkeypatch.setattr(notice_retry, "wait", stepper)
    yield stepper
    stepper.end()


def test_the_retry_thread_tries_again_by_its_clock(mm, monkeypatch, thread):
    tries = iter([False, False, True])
    run = mm.hermes(lambda to: (next(tries), unresolved(to)))
    notify_here(mm, monkeypatch)
    thread.ready()
    assert thread.waits[-1] == 30
    thread.step()  # T0+30: the second try fails
    assert len(run.to(CHAT)) == 2 and thread.waits[-1] == 30  # idle poll, capped at POLL
    thread.step()  # T0+60
    thread.step()  # T0+90: the third try gets through
    assert len(run.to(CHAT)) == 3
    assert {r["thread"] for r in run.to(CHAT)[1:]} == {"sentrook-notice-retry"}
    assert not notice_retry.pending(mm.state, CHAT)
    # idle: it keeps watching the file, one poll at a time
    assert thread.waits[-1] == notice_retry.POLL
    assert list(notice_retry._workers) == [str(mm.state)]


def test_an_idle_thread_picks_up_a_notice_another_process_kept_within_one_poll(
    mm, monkeypatch, thread
):
    """A managed gateway runs each cron job in a worker process, which only writes the queue: the gateway's idle thread
    finds the notice at its next look at the file, and the schedule still counts from when it was kept."""
    run = mm.hermes(lambda to: (True, ""))
    notify_here(mm, monkeypatch)
    notice_retry.resume(mm.state)
    thread.ready()
    assert thread.waits[-1] == notice_retry.POLL
    # the worker process keeps a notice (it does not run retries)
    monkeypatch.setattr(notice_retry, "kick", lambda state_dir: None)
    assert notice_retry.keep(mm.state, CHAT, "Sentrook held a call", now=mm.clock.t)
    run.runs.clear()
    thread.step()  # one poll later
    assert [r["input"] for r in run.runs] == ["Sentrook held a call"]
    assert not notice_retry.pending(mm.state, CHAT)


def test_a_notice_found_late_gets_the_rest_of_its_window(mm, monkeypatch, thread):
    run = mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    notice_retry.resume(mm.state)
    thread.ready()
    monkeypatch.setattr(notice_retry, "kick", lambda state_dir: None)
    notice_retry.keep(mm.state, CHAT, "late", now=mm.clock.t - 500)
    run.runs.clear()
    thread.step()
    kept = [
        e
        for e in json.loads((mm.state / notice_retry.FILE).read_text())["notices"]
        if e["text"] == "late"
    ]
    assert len(run.to(CHAT)) >= 1
    assert kept and kept[0]["next"] <= kept[0]["first"] + notice_retry.WINDOW


def test_the_notify_here_reply_says_the_first_notice_may_take_a_few_minutes(mm, monkeypatch):
    mm.hermes(lambda to: (True, ""))
    reply = notify_here(mm, monkeypatch)
    assert owner_settings.TEST_SENT_CHAT in reply
    assert "may take a few minutes" in reply and "up to 10 minutes" in reply


# ---- must stay silent -----------------------------------------------------------------------------------------


def test_a_failure_other_than_resolve_is_not_tried_again(mm, monkeypatch, notice_retry_kicks):
    run = mm.hermes(lambda to: (False, "Forbidden: the bot was blocked by the user"))
    notify_here(mm, monkeypatch)
    assert len(run.runs) == 1
    assert not (mm.state / notice_retry.FILE).exists()
    assert notice_retry_kicks == []
    assert owner_settings.FAILED_TEXT.format(where="mattermost chat") in status(mm)


def test_a_telegram_dm_by_numeric_id_is_sent_once_as_before(mm, monkeypatch, notice_retry_kicks):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u1")
    run = mm.hermes(lambda to: (True, ""))
    reply = from_chat(mm, monkeypatch, "notify here")
    hold.wait_for_notices()
    turn(mm)
    send(mm)
    hold.wait_for_notices()
    assert [r["to"] for r in run.runs] == ["telegram:4242"] * 2
    assert not (mm.state / notice_retry.FILE).exists()
    assert notice_retry_kicks == []
    assert owner_settings.TEST_SENT_CHAT in reply
    assert owner_settings.failed_line(plugin._load()[0]) == ""


def test_notify_a_platform_with_a_home_channel_is_unchanged(mm, monkeypatch, notice_retry_kicks):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    monkeypatch.setattr(hold, "home_channel_name", lambda p: "town-square")
    run = mm.hermes(lambda to: (True, ""))
    reply = slash(mm, "notify mattermost")
    hold.wait_for_notices()
    assert owner_settings.TEST_SENT.format(where="the mattermost home channel") in reply
    assert "few minutes" not in reply
    turn(mm)
    send(mm)
    hold.wait_for_notices()
    assert [r["to"] for r in run.runs] == ["mattermost"] * 2


def test_a_home_channel_notice_is_never_kept_even_on_a_resolve_error(mm, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    run = mm.hermes(lambda to: (False, unresolved(to)))
    slash(mm, "notify mattermost")
    hold.wait_for_notices()
    assert len(run.runs) == 1
    assert not (mm.state / notice_retry.FILE).exists()


def test_a_notice_through_the_send_message_tool_is_not_kept(h, notice_route):
    """Only `hermes send` is tried again; the send_message tool route stays as it was."""
    notice_route["hermes_send"], notice_route["send_tool"] = False, True
    h.ctx.dispatch_tool = lambda *_a, **_k: json.dumps({"error": unresolved(CHAT)})
    hold.deliver(h.ctx, CHAT, "a notice", state_dir=h.dir / "sentrook")
    hold.wait_for_notices()
    assert not (h.dir / "sentrook" / notice_retry.FILE).exists()


# ---- review fixes ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "keeps_running"),
    [
        (["/usr/bin/hermes", "gateway", "run"], True),
        (["-c", "gateway", "run"], True),
        (["hermes", "--profile", "work", "gateway", "run", "--replace"], True),
        (["hermes", "gateway"], True),
        (["hermes", "gateway", "restart"], True),
        (["hermes", "serve"], True),
        (["hermes", "dashboard"], True),
        (["/opt/hermes/tui_gateway/entry.py"], True),
        (["/opt/hermes/gateway/run.py"], True),
        (["hermes", "gateway", "status"], False),
        (["hermes", "cron", "run", "j1"], False),
        (["hermes", "sentrook", "status"], False),
        (["hermes", "chat", "-q", "gateway"], False),
        (["hermes", "-p", "serve", "chat"], False),
        (["hermes"], False),
        ([], False),
    ],
)
def test_only_a_process_that_keeps_running_runs_the_retry_thread(argv, keeps_running):
    assert notice_retry.long_lived(argv) is keeps_running


def test_a_short_lived_process_only_writes_the_queue(mm, monkeypatch):
    """A `hermes cron run` or `hermes sentrook status` process could be cut off in the middle of a retry's send, which
    would leave the notice claimed and send it again later: it keeps the notice for the gateway and sends nothing."""
    monkeypatch.setattr(notice_retry, "kick", REAL_KICK)
    monkeypatch.setattr(notice_retry, "_runs_retries", lambda: False)
    started = []
    monkeypatch.setattr(notice_retry, "_work", lambda state_dir, event: started.append(state_dir))
    run = mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    plugin.register(mm.ctx)
    notice_retry.resume(mm.state)
    assert started == [] and notice_retry._workers == {}
    assert len(run.runs) == 1
    assert notice_retry.pending(mm.state, CHAT)
    # the gateway picks it up
    monkeypatch.setattr(notice_retry, "_runs_retries", lambda: True)
    notice_retry.resume(mm.state)
    notice_retry.stop()
    assert started == [mm.state]


def test_the_gateway_starts_its_retry_thread_when_a_turn_starts(mm, monkeypatch):
    started = []
    monkeypatch.setattr(
        notice_retry, "_start", lambda state_dir, wake: started.append((state_dir, wake))
    )
    turn(mm)
    assert started == [(mm.state, False)]


def test_a_kept_scan_failure_notice_keeps_its_quiet_period_until_it_finally_fails(mm, monkeypatch):
    """While a notice is being tried again it counts as sent: the caller's `on_fail` (which lets the next notice of
    its kind go out) runs only when the last try fails, so a further failure is not announced and kept again."""
    run = mm.hermes(lambda to: (True, ""))
    notify_here(mm, monkeypatch)
    released = []
    run.answer = lambda to: (False, unresolved(to))
    hold.deliver(
        mm.ctx, CHAT, "scan failure", on_fail=lambda: released.append(1), state_dir=mm.state
    )
    hold.wait_for_notices()
    assert released == []
    assert notice_retry.pending(mm.state, CHAT)
    retry_until(mm, 10_000)
    assert released == [1]


def test_a_kept_notice_that_goes_to_the_home_channel_does_not_run_on_fail(mm, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    run = mm.hermes(lambda to: (True, ""))
    notify_here(mm, monkeypatch)
    released = []
    run.answer = lambda to: (to == "mattermost", unresolved(to))
    hold.deliver(mm.ctx, CHAT, "a save", on_fail=lambda: released.append(1), state_dir=mm.state)
    hold.wait_for_notices()
    retry_until(mm, 10_000)
    assert len(run.to("mattermost")) == 1
    assert released == []


def test_scan_failures_during_the_retries_are_not_announced_again(mm, monkeypatch):
    run = mm.hermes(lambda to: (True, ""))
    notify_here(mm, monkeypatch)
    run.answer = lambda to: (False, unresolved(to))
    turn(mm)
    mm.unreachable = True
    send(mm)
    hold.wait_for_notices()
    send(mm)
    hold.wait_for_notices()
    kept = json.loads((mm.state / notice_retry.FILE).read_text())["notices"]
    assert len(kept) == 1 and kept[0]["text"].startswith("Sentrook could not scan")
    assert len([r for r in run.to(CHAT) if r["input"].startswith("Sentrook could not scan")]) == 1


def test_each_claim_and_try_reads_the_clock_afresh(mm, monkeypatch):
    """With a backlog of slow sends, each claim's lease and each next time start from when that claim or try ran,
    not from when the run began."""
    monkeypatch.setattr(owner_settings, "notice_failed", lambda *a, **k: None)
    for i in range(3):
        notice_retry.keep(mm.state, CHAT, f"notice {i}", now=T0)
    owner = {"platform": "mattermost", "chat_id": CHAT.partition(":")[2], "thread_id": ""}
    (mm.state / "settings.json").write_text(
        json.dumps({"version": 1, "notify": owner, "attended": []})
    )
    leases, settles = [], []

    def slow(to):
        kept = json.loads((mm.state / notice_retry.FILE).read_text())["notices"]
        leases.append(max(e.get("claimed_until", 0) for e in kept) - mm.clock.t)
        mm.clock.t += 50  # each send takes 50 seconds
        return False, unresolved(to)

    real_settle = notice_retry._settle

    def settle(state_dir, nid, next_at):
        settles.append((next_at, mm.clock.t))
        return real_settle(state_dir, nid, next_at)

    monkeypatch.setattr(notice_retry, "_settle", settle)
    mm.hermes(slow)
    due_at(mm, T0 + 30)
    assert leases and set(leases) == {notice_retry.lease()}
    for next_at, at in settles:
        assert next_at is None or next_at > at
        assert next_at is None or next_at <= T0 + notice_retry.WINDOW
    # the first three tries ran at T0+30, +80 and +130, each next one 60 seconds after its own send returned
    assert [n - T0 for n, _ in settles[:3]] == [140, 190, 240]


def test_the_last_try_is_never_after_the_window_ends(mm, monkeypatch):
    def slow(to):
        mm.clock.t += 50
        return False, unresolved(to)

    mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    mm.hermes(slow)
    retry_until(mm, 10_000)
    assert not notice_retry.pending(mm.state, CHAT)
    assert mm.clock.t <= T0 + notice_retry.WINDOW + 50


def test_a_kept_notice_to_a_target_no_longer_in_force_is_dropped_unsent(mm, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    run = mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    slash(mm, "notify off")
    run.runs.clear()
    assert due_at(mm, T0 + 30) is None
    assert run.runs == []
    assert not notice_retry.pending(mm.state, CHAT)


def test_a_kept_notice_is_dropped_when_notices_moved_to_another_chat(mm, monkeypatch):
    run = mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    run.answer = lambda to: (True, "")
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u1")
    from_chat(mm, monkeypatch, "notify here")
    hold.wait_for_notices()
    run.runs.clear()
    due_at(mm, T0 + 30)
    assert run.runs == []
    assert not notice_retry.pending(mm.state, CHAT)


@pytest.mark.parametrize(
    "bad",
    [
        {"claimed_until": "soon"},
        {"next": "later"},
        {"tries": None},
        {"first": float("nan")},
        {"to": 7},
    ],
)
def test_a_malformed_entry_is_dropped_and_the_queue_recovers(mm, monkeypatch, bad):
    run = mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    path = mm.state / notice_retry.FILE
    data = json.loads(path.read_text())
    data["notices"].append({**data["notices"][0], "id": "bad", **bad})
    path.write_text(json.dumps(data))
    assert notice_retry.pending(mm.state, CHAT)
    run.answer = lambda to: (True, "")
    assert due_at(mm, T0 + 30) is None
    assert len(run.to(CHAT)) == 2
    assert json.loads(path.read_text())["notices"] == []
    assert notice_retry.keep(mm.state, CHAT, "again")


def test_an_unreadable_queue_file_starts_afresh(mm):
    path = mm.state / notice_retry.FILE
    mm.state.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json")
    assert not notice_retry.pending(mm.state, CHAT)
    assert notice_retry.keep(mm.state, CHAT, "a notice")
    assert notice_retry.pending(mm.state, CHAT)


def test_a_settle_that_meets_a_held_lock_is_tried_again(mm, monkeypatch):
    mm.hermes(lambda to: (False, unresolved(to)))
    notify_here(mm, monkeypatch)
    real, calls = notice_retry._change, []

    def flaky(state_dir, fn):
        calls.append(fn)
        if len(calls) in (2, 3):  # the settle after the claim
            raise notice_retry.LockTimeout("held")
        return real(state_dir, fn)

    monkeypatch.setattr(notice_retry, "_change", flaky)
    mm.hermes(lambda to: (True, ""))
    assert due_at(mm, T0 + 30) is None
    assert not notice_retry.pending(mm.state, CHAT)


def test_status_says_still_being_tried_while_the_home_channel_send_runs(mm, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    seen = []

    def answer(to):
        if to == "mattermost":
            seen.append(owner_settings.failed_line(plugin._load()[0]))
            return True, ""
        return False, unresolved(to)

    mm.hermes(answer)
    notify_here(mm, monkeypatch)
    retry_until(mm, 10_000)
    assert len(seen) == 1 and "has not been delivered yet" in seen[0]
    assert owner_settings.FELL_BACK_TEXT.format(platform="mattermost") in status(mm)


def test_a_claim_outlasts_the_longest_try():
    assert notice_retry.lease() >= 2 * hold.SEND_TIMEOUT + 30


def test_keep_counts_a_written_notice_as_kept_whatever_fails_after(mm, monkeypatch):
    """Once the queue is written the notice will be tried again, so the caller must not run its `on_fail` too."""

    def boom(*_a, **_k):
        raise notice_retry.LockTimeout("held")

    monkeypatch.setattr(owner_settings, "notice_failed", boom)
    monkeypatch.setattr(notice_retry, "kick", boom)
    assert notice_retry.keep(mm.state, CHAT, "a notice") is True
    assert notice_retry.pending(mm.state, CHAT)


def test_a_failed_record_does_not_leave_the_last_try_claimed(mm, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["mattermost"])
    run = mm.hermes(lambda to: (to == "mattermost", unresolved(to)))
    notify_here(mm, monkeypatch)

    def boom(*_a, **_k):
        raise notice_retry.LockTimeout("held")

    monkeypatch.setattr(owner_settings, "notice_failed", boom)
    retry_until(mm, 10_000)
    assert not notice_retry.pending(mm.state, CHAT)
    mm.clock.t += notice_retry.lease() + 1
    assert notice_retry.run_due(mm.state) is None
    assert len(run.to("mattermost")) == 1


REAL_KICK = notice_retry.kick
