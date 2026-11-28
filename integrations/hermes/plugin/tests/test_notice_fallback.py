"""With no notice target set, a held call's notice goes to the job's own delivery chat, else the owner's direct
message where Hermes can address one, and says how to set a target. It never goes to a chat the owner did not
choose for the job: not a home channel the job does not deliver to, not a broadcast, not a group. Status, verify and
the setup report warn when calls are held and no target is set.
"""

from datetime import UTC, datetime

import pytest

from plugin import cli, commands, hold

from . import test_run_now
from .test_run_now import HELD, call, end_run, write_jobs

h = test_run_now.h
JOB = test_run_now.JOB
OWNER = "424242"
GROUP = "-1001234567"


@pytest.fixture
def unset(h, monkeypatch):
    """The held-call harness with no notice target: no `owner_channel`, nothing set by command. Discord has a home
    channel (the harness's), Telegram is connected without one, and no allowlist names the owner."""
    del h.ctx.settings["owner_channel"]
    monkeypatch.setattr(hold, "connected_platforms", lambda: ["discord", "telegram"])
    for k in ("TELEGRAM_ALLOWED_USERS", "GATEWAY_ALLOWED_USERS", "DISCORD_ALLOWED_USERS"):
        monkeypatch.delenv(k, raising=False)
    return h


def job(h, **fields):
    write_jobs(h, [{**JOB, **fields}])


def sends(h):
    return [s["args"] for s in h.sent if s["name"] == "send_message"]


def notice_of(rec):
    return rec["hold"]["notice"]


# ---- must stay silent: the notice is delivered ----------------------------------------------------------------


def test_a_held_cron_call_with_no_target_goes_to_the_jobs_origin_chat(unset):
    job(
        unset,
        deliver="origin",
        origin={"platform": "telegram", "chat_id": GROUP, "chat_name": "Ops"},
    )
    out, rec = call(unset, 1)
    assert out == HELD
    [sent] = sends(unset)
    assert sent["target"] == f"telegram:{GROUP}"
    assert hold.fallback_note(hold.VIA_JOB, commands.CMD) in sent["message"]
    assert notice_of(rec) == {"status": "queued", "target": "telegram chat", "via": hold.VIA_JOB}


def test_the_origin_chats_thread_is_kept(unset):
    job(
        unset,
        deliver="origin",
        origin={"platform": "telegram", "chat_id": GROUP, "thread_id": "17"},
    )
    call(unset, 1)
    assert [s["target"] for s in sends(unset)] == [f"telegram:{GROUP}:17"]


@pytest.mark.parametrize(
    "deliver, to",
    [
        (f"telegram:{GROUP}", f"telegram:{GROUP}"),
        (f"local,telegram:{GROUP}", f"telegram:{GROUP}"),
        ([f"telegram:{GROUP}"], f"telegram:{GROUP}"),
        ("discord", "discord"),  # the job delivers to the Discord home channel itself
    ],
)
def test_a_job_that_names_its_chat_gets_the_notice_there(unset, deliver, to):
    job(unset, deliver=deliver)
    call(unset, 1)
    assert [s["target"] for s in sends(unset)] == [to]


def test_the_run_end_line_goes_to_the_jobs_chat_too(unset):
    job(unset, deliver=f"telegram:{GROUP}")
    for i, tool in enumerate(("terminal", "web_extract")):
        unset.reply = {
            **test_run_now.NAMED,
            "tool_description": {"category": "fetches_remote_content", "template": "Runs {E1}"},
        }
        call(unset, 1, cid=f"c{i}", tool=tool)
    end_run(unset, 1)
    assert [s["target"] for s in sends(unset)] == [f"telegram:{GROUP}"] * 2
    [rec] = [r for r in unset.traffic() if r.get("kind") == "run_group"]
    assert rec["notice"] == {"status": "queued", "target": "telegram chat", "via": hold.VIA_JOB}
    assert hold.fallback_note(hold.VIA_JOB, commands.CMD) in sends(unset)[-1]["message"]


def test_a_job_with_no_chat_falls_back_to_the_one_allowlisted_owner(unset, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", OWNER)
    job(unset, deliver="local")
    _out, rec = call(unset, 1)
    [sent] = sends(unset)
    assert sent["target"] == f"telegram:{OWNER}"
    assert hold.fallback_note(hold.VIA_DM, commands.CMD) in sent["message"]
    assert notice_of(rec) == {"status": "queued", "target": "telegram chat", "via": hold.VIA_DM}


def test_the_jobs_chat_comes_before_the_owners_direct_message(unset, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", OWNER)
    job(unset, deliver=f"telegram:{GROUP}")
    call(unset, 1)
    assert [s["target"] for s in sends(unset)] == [f"telegram:{GROUP}"]


# ---- must fire: no fallback where the owner did not choose ----------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"deliver": "local"},
        {"deliver": "all"},  # a broadcast to every home channel
        {"deliver": "origin"},  # no origin: Hermes would pick a home channel itself
        {"deliver": "origin", "origin": {"platform": "api_server", "chat_id": "x1"}},
        {"deliver": "bot-chat"},
        {"deliver": "telegram"},  # Telegram has no home channel and the job no origin there
        {"deliver": None},
    ],
)
def test_no_fallback_to_a_chat_the_job_does_not_deliver_to(unset, fields):
    job(unset, **fields)
    out, rec = call(unset, 1)
    assert out == HELD
    assert sends(unset) == [], "never the Discord home channel or any other group"
    assert notice_of(rec) == {"status": "unsent", "target": None, "reason": hold.NO_OWNER_CHANNEL}


@pytest.mark.parametrize(
    "env",
    [
        # two people: which one is the owner is not known
        {"TELEGRAM_ALLOWED_USERS": f"{OWNER},777"},
        {"TELEGRAM_ALLOWED_USERS": GROUP},  # a negative id is a group, not a person
        {"TELEGRAM_ALLOWED_USERS": "*"},
        {"GATEWAY_ALLOWED_USERS": OWNER},  # not tied to a platform
        {"DISCORD_ALLOWED_USERS": OWNER},  # a Discord user id is not a chat Hermes can send to
    ],
)
def test_no_direct_message_without_one_owner_hermes_can_address(unset, monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    job(unset, deliver="local")
    call(unset, 1)
    assert sends(unset) == []


def test_no_direct_message_on_a_platform_that_is_not_connected(unset, monkeypatch):
    monkeypatch.setattr(hold, "connected_platforms", lambda: ["discord"])
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", OWNER)
    job(unset, deliver="local")
    call(unset, 1)
    assert sends(unset) == []


def test_with_a_target_set_nothing_changes(h, monkeypatch):
    """The harness's `owner_channel` is Discord: the notice goes to its home channel, with no fallback note."""
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", OWNER)
    job(h, deliver=f"telegram:{GROUP}")
    _out, rec = call(h, 1)
    [sent] = sends(h)
    assert sent["target"] == "discord"
    assert "No notice target is set" not in sent["message"]
    assert notice_of(rec) == {"status": "queued", "target": "discord"}


# ---- status, verify and the setup report warn ------------------------------------------------------------------


def test_status_and_verify_warn_when_calls_are_held_and_no_target_is_set(unset):
    job(unset, deliver="local")
    call(unset, 1)
    status = commands.run_status("", dict(unset.ctx.settings)).splitlines()
    [line] = [x for x in status if x.startswith("held calls: ")]
    assert hold.UNSET_WARNING.format(n=1) in line
    checks = {n: (ok, d) for n, ok, d in cli.run_verify(dict(unset.ctx.settings), timeout=0.01)}
    ok, detail = checks["held-call notices"]
    assert ok is False and hold.UNSET_WARNING.format(n=1) in detail


def test_no_warning_without_held_calls(unset):
    status = commands.run_status("", dict(unset.ctx.settings))
    assert "WARNING" not in status
    checks = {n: (ok, d) for n, ok, d in cli.run_verify(dict(unset.ctx.settings), timeout=0.01)}
    assert checks["held-call notices"][0] is True


def test_with_a_target_held_calls_raise_no_warning(h):
    job(h, deliver="local")
    call(h, 1)
    assert "WARNING" not in commands.run_status("", dict(h.ctx.settings))
    checks = {n: (ok, d) for n, ok, d in cli.run_verify(dict(h.ctx.settings), timeout=0.01)}
    assert checks["held-call notices"][0] is True


def test_the_unset_warning_counts_waiting_holds(tmp_path):
    from plugin.owner_settings import Notify

    assert hold.unset_warning(tmp_path, Notify(), datetime.now(UTC)) == ""


def test_a_fallback_notice_is_never_kept_for_a_retry(unset, monkeypatch):
    """A kept notice's last try goes to the platform's home channel, which the job did not choose: a fallback notice is
    sent once, with no state folder, so `notice_retry` never sees it."""
    import plugin

    calls = []
    monkeypatch.setattr(hold, "deliver", lambda *a, **kw: calls.append(kw))
    cfg = plugin._load()[0]
    plugin._deliver(cfg, f"telegram:{GROUP}", "text", via=hold.VIA_JOB)
    plugin._deliver(cfg, "discord", "text")
    assert "state_dir" not in calls[0] and calls[1]["state_dir"] == cfg.state_dir
