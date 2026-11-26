"""Where notices go (`notify`) and which extra platforms count as attended (`attended`), set by owner command.

Both are kept in `<hermes home>/sentrook/settings.json`. The config values (`owner_channel`,
`attended_platforms`) still apply; a notice target set by command wins over `owner_channel`, and the
platforms added by command join `attended_platforms`. `status`, `verify`, `help`, `notify status` and
`attended list` show the same plain explanation of each.
"""

import json
import types

import pytest

import plugin
from plugin import cli, commands, hold, owner_settings

from . import test_hold
from .test_hold import _cron, send, slash, turn
from .test_plugin import call
from .test_plugin import turn as chat_turn

DM_USER = "u1"

#: The held-call harness and its `hermes send` stand-in, as fixtures of this module too.
h = test_hold.h
hermes_send = test_hold.hermes_send


def source(platform="telegram", chat_id="4242", thread_id=None, chat_type="dm"):
    """A gateway SessionSource as Hermes passes it to a plugin command handler."""
    return types.SimpleNamespace(
        platform=types.SimpleNamespace(value=platform),
        chat_id=chat_id,
        thread_id=thread_id,
        chat_type=chat_type,
        user_id=DM_USER,
    )


def from_chat(h, monkeypatch, raw, *, facts=None, src=None, platform="telegram"):
    """`raw` sent as `/sentrook ...` in a chat (by default the owner's Telegram DM), then back to the
    harness's local terminal for whatever the test runs next."""
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", DM_USER)
    src = source(platform) if src is None else src
    if facts is None:
        # The gateway binds the same chat for the owner check as it passes the handler.
        facts = {
            "platform": platform,
            "chat_type": "dm",
            "user_id": DM_USER,
            "chat_id": src.chat_id,
        }
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(facts))
    monkeypatch.setattr(plugin, "session_surface", lambda: "")
    try:
        return h.ctx.commands["sentrook"]["handler"](
            raw,
            session_id="s-chat",
            session_key="k-chat",
            platform=platform,
            source=src,
        )
    finally:
        monkeypatch.setattr(plugin, "session_facts", lambda: {})
        monkeypatch.setattr(plugin, "session_surface", lambda: "cli")


def held(h):
    """The held-call notices sent, as (target, text)."""
    return [
        (s["args"]["target"], s["args"]["message"])
        for s in h.sent
        if s["args"]["message"].startswith("Sentrook held")
    ]


def sent_test_notices(h):
    return [
        s["args"]["target"] for s in h.sent if s["args"]["message"] == owner_settings.TEST_NOTICE
    ]


def records(h, kind):
    return [r for r in h.traffic() if r.get("kind") == kind]


def settings_file(h):
    return json.loads((h.dir / "sentrook" / "settings.json").read_text())


def status_lines(h):
    return slash(h, "status").splitlines()


def verify(h):
    return {n: (ok, d) for n, ok, d in cli.run_verify(dict(h.ctx.settings), timeout=0.01)}


# ---- must stay silent (works): notify ------------------------------------------------------------------


def test_notify_here_in_a_telegram_dm_sends_the_next_held_call_notice_to_that_dm(h, monkeypatch):
    del h.ctx.settings["owner_channel"]
    reply = from_chat(h, monkeypatch, "notify here")
    hold.wait_for_notices()
    assert sent_test_notices(h) == ["telegram:4242"]
    assert "A test notice was sent to this chat." in reply
    line = owner_settings.notify_line(owner_settings.notify_of(plugin._load()[0]))
    assert line.startswith(
        "Notices: the telegram chat where you sent /sentrook notify here (set by command)."
    )
    assert line in reply
    assert settings_file(h)["notify"]["platform"] == "telegram"
    assert settings_file(h)["notify"]["chat_id"] == "4242"

    turn(h)
    _out, rec = send(h)
    assert [t for t, _ in held(h)] == ["telegram:4242"]
    # The traffic log names the platform, never the chat id (on Telegram a DM's id is the person's).
    assert rec["hold"]["notice"] == {"status": "queued", "target": "telegram chat"}
    assert line in status_lines(h)
    assert "set by command" in slash(h, "status")
    assert "4242" not in json.dumps(h.traffic())


def test_notify_here_sends_with_hermes_send_to_that_chat_and_thread(h, hermes_send, monkeypatch):
    from_chat(h, monkeypatch, "notify here", src=source(chat_id="-1009", thread_id="17"))
    turn(h)
    send(h)
    assert [r["argv"][2:4] for r in hermes_send.runs] == [["--to", "telegram:-1009:17"]] * 2
    assert hermes_send.runs[0]["input"] == owner_settings.TEST_NOTICE


def test_a_command_set_target_wins_over_owner_channel_in_config_and_status_names_both(
    h, monkeypatch
):
    h.ctx.settings["owner_channel"] = "discord"
    from_chat(h, monkeypatch, "notify here")
    turn(h)
    send(h)
    assert [t for t, _ in held(h)] == ["telegram:4242"]
    [line] = [x for x in status_lines(h) if x.startswith("Notices:")]
    assert "telegram" in line and "set by command" in line
    assert "owner_channel discord in config is not used" in line
    assert verify(h)["notice target"] == (True, line)


def test_notify_off_goes_back_to_owner_channel_in_config(h, monkeypatch):
    h.ctx.settings["owner_channel"] = "discord"
    from_chat(h, monkeypatch, "notify here")
    reply = slash(h, "notify off")
    assert "owner_channel discord in config applies again" in reply
    assert settings_file(h)["notify"] is None
    turn(h)
    send(h)
    assert [t for t, _ in held(h)] == ["discord"]
    assert [r["op"] for r in records(h, "settings")] == ["notify_here", "notify_off"]


def test_notify_platform_from_the_terminal_needs_its_home_channel(h, monkeypatch):
    del h.ctx.settings["owner_channel"]
    monkeypatch.setattr(hold, "home_channel_name", lambda p: "ops-home")
    reply = slash(h, "notify discord")
    assert "home channel, which is ops-home" in reply
    turn(h)
    send(h)
    assert [t for t, _ in held(h)] == ["discord"]
    assert sent_test_notices(h) == ["discord"]
    assert "Notices: the discord home channel (set by command)." in slash(h, "notify status")


def test_notify_here_without_a_chat_id_falls_back_to_the_home_channel_and_says_so(h, monkeypatch):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["discord", "telegram"])
    monkeypatch.setattr(hold, "home_channel_name", lambda p: "family-group")
    reply = from_chat(h, monkeypatch, "notify here", src=source(chat_id=""))
    assert "notices will go to telegram's home channel, which is family-group, not this chat" in (
        reply
    )
    assert settings_file(h)["notify"] == {**settings_file(h)["notify"], "platform": "telegram"}
    assert "chat_id" not in settings_file(h)["notify"]


# ---- must stay silent (works): attended ----------------------------------------------------------------


def test_attended_add_api_server_turns_its_holds_into_approval_prompts(harness, monkeypatch):
    monkeypatch.setattr(plugin, "session_facts", lambda: {})
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    chat_turn(harness, platform="api_server")
    assert call(harness, "c1", "rm REVIEW")["action"] == "block"
    reply = harness.ctx.commands["sentrook"]["handler"](
        "attended add api_server --confirm", session_id=""
    )
    assert "This loosens Sentrook" in reply
    assert call(harness, "c2", "rm REVIEW")["action"] == "approve"
    line = owner_settings.attended_line(plugin._load()[0])
    assert line.startswith("Attended platforms: api_server (set by command).")
    status = commands.run_status("", dict(harness.ctx.settings)).splitlines()
    assert line in status

    reply = harness.ctx.commands["sentrook"]["handler"]("attended remove api_server", session_id="")
    assert "held for you again" in reply
    assert call(harness, "c3", "rm REVIEW")["action"] == "block"
    ops = [r["op"] for r in harness.traffic() if r.get("kind") == "settings"]
    assert ops == ["attended_add", "attended_remove"]


def test_attended_list_names_the_config_and_command_sources(h):
    h.ctx.settings["attended_platforms"] = ["webhook"]
    slash(h, "attended add api_server --confirm")
    out = slash(h, "attended list")
    assert "api_server (set by command)" in out and "webhook (config)" in out
    assert "is set in the plugin config" in slash(h, "attended remove webhook")


# ---- must fire / refuse ----------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["notify here", "attended add api_server --confirm"])
@pytest.mark.parametrize(
    "who",
    [
        {"platform": "telegram", "chat_type": "group", "user_id": DM_USER},
        {"platform": "telegram", "chat_type": "dm", "user_id": "u2"},
        "allow-all",
    ],
)
def test_a_non_owner_a_group_chat_or_an_allow_all_dm_is_refused_and_audited(
    h, monkeypatch, raw, who
):
    if who == "allow-all":
        monkeypatch.setenv("TELEGRAM_ALLOW_ALL_USERS", "true")
        facts = {"platform": "telegram", "chat_type": "dm", "user_id": "u9"}
    else:
        facts = who
    reply = from_chat(h, monkeypatch, raw, facts=facts)
    verb = raw.split()[0]
    assert reply.startswith(f"Only the owner can run /sentrook {verb}")
    assert not (h.dir / "sentrook" / "settings.json").exists()
    [rec] = records(h, "command")
    assert (rec["verb"], rec["outcome"]) == (verb, "refused")
    assert records(h, "settings") == []


def test_attended_add_refuses_an_unknown_platform_with_the_known_list(h):
    reply = slash(h, "attended add api-server")
    assert reply.startswith('Unknown platform "api-server".')
    assert "api_server" in reply and "webhook" in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()


#: Front ends that may put a person in front of Hermes's approval prompts.
FRONT_ENDS = [
    "a2a",
    "api_server",
    "homeassistant",
    "msgraph_webhook",
    "relay",
    "webhook",
    "wecom_callback",
]
#: Runs Hermes starts itself (where an approval nobody answers may be auto-approved), Raft (its prompts reach
#: nobody), and the local terminal (attended only with a terminal, which a scripted run lacks).
NEVER = [
    "batch",
    "codex",
    "cron",
    "curator",
    "gateway",
    "kanban",
    "raft",
    "subagent",
    "tool",
    "cli",
    "local",
]


def test_every_platform_is_in_exactly_one_group():
    groups = [
        set(FRONT_ENDS),
        set(NEVER),
        set(owner_settings.ATTENDED_BY_DEFAULT),
    ]
    assert set().union(*groups) == set(owner_settings.KNOWN_PLATFORMS)
    assert sum(map(len, groups)) == len(owner_settings.KNOWN_PLATFORMS)
    assert set(FRONT_ENDS) == set(owner_settings.CONFIRMABLE)


@pytest.mark.parametrize("platform", FRONT_ENDS)
def test_attended_add_of_a_front_end_needs_confirm_and_warns(h, platform):
    reply = slash(h, f"attended add {platform}")
    assert reply.startswith(f"Warning: Sentrook treats {platform} as a place nobody watches.")
    assert f"/sentrook attended add {platform} --confirm" in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()
    assert "This loosens Sentrook" in slash(h, f"attended add {platform} --confirm")


@pytest.mark.parametrize("platform", NEVER)
def test_self_started_runs_and_the_local_terminal_can_never_be_added(h, platform):
    reply = slash(h, f"attended add {platform} --confirm")
    assert "Nothing was changed" in reply
    assert "Warning" not in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()


@pytest.mark.parametrize("platform", ["kanban", "cli"])
def test_a_never_attended_platform_in_the_file_does_not_apply(h, platform):
    path = h.dir / "sentrook" / "settings.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"version": 1, "attended": [{"platform": platform}]}))
    assert owner_settings.attended_of(plugin._load()[0]) == frozenset()


def test_a_platform_attended_by_default_is_not_added(h):
    assert "already attended" in slash(h, "attended add telegram")
    assert not (h.dir / "sentrook" / "settings.json").exists()


def test_notify_here_with_no_home_channel_and_no_chat_id_is_refused_with_what_to_set(
    h, monkeypatch
):
    monkeypatch.setattr(hold, "home_platforms", lambda: ["discord"])
    reply = from_chat(h, monkeypatch, "notify here", src=source(chat_id=""))
    assert "telegram has no home channel" in reply
    assert "send /sethome in the chat where you want notices" in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()


def test_notify_here_with_a_chat_other_than_the_one_the_owner_check_passed_is_refused(
    h, monkeypatch
):
    """The owner check passed for the owner's DM, but the chat the handler is given is another one."""
    facts = {"platform": "telegram", "chat_type": "dm", "user_id": DM_USER, "chat_id": "4242"}
    reply = from_chat(h, monkeypatch, "notify here", facts=facts, src=source(chat_id="-100123"))
    assert "could not tell which chat" in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()


def test_notify_here_takes_the_chat_type_from_the_owner_check_when_the_chat_has_none(
    h, monkeypatch
):
    facts = {"platform": "telegram", "chat_type": "dm", "user_id": DM_USER, "chat_id": "4242"}
    reply = from_chat(h, monkeypatch, "notify here", facts=facts, src=source(chat_type=""))
    assert "A test notice was sent to this chat." in reply
    assert settings_file(h)["notify"]["chat_id"] == "4242"


def test_notify_here_from_the_local_terminal_naming_a_chat_is_refused(h):
    """The owner passed as the local terminal, yet the handler was given a chat platform's source."""
    reply = h.ctx.commands["sentrook"]["handler"](
        "notify here", session_id="", platform="cli", source=source()
    )
    assert "could not tell which chat" in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()


def failing_sends(h):
    """Every send answers as Hermes does for a chat it cannot address."""
    h.ctx.dispatch_tool = lambda *_a, **_k: json.dumps(
        {"error": "Could not resolve '4242' on telegram."}
    )


def test_notify_here_says_a_test_notice_was_sent_and_what_to_do_if_it_does_not_arrive(
    h, monkeypatch
):
    reply = from_chat(h, monkeypatch, "notify here")
    hold.wait_for_notices()
    assert sent_test_notices(h) == ["telegram:4242"]
    assert owner_settings.TEST_SENT_CHAT in reply
    assert "/sentrook notify status" in reply
    assert owner_settings.FAILED_TEXT[:20] not in slash(h, "notify status")


def test_a_test_notice_that_was_not_delivered_is_reported_until_a_notice_gets_through(
    h, monkeypatch
):
    """Must fire: Hermes could not send the test notice (on some platforms it reaches a new chat only once it
    has listed it), so notify status, status and verify say so; the next notice that gets through clears it."""
    failing_sends(h)
    from_chat(h, monkeypatch, "notify here")
    hold.wait_for_notices()
    warning = owner_settings.failed_line(plugin._load()[0])
    assert warning.startswith("The last notice to the telegram chat was not delivered:")
    assert warning in slash(h, "notify status")
    assert warning in status_lines(h)
    assert warning in verify(h)["notice target"][1]
    assert "4242" not in slash(h, "status")

    h.sent.clear()
    h.ctx.dispatch_tool = lambda name, args, **_k: (
        h.sent.append({"name": name, "args": args}) or json.dumps({"success": True})
    )
    turn(h)
    send(h)
    assert [t for t, _ in held(h)] == ["telegram:4242"]
    assert owner_settings.failed_line(plugin._load()[0]) == ""
    assert warning not in slash(h, "status")


def test_a_failed_test_notice_is_forgotten_when_the_target_changes(h, monkeypatch):
    failing_sends(h)
    from_chat(h, monkeypatch, "notify here")
    hold.wait_for_notices()
    assert owner_settings.failed_line(plugin._load()[0])
    slash(h, "notify off")
    assert owner_settings.failed_line(plugin._load()[0]) == ""
    assert settings_file(h).get(owner_settings.FAILED_KEY) is None


def test_notify_here_from_the_terminal_is_refused_with_the_platform_form(h):
    reply = slash(h, "notify here")
    assert "There is no chat here" in reply and "/sentrook notify <platform>" in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()


def test_notify_a_platform_without_a_home_channel_is_refused(h):
    reply = slash(h, "notify telegram")
    assert "telegram has no home channel" in reply and "discord" in reply
    assert not (h.dir / "sentrook" / "settings.json").exists()


def test_the_cli_form_takes_confirm_as_a_flag(h):
    import argparse

    ran = []
    real = cli.dispatch
    try:
        cli.dispatch = lambda raw, *a, **k: ran.append(raw) or ""  # type: ignore[assignment]
        parser = argparse.ArgumentParser()
        cli.register_cli(
            types.SimpleNamespace(
                register_cli_command=lambda **kw: (
                    kw["setup_fn"](parser) or setattr(parser, "handler", kw["handler_fn"])
                )
            ),
            lambda: {},
            lambda *_a, **_k: None,
        )
        parser.handler(parser.parse_args(["attended", "add", "api_server", "--confirm"]))
        parser.handler(parser.parse_args(["notify", "telegram"]))
    finally:
        cli.dispatch = real  # type: ignore[assignment]
    assert ran == ["attended add api_server --confirm", "notify telegram"]


# ---- one explanation, wherever shown ----------------------------------------------------------------------


def test_status_verify_and_help_show_the_same_explanations(h):
    del h.ctx.settings["owner_channel"]
    cfg = plugin._load()[0]
    notices = owner_settings.notify_line(owner_settings.notify_of(cfg))
    attended = owner_settings.attended_line(cfg)
    assert notices == (
        "Notices not set: calls held on scheduled jobs and other runs nobody watches are held "
        "silently. In the chat where you want notices, send /sentrook notify here."
    )
    assert attended.startswith("Attended platforms: none added.")
    assert notices in status_lines(h)
    assert attended in status_lines(h)
    assert verify(h)["notice target"] == (True, notices)
    assert verify(h)["approval prompts"] == (True, attended)
    helped = slash(h, "help")
    assert notices in helped and attended in helped
    assert notices in slash(h, "notify status")
    assert attended in slash(h, "attended list")


def test_open_status_and_help_never_show_the_chat_id(h, monkeypatch):
    from_chat(h, monkeypatch, "notify here", src=source(chat_id="-1009876", thread_id="55"))
    for text in (slash(h, "status"), slash(h, "help"), slash(h, "notify status")):
        assert "-1009876" not in text and ":55" not in text
    assert "-1009876" not in json.dumps(h.traffic())


def test_a_scan_failure_notice_goes_to_the_chat_set_by_command(h, monkeypatch):
    del h.ctx.settings["owner_channel"]
    from_chat(h, monkeypatch, "notify here")
    h.unreachable = True
    out, rec = _cron(h)
    assert out["action"] == "block"
    assert rec["notice"] == {"status": "queued", "target": "telegram chat"}
    failure = [s for s in h.sent if s["args"]["message"] != owner_settings.TEST_NOTICE]
    assert [s["args"]["target"] for s in failure] == ["telegram:4242"]


def test_the_hermes_log_names_the_platform_not_the_chat(h, notice_route, monkeypatch, caplog):
    from_chat(h, monkeypatch, "notify here", src=source(chat_id="-1009876"))
    h.ctx.dispatch_tool = lambda *_a, **_k: json.dumps({"error": "Could not resolve '-1009876'"})
    turn(h)
    send(h)
    assert "not delivered" in caplog.text and "telegram chat" in caplog.text
    assert "-1009876" not in caplog.text


def test_both_verbs_are_owner_only_in_help():
    out = commands.run_help()
    assert "/sentrook notify " in out and "/sentrook attended " in out
    for line in out.splitlines():
        if line.startswith(("/sentrook notify", "/sentrook attended")):
            assert line.endswith("(owner only)")
