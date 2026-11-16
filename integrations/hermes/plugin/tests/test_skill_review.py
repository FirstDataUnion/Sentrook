"""Hermes's self-improvement loop: its skill and memory saves are declared to the scanner as self-edits.

A loop save is `skill_manage` or `memory` called while Hermes's write origin is `background_review` and the
review is unattended (the automatic review and the curator, not an owner's `/refine`). With `skill_review:
allow` (the default) it is sent with trigger system and a `self_edit` block; the scanner's verdict is then
applied like any other. With `skill_review: review` it is sent like any other call. Nothing else changes.
"""

import io
import sys

import pytest

import plugin
from plugin import commands, config, history

SID = {"session_id": "S1", "task_id": "S1"}
SYSTEM_TRIGGER = {
    "kind": "system",
    "channel": None,
    "sender": {"relation": "unknown", "basis": ["none"]},
}

LOOP_CALLS = [
    ("skill_manage", {"action": "create", "name": "tidy", "content": "# Tidy\nSteps."}, "skills"),
    (
        "skill_manage",
        {"action": "patch", "name": "tidy", "old_string": "Steps.", "new_string": "Two steps."},
        "skills",
    ),
    ("skill_manage", {"action": "edit", "name": "tidy", "content": "# Tidy\nNew."}, "skills"),
    ("skill_manage", {"action": "delete", "name": "tidy"}, "skills"),
    (
        "memory",
        {"action": "add", "target": "memory", "content": "Prefers short replies."},
        "memory",
    ),
]
LOOP_IDS = ["create", "patch", "edit", "delete", "memory-add"]


class Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def h(loop_h):
    return loop_h


def turn(h, platform, text="", turn_id="t1"):
    h.ctx.hooks["pre_llm_call"](
        turn_id=turn_id, user_message=text, platform=platform, sender_id="u1", **SID
    )


def call(h, tool, args):
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool, args=args, tool_call_id=f"c{len(h.scans)}", turn_id="t1", **SID
    )
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def history_action(h):
    scans = history.recent_scans(h.dir / "sentrook" / "traffic.jsonl", 1)
    return history.action_of(*scans[0])


# ---- must declare ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "args", "store"), LOOP_CALLS, ids=LOOP_IDS)
@pytest.mark.parametrize("platform", ["telegram", "api_server", "webhook", "cli", "curator", None])
def test_a_loop_save_is_declared_as_a_self_edit(h, monkeypatch, tool, args, store, platform):
    """Attended chat, API server, webhook, the local terminal, the curator (its own platform), and a
    run with no turn recorded: trigger system, the block with the save's store, and the scanner's
    allow applied."""
    if platform == "cli":
        monkeypatch.setattr(sys, "stdin", Tty())
    if platform is not None:
        turn(h, platform, "keep replies short")
    out, rec = call(h, tool, args)
    assert out is None
    assert (rec["verdict"], rec["decision"], rec["skill_review"]) == ("allow", "allowed", True)
    sent = h.scans[-1]
    assert sent["trigger"] == SYSTEM_TRIGGER
    assert sent["self_edit"]["kind"] == "background_review"
    assert sent["self_edit"]["store"] == store
    assert isinstance(sent["self_edit"]["conversation"], list)
    assert rec["planir"]["self_edit"] == sent["self_edit"]


# ---- the verdict decides -------------------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "args", "store"), LOOP_CALLS, ids=LOOP_IDS)
@pytest.mark.parametrize("platform", ["api_server", "webhook", "curator", None])
def test_an_unattended_review_of_a_loop_save_is_a_block(h, tool, args, store, platform):
    if platform is not None:
        turn(h, platform)
    h.reply.update(risk=55)
    out, rec = call(h, tool, args)
    assert out["action"] == "block"
    assert (rec["verdict"], rec["decision"], rec["skill_review"]) == ("review", "blocked", True)
    assert history_action(h) == "blocked (no reviewer)"
    assert "self_edit" in h.scans[-1]


@pytest.mark.parametrize("platform", ["telegram", "cli"])
def test_an_attended_review_of_a_loop_save_asks(h, monkeypatch, platform):
    if platform == "cli":
        monkeypatch.setattr(sys, "stdin", Tty())
    turn(h, platform)
    h.reply.update(risk=55)
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "approve"
    assert rec["decision"] == "review_timed_out" and rec["skill_review"] is True
    assert history_action(h) == "review"


@pytest.mark.parametrize("platform", ["api_server", "webhook", None])
def test_a_reviewed_bare_save_is_blocked_unattended_and_still_declared(h, platform):
    """The scanner reviews a loop save whose only reasons are the save itself and the system trigger: the
    plugin applies that review as it is (no allow of its own), and the save still carries its block."""
    if platform is not None:
        turn(h, platform, "keep replies short")
    h.reply.update(risk=55, reasons=[{"code": "selfmod.memory"}, {"code": "trigger.system"}])
    out, rec = call(h, *LOOP_CALLS[4][:2])
    assert out is not None and out["action"] == "block"
    assert (rec["verdict"], rec["decision"], rec["skill_review"]) == ("review", "blocked", True)
    assert history_action(h) == "blocked (no reviewer)"
    sent = h.scans[-1]
    assert sent["trigger"] == SYSTEM_TRIGGER and sent["self_edit"]["store"] == "memory"


def test_a_block_is_still_a_block(h):
    turn(h, "telegram")
    h.reply.update(risk=92)
    out, rec = call(h, *LOOP_CALLS[3][:2])
    assert out["action"] == "block" and rec["verdict"] == "block"


@pytest.mark.parametrize("floor", ["review", "block"])
def test_an_enforced_floor_applies(h, floor):
    turn(h, "telegram")
    h.reply.update(risk=20, enforced=floor)
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == ("approve" if floor == "review" else "block")
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[4][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"


def test_observe_mode_is_unchanged(h):
    h.ctx.settings["mode"] = "observe"
    turn(h, "api_server")
    h.reply.update(risk=55)
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out is None and history_action(h) == "observed (would review)"
    assert "self_edit" in h.scans[-1]


# ---- must not declare -----------------------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "args", "store"), LOOP_CALLS, ids=LOOP_IDS)
def test_an_owner_turn_save_is_sent_as_before(h, tool, args, store):
    """Origin assistant_tool: the owner asked for it in a turn. Normal trigger, no block."""
    h.prov["origin"] = "assistant_tool"
    turn(h, "telegram", "remember that I like short replies")
    h.reply.update(risk=55)
    out, rec = call(h, tool, args)
    assert out["action"] == "approve"
    assert "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "message" and "self_edit" not in h.scans[-1]
    turn(h, "api_server")
    out, rec = call(h, tool, args)
    assert out["action"] == "block" and "self_edit" not in h.scans[-1]


def test_an_attended_refine_is_sent_as_before(h):
    h.prov["attended"] = True
    turn(h, "telegram")
    h.reply.update(risk=55)
    out, rec = call(h, *LOOP_CALLS[1][:2])
    assert out["action"] == "approve" and "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "message" and "self_edit" not in h.scans[-1]


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("terminal", {"command": "ls"}),
        ("write_file", {"path": "skills/tidy/SKILL.md", "content": "x"}),
        ("patch", {"path": "skills/tidy/SKILL.md", "old": "a", "new": "b"}),
        ("read_file", {"path": "skills/tidy/SKILL.md"}),
        ("skills_list", {}),
    ],
)
def test_other_tools_in_a_loop_run_are_sent_normally(h, tool, args):
    turn(h, "api_server")
    h.reply.update(risk=55)
    out, rec = call(h, tool, args)
    assert out["action"] == "block" and rec["decision"] == "blocked"
    assert "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "hook" and "self_edit" not in h.scans[-1]


@pytest.mark.parametrize("broken", ["missing", "raises", "no_unattended"])
def test_without_the_write_origin_nothing_is_declared_and_no_error(h, monkeypatch, broken):
    if broken == "missing":
        monkeypatch.setitem(sys.modules, "tools.skill_provenance", None)
    elif broken == "raises":
        sys.modules["tools.skill_provenance"].get_current_write_origin = lambda: 1 / 0
    else:
        del sys.modules["tools.skill_provenance"].is_unattended_review
    turn(h, "api_server")
    h.reply.update(risk=55)
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"
    assert "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "hook" and "self_edit" not in h.scans[-1]


# ---- the setting ----------------------------------------------------------------------------------------


def test_skill_review_review_sends_a_loop_save_like_any_other_call(h):
    h.ctx.settings["skill_review"] = "review"
    turn(h, "api_server", "tidy my notes")
    h.reply.update(risk=55)
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"
    assert rec["skill_review"] is True  # still counted
    sent = h.scans[-1]
    assert sent["trigger"]["kind"] == "hook" and "self_edit" not in sent
    turn(h, "telegram")
    out, rec = call(h, *LOOP_CALLS[4][:2])
    assert out["action"] == "approve"
    assert h.scans[-1]["trigger"]["kind"] == "message" and "self_edit" not in h.scans[-1]
    # No conversation is kept either.
    assert not (h.dir / "sentrook" / "conversations").exists()


@pytest.mark.parametrize(
    ("settings", "env", "want"),
    [
        ({}, {}, "allow"),
        ({"skill_review": "review"}, {}, "review"),
        ({"skill_review": "ALLOW"}, {}, "allow"),
        ({}, {"SENTROOK_SKILL_REVIEW": "review"}, "review"),
        ({"skill_review": "allow"}, {"SENTROOK_SKILL_REVIEW": "review"}, "allow"),
        ({"skill_review": "alow"}, {}, "allow"),
        ({"skill_review": "reveiw"}, {}, "allow"),
        ({"skill_review": "off"}, {}, "allow"),
        # YAML reads `off`, `no` and `false` as False, and `on`, `yes`, `true` as True.
        ({"skill_review": False}, {}, "review"),
        ({"skill_review": True}, {}, "allow"),
        ({"skill_review": False}, {"SENTROOK_SKILL_REVIEW": "allow"}, "review"),
        ({"skill_review": True}, {"SENTROOK_SKILL_REVIEW": "review"}, "allow"),
        ({"skill_review": 0}, {}, "allow"),
        ({"skill_review": 0}, {"SENTROOK_SKILL_REVIEW": "review"}, "allow"),
        ({"skill_review": ["review"]}, {}, "allow"),
    ],
)
def test_the_setting_resolves_and_a_typo_never_stops_the_loop(settings, env, want):
    assert config.resolve_config(settings, env).skill_review == want


@pytest.mark.parametrize(
    ("value", "named"),
    [(False, None), (True, None), ("off", "off"), (0, "0"), (["review"], "['review']")],
)
def test_a_value_that_is_not_allow_or_review_is_named(h, caplog, value, named):
    h.ctx.settings["skill_review"] = value
    cfg = config.resolve_config(dict(h.ctx.settings), {})
    assert cfg.skill_review_unknown == named
    line = status(h)
    with caplog.at_level("WARNING", logger=plugin.logger.name):
        plugin.register(h.ctx)
    warnings = [r.getMessage() for r in caplog.records if "skill_review" in r.getMessage()]
    if named is None:
        assert "unknown value" not in line and warnings == []
        assert line.startswith("skill review: " + ("review" if value is False else "allow") + ";")
    else:
        assert line.startswith(f'skill review: allow (unknown value "{named}" read as allow); ')
        assert len(warnings) == 1 and repr(named) in warnings[0]


def test_the_setting_is_read_from_hermes(h):
    assert "skill_review" in plugin.SETTINGS_KEYS


# ---- visibility -----------------------------------------------------------------------------------------


def status(h):
    out = commands.run_status("", dict(h.ctx.settings))
    return next(line for line in out.splitlines() if line.startswith("skill review:"))


def test_status_counts_allowed_blocked_and_asked_loop_saves(h):
    assert status(h) == "skill review: allow; loop saves in the traffic log: 0 allowed, 0 blocked"
    turn(h, "api_server")
    call(h, *LOOP_CALLS[0][:2])
    call(h, *LOOP_CALLS[4][:2])
    h.reply.update(risk=55)
    call(h, *LOOP_CALLS[3][:2])
    h.prov["origin"] = "assistant_tool"
    call(h, *LOOP_CALLS[3][:2])  # an owner turn: not a loop save, not counted
    assert status(h) == "skill review: allow; loop saves in the traffic log: 2 allowed, 1 blocked"

    h.prov["origin"] = "background_review"
    turn(h, "telegram")
    call(h, *LOOP_CALLS[3][:2])
    assert status(h).endswith("2 allowed, 1 blocked, 1 asked")


def test_an_unknown_value_reads_as_allow_and_is_named(h):
    h.ctx.settings["skill_review"] = "reveiw"
    cfg = config.resolve_config(dict(h.ctx.settings), {})
    assert (cfg.skill_review, cfg.skill_review_unknown) == ("allow", "reveiw")
    assert status(h).startswith('skill review: allow (unknown value "reveiw" read as allow); ')
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out is None and rec["decision"] == "allowed"
    assert h.scans[-1]["trigger"] == SYSTEM_TRIGGER and "self_edit" in h.scans[-1]


def test_status_with_the_traffic_log_off(h):
    h.ctx.settings["traffic_log"] = {"enabled": False}
    h.ctx.settings["skill_review"] = "review"
    assert status(h) == "skill review: review (loop saves not counted: the traffic log is off)"
