"""Hermes's self-improvement loop: its skill and memory saves go through when the save is all the scanner found.

A loop save is `skill_manage` or `memory` called while Hermes's write origin is `background_review` and the
review is unattended (the automatic review and the curator, not an owner's `/refine`). Its review becomes an
allow when there is no enforced floor and every reason is selfmod.plugin or selfmod.memory, attended or not.
Everything else keeps today's decision.
"""

import io
import sys
import types

import pytest

import plugin
from plugin import auth, commands, config, history, scan_client, skill_review

SID = {"session_id": "S1", "task_id": "S1"}
# What the scanner gives a bare loop save (trigger system): the change and the loop's own context.
SELFMOD_SKILL = [{"code": "selfmod.plugin"}, {"code": "trigger.system"}]
SELFMOD_MEMORY = [
    {"code": "origin.agent_generated"},
    {"code": "selfmod.memory"},
    {"code": "trigger.system"},
]

LOOP_CALLS = [
    (
        "skill_manage",
        {"action": "create", "name": "tidy", "content": "# Tidy\nSteps."},
        SELFMOD_SKILL,
    ),
    (
        "skill_manage",
        {"action": "patch", "name": "tidy", "old": "Steps.", "new": "Two steps."},
        SELFMOD_SKILL,
    ),
    ("skill_manage", {"action": "edit", "name": "tidy", "content": "# Tidy\nNew."}, SELFMOD_SKILL),
    ("skill_manage", {"action": "delete", "name": "tidy"}, SELFMOD_SKILL),
    (
        "memory",
        {"action": "add", "target": "memory", "content": "Prefers short replies."},
        SELFMOD_MEMORY,
    ),
]
LOOP_IDS = ["create", "patch", "edit", "delete", "memory-add"]


class Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def h(harness, monkeypatch):
    """The harness with a scanner whose reply each test sets, and Hermes's write origin under test control."""
    fake = harness
    reply = {"risk": 55, "enforced": None, "reasons": SELFMOD_SKILL}

    def http(url, *, data=None, headers=None, timeout):
        if url != "http://scan.test/scan":
            return fake(url, data=data, headers=headers, timeout=timeout)
        import json

        p = json.loads(data)
        fake.scans.append(p)
        return (
            200,
            {
                "response_version": "2.0",
                "request_id": p["request_id"],
                "status": "ok",
                "entities": {},
                "tool_description": {"template": "Saves a skill"},
                "action_fingerprint": f"afp1:x|step:{p['session']['step']}",
                "state": "tok",
                **reply,
            },
            {},
        )

    monkeypatch.setattr(auth, "http_json", http)
    monkeypatch.setattr(scan_client, "http_json", http)

    prov = {"origin": "background_review", "attended": False}
    mod = types.ModuleType("tools.skill_provenance")
    mod.get_current_write_origin = lambda: prov["origin"]
    mod.is_unattended_review = lambda: (
        prov["origin"] == "background_review" and not prov["attended"]
    )
    pkg = types.ModuleType("tools")
    pkg.__path__ = []
    pkg.skill_provenance = mod
    monkeypatch.setitem(sys.modules, "tools", pkg)
    monkeypatch.setitem(sys.modules, "tools.skill_provenance", mod)
    # Not a terminal: platforms outside the chat list are unattended unless a test says otherwise.
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    for k in ("HERMES_SESSION_PLATFORM", "HERMES_PLATFORM", "SENTROOK_SKILL_REVIEW"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(plugin, "session_facts", lambda: {})

    fake.reply = reply
    fake.prov = prov
    return fake


def turn(h, platform):
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="", platform=platform, sender_id="u1", **SID
    )


def call(h, tool, args):
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool, args=args, tool_call_id=f"c{len(h.scans)}", turn_id="t1", **SID
    )
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def history_action(h):
    scans = history.recent_scans(h.dir / "sentrook" / "traffic.jsonl", 1)
    return history.action_of(*scans[0])


# ---- must allow ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "args", "reasons"), LOOP_CALLS, ids=LOOP_IDS)
@pytest.mark.parametrize("platform", ["telegram", "api_server", "webhook", "cli", "curator", None])
def test_a_loop_save_whose_only_reason_is_the_save_is_allowed(
    h, monkeypatch, tool, args, reasons, platform
):
    """Attended chat, API server, webhook, the local terminal, the curator (its own platform), and a
    run with no turn recorded."""
    if platform == "cli":
        monkeypatch.setattr(sys, "stdin", Tty())
    if platform is not None:
        turn(h, platform)
    h.reply["reasons"] = reasons
    out, rec = call(h, tool, args)
    assert out is None
    assert (rec["verdict"], rec["decision"], rec["skill_review"]) == ("review", "allowed", True)
    assert history_action(h) == "allowed (skill review)"
    assert h.scans[-1]["trigger"] == {
        "kind": "system",
        "channel": None,
        "sender": {"relation": "unknown", "basis": ["none"]},
    }


def test_both_save_reasons_together_are_still_only_the_save(h):
    turn(h, "api_server")
    h.reply["reasons"] = [*SELFMOD_SKILL, *SELFMOD_MEMORY, {"code": "selfmod.plugin", "detail": {}}]
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out is None and rec["decision"] == "allowed"


# ---- must stay as it is -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        "exposure.instructions",
        "exposure.session_tainted",
        "exfil.exec_egress",
        "origin.only_in_untrusted",
        "origin.agent_created_dirty_lineage",
        "trigger.sender_other",
        "trigger.unknown_sender",
        "call.not_supported_by_request",
        "jev.self_modification",
        "coverage.unknown_sender",
        "selfmod.config",
        "selfmod.workspace_skill",
    ],
)
def test_any_other_reason_keeps_the_review(h, extra):
    turn(h, "telegram")
    h.reply["reasons"] = [*SELFMOD_SKILL, {"code": extra}]
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "approve"
    assert rec["decision"] == "review_timed_out" and rec["skill_review"] is True
    assert history_action(h) == "review"

    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[3][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"
    assert history_action(h) == "blocked (no reviewer)"


@pytest.mark.parametrize(
    "reasons",
    [
        [],
        None,
        [{"code": None}],
        ["selfmod.plugin"],
        [{"code": "trigger.system"}],
        [{"code": "trigger.system"}, {"code": "origin.agent_generated"}],
    ],
)
def test_a_review_without_a_readable_save_reason_is_not_relieved(h, reasons):
    turn(h, "api_server")
    h.reply["reasons"] = reasons
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"


def test_a_block_is_still_a_block(h):
    turn(h, "telegram")
    h.reply.update(risk=92)
    out, rec = call(h, *LOOP_CALLS[3][:2])
    assert out["action"] == "block" and rec["verdict"] == "block"


@pytest.mark.parametrize("floor", ["review", "block"])
def test_an_enforced_floor_is_untouched(h, floor):
    turn(h, "telegram")
    h.reply.update(risk=20, enforced=floor)
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == ("approve" if floor == "review" else "block")
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[4][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"


def test_an_owner_turn_save_is_reviewed_as_before(h):
    """Origin assistant_tool: the owner asked for it in a turn. Normal trigger, normal review."""
    h.prov["origin"] = "assistant_tool"
    turn(h, "telegram")
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "approve"
    assert "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "message"
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[4][:2])
    assert out["action"] == "block"


def test_an_attended_refine_keeps_the_prompt(h):
    h.prov["attended"] = True
    turn(h, "telegram")
    out, rec = call(h, *LOOP_CALLS[1][:2])
    assert out["action"] == "approve" and "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "message"


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("terminal", {"command": "ls"}),
        ("write_file", {"path": "skills/tidy/SKILL.md", "content": "x"}),
        ("patch", {"path": "skills/tidy/SKILL.md", "old": "a", "new": "b"}),
        ("read_file", {"path": "skills/tidy/SKILL.md"}),
    ],
)
def test_other_tools_in_a_loop_run_are_scored_normally(h, tool, args):
    turn(h, "api_server")
    out, rec = call(h, tool, args)
    assert out["action"] == "block" and rec["decision"] == "blocked"
    assert "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "hook"


@pytest.mark.parametrize("broken", ["missing", "raises", "no_unattended"])
def test_without_the_write_origin_there_is_no_relief_and_no_error(h, monkeypatch, broken):
    if broken == "missing":
        monkeypatch.setitem(sys.modules, "tools.skill_provenance", None)
    elif broken == "raises":
        sys.modules["tools.skill_provenance"].get_current_write_origin = lambda: 1 / 0
    else:
        del sys.modules["tools.skill_provenance"].is_unattended_review
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"
    assert "skill_review" not in rec
    assert h.scans[-1]["trigger"]["kind"] == "hook"


def test_observe_mode_is_unchanged(h):
    h.ctx.settings["mode"] = "observe"
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out is None and history_action(h) == "observed (would review)"


# ---- the setting ----------------------------------------------------------------------------------------


def test_skill_review_review_restores_the_normal_decision(h):
    h.ctx.settings["skill_review"] = "review"
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out["action"] == "block" and rec["decision"] == "blocked"
    assert rec["skill_review"] is True  # still counted
    turn(h, "telegram")
    out, rec = call(h, *LOOP_CALLS[4][:2])
    assert out["action"] == "approve"


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
    ],
)
def test_the_setting_resolves_and_a_typo_never_stops_the_loop(settings, env, want):
    assert config.resolve_config(settings, env).skill_review == want


def test_the_setting_is_read_from_hermes(h):
    assert "skill_review" in plugin.SETTINGS_KEYS


# ---- visibility -----------------------------------------------------------------------------------------


def status(h):
    out = commands.run_status("", dict(h.ctx.settings))
    return next(line for line in out.splitlines() if line.startswith("skill review:"))


def test_status_counts_allowed_and_blocked_loop_saves(h):
    assert status(h) == "skill review: allow; loop saves in the traffic log: 0 allowed, 0 blocked"
    turn(h, "api_server")
    call(h, *LOOP_CALLS[0][:2])
    call(h, *LOOP_CALLS[4][:2])
    h.reply["reasons"] = [*SELFMOD_SKILL, {"code": "exposure.injection"}]
    call(h, *LOOP_CALLS[3][:2])
    h.prov["origin"] = "assistant_tool"
    call(h, *LOOP_CALLS[3][:2])  # an owner turn: not a loop save, not counted
    assert status(h) == "skill review: allow; loop saves in the traffic log: 2 allowed, 1 blocked"

    h.prov["origin"] = "background_review"
    turn(h, "telegram")
    call(h, *LOOP_CALLS[3][:2])
    assert status(h).endswith("2 allowed, 1 blocked, 1 asked")


def test_an_unknown_value_is_allowed_and_named(h):
    h.ctx.settings["skill_review"] = "reveiw"
    cfg = config.resolve_config(dict(h.ctx.settings), {})
    assert (cfg.skill_review, cfg.skill_review_unknown) == ("allow", "reveiw")
    assert status(h).startswith('skill review: allow (unknown value "reveiw" read as allow); ')
    turn(h, "api_server")
    out, rec = call(h, *LOOP_CALLS[0][:2])
    assert out is None and rec["decision"] == "allowed"


def test_status_with_the_traffic_log_off(h):
    h.ctx.settings["traffic_log"] = {"enabled": False}
    h.ctx.settings["skill_review"] = "review"
    assert status(h) == "skill review: review (loop saves not counted: the traffic log is off)"


def test_history_labels_only_a_relieved_review():
    base = {"response": {"risk": 55}, "mode": "enforce"}
    assert (
        history.action_of(
            {**base, "verdict": "review", "decision": "allowed", "skill_review": True}, None
        )
        == "allowed (skill review)"
    )
    assert (
        history.action_of(
            {**base, "verdict": "allow", "decision": "allowed", "skill_review": True}, None
        )
        == "allowed"
    )
    assert (
        history.action_of(
            {**base, "verdict": "review", "decision": "blocked", "skill_review": True}, None
        )
        == "blocked (no reviewer)"
    )
    assert skill_review.relieves({"reasons": SELFMOD_MEMORY, "enforced": "allow"})
