"""Hermes's background skill and memory saves never ask for approval.

The background review and the curator save skills (`skill_manage`) and memory (`memory`) after the owner's turn has
ended. Nobody is there to answer a prompt from them: on the local terminal Hermes denies it unseen, on a gateway the
prompt goes nowhere because the turn is over, so a review there would lose the save without anyone knowing. So, on
every surface and whatever Hermes's approval settings:

- allow: the save runs;
- block: the save is blocked and the owner gets a notice;
- review the scanner marks lenient (`self_edit.lenient`, on an ok scan of a save sent with its `self_edit` block): the
  save runs and the owner gets a notice that it was let through; any other review is held: not saved, recorded in
  history and status (not in the approvable holds, since approving could not make the save), with a notice;
- scan failure: what any unattended run does (`on_scan_error`), with the scan-failure notice when it blocks.

A snooze lets a would-be-held save through only when the save follows a session the owner attends (a chat or the
terminal). Notices go to the `owner_channel` home channel, at most one of each kind per session every 6 hours. Without a home
channel nothing changes but the notice, and `status` and `verify` say so. History marks these saves "(self-edit)".
An owner's own skill or memory change, an owner's `/refine`, and any other tool the background run calls are not
background saves and are unchanged.
"""

import io
import json
import sys

import pytest

import plugin
from plugin import cli, commands, history, hold
from plugin.scan_error_policy import ScanFailure

SID = {"session_id": "S1", "task_id": "S1"}
SKILL = ("skill_manage", {"action": "create", "name": "tidy", "content": "# Tidy\nSteps."})
MEMORY = ("memory", {"action": "add", "target": "memory", "content": "Prefers short replies."})
#: (what saves, the tool and its arguments, the platform the run reports when it is not the surface's own)
SAVES = {
    "fork-skill": (SKILL, None),
    "fork-memory": (MEMORY, None),
    "curator": (SKILL, "curator"),
}
#: The local terminal, a gateway chat, and a run with no terminal (the API server).
SURFACES = ["cli", "telegram", "api_server"]
LENIENT = {"adds": [], "lenient": True}
NOT_LENIENT = {"adds": ["command"], "lenient": False}


class Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def h(loop_h, monkeypatch):
    """The background-review harness with Telegram as the owner's notice channel and a `dispatch_tool` that records
    each send (`.sent`)."""
    fake = loop_h
    monkeypatch.setattr(hold, "home_platforms", lambda: ["telegram"])
    fake.sent = []

    def dispatch_tool(name, args, **_kw):
        fake.sent.append({"name": name, "args": args})
        return json.dumps({"success": True})

    fake.ctx.dispatch_tool = dispatch_tool
    fake.ctx.settings["owner_channel"] = "telegram"
    return fake


def run(h, monkeypatch, save, surface):
    (tool, args), platform = SAVES[save]
    if surface == "cli":
        monkeypatch.setattr(sys, "stdin", Tty())
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1",
        user_message="keep replies short",
        platform=platform or surface,
        sender_id="u1",
        **SID,
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool, args=args, tool_call_id=f"c{len(h.scans)}", turn_id="t1", **SID
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def shown(h):
    scan, res = history.recent_scans(h.dir / "sentrook" / "traffic.jsonl", 1)[0]
    action = history.action_of(scan, res)
    return action, history.review_of(action, res)


def notices(h):
    return [s["args"]["message"] for s in h.sent]


def set_verdict(h, monkeypatch, verdict):
    if verdict == "allow":
        h.reply.update(risk=5)
    elif verdict == "review-lenient":
        h.reply.update(risk=55, self_edit=LENIENT)
    elif verdict == "review":
        h.reply.update(risk=55, self_edit=NOT_LENIENT)
    elif verdict == "block":
        h.reply.update(risk=92, reasons=[{"code": "selfmod.plugin"}])
    else:
        monkeypatch.setattr(
            "plugin.post_scan",
            lambda **_kw: ScanFailure(ok=False, kind="http", status=500, detail="boom"),
        )


# ---- the outcome matrix ----------------------------------------------------------------------------------------

#: verdict -> (what the host is told, the decision recorded, history's action, a notice sent)
OUTCOMES = {
    "allow": (None, "allowed", "allowed (self-edit)", False),
    "review-lenient": (None, "allowed", "allowed (let through, self-edit)", True),
    "review": ("held", "held", "held (self-edit)", True),
    "block": ("block", "blocked", "blocked (self-edit)", True),
    "scan-error": ("block", "blocked_on_error", "blocked (scan error)", True),
}


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("verdict", list(OUTCOMES))
@pytest.mark.parametrize("save", list(SAVES))
def test_a_background_save_never_asks(h, monkeypatch, save, surface, verdict):
    set_verdict(h, monkeypatch, verdict)
    told, decision, action, notice = OUTCOMES[verdict]
    out, rec = run(h, monkeypatch, save, surface)
    # never Hermes's approval prompt, and nothing kept to wait for an answer
    assert out is None or out["action"] == "block"
    assert (
        not (h.dir / "sentrook" / "reviews.json").exists()
        or "sentrook:" not in (h.dir / "sentrook" / "reviews.json").read_text()
    )
    if told is None:
        assert out is None
    elif told == "held":
        assert out == {"action": "block", "message": hold.HELD_TEXT}
    else:
        assert out["action"] == "block" and "message" in out
    assert rec["decision"] == decision and rec["skill_review"] is True
    assert shown(h)[0] == action
    if notice:
        assert len(h.sent) == 1 and h.sent[0]["args"]["target"] == "telegram"
        assert rec["notice"]["status"] == "queued" and "hold" not in rec
    else:
        assert h.sent == [] and "notice" not in rec


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("verdict", ["review-lenient", "review", "block", "scan-error"])
@pytest.mark.parametrize("save", list(SAVES))
def test_without_a_home_channel_only_the_notice_is_missing(h, monkeypatch, save, surface, verdict):
    del h.ctx.settings["owner_channel"]
    set_verdict(h, monkeypatch, verdict)
    told, decision, action, _ = OUTCOMES[verdict]
    out, rec = run(h, monkeypatch, save, surface)
    assert out is None if told is None else out["action"] == "block"
    assert rec["decision"] == decision and shown(h)[0] == action
    assert h.sent == []
    sent = rec["notice"]
    assert sent["status"] == "unsent" and "owner_channel is not set" in sent["reason"]


@pytest.mark.parametrize("bypass", ["yolo", "approvals-off"])
def test_hermes_approval_settings_do_not_change_it(h, monkeypatch, bypass):
    """With approvals off or YOLO, Hermes would approve a prompt itself; a background save is held all the same."""
    if bypass == "yolo":
        monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    else:
        monkeypatch.setattr(plugin.intent, "hermes_config", lambda: {"approvals": {"mode": "off"}})
    set_verdict(h, monkeypatch, "review")
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out == {"action": "block", "message": hold.HELD_TEXT} and rec["decision"] == "held"


@pytest.mark.parametrize("surface", ["cli", "telegram"])
def test_the_attended_owner_ceiling_does_not_turn_a_background_block_into_a_question(
    h, monkeypatch, surface
):
    """The scanner's attended-owner ceiling lowers a block to a question only for someone who can answer it."""
    h.reply.update(risk=92, ceiling="review")
    out, rec = run(h, monkeypatch, "fork-skill", surface)
    assert out["action"] == "block" and rec["decision"] == "blocked" and len(h.sent) == 1


def test_a_retry_of_an_unanswered_review_capped_at_review_is_held(h, monkeypatch):
    h.reply.update(
        risk=92, ceiling="review", reasons=[{"code": "cap.unanswered_retry"}], self_edit=LENIENT
    )
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out == {"action": "block", "message": hold.HELD_TEXT} and rec["decision"] == "held"


# ---- lenient ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "self_edit",
    [
        None,
        {},
        {"adds": []},
        {"adds": [], "lenient": "true"},
        {"adds": [], "lenient": 1},
        "lenient",
    ],
    ids=["missing", "empty", "no-flag", "string", "number", "not-an-object"],
)
def test_only_a_json_true_lenient_lets_a_review_through(h, monkeypatch, self_edit):
    h.reply.update(risk=55)
    if self_edit is not None:
        h.reply["self_edit"] = self_edit
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out == {"action": "block", "message": hold.HELD_TEXT}
    assert rec["decision"] == "held" and "lenient" not in rec


@pytest.mark.parametrize("status", ["degraded", None, "partial"])
def test_lenient_counts_only_on_an_ok_scan(h, monkeypatch, status):
    h.reply.update(risk=55, status=status, self_edit=LENIENT)
    out, rec = run(h, monkeypatch, "fork-memory", "telegram")
    assert out == {"action": "block", "message": hold.HELD_TEXT}
    assert rec["decision"] == "held" and "lenient" not in rec


def test_lenient_counts_only_when_the_save_was_declared(h, monkeypatch):
    """With `skill_review: review` no `self_edit` block is sent, so a lenient mark answers nothing the plugin asked."""
    h.ctx.settings["skill_review"] = "review"
    h.reply.update(risk=55, self_edit=LENIENT)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out == {"action": "block", "message": hold.HELD_TEXT} and "lenient" not in rec


@pytest.mark.parametrize("floor", ["review", "block"])
def test_lenient_never_overrides_an_enforced_floor(h, monkeypatch, floor):
    h.reply.update(risk=20, enforced=floor, self_edit=LENIENT)
    out, rec = run(h, monkeypatch, "fork-memory", "telegram")
    assert out["action"] == "block"
    assert rec["decision"] == ("held" if floor == "review" else "blocked")


def test_lenient_never_lets_a_block_through(h, monkeypatch):
    h.reply.update(risk=92, self_edit=LENIENT)
    out, rec = run(h, monkeypatch, "fork-skill", "cli")
    assert out["action"] == "block" and rec["decision"] == "blocked"


def test_the_let_through_notice(h, monkeypatch):
    h.reply.update(risk=55, self_edit=LENIENT)
    _, rec = run(h, monkeypatch, "fork-memory", "telegram")
    (text,) = notices(h)
    rid = rec["request_id"][:8]
    assert text.splitlines() == [
        "Sentrook let a background memory save through without asking, though it would normally ask "
        "about a save like this.",
        f"Run: background save, session {rec['session_ref']}",
        "Save: memory: Saves a skill",
        f"Details: /sentrook why {rid}; every background save is in /sentrook history.",
        "More background saves let through in this session are not announced for 6 hours.",
    ]
    assert rec["lenient"] is True and rec["verdict"] == "review"


def test_the_block_notice(h, monkeypatch):
    h.reply.update(risk=92, reasons=[{"code": "selfmod.plugin"}])
    _, rec = run(h, monkeypatch, "curator", "api_server")
    (text,) = notices(h)
    assert text.splitlines()[:4] == [
        "Sentrook blocked a background skill save, so it was not saved.",
        f"Run: background save, session {rec['session_ref']}",
        "Save: skill_manage: Saves a skill",
        "Blocked because it changes the agent's own setup, such as its configuration, memory, plugins, "
        "skills or scheduled jobs.",
    ]
    assert text.splitlines()[-1] == (
        "More blocked background saves in this session are not announced for 6 hours."
    )


def test_the_held_notice_offers_no_approval(h, monkeypatch):
    """Approving could not make the save, so the notice says it was not made and where to see it."""
    h.reply.update(risk=55)
    _, rec = run(h, monkeypatch, "fork-skill", "cli")
    (text,) = notices(h)
    rid = rec["request_id"][:8]
    assert text.splitlines() == [
        "Sentrook held a background skill save for you, so it was not saved. To keep it, ask the agent for it "
        "in a chat.",
        f"Run: background save, session {rec['session_ref']}",
        "Save: skill_manage: Saves a skill",
        "Held because it changes the agent's own setup, such as its configuration, memory, plugins, skills or "
        "scheduled jobs.",
        f"Details: /sentrook why {rid}; every background save is in /sentrook history.",
        "More background saves held in this session are not announced for 6 hours.",
    ]
    assert "approve" not in text


def test_history_says_a_held_background_save_was_not_saved(h, monkeypatch):
    h.reply.update(risk=55)
    run(h, monkeypatch, "fork-skill", "telegram")
    assert shown(h) == ("held (self-edit)", "not saved")


def test_a_curator_pass_sends_one_held_notice(h, monkeypatch):
    h.reply.update(risk=55)
    for _ in range(25):
        _, rec = run(h, monkeypatch, "curator", "api_server")
        assert rec["decision"] == "held"
    assert len(h.sent) == 1 and rec["notice"] == {"status": "quiet"}


def test_held_background_saves_never_evict_approvable_holds(h, monkeypatch):
    h.reply.update(risk=55)
    h.prov["origin"] = "assistant_tool"
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="x", platform="cron", sender_id="u1", **SID
    )
    h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args={"command": "echo hi"}, tool_call_id="c0", turn_id="t1", **SID
    )
    first = [r for r in h.traffic() if r.get("kind") == "scan"][-1]["hold"]["id"]
    h.prov["origin"] = "background_review"
    for _ in range(hold.MAX_HOLDS + 5):
        run(h, monkeypatch, "fork-skill", "telegram")
    ids = [x["id"] for x in json.loads((h.dir / "sentrook" / "holds.json").read_text())["holds"]]
    assert ids == [first]
    status = commands.run_status("", dict(h.ctx.settings))
    assert f"{hold.MAX_HOLDS + 5} held" in status


def test_notice_text_is_built_only_from_display_fields(h, monkeypatch):
    """The entity display strings are redacted by the scanner; chat markup in them is taken out."""
    h.reply.update(
        risk=55,
        self_edit=LENIENT,
        tool_description={"template": "Saves skill {E1}"},
        entities={"E1": {"kind": "skill", "display": "[tidy](https://evil.example) @everyone"}},
    )
    run(h, monkeypatch, "fork-skill", "telegram")
    (text,) = notices(h)
    line = next(x for x in text.splitlines() if x.startswith("Save:"))
    assert line == "Save: skill_manage: Saves skill tidyhttps://evil.example everyone"


def test_one_notice_of_each_kind_per_session_in_the_quiet_period(h, monkeypatch):
    h.reply.update(risk=55, self_edit=LENIENT)
    run(h, monkeypatch, "fork-skill", "telegram")
    _, rec = run(h, monkeypatch, "fork-memory", "telegram")
    assert rec["notice"] == {"status": "quiet"} and len(h.sent) == 1
    h.reply.update(risk=92, self_edit=None)
    _, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert rec["notice"]["status"] == "queued" and len(h.sent) == 2
    _, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert rec["notice"] == {"status": "quiet"} and len(h.sent) == 2


def test_a_snoozed_let_through_does_not_silence_a_lenient_one(h, monkeypatch):
    snooze(h, "1h")
    h.reply.update(risk=55)
    run(h, monkeypatch, "fork-skill", "telegram")
    h.reply.update(self_edit=LENIENT)
    _, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert rec["notice"]["status"] == "queued" and len(h.sent) == 2


def test_an_undelivered_notice_is_announced_next_time(h, monkeypatch):
    h.ctx.dispatch_tool = lambda *_a, **_k: json.dumps({"error": "no home channel"})
    h.reply.update(risk=55, self_edit=LENIENT)
    run(h, monkeypatch, "fork-skill", "telegram")
    sent = []
    h.ctx.dispatch_tool = lambda name, args, **_k: (
        sent.append(args) or json.dumps({"success": True})
    )
    _, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert rec["notice"]["status"] == "queued" and len(sent) == 1


def test_observe_mode_sends_no_notice(h, monkeypatch):
    h.ctx.settings["mode"] = "observe"
    h.reply.update(risk=92)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out is None and h.sent == [] and "notice" not in rec
    assert shown(h)[0] == "observed (would block, self-edit)"


@pytest.mark.parametrize("policy", ["allow", "deny"])
def test_a_scan_error_follows_the_unattended_policy(h, monkeypatch, policy):
    h.ctx.settings["on_scan_error"] = policy
    set_verdict(h, monkeypatch, "scan-error")
    out, rec = run(h, monkeypatch, "fork-skill", "cli")
    if policy == "allow":
        assert out is None and rec["decision"] == "allowed_on_error" and h.sent == []
    else:
        assert out["action"] == "block" and rec["decision"] == "blocked_on_error"
        assert len(h.sent) == 1 and "could not scan" in h.sent[0]["args"]["message"]
        assert "Run: background save, session" in h.sent[0]["args"]["message"]


# ---- snooze ----------------------------------------------------------------------------------------------


def snooze(h, rest):
    return commands.run_snooze(rest, dict(h.ctx.settings), None, {"basis": ["cli"]}, "S1")


@pytest.mark.parametrize("surface", ["telegram", "cli"])
@pytest.mark.parametrize("scope", ["session", "all"])
def test_a_snooze_lets_a_reviewed_background_save_through_with_the_notice(
    h, monkeypatch, scope, surface
):
    """Only after a session the owner attends: a chat or the terminal."""
    snooze(h, "1h" if scope == "session" else "--all 1h")
    h.reply.update(risk=55)
    out, rec = run(h, monkeypatch, "fork-skill", surface)
    assert out is None and rec["decision"] == "allowed" and rec["snoozed"] is True
    assert shown(h)[0] == "allowed (snoozed, self-edit)"
    (text,) = notices(h)
    assert text.splitlines()[0] == (
        "Sentrook let a background skill save through because a snooze is on, though it would normally "
        "ask about a save like this."
    )


def test_a_lenient_save_under_a_snooze_is_let_through_as_lenient(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=55, self_edit=LENIENT)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out is None and rec["lenient"] is True and "snoozed" not in rec
    assert notices(h)[0].startswith("Sentrook let a background skill save through without asking")


UNATTENDED_PARENTS = [
    "cron",
    "webhook",
    "api_server",
    "msgraph_webhook",
    "curator",
    "",
    "something-new",
]


@pytest.mark.parametrize("platform", UNATTENDED_PARENTS)
def test_a_snooze_never_reaches_a_save_after_an_unattended_session(h, monkeypatch, platform):
    """Unattended runs are never snoozed, and a background save after one is no exception: only a chat platform,
    the local terminal or a configured attended platform counts as attended, whatever stdin is (the curator runs
    inside the terminal's process; a gateway may run in a foreground terminal)."""
    reply = snooze(h, "--all 1h")
    assert "unattended runs are not snoozed" in reply
    h.reply.update(risk=55)
    monkeypatch.setattr(sys, "stdin", Tty())
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="curate", platform=platform, sender_id="", **SID
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=SKILL[0], args=SKILL[1], tool_call_id="c1", turn_id="t1", **SID
    )
    rec = [r for r in h.traffic() if r.get("kind") == "scan"][-1]
    assert out == {"action": "block", "message": hold.HELD_TEXT}
    assert rec["decision"] == "held" and "snoozed" not in rec


def test_a_configured_attended_platform_counts(h, monkeypatch):
    h.ctx.settings["attended_platforms"] = ["api_server"]
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    out, rec = run(h, monkeypatch, "fork-skill", "api_server")
    assert out is None and rec["snoozed"] is True


def parent_turn(h, platform, turn_id="t1", sid=SID, **extra):
    """The owner's (or a run's) turn as Hermes starts it: `pre_llm_call` under the assistant's own write origin."""
    h.prov["origin"] = "assistant_tool"
    h.ctx.hooks["pre_llm_call"](
        turn_id=turn_id, user_message="hi", platform=platform, sender_id="u1", **sid, **extra
    )


def fork_save(h, monkeypatch, facts, *, tty=True, sid=SID, turn_id="fork-turn"):
    """The review fork as real Hermes runs it: no `pre_llm_call` of its own (its persistence is off), a turn id of its
    own, the parent's session id, and the session facts Hermes copies to its thread: a gateway binds the chat's
    platform; the terminal binds none (the CLI) or an empty one (the TUI)."""
    h.prov["origin"] = "background_review"
    h.facts = facts
    if tty:
        monkeypatch.setattr(sys, "stdin", Tty())
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=SKILL[0], args=SKILL[1], tool_call_id="f1", turn_id=turn_id, **sid
    )
    rec = [r for r in h.traffic() if r.get("kind") == "scan"][-1]
    assert rec["skill_review"] is True
    return out, rec


TERMINAL_FACTS = [{}, {"platform": "", "source": "cli"}, {"platform": "", "source": "tui"}]


@pytest.mark.parametrize(
    ("parent", "facts", "tty", "want"),
    [
        ("telegram", {"platform": "telegram", "chat_type": "dm"}, False, "allowed"),
        *[("cli", f, True, "allowed") for f in TERMINAL_FACTS],
        ("tui", {"platform": "", "source": "tui"}, True, "allowed"),
        ("tui", {}, True, "allowed"),
        # the TUI and the desktop app show Hermes's own approval card: attended with no terminal too
        ("tui", {"platform": "", "source": "tui"}, False, "allowed"),
        ("tui", {}, False, "allowed"),
        ("desktop", {}, False, "allowed"),
        ("desktop", {"platform": "desktop"}, False, "allowed"),
        # the local terminal still needs a terminal, as for the owner's own calls there
        ("cli", {}, False, "held"),
        *[
            (p, f, tty, "held")
            for p in ("cron", "webhook", "api_server", "curator", "subagent", "")
            for f in ({}, {"platform": p} if p else {"platform": "", "source": "cli"})
            for tty in (True, False)
        ],
    ],
)
def test_a_snooze_through_the_forks_own_turn(h, monkeypatch, parent, facts, tty, want):
    """A fork whose own turn and thread name no platform takes it from the turn it follows in the same session: the
    owner at the terminal gets the snooze; after a cron, webhook, API-server, curator or sub-agent turn it never does,
    terminal or not."""
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    parent_turn(h, parent)
    out, rec = fork_save(h, monkeypatch, facts, tty=tty)
    assert rec["decision"] == want
    if want == "allowed":
        assert out is None and rec["snoozed"] is True
    else:
        assert out == {"action": "block", "message": hold.HELD_TEXT} and "snoozed" not in rec


def test_a_fork_after_a_sub_agent_turn_at_the_terminal_is_not_attended(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    parent_turn(h, "cli", parent_session_id="P0")
    _out, rec = fork_save(h, monkeypatch, {})
    assert rec["decision"] == "held"


def test_a_terminal_turn_of_another_session_never_makes_a_fork_attended(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    parent_turn(h, "cli", sid={"session_id": "S2", "task_id": "S2"})
    _out, rec = fork_save(h, monkeypatch, {})
    assert rec["decision"] == "held"


@pytest.mark.parametrize("later", ["webhook", "api_server", "cron"])
def test_only_the_turn_the_fork_follows_counts(h, monkeypatch, later):
    """An earlier terminal turn of the session does not carry over a later unattended one."""
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    parent_turn(h, "cli")
    parent_turn(h, later, turn_id="t2")
    _out, rec = fork_save(h, monkeypatch, {})
    assert rec["decision"] == "held"


def test_a_later_turn_without_an_id_ends_the_carry(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    parent_turn(h, "cli")
    parent_turn(h, "webhook", turn_id=None)
    _out, rec = fork_save(h, monkeypatch, {})
    assert rec["decision"] == "held"


def test_a_fork_without_a_session_id_is_not_attended(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    parent_turn(h, "cli", sid={})
    _out, rec = fork_save(h, monkeypatch, {}, sid={})
    assert rec["decision"] == "held"


def test_a_fork_in_a_session_with_no_turn_is_not_attended_with_a_terminal(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    _out, rec = fork_save(h, monkeypatch, {})
    assert rec["decision"] == "held"


def test_the_curators_own_turn_is_never_carried_from_the_owners(h, monkeypatch):
    """The curator fires `pre_llm_call` under the background-review origin with platform `curator`: its saves stay
    not attended even in a session whose last owner turn was at the terminal."""
    snooze(h, "--all 1h")
    h.reply.update(risk=55)
    parent_turn(h, "cli")
    h.prov["origin"] = "background_review"
    h.ctx.hooks["pre_llm_call"](
        turn_id="cur-1", user_message="curate", platform="curator", sender_id="", **SID
    )
    _out, rec = fork_save(h, monkeypatch, {}, turn_id="cur-1")
    assert rec["decision"] == "held"


def test_a_snooze_never_lets_a_retry_capped_review_through(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=92, ceiling="review", reasons=[{"code": "cap.unanswered_retry"}])
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert rec["decision"] == "held" and "snoozed" not in rec


def test_an_owner_chat_save_under_a_snooze_is_unchanged(h, monkeypatch):
    """Snoozed in the chat the owner attends, as before: allowed without asking, and no background notice."""
    snooze(h, "1h")
    h.prov["origin"] = "assistant_tool"
    h.reply.update(risk=55)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out is None and rec["snoozed"] is True and "skill_review" not in rec and h.sent == []


def test_a_snooze_of_another_session_does_not(h, monkeypatch):
    commands.run_snooze("1h", dict(h.ctx.settings), None, {"basis": ["cli"]}, "S2")
    h.reply.update(risk=55)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert rec["decision"] == "held"


@pytest.mark.parametrize("resp", [{"risk": 20, "enforced": "review"}, {"risk": 92}])
def test_a_snooze_never_lets_an_enforced_review_or_a_block_through(h, monkeypatch, resp):
    snooze(h, "--all 1h")
    h.reply.update(**resp)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out["action"] == "block" and rec["decision"] in ("held", "blocked")


def test_a_snooze_never_turns_a_background_block_into_a_question(h, monkeypatch):
    snooze(h, "--all 1h")
    h.reply.update(risk=92, relaxable=True)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out["action"] == "block" and rec["decision"] == "blocked" and "relaxed" not in rec


# ---- not background saves: unchanged ---------------------------------------------------------------------


@pytest.mark.parametrize("tool", [SKILL, MEMORY])
def test_an_owner_chat_save_still_asks(h, monkeypatch, tool):
    h.prov["origin"] = "assistant_tool"
    h.reply.update(risk=55, self_edit=LENIENT)
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="remember this", platform="telegram", sender_id="u1", **SID
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool[0], args=tool[1], tool_call_id="c1", turn_id="t1", **SID
    )
    assert out["action"] == "approve"
    rec = [r for r in h.traffic() if r.get("kind") == "scan"][-1]
    assert "skill_review" not in rec and shown(h)[0] == "review"


def test_an_owner_refine_still_asks(h, monkeypatch):
    h.prov["attended"] = True
    h.reply.update(risk=55)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out["action"] == "approve" and "skill_review" not in rec


def test_another_tool_in_the_background_run_is_unchanged(h, monkeypatch):
    h.reply.update(risk=55)
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="x", platform="telegram", sender_id="u1", **SID
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="read_file", args={"path": "notes.md"}, tool_call_id="c1", turn_id="t1", **SID
    )
    assert out["action"] == "approve"


def test_the_review_setting_still_never_asks(h, monkeypatch):
    """`skill_review: review` only stops declaring the save to the scanner; the save still cannot ask."""
    h.ctx.settings["skill_review"] = "review"
    h.reply.update(risk=55)
    out, rec = run(h, monkeypatch, "fork-skill", "telegram")
    assert out == {"action": "block", "message": hold.HELD_TEXT} and rec["decision"] == "held"
    assert "self_edit" not in h.scans[-1]


# ---- status and verify -------------------------------------------------------------------------------------


def status_lines(h):
    return commands.run_status("", dict(h.ctx.settings)).splitlines()


def test_status_and_verify_name_the_notice_channel(h):
    assert "background-save notices: to the telegram home channel" in status_lines(h)
    verify = {n: (ok, d) for n, ok, d in cli.run_verify(dict(h.ctx.settings), timeout=0.01)}
    assert verify["background-save notices"] == (True, "to the telegram home channel")


@pytest.mark.parametrize("channel", [None, "discord"])
def test_without_a_home_channel_status_and_verify_say_so_plainly(h, channel):
    if channel is None:
        del h.ctx.settings["owner_channel"]
        why = "owner_channel is not set"
    else:
        h.ctx.settings["owner_channel"] = channel
        why = "owner_channel discord has no home channel"
    want = (
        f"cannot be delivered ({why}). Set owner_channel to a platform with a home channel: "
        "hermes config set plugins.entries.sentrook.settings.owner_channel <platform>, then /sethome "
        "in that chat. Until then background saves Sentrook lets through, holds or blocks show only in "
        "/sentrook history and the skill review counts."
    )
    assert f"background-save notices: {want}" in status_lines(h)
    verify = {n: (ok, d) for n, ok, d in cli.run_verify(dict(h.ctx.settings), timeout=0.01)}
    assert verify["background-save notices"] == (True, want)


def test_status_counts_saves_let_through(h, monkeypatch):
    h.reply.update(risk=55, self_edit=LENIENT)
    run(h, monkeypatch, "fork-skill", "telegram")
    h.reply.update(risk=55, self_edit=None)
    run(h, monkeypatch, "fork-skill", "telegram")
    line = next(x for x in status_lines(h) if x.startswith("skill review:"))
    assert line == (
        "skill review: allow; loop saves in the traffic log: 0 allowed, 0 blocked, 1 held, 1 let through"
    )
    snooze(h, "--all 1h")
    run(h, monkeypatch, "fork-skill", "telegram")
    line = next(x for x in status_lines(h) if x.startswith("skill review:"))
    assert line.endswith("1 held, 2 let through")
