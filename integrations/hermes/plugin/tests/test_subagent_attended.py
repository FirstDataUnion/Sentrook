"""A sub-agent of the owner's attended chat asks its reviews in that chat.

Hermes runs a delegated child on a worker thread that keeps its parent's session context, so on the gateway (the chat
platforms, the TUI and the desktop app) the child's approval prompt joins the parent chat's approval queue. A review in
such a child is a prompt the owner answers there, as it would be in the chat itself. Where Hermes cannot show a child's
prompt (the classic terminal answers it on the worker thread with nobody asked), or the prompt times out, the call is
held for the owner, bound to the parent session. A sub-agent of a cron job, a webhook run, another unattended
sub-agent or a chat that is not the owner's stays unattended: its reviews are held.
"""

import pytest

import plugin
from plugin import hold, passes

from .test_hold import held_call_harness, holds, resolutions
from .test_hold import slash as _slash
from .test_holds_v2 import HELD, NAMED, notices

OWNER = "u-owner"
#: The owner's direct message on Telegram.
OWNER_DM = {
    "platform": "telegram",
    "chat_type": "dm",
    "user_id": OWNER,
    "key": f"agent:main:telegram:dm:{OWNER}",
}
#: A scan with nothing to review (the parent's `delegate_task`).
QUIET = {"risk": 5, "enforced": None, "owner_pass": None, "reasons": []}


@pytest.fixture
def h(harness, monkeypatch):
    fake = held_call_harness(harness, monkeypatch)
    fake.reply = dict(NAMED)
    fake.facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(fake.facts))
    # Hermes's config as the plugin reads it: sub-agent prompts not approved by Hermes itself
    monkeypatch.setattr(
        plugin, "hermes_config", lambda: {"delegation": {"subagent_auto_approve": False}}
    )
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", OWNER)
    for k in ("HERMES_CRON_SESSION", "HERMES_YOLO_MODE"):
        monkeypatch.delenv(k, raising=False)
    return fake


def _turn(h, sid, platform, parent=""):
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid}",
        user_message="Research the vendors and post a summary.",
        platform=platform,
        sender_id="",
        parent_session_id=parent,
        session_id=sid,
        task_id=sid,
    )


def delegate(h, sid="P1", platform="telegram", facts=OWNER_DM):
    """The parent session `sid` delegates to a sub-agent: its own `delegate_task` call, scanned quietly."""
    h.facts = dict(facts)
    _turn(h, sid, platform)
    h.reply, kept = dict(QUIET), h.reply
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="delegate_task",
        args={"tasks": [{"goal": "Compare the vendors' docs."}]},
        tool_call_id=f"d-{sid}",
        turn_id=f"t-{sid}",
        session_id=sid,
        task_id=sid,
    )
    h.reply = kept
    assert out is None
    return sid


def child_send(h, parent="P1", n=1, cid="c1"):
    """A review-band send from sub-agent `n` of session `parent`, on the child's worker thread (the parent's chat
    context, as Hermes keeps it); the directive and the scan record."""
    sid = f"sub-{parent}-{n}"
    _turn(h, sid, "subagent", parent=parent)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": f"Vendor summary {n}"},
        tool_call_id=cid,
        turn_id=f"t-{sid}",
        session_id=sid,
        task_id=sid,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def answer(h, out, choice, sid, key=OWNER_DM["key"], surface="gateway"):
    """Hermes's approval hook for the prompt: the child's session id, the parent chat's session key."""
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{out['rule_key']}",
        choice=choice,
        session_id=sid,
        session_key=key,
        surface=surface,
    )
    hold.wait_for_notices()


def history_of(h, sid):
    return plugin._store.load_session(sid)["history"]


def slash(h, raw):
    h.facts = {}
    return _slash(h, raw)


# ---- must ask (a prompt in the parent chat) ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "platform,facts",
    [
        ("telegram", OWNER_DM),
        ("tui", {"platform": "tui"}),
        ("desktop", {"platform": "desktop"}),
    ],
)
def test_a_subagent_of_the_owners_chat_asks_in_that_chat_and_approving_runs_the_call(
    h, platform, facts
):
    delegate(h, platform=platform, facts=facts)
    out, rec = child_send(h)
    assert out["action"] == "approve"
    assert rec["decision"] == "review_timed_out", "provisional until the owner answers"
    assert rec["parent_chat"] is True
    assert rec["planir"]["trigger"]["kind"] == "subagent"
    assert not (h.dir / "sentrook" / "holds.json").exists() or holds(h) == []
    assert notices(h) == [], "no hold notice: the owner is asked in the chat"
    answer(h, out, "once", "sub-P1-1")
    [res] = resolutions(h)
    assert (res["resolution"], res["decision"]) == ("once", "approved_by_user")
    assert history_of(h, "sub-P1-1")[-1]["decision"] == "approved_by_user"


def test_a_strong_signal_with_no_owner_pass_is_still_a_prompt_with_its_reasons(h):
    h.reply = {
        **NAMED,
        "owner_pass": None,
        "reasons": NAMED["reasons"] + [{"code": "origin.untrusted_destination"}],
    }
    delegate(h)
    out, rec = child_send(h)
    assert out["action"] == "approve" and rec["verdict"] == "review"
    assert "hold" not in rec
    assert out["message"], "the full card"


def test_a_subagent_of_an_asking_subagent_asks_in_the_same_chat(h):
    delegate(h)
    h.reply, kept = dict(QUIET), h.reply
    child_send(h)  # the first sub-agent's own call: quiet, and it now delegates in turn
    h.reply = kept
    out, rec = child_send(h, parent="sub-P1-1")
    assert out["action"] == "approve" and rec["parent_chat"] is True


def test_a_denied_prompt_is_the_owners_denial_not_a_hold(h):
    delegate(h)
    out, _rec = child_send(h)
    answer(h, out, "deny", "sub-P1-1")
    assert resolutions(h)[-1]["decision"] == "denied_by_user"
    assert not (h.dir / "sentrook" / "holds.json").exists() or holds(h) == []


# ---- must fire (held, or blocked) ------------------------------------------------------------------------------


@pytest.mark.parametrize("choice", ["timeout", "notify_failed", "cancelled"])
def test_a_prompt_nobody_answers_or_hermes_cannot_show_falls_back_to_a_hold_for_the_parent(
    h, choice
):
    delegate(h)
    out, rec = child_send(h)
    assert out["action"] == "approve"
    answer(h, out, choice, "sub-P1-1")
    [res] = resolutions(h)
    assert res["decision"] == "held" and res["hold"]["id"]
    [entry] = holds(h)
    assert entry["source"] == passes.source_of("subagent", plugin.planir.session_ref("P1"))
    assert entry["where"].startswith("subagent run, parent session ")
    assert len(notices(h)) == 1, "the owner is told, as for any hold"
    assert history_of(h, "sub-P1-1")[-1]["decision"] == "held"
    # the owner's allow lets the next matching call from a sub-agent of the same parent through once
    slash(h, f"allow {res['hold']['id']}")
    out, rec = child_send(h, n=2)
    assert out is None and rec["decision"] == "allowed_by_pass"


def test_a_deny_from_the_subagents_own_thread_is_nobodys_answer_and_falls_back_to_a_hold(h):
    """Where no chat shows the prompt, Hermes's callback for the sub-agent's thread answers it on the terminal
    surface: that deny is not the owner's."""
    delegate(h, platform="tui", facts={"platform": "tui"})
    out, _rec = child_send(h)
    answer(h, out, "deny", "sub-P1-1", surface="cli")
    [res] = resolutions(h)
    assert res["decision"] == "held" and res["hold"]["id"]


def test_a_deny_nobody_gave_is_not_the_owners_even_when_no_hold_can_be_made(h):
    delegate(h, platform="tui", facts={"platform": "tui"})
    out, _rec = child_send(h)
    plugin._child_prompts.clear()  # asked before a restart: the plugin no longer has what a hold needs
    answer(h, out, "deny", "sub-P1-1", surface="cli")
    assert resolutions(h)[-1]["decision"] == "blocked"


@pytest.mark.parametrize("config", [{}, None])
def test_a_subagent_is_held_when_the_plugin_cannot_read_hermess_config(h, monkeypatch, config):
    delegate(h)
    if config is None:
        monkeypatch.setenv("HERMES_IGNORE_USER_CONFIG", "1")
    else:
        monkeypatch.setattr(plugin, "hermes_config", lambda: config)
    out, _rec = child_send(h)
    assert out == HELD


@pytest.mark.parametrize("value", [True, "true", 1])
def test_a_subagent_is_held_when_hermes_approves_subagent_prompts_by_itself(h, monkeypatch, value):
    delegate(h)
    monkeypatch.setattr(
        plugin, "hermes_config", lambda: {"delegation": {"subagent_auto_approve": value}}
    )
    out, rec = child_send(h)
    assert out == HELD and "parent_chat" not in rec


@pytest.mark.parametrize(
    "platform,facts",
    [
        ("cron", {"platform": "cron"}),
        ("webhook", {"platform": "webhook", "user_id": "webhook:github-push"}),
        ("telegram", {**OWNER_DM, "chat_type": "group"}),
        ("telegram", {**OWNER_DM, "user_id": "u-member"}),
        ("cli", {}),
    ],
    ids=["cron-job", "webhook-run", "group-chat", "not-the-owner", "classic-terminal"],
)
def test_a_subagent_of_a_parent_where_nobody_can_answer_its_prompt_is_held(h, platform, facts):
    delegate(h, platform=platform, facts=facts)
    out, rec = child_send(h)
    assert out == HELD and rec["decision"] == "held"
    assert "parent_chat" not in rec
    [entry] = holds(h)
    assert entry["source"] == passes.source_of("subagent", plugin.planir.session_ref("P1"))


def test_a_subagent_whose_parent_the_plugin_never_saw_is_held(h):
    out, rec = child_send(h, parent="P-unknown")
    assert out == HELD and rec["decision"] == "held"


def test_a_subagent_of_a_held_subagent_is_held(h):
    delegate(h, platform="cron", facts={"platform": "cron"})
    h.reply, kept = dict(QUIET), h.reply
    child_send(h)
    h.reply = kept
    out, _rec = child_send(h, parent="sub-P1-1")
    assert out == HELD


def test_approvals_bypassed_in_the_parent_chat_hold_the_subagent_too(h, monkeypatch):
    delegate(h)
    monkeypatch.setenv("HERMES_YOLO_MODE", "1")
    out, _rec = child_send(h)
    assert out == HELD


@pytest.mark.parametrize(
    "reply",
    [{"risk": 95, "enforced": None}, {"risk": 40, "enforced": "block"}],
    ids=["over-the-block-line", "enforced-block"],
)
def test_a_block_in_a_subagent_of_the_owners_chat_stays_a_block(h, reply):
    delegate(h)
    h.reply = {**NAMED, **reply}
    out, rec = child_send(h)
    assert out["action"] == "block" and rec["decision"] == "blocked"


# ---- unchanged ---------------------------------------------------------------------------------------------------


def test_a_subagent_of_the_background_review_stays_a_background_run(h, monkeypatch):
    delegate(h)
    monkeypatch.setattr(plugin.skill_review, "in_unattended_review", lambda: True)
    out, rec = child_send(h)
    assert out["action"] == "block" and rec.get("background_run") is True
    assert "parent_chat" not in rec
