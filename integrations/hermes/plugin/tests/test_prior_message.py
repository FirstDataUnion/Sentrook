"""The agent's last message beside a short owner reply (`request.prior_agent_message`).

An owner who answers the agent's proposal with "yes", "go with A" or "try again" says nothing the scanner could compare
the call with. On a turn that begins with the owner's own message of at most 300 characters, every call carries the
agent's last message before it: the last text the agent wrote on the session's previous turn. It is redacted with the
plugin's redactor and cut to 2,000 characters, one third head and two thirds tail (a proposal usually ends the
message). It is the agent's text: it never goes in `request.text`, and it is not sent on a longer message, the first
turn, another sender's message, a turn Hermes starts itself or the background review's calls.
"""

import json

import pytest

from plugin.planir import PRIOR_MESSAGE_CAP_CHARS, PRIOR_MESSAGE_REQUEST_MAX_CHARS

SID = {"session_id": "S1", "task_id": "S1"}
SECRET = "ghp_" + "d" * 36
PROPOSAL = (
    "I drafted two tickets for the Sprint board. Reply **yes** and I'll file both, or send edits."
)
NOTICE = (
    "[ASYNC DELEGATION COMPLETE — deleg_7f3a]\n"
    "A background subagent you dispatched earlier has finished.\n"
    "Goal: check the mirror\nStatus: completed   Duration: 41s\n--- RESULT ---\nDone.\n"
)


@pytest.fixture
def h(loop_h, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u-owner")
    loop_h.prov["origin"] = "assistant_tool"
    loop_h.facts = {"platform": "telegram", "chat_type": "dm", "user_id": "u-owner"}
    return loop_h


def turn(h, turn_id, text, sender="u-owner"):
    h.ctx.hooks["pre_llm_call"](
        user_message=text, platform="telegram", sender_id=sender, turn_id=turn_id, **SID
    )


def reply(h, turn_id, text):
    h.ctx.hooks["post_api_request"](
        turn_id=turn_id, response={"assistant_message": {"content": text, "tool_calls": []}}, **SID
    )


def call(h, turn_id, cid, tool="terminal", args=None):
    h.ctx.hooks["pre_tool_call"](
        tool_name=tool, args=args or {"command": "ls"}, tool_call_id=cid, turn_id=turn_id, **SID
    )
    return h.scans[-1]


def proposed(h, text=PROPOSAL):
    turn(h, "t1", "look through yesterday's log and draft tickets for anything odd")
    call(h, "t1", "c1")
    reply(
        h, "t1", "Reading the log now."
    )  # an earlier model call of the turn, before its tools ran
    reply(h, "t1", text)  # the turn's final message, which the owner reads


def test_a_short_owner_reply_carries_the_agents_last_message(h):
    proposed(h)
    turn(h, "t2", "yes")
    first = call(h, "t2", "c2")
    later = call(h, "t2", "c3")
    for s in (first, later):
        assert s["request"] == {
            "text": "yes",
            "carried_from_turn": None,
            "prior_agent_message": PROPOSAL,
        }


def test_a_reply_at_the_limit_carries_it_and_a_longer_message_does_not(h):
    proposed(h)
    turn(h, "t2", "y" * PRIOR_MESSAGE_REQUEST_MAX_CHARS)
    assert call(h, "t2", "c2")["request"]["prior_agent_message"] == PROPOSAL
    reply(h, "t2", PROPOSAL)
    turn(h, "t3", "z" * (PRIOR_MESSAGE_REQUEST_MAX_CHARS + 1))
    assert "prior_agent_message" not in call(h, "t3", "c3")["request"]


def test_the_first_turn_has_none(h):
    turn(h, "t1", "yes")
    assert "prior_agent_message" not in call(h, "t1", "c1")["request"]


def test_a_final_response_without_text_leaves_the_agents_last_words(h):
    proposed(h, text="")
    turn(h, "t2", "yes")
    assert call(h, "t2", "c2")["request"]["prior_agent_message"] == "Reading the log now."


def test_a_previous_turn_with_no_text_at_all_has_none(h):
    turn(h, "t1", "list the folder")
    call(h, "t1", "c1")
    turn(h, "t2", "yes")
    assert "prior_agent_message" not in call(h, "t2", "c2")["request"]


def test_another_senders_message_has_none(h):
    h.facts = {"platform": "telegram", "chat_type": "group", "user_id": "u-other"}
    proposed(h)
    turn(h, "t2", "yes", sender="u-other")
    sent = call(h, "t2", "c2")
    assert sent["trigger"]["sender"]["relation"] != "owner"
    assert "prior_agent_message" not in sent["request"]


def test_a_turn_hermes_starts_itself_has_none(h):
    proposed(h)
    turn(h, "t2", NOTICE)
    sent = call(h, "t2", "c2")
    assert sent["request"]["carried_from_turn"] == 1
    assert "prior_agent_message" not in sent["request"]


def test_the_background_reviews_calls_have_none(h):
    proposed(h)
    turn(h, "t2", "yes")
    call(h, "t2", "c2")
    h.prov["origin"] = "background_review"
    sent = call(h, "rv", "c3", "memory", {"action": "add", "content": "owner files tickets"})
    assert "prior_agent_message" not in sent["request"]


def test_the_message_is_redacted_and_cut_keeping_its_end(h):
    long = f"token {SECRET} " + "x" * 5000 + " Reply yes to go ahead."
    proposed(h, text=long)
    turn(h, "t2", "go ahead")
    sent = call(h, "t2", "c2")["request"]["prior_agent_message"]
    assert SECRET not in sent and "⟦secret" in sent
    assert sent.endswith("Reply yes to go ahead.")
    assert "characters cut]" in sent
    assert len(sent) <= PRIOR_MESSAGE_CAP_CHARS + 40
    assert "prior_agent_message" not in json.dumps(call(h, "t2", "c3")["request"]["text"])
