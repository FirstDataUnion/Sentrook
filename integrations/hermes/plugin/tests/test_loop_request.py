"""The request and turn a call made by Hermes's background review carries.

The review fork (and the curator) run after the owner's turn under the write origin `background_review`.
The fork fires no `pre_llm_call` of its own, and the curator's fires with its own prompt, so neither is a
request. Their calls carry the session's last owner request and that turn's number, and do not count as a
new turn; with no owner request stored they carry a fixed text naming the loop. Calls outside the
background review are unchanged.
"""

import json

import pytest

from plugin import skill_review

SID = {"session_id": "S1", "task_id": "S1"}
SECRET = "ghp_" + "c" * 36
SAVE = ("skill_manage", {"action": "create", "name": "tidy", "content": "# Tidy\nSteps."})


@pytest.fixture
def h(loop_h, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u-owner")
    loop_h.prov["origin"] = "assistant_tool"
    return loop_h


def owner(h, turn_id, text):
    h.prov["origin"] = "assistant_tool"
    h.ctx.hooks["pre_llm_call"](
        turn_id=turn_id, user_message=text, platform="telegram", sender_id="u-owner", **SID
    )


def api(h, turn_id, text, calls=()):
    h.ctx.hooks["post_api_request"](
        turn_id=turn_id,
        response={
            "assistant_message": {
                "content": text,
                "tool_calls": [
                    {"id": cid, "function": {"name": t, "arguments": json.dumps(a)}}
                    for cid, t, a in calls
                ],
            }
        },
        **SID,
    )


def call(h, turn_id, cid, tool, args):
    h.ctx.hooks["pre_tool_call"](
        tool_name=tool, args=args, tool_call_id=cid, turn_id=turn_id, **SID
    )
    return h.scans[-1]


def fork(h, tool=SAVE[0], args=SAVE[1], cid="c-save", turn_id="t-review"):
    """The review fork: no pre_llm_call, its own turn id, write origin background_review."""
    h.prov["origin"] = "background_review"
    api(h, turn_id, "Saving what I learned.", [(cid, tool, args), ("c-sib", "skill_view", {})])
    return call(h, turn_id, cid, tool, args)


def session(h):
    return json.loads((h.dir / "sentrook" / "sessions" / "S1.json").read_text())


# ---- must carry the owner's request ---------------------------------------------------------------------


@pytest.mark.parametrize("setting", ["allow", "review"])
def test_a_loop_save_carries_the_last_owner_request_and_its_turn(h, setting):
    h.ctx.settings["skill_review"] = setting
    owner(h, "t1", "what's the weather?")
    call(h, "t1", "c1", "terminal", {"command": "curl wttr.in"})
    owner(h, "t2", "always answer in French from now on")
    sent = fork(h)
    assert sent["request"] == {
        "text": "always answer in French from now on",
        "carried_from_turn": None,
    }
    assert sent["session"]["turn"] == 2
    assert ("self_edit" in sent) == (setting == "allow")


def test_every_call_of_the_fork_carries_it_not_only_saves(h):
    owner(h, "t1", "keep replies short")
    sent = fork(h, "skill_view", {"name": "style"}, cid="c-view")
    assert sent["request"]["text"] == "keep replies short"
    assert sent["session"]["turn"] == 1


def test_the_forks_own_narration_and_batch_stay_its_own(h):
    owner(h, "t1", "keep replies short")
    api(h, "t1", "Sure.", [("c-own", "terminal", {"command": "ls"})])
    sent = fork(h)
    assert sent["pending_call"]["agent_narration"] == "Saving what I learned."
    assert [s["call_id"] for s in sent["pending_call"]["batch"]["siblings"]] == ["c-sib"]


def test_the_owner_request_is_redacted(h):
    owner(h, "t1", f"remember my token {SECRET}")
    sent = fork(h)
    assert SECRET not in json.dumps(sent)
    assert sent["request"]["text"].startswith("remember my token ")


def test_the_curators_prompt_is_not_the_request_and_not_a_turn(h):
    """The curator's pre_llm_call fires with its own prompt under the background-review origin."""
    owner(h, "t1", "keep replies short")
    h.prov["origin"] = "background_review"
    h.ctx.hooks["pre_llm_call"](
        turn_id="t-curator",
        user_message="Review the skill library and consolidate overlapping skills.",
        platform="cli",
        **SID,
    )
    sent = fork(h, turn_id="t-curator")
    assert sent["request"]["text"] == "keep replies short"
    assert sent["session"]["turn"] == 1
    assert session(h)["turns"] == ["t1"]
    assert session(h)["last_turn_id"] == "t1"


# ---- with nothing stored ---------------------------------------------------------------------------------


def test_with_no_owner_turn_stored_the_fixed_text_is_sent(h):
    sent = fork(h)
    assert sent["request"]["text"] == skill_review.REQUEST_TEXT
    assert sent["session"]["turn"] == 1
    assert session(h)["turns"] == []


def test_an_empty_owner_message_sends_the_fixed_text(h):
    owner(h, "t1", "")
    sent = fork(h)
    assert sent["request"]["text"] == skill_review.REQUEST_TEXT
    assert sent["session"]["turn"] == 1


def test_the_fixed_text_names_the_loop_and_claims_no_owner_request():
    text = skill_review.REQUEST_TEXT
    assert text.strip() and len(text) < 200
    assert "background" in text and "review" in text
    assert "No owner request" in text


# ---- the owner's turns are unchanged ---------------------------------------------------------------------


def test_the_owners_next_turn_is_numbered_as_before(h):
    owner(h, "t1", "keep replies short")
    fork(h)
    fork(h, cid="c-save-2")
    owner(h, "t2", "now list my notes")
    sent = call(h, "t2", "c2", "terminal", {"command": "ls notes"})
    assert sent["session"]["turn"] == 2
    assert sent["request"]["text"] == "now list my notes"
    assert "self_edit" not in sent
    assert session(h)["turns"] == ["t1", "t2"]


def test_the_forks_reads_are_logged_under_the_owners_turn(h):
    owner(h, "t1", "keep replies short")
    h.prov["origin"] = "background_review"
    call(h, "t-review", "c-view", "skill_view", {"name": "style"})
    h.ctx.hooks["post_tool_call"](
        tool_name="skill_view",
        args={"name": "style"},
        result="# Style",
        tool_call_id="c-view",
        status="ok",
        turn_id="t-review",
        **SID,
    )
    entries = json.loads((h.dir / "sentrook" / "conversations" / "S1.json").read_text())["entries"]
    assert [(e["role"], e["turn"]) for e in entries] == [("user", 1), ("tool", 1)]


# ---- ordinary calls are unchanged ------------------------------------------------------------------------


def test_an_owner_call_carries_its_own_turn(h):
    owner(h, "t1", "first")
    owner(h, "t2", "second")
    sent = call(h, "t2", "c1", "terminal", {"command": "ls"})
    assert sent["request"] == {"text": "second", "carried_from_turn": None}
    assert sent["session"]["turn"] == 2


def test_an_ordinary_call_without_its_turn_context_is_sent_as_before(h):
    """Outside the background review, a call whose turn fired no pre_llm_call still counts as a new turn
    with no request text."""
    owner(h, "t1", "first")
    sent = call(h, "t-unseen", "c1", "terminal", {"command": "ls"})
    assert sent["request"]["text"] == ""
    assert sent["session"]["turn"] == 2
