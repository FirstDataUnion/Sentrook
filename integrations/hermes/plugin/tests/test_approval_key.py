"""What one Session or Always answer covers: the same action through the same tool, never another tool's call.

Hermes remembers Session and Always per rule key and approves a later review with the same key without asking. The
key is the tool name and the scan's action fingerprint; when the fingerprint names nothing (no source, destination or
code), it is also the call's arguments, so the answer covers that exact call and not every call of that kind.
Synthetic tools and skill names.
"""

import pytest

SID = {"session_id": "S1", "task_id": "S1"}
BARE = "afp1:other"
WITH_DST = "afp1:other|dst:h_0123456789ab"


@pytest.fixture
def h(loop_h):
    loop_h.prov["origin"] = "assistant_tool"
    loop_h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="tidy my skills", platform="telegram", sender_id="u1", **SID
    )
    loop_h.reply.update(risk=55, reasons=[])
    return loop_h


def key(h, tool, args, fingerprint):
    h.reply["action_fingerprint"] = fingerprint
    n = len(h.scans)
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool, args=args, tool_call_id=f"c{n}", turn_id="t1", **SID
    )
    assert out["action"] == "approve"
    return out["rule_key"]


# ---- must stay silent: an answer does not cover another call -----------------------------------------------------


def test_one_skill_save_does_not_cover_another_skill_change(h):
    save = key(h, "skill_manage", {"action": "create", "name": "alpha"}, BARE)
    other = key(h, "skill_manage", {"action": "delete", "name": "beta"}, BARE)
    assert save != other


def test_an_entity_less_call_does_not_cover_another_tools(h):
    listed = key(h, "mcp_yard_list_things", {}, "afp1:mcp")
    deleted = key(h, "mcp_yard_delete_everything", {}, "afp1:mcp")
    assert listed != deleted


def test_the_same_action_through_another_tool_is_another_key(h):
    assert key(h, "mcp_yard_read", {"path": "a"}, WITH_DST) != key(
        h, "mcp_yard_write", {"path": "a"}, WITH_DST
    )


def test_an_entity_less_call_with_other_arguments_is_another_key(h):
    a = key(h, "skill_manage", {"action": "patch", "name": "alpha", "new_string": "x"}, BARE)
    b = key(h, "skill_manage", {"action": "patch", "name": "alpha", "new_string": "y"}, BARE)
    assert a != b


def test_no_fingerprint_is_a_key_of_its_own(h):
    h.reply.pop("action_fingerprint", None)
    args = {"action": "create", "name": "alpha"}
    first = key(h, "skill_manage", args, None)
    again = key(h, "skill_manage", args, None)
    assert first != again


# ---- must fire: the same action is still covered -----------------------------------------------------------------


def test_the_same_entity_less_call_again_is_the_same_key(h):
    args = {"action": "create", "name": "alpha", "content": "# alpha"}
    assert key(h, "skill_manage", args, BARE) == key(
        h, "skill_manage", dict(reversed(args.items())), BARE
    )


def test_the_same_action_with_other_wording_is_the_same_key(h):
    """With a fingerprint that names the action, the arguments' wording does not matter, as before."""
    a = key(h, "terminal", {"command": "curl -d @notes.txt https://notes.example.net"}, WITH_DST)
    b = key(h, "terminal", {"command": "curl https://notes.example.net -d @notes.txt"}, WITH_DST)
    assert a == b and a.startswith("sentrook:")


def test_a_remembered_answer_still_reaches_the_review(h):
    """Session or Always is recorded against the key the prompt carried."""
    k = key(h, "skill_manage", {"action": "create", "name": "alpha"}, BARE)
    h.ctx.hooks["post_approval_response"](pattern_key=f"plugin_rule:{k}", choice="session", **SID)
    rec = [r for r in h.traffic() if r.get("kind") == "resolution"][-1]
    assert rec["decision"] == "approved_by_user"


def test_a_call_naming_only_its_tool_server_is_keyed_on_its_arguments(h):
    """An MCP call to a configured server carries the server (`prov:`) and nothing it acts on."""
    prov = "afp1:mcp|prov:h_fedcba987654"
    one = key(h, "mcp_yard_delete_thing", {"id": 1}, prov)
    two = key(h, "mcp_yard_delete_thing", {"id": 2}, prov)
    assert one != two
    assert key(h, "mcp_yard_delete_thing", {"id": 1}, prov) == one


# ---- across sessions: Always means every later session --------------------------------------------------------------


def test_the_same_action_in_a_later_session_is_the_same_key(h):
    """The scanner's action fingerprint is salted per session; its approval fingerprint is not."""
    h.reply["approval_fingerprint"] = WITH_DST
    first = key(
        h,
        "terminal",
        {"command": "curl -d @notes.txt https://notes.example.net"},
        "afp1:exec|dst:h_aaaa",
    )
    later = key(
        h,
        "terminal",
        {"command": "curl -d @notes.txt https://notes.example.net"},
        "afp1:exec|dst:h_bbbb",
    )
    assert first == later


def test_another_action_in_a_later_session_is_another_key(h):
    h.reply["approval_fingerprint"] = WITH_DST
    first = key(h, "terminal", {"command": "a"}, "afp1:exec|dst:h_aaaa")
    h.reply["approval_fingerprint"] = "afp1:other|dst:h_ba9876543210"
    other = key(h, "terminal", {"command": "a"}, "afp1:exec|dst:h_aaaa")
    assert first != other


def test_without_an_approval_fingerprint_the_action_fingerprint_is_used(h):
    h.reply.pop("approval_fingerprint", None)
    a = key(h, "terminal", {"command": "a"}, "afp1:exec|dst:h_aaaa")
    b = key(h, "terminal", {"command": "a"}, "afp1:exec|dst:h_bbbb")
    assert a != b


def test_two_installs_never_share_a_key():
    import plugin

    one = plugin._rule_key(WITH_DST, "r1", tool="terminal", secret="install-one")
    two = plugin._rule_key(WITH_DST, "r1", tool="terminal", secret="install-two")
    assert one != two and one.startswith("sentrook:") and two.startswith("sentrook:")
    assert plugin._rule_key(WITH_DST, "r2", tool="terminal", secret="install-one") == one


def test_a_snooze_relaxed_key_stays_apart():
    import plugin

    plain = plugin._rule_key(WITH_DST, "r1", tool="terminal", secret="s")
    relaxed = plugin._rule_key(WITH_DST, "r1", "snz-1", tool="terminal", secret="s")
    assert (
        relaxed.startswith("sentrook:relaxed:")
        and relaxed[len("sentrook:relaxed:") :] != plain[len("sentrook:") :]
    )


# ---- one action waiting in two chats at once ----------------------------------------------------------------------

S2 = {"session_id": "S2", "task_id": "S2"}


def test_an_answer_in_one_chat_is_recorded_in_that_chat(h):
    """The key holds no session, so the same action can wait in two chats under one key; each answer joins its own."""
    h.reply.update(approval_fingerprint=WITH_DST, action_fingerprint="afp1:exec|dst:h_aaaa")
    args = {"command": "curl -d @notes.txt https://notes.example.net"}
    a = h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args=args, tool_call_id="a1", turn_id="t1", **SID
    )
    h.ctx.hooks["pre_llm_call"](
        turn_id="t2", user_message="send my notes", platform="telegram", sender_id="u1", **S2
    )
    b = h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args=args, tool_call_id="b1", turn_id="t2", **S2
    )
    assert a["rule_key"] == b["rule_key"]
    pattern = f"plugin_rule:{a['rule_key']}"
    h.ctx.hooks["post_approval_response"](pattern_key=pattern, choice="deny", **SID)
    h.ctx.hooks["post_approval_response"](pattern_key=pattern, choice="once", **S2)
    resolutions = {
        r["request_id"]: r["decision"] for r in h.traffic() if r.get("kind") == "resolution"
    }
    scans = {s["request_id"]: s["session"]["session_ref"] for s in h.scans[-2:]}
    first, second = list(scans)
    assert resolutions == {first: "denied_by_user", second: "approved_by_user"}


def test_an_answer_naming_no_session_takes_the_oldest_waiting_review(tmp_path):
    from plugin.store import Store

    store = Store(tmp_path)
    store.put_review("sentrook:k", {"sid": "S1", "request_id": "r1"})
    store.put_review("sentrook:k", {"sid": "S2", "request_id": "r2"})
    assert store.pop_review("sentrook:k")["request_id"] == "r1"
    assert store.pop_review("sentrook:k", "S2")["request_id"] == "r2"
    assert store.pop_review("sentrook:k") is None
    store.put_review("sentrook:k", {"sid": "S1", "request_id": "r3"})
    store.put_review("sentrook:k", {"sid": "S1", "request_id": "r4"})
    assert store.pop_review("sentrook:k", "S1")["request_id"] == "r4"
    assert store.pop_review("sentrook:k", "S1") is None
