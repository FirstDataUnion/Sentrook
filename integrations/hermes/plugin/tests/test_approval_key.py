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
