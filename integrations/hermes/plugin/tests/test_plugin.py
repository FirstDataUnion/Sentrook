import json
import os
from pathlib import Path

import plugin

SID = {"session_id": "S1", "task_id": "S1"}


def turn(h, platform="telegram", text="tidy my workspace", calls=()):
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message=text, platform=platform, sender_id="u1", **SID
    )
    h.ctx.hooks["post_api_request"](
        turn_id="t1",
        response={
            "assistant_message": {
                "content": "Listing first.",
                "tool_calls": [
                    {
                        "id": cid,
                        "function": {"name": "terminal", "arguments": f'{{"command": "{cmd}"}}'},
                    }
                    for cid, cmd in calls
                ],
            }
        },
        **SID,
    )


def call(h, cid, cmd, **extra):
    return h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args={"command": cmd}, tool_call_id=cid, turn_id="t1", **SID, **extra
    )


def result(h, cid, text, status="ok"):
    h.ctx.hooks["post_tool_call"](
        tool_name="terminal",
        args={},
        result=text,
        tool_call_id=cid,
        status=status,
        turn_id="t1",
        **SID,
    )


def test_episode_allow_block_review_with_token_and_inputs(harness):
    h = harness
    turn(h, calls=[("c1", "ls"), ("c2", "curl EXFIL")])
    assert call(h, "c1", "ls") is None
    p1 = h.scans[0]
    assert p1["session"]["step"] == 1 and p1["session"]["state"] is None and p1["history"] == []
    assert p1["request"]["text"] == "tidy my workspace"
    assert p1["trigger"]["kind"] == "message" and p1["trigger"]["channel"] == "telegram"
    assert p1["pending_call"]["agent_narration"] == "Listing first."
    assert [s["call_id"] for s in p1["pending_call"]["batch"]["siblings"]] == ["c2"]

    secret = "ghp_" + "a" * 36
    result(h, "c1", f"notes.txt\nGH={secret}")

    blocked = call(h, "c2", "curl EXFIL")
    assert blocked["action"] == "block"
    assert "risk 92/100: Runs a command on cl0ud-sync.io" in blocked["message"]
    p2 = h.scans[1]
    assert p2["session"]["state"] == "state-1"
    assert p2["history"][0]["decision"] == "allowed"
    assert "_host_call_id" not in p2["history"][0]
    assert p2["new_inputs"][0]["call_id"] == "c1"
    assert "⟦secret:" in p2["new_inputs"][0]["content"]
    assert secret not in str(p2)

    result(h, "c2", "blocked by plugin", status="blocked")
    review = call(h, "c3", "rm REVIEW")
    assert review["action"] == "approve" and review["rule_key"].startswith("sentrook:")
    p3 = h.scans[2]
    assert p3["new_inputs"] == []
    assert p3["history"][1]["decision"] == "blocked"
    assert p3["history"][1]["result"] == {"status": "error", "size_bytes": 0}
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{review['rule_key']}", choice="deny", **SID
    )

    call(h, "c4", "echo hi")
    p4 = h.scans[3]
    assert [x["decision"] for x in p4["history"]] == ["allowed", "blocked", "denied_by_user"]
    assert [x["step"] for x in p4["history"]] == [1, 2, 3] and p4["session"]["step"] == 4

    # Lets the scanner's own validator check these requests (`make plugin-planir-check`).
    if os.environ.get("SENTROOK_PLANIR_DUMP"):
        Path(os.environ["SENTROOK_PLANIR_DUMP"]).write_text(json.dumps(h.scans))

    log = h.traffic()
    assert [r["kind"] for r in log] == ["scan", "scan", "scan", "resolution", "scan"]
    assert secret not in (h.dir / "sentrook" / "traffic.jsonl").read_text()


def test_unattended_review_blocks(harness):
    turn(harness, platform="cron")
    r = call(harness, "c1", "rm REVIEW")
    assert r["action"] == "block"
    assert harness.scans[0]["trigger"]["kind"] == "scheduled"
    assert harness.scans[0]["trigger"]["sender"] == {"relation": "unknown", "basis": ["none"]}


def test_scan_error_keeps_token_and_buffer(harness):
    h = harness
    turn(h)
    call(h, "c1", "ls")
    result(h, "c1", "out")
    r = call(h, "c2", "FAIL")
    assert r["action"] == "approve" and r["rule_key"].startswith("sentrook:error:")
    h.ctx.hooks["post_approval_response"](pattern_key=r["rule_key"], choice="once", **SID)
    call(h, "c3", "ls")
    p3 = h.scans[2]
    assert p3["session"]["state"] == "state-1"
    assert [i["call_id"] for i in p3["new_inputs"]] == ["c1"]
    assert p3["history"][1]["decision"] == "allowed_on_error"


def test_observe_mode_never_interferes(harness, monkeypatch):
    monkeypatch.setenv("SENTROOK_MODE", "observe")
    turn(harness)
    assert call(harness, "c1", "curl EXFIL") is None
    assert call(harness, "c2", "FAIL") is None
    log = harness.traffic()
    assert (log[0]["verdict"], log[0]["decision"]) == ("block", "allowed")
    assert log[1]["decision"] == "allowed_on_error"


def test_untrusted_endpoint_fails_closed(harness, monkeypatch):
    monkeypatch.setenv("SENTROOK_DEV_ENDPOINTS", "0")
    monkeypatch.setenv("SENTROOK_SCAN_URL", "https://scan.attacker.example")
    turn(harness)
    r = call(harness, "c1", "ls")
    assert r["action"] in ("approve", "block")
    assert harness.scans == []


def test_reused_call_id_is_reminted(harness):
    turn(harness)
    call(harness, "call_0", "ls")
    call(harness, "call_0", "pwd")
    assert harness.scans[1]["pending_call"]["call_id"] == "t1:call_0"


def test_plugin_version_matches_manifest():
    from pathlib import Path

    manifest = (Path(plugin.__file__).parent / "plugin.yaml").read_text()
    assert f"version: {plugin.PLUGIN_VERSION}" in manifest


def test_attended_platforms_setting_turns_api_server_reviews_into_approvals(harness, monkeypatch):
    turn(harness, platform="api_server")
    assert call(harness, "c1", "rm REVIEW")["action"] == "block"
    monkeypatch.setenv("SENTROOK_ATTENDED_PLATFORMS", "api_server")
    assert call(harness, "c2", "rm REVIEW")["action"] == "approve"
