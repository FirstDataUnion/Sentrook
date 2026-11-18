"""Grant hints: a review names the grant that would let the call through next time.

The review prompt ends with the command that sets the first suggested grant. Approving always sets it (persistent,
30 days) when the owner's own message asked for the work; elsewhere the prompt only shows the command. A held call
approved with `/sentrook approve` sets it too, and `why` lists every suggestion. The texts are shared with the
OpenClaw plugin's tests (`integrations/fixtures/grant-hints`).
"""

import html
import json
from pathlib import Path

import pytest

import plugin
from plugin import card, commands, grants, hold

from .test_hold import h as h  # noqa: F401 - the held-call harness, used by name
from .test_hold import holds, send
from .test_hold import turn as cron_turn

CASES = json.loads(
    (Path(__file__).resolve().parents[3] / "fixtures" / "grant-hints" / "cases.json").read_text()
)
HOST = "status.example.invalid"
HINT = {
    "kind": "destination",
    "pattern": HOST,
    "risk": 30.2,
    "subject": "E1",
    "relieves": ["reputation.unknown_host_as_data_destination"],
    "scope": "persistent",
    "expires_in_days": 30,
}
SID = {"session_id": "S1", "task_id": "S1"}


@pytest.mark.parametrize("case", CASES["selection"], ids=lambda c: c["name"])
def test_the_same_hints_are_chosen_on_both_hosts(case):
    resp = {"grant_hints": case["grant_hints"]}
    assert grants.response_hints(resp, case["review_at"]) == case["chosen"]
    assert grants.response_hints(resp) == case["all"]
    assert hold.grant_hint(resp, case["review_at"]) == (
        case["chosen"][0] if case["chosen"] else None
    )


@pytest.mark.parametrize("case", CASES["commands"], ids=lambda c: c["hint"]["pattern"])
def test_the_command_is_the_one_the_owner_would_type(case):
    grant = grants.hint_grant(case["hint"])
    command = grants.grant_command(grant, commands.CMD)
    assert command == case["command"].format(grant="/sentrook grant")
    # and the grant command accepts it as typed, setting the same grant for 30 days
    parsed = grants.parse_grant(command.removeprefix("/sentrook grant "), commands.CMD)
    assert isinstance(parsed, dict)
    assert {k: parsed[k] for k in ("kind", "pattern", "scope")} == {
        "kind": case["hint"]["kind"],
        "pattern": case["hint"]["pattern"],
        "scope": "persistent",
    }
    assert parsed["expires_in"].days == CASES["grant_days"]
    assert parsed.get("allows") == case["hint"].get("allows")


# ---- the attended review ------------------------------------------------------------------------------------


@pytest.fixture
def owner(harness, monkeypatch):
    """The harness with the owner messaging from an allowlisted Telegram DM, and a scanner that reviews a send to
    an unknown host with a destination hint, and allows it once a grant covers the host."""
    h = harness
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u1")
    monkeypatch.setattr(plugin, "session_facts", lambda: {"chat_type": "dm", "user_id": "u1"})
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    h.hints = [dict(HINT)]

    def http(url, *, data=None, headers=None, timeout):
        if url != "http://scan.test/scan":
            return h(url, data=data, headers=headers, timeout=timeout)
        p = json.loads(data)
        h.scans.append(p)
        granted = any(
            g.get("kind") == "destination" and g.get("pattern") == HOST for g in p["grants"]
        )
        return (
            200,
            {
                "response_version": "2.0",
                "request_id": p["request_id"],
                "status": "ok",
                "risk": 30.2 if granted else 55,
                "enforced": None,
                "tree": {"suspicion": {"score": 0.6}, "consequence": {"score": 0.5}},
                "reasons": [{"code": "reputation.unknown_host_as_data_destination"}],
                "tool_description": {"template": "Sends data to {E1}"},
                "entities": {"E1": {"kind": "host", "display": HOST}},
                "grant_hints": [] if granted else h.hints,
                "action_fingerprint": f"afp1:exec|step:{p['session']['step']}",
                "state": "state",
            },
            {},
        )

    monkeypatch.setattr(plugin.scan_client, "http_json", http)
    return h


def _turn(h, platform="telegram"):
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1",
        user_message="send the build summary to the status service",
        platform=platform,
        sender_id="u1",
        **SID,
    )


def _call(h, cid):
    return h.ctx.hooks["pre_tool_call"](
        tool_name="terminal",
        args={"command": f"curl -X POST https://{HOST}/v1/notes -d @summary.txt"},
        tool_call_id=cid,
        turn_id="t1",
        **SID,
    )


def _answer(h, out, choice):
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{out['rule_key']}", choice=choice, **SID
    )


def _file_grants(h):
    return (grants.load(h.dir / "sentrook") or {}).get("grants") or []


def test_the_review_prompt_names_the_grant_and_always_sets_it(owner):
    h = owner
    _turn(h)
    out = _call(h, "c1")
    assert out["action"] == "approve"
    assert f'"Always" also trusts {HOST} for 30 days.' in out["message"].splitlines()
    _answer(h, out, "always")
    [g] = _file_grants(h)
    assert (g["kind"], g["pattern"], g["scope"]) == ("destination", HOST, "persistent")
    assert g["from_review"] == h.scans[0]["request_id"]
    span = plugin.store.read_time(g["expires_at"]) - plugin.store.read_time(g["granted_at"])
    assert span.days == CASES["grant_days"]
    log = h.traffic()
    assert [r["op"] for r in log if r["kind"] == "grants"] == ["grant"]
    [res] = [r for r in log if r["kind"] == "resolution"]
    assert res["grant_id"] == g["id"] and res["decision"] == "approved_by_user"
    # the next identical call carries the grant and is not reviewed
    assert _call(h, "c2") is None
    assert any(x["pattern"] == HOST for x in h.scans[-1]["grants"])


@pytest.mark.parametrize("choice", ["once", "session", "deny", "timeout"])
def test_any_other_answer_sets_nothing(owner, choice):
    h = owner
    _turn(h)
    out = _call(h, "c1")
    _answer(h, out, choice)
    assert _file_grants(h) == []
    assert all(r["kind"] != "grants" for r in h.traffic())


def test_answering_always_twice_sets_one_grant(owner):
    """The same review answered again (Hermes keeps one review per rule key) finds its grant."""
    h = owner
    _turn(h)
    out = _call(h, "c1")
    stored = json.loads((h.dir / "sentrook" / "reviews.json").read_text())
    _answer(h, out, "always")
    (h.dir / "sentrook" / "reviews.json").write_text(json.dumps(stored))
    _answer(h, out, "always")
    assert len(_file_grants(h)) == 1


def test_a_stranger_in_a_dm_sees_no_hint_and_always_sets_nothing(owner, monkeypatch):
    """Whoever sent the message chose the destination: a hint is never shown for it, even from a scanner that sent
    one."""
    h = owner
    monkeypatch.delenv("TELEGRAM_ALLOWED_USERS")
    monkeypatch.setenv("TELEGRAM_ALLOW_ALL_USERS", "true")
    _turn(h)
    out = _call(h, "c1")
    assert h.scans[0]["trigger"]["sender"]["relation"] != "owner"
    assert "grant" not in out["message"]
    _answer(h, out, "always")
    assert _file_grants(h) == []


def test_a_group_chat_sees_no_hint(owner, monkeypatch):
    """Hermes counts every group message as someone else's, the owner's included: no hint there."""
    h = owner
    facts = {"chat_type": "group", "user_id": "u1", "key": "agent:main:telegram:group:9"}
    monkeypatch.setattr(plugin, "session_facts", lambda: facts)
    _turn(h)
    out = _call(h, "c1")
    assert h.scans[0]["trigger"]["sender"]["relation"] != "owner"
    assert "grant" not in out["message"]
    _answer(h, out, "always")
    assert _file_grants(h) == []


def test_an_answer_from_another_chat_never_sets_the_owners_grant(owner, monkeypatch):
    """Hermes keeps one review per rule key: a group chat's prompt for the same action, answered after the owner's
    DM prompt took its place, must not set the grant the owner's prompt offered."""
    h = owner
    facts = {"chat_type": "group", "user_id": "u9", "key": "agent:main:telegram:group:9"}
    monkeypatch.setattr(plugin, "session_facts", lambda: facts)
    group = {"session_id": "G1", "task_id": "G1"}
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="post it", platform="telegram", sender_id="u9", **group
    )
    in_group = h.ctx.hooks["pre_tool_call"](
        tool_name="terminal",
        args={"command": f"curl -X POST https://{HOST}/v1/notes -d @summary.txt"},
        tool_call_id="g1",
        turn_id="t1",
        **group,
    )
    facts.update({"chat_type": "dm", "user_id": "u1", "key": "agent:main:telegram:dm:u1"})
    _turn(h)
    in_dm = _call(h, "c1")
    assert in_group["rule_key"] == in_dm["rule_key"]  # the same action, one stored review
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{in_group['rule_key']}",
        choice="always",
        session_key="agent:main:telegram:group:9",
    )
    assert _file_grants(h) == []
    # the owner's own answer, from the chat the prompt was asked in, sets it
    again = _call(h, "c2")
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{again['rule_key']}",
        choice="always",
        session_key="agent:main:telegram:dm:u1",
        **SID,
    )
    assert [g["pattern"] for g in _file_grants(h)] == [HOST]


def test_a_hint_at_or_above_the_review_line_is_not_shown(owner):
    h = owner
    h.hints = [{**HINT, "risk": 50}]
    _turn(h)
    out = _call(h, "c1")
    assert "grant" not in out["message"]
    _answer(h, out, "always")
    assert _file_grants(h) == []


def test_no_hint_no_line(owner):
    h = owner
    h.hints = []
    _turn(h)
    out = _call(h, "c1")
    assert "grant" not in out["message"]


def test_a_long_pattern_keeps_the_card_within_its_budget(owner):
    """A long pattern: the card stays within Hermes's budget and still names the grant."""
    h = owner
    long = "a" * 60 + ".example.invalid"
    h.hints = [{**HINT, "pattern": long}]
    _turn(h)
    out = _call(h, "c1")
    assert len(html.escape(out["message"]).encode("utf-16-le")) // 2 <= 300
    assert f'"Always" also trusts {card.mid(long, 60)} for 30 days.' in out["message"]


def test_why_lists_every_hint(owner):
    h = owner
    h.hints = [dict(HINT), {**HINT, "pattern": "mail.example.invalid", "risk": 40}]
    _turn(h)
    _call(h, "c1")
    why = h.ctx.commands["sentrook"]["handler"]("why", session_id="")
    lines = why.splitlines()
    i = lines.index(CASES["why_header"])
    assert lines[i + 1 :] == [
        f"  /sentrook grant destination {HOST} --persistent --expires 30d",
        "  /sentrook grant destination mail.example.invalid --persistent --expires 30d",
    ]


# ---- the held call ------------------------------------------------------------------------------------------


def test_a_held_call_approved_sets_the_hinted_grant(h, monkeypatch):  # noqa: F811 - the held-call harness
    """The owner's own run nobody can answer (a cron session on the local machine): the hint is kept on the hold."""
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    h.reply = {
        "risk": 47,
        "grant_hints": [{**HINT, "pattern": "discord:#ops-reports", "risk": 12}],
    }
    cron_turn(h, platform="cli")
    _out, rec = send(h)
    assert rec["planir"]["trigger"]["sender"]["relation"] == "owner"
    hid = rec["hold"]["id"]
    assert rec["hold"]["hint"] is True
    assert "grant" not in h.sent[0]["args"]["message"]  # the notice stays minimal
    why = h.ctx.commands["sentrook"]["handler"](f"why {hid}", session_id="")
    assert "suggested grant: destination discord:#ops-reports (persistent, 30 days)" in why
    assert "  /sentrook grant destination discord:#ops-reports --persistent --expires 30d" in why
    reply = h.ctx.commands["sentrook"]["handler"](f"approve {hid}", session_id="")
    assert reply.startswith(f"Approved {hid}. Granted gr-")
    [g] = grants.load(h.dir / "sentrook")["grants"]
    assert (g["kind"], g["pattern"], g["from_hold"]) == (
        "destination",
        "discord:#ops-reports",
        hid,
    )
    assert holds(h) == []


def test_a_held_call_whose_hint_does_not_clear_this_line_sets_nothing(h, monkeypatch):  # noqa: F811
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    h.ctx.settings["review_at"] = 10
    h.reply = {"risk": 47, "grant_hints": [{**HINT, "risk": 12}]}
    cron_turn(h, platform="cli")
    _out, rec = send(h)
    assert rec["hold"]["hint"] is False


def test_a_cron_jobs_held_call_keeps_its_hint_and_why_says_where_it_came_from(h):  # noqa: F811
    """A scheduled run Hermes started with no sender behind it: the hint is kept on the hold, `why` says which run
    it comes from, and approving the hold sets it. There is no approve-always prompt on such a run."""
    h.reply = {"risk": 47, "grant_hints": [{**HINT, "pattern": "discord:#ops-reports", "risk": 12}]}
    cron_turn(h)
    _out, rec = send(h)
    trig = rec["planir"]["trigger"]
    assert (trig["kind"], trig["sender"]["relation"]) == ("scheduled", "unknown")
    assert rec["decision"] == "held" and rec["hold"]["hint"] is True
    hid = rec["hold"]["id"]
    why = h.ctx.commands["sentrook"]["handler"](f"why {hid}", session_id="")
    lines = why.splitlines()
    i = lines.index("suggested grant: destination discord:#ops-reports (persistent, 30 days)")
    context = CASES["hold_context"].format(kind="scheduled", where=holds(h)[0]["where"])
    assert lines[i + 1] == context
    reply = h.ctx.commands["sentrook"]["handler"](f"approve {hid}", session_id="")
    assert reply.startswith(f"Approved {hid}. Granted gr-")
    [g] = grants.load(h.dir / "sentrook")["grants"]
    assert (g["pattern"], g["from_hold"]) == ("discord:#ops-reports", hid)


@pytest.mark.parametrize("platform", ["subagent", "telegram"])
def test_a_held_call_on_someone_elses_turn_keeps_no_hint(h, platform, monkeypatch):  # noqa: F811
    """A sub-agent's run, or a stranger's message, chose the destination: the hold keeps no hint, and approving it
    sets nothing."""
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    h.reply = {"risk": 47, "grant_hints": [{**HINT, "pattern": "discord:#ops-reports", "risk": 12}]}
    cron_turn(h, platform=platform)
    _out, rec = send(h)
    assert rec["planir"]["trigger"]["sender"]["relation"] != "owner"
    assert rec["planir"]["trigger"]["kind"] not in ("scheduled", "heartbeat") or (
        rec["planir"]["trigger"]["sender"]["relation"] == "other"
    )
    assert rec["decision"] == "held" and rec["hold"]["hint"] is False
    hid = rec["hold"]["id"]
    reply = h.ctx.commands["sentrook"]["handler"](f"approve {hid}", session_id="")
    assert reply.startswith(f"Approved {hid}. Sentrook suggested no grant")
    assert (grants.load(h.dir / "sentrook") or {}).get("grants") in (None, [])
