"""Always on a review of an MCP tool call: later calls of that tool on that server are not asked again.

Hermes remembers an Always answer under the prompt's rule key. For a call whose approval fingerprint names only its
MCP server, that key also holds the call's arguments (an approval of one such call must not cover every call of the
tool), and an MCP write tool's arguments change on every call, so the key never repeats and Always behaved like Once.

On the owner's own turn, an Always answer to a review of an MCP tool call is also kept as a standing allowance for
that tool on that server (the server's identity, as the scan names the provider), with the same limits as Session
coverage: at most 10 points above the answered risk, below the block line, no warning the answered review lacked, no
floor, nothing enforced, a complete scan. Paths the call names (the page it writes) are not part of the key; any
other party (a host, a recipient, a channel) is. It lasts 30 days, is listed with the grants and revoked like one.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import plugin
from plugin import always_allow, grants

#: Shared with the OpenClaw plugin's tests: both hosts key and match an Always answer the same way.
CASES = json.loads(
    (Path(__file__).resolve().parents[3] / "fixtures" / "always-allow" / "cases.json").read_text()
)
SID = {"session_id": "S1", "task_id": "S1"}
WIKI = {"url": "https://wiki.example-team.test/mcp"}
OTHER_WIKI = {"url": "https://wiki.example-other.test/mcp"}
HINT = {
    "kind": "provider",
    "pattern": "remote:wiki.example-team.test",
    "risk": 30.2,
    "subject": "E1",
    "relieves": ["reputation.unknown_mcp_server_as_tool_provider"],
    "scope": "persistent",
    "expires_in_days": 30,
}


def _resp(
    p,
    *,
    risk=50.0,
    page=None,
    host=None,
    enforced=None,
    floors=(),
    hints=(),
    extra=(),
    status="ok",
):
    """A review of a page write through the wiki server: the judge's consequence reasons only (no subject), the
    server named by the description, and `page` (a path) or `host` named as the place written to when given."""
    prov = p["pending_call"]["provider"]
    ents = {"E1": {"kind": "mcp_server", "display": str(prov["name"])}}
    template = "Writes a page through {E1}"
    reasons = [
        {"code": c, "subject": None, "text": "it cannot be undone"}
        for c in ("jev.irreversibility", "jev.reach", "jev.sensitivity")
    ]
    parts = []
    if page is not None:
        ents["E2"] = {"kind": "path", "display": page}
        template = "Writes {E2} through {E1}"
        reasons.append({"code": "origin.agent_generated", "subject": "E2", "text": None})
        parts.append(f"dst:{page}")
    if host is not None:
        ents["E3"] = {"kind": "host", "display": host}
        template += " and sends it to {E3}"
        reasons.append({"code": "send.off_host", "subject": "E3", "text": None})
        parts.append(f"dst:{host}")
    reasons += [{"code": c, "subject": None, "text": None} for c in extra]
    return {
        "response_version": "2.0",
        "request_id": p["request_id"],
        "status": status,
        "risk": risk,
        "enforced": enforced,
        "ceiling": None,
        "relaxable": None,
        "floors_applied": list(floors),
        "tree": {"suspicion": {"score": 0.2}, "consequence": {"score": 0.8}},
        "reasons": reasons,
        "tool_description": {"template": template},
        "entities": ents,
        "grant_hints": list(hints),
        "approval_fingerprint": "|".join(["afp1:mcp", *parts, f"prov:{prov['identity']}"]),
        "action_fingerprint": f"afp1:mcp|step:{p['session']['step']}",
        "state": "state",
    }


@pytest.fixture
def owner(harness, monkeypatch):
    """The owner messaging from an allowlisted Telegram DM, with a wiki MCP server configured; `h.next` sets what
    the scanner answers next, `h.mcp` the host's MCP servers."""
    h = harness
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u1")
    h.facts = {"chat_type": "dm", "user_id": "u1"}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(h.facts))
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    h.mcp = {"wiki": dict(WIKI), "notes": dict(OTHER_WIKI)}
    monkeypatch.setattr(plugin, "hermes_config", lambda: {"mcp_servers": h.mcp})
    h.next = {}

    def http(url, *, data=None, headers=None, timeout):
        if url != "http://scan.test/scan":
            return h(url, data=data, headers=headers, timeout=timeout)
        p = json.loads(data)
        h.scans.append(p)
        return 200, _resp(p, **h.next), {}

    monkeypatch.setattr(plugin.scan_client, "http_json", http)
    return h


def _turn(h, sid=SID, sender="u1"):
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid['session_id']}-{sender}",
        user_message="update the onboarding pages on the wiki",
        platform="telegram",
        sender_id=sender,
        **sid,
    )


def _call(h, cid, *, tool="mcp__wiki__update_page", sid=SID, sender="u1", title=None):
    return h.ctx.hooks["pre_tool_call"](
        tool_name=tool,
        args={"title": title or f"Onboarding/{cid}", "text": f"Revised section {cid}."},
        tool_call_id=cid,
        turn_id=f"t-{sid['session_id']}-{sender}",
        **sid,
    )


def _answer(h, out, choice, sid=SID, **kw):
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{out['rule_key']}", choice=choice, **sid, **kw
    )


def _asked(out):
    return out is not None and out["action"] == "approve"


def _scans(h):
    return [r for r in h.traffic() if r["kind"] == "scan"]


def _kept(h):
    return (always_allow.load(h.dir / "sentrook") or {}).get("allows") or []


def _always_then(h, first=None, then=None, choice="always", **call):
    """The owner's turn: a review of an update_page call answered `choice`, then the next call with `then` as the
    scanner's answer."""
    h.next = first or {}
    _turn(h)
    out = _call(h, "c1")
    assert _asked(out)
    _answer(h, out, choice)
    h.next = then or {}
    return _call(h, "c2", **call)


def slash(h, raw_args, session_id="S1"):
    return h.ctx.commands["sentrook"]["handler"](raw_args, session_id=session_id)


# ---- shared cases ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES["keys"], ids=lambda c: c["name"])
def test_shared_key(case):
    got = always_allow.key(case["tool"], case["provider"], case["response"], CASES["secret"])
    assert got == case["match"]


@pytest.mark.parametrize("case", CASES["covering"], ids=lambda c: c["name"])
def test_shared_covering(case):
    now = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)
    answer = {**case["answer"], "request_id": "r1", "at": "2026-11-28T11:00:00Z"}
    data = {"allows": [{"id": "aa-000001", "key": "k", "answers": [answer]}]}
    got = always_allow.covering(data, "k", case["response"], now, CASES["block_at"])
    assert (got is not None) == case["covered"]


# ---- the guard stays: Hermes's exact key ---------------------------------------------------------------------


def test_two_update_page_calls_with_other_arguments_have_other_rule_keys():
    """Unit level: a fingerprint naming only the provider keys on the arguments too (the exact-key guard)."""
    fp = "afp1:mcp|prov:remote:wiki.example-team.test"
    one = plugin._rule_key(fp, "r1", tool="mcp__wiki__update_page", args={"title": "A"})
    two = plugin._rule_key(fp, "r2", tool="mcp__wiki__update_page", args={"title": "B"})
    assert one != two


# ---- must stay silent ---------------------------------------------------------------------------------------


def test_after_always_the_same_tool_on_the_same_server_with_other_arguments_is_not_asked(owner):
    h = owner
    assert _always_then(h, then={"risk": 49.0}) is None  # the call runs, not asked
    first, second = _scans(h)
    assert first["response"]["approval_fingerprint"] == second["response"]["approval_fingerprint"]
    assert second["verdict"] == "review"
    assert second["decision"] == "allowed"
    [kept] = _kept(h)
    assert second["always_allowed"] == {"by": h.scans[0]["request_id"], "id": kept["id"]}
    [res] = [r for r in h.traffic() if r["kind"] == "resolution"]
    assert res["resolution"] == "always"
    assert res["always_allow"] == kept["id"]
    # history tells the scanner it was allowed, not that the owner was shown it
    assert _call(h, "c3") is None
    assert [x["decision"] for x in h.scans[-1]["history"]][-2:] == ["approved_by_user", "allowed"]


def test_it_lasts_into_another_session(owner):
    h = owner
    _always_then(h)
    other = {"session_id": "S2", "task_id": "S2"}
    _turn(h, sid=other)
    assert _call(h, "c9", sid=other) is None


def test_a_call_writing_another_page_is_not_asked(owner):
    """The page the call writes is not part of the key: every call of an update tool names another one."""
    first = {"page": "Onboarding/Laptops"}
    assert _always_then(owner, first, then={"page": "Onboarding/Accounts"}) is None


def test_a_call_naming_a_page_after_one_that_named_none_is_not_asked(owner):
    assert _always_then(owner, then={"page": "Onboarding/Accounts"}) is None


@pytest.mark.parametrize("risk", [55.0, 60.0])
def test_a_call_up_to_10_points_higher_is_not_asked(owner, risk):
    assert _always_then(owner, then={"risk": risk}) is None


def test_a_rising_consequence_trend_alone_does_not_ask(owner):
    assert _always_then(owner, then={"extra": ["escalation.consequence_rising"]}) is None


def test_the_judges_own_reasons_changing_does_not_ask(owner):
    assert _always_then(owner, then={"extra": ["call.not_supported_by_request"]}) is None


def test_the_answer_is_kept_once_per_tool_and_server(owner):
    h = owner
    _always_then(h)
    h.next = {"risk": 75.0}  # more than 10 points higher: asked, and answered Always again
    out = _call(h, "c3")
    assert _asked(out)
    _answer(h, out, "always")
    [kept] = _kept(h)
    assert sorted(a["risk"] for a in kept["answers"]) == [50.0, 75.0]
    h.next = {"risk": 80.0 - 0.5}
    assert _call(h, "c4") is None  # covered by the answer at 75


# ---- must still fire ----------------------------------------------------------------------------------------


def test_the_same_tool_on_another_server_asks(owner):
    """The server is its identity: the same name pointed at another address is another server."""
    h = owner
    h.next = {}
    _turn(h)
    out = _call(h, "c1")
    _answer(h, out, "always")
    h.mcp["wiki"] = dict(OTHER_WIKI)
    assert _asked(_call(h, "c2"))


def test_a_tool_of_the_same_name_on_another_configured_server_asks(owner):
    assert _asked(_always_then(owner, tool="mcp__notes__update_page"))


def test_another_tool_on_the_same_server_asks(owner):
    assert _asked(_always_then(owner, tool="mcp__wiki__create_page"))


def test_a_call_that_also_sends_to_a_host_asks(owner):
    assert _asked(_always_then(owner, then={"host": "paste.example-drop.test"}))


def test_more_than_10_points_higher_asks(owner):
    assert _asked(_always_then(owner, then={"risk": 60.5}))


def test_a_new_warning_asks(owner):
    assert _asked(_always_then(owner, then={"extra": ["exposure.task_change"]}))


def test_a_floor_asks(owner):
    assert _asked(
        _always_then(owner, then={"risk": 50.0, "floors": [{"floor": "sensitive_data_sent"}]})
    )


def test_an_enforced_review_asks(owner):
    assert _asked(_always_then(owner, then={"risk": 30.0, "enforced": "review"}))


def test_a_degraded_scan_asks(owner):
    assert _asked(_always_then(owner, then={"status": "degraded"}))


def test_a_block_score_is_blocked(owner):
    out = _always_then(owner, first={"risk": 75.0}, then={"risk": 82.0})
    assert out is not None and out["action"] == "block"


def test_after_30_days_it_asks_again(owner):
    h = owner
    _always_then(h)
    path = h.dir / "sentrook" / "always-allows.json"
    data = json.loads(path.read_text())
    old = (datetime.now(UTC) - timedelta(days=31)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for a in data["allows"]:
        for ans in a["answers"]:
            ans["at"] = old
    path.write_text(json.dumps(data))
    assert _asked(_call(h, "c3"))


def test_revoked_it_asks_again(owner):
    h = owner
    _always_then(h)
    [kept] = _kept(h)
    listing = slash(h, "grants")
    assert kept["id"] in listing
    assert "mcp__wiki__update_page" in listing and "remote:wiki.example-team.test" in listing
    assert slash(h, f"revoke {kept['id']}") == (
        f"Revoked {kept['id']}: Always for mcp__wiki__update_page on wiki."
    )
    assert _kept(h) == []
    assert _asked(_call(h, "c3"))


# ---- when nothing is kept ----------------------------------------------------------------------------------


def test_once_keeps_nothing(owner):
    assert _asked(_always_then(owner, choice="once"))
    assert _kept(owner) == []


def test_session_keeps_no_standing_allowance(owner):
    h = owner
    _always_then(h, choice="session")
    assert _kept(h) == []
    other = {"session_id": "S2", "task_id": "S2"}
    _turn(h, sid=other)
    assert _asked(_call(h, "c9", sid=other))


def test_in_a_group_chat_always_keeps_nothing(owner):
    """Whoever answers in a group is not known to be the owner."""
    owner.facts["chat_type"] = "group"
    owner.facts["chat_id"] = "g1"
    assert _asked(_always_then(owner))
    assert _kept(owner) == []


def test_an_answer_from_another_chat_keeps_nothing(owner):
    h = owner
    h.next = {}
    _turn(h)
    out = _call(h, "c1")
    _answer(h, out, "always", session_key="elsewhere")
    assert _kept(h) == []


def test_with_a_suggested_grant_always_sets_the_grant_and_no_allowance(owner):
    h = owner
    _always_then(h, first={"hints": [HINT]})
    assert _kept(h) == []
    assert [g["pattern"] for g in grants.load(h.dir / "sentrook")["grants"]] == [HINT["pattern"]]


def test_at_the_block_line_nothing_is_kept(owner):
    """A block the scanner capped to a review."""
    h = owner
    h.next = {"risk": 85.0, "extra": []}
    _turn(h)
    out = _call(h, "c1")
    if _asked(out):
        _answer(h, out, "always")
    assert _kept(h) == []


def test_a_built_in_tool_keeps_hermes_exact_key_only(owner):
    """Not an MCP call: no standing allowance; the exact-key guard decides, as before."""
    h = owner
    h.next = {}
    _turn(h)
    out = _call(h, "c1", tool="write_file")
    if _asked(out):
        _answer(h, out, "always")
    assert _kept(h) == []


def test_without_a_server_identity_nothing_is_kept(owner):
    """A server the host config does not describe has no identity to key on."""
    h = owner
    del h.mcp["wiki"]
    assert _asked(_always_then(h))
    assert _kept(h) == []


# ---- the card ----------------------------------------------------------------------------------------------


def test_the_card_says_what_always_covers(owner):
    h = owner
    _turn(h)
    out = _call(h, "c1")
    assert (
        '"Always" also covers this tool on this server at a similar risk for 30 days.'
        in out["message"]
    )


def test_the_card_says_nothing_of_it_where_nothing_would_be_kept(owner):
    h = owner
    h.facts["chat_type"] = "group"
    h.facts["chat_id"] = "g1"
    _turn(h)
    out = _call(h, "c1")
    assert "this tool on this server" not in out["message"]
