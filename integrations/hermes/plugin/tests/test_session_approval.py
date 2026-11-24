"""Session on a review: the rest of the same job in this chat goes through without asking.

Hermes remembers a Session answer under the rule key the prompt carried, and that key holds every entity of the call,
so a job whose calls differ in an incidental file (each writes its own output) would ask again at every step. On the
owner's own turn, a Session answer also lets a later review in the same chat through when it is a call of the same
tool, about the same parties (the entities its reasons and its description name), scoring no higher, with no
attack-type warning the answered review lacked, nothing enforced and no floor, within 12 hours. Anything else asks.
A Session answer that sets the review's suggested grant (for this session only) keeps no such allowance: the scanner
scores later calls with the grant. Always is unchanged: Hermes's exact key and the 30-day grant.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest

import plugin
from plugin import grants
from plugin.planir import session_ref

HOST = "api.example-notes.test"
OTHER = "files.example-drop.test"
SID = {"session_id": "S1", "task_id": "S1"}
HINT = {
    "kind": "destination",
    "pattern": HOST,
    "risk": 30.2,
    "subject": "E1",
    "relieves": ["reputation.unknown_host_as_data_destination"],
    "scope": "persistent",
    "expires_in_days": 30,
}


def _resp(
    p,
    *,
    risk=55.0,
    hosts=(HOST,),
    enforced=None,
    floors=(),
    hints=(),
    relaxable=None,
    ceiling=None,
    subjects=None,
    extra=(),
    source=None,
):
    """A review of a send to `hosts`, each the subject of a reason, plus an output file nothing names (its path
    differs per step, so the approval fingerprint does too). `source`: a file the description says is sent. `extra`:
    more reason codes, with no subject."""
    step = p["session"]["step"]
    ents = {f"E{i + 1}": {"kind": "host", "display": h} for i, h in enumerate(hosts)}
    template = "Runs code that sends data to {E1}"
    if source is not None:
        sid = f"E{len(ents) + 1}"
        ents[sid] = {"kind": "path", "display": source}
        template = "Sends {" + sid + "} to {E1}"
    ents[f"E{len(ents) + 1}"] = {
        "kind": "path",
        "display": f"~/.agent/cache/scratch/out-{step}.json",
    }
    named = [f"E{i + 1}" for i in range(len(hosts))] if subjects is None else subjects
    reasons = [{"code": "send.off_host", "subject": e, "text": None} for e in named]
    reasons.append(
        {"code": "jev.scope_overreach", "subject": None, "text": "it does more than you asked for"}
    )
    reasons += [{"code": c, "subject": None, "text": None} for c in extra]
    if not named and source is None:
        template = "Runs code"
    return {
        "response_version": "2.0",
        "request_id": p["request_id"],
        "status": "ok",
        "risk": risk,
        "enforced": enforced,
        "ceiling": ceiling,
        "relaxable": relaxable,
        "floors_applied": list(floors),
        "tree": {"suspicion": {"score": 0.6}, "consequence": {"score": 0.8}},
        "reasons": reasons,
        "tool_description": {"template": template},
        "entities": ents,
        "grant_hints": list(hints),
        "approval_fingerprint": "afp1:exec|"
        + "|".join(f"dst:{h}" for h in hosts)
        + f"|src:out-{step}",
        "action_fingerprint": f"afp1:exec|step:{step}",
        "state": "state",
    }


@pytest.fixture
def owner(harness, monkeypatch):
    """The owner messaging from an allowlisted Telegram DM; `h.next` sets what the scanner answers next."""
    h = harness
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u1")
    monkeypatch.setattr(plugin, "session_facts", lambda: {"chat_type": "dm", "user_id": "u1"})
    monkeypatch.setattr(plugin, "session_surface", lambda: "cli")
    h.next = {}
    h.down = False

    def http(url, *, data=None, headers=None, timeout):
        if url != "http://scan.test/scan":
            return h(url, data=data, headers=headers, timeout=timeout)
        p = json.loads(data)
        h.scans.append(p)
        if h.down:
            return 503, {"error": "unavailable"}, {}
        return 200, _resp(p, **h.next), {}

    monkeypatch.setattr(plugin.scan_client, "http_json", http)
    return h


def _turn(h, sid=SID, sender="u1"):
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid['session_id']}-{sender}",
        user_message="check the notes service for open items",
        platform="telegram",
        sender_id=sender,
        **sid,
    )


def _code(h, cid, sid=SID, tool="execute_code", sender="u1"):
    url = f"https://{HOST}/v1/items?page={cid}"
    args = {
        "execute_code": {"code": f"import urllib.request\nurllib.request.urlopen('{url}')"},
        "terminal": {"command": f"curl -s '{url}'"},
        "web_extract": {"urls": [url]},
    }[tool]
    return h.ctx.hooks["pre_tool_call"](
        tool_name=tool,
        args=args,
        tool_call_id=cid,
        turn_id=f"t-{sid['session_id']}-{sender}",
        **sid,
    )


def _answer(h, out, choice, sid=SID, **kw):
    h.ctx.hooks["post_approval_response"](
        pattern_key=f"plugin_rule:{out['rule_key']}", choice=choice, **sid, **kw
    )


def _scan_records(h):
    return [r for r in h.traffic() if r["kind"] == "scan"]


def _file_grants(h):
    return (grants.load(h.dir / "sentrook") or {}).get("grants") or []


def _allows(h):
    """Every allowance kept in any session's state."""
    out = []
    for f in (h.dir / "sentrook" / "sessions").glob("*.json"):
        out += json.loads(f.read_text()).get("session_allows") or []
    return out


def _asked(out):
    return out is not None and out["action"] == "approve"


def _session_then(h, first=None, then=None, **call):
    """The owner's turn: a review answered Session, then the next call with `then` as the scanner's answer."""
    h.next = first or {}
    _turn(h)
    out = _code(h, "c1")
    assert _asked(out)
    _answer(h, out, "session")
    h.next = then or {}
    return _code(h, "c2", **call)


# ---- must stay silent ---------------------------------------------------------------------------------------


def test_after_session_the_same_job_at_no_higher_risk_is_not_asked_again(owner):
    h = owner
    assert _session_then(h, then={"risk": 50.0}) is None  # the call runs, not asked
    first_rec, second_rec = _scan_records(h)
    # the two calls differ in their output file, so Hermes's own exact key would not have matched
    assert (
        first_rec["response"]["approval_fingerprint"]
        != second_rec["response"]["approval_fingerprint"]
    )
    assert second_rec["verdict"] == "review"
    assert second_rec["decision"] == "allowed"
    assert second_rec["session_allowed"] == {"by": h.scans[0]["request_id"]}
    [res] = [r for r in h.traffic() if r["kind"] == "resolution"]
    assert res["session_allow"] is True
    # history tells the scanner it was allowed, not that the owner was shown it
    assert _code(h, "c3") is None
    assert [x["decision"] for x in h.scans[-1]["history"]][-2:] == ["approved_by_user", "allowed"]


def test_the_same_risk_is_not_asked_again(owner):
    assert _session_then(owner) is None


def test_a_new_judge_wording_alone_does_not_ask(owner):
    """The judge's own reasons vary from call to call; only attack-type warnings count."""
    assert (
        _session_then(owner, then={"risk": 50.0, "extra": ["call.not_supported_by_request"]})
        is None
    )


def test_a_warning_the_answered_review_already_had_does_not_ask(owner):
    first = {"extra": ["exposure.task_change"]}
    assert _session_then(owner, first, {"risk": 50.0, "extra": ["exposure.task_change"]}) is None


@pytest.mark.parametrize(
    "note",
    [
        "call.not_supported_by_request",
        "jev.concealment",
        "coverage.unknown_entities",
        "agreement.consequence_split",
        "relief.credential_own_service",
        "origin.agent_generated",
    ],
)
def test_the_scanners_scoring_notes_do_not_ask(owner, note):
    assert _session_then(owner, then={"risk": 50.0, "extra": [note]}) is None


@pytest.mark.parametrize(
    "background", ["exposure.instructions", "exposure.authority", "exposure.session_tainted"]
)
def test_what_the_session_has_been_reading_does_not_ask_while_the_score_stays_no_higher(
    owner, background
):
    """A job that reads documents picks up a different one of these at every step."""
    h = owner
    assert _session_then(h, then={"risk": 50.0, "extra": [background]}) is None
    h.next = {"risk": 60.0, "extra": [background]}
    assert _asked(_code(h, "c3"))


def test_warnings_from_two_answers_are_not_combined(owner):
    """Session on a review with one warning and on another with a second: a call with both still asks."""
    h = owner
    h.next = {"extra": ["exfil.web_post"]}
    _turn(h)
    _answer(h, _code(h, "c1"), "session")
    h.next = {"extra": ["exposure.task_change"]}
    second = _code(h, "c2")
    assert _asked(second)
    _answer(h, second, "session")
    h.next = {"risk": 50.0, "extra": ["exfil.web_post", "exposure.task_change"]}
    assert _asked(_code(h, "c3"))


def test_a_session_answer_sets_the_suggested_grant_for_this_session_only(owner):
    h = owner
    h.next = {"hints": [dict(HINT)]}
    _turn(h)
    first = _code(h, "c1")
    _answer(h, first, "session")
    [g] = _file_grants(h)
    assert (g["kind"], g["pattern"], g["scope"]) == ("destination", HOST, "session")
    assert g["session_ref"] == session_ref("S1")
    assert g["from_review"] == h.scans[0]["request_id"]
    assert g["set_by"]["basis"] == ["review_session"]
    [rec] = [r for r in h.traffic() if r["kind"] == "grants"]
    assert rec["entry"]["id"] == g["id"]
    [res] = [r for r in h.traffic() if r["kind"] == "resolution"]
    assert res["grant_id"] == g["id"]
    # sent on this session's scans, never on another chat's
    h.next = {}
    _code(h, "c2")
    assert any(x.get("pattern") == HOST and x["scope"] == "session" for x in h.scans[-1]["grants"])
    other = {"session_id": "S2", "task_id": "S2"}
    _turn(h, other)
    _code(h, "d1", other)
    assert not any(x.get("pattern") == HOST for x in h.scans[-1]["grants"])


# ---- must still ask -----------------------------------------------------------------------------------------


def test_a_session_answer_that_sets_a_grant_keeps_no_allowance(owner):
    """The grant goes to the scanner; a review despite it has something new and asks."""
    h = owner
    assert _asked(_session_then(h, {"hints": [dict(HINT)]}, {"risk": 50.0}))
    assert _allows(h) == []


def test_always_keeps_no_allowance(owner):
    """Always is unchanged: Hermes's exact key, and the 30-day grant where there is one."""
    h = owner
    _turn(h)
    _answer(h, _code(h, "c1"), "always")
    assert _allows(h) == []
    h.next = {"risk": 50.0}
    assert _asked(_code(h, "c2"))


def test_a_higher_risk_asks(owner):
    assert _asked(_session_then(owner, then={"risk": 60.0}))


@pytest.mark.parametrize(
    "warning",
    [
        "exposure.task_change",
        "exposure.session_injected_content",
        "origin.only_in_untrusted",
        "exfil.web_post",
        "reputation.near_miss_host",
        "reputation.known_bad_host",
        "retry.same_action",
        "conceal.encoded_payload",
        "lineage.secret_carried_to_send",
        "lineage.lookalike_of_named_host",
        "code.steered_source",
        "remote.delete",
        "remote.account_change",
        "priv.sudo",
        "selfmod.startup",
        "destroy.workspace_wide",
        "sensitivity.session_holds_sensitive",
        "escalation.consequence_rising",
        "reputation.unknown_host_as_code_source",
        "a.code_the_scanner_adds_later",
    ],
)
def test_a_new_attack_type_warning_asks_even_at_a_lower_score(owner, warning):
    assert _asked(_session_then(owner, then={"risk": 46.0, "extra": [warning]}))


def test_a_new_party_asks(owner):
    assert _asked(_session_then(owner, then={"risk": 50.0, "hosts": (HOST, OTHER)}))


def test_another_party_alone_asks(owner):
    assert _asked(_session_then(owner, then={"risk": 50.0, "hosts": (OTHER,)}))


def test_another_file_sent_to_the_same_host_asks(owner):
    """The file the description names is one of the parties, though no reason names it."""
    first = {"source": "~/notes/q3-plan.md"}
    assert _asked(_session_then(owner, first, {"risk": 50.0, "source": "~/notes/salaries.xlsx"}))


def test_the_same_file_to_the_same_host_does_not_ask(owner):
    first = {"source": "~/notes/q3-plan.md"}
    assert _session_then(owner, first, {"risk": 50.0, "source": "~/notes/q3-plan.md"}) is None


@pytest.mark.parametrize(
    "change", [{"enforced": "review"}, {"floors": [{"floor": "sensitive_data_sent"}]}]
)
def test_an_enforced_review_or_a_floor_asks(owner, change):
    assert _asked(_session_then(owner, then={"risk": 50.0, **change}))


@pytest.mark.parametrize("tool", ["terminal", "web_extract"])
def test_another_tool_asks_even_of_the_same_kind(owner, tool):
    assert _asked(_session_then(owner, then={"risk": 50.0}, tool=tool))


def test_a_block_still_blocks(owner):
    out = _session_then(owner, then={"risk": 90.0})
    assert out["action"] == "block"


@pytest.mark.parametrize("choice", ["once", "deny", "timeout"])
def test_any_other_answer_covers_nothing_more(owner, choice):
    h = owner
    _turn(h)
    _answer(h, _code(h, "c1"), choice)
    assert _allows(h) == []
    h.next = {"risk": 50.0}
    assert _asked(_code(h, "c2"))


def test_another_chat_asks(owner):
    h = owner
    _turn(h)
    _answer(h, _code(h, "c1"), "session")
    other = {"session_id": "S2", "task_id": "S2"}
    _turn(h, other)
    h.next = {"risk": 50.0}
    assert _asked(_code(h, "d1", other))


def _as(monkeypatch, user):
    monkeypatch.setattr(plugin, "session_facts", lambda: {"chat_type": "dm", "user_id": user})


def test_someone_elses_turn_in_the_same_chat_asks(owner, monkeypatch):
    h = owner
    _session_then(h, then={"risk": 50.0})
    _as(monkeypatch, "u9")
    _turn(h, sender="u9")
    h.next = {"risk": 50.0}
    out = _code(h, "c3", sender="u9")
    assert h.scans[-1]["trigger"]["sender"]["relation"] != "owner"
    assert _asked(out)


def test_an_answer_from_another_chat_covers_nothing(owner, monkeypatch):
    """The answer must come from the chat the review was asked in, as for the suggested grant."""
    h = owner
    monkeypatch.setattr(
        plugin,
        "session_facts",
        lambda: {"chat_type": "dm", "user_id": "u1", "key": "agent:main:telegram:dm:u1"},
    )
    _turn(h)
    first = _code(h, "c1")
    _answer(h, first, "session", session_key="agent:main:telegram:group:9")
    assert _allows(h) == []
    h.next = {"risk": 50.0}
    assert _asked(_code(h, "c2"))


def test_a_review_that_names_no_party_covers_only_that_action(owner):
    h = owner
    assert _asked(_session_then(h, {"subjects": []}, {"risk": 50.0, "subjects": []}))
    assert _allows(h) == []


def test_on_someone_elses_turn_session_keeps_nothing(owner, monkeypatch):
    """Whoever answers outside the owner's own message is not known to be the owner: Hermes's exact key only."""
    h = owner
    h.next = {"hints": [dict(HINT)]}
    _as(monkeypatch, "u9")
    _turn(h, sender="u9")
    first = _code(h, "c1", sender="u9")
    assert h.scans[0]["trigger"]["sender"]["relation"] != "owner"
    _answer(h, first, "session")
    assert _file_grants(h) == []
    assert _allows(h) == []
    # and the owner's own next call in this chat is asked too
    _as(monkeypatch, "u1")
    _turn(h)
    h.next = {"risk": 50.0}
    assert _asked(_code(h, "c2"))


def _snooze(h):
    now = datetime.now(UTC)
    (h.dir / "sentrook").mkdir(parents=True, exist_ok=True)
    (h.dir / "sentrook" / "snooze.json").write_text(
        json.dumps(
            {
                "version": 1,
                "snoozes": [
                    {
                        "scope": "session",
                        "session_ref": session_ref("S1"),
                        "set_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "set_by": {"basis": ["local_terminal"], "platform": "", "sender_ref": None},
                    }
                ],
            }
        )
    )


def test_a_block_a_snooze_turned_into_a_review_keeps_nothing(owner):
    h = owner
    _snooze(h)
    h.next = {"risk": 85.0, "relaxable": True}
    _turn(h)
    first = _code(h, "c1")
    assert _asked(first) and "a snooze is on" in first["message"]
    _answer(h, first, "session")
    assert _allows(h) == []


def test_a_block_the_scanner_capped_to_a_review_keeps_nothing(owner):
    h = owner
    h.next = {"risk": 85.0, "ceiling": "review"}
    _turn(h)
    first = _code(h, "c1")
    assert _asked(first)
    _answer(h, first, "session")
    assert _allows(h) == []


def test_a_scan_error_answered_session_keeps_nothing(owner):
    h = owner
    h.down = True
    _turn(h)
    out = _code(h, "c1")
    assert _asked(out)
    _answer(h, out, "session")
    assert _allows(h) == []


def test_an_allowance_ends_after_12_hours(owner):
    h = owner
    _turn(h)
    _answer(h, _code(h, "c1"), "session")
    assert len(_allows(h)) == 1
    for f in (h.dir / "sentrook" / "sessions").glob("*.json"):
        s = json.loads(f.read_text())
        for a in s.get("session_allows") or []:
            a["at"] = (datetime.now(UTC) - timedelta(hours=13)).strftime("%Y-%m-%dT%H:%M:%SZ")
        f.write_text(json.dumps(s))
    h.next = {"risk": 50.0}
    assert _asked(_code(h, "c2"))


# ---- the card -----------------------------------------------------------------------------------------------


def test_the_card_says_what_session_covers(owner):
    h = owner
    _turn(h)
    out = _code(h, "c1")
    assert '"Session" also covers the same parties at no higher risk.' in out["message"]
    assert len(out["message"]) <= 300


def test_with_a_suggested_grant_the_card_names_it_for_session_and_always(owner):
    h = owner
    h.next = {"hints": [dict(HINT)]}
    _turn(h)
    out = _code(h, "c1")
    lines = out["message"].splitlines()
    assert f'"Session" also trusts {HOST} in this chat, "Always" for 30 days.' in lines
    assert not any("same parties" in line for line in lines)
    assert len(out["message"]) <= 300


def test_with_no_party_the_card_says_session_covers_this_action(owner):
    h = owner
    h.next = {"subjects": []}
    _turn(h)
    out = _code(h, "c1")
    assert '"Session" covers only this exact action.' in out["message"]
