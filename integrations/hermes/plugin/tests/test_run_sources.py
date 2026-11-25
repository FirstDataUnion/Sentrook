"""Held calls on unattended runs that are not cron jobs: the answers bind to where the run came from.

Hermes names a subagent's parent session (`parent_session_id` on each turn of a delegated child) and a webhook run's
route (the `webhook:<route>` user id its webhook platform binds for an authenticated route). On a hold from such a run
`allow` is a one-use pass for the next matching call from the same source within 7 days (nothing is started), and
`allow always` and `deny` are bound to the same source. An API-server run has no source Hermes names (one shared key,
no key name): it keeps `allow` alone, bound to the exact call. The texts are shared with the OpenClaw plugin
(`integrations/fixtures/hold/cases.json`, `sources`).
"""

import json
from datetime import timedelta

import pytest

import plugin
from plugin import hold, passes

from .test_hold import FIXTURES, held_call_harness, holds
from .test_hold import slash as _slash
from .test_holds_v2 import ALWAYS, DECLINED, HELD, NAMED, notices, stored_passes

SOURCES = FIXTURES["sources"]


@pytest.fixture
def h(harness, monkeypatch):
    fake = held_call_harness(harness, monkeypatch)
    fake.reply = dict(NAMED)
    fake.facts = {}
    monkeypatch.setattr(plugin, "session_facts", lambda: dict(fake.facts))
    return fake


def call(h, sid, *, platform, parent="", message="Daily brief", cid="c1"):
    """One send from session `sid` on `platform` (a subagent: of parent session `parent`); the directive and the
    scan record."""
    ids = {"session_id": sid, "task_id": sid}
    h.ctx.hooks["pre_llm_call"](
        turn_id=f"t-{sid}",
        user_message="Post the brief.",
        platform=platform,
        sender_id="",
        parent_session_id=parent,
        **ids,
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name="send_message",
        args={"action": "send", "target": "discord:#ops-reports", "message": message},
        tool_call_id=cid,
        turn_id=f"t-{sid}",
        **ids,
    )
    hold.wait_for_notices()
    return out, [r for r in h.traffic() if r.get("kind") == "scan"][-1]


def child(h, n, parent="P1", **kw):
    """A send from subagent session `n` of parent session `parent`."""
    return call(h, f"sub-{parent}-{n}", platform="subagent", parent=parent, **kw)


def hook(h, n, route="github-push", **kw):
    """A send from a webhook delivery `n` on `route`, unattended (a gateway with no terminal)."""
    h.facts = {"platform": "webhook", "user_id": f"webhook:{route}", "chat_id": f"webhook:v2:{n}"}
    return call(h, f"hook-{route}-{n}", platform="webhook", **kw)


def slash(h, raw):
    """The owner's command, from the local terminal (not from inside the webhook run the last call came from)."""
    h.facts = {}
    return _slash(h, raw)


@pytest.fixture
def unattended(monkeypatch):
    monkeypatch.setattr(plugin, "is_unattended", lambda *_a, **_kw: True)


def parent_ref(parent):
    return plugin.planir.session_ref(parent)


# ---- must stay silent ----------------------------------------------------------------------------------------


def test_allow_on_a_subagent_hold_lets_the_next_matching_call_from_the_same_parent_through_once(h):
    out, rec = child(h, 1)
    assert out == HELD
    hid = rec["hold"]["id"]
    assert rec["hold"]["offers"] == ["allow", "deny"]
    [entry] = holds(h)
    assert entry["source"] == passes.source_of("subagent", parent_ref("P1"))
    assert (
        entry["where"]
        == f"subagent run, parent session {parent_ref('P1')}, session {rec['session_ref']}"
    )
    reply = slash(h, f"allow {hid}")
    [p] = stored_passes(h)
    assert reply == SOURCES["replies"]["allow"].format(
        subject=f"Subagents of session {parent_ref('P1')}",
        until=passes.show(passes.read_time(p["expires_at"])),
        passes="/sentrook passes",
        **{"pass": p["id"]},
    )
    assert (p["kind"], p["uses"], p["source_kind"], p["source_ref"]) == (
        "allow",
        "once",
        "subagent",
        entry["source"]["ref"],
    )
    assert passes.read_time(p["expires_at"]) - passes.read_time(p["set_at"]) == timedelta(days=7)
    assert not [r for r in h.traffic() if r.get("kind") == "run_now"], "nothing is started"
    out, rec = child(h, 2)
    assert out is None and rec["decision"] == "allowed_by_pass"
    assert stored_passes(h) == [], "used up"
    out, rec = child(h, 3)
    assert out == HELD


def test_allow_always_on_a_webhook_hold_lets_the_route_make_the_call_for_30_days(h, unattended):
    h.reply = dict(ALWAYS)
    _out, rec = hook(h, 1)
    hid = rec["hold"]["id"]
    assert rec["hold"]["offers"] == ["allow", "allow always", "deny"]
    [entry] = holds(h)
    assert entry["where"] == f'webhook run, hook "github-push", session {rec["session_ref"]}'
    reply = slash(h, f"allow {hid} always")
    [p] = stored_passes(h)
    assert reply.startswith('Webhook "github-push" may make this call until ')
    assert passes.read_time(p["expires_at"]) - passes.read_time(p["set_at"]) == timedelta(days=30)
    for n in (2, 3, 4):
        out, rec = hook(h, n)
        assert out is None and rec["decision"] == "allowed_by_pass"
    assert stored_passes(h)[0]["use_count"] == 3
    listed = slash(h, "passes")
    assert 'allowed from webhook "github-push" until ' in listed and "used 3 times" in listed


# ---- must fire ---------------------------------------------------------------------------------------------


def test_the_same_call_from_a_subagent_of_another_parent_session_is_held(h):
    _out, rec = child(h, 1, parent="P1")
    slash(h, f"allow {rec['hold']['id']}")
    out, rec = child(h, 1, parent="P2")
    assert out == HELD and rec["decision"] == "held"
    assert len(stored_passes(h)) == 1, "P1's pass is still there"


def test_the_same_call_from_another_webhook_route_is_held(h, unattended):
    _out, rec = hook(h, 1, route="github-push")
    slash(h, f"allow {rec['hold']['id']}")
    out, rec = hook(h, 2, route="stripe")
    assert out == HELD


def test_deny_is_bound_to_the_source(h):
    _out, rec = child(h, 1, parent="P1")
    reply = slash(h, f"deny {rec['hold']['id']}")
    assert reply.startswith(
        f"Subagents of session {parent_ref('P1')} will not make this call until "
    )
    sent = len(notices(h))
    out, rec = child(h, 2, parent="P1")
    assert out == DECLINED and rec["decision"] == "denied_by_owner"
    assert len(notices(h)) == sent, "no notice for a denied call"
    out, rec = child(h, 1, parent="P2")
    assert out == HELD
    assert len(notices(h)) == sent + 1
    assert "denied from subagents of session " in slash(h, "passes")


def test_a_subagent_whose_parent_hermes_does_not_name_offers_no_always_or_deny(h):
    h.reply = dict(ALWAYS)
    out, rec = child(h, 1, parent="")
    assert out == HELD
    assert rec["hold"]["offers"] == ["allow"]
    hid = rec["hold"]["id"]
    assert "no cron job or other source" in slash(h, f"deny {hid}")
    assert "no cron job or other source" in slash(h, f"allow {hid} always")


def test_an_api_server_run_has_no_source(h, unattended):
    h.reply = dict(ALWAYS)
    h.facts = {"platform": "api_server", "chat_id": "client-chosen", "key": "client-chosen"}
    out, rec = call(h, "api-1", platform="api_server")
    assert out == HELD
    assert rec["hold"]["offers"] == ["allow"]
    [entry] = holds(h)
    assert entry["source"] is None


def test_a_webhook_run_without_a_route_has_no_source(h, unattended):
    h.reply = dict(ALWAYS)
    h.facts = {"platform": "webhook", "user_id": "", "chat_id": "webhook:v2:abc"}
    out, rec = call(h, "hook-1", platform="webhook")
    assert rec["hold"]["offers"] == ["allow"]


def test_a_pass_from_a_source_does_not_cover_an_exact_call_from_no_source(h):
    """A one-use pass bound to a source settles only calls from that source, never one from a run with none."""
    _out, rec = child(h, 1, parent="P1")
    slash(h, f"allow {rec['hold']['id']}")
    out, _rec = child(h, 2, parent="")
    assert out == HELD


# ---- must stay the same ------------------------------------------------------------------------------------


def test_a_repeat_of_a_waiting_source_hold_sends_no_new_notice(h):
    child(h, 1)
    child(h, 2)
    [entry] = holds(h)
    assert entry["count"] == 2
    assert len(notices(h)) == 1


def test_a_cron_jobs_hold_is_unchanged(h):
    from .test_holds_v2 import run

    _out, rec = run(h, 1)
    assert rec["hold"]["offers"] == ["allow", "allow later", "deny"]
    [entry] = holds(h)
    assert entry["source"] is None and entry["job_id"] == "job-j"


# ---- the shared texts --------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", SOURCES["refs"], ids=lambda c: f"{c['kind']}:{c['value']}")
def test_source_refs(case):
    assert passes.source_ref(case["kind"], case["value"]) == case["ref"]


@pytest.mark.parametrize("case", SOURCES["subjects"], ids=lambda c: c["subject"])
def test_reply_subjects(case):
    found = {
        "v": 2,
        "job_ref": None,
        "source": {"kind": case["kind"], "ref": "x_1", "name": case["name"]},
    }
    assert hold._subject(found) == case["subject"]


@pytest.mark.parametrize("want", ["allow", "allow always", "deny"])
def test_the_passes_list_names_the_source(want):
    p = {
        "id": "p-000000",
        "kind": "deny" if want == "deny" else "allow",
        "uses": "once" if want == "allow" else "standing",
        "job_ref": None,
        "source_kind": "heartbeat",
        "source_ref": passes.source_ref("heartbeat", "main"),
        "source_name": "main",
        "tool": "message",
        "description": "Sends a message to discord:#ops-reports",
        "expires_at": "2026-12-01T10:00:00Z",
        "use_count": 2,
    }
    assert passes.describe(p) == SOURCES["passes_list"][want].format(
        source='the heartbeat of agent "main"',
        until="2026-12-01 10:00 UTC",
        tool="message",
        description="Sends a message to discord:#ops-reports",
        used=2,
    )


def test_fixture_is_valid_json():
    assert json.loads(json.dumps(SOURCES))
