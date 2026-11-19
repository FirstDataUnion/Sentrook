"""A held background save is staged in Hermes's own pending store, so the owner can look at it and approve or reject
it with Hermes's own commands (`/skills diff|approve|reject <id>`, `/memory pending|approve|reject`).

Hermes's background review and its curator save skills and memory after the owner's turn has ended, so a review of
one of those saves cannot ask anyone: it is held. Held, its content used to be lost. Now, when Hermes can replay it,
the plugin stages it with Hermes's `tools.write_approval.stage_write`, whatever Hermes's own `write_approval` settings:

- staged: `skill_manage` create, edit, patch, write_file, remove_file (and batches of those); `memory` add (and
  batches of only adds). A review a rule floor enforces is staged too, and its summary says a rule asked for it.
- never staged, held exactly as before: a block; a block-level score a retry rule capped at review; a save whose scan
  says it adds a secret (or, from a scanner that sends no `self_edit` object, one the plugin's redaction changed); a
  skill delete; a memory patch or remove; anything the plugin did not declare with its `self_edit` block.
- a memory patch or remove from an unattended review on a Hermes whose own gate stages it is let through to that
  gate, and `post_tool_call` records and announces what Hermes did: staged, saved, or neither.
- the staged file is made 0600; at most 20 records the plugin staged wait in each store; anything failing holds.
- the agent is told the save was not saved, is staged for the owner, and must not be retried; the owner's notice
  carries the pending id and Hermes's commands, never what the save writes.
- observe mode, attended calls and saves let through as lenient are unchanged.
"""

import json
import os
import stat
import sys
import types

import pytest

import plugin
from plugin import commands, dashboard, history, hold, staging
from plugin.redact import Redactor

from . import hermes_fakes
from .test_background_saves import LENIENT, NOT_LENIENT, SID, Tty

#: A save the plugin's redaction changes: a password stated in prose.
PASSWORD = "Zt8" + "qL2mW7xR"
SECRET_NOTE = f"The staging database password is {PASSWORD} for the deploy user."

SKILL_MD = (
    "---\nname: tidy\ndescription: Tidy notes.\n---\n\n# Tidy\n\nRun `make tidy` after edits.\n"
)
#: name -> (tool, the call's arguments, the store, the payload Hermes replays on approval)
STAGEABLE = {
    "skill-create": (
        "skill_manage",
        {"action": "create", "name": "tidy", "content": SKILL_MD},
        "skills",
        {"action": "create", "name": "tidy", "content": SKILL_MD},
    ),
    "skill-edit": (
        "skill_manage",
        {"action": "edit", "name": "tidy", "content": SKILL_MD},
        "skills",
        {"action": "edit", "name": "tidy", "content": SKILL_MD},
    ),
    "skill-patch": (
        "skill_manage",
        {
            "action": "patch",
            "name": "tidy",
            "old_string": "make tidy",
            "new_string": "make tidy-all",
            "replace_all": False,
        },
        "skills",
        {
            "action": "patch",
            "name": "tidy",
            "old_string": "make tidy",
            "new_string": "make tidy-all",
            "replace_all": False,
        },
    ),
    "skill-write-file": (
        "skill_manage",
        {
            "action": "write_file",
            "name": "tidy",
            "file_path": "references/notes.md",
            "file_content": "# Notes\nKeep it short.\n",
        },
        "skills",
        {
            "action": "write_file",
            "name": "tidy",
            "file_path": "references/notes.md",
            "file_content": "# Notes\nKeep it short.\n",
        },
    ),
    "skill-remove-file": (
        "skill_manage",
        {"action": "remove_file", "name": "tidy", "file_path": "references/old.md"},
        "skills",
        {"action": "remove_file", "name": "tidy", "file_path": "references/old.md"},
    ),
    "skill-batch": (
        "skill_manage",
        {
            "operations": [
                {"action": "create", "name": "tidy", "content": SKILL_MD},
                {"action": "patch", "name": "tidy", "old_string": "make", "new_string": "just"},
            ]
        },
        "skills",
        {
            "action": "batch",
            "operations": [
                {"action": "create", "name": "tidy", "content": SKILL_MD},
                {"action": "patch", "name": "tidy", "old_string": "make", "new_string": "just"},
            ],
        },
    ),
    "memory-add": (
        "memory",
        {"action": "add", "target": "memory", "content": "Prefers short replies."},
        "memory",
        {
            "action": "add",
            "target": "memory",
            "content": "Prefers short replies.",
            "old_text": None,
        },
    ),
    "memory-add-new-text": (
        "memory",
        {"action": "add", "target": "user", "new_text": "Works in UTC."},
        "memory",
        {"action": "add", "target": "user", "content": "Works in UTC.", "old_text": None},
    ),
    "memory-batch-adds": (
        "memory",
        {
            "target": "memory",
            "operations": [
                {"action": "add", "content": "Uses uv."},
                {"action": "add", "content": "Runs make lint before a PR."},
            ],
        },
        "memory",
        {
            "action": "batch",
            "target": "memory",
            "operations": [
                {"action": "add", "content": "Uses uv."},
                {"action": "add", "content": "Runs make lint before a PR."},
            ],
        },
    ),
}


@pytest.fixture
def h(loop_h, monkeypatch):
    """The background-review harness with Telegram as the owner's notice channel, a `dispatch_tool` that records each
    send (`.sent`), and Hermes's pending store (`.wa`, `tools.write_approval`) under `HERMES_HOME`."""
    fake = loop_h
    monkeypatch.setattr(hold, "home_platforms", lambda: ["telegram"])
    fake.sent = []

    def dispatch_tool(name, args, **_kw):
        fake.sent.append({"name": name, "args": args})
        return json.dumps({"success": True})

    fake.ctx.dispatch_tool = dispatch_tool
    fake.ctx.settings["owner_channel"] = "telegram"
    fake.wa = hermes_fakes.write_approval(fake.dir, lambda: fake.prov["origin"])
    constants = types.ModuleType("hermes_constants")
    constants.get_hermes_home = lambda: fake.dir
    tools = sys.modules["tools"]
    tools.write_approval = fake.wa
    monkeypatch.setitem(sys.modules, "tools.write_approval", fake.wa)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    fake.reply.update(risk=55, self_edit=NOT_LENIENT)
    return fake


@pytest.fixture
def gate(h, monkeypatch):
    """Hermes's memory tool with its unattended-review gate (`tools.memory_tool`), as `hermes_fakes` shapes it."""
    mod = hermes_fakes.memory_tool_module()
    sys.modules["tools"].memory_tool = mod
    monkeypatch.setitem(sys.modules, "tools.memory_tool", mod)
    h.memory_tool = mod
    return h


def save(h, tool, args, call_id=None, platform="telegram"):
    h.ctx.hooks["pre_llm_call"](
        turn_id="t1", user_message="keep replies short", platform=platform, sender_id="u1", **SID
    )
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=tool,
        args=args,
        tool_call_id=call_id or f"c{len(h.scans)}",
        turn_id="t1",
        **SID,
    )
    hold.wait_for_notices()
    return out, scans(h)[-1]


def scans(h):
    return [r for r in h.traffic() if r.get("kind") == "scan"]


def pending(h, store):
    d = h.dir / "pending" / store
    return sorted(d.glob("*.json")) if d.exists() else []


def shown(h):
    scan, res = history.recent_scans(h.dir / "sentrook" / "traffic.jsonl", 1)[0]
    action = history.action_of(scan, res)
    return action, history.review_of(action, res)


def notices(h):
    return [s["args"]["message"] for s in h.sent]


HELD = {"action": "block", "message": hold.HELD_TEXT}
STAGED = {"action": "block", "message": staging.STAGED_TEXT}


# ---- staged ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(STAGEABLE))
def test_a_held_save_hermes_can_replay_is_staged(h, name):
    tool, args, store, payload = STAGEABLE[name]
    out, rec = save(h, tool, args)
    assert out == STAGED
    (path,) = pending(h, store)
    record = json.loads(path.read_text())
    assert rec["decision"] == "staged" and rec["skill_review"] is True
    assert rec["staging"] == {
        "status": "staged",
        "store": store,
        "id": record["id"],
        "by": "sentrook",
    }
    # exactly the call, so approving makes the save the scan judged
    assert record["payload"] == payload
    assert record["origin"] == "background_review"
    assert record["summary"].startswith("Held by Sentrook (Sentrook asks for a review): ")
    assert len(record["summary"]) <= 200
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert shown(h) == ("staged (self-edit)", "pending in Hermes")
    assert len(h.sent) == 1


@pytest.mark.parametrize("surface", ["cli", "telegram", "api_server", "curator"])
def test_staged_from_every_background_run(h, monkeypatch, surface):
    """The review fork after a chat, the terminal or the API server, and the curator: one code path."""
    if surface == "cli":
        monkeypatch.setattr(sys, "stdin", Tty())
    out, rec = save(h, *STAGEABLE["skill-create"][:2], platform=surface)
    assert out == STAGED and rec["decision"] == "staged" and len(pending(h, "skills")) == 1


def test_the_summary_is_the_plugins_own_words_and_never_the_save(h):
    tool, args, *_ = STAGEABLE["memory-add"]
    save(h, tool, args)
    (call,) = h.wa.calls
    assert call["summary"] == (
        "Held by Sentrook (Sentrook asks for a review): add 1 entry to memory. Not saved until you approve it."
    )
    assert "short replies" not in call["summary"]
    save(h, *STAGEABLE["skill-batch"][:2])
    assert h.wa.calls[-1]["summary"] == (
        "Held by Sentrook (Sentrook asks for a review): 2 skill changes on 'tidy'. Not saved until you approve it."
    )


def test_a_review_a_rule_floor_enforces_is_staged_and_says_so(h):
    h.reply.update(risk=20, enforced="review")
    out, rec = save(h, *STAGEABLE["skill-patch"][:2])
    assert out == STAGED and rec["decision"] == "staged"
    assert h.wa.calls[0]["summary"] == (
        "Held by Sentrook (a Sentrook rule asks for a review): edit skill 'tidy'. Not saved until you approve it."
    )
    (text,) = notices(h)
    assert "(a Sentrook rule asks for a review of this)." in text


def test_a_scanner_without_a_self_edit_object_stages_an_unredacted_save(h):
    h.reply["self_edit"] = None
    del h.reply["self_edit"]
    out, rec = save(h, *STAGEABLE["memory-add"][:2])
    assert out == STAGED and rec["decision"] == "staged"


def test_the_skill_notice_gives_the_id_and_the_commands_and_never_the_save(h):
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    pid = rec["staging"]["id"]
    (text,) = notices(h)
    assert text.splitlines() == [
        "Sentrook held a background skill save and staged it in Hermes for you to approve, so it is not saved yet.",
        f"Run: background save, session {rec['session_ref']}",
        "Save: skill_manage: Saves a skill",
        "Held because it changes the agent's own setup, such as its configuration, memory, plugins, skills or "
        "scheduled jobs.",
        f"Pending id: {pid}",
        f"Look first: /skills diff {pid}",
        f"Then approve it: /skills approve {pid}",
        f"Or reject it: /skills reject {pid}",
        f"Details: /sentrook why {rec['request_id'][:8]}; every background save is in /sentrook history.",
        "More staged background saves in this session are not announced for 6 hours; /skills pending and "
        "/memory pending list them all.",
    ]
    assert "Tidy" not in text and "make tidy" not in text
    assert rec["notice"] == {"status": "queued", "target": "telegram"}


def test_the_memory_notice_says_where_the_text_is(h):
    _, rec = save(h, *STAGEABLE["memory-add"][:2])
    pid = rec["staging"]["id"]
    (text,) = notices(h)
    lines = text.splitlines()
    assert lines[0] == (
        "Sentrook held a background memory save and staged it in Hermes for you to approve, so it is not saved yet."
    )
    assert lines[4:8] == [
        f"Pending id: {pid}",
        "Look first: /memory pending (it lists the change, not the text; the text is in "
        f"pending/memory/{pid}.json in the Hermes home folder)",
        f"Then approve it: /memory approve {pid}",
        f"Or reject it: /memory reject {pid}",
    ]
    assert "short replies" not in text


def test_one_staged_notice_per_session_in_the_quiet_period(h):
    save(h, *STAGEABLE["skill-create"][:2])
    _, rec = save(h, *STAGEABLE["memory-add"][:2])
    assert rec["decision"] == "staged" and rec["notice"] == {"status": "quiet"}
    assert len(h.sent) == 1 and len(pending(h, "memory")) == 1


def test_a_staged_save_is_sent_to_the_scanner_as_not_run(h):
    save(h, *STAGEABLE["skill-create"][:2])
    h.ctx.hooks["post_tool_call"](
        tool_name="skill_manage",
        args=STAGEABLE["skill-create"][1],
        result=staging.STAGED_TEXT,
        status="blocked",
        tool_call_id="c0",
        turn_id="t1",
        **SID,
    )
    save(h, "read_file", {"path": "notes.md"})
    (earlier,) = [x for x in h.scans[-1]["history"] if x["tool"] == "skill_manage"]
    assert earlier["decision"] == "review_timed_out" and earlier["result"]["size_bytes"] == 0


def test_status_and_the_dashboard_count_staged_saves(h):
    save(h, *STAGEABLE["skill-create"][:2])
    status = commands.run_status("", dict(h.ctx.settings))
    line = next(x for x in status.splitlines() if x.startswith("skill review:"))
    assert line.endswith("0 allowed, 0 blocked, 1 staged")
    scan, res = history.recent_scans(h.dir / "sentrook" / "traffic.jsonl", 1)[0]
    assert dashboard.scan_model(scan, res)["bucket"] == "review"


# ---- never staged: held as before ------------------------------------------------------------------------


NEVER = {
    "block": ("skill-create", {"risk": 92}, None, "blocked"),
    "retry-capped-block": (
        "skill-create",
        {"risk": 92, "ceiling": "review", "reasons": [{"code": "cap.unanswered_retry"}]},
        "block_level",
        "held",
    ),
    "adds-a-secret": (
        "memory-add",
        {"self_edit": {"adds": ["secret"], "lenient": False}},
        "secret",
        "held",
    ),
    "self-edit-not-an-object": ("memory-add", {"self_edit": "x"}, "self_edit_unreadable", "held"),
    "adds-not-a-list": (
        "memory-add",
        {"self_edit": {"adds": "secret"}},
        "self_edit_unreadable",
        "held",
    ),
}


@pytest.mark.parametrize("case", list(NEVER))
def test_never_staged_by_the_response(h, case):
    name, reply, reason, decision = NEVER[case]
    h.reply.update(reply)
    out, rec = save(h, *STAGEABLE[name][:2])
    assert rec["decision"] == decision and h.wa.calls == []
    assert pending(h, "skills") == pending(h, "memory") == []
    if decision == "held":
        assert out == HELD and rec["staging"] == {"status": "held", "reason": reason}
        assert notices(h)[0].startswith("Sentrook held a background")
    else:
        assert out["action"] == "block" and "staging" not in rec


def test_an_old_scanner_never_stages_a_save_the_plugins_redaction_changed(h):
    assert Redactor("standard", "s").string(SECRET_NOTE) != SECRET_NOTE
    del h.reply["self_edit"]
    out, rec = save(h, "memory", {"action": "add", "target": "memory", "content": SECRET_NOTE})
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "redacted"}
    assert h.wa.calls == [] and pending(h, "memory") == []


def test_a_save_the_plugins_redaction_changed_is_never_staged_whatever_the_scanner_says(h):
    """The scanner may not have seen the secret: a copy cut to the input cap can leave it out."""
    out, rec = save(h, "memory", {"action": "add", "target": "memory", "content": SECRET_NOTE})
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "redacted"}
    assert h.wa.calls == []


def test_a_save_larger_than_the_scanned_copy_is_never_staged(h):
    h.ctx.settings["input_cap_bytes"] = 1024
    out, rec = save(
        h,
        "memory",
        {"action": "add", "target": "memory", "content": "Prefers short replies. " * 60},
    )
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "too_large"}
    assert h.wa.calls == []


def test_an_undeclared_save_is_never_staged(h):
    """With `skill_review: review` no `self_edit` block is sent."""
    h.ctx.settings["skill_review"] = "review"
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "not_declared"}


NOT_STAGEABLE = {
    "skill-delete": ("skill_manage", {"action": "delete", "name": "tidy"}, "delete"),
    "skill-batch-with-delete": (
        "skill_manage",
        {"operations": [{"action": "delete", "name": "tidy"}]},
        "delete",
    ),
    "skill-unknown-action": ("skill_manage", {"action": "archive", "name": "tidy"}, "action"),
    "skill-without-name": ("skill_manage", {"action": "create", "content": SKILL_MD}, "name"),
    "skill-empty-batch": ("skill_manage", {"operations": []}, "batch"),
    "memory-patch": (
        "memory",
        {"action": "patch", "target": "memory", "old_text": "short", "content": "long"},
        "destructive_memory",
    ),
    "memory-remove": (
        "memory",
        {"action": "remove", "target": "memory", "old_text": "short"},
        "destructive_memory",
    ),
    "memory-batch-with-remove": (
        "memory",
        {
            "target": "memory",
            "operations": [
                {"action": "add", "content": "Uses uv."},
                {"action": "remove", "old_text": "pip"},
            ],
        },
        "destructive_memory",
    ),
    "memory-replace": (
        "memory",
        {"action": "replace", "target": "memory", "old_text": "a", "content": "b"},
        "action",
    ),
    "memory-without-target": ("memory", {"action": "add", "content": "x"}, "target"),
    "memory-add-without-content": ("memory", {"action": "add", "target": "memory"}, "content"),
}


@pytest.mark.parametrize("case", list(NOT_STAGEABLE))
def test_never_staged_by_what_it_saves(h, case):
    tool, args, reason = NOT_STAGEABLE[case]
    out, rec = save(h, tool, args)
    assert out == HELD and rec["decision"] == "held"
    assert rec["staging"] == {"status": "held", "reason": reason}
    assert h.wa.calls == [] and pending(h, "skills") == pending(h, "memory") == []
    assert shown(h) == ("held (self-edit)", "not saved")


# ---- falls back to the hold ------------------------------------------------------------------------------


def test_without_hermess_pending_store_the_save_is_held(h, monkeypatch):
    """An older Hermes, or the plugin running out of process: `tools.write_approval` cannot be imported."""
    monkeypatch.delitem(sys.modules, "tools.write_approval")
    del sys.modules["tools"].write_approval
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "unavailable"}
    (text,) = notices(h)
    assert text.startswith("Sentrook held a background skill save for you, so it was not saved.")


@pytest.mark.parametrize(
    ("fail", "reason"), [("raise", "failed"), ("list", "failed"), ("no_file", "not_written")]
)
def test_a_staging_failure_holds_the_save(h, fail, reason):
    h.wa.fail = fail
    out, rec = save(h, *STAGEABLE["memory-add"][:2])
    assert out == HELD and rec["decision"] == "held"
    assert rec["staging"] == {"status": "held", "reason": reason}
    assert pending(h, "memory") == []
    assert notices(h)[0].startswith(
        "Sentrook held a background memory save for you, so it was not saved."
    )


def test_a_record_that_cannot_be_made_private_is_discarded_and_the_save_held(h, monkeypatch):
    monkeypatch.setattr(staging, "make_private", lambda _path: False)
    out, rec = save(h, *STAGEABLE["memory-add"][:2])
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "not_written"}
    assert pending(h, "memory") == []


def test_a_bad_record_id_holds_the_save(h):
    real = h.wa.stage_write
    h.wa.stage_write = lambda *a, **k: {**real(*a, **k), "id": "../../x"}
    out, rec = save(h, *STAGEABLE["memory-add"][:2])
    assert out == HELD and rec["staging"]["reason"] == "failed"


def seed(h, store, n, summary):
    d = h.dir / "pending" / store
    d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (d / f"{i:08x}.json").write_text(
            json.dumps({"id": f"{i:08x}", "summary": summary, "created_at": i, "payload": {}})
        )


def test_at_most_twenty_staged_records_per_store(h):
    seed(h, "skills", staging.MAX_PENDING - 1, "Held by Sentrook (Sentrook asks for a review): x")
    # Hermes's own records do not count
    seed_host = h.dir / "pending" / "skills" / "aaaaaaaa.json"
    seed_host.write_text(json.dumps({"id": "aaaaaaaa", "summary": "create 'x'", "payload": {}}))
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    assert out == STAGED
    out, rec = save(h, *STAGEABLE["skill-patch"][:2])
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "over_cap"}
    assert len(pending(h, "skills")) == staging.MAX_PENDING + 1
    # the other store has its own cap
    out, rec = save(h, *STAGEABLE["memory-add"][:2])
    assert out == STAGED


# ---- unchanged ----------------------------------------------------------------------------------------------


def test_observe_mode_never_stages(h):
    h.ctx.settings["mode"] = "observe"
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    assert out is None and h.wa.calls == [] and "staging" not in rec and h.sent == []


def test_a_lenient_save_is_let_through_not_staged(h):
    h.reply.update(self_edit=LENIENT)
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    assert out is None and rec["lenient"] is True and h.wa.calls == []


def test_an_attended_save_still_asks(h):
    h.prov["origin"] = "assistant_tool"
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    assert out["action"] == "approve" and h.wa.calls == [] and "staging" not in rec


def test_an_allowed_save_runs(h):
    h.reply.update(risk=5)
    out, rec = save(h, *STAGEABLE["skill-create"][:2])
    assert out is None and rec["decision"] == "allowed" and h.wa.calls == []


# ---- destructive memory changes Hermes's own gate stages --------------------------------------------------

DESTRUCTIVE = {
    "patch": {"action": "patch", "target": "memory", "old_text": "short", "content": "very short"},
    "remove": {"action": "remove", "target": "memory", "old_text": "short"},
    "batch": {
        "target": "user",
        "operations": [
            {"action": "add", "content": "Uses uv."},
            {"action": "remove", "old_text": "pip"},
        ],
    },
}


def done(h, args, result, status="ok", call_id="c0"):
    h.ctx.hooks["post_tool_call"](
        tool_name="memory",
        args=args,
        result=result,
        status=status,
        tool_call_id=call_id,
        turn_id="t1",
        **SID,
    )
    hold.wait_for_notices()
    return [r for r in h.traffic() if r.get("kind") == "resolution"]


@pytest.mark.parametrize("name", list(DESTRUCTIVE))
def test_a_destructive_memory_change_goes_to_hermess_own_gate(gate, name):
    h = gate
    out, rec = save(h, "memory", DESTRUCTIVE[name])
    assert out is None and rec["decision"] == "host_staging"
    assert rec["staging"] == {"status": "host", "store": "memory", "by": "hermes"}
    assert h.wa.calls == [] and h.sent == []
    assert shown(h) == ("sent to Hermes to stage (self-edit)", "-")
    # Hermes's gate runs and stages it: the tool result says so
    result = h.memory_tool.memory_tool(**DESTRUCTIVE[name])
    pid = json.loads(result)["pending_id"]
    (res,) = done(h, DESTRUCTIVE[name], result)
    assert (
        res["resolution"] == "host_staged"
        and res["decision"] == "staged"
        and res["pending_id"] == pid
    )
    assert stat.S_IMODE(os.stat(h.dir / "pending" / "memory" / f"{pid}.json").st_mode) == 0o600
    assert shown(h) == ("staged (by Hermes, self-edit)", "pending in Hermes")
    (text,) = notices(h)
    lines = text.splitlines()
    assert lines[0] == (
        "Sentrook held a background memory save and Hermes staged it for you to approve, so it is not saved yet."
    )
    assert lines[4:8] == [
        f"Pending id: {pid}",
        "Look first: /memory pending",
        f"Then approve it: /memory approve {pid}",
        f"Or reject it: /memory reject {pid}",
    ]
    assert "short" not in text
    status = commands.run_status("", dict(h.ctx.settings))
    assert next(x for x in status.splitlines() if x.startswith("skill review:")).endswith(
        "1 staged"
    )


def test_a_change_hermes_staged_is_sent_to_the_scanner_as_not_run(gate):
    h = gate
    save(h, "memory", DESTRUCTIVE["remove"])
    done(h, DESTRUCTIVE["remove"], h.memory_tool.memory_tool(**DESTRUCTIVE["remove"]))
    save(h, "read_file", {"path": "notes.md"})
    (earlier,) = [x for x in h.scans[-1]["history"] if x["tool"] == "memory"]
    assert earlier["decision"] == "review_timed_out" and earlier["result"]["size_bytes"] == 0
    assert not any(i.get("call_id") == earlier["call_id"] for i in h.scans[-1]["new_inputs"])


def test_a_destructive_change_hermes_saved_is_announced_truthfully(gate):
    h = gate
    save(h, "memory", DESTRUCTIVE["remove"])
    (res,) = done(
        h, DESTRUCTIVE["remove"], json.dumps({"success": True, "message": "Entry removed."})
    )
    assert res["resolution"] == "host_saved" and res["decision"] == "allowed"
    assert shown(h) == ("saved (not staged by Hermes, self-edit)", "saved without approval")
    (text,) = notices(h)
    assert text.splitlines()[0] == (
        "Sentrook let a background memory change through for Hermes to stage for your approval, but Hermes saved "
        "it without staging it."
    )
    status = commands.run_status("", dict(h.ctx.settings))
    assert next(x for x in status.splitlines() if x.startswith("skill review:")).endswith(
        "1 let through"
    )


@pytest.mark.parametrize(
    ("result", "status", "resolution", "first"),
    [
        (
            json.dumps({"success": False, "error": "no match"}),
            "ok",
            "host_not_saved",
            "Sentrook held",
        ),
        ("Sentrook security block: blocked", "blocked", "host_not_saved", "Sentrook held"),
        ("not json", "ok", "host_unknown", "Sentrook let"),
        ("worker abandoned", "cancelled", "host_unknown", "Sentrook let"),
        (
            json.dumps({"success": True, "staged": True, "pending_id": "../x"}),
            "ok",
            "host_unknown",
            "Sentrook let",
        ),
    ],
    ids=["refused", "blocked", "unreadable", "cancelled", "bad-id"],
)
def test_what_hermes_did_is_read_from_the_result(gate, result, status, resolution, first):
    h = gate
    save(h, "memory", DESTRUCTIVE["patch"])
    (res,) = done(h, DESTRUCTIVE["patch"], result, status=status)
    assert res["resolution"] == resolution and "pending_id" not in res
    assert notices(h)[0].startswith(first)
    if resolution == "host_not_saved":
        assert shown(h) == ("held (self-edit)", "not saved")
    else:
        assert shown(h) == ("sent to Hermes (outcome unknown, self-edit)", "may have been saved")


def test_a_destructive_change_carrying_a_secret_stays_held(gate):
    h = gate
    h.reply.update(self_edit={"adds": ["secret"], "lenient": False})
    out, rec = save(h, "memory", DESTRUCTIVE["patch"])
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "secret"}


UNSURE = {
    "no-memory-tool": lambda m: None,
    "gate-missing": lambda m: delattr(m, "_background_delete_gate"),
    "gate-not-called": lambda m: setattr(m, "_memory_tool", hermes_fakes._memory_tool_unwired),
    "gate-on-one-path-only": lambda m: setattr(
        m, "_memory_tool", hermes_fakes._memory_tool_batch_only
    ),
    "gate-after-write": lambda m: setattr(
        m, "_memory_tool", hermes_fakes._memory_tool_gate_after_write
    ),
    "gate-never-stages": lambda m: setattr(
        m, "_background_delete_gate", hermes_fakes._background_delete_gate_denies
    ),
    "source-unreadable": lambda m: setattr(m, "_memory_tool", len),
    "not-destructive-to-hermes": lambda m: setattr(m, "destructive_ops", lambda _p: []),
    "no-stage-write": lambda m: delattr(sys.modules["tools.write_approval"], "stage_write"),
}


@pytest.mark.parametrize("case", list(UNSURE))
def test_when_hermess_gate_cannot_be_established_the_change_is_held(gate, monkeypatch, case):
    h = gate
    if case == "no-memory-tool":
        monkeypatch.delitem(sys.modules, "tools.memory_tool")
        del sys.modules["tools"].memory_tool
    else:
        UNSURE[case](h.memory_tool)
    out, rec = save(h, "memory", DESTRUCTIVE["remove"])
    assert out == HELD and rec["staging"] == {"status": "held", "reason": "destructive_memory"}


def test_an_attended_review_is_never_left_to_hermess_gate(gate):
    """Hermes's gate stages only an unattended review's changes; an owner's `/refine` is not a background save."""
    h = gate
    h.prov["attended"] = True
    out, rec = save(h, "memory", DESTRUCTIVE["remove"])
    assert out["action"] == "approve" and "staging" not in rec


# ---- units ---------------------------------------------------------------------------------------------------


def test_the_summary_is_bounded_and_inert():
    r = Redactor("standard", "s")
    bad = staging.Plan("skills", "x‮\u0007​" + "y" * 400)
    out = staging.summary(bad, rule=False)
    assert len(out) == 200 and "‮" not in out and "\u0007" not in out and "​" not in out
    for name in ("evil.example", "a@b", "x:y", "[a](b)", "UPPER", "a" * 60):
        p = staging.plan("skill_manage", {"action": "create", "name": name, "content": "c"}, r)
        assert p.what == "create a skill", name
    assert staging.plan(
        "skill_manage", {"action": "create", "name": "tidy-2", "content": "c"}, r
    ).what == ("create skill 'tidy-2'")


@pytest.mark.parametrize(
    ("status", "result", "want"),
    [
        (
            "ok",
            {"success": True, "staged": True, "proposal_staged": True, "pending_id": "0a1b2c3d"},
            "staged",
        ),
        ("ok", json.dumps({"success": True, "staged": True, "pending_id": "0a1b2c3d"}), "staged"),
        ("ok", {"success": True}, "saved"),
        ("ok", {"success": False}, "not_saved"),
        ("error", "boom", "unknown"),
        ("cancelled", "x", "unknown"),
        ("blocked", "x", "not_saved"),
        ("ok", {"success": True, "staged": True}, "unknown"),
    ],
)
def test_host_outcome(status, result, want):
    assert staging.host_outcome(status, result)["result"] == want


def test_plugin_exports_the_staging_module():
    assert plugin.staging is staging
