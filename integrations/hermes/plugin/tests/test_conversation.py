"""The conversation a background save is judged against: what the plugin keeps, and what a save carries."""

import json

import pytest

from plugin import conversation
from plugin.intent import conversation_sender_of
from plugin.redact import Redactor

SID = {"session_id": "S1", "task_id": "S1"}
SECRET = "ghp_" + "b" * 36
OWNER_DM = {"relation": "owner", "basis": ["host_allowlist_dm"]}
NO_SENDER = {"relation": "unknown", "basis": ["none"]}


@pytest.fixture
def h(loop_h, monkeypatch):
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", "u-owner")
    loop_h.prov["origin"] = "assistant_tool"
    return loop_h


def user(h, turn_id, text, platform="telegram", sender="u-owner"):
    h.ctx.hooks["pre_llm_call"](
        turn_id=turn_id, user_message=text, platform=platform, sender_id=sender, **SID
    )


def api(h, turn_id, text, calls=()):
    h.ctx.hooks["post_api_request"](
        turn_id=turn_id,
        response={
            "assistant_message": {
                "content": text,
                "tool_calls": [
                    {"id": cid, "function": {"name": tool, "arguments": json.dumps(args)}}
                    for cid, tool, args in calls
                ],
            }
        },
        **SID,
    )


def tool(h, turn_id, cid, name, args, result):
    out = h.ctx.hooks["pre_tool_call"](
        tool_name=name, args=args, tool_call_id=cid, turn_id=turn_id, **SID
    )
    h.ctx.hooks["post_tool_call"](
        tool_name=name,
        args=args,
        result=result,
        tool_call_id=cid,
        status="ok",
        turn_id=turn_id,
        **SID,
    )
    return out


def log(h):
    path = h.dir / "sentrook" / "conversations" / "S1.json"
    return json.loads(path.read_text())["entries"] if path.exists() else []


def dm(h):
    h.facts = {"platform": "telegram", "chat_type": "dm", "user_id": "u-owner"}


def save(h, tool_name="memory", args=None):
    """The review fork: no pre_llm_call, its own turn, write origin background_review."""
    h.prov["origin"] = "background_review"
    args = args or {"action": "add", "target": "memory", "content": "Keeps notes tidy."}
    api(h, "t-review", "Saving what I learned.", [("c-save", tool_name, args)])
    h.ctx.hooks["pre_tool_call"](
        tool_name=tool_name, args=args, tool_call_id="c-save", turn_id="t-review", **SID
    )
    return h.scans[-1]


# ---- capture ---------------------------------------------------------------------------------------------


def test_user_assistant_and_tool_entries_are_recorded_with_roles_turns_and_senders(h):
    dm(h)
    user(h, "t1", "please tidy the notes folder")
    api(h, "t1", "Listing first.", [("c1", "terminal", {"command": "ls notes"})])
    tool(h, "t1", "c1", "terminal", {"command": "ls notes"}, "a.txt\nb.txt")
    api(h, "t1", "Done, tidied.")
    user(h, "t2", "thanks")  # a turn without tool calls still has its own number
    api(h, "t2", "You're welcome.")
    user(h, "t3", "what is in a.txt?")
    api(h, "t3", "", [("c2", "read_file", {"path": "notes/a.txt"})])  # no text: no entry
    tool(h, "t3", "c2", "read_file", {"path": "notes/a.txt"}, "shopping list")

    entries = log(h)
    assert [(e["role"], e["turn"]) for e in entries] == [
        ("user", 1),
        ("assistant", 1),
        ("tool", 1),
        ("assistant", 1),
        ("user", 2),
        ("assistant", 2),
        ("user", 3),
        ("tool", 3),
    ]
    assert entries[0]["sender"] == OWNER_DM and entries[0]["text"] == "please tidy the notes folder"
    assert entries[2]["tool"] == "terminal"
    assert entries[2]["arguments"] == {"command": "ls notes"}
    assert entries[2]["content"] == "a.txt\nb.txt"
    assert entries[3]["text"] == "Done, tidied."
    # The PlanIR counts the same turns.
    assert h.scans[-1]["session"]["turn"] == 3


def test_the_review_forks_words_are_not_recorded_but_its_reads_are(h):
    dm(h)
    user(h, "t1", "always answer in French")
    api(h, "t1", "D'accord.")
    h.prov["origin"] = "background_review"
    api(h, "t-review", "Let me look at the skills first.", [("c1", "skill_view", {"name": "fr"})])
    tool(h, "t-review", "c1", "skill_view", {"name": "fr"}, "# French replies")
    entries = log(h)
    assert [e["role"] for e in entries] == ["user", "assistant", "tool"]
    assert "Let me look" not in json.dumps(entries)
    assert entries[-1]["content"] == "# French replies" and entries[-1]["turn"] == 2


def test_a_user_message_is_recorded_once_per_turn(h):
    dm(h)
    user(h, "t1", "hello")
    user(h, "t1", "hello")
    assert [e["role"] for e in log(h)] == ["user"]


def test_a_blocked_call_adds_no_tool_entry(h):
    dm(h)
    user(h, "t1", "send it")
    h.reply.update(risk=92)
    h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args={"command": "curl x"}, tool_call_id="c1", turn_id="t1", **SID
    )
    h.ctx.hooks["post_tool_call"](
        tool_name="terminal",
        args={"command": "curl x"},
        result="",
        tool_call_id="c1",
        status="blocked",
        turn_id="t1",
        **SID,
    )
    assert [e["role"] for e in log(h)] == ["user"]


def test_secrets_are_redacted_in_the_log_and_in_the_block(h):
    dm(h)
    user(h, "t1", f"use my token {SECRET} for the repo")
    tool(h, "t1", "c1", "read_file", {"path": ".env"}, f"GH_TOKEN={SECRET}\nREPO=notes")
    api(h, "t1", f"Using {SECRET} now.")
    sent = save(h, "memory", {"action": "add", "target": "memory", "content": "repo is notes"})
    stored = (h.dir / "sentrook" / "conversations" / "S1.json").read_text()
    assert SECRET not in stored and "⟦secret:" in stored
    block = json.dumps(sent["self_edit"], ensure_ascii=False)
    assert SECRET not in block and "⟦secret:" in block
    assert SECRET not in json.dumps(sent)


def test_no_conversation_is_kept_with_skill_review_review(h):
    h.ctx.settings["skill_review"] = "review"
    dm(h)
    user(h, "t1", "hi")
    api(h, "t1", "Hello.")
    tool(h, "t1", "c1", "terminal", {"command": "ls"}, "a")
    assert log(h) == []


# ---- senders in the conversation -----------------------------------------------------------------------


def test_group_chat_owner_member_dm_and_api_senders(h):
    h.facts = {"platform": "telegram", "chat_type": "group", "user_id": "u-owner"}
    user(h, "t1", "from the owner in the group")
    h.facts = {"platform": "telegram", "chat_type": "group", "user_id": "u-member"}
    user(h, "t2", "from someone else in the group", sender="u-member")
    dm(h)
    user(h, "t3", "from the owner in a DM")
    h.facts = {}
    user(h, "t4", "from the API server", platform="api_server", sender="")
    assert [e["sender"] for e in log(h)] == [
        {"relation": "owner", "basis": ["group_chat"]},
        {"relation": "other", "basis": ["group_chat"]},
        OWNER_DM,
        NO_SENDER,
    ]
    # The trigger mapping is unchanged: every group message is "other".
    h.facts = {"platform": "telegram", "chat_type": "group", "user_id": "u-owner"}
    user(h, "t5", "owner again in the group")
    h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args={"command": "ls"}, tool_call_id="c1", turn_id="t5", **SID
    )
    assert h.scans[-1]["trigger"]["sender"] == {"relation": "other", "basis": ["group_chat"]}


@pytest.mark.parametrize(
    ("platform", "facts", "env", "want"),
    [
        (
            "telegram",
            {"chat_type": "group", "user_id": "u1"},
            {"TELEGRAM_ALLOWED_USERS": "u1"},
            {"relation": "owner", "basis": ["group_chat"]},
        ),
        (
            "slack",
            {"chat_type": "channel", "user_id": "u1"},
            {"GATEWAY_ALLOWED_USERS": "u0,u1"},
            {"relation": "owner", "basis": ["group_chat"]},
        ),
        (
            "telegram",
            {"chat_type": "group", "user_id": "u2"},
            {"TELEGRAM_ALLOWED_USERS": "u1"},
            {"relation": "other", "basis": ["group_chat"]},
        ),
        (
            "telegram",
            {"chat_type": "dm", "user_id": "u1"},
            {"TELEGRAM_ALLOWED_USERS": "u1"},
            OWNER_DM,
        ),
        (
            "telegram",
            {"chat_type": "dm", "user_id": "u2"},
            {"TELEGRAM_ALLOWED_USERS": "u1"},
            {"relation": "other", "basis": ["host_open_access"]},
        ),
        ("cli", {}, {}, OWNER_DM),
        ("api_server", {}, {}, NO_SENDER),
        ("webhook", {}, {}, NO_SENDER),
        ("cron", {}, {}, NO_SENDER),
    ],
)
def test_conversation_sender(platform, facts, env, want):
    assert conversation_sender_of(platform, facts, None, env) == want


# ---- rolling caps ----------------------------------------------------------------------------------------


R = Redactor("standard", "salt")


def test_the_log_keeps_at_most_200_entries():
    entries = []
    for i in range(250):
        entries = conversation.append(
            conversation.user_entry(i + 1, NO_SENDER, f"m{i}", R, f"t{i}")
        )(entries)
    assert len(entries) == 200 and entries[0]["text"] == "m50" and entries[-1]["text"] == "m249"


def test_the_log_drops_the_oldest_tool_contents_first_then_the_oldest_entries():
    big = "x" * 15_000
    entries = [conversation.user_entry(1, NO_SENDER, "first", R, "t1")]
    for i in range(40):
        entries = conversation.append(conversation.tool_entry(1, "read_file", {"n": i}, big, R))(
            entries
        )
    size = len(json.dumps(entries, ensure_ascii=False).encode())
    assert size <= conversation.LOG_MAX_BYTES
    assert entries[0]["text"] == "first"  # nothing dropped yet: only old tool contents emptied
    assert len(entries) == 41
    emptied = [e["arguments"]["n"] for e in entries[1:] if e["content"] == ""]
    assert emptied == list(range(len(emptied))) and 0 < len(emptied) < 40

    # Messages alone over the cap: the oldest entries go.
    many = []
    for i in range(60):
        many = conversation.append(conversation.user_entry(i, NO_SENDER, "y" * 10_000, R, f"u{i}"))(
            many
        )
    assert len(json.dumps(many).encode()) <= conversation.LOG_MAX_BYTES
    assert many[-1]["_turn_id"] == "u59" and many[0]["_turn_id"] != "u0"


def test_stored_text_and_arguments_are_capped():
    t = conversation.tool_entry(1, "read_file", {"path": "p" * 5000}, "z" * 100_000, R)
    assert len(t["content"].encode()) <= conversation.STORE_TEXT_CAP
    assert t["chars"] == 100_000
    assert len(json.dumps(t["arguments"]).encode()) <= conversation.ARGS_CAP_BYTES + 200
    u = conversation.user_entry(1, NO_SENDER, "q" * 50_000, R)
    assert len(u["text"]) == conversation.STORE_TEXT_CAP and u["chars"] == 50_000


# ---- selection -------------------------------------------------------------------------------------------


def U(turn, text):
    return {"role": "user", "turn": turn, "sender": OWNER_DM, "text": text, "chars": len(text)}


def A(turn, text):
    return {"role": "assistant", "turn": turn, "text": text, "chars": len(text)}


def T(turn, content, name="read_file"):
    return {
        "role": "tool",
        "turn": turn,
        "tool": name,
        "arguments": {"n": turn},
        "content": content,
        "chars": len(content),
    }


def filler(n, word="lorem"):
    return " ".join(f"{word}{i % 50}" for i in range(n))[: n * 6]


def test_every_user_entry_is_kept_and_capped():
    entries = [U(1, "short"), A(1, "ok"), U(2, "u" * 2500)]
    out = conversation.select(entries, {"content": "nothing"})
    assert [e["role"] for e in out] == ["user", "assistant", "user"]
    assert out[0] == {"role": "user", "turn": 1, "sender": OWNER_DM, "text": "short"}
    assert len(out[2]["text"]) == 2000 and out[2]["truncated"] is True
    many = [U(i, f"m{i}") for i in range(40)]
    out = conversation.select(many, {})
    assert [e["text"] for e in out] == [f"m{i}" for i in range(10, 40)]


def test_assistant_entries_are_the_20_latest_and_capped():
    entries = [A(i, f"a{i}") for i in range(25)] + [A(26, "w" * 1600)]
    out = conversation.select(entries, {})
    assert [e["text"][:3] for e in out] == [f"a{i}" for i in range(6, 25)] + ["www"]
    assert len(out[-1]["text"]) == 1500 and out[-1]["truncated"] is True
    assert "truncated" not in out[0]


def test_tool_entries_ranked_by_overlap_windowed_plus_the_latest_kept_in_order():
    recipe = "grandmother's cardamom bun recipe uses saffron.threads and orange@zest"
    hidden = filler(800) + " " + recipe + " " + filler(800, "ipsum")
    entries = [U(1, "remember my bun recipe")]
    for i in range(20):
        entries.append(T(2, filler(300, f"noise{i}x")))
    entries.insert(5, T(2, hidden, "web_extract"))
    entries.append(A(3, "Noted."))
    args = {"action": "add", "content": "Bun recipe: cardamom, saffron.threads, orange@zest"}
    out = conversation.select(entries, args)

    picked = [e for e in out if e["role"] == "tool"]
    # The overlapping result, then the 4 latest; nothing else overlaps.
    assert [e["tool"] for e in picked] == ["web_extract"] + ["read_file"] * 4
    best = picked[0]
    assert all(w in best["content"] for w in ("cardamom", "saffron.threads", "orange@zest"))
    assert len(best["content"]) == 1500 and best["excerpt_of_chars"] == len(hidden)
    # Conversation order is kept: user first, assistant last, tools between.
    assert out[0]["role"] == "user" and out[-1]["role"] == "assistant"
    latest = [e["content"] for e in entries if e["role"] == "tool"][-4:]
    assert [e["content"] for e in picked[1:]] == [c[:1500] for c in latest]
    assert all("chars" not in e and "_turn_id" not in e for e in out)


def test_the_10_best_overlapping_tools_are_chosen_from_operations_too():
    entries = [T(1, f"unrelated words here {i}") for i in range(10)]
    entries += [T(2, f"overlap{i} common.term") for i in range(15)]
    entries += [T(3, f"tail words only {i}") for i in range(4)]
    args = {
        "action": "edit",
        "operations": [{"new_string": " ".join(f"overlap{i}" for i in range(15)) + " common.term"}],
    }
    out = conversation.select(entries, args)
    contents = [e["content"] for e in out]
    assert sum(c.startswith("overlap") for c in contents) == 10
    assert sum(c.startswith("tail") for c in contents) == 4
    assert not any(c.startswith("unrelated") for c in contents)
    # Later results win a tie.
    assert "overlap14 common.term" in contents and "overlap0 common.term" not in contents


@pytest.mark.parametrize(
    "args",
    [
        {"content": "alpha.beta gamma"},
        {"file_content": "alpha.beta gamma"},
        {"new_string": "alpha.beta gamma"},
        {"operations": [{"content": "alpha.beta gamma"}]},
    ],
)
def test_save_text_reads_each_written_field(args):
    assert "alpha.beta" in conversation.save_text(args)
    assert conversation.save_text({"action": "delete", "name": "alpha.beta"}) == ""


def test_the_budget_drops_old_assistant_and_tool_entries_before_users():
    entries = []
    for i in range(20):
        entries += [U(i, f"user{i} " + "u" * 1500), A(i, "a" * 1500), T(i, "t" * 1500)]
    out = conversation.select(entries, {"content": "x"})
    assert len(json.dumps(out, ensure_ascii=False).encode()) <= conversation.BLOCK_BUDGET
    assert sum(e["role"] == "user" for e in out) == 20
    kept = [e for e in out if e["role"] != "user"]
    assert kept and all(e["turn"] >= 10 for e in kept)
    turns = [e["turn"] for e in out]
    assert turns == sorted(turns)


def test_users_are_dropped_only_when_still_over():
    entries = [U(i, "u" * 2000) for i in range(30)] + [A(31, "a")]
    out = conversation.select(entries, {})
    assert all(e["role"] == "user" for e in out)
    assert len(json.dumps(out).encode()) <= conversation.BLOCK_BUDGET
    assert out[-1]["turn"] == 29 and out[0]["turn"] > 0


# ---- the block on a save ---------------------------------------------------------------------------------


def test_a_loop_save_carries_the_selected_conversation(h):
    dm(h)
    user(h, "t1", "my dentist is Dr Hale on Fridays")
    api(h, "t1", "Noted.")
    sent = save(
        h, "memory", {"action": "add", "target": "memory", "content": "Dentist Dr Hale, Fridays"}
    )
    assert sent["trigger"]["kind"] == "system"
    block = sent["self_edit"]
    assert block["kind"] == "background_review" and block["store"] == "memory"
    assert block["conversation"] == [
        {"role": "user", "turn": 1, "sender": OWNER_DM, "text": "my dentist is Dr Hale on Fridays"},
        {"role": "assistant", "turn": 1, "text": "Noted."},
    ]
    # The review fork's narration before the save is not part of it.
    assert "Saving what I learned" not in json.dumps(block)


def test_a_skill_save_says_skills(h):
    dm(h)
    user(h, "t1", "tidy")
    sent = save(h, "skill_manage", {"action": "create", "name": "tidy", "content": "# Tidy"})
    assert sent["self_edit"]["store"] == "skills"


def test_a_broken_log_never_breaks_the_scan_or_the_buffer(h, monkeypatch):
    from plugin.store import Store

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(Store, "update_conversation", boom)
    dm(h)
    user(h, "t1", "hi")
    tool(h, "t1", "c1", "terminal", {"command": "ls"}, "a.txt")
    h.ctx.hooks["pre_tool_call"](
        tool_name="terminal", args={"command": "ls"}, tool_call_id="c2", turn_id="t1", **SID
    )
    assert h.scans[-1]["new_inputs"][0]["content"] == "a.txt"

    monkeypatch.setattr(conversation, "select", boom)
    sent = save(h)
    assert sent["self_edit"] == {"kind": "background_review", "store": "memory", "conversation": []}
    assert sent["trigger"]["kind"] == "system"


# ---- the curator --------------------------------------------------------------------------------------


def test_the_curators_own_prompt_is_not_a_user_message(h):
    """The curator is a fresh agent whose pre_llm_call fires with its curation prompt, in a context that
    can still hold the owner's chat: it is not recorded, and never as the owner."""
    dm(h)
    user(h, "t1", "keep replies short")
    h.prov["origin"] = "background_review"
    user(h, "t-curator", "Review the skill library and consolidate overlapping skills.")
    assert [e["text"] for e in log(h) if e["role"] == "user"] == ["keep replies short"]
    sent = save(h, "skill_manage", {"action": "edit", "name": "tidy", "content": "# Tidy"})
    texts = [e.get("text") for e in sent["self_edit"]["conversation"]]
    assert "Review the skill library" not in json.dumps(texts)
    owner = [e for e in sent["self_edit"]["conversation"] if e.get("sender") == OWNER_DM]
    assert [e["text"] for e in owner] == ["keep replies short"]


def test_no_sender_is_the_owner_during_the_background_review(h, monkeypatch):
    env = {"TELEGRAM_ALLOWED_USERS": "u1"}
    facts = {"chat_type": "dm", "user_id": "u1"}
    assert conversation_sender_of("telegram", facts, "u1", env) == OWNER_DM
    h.prov["origin"] = "background_review"
    assert conversation_sender_of("telegram", facts, "u1", env) == NO_SENDER
    assert conversation_sender_of("cli", {}, None, {}) == NO_SENDER
    group = {"chat_type": "group", "user_id": "u1"}
    assert conversation_sender_of("telegram", group, "u1", env)["relation"] != "owner"


# ---- retention ------------------------------------------------------------------------------------------

DAY = 86_400


def conv_dir(h):
    return h.dir / "sentrook" / "conversations"


def old_logs(h, n, age_days, prefix="old"):
    import os
    import time

    d = conv_dir(h)
    d.mkdir(parents=True, exist_ok=True)
    now = time.time()
    paths = []
    for i in range(n):
        p = d / f"{prefix}{i}.json"
        p.write_text('{"version": 1, "entries": []}')
        t = now - age_days * DAY - i
        os.utime(p, (t, t))
        paths.append(p)
    return paths


def test_logs_older_than_7_days_are_deleted_when_a_log_is_written(h):
    stale = old_logs(h, 3, 8, "stale")
    fresh = old_logs(h, 3, 6, "fresh")
    dm(h)
    user(h, "t1", "hi")
    assert not any(p.exists() for p in stale)
    assert all(p.exists() for p in fresh) and (conv_dir(h) / "S1.json").exists()


def test_at_most_100_logs_are_kept_the_most_recent(h):
    many = old_logs(h, 120, 1)  # many[0] is the newest
    dm(h)
    user(h, "t1", "hi")
    left = sorted(p.name for p in conv_dir(h).iterdir() if p.suffix == ".json")
    assert len(left) == 100 and "S1.json" in left
    assert all(p.exists() for p in many[:99]) and not any(p.exists() for p in many[99:])


def test_pruning_runs_at_most_once_an_hour_per_process(h, monkeypatch):
    import time

    from plugin import store as store_mod

    dm(h)
    user(h, "t1", "hi")
    stale = old_logs(h, 2, 8, "late")
    user(h, "t2", "again")
    assert all(p.exists() for p in stale)  # within the hour: not pruned again
    real = time.time
    monkeypatch.setattr(store_mod.time, "time", lambda: real() + 3601)
    user(h, "t3", "later")
    assert not any(p.exists() for p in stale)


def test_skill_review_review_deletes_the_logs_and_records_nothing(h):
    dm(h)
    user(h, "t1", "hi")
    old_logs(h, 2, 1, "other")
    assert conv_dir(h).exists()
    h.ctx.settings["skill_review"] = "review"  # changed at runtime: the next hook deletes them
    api(h, "t1", "Hello.")
    assert not conv_dir(h).exists()
    user(h, "t2", "more")
    tool(h, "t2", "c1", "terminal", {"command": "ls"}, "a")
    assert not conv_dir(h).exists()


@pytest.mark.parametrize(
    "hook", ["pre_llm_call", "post_api_request", "pre_tool_call", "post_tool_call"]
)
def test_every_hook_deletes_the_logs_once_the_setting_is_review(h, hook):
    old_logs(h, 1, 1)
    h.ctx.settings["skill_review"] = "review"
    kw = {"turn_id": "t1", **SID}
    if hook == "pre_llm_call":
        h.ctx.hooks[hook](user_message="x", platform="telegram", **kw)
    elif hook == "post_api_request":
        h.ctx.hooks[hook](response={"assistant_message": {"content": "x"}}, **kw)
    elif hook == "pre_tool_call":
        h.ctx.hooks[hook](tool_name="terminal", args={"command": "ls"}, tool_call_id="c1", **kw)
    else:
        h.ctx.hooks[hook](tool_name="terminal", args={}, result="x", tool_call_id="c9", **kw)
    assert not conv_dir(h).exists()


def test_register_with_review_deletes_the_logs(h):
    import plugin

    old_logs(h, 2, 1)
    h.ctx.settings["skill_review"] = False
    plugin.register(h.ctx)
    assert not conv_dir(h).exists()
