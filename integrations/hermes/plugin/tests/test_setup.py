"""The owner's setup screen (`/sentrook setup`): items from config, reviews the owner approved and the agent's
proposals, described in the plugin's words; `apply` sets them only with the screen's code.

The rules, the screen and what applying does are shared with the OpenClaw plugin's tests (`integrations/fixtures/setup`).
"""

import json
import re
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from plugin import commands, setup
from plugin.config import resolve_config
from plugin.store import Store, read_time

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "setup"
RULES = json.loads((FIXTURES / "rules.json").read_text())
SCENARIO = FIXTURES / "scenario"
META = json.loads((SCENARIO / "scenario.json").read_text())
NOW = datetime.fromisoformat(META["now"].replace("Z", "+00:00"))
CMD = "/sentrook {}".format
WHO = {"basis": ["local_terminal"], "platform": "", "sender_ref": None}
HOST = {
    "{setup}": "/sentrook setup",
    "{revoke}": "/sentrook revoke",
    "{bind}": "/sentrook bind",
    "{grants}": "/sentrook grants",
}


def host_text(text: str) -> str:
    for k, v in HOST.items():
        text = text.replace(k, v)
    return text


def no_ids(text: str) -> str:
    return re.sub(r"gr-[0-9a-f]{6}", "gr-??????", text)


# ---- the rules --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("platform", "to", "pattern"), RULES["delivery"])
def test_a_cron_jobs_delivery_to_a_room_is_a_channel_binding(platform, to, pattern, tmp_path):
    assert setup.room_pattern(platform, to) == pattern
    (tmp_path / "cron").mkdir()
    (tmp_path / "cron" / "jobs.json").write_text(
        json.dumps({"jobs": [{"id": "j1", "deliver": f"origin,{platform}:{to}"}]})
    )
    assert setup.cron_targets(tmp_path) == ([("j1", pattern)] if pattern else [])


def test_a_hermes_job_delivers_to_each_room_it_names_and_nothing_the_host_picks(tmp_path):
    (tmp_path / "cron").mkdir()
    jobs = [
        {"id": "a", "deliver": ["discord:#one", "slack:#two"]},
        {"id": "b", "deliver": "local"},
        {"id": "c", "deliver": "all,telegram,bot-chat,room:abc"},
        {"id": "d", "enabled": False, "deliver": "discord:#off"},
        {"id": "", "deliver": "discord:#no-id"},
    ]
    (tmp_path / "cron" / "jobs.json").write_text(json.dumps({"jobs": jobs}))
    assert setup.cron_targets(tmp_path) == [("a", "discord:#one"), ("a", "slack:#two")]
    (tmp_path / "cron" / "jobs.json").write_text("not json")
    assert setup.cron_targets(tmp_path) == []
    assert setup.cron_targets(tmp_path / "missing") == []


@pytest.mark.parametrize(
    "case", RULES["covers"], ids=lambda c: f"{c['existing']['pattern']}>{c['candidate']['pattern']}"
)
def test_a_grant_in_force_covers_an_item(case):
    assert setup.covers(case["existing"], case["candidate"]) is case["covers"]


@pytest.mark.parametrize("case", RULES["warnings"], ids=lambda c: c["item"]["pattern"])
def test_an_item_warns_from_its_own_kind_pattern_and_allows(case):
    item = {**case["item"], "binding": case.get("binding", False)}
    assert setup.item_warnings(item) == case["warnings"]


@pytest.mark.parametrize(("host", "domain"), RULES["registrable"])
def test_the_registrable_domain_is_shown_in_ascii(host, domain):
    assert setup.registrable(host) == domain


@pytest.mark.parametrize("case", RULES["describe"], ids=lambda c: c["text"][:40])
def test_each_item_is_described_in_the_plugins_words(case):
    item = {**case["item"], "binding": case.get("binding", False)}
    assert setup.describe(item, case["minutes"]) == case["text"]


@pytest.mark.parametrize(("now", "last", "text"), RULES["last"])
def test_the_last_approved_review_is_counted_in_days(now, last, text):
    read = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))  # noqa: E731
    assert setup.last_text(read(now), read(last)) == text


@pytest.mark.parametrize(("reason", "line"), RULES["notes"])
def test_the_agents_note_turns_no_link_mention_or_emphasis_on(reason, line):
    assert setup.note_line(reason) == line


def test_text_from_config_can_never_end_its_code_span_or_add_lines(scene):
    """An MCP server entry the agent wrote with a newline, a backtick or a space is left out and counted."""
    screen = scene["run"]("")
    assert "99." not in screen and "apply 0000" not in screen and "ex ample" not in screen
    assert "From your config: 3 items could not be read and are left out." in screen
    for line in screen.splitlines():
        assert line.count("`") % 2 == 0, line


def test_a_covering_grants_id_is_neutralised(scene):
    raw = json.loads((scene["state"] / "grants.json").read_text())
    raw["grants"][0]["id"] = "[gr](https://evil.example) @here"
    (scene["state"] / "grants.json").write_text(json.dumps(raw))
    screen = scene["run"]("")
    assert "Warning: a grant in force already covers this (`grhttps://evil.examp`)." in screen


def test_a_proposal_dated_in_the_future_is_not_live(scene):
    ids = [p["id"] for p in setup.load_proposals(scene["state"], NOW)]
    assert "p-f00000" not in ids
    assert "future.example.com" not in scene["run"]("")


@pytest.mark.parametrize("case", RULES["exposure"])
def test_exposure_flagged_by_the_scanner(case):
    assert setup.exposure_flagged(case["response"]) is case["flagged"]


# ---- the scenario -----------------------------------------------------------------------------------------------


@pytest.fixture
def scene(tmp_path):
    """The scenario's files in a Hermes home, and a runner for the setup command at a given time."""
    home = tmp_path / "home"
    state = home / "sentrook"
    state.mkdir(parents=True)
    (home / "cron").mkdir()
    shutil.copy(SCENARIO / "hermes-jobs.json", home / "cron" / "jobs.json")
    for name in ("grants.json", "proposals.json", "traffic.jsonl"):
        shutil.copy(SCENARIO / name, state / name)
    host_cfg = {"mcp_servers": json.loads((SCENARIO / "mcp-servers.json").read_text())}
    records = []

    def cfg(log=True):
        return resolve_config(
            {"review_at": META["review_at"], "traffic_log": {"enabled": log}},
            {"HOME": str(tmp_path), "HERMES_HOME": str(home)},
        )

    def run(args, minutes=0, log=True):
        return setup.run(
            cfg(log),
            args,
            WHO,
            NOW + timedelta(minutes=minutes),
            CMD,
            records.append,
            home=home,
            host_cfg=host_cfg,
            code=lambda: META["code"],
        )

    return {"run": run, "state": state, "records": records, "home": home}


def test_the_screen_lists_config_approved_reviews_and_proposals(scene):
    assert scene["run"]("") == host_text((SCENARIO / "screen.txt").read_text().rstrip("\n"))


def test_with_the_log_off_there_is_no_evidence(scene):
    assert scene["run"]("", log=False) == host_text(
        (SCENARIO / "screen-log-off.txt").read_text().rstrip("\n")
    )


def _grants_and_bindings(state):
    return json.loads((state / "grants.json").read_text())


def _projection(entry):
    keep = ("kind", "pattern", "allows", "scope", "expires_at", "source")
    return {k: entry[k] for k in keep if k in entry}


@pytest.mark.parametrize(
    "case", json.loads((SCENARIO / "apply.json").read_text())["cases"], ids=lambda c: c["name"]
)
def test_apply_and_discard(scene, case):
    before = json.loads((SCENARIO / "grants.json").read_text())
    scene["run"]("")
    for step in case["steps"]:
        reply = scene["run"](step["args"], minutes=step.get("minutes_later", 0))
        if "items" in step:
            n = step["items"]
            assert reply.startswith(f"Sentrook setup: {n} item{'' if n == 1 else 's'}."), reply
        else:
            assert no_ids(reply) == host_text(step["reply"])
    after = _grants_and_bindings(scene["state"])
    old_ids = {g["id"] for g in before["grants"]}
    added = [g for g in after["grants"] if g["id"] not in old_ids]
    assert [_projection(g) for g in added] == case["grants_added"]
    for g in added:
        assert g["set_by"] == WHO
        assert NOW <= read_time(g["granted_at"]) <= NOW + timedelta(minutes=15)
        assert re.fullmatch(r"gr-[0-9a-f]{6}", g["id"])
    new_bindings = after["bindings"][len(before["bindings"]) :]
    assert [{"pattern": b["pattern"], "source": b["source"]} for b in new_bindings] == case[
        "bindings_added"
    ]
    for b in new_bindings:
        assert b["set_by"] == WHO
    live = setup._live_proposals(Store(scene["state"]).load_proposals(), NOW)
    assert {p["id"]: len(p["items"]) for p in live} == case["proposals_left"]


def test_applied_grants_are_persistent_and_listed_by_grants(scene):
    scene["run"]("")
    scene["run"]("apply 4821 3,4")
    cfg = resolve_config({}, {"HERMES_HOME": str(scene["home"])})
    listing = commands.grants.format_grants(
        cfg, commands.grants.load(cfg.state_dir), NOW, CMD, None
    )
    assert re.search(r"gr-[0-9a-f]{6}\s+destination\s+persistent\s+api\.example\.com", listing)
    assert re.search(r"gr-[0-9a-f]{6}\s+destination\s+persistent\s+files\.example\.org", listing)


def test_applying_the_same_item_twice_changes_nothing(scene):
    scene["run"]("")
    scene["run"]("apply 4821 1,3")
    first = (scene["state"] / "grants.json").read_text()
    # The same screen again (the same items), applied again with its new code.
    screen = scene["run"]("")
    assert "`discord:#daily-brief`" not in screen and "`api.example.com`" not in screen
    kept = Store(scene["state"]).load_setup()
    kept["items"] = [
        {
            "binding": True,
            "kind": "destination",
            "pattern": "discord:#daily-brief",
            "allows": None,
            "minutes": None,
            "tags": ["config"],
            "proposals": [],
        },
        {
            "binding": False,
            "kind": "destination",
            "pattern": "api.example.com",
            "allows": None,
            "minutes": None,
            "tags": ["reviews"],
            "proposals": [],
        },
    ]
    Store(scene["state"]).save_setup(kept)
    reply = scene["run"]("apply 4821")
    assert "1. Already set: channel `discord:#daily-brief`." in reply
    assert re.search(
        r"2\. Already set: destination `api\.example\.com` \(gr-[0-9a-f]{6}\)\.", reply
    )
    assert (scene["state"] / "grants.json").read_text() == first


def test_apply_writes_each_change_and_the_apply_to_the_traffic_log(scene):
    scene["run"]("")
    scene["run"]("apply 4821 1,3")
    kinds = [(r["kind"], r.get("op")) for r in scene["records"]]
    assert kinds == [("grants", "bind_add"), ("grants", "grant"), ("setup", "apply")]
    assert all(r["by"] == WHO for r in scene["records"])
    assert scene["records"][-1]["items"] == [1, 3]


def test_nine_unapproved_reviews_give_no_evidence(scene):
    """The agent cannot manufacture evidence: reviews nobody approved, or approved outside the owner's own
    message, or in a chat where the scanner flagged exposure, count for nothing."""
    cfg = resolve_config({"review_at": META["review_at"]}, {"HERMES_HOME": str(scene["home"])})
    ev = setup.read_evidence(cfg.traffic_log_path, cfg.review_at, NOW)
    counted = {e["grant"]["pattern"]: e["count"] for e in ev.approved.values()}
    assert counted == {"api.example.com": 3, "files.example.org": 2}
    assert ev.exposed == {"s_0000000000a4"}
    assert [e["grant"]["pattern"] for e in setup.approved_suggestions(ev)] == [
        "api.example.com",
        "files.example.org",
    ]


def test_a_broader_pattern_never_inherits_the_count(scene):
    cfg = resolve_config({"review_at": META["review_at"]}, {"HERMES_HOME": str(scene["home"])})
    ev = setup.read_evidence(cfg.traffic_log_path, cfg.review_at, NOW)
    assert ev.backing({"kind": "destination", "pattern": "files.example.org"})["count"] == 2
    assert ev.backing({"kind": "destination", "pattern": "*.example.org"}) is None
    assert ev.backing({"kind": "destination", "pattern": "*.example.com"}) is None


def test_no_attended_item_ever_appears(scene):
    screen = scene["run"]("")
    assert "attended" not in screen.lower() and "telegram" not in screen.lower()


def test_nothing_to_set_up(tmp_path):
    cfg = resolve_config({}, {"HERMES_HOME": str(tmp_path)})
    reply = setup.run(cfg, "", WHO, NOW, CMD, lambda r: None, home=tmp_path, host_cfg={})
    assert reply == "Sentrook setup: nothing to set up right now."
    assert Store(cfg.state_dir).load_setup()["code"] is None
    assert setup.run(
        cfg, "apply 0000", WHO, NOW, CMD, lambda r: None, home=tmp_path, host_cfg={}
    ).startswith("That is not the code on the setup screen")


def test_each_screen_has_a_new_code(scene, tmp_path):
    cfg = resolve_config({}, {"HERMES_HOME": str(scene["home"])})
    codes = set()
    for _ in range(5):
        reply = setup.run(cfg, "", WHO, NOW, CMD, lambda r: None, home=scene["home"], host_cfg={})
        codes.add(re.search(r"apply ([0-9]{4})\n", reply)[1])
        assert Store(cfg.state_dir).load_setup()["code"] in codes
    assert len(codes) > 1


def test_an_unreadable_proposals_file_is_said(scene):
    (scene["state"] / "proposals.json").write_text("[1, 2")
    screen = scene["run"]("")
    assert "The agent's proposals could not be read, so none are shown." in screen
    assert "p-a1b2c3" not in screen


def test_a_proposal_lasts_a_day_at_most(scene):
    raw = json.loads((scene["state"] / "proposals.json").read_text())
    for p in raw["proposals"]:
        p["expires_at"] = "2027-01-01T00:00:00Z"
    (scene["state"] / "proposals.json").write_text(json.dumps(raw))
    later = NOW + timedelta(hours=22, minutes=30)
    ids = [p["id"] for p in setup.load_proposals(scene["state"], later)]
    assert ids == ["p-d4e5f6"]


# ---- the command --------------------------------------------------------------------------------------------------


def test_setup_is_an_owner_command_on_chat_and_command_line(scene, monkeypatch):
    assert commands.COMMANDS["setup"].owner_only and commands.COMMANDS["setup"].cli_rest
    assert commands.dispatch("setup", {}).startswith("Only the owner can run /sentrook setup")
    assert commands.dispatch("setup apply 4821", {}).startswith(
        "Only the owner can run /sentrook setup"
    )
    monkeypatch.setattr(commands, "hermes_config", lambda: {})
    env = {"HERMES_HOME": str(scene["home"]), "HOME": str(scene["home"])}
    gate = lambda verb, fn, **_kw: lambda raw: fn(raw, WHO)  # noqa: E731
    reply = commands.dispatch("setup", {"review_at": 45}, env, gate=gate)
    assert reply.startswith("Sentrook setup: ")
    code = re.search(r"/sentrook setup apply ([0-9]{4})\n", reply)[1]
    reply = commands.dispatch(f"setup apply {code} 1", {"review_at": 45}, env, gate=gate)
    assert (
        reply.splitlines()[1]
        == "1. Channel binding added: `discord:#daily-brief` (until you remove it)."
    )
