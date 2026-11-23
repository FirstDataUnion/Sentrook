"""The read-only dashboard: the model built from the traffic log, and the Hermes dashboard tab's backend."""

import asyncio
import importlib.util
import json
import shutil
import sys
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest

from plugin import SETTINGS_KEYS, dashboard
from plugin.config import resolve_config

PLUGIN = Path(__file__).resolve().parents[1]
#: Shared with the OpenClaw plugin's tests: both plugins build the same model for the same log.
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "traffic-log"
DASH = FIXTURES / "dashboard"
#: Strings that appear only in call arguments, reason and floor details, descriptions and failure details.
RAW = "RAW-ARG-MARKER"
OPENCLAW_VIEW = PLUGIN.parents[1] / "openclaw" / "plugin" / "dashboardView.js"


@pytest.mark.parametrize(
    ("log", "expected"),
    [
        (DASH / "traffic.jsonl", "model.json"),
        (FIXTURES / "traffic.jsonl", "model-history.json"),
        (FIXTURES / "edge" / "traffic.jsonl", "model-edge.json"),
    ],
)
def test_scans_model_matches_the_shared_fixture(log, expected):
    assert dashboard.scans_model(log, True, 50) == json.loads((DASH / expected).read_text())


@pytest.mark.parametrize(
    ("raw", "step"), [(3, 3), (3.0, 3), (3.5, None), (True, None), ("3", None)]
)
def test_step_reads_as_javascript_does(raw, step):
    assert dashboard.scan_model({"request_id": "x", "step": raw}, None)["step"] == step


@pytest.mark.parametrize(
    "log",
    [DASH / "traffic.jsonl", FIXTURES / "traffic.jsonl", FIXTURES / "edge" / "traffic.jsonl"],
)
def test_model_never_carries_raw_content(log):
    text = json.dumps(dashboard.scans_model(log, True, 50))
    assert RAW not in text
    assert "planir" not in text
    assert '"detail"' not in text


def test_log_off_gives_an_empty_model():
    m = dashboard.scans_model(DASH / "traffic.jsonl", False, 10)
    assert m["log"] == "off"
    assert m["scans"] == []


@pytest.mark.parametrize(
    ("raw", "n"), [(None, 10), ("", 10), ("abc", 10), ("0", 10), ("25", 25), ("999", 50)]
)
def test_limit_of(raw, n):
    assert dashboard.limit_of(raw) == n


def test_build_model_adds_lines_mode_and_state(tmp_path):
    cfg = resolve_config({"state_dir": str(tmp_path)}, {})
    shutil.copy(DASH / "traffic.jsonl", tmp_path / "traffic.jsonl")
    m = dashboard.build_model(cfg, dashboard.query_of({"n": "10"}))
    assert m["lines"] == {"review_at": 45, "block_at": 80}
    assert m["mode"] == "enforce"
    assert isinstance(m["state"]["grants"], str)
    assert isinstance(m["state"]["snooze"], str)
    assert m["commands"] == dashboard.COMMANDS
    assert m["commands"]["prefix"] == "/sentrook "
    assert m["pending"]["review_window_s"] == 300
    assert len(m["scans"]) == 6


def test_pending_matches_the_shared_fixture(tmp_path):
    shutil.copy(DASH / "holds.json", tmp_path / "holds.json")
    log = FIXTURES / "traffic.jsonl"
    now = datetime(2026, 10, 29, 9, 47, tzinfo=UTC)
    got = dashboard.pending_of(log, True, tmp_path, now, 300)
    assert got == json.loads((DASH / "pending.json").read_text())
    assert RAW not in json.dumps(got)
    later = datetime(2026, 10, 29, 9, 51, tzinfo=UTC)
    assert dashboard.pending_of(log, True, tmp_path, later, 300)["reviews"] == []
    off = dashboard.pending_of(log, False, tmp_path, now, 300)
    assert off["reviews"] == []
    assert all(h["scan"] is None for h in off["holds"])


def test_pending_with_an_unreadable_holds_file(tmp_path):
    (tmp_path / "holds.json").write_text("not json")
    got = dashboard.pending_of(DASH / "traffic.jsonl", True, tmp_path, datetime.now(UTC), 300)
    assert got["holds"] == []
    assert got["holds_readable"] is False


def test_query_cases_match_the_shared_fixture():
    logs = {
        "dashboard": DASH / "traffic.jsonl",
        "history": FIXTURES / "traffic.jsonl",
        "edge": FIXTURES / "edge" / "traffic.jsonl",
    }
    for case in json.loads((DASH / "query-cases.json").read_text()):
        r = dashboard.query_scans(logs[case["log"]], dashboard.query_of(case["params"]))
        got = {"ids": [s["id"] for s in r["scans"]], "page": r["page"], "query": r["query"]}
        want = {"ids": case["ids"], "page": case["page"], "query": case["query"]}
        assert got == want, case["name"]


def test_query_stops_at_the_budget_and_says_so():
    q = dashboard.query_of({"tool": "nothing-matches"})
    r = dashboard.query_scans(DASH / "traffic.jsonl", q, 1024)
    assert r["page"]["budget_hit"] is True
    assert r["page"]["read_bytes"] == 1024
    assert r["scans"] == []


def test_budget_covers_the_whole_log_within_bounds():
    mb = 1024 * 1024
    assert dashboard.budget_for(50 * mb) == 101 * mb
    assert dashboard.budget_for(1 * mb) == 16 * mb
    assert dashboard.budget_for(1024 * mb) == 256 * mb


def test_view_is_the_openclaw_view_byte_for_byte():
    assert (PLUGIN / "dashboard" / "view.js").read_bytes() == OPENCLAW_VIEW.read_bytes()


def test_manifest():
    manifest = json.loads((PLUGIN / "dashboard" / "manifest.json").read_text())
    # Hermes enables the tab and mounts the API by this name, the same as plugins.enabled.
    assert manifest["name"] == "sentrook"
    for key in ("entry", "api"):
        p = (PLUGIN / "dashboard" / manifest[key]).resolve()
        assert p.is_file()
        assert p.parent == (PLUGIN / "dashboard").resolve()
    version = next(
        line.split(":", 1)[1].strip()
        for line in (PLUGIN / "plugin.yaml").read_text().splitlines()
        if line.startswith("version:")
    )
    assert manifest["version"] == version


# --- plugin_api.py, loaded the way Hermes loads it: on its own, outside the plugin package.


class _Router:
    def __init__(self):
        self.routes = {}

    def get(self, path):
        def deco(fn):
            self.routes[path] = fn
            return fn

        return deco


@pytest.fixture
def api(monkeypatch, tmp_path):
    """plugin_api.py with stand-ins for FastAPI and Hermes's config and profile home."""
    fastapi = types.ModuleType("fastapi")
    fastapi.APIRouter = _Router
    fastapi.Request = object
    monkeypatch.setitem(sys.modules, "fastapi", fastapi)
    settings = {}
    approvals = {}
    hermes_cli = types.ModuleType("hermes_cli")
    hermes_config = types.ModuleType("hermes_cli.config")
    hermes_config.load_config_readonly = lambda: {
        "plugins": {"entries": {"sentrook": {"settings": dict(settings)}}},
        "approvals": dict(approvals),
    }
    hermes_cli.config = hermes_config
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", hermes_config)
    home = {"path": tmp_path / "default"}
    constants = types.ModuleType("hermes_constants")
    constants.get_hermes_home = lambda: home["path"]
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    monkeypatch.delenv("HERMES_STATE_DIR", raising=False)
    monkeypatch.delenv("SENTROOK_TRAFFIC_LOG", raising=False)
    # Not importable as part of a package: the plugin's own package must not be needed.
    for name in [m for m in sys.modules if m.startswith("_sentrook_dashboard_plugin")]:
        monkeypatch.delitem(sys.modules, name)
    spec = importlib.util.spec_from_file_location(
        "hermes_dashboard_plugin_sentrook", PLUGIN / "dashboard" / "plugin_api.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.settings = settings
    mod.approvals = approvals
    mod.home = home
    return mod


def _home_with_log(root: Path) -> Path:
    (root / "sentrook").mkdir(parents=True)
    shutil.copy(DASH / "traffic.jsonl", root / "sentrook" / "traffic.jsonl")
    return root


def test_api_serves_the_model_from_the_profile_home(api, tmp_path):
    api.home["path"] = _home_with_log(tmp_path / "default")
    request = types.SimpleNamespace(query_params={"n": "25", "tool": "web"})
    m = asyncio.run(api.router.routes["/model"](request))
    assert m["host"] == "hermes"
    assert m["limit"] == 25
    assert [s["tool"] for s in m["scans"]] == ["web_fetch", "web_fetch"]
    assert RAW not in json.dumps(m)


def test_api_resolves_the_profile_per_request(api, tmp_path):
    api.home["path"] = _home_with_log(tmp_path / "work")
    assert len(api.build({})["scans"]) == 6
    api.home["path"] = tmp_path / "empty"
    assert api.build({})["scans"] == []


def test_api_reads_the_plugin_settings(api, tmp_path):
    api.home["path"] = tmp_path / "nothing-here"
    elsewhere = tmp_path / "custom" / "log.jsonl"
    elsewhere.parent.mkdir(parents=True)
    shutil.copy(DASH / "traffic.jsonl", elsewhere)
    api.settings["traffic_log"] = {"path": str(elsewhere)}
    api.settings["review_at"] = 30
    m = api.build({"n": "5"})
    assert len(m["scans"]) == 5
    assert m["lines"]["review_at"] == 30
    api.settings["traffic_log"] = {"enabled": False}
    assert api.build({})["log"] == "off"


def test_api_does_not_load_the_agent_side_plugin(api, tmp_path):
    api.home["path"] = _home_with_log(tmp_path / "default")
    api.build({})
    # The plugin's __init__.py hooks into the agent; the dashboard process must not run it.
    pkg = sys.modules["_sentrook_dashboard_plugin"]
    assert not hasattr(pkg, "register")


def test_api_takes_the_answer_window_from_hermes_approvals_timeout(api, tmp_path):
    api.home["path"] = _home_with_log(tmp_path / "default")
    assert api.build({})["pending"]["review_window_s"] == 300
    api.approvals["timeout"] = 120
    assert api.build({})["pending"]["review_window_s"] == 120
    api.approvals["timeout"] = "soon"
    assert api.build({})["pending"]["review_window_s"] == 300


REPORT_FIXTURES = FIXTURES / "report"


def test_build_model_adds_the_report_panel_only_when_asked(tmp_path):
    from plugin import history, report

    cfg = resolve_config({"state_dir": str(tmp_path)}, {})
    shutil.copy(REPORT_FIXTURES / "traffic.jsonl", tmp_path / "traffic.jsonl")
    assert "report" not in dashboard.build_model(cfg, dashboard.query_of({"n": "10"}))
    m = dashboard.build_model(cfg, dashboard.query_of({"n": "10"}), report_ref="aaaa1b2c")
    found = report.find(tmp_path / "traffic.jsonl", history.parse_ref("aaaa1b2c"))
    assert m["report"] == report.model(found, dashboard.CMD)
    assert m["report"]["full_commands"] == [
        "/sentrook report aaaa1b2c --save",
        "/sentrook report aaaa1b2c --full",
    ]
    assert not any(
        marker in json.dumps(m) for marker in ("PLANIR-BODY-MARKER", "PRIVATE-PATH-MARKER")
    )
    assert m["report"]["summary"] == (REPORT_FIXTURES / "summary-aaaa1b2c.txt").read_text().rstrip(
        "\n"
    )
    for ref in ("abcdef12", "last", "../etc"):
        got = dashboard.build_model(cfg, dashboard.query_of({}), report_ref=ref)["report"]
        assert got == {"id": ref, "missing": True}, ref
    off = resolve_config({"state_dir": str(tmp_path), "traffic_log": {"enabled": False}}, {})
    assert dashboard.build_model(off, dashboard.query_of({}), report_ref="aaaa1b2c")["report"][
        "missing"
    ]


def test_api_serves_the_report_panel(api, tmp_path):
    home = tmp_path / "default"
    (home / "sentrook").mkdir(parents=True)
    shutil.copy(REPORT_FIXTURES / "traffic.jsonl", home / "sentrook" / "traffic.jsonl")
    api.home["path"] = home
    request = types.SimpleNamespace(query_params={"n": "10", "report": "aaaa1b2c"})
    m = asyncio.run(api.router.routes["/model"](request))
    assert m["report"]["id"] == "aaaa1b2c-0000-4000-8000-00000000000a"
    assert "PLANIR-BODY-MARKER" not in json.dumps(
        m
    )  # the full record stays with the owner's commands


# ---- Showing the call (dashboard_show_calls, off by default) ----

CALLS_LOG = DASH / "calls.jsonl"
#: Strings in the calls fixture that sit outside the pending call's tool and arguments.
NOT_THE_CALL = (
    "REQUEST-TEXT-MARKER",
    "HISTORY-MARKER",
    "NARRATION-MARKER",
    "SIBLING-MARKER",
    "DETAIL-MARKER",
    "planir",
)


def _typed(v):
    """A value with each scalar tagged by its JSON type, so True is not 1 and 1 is not "1"."""
    if isinstance(v, dict):
        return {k: _typed(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_typed(x) for x in v]
    if isinstance(v, bool) or v is None:
        return (type(v).__name__, v)
    if isinstance(v, (int, float)):
        return ("number", float(v))
    return ("str", v)


def test_call_of_matches_the_shared_fixture():
    got = [dashboard.call_of(json.loads(line)) for line in CALLS_LOG.read_text().splitlines()]
    assert _typed(got) == _typed(json.loads((DASH / "calls.json").read_text()))
    # Numbers as JavaScript reads them: past 2^53 a double, past the double range None; long keys cut.
    huge = got[12]["arguments"]
    assert list(huge.values())[:4] == [None, float(2**60), 2**53, -float(2**60)]
    assert list(huge)[4] == "k" * 200 + "…"
    assert got[2]["arguments"]["background"] is False
    # Integer-like keys first, as JavaScript orders them; the rest as written.
    assert list(got[8]["arguments"]) == ["2", "10", "b", "a", "01", "-1"]
    assert got[11] is None


def test_show_calls_setting_is_off_by_default(tmp_path):
    assert resolve_config({}, {}).dashboard_show_calls is False
    assert resolve_config({"dashboard_show_calls": True}, {}).dashboard_show_calls is True
    assert resolve_config({}, {"SENTROOK_DASHBOARD_SHOW_CALLS": "1"}).dashboard_show_calls is True
    assert "dashboard_show_calls" in SETTINGS_KEYS


def test_calls_off_the_model_holds_no_part_of_a_call(tmp_path):
    shutil.copy(CALLS_LOG, tmp_path / "traffic.jsonl")
    cfg = resolve_config({"state_dir": str(tmp_path)}, {})
    m = dashboard.build_model(cfg, dashboard.query_of({"n": "50"}))
    assert m["show_calls"] is False
    assert len(m["scans"]) == 13
    assert all("call" not in s for s in m["scans"])
    text = json.dumps(m, ensure_ascii=False)
    for marker in (*NOT_THE_CALL, "notes/todo.md", "git status", "#général"):
        assert marker not in text


def test_calls_on_each_scan_carries_its_call_and_nothing_else(tmp_path):
    shutil.copy(CALLS_LOG, tmp_path / "traffic.jsonl")
    cfg = resolve_config({"state_dir": str(tmp_path), "dashboard_show_calls": True}, {})
    m = dashboard.build_model(cfg, dashboard.query_of({"n": "50"}))
    assert m["show_calls"] is True
    edits = [s for s in m["scans"] if s["tool"] == "edit"]
    assert edits[-1]["call"] == {
        "tool": "edit",
        "arguments": {
            "path": "notes/todo.md",
            "old_string": "- [ ] ship\n",
            "new_string": "- [x] ship\n- [ ] <script>alert(1)</script>\n",
        },
    }
    assert [s for s in m["scans"] if s["tool"] == "web_fetch"][0]["call"] is None
    text = json.dumps(m, ensure_ascii=False)
    for marker in NOT_THE_CALL:
        assert marker not in text
    assert m["commands"]["call_setting"].endswith("dashboard_show_calls true")
