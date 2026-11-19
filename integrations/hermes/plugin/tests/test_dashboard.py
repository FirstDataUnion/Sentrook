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

from plugin import dashboard
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
    m = dashboard.build_model(cfg, 10)
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
    model = dashboard.scans_model(FIXTURES / "traffic.jsonl", True, 50)
    now = datetime(2026, 10, 29, 9, 47, tzinfo=UTC)
    got = dashboard.pending_of(model, tmp_path, now, 300)
    assert got == json.loads((DASH / "pending.json").read_text())
    assert RAW not in json.dumps(got)
    later = datetime(2026, 10, 29, 9, 51, tzinfo=UTC)
    assert dashboard.pending_of(model, tmp_path, later, 300)["reviews"] == []


def test_pending_with_an_unreadable_holds_file(tmp_path):
    (tmp_path / "holds.json").write_text("not json")
    got = dashboard.pending_of({"scans": []}, tmp_path, datetime.now(UTC), 300)
    assert got["holds"] == []
    assert got["holds_readable"] is False


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
    m = asyncio.run(api.router.routes["/model"]("25"))
    assert m["host"] == "hermes"
    assert m["limit"] == 25
    assert len(m["scans"]) == 6
    assert RAW not in json.dumps(m)


def test_api_resolves_the_profile_per_request(api, tmp_path):
    api.home["path"] = _home_with_log(tmp_path / "work")
    assert len(api.build(None)["scans"]) == 6
    api.home["path"] = tmp_path / "empty"
    assert api.build(None)["scans"] == []


def test_api_reads_the_plugin_settings(api, tmp_path):
    api.home["path"] = tmp_path / "nothing-here"
    elsewhere = tmp_path / "custom" / "log.jsonl"
    elsewhere.parent.mkdir(parents=True)
    shutil.copy(DASH / "traffic.jsonl", elsewhere)
    api.settings["traffic_log"] = {"path": str(elsewhere)}
    api.settings["review_at"] = 30
    m = api.build("5")
    assert len(m["scans"]) == 5
    assert m["lines"]["review_at"] == 30
    api.settings["traffic_log"] = {"enabled": False}
    assert api.build(None)["log"] == "off"


def test_api_does_not_load_the_agent_side_plugin(api, tmp_path):
    api.home["path"] = _home_with_log(tmp_path / "default")
    api.build(None)
    # The plugin's __init__.py hooks into the agent; the dashboard process must not run it.
    pkg = sys.modules["_sentrook_dashboard_plugin"]
    assert not hasattr(pkg, "register")


def test_api_takes_the_answer_window_from_hermes_approvals_timeout(api, tmp_path):
    api.home["path"] = _home_with_log(tmp_path / "default")
    assert api.build(None)["pending"]["review_window_s"] == 300
    api.approvals["timeout"] = 120
    assert api.build(None)["pending"]["review_window_s"] == 120
    api.approvals["timeout"] = "soon"
    assert api.build(None)["pending"]["review_window_s"] == 300
