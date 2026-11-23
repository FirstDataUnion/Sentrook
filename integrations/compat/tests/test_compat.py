"""Host compatibility helpers: version picking, the warnings baseline, the bump, the canary issue."""

import dataclasses
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import compat  # noqa: E402

HERMES = compat.HOSTS["hermes"]


# --- pinned versions stay truthful -----------------------------------------------------------------


def test_floor_is_the_plugins_declared_minimum():
    manifest = (compat.REPO_ROOT / "integrations/hermes/plugin/plugin.yaml").read_text()
    declared = re.search(r'^requires_hermes:\s*"?>=\s*([\d.]+)"?', manifest, re.M)
    assert declared, "plugin.yaml has no requires_hermes >= floor"
    assert compat.read_versions(HERMES.compat_dir / "versions.txt")["floor"] == f"v{declared[1]}"


def test_install_guide_names_the_tested_versions():
    pinned = compat.read_versions(HERMES.compat_dir / "versions.txt")
    found = compat.TESTED_ON.findall(HERMES.readme.read_text())
    assert found == [(pinned["floor"], pinned["latest"])]


def test_baseline_reads_without_comments():
    baseline = compat.read_baseline(HERMES.compat_dir / "warnings-baseline.txt")
    assert baseline and not any(line.startswith("#") for line in baseline)


# --- tags ------------------------------------------------------------------------------------------

TAGS = [
    "latest",
    "stable",
    "main",
    "v0.23.2",
    "v0.23.2-desktop",
    "rc.13-v0.23.2",
    "rc.13-v0.23.2-arm64",
    "v0.23.1",
    "rc.3-v0.23.1",
    "v0.9.10",
    "v2026.9.24",
    "v2026.9.24-desktop",
    "v2026.8.16.2",
]


def test_newest_stable_orders_numerically_and_skips_variants():
    assert compat.newest_stable(HERMES, TAGS) == "v0.23.2"
    assert compat.newest_stable(HERMES, ["v0.9.10", "v0.10.0"]) == "v0.10.0"
    assert compat.newest_stable(HERMES, ["main", "rc.1-v1.0.0"]) is None


def test_hermes_calendar_tags_are_not_releases():
    """Hermes's older calendar-versioned images must never become `latest` or a release candidate."""
    assert compat.newest_stable(HERMES, ["v2026.9.24", "v2026.9.21"]) is None
    assert compat.newest_rc(HERMES, ["rc.1-v2026.9.24"], "v0.23.2") is None


def test_rc_only_when_newer_than_latest():
    assert compat.newest_rc(HERMES, TAGS, "v0.23.2") is None
    newer = [*TAGS, "rc.1-v0.23.3", "rc.2-v0.23.3", "rc.10-v0.23.3", "rc.2-v0.23.3-amd64"]
    assert compat.newest_rc(HERMES, newer, "v0.23.2") == "rc.10-v0.23.3"
    assert compat.newest_rc(HERMES, [*newer, "rc.1-v0.24.0"], "v0.23.2") == "rc.1-v0.24.0"


def test_matrix_sets():
    blocking = compat.matrix(HERMES, "blocking")
    pinned = compat.read_versions(HERMES.compat_dir / "versions.txt")
    assert [m["image"] for m in blocking] == [
        f"nousresearch/hermes-agent:{pinned['floor']}",
        f"nousresearch/hermes-agent:{pinned['latest']}",
    ]
    assert compat.matrix(HERMES, "rc", tags=["rc.1-v0.0.1"]) == []
    assert compat.matrix(HERMES, "rc", tags=["rc.4-v99.0.0"]) == [
        {
            "host": "hermes",
            "name": "rc rc.4-v99.0.0",
            "image": "nousresearch/hermes-agent:rc.4-v99.0.0",
            "target": "release candidate",
        }
    ]


def test_main_canary_runs_on_a_fresh_main_build():
    def pushed(image, tag):
        return {"main": "2026-11-17T04:00:00Z"}.get(tag, "2026-11-16T20:59:00Z")

    assert compat.matrix(HERMES, "main", pushed_at=pushed) == [
        {
            "host": "hermes",
            "name": "main",
            "image": "nousresearch/hermes-agent:main",
            "target": "main",
        }
    ]


def test_main_canary_skips_a_main_build_older_than_latest(capsys):
    def pushed(image, tag):
        return {"main": "2026-11-05T13:32:14Z"}.get(tag, "2026-11-16T20:59:00Z")

    assert compat.matrix(HERMES, "main", pushed_at=pushed) == []
    assert "skipping the main canary" in capsys.readouterr().err


# --- warnings --------------------------------------------------------------------------------------


def test_line_numbers_do_not_make_a_warning_new():
    base = ["private core imports: planir.py:82 hermes_cli; skill_review.py:56 tools.x"]
    now = ["private core imports: planir.py:90 hermes_cli; skill_review.py:61 tools.x"]
    assert compat.warnings_diff(base, now) == ([], [])


def test_new_and_gone_warnings():
    new, gone = compat.warnings_diff(
        ["a known warning"], ["provides_hooks declares on_x but register() did not register them"]
    )
    assert new == ["provides_hooks declares on_x but register() did not register them"]
    assert gone == ["a known warning"]


def test_an_added_private_import_is_new():
    base = ["private core imports: planir.py:82 hermes_cli"]
    now = ["private core imports: planir.py:82 hermes_cli; grants.py:3 tools.approval"]
    assert compat.warnings_diff(base, now)[0] == [compat.normalize_warning(now[0])]


def test_warnings_cli_fails_on_a_new_warning(tmp_path, capsys):
    report = tmp_path / "validate.json"
    report.write_text(json.dumps({"ok": True, "checks": [], "warnings": ["something new"]}))
    assert compat.main(["warnings", "--host", "hermes", str(report)]) == 1
    assert "FAIL new validator warning" in capsys.readouterr().out


def test_warnings_cli_fails_without_a_report(tmp_path):
    assert compat.main(["warnings", "--host", "hermes", str(tmp_path / "missing.json")]) == 1


# --- bump ------------------------------------------------------------------------------------------


@pytest.fixture
def host_copy(tmp_path):
    (tmp_path / "compat").mkdir()
    (tmp_path / "compat/versions.txt").write_text("# pinned\nfloor v0.23.0\nlatest v0.23.2\n")
    (tmp_path / "README.md").write_text("Needs v0.23.0.\n  Tested on v0.23.0 and v0.23.2.\nMore.\n")
    return dataclasses.replace(
        HERMES, compat_dir=tmp_path / "compat", readme=tmp_path / "README.md"
    )


def test_bump_moves_latest_and_the_guide(host_copy):
    assert compat.bump(host_copy, "v0.24.0") is True
    assert compat.read_versions(host_copy.compat_dir / "versions.txt") == {
        "floor": "v0.23.0",
        "latest": "v0.24.0",
    }
    assert "# pinned" in (host_copy.compat_dir / "versions.txt").read_text()
    assert "Tested on v0.23.0 and v0.24.0." in host_copy.readme.read_text()


def test_bump_never_moves_backwards(host_copy):
    assert compat.bump(host_copy, "v0.23.2") is False
    assert compat.bump(host_copy, "v0.23.1") is False
    assert compat.read_versions(host_copy.compat_dir / "versions.txt")["latest"] == "v0.23.2"


def test_bump_rejects_a_non_release_tag(host_copy):
    with pytest.raises(ValueError):
        compat.bump(host_copy, "rc.1-v0.24.0")


# --- canary issue ----------------------------------------------------------------------------------


class FakeGh:
    def __init__(self, open_issues):
        self.open = list(open_issues)
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        if args[:2] == ["issue", "list"]:
            return json.dumps(self.open)
        if args[:2] == ["issue", "create"]:
            title = args[args.index("--title") + 1]
            self.open.append({"number": 100 + len(self.open), "title": title})
        if args[:2] == ["issue", "close"]:
            self.open = [i for i in self.open if i["number"] != int(args[2])]
        return ""

    def writes(self):
        """Issue changes; listing issues and creating the label are not."""
        return [c[:2] for c in self.calls if c[0] == "issue" and c[1] != "list"]


def run_canary(gh, failed, target="main"):
    return compat.canary_issue(HERMES, target, failed, "https://example.invalid/run/1", "", gh)


def test_green_canary_opens_no_issue():
    gh = FakeGh([])
    assert run_canary(gh, failed=False) == "none"
    assert gh.writes() == []


def test_failing_canary_opens_one_issue_then_comments():
    gh = FakeGh([{"number": 7, "title": "unrelated"}])
    assert run_canary(gh, failed=True) == "create"
    assert run_canary(gh, failed=True) == "comment #101"
    assert run_canary(gh, failed=True) == "comment #101"
    titles = [i["title"] for i in gh.open]
    assert titles.count(compat.issue_title(HERMES, "main")) == 1
    assert gh.writes() == [["issue", "create"], ["issue", "comment"], ["issue", "comment"]]


def test_passing_canary_closes_its_issue_only():
    rc_title = compat.issue_title(HERMES, "release candidate")
    gh = FakeGh(
        [
            {"number": 5, "title": compat.issue_title(HERMES, "main")},
            {"number": 6, "title": rc_title},
        ]
    )
    assert run_canary(gh, failed=False) == "close #5"
    assert gh.open == [{"number": 6, "title": rc_title}]


def test_each_canary_target_has_its_own_issue():
    gh = FakeGh([])
    run_canary(gh, failed=True, target="main")
    run_canary(gh, failed=True, target="release candidate")
    assert len(gh.open) == 2


# --- OpenClaw --------------------------------------------------------------------------------------

OPENCLAW = compat.HOSTS["openclaw"]

OPENCLAW_TAGS = [
    "main",
    "latest",
    "main-slim",
    "main-14e2e10794-amd64",
    "2026.11.5",
    "2026.11.5-browser",
    "2026.11.5-slim-amd64",
    "2026.11.5-beta.4",
    "2026.11.5-beta.4-browser",
    "2026.9.37",
    "2026.5.23-alpha.1",
    "sha256-405dcc682726f",
]


def test_openclaw_floor_is_the_plugins_declared_minimum():
    pkg = json.loads((compat.REPO_ROOT / "integrations/openclaw/plugin/package.json").read_text())
    declared = re.fullmatch(r">=\s*([\d.]+)", pkg["openclaw"]["compat"]["pluginApi"])
    assert declared, "package.json openclaw.compat.pluginApi is not >= floor"
    floor = compat.read_versions(OPENCLAW.compat_dir / "versions.txt")["floor"]
    assert floor == declared[1] == pkg["openclaw"]["build"]["openclawVersion"]


def test_openclaw_install_guide_names_the_tested_versions():
    pinned = compat.read_versions(OPENCLAW.compat_dir / "versions.txt")
    found = compat.TESTED_ON.findall(OPENCLAW.readme.read_text())
    assert found == [(pinned["floor"], pinned["latest"])]


def test_openclaw_baseline_reads_without_comments():
    baseline = compat.read_baseline(OPENCLAW.compat_dir / "warnings-baseline.txt")
    assert baseline and not any(line.startswith("#") for line in baseline)


def test_openclaw_newest_stable_skips_variants_and_the_older_line():
    assert compat.newest_stable(OPENCLAW, OPENCLAW_TAGS) == "2026.11.5"
    assert compat.newest_stable(OPENCLAW, ["2026.9.37", "2026.10.10"]) == "2026.10.10"


def test_openclaw_beta_only_when_newer_than_latest():
    assert compat.newest_rc(OPENCLAW, OPENCLAW_TAGS, "2026.11.5") is None
    newer = [*OPENCLAW_TAGS, "2026.11.6-beta.2", "2026.11.6-beta.10", "2026.11.6-beta.10-browser"]
    assert compat.newest_rc(OPENCLAW, newer, "2026.11.5") == "2026.11.6-beta.10"
    assert (
        compat.newest_rc(OPENCLAW, [*newer, "2026.12.1-beta.1"], "2026.11.5") == "2026.12.1-beta.1"
    )


def test_openclaw_matrix_sets():
    pinned = compat.read_versions(OPENCLAW.compat_dir / "versions.txt")
    assert [m["image"] for m in compat.matrix(OPENCLAW, "blocking")] == [
        f"ghcr.io/openclaw/openclaw:{pinned['floor']}",
        f"ghcr.io/openclaw/openclaw:{pinned['latest']}",
    ]
    assert compat.matrix(OPENCLAW, "rc", tags=["2099.1.1-beta.3"]) == [
        {
            "host": "openclaw",
            "name": "beta 2099.1.1-beta.3",
            "image": "ghcr.io/openclaw/openclaw:2099.1.1-beta.3",
            "target": "beta",
        }
    ]


def test_openclaw_main_canary_skips_a_stale_main_build(capsys):
    def stale(image, tag):
        return {"main": "2026-11-01T00:00:00Z"}.get(tag, "2026-11-17T03:41:55Z")

    assert compat.matrix(OPENCLAW, "main", pushed_at=stale) == []
    assert "skipping the main canary" in capsys.readouterr().err


def test_canary_targets_are_named_per_host():
    assert compat.issue_title(HERMES, HERMES.prerelease) == (
        "Hermes compatibility canary failing: release candidate"
    )
    assert compat.issue_title(OPENCLAW, OPENCLAW.prerelease) == (
        "OpenClaw compatibility canary failing: beta"
    )


def test_bump_moves_an_openclaw_guide(tmp_path):
    (tmp_path / "compat").mkdir()
    (tmp_path / "compat/versions.txt").write_text("floor 2026.9.5\nlatest 2026.11.5\n")
    (tmp_path / "README.md").write_text(
        "Tested on 2026.9.5 and 2026.11.5. Older releases refuse.\n"
    )
    host = dataclasses.replace(
        OPENCLAW, compat_dir=tmp_path / "compat", readme=tmp_path / "README.md"
    )
    assert compat.bump(host, "2026.11.12") is True
    assert "Tested on 2026.9.5 and 2026.11.12." in host.readme.read_text()
    assert compat.bump(host, "2026.9.38") is False
    with pytest.raises(ValueError):
        compat.bump(host, "2026.12.1-beta.1")


def test_ghcr_build_time_reads_the_amd64_image_config():
    index = {
        "manifests": [
            {"digest": "sha256:arm", "mediaType": "m", "platform": {"architecture": "arm64"}},
            {"digest": "sha256:amd", "mediaType": "m", "platform": {"architecture": "amd64"}},
        ]
    }
    docs = {
        "manifests/main": index,
        "manifests/sha256:amd": {"config": {"digest": "sha256:cfg"}},
        "blobs/sha256:cfg": {"created": "2026-11-17T03:41:55.2Z"},
    }
    assert compat.ghcr_created("ghcr.io/openclaw/openclaw", "main", get=lambda p: docs[p]) == (
        "2026-11-17T03:41:55.2Z"
    )


# --- OpenClaw seam probe ---------------------------------------------------------------------------

sys.path.insert(0, str(compat.REPO_ROOT / "integrations/openclaw/compat"))

import seams  # noqa: E402


def probe_records(**changes):
    """What the probe records on a compatible OpenClaw, with `changes` merged into the full registration."""
    fields = dict.fromkeys(seams.API_FIELDS, "function")
    fields["runtime.version"] = "string"
    register = {
        "at": "register",
        "mode": "full",
        "fields": fields,
        "extra": [],
        "version": "2026.11.5",
        "current": "object",
    }
    for key, value in changes.items():
        if key == "fields":
            fields.update(value)
        else:
            register[key] = value
    call = {"at": "before_tool_call", **{f: s for f, s in seams.TOOL_CALL_FIELDS.items()}}
    return [
        {"at": "register", "mode": "discovery", "fields": {}, "extra": [], "version": None},
        register,
        {"at": "before_prompt_build", "messages": "array", "users": 0, "ownerMarked": 0},
        {"at": "middleware_registered", "mode": "full", "ok": True},
        call,
        {"at": "tool_result_middleware", "toolCallId": "string", "result": "object"},
        call,
        {"at": "before_prompt_build", "messages": "array", "users": 1, "ownerMarked": 1},
    ]


def test_seams_silent_on_a_compatible_host():
    assert seams.judge(probe_records()) == []


def test_seams_fire_when_a_probed_field_is_missing():
    problems = seams.judge(probe_records(fields={"runtime.config.current": "undefined"}))
    assert problems == ["api.runtime.config.current is undefined, expected function"]
    extra = probe_records(
        extra=["runtime.compatNoSuchField"], fields={"runtime.compatNoSuchField": "undefined"}
    )
    assert seams.judge(extra) == ["api.runtime.compatNoSuchField is missing (undefined)"]


def test_seams_fire_when_the_owner_marker_moves():
    records = [r for r in probe_records() if r["at"] != "before_prompt_build"]
    records.append(
        {
            "at": "before_prompt_build",
            "messages": "array",
            "users": 1,
            "ownerMarked": 0,
            "markerShapes": ["undefined"],
        }
    )
    assert seams.judge(records) == [
        "no user message carried __openclaw.senderIsOwner === true (found: undefined)"
    ]


def test_seams_fire_when_a_tool_call_field_moves():
    records = probe_records()
    records[4] = {**records[4], "toolName": "undefined", "session": None}
    assert seams.judge(records) == [
        "before_tool_call toolName is undefined, expected string",
        "before_tool_call session is None, expected string",
    ]


def test_seams_fire_without_a_full_registration():
    assert seams.judge([r for r in probe_records() if r.get("mode") != "full"]) == [
        "the probe was never registered in full mode (no agent run loaded plugins)"
    ]


def test_seams_fire_when_the_result_middleware_is_refused_or_silent():
    records = [r for r in probe_records() if r["at"] != "tool_result_middleware"]
    assert seams.judge(records) == ["the tool-result middleware never ran"]
    records = [
        {**r, "ok": False, "error": "Error: unknown runtime"}
        if r["at"] == "middleware_registered"
        else r
        for r in probe_records()
    ]
    assert seams.judge(records) == [
        "registerAgentToolResultMiddleware refused: Error: unknown runtime"
    ]


def test_seams_cli_reports_ok_with_the_version(tmp_path, capsys, monkeypatch):
    path = tmp_path / "probe.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in probe_records()))
    monkeypatch.setattr(sys, "argv", ["seams.py", str(path)])
    assert seams.main() == 0
    assert capsys.readouterr().out.startswith("ok\t")


# --- Hermes platform classification ----------------------------------------------------------------

sys.path.insert(0, str(compat.REPO_ROOT / "integrations/hermes/compat"))

import importlib.util  # noqa: E402
import types  # noqa: E402

import platforms  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "hermes_plugin_intent", compat.REPO_ROOT / "integrations/hermes/plugin/intent.py"
)
intent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(intent)

#: The values `platforms.hermes_platforms` read from Hermes v0.23.0 to v0.23.3 (enum, bundled platform plugins,
#: Hermes's own surface sets and the values it sets where it creates a session).
HERMES_0_23_PLATFORMS = {
    "",
    "a2a",
    "acp",
    "api_server",
    "batch",
    "bot_room",
    "bluebubbles",
    "buzz",
    "cli",
    "codex",
    "curator",
    "desktop",
    "dingtalk",
    "discord",
    "email",
    "feishu",
    "gateway",
    "google_chat",
    "irc",
    "kanban",
    "line",
    "local",
    "matrix",
    "mattermost",
    "msgraph_webhook",
    "ntfy",
    "photon",
    "qqbot",
    "raft",
    "relay",
    "signal",
    "simplex",
    "slack",
    "sms",
    "teams",
    "telegram",
    "tool",
    "tui",
    "webhook",
    "wecom",
    "wecom_callback",
    "weixin",
    "whatsapp",
    "whatsapp_cloud",
    "yuanbao",
}


def test_every_hermes_0_23_platform_is_classified():
    assert platforms.unclassified(HERMES_0_23_PLATFORMS, platforms.classified(intent)) == []


def test_attended_and_not_attended_do_not_overlap():
    assert not intent.ATTENDED_PLATFORMS & intent.NOT_ATTENDED_PLATFORMS
    assert not intent.LOCAL_PLATFORMS & (intent.ATTENDED_PLATFORMS | intent.NOT_ATTENDED_PLATFORMS)


def _run_platforms_check(monkeypatch, capsys, values):
    monkeypatch.setattr(platforms, "hermes_platforms", lambda: set(values))
    monkeypatch.setitem(sys.modules, "sentrook", types.SimpleNamespace(intent=intent))
    monkeypatch.setattr(sys, "path", list(sys.path))  # main() puts the plugin directory first
    rc = platforms.main(["platforms.py", "/nonexistent"])
    return rc, capsys.readouterr().out


def test_platforms_check_fails_on_a_platform_in_neither_list(monkeypatch, capsys):
    """Must fire: a platform value a new Hermes adds is reported until it is classified."""
    rc, out = _run_platforms_check(
        monkeypatch, capsys, HERMES_0_23_PLATFORMS | {"new_chat", "zulip"}
    )
    assert rc == 1
    assert out.startswith("unclassified new_chat, zulip:")


def test_platforms_check_passes_when_every_value_is_classified(monkeypatch, capsys):
    rc, out = _run_platforms_check(monkeypatch, capsys, HERMES_0_23_PLATFORMS)
    assert rc == 0
    assert out.strip() == f"all {len(HERMES_0_23_PLATFORMS)} platform values classified"


def test_platforms_check_cannot_pass_on_no_values(monkeypatch, capsys):
    rc, out = _run_platforms_check(monkeypatch, capsys, set())
    assert rc == 2
    assert "none found" in out
