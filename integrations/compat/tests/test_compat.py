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
]


def test_newest_stable_orders_numerically_and_skips_variants():
    assert compat.newest_stable(HERMES, TAGS) == "v0.23.2"
    assert compat.newest_stable(HERMES, ["v0.9.10", "v0.10.0"]) == "v0.10.0"
    assert compat.newest_stable(HERMES, ["main", "rc.1-v1.0.0"]) is None


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
        }
    ]


def test_main_canary_runs_on_a_fresh_main_build():
    def pushed(image, tag):
        return {"main": "2026-11-17T04:00:00Z"}.get(tag, "2026-11-16T20:59:00Z")

    assert compat.matrix(HERMES, "main", pushed_at=pushed) == [
        {"host": "hermes", "name": "main", "image": "nousresearch/hermes-agent:main"}
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
