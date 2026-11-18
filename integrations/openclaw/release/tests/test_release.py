"""The OpenClaw plugin release: one version, the CHANGELOG gate, the channel, the packed artifact, the ClawHub
validation report, and the workflow's order (nothing is published before the compatibility check, nothing at all
on a dry run).

A minimal package stands in for the plugin where the real one would need a build; `npm pack` runs for real.
"""

import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import release  # noqa: E402

WORKFLOW = release.REPO_ROOT / ".github/workflows/release-plugin.yml"
CLEAN_REPORT = (
    'Validating ./ ...\n{"status": "pass", "summary": {"breakageCount": 0, "warningCount": 0,'
    ' "issueCount": 0}, "issues": []}\n'
)


def plugin(tmp_path: Path, *, version="2.1.0-beta.1", constant=None, changelog=None) -> Path:
    """A plugin directory with the files the release reads: package.json, planir.ts, CHANGELOG.md."""
    d = tmp_path / "plugin"
    d.mkdir()
    (d / "package.json").write_text(
        json.dumps(
            {
                "name": release.PACKAGE_NAME,
                "version": version,
                "files": ["index.js", "CHANGELOG.md"],
                "publishConfig": {"registry": release.NPMJS_REGISTRY, "access": "public"},
            }
        )
    )
    (d / "planir.ts").write_text(
        f'// header\nexport const PLUGIN_VERSION = "{constant or version}";\n'
    )
    (d / "index.js").write_text("export default {};\n")
    if changelog is None:
        changelog = f"# {release.PACKAGE_NAME}\n\n## {version}\n\n### Patch Changes\n\n- A fix.\n"
    (d / "CHANGELOG.md").write_text(changelog)
    return d


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def run_text(job: dict) -> str:
    return "\n".join(s.get("run", "") for s in job["steps"])


# --- must fire --------------------------------------------------------------------------------------


def test_a_dry_run_with_no_changelog_entry_fails(tmp_path):
    d = plugin(tmp_path, changelog=f"# {release.PACKAGE_NAME}\n\n## 2.0.0\n\n- Older.\n")
    with pytest.raises(release.ReleaseError, match="no entry for 2.1.0-beta.1"):
        release.check(d, "next")
    # The workflow's first gate is the CLI: it exits non-zero, so the run stops there.
    assert release.main(["check", "--plugin", str(d), "--channel", "next"]) == 1


def test_an_empty_changelog_entry_fails(tmp_path):
    d = plugin(tmp_path, changelog="# x\n\n## 2.1.0-beta.1\n\n## 2.0.0\n\n- Older.\n")
    with pytest.raises(release.ReleaseError, match="empty"):
        release.check(d, "next")


def test_a_version_mismatch_between_package_json_and_the_plugin_constant_fails(tmp_path):
    d = plugin(tmp_path, constant="2.1.0-beta.0")
    with pytest.raises(release.ReleaseError, match="PLUGIN_VERSION 2.1.0-beta.0 .* 2.1.0-beta.1"):
        release.check(d, "next")
    assert release.main(["check", "--plugin", str(d), "--channel", "next"]) == 1


def test_a_missing_plugin_constant_fails(tmp_path):
    d = plugin(tmp_path)
    (d / "planir.ts").write_text("export const OTHER = 1;\n")
    with pytest.raises(release.ReleaseError, match="PLUGIN_VERSION"):
        release.check(d, "next")


@pytest.mark.parametrize(("version", "channel"), [("2.1.0-beta.1", "latest"), ("2.1.0", "next")])
def test_the_channel_must_match_the_version(tmp_path, version, channel):
    """A prerelease goes only to next (ClawHub beta); a stable version only to latest."""
    d = plugin(tmp_path, version=version)
    with pytest.raises(release.ReleaseError, match="channel"):
        release.check(d, channel)


def test_a_package_not_bound_for_public_npmjs_fails(tmp_path):
    d = plugin(tmp_path)
    pkg = json.loads((d / "package.json").read_text())
    pkg["publishConfig"]["registry"] = "https://npm.example.invalid"
    (d / "package.json").write_text(json.dumps(pkg))
    with pytest.raises(release.ReleaseError, match="publishConfig.registry"):
        release.check(d, "next")


@pytest.mark.parametrize(
    "report",
    [
        # A finding: validate still exits 0, so the report itself is the gate.
        '{"status": "pass", "summary": {"issueCount": 1}, "issues": [{"severity": "warn",'
        ' "code": "package-plugin-api-compat-missing", "message": "pluginApi is required"}]}',
        '{"status": "fail", "summary": {"breakageCount": 1, "issueCount": 0}, "issues": []}',
        "no JSON at all",
    ],
)
def test_a_package_that_fails_clawhub_validate_fails(tmp_path, report):
    f = tmp_path / "validate.out"
    f.write_text(report)
    ok, _ = release.validate_report(report)
    assert not ok
    assert release.main(["validate-report", str(f)]) == 1


def test_clawhub_validate_and_the_compat_check_run_before_any_publish():
    """Validate, the ClawHub dry run and host-compat on the exact artifact all gate the publish job."""
    jobs = workflow()["jobs"]
    build, publish = jobs["build"], jobs["publish"]
    names = [s.get("name", "") for s in build["steps"]]
    validate = names.index("ClawHub validate")
    assert re.search(r'RELEASE_PY\}?" validate-report ', build["steps"][validate]["run"])
    assert names.index("ClawHub dry-run publish") > names.index("Pack the release artifact")
    upload = next(
        i
        for i, s in enumerate(build["steps"])
        if s.get("uses", "").startswith("actions/upload-artifact")
    )
    assert validate < upload, "only a validated package is handed on"

    package_artifact = build["steps"][upload]["with"]["name"]
    assert jobs["compat"]["uses"] == "./.github/workflows/host-compat.yml"
    assert jobs["compat"]["with"] == {
        "mode": "release",
        "hosts": "openclaw",
        "plugin-artifact": package_artifact,
    }
    assert set(publish["needs"]) == {"build", "compat"}
    # The bytes published are the bytes checked.
    assert re.search(r'RELEASE_PY\}?" verify --release ', run_text(publish))


def test_the_1x_full_eval_gate_is_gone():
    text = WORKFLOW.read_text()
    assert "full-eval" not in text and "require_full_eval" not in text


def test_a_tampered_artifact_is_refused(tmp_path):
    d = plugin(tmp_path)
    info = release.pack(d, tmp_path / "out")
    tgz = tmp_path / "out/package" / info["file"]
    tgz.write_bytes(tgz.read_bytes() + b"\0")
    with pytest.raises(release.ReleaseError, match="sha256"):
        release.verify(info, tmp_path / "out/package")


# --- must stay silent -------------------------------------------------------------------------------


def test_a_dry_run_on_a_valid_tree_checks_packs_and_publishes_nothing(tmp_path):
    d = plugin(tmp_path)
    meta = release.check(d, "next")
    assert meta == {
        "name": release.PACKAGE_NAME,
        "version": "2.1.0-beta.1",
        "tag": "next",
        "clawhub_tag": "beta",
    }
    info = release.pack(d, tmp_path / "out")
    tgz = tmp_path / "out/package" / info["file"]
    assert info["version"] == "2.1.0-beta.1" and tgz.is_file()
    assert (tmp_path / "out/release.json").read_text() == json.dumps(info, indent=2) + "\n"
    release.verify(
        info, tmp_path / "out/package"
    )  # the publish job's check passes on the same bytes
    with tarfile.open(tgz) as t:
        assert "package/CHANGELOG.md" in t.getnames()
    ok, lines = release.validate_report(CLEAN_REPORT)
    assert ok and lines[0].startswith("Plugin Inspector: pass")

    # The workflow: on a dry run the publish job does not run, and nothing before it publishes.
    jobs = workflow()["jobs"]
    assert "!inputs.dry_run" in jobs["publish"]["if"].replace(" ", "")
    assert jobs["publish"]["environment"] == "release-npm"
    for name, job in jobs.items():
        if name == "publish" or "steps" not in job:
            continue
        text = run_text(job)
        assert "npm publish" not in text, name
        assert "gh release" not in text, name
        for line in text.splitlines():
            if "package publish" in line:
                assert "--dry-run" in line, f"{name}: {line}"
        assert "id-token" not in json.dumps(job.get("permissions", {})), name


def test_stable_goes_to_latest_on_both_stores(tmp_path):
    meta = release.check(plugin(tmp_path, version="2.1.0"), "latest")
    assert (meta["tag"], meta["clawhub_tag"]) == ("latest", "latest")


def test_the_release_notes_are_the_changelog_entry(tmp_path):
    d = plugin(tmp_path)
    notes = release.notes(release.check(d, "next"), d)
    assert "- A fix." in notes
    assert f"openclaw plugins install npm:{release.PACKAGE_NAME}@next" in notes


def test_the_current_tree_is_releasable():
    """package.json, PLUGIN_VERSION and CHANGELOG.md agree today, on the channel the version implies."""
    version = release.package(release.PLUGIN_DIR)["version"]
    channel = "next" if "-" in version else "latest"
    assert release.check(release.PLUGIN_DIR, channel)["version"] == version


def test_the_changelog_keeps_the_layout_changesets_writes_into():
    """`changeset version` inserts each new entry after the first line: anything between the title and the first
    entry would end up inside the new entry."""
    lines = (release.PLUGIN_DIR / "CHANGELOG.md").read_text().splitlines()
    assert lines[0] == f"# {release.PACKAGE_NAME}"
    first_entry = next(i for i, line in enumerate(lines) if line.startswith("## "))
    assert all(not line.strip() for line in lines[1:first_entry])


def test_the_compat_check_takes_the_packed_artifact():
    """run.sh checks a packed tarball as given (the release's artifact) instead of packing the source again."""
    run_sh = (release.REPO_ROOT / "integrations/openclaw/compat/run.sh").read_text()
    assert re.search(r"\*\.tgz", run_sh)
    assert "the package as given" in run_sh


def test_npm_pack_output_is_what_the_record_names(tmp_path):
    d = plugin(tmp_path)
    info = release.pack(d, tmp_path / "out")
    listed = subprocess.run(
        ["tar", "-tzf", str(tmp_path / "out/package" / info["file"])],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert "package/package.json" in listed
    assert sorted(p.name for p in (tmp_path / "out/package").iterdir()) == [info["file"]]
