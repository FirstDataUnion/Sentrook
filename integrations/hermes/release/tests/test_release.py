"""The Hermes plugin release: CHANGELOG gate, the mirror commit, the push, the catalog entry and PR text.

A local bare repository stands in for the mirror, so the build, the dry run and the promote run for real.
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import release  # noqa: E402

DATE = "2026-11-18T12:00:00Z"
UPSTREAM = "a" * 40


def git(*args, cwd=None):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def mirror(tmp_path):
    """A bare 'mirror' with an old README, mirror-authored docs and a file the plugin no longer has."""
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "README.md").write_text("# Old README: put the credentials in .env\n")
    (seed / "LICENSE").write_text("Apache License 2.0\n")
    (seed / "SECURITY.md").write_text("Report to security@example.invalid\n")
    (seed / "CONTRIBUTING.md").write_text("Send changes to the monorepo.\n")
    (seed / ".github").mkdir()
    (seed / ".github/pull_request_template.md").write_text("PRs go to the monorepo.\n")
    (seed / "stale_module.py").write_text("OLD = True\n")
    git("init", "-q", "-b", "main", cwd=seed)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=seed)
    git(
        "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "seed", cwd=seed
    )
    bare = tmp_path / "mirror.git"
    git("clone", "-q", "--bare", str(seed), str(bare))
    return bare


def url(bare: Path) -> str:
    return bare.as_uri()


def remote_state(bare: Path) -> dict[str, str]:
    out = git("for-each-ref", "--format=%(refname) %(objectname)", cwd=bare)
    return dict(line.split(" ", 1) for line in out.splitlines())


def build(bare, out, **kw):
    return release.build(url(bare), out, upstream_sha=UPSTREAM, date=DATE, **kw)


def checkout(bare: Path, ref: str, dest: Path) -> Path:
    git("clone", "-q", "--branch", ref, url(bare), str(dest))
    return dest


# --- must fire --------------------------------------------------------------------------------------


def test_a_version_without_a_changelog_entry_is_refused():
    text = "# sentrook\n\n## 2.0.0\n\n- Something.\n"
    with pytest.raises(release.ReleaseError, match="no entry for 2.0.1"):
        release.changelog_entry(text, "2.0.1")
    with pytest.raises(release.ReleaseError, match="empty"):
        release.changelog_entry("## 2.0.1\n\n## 2.0.0\n\n- Old.\n", "2.0.1")


def test_a_dry_run_without_a_changelog_entry_fails_before_building(tmp_path, mirror):
    plugin = tmp_path / "plugin"
    shutil.copytree(
        release.PLUGIN_DIR, plugin, ignore=shutil.ignore_patterns("tests", "__pycache__")
    )
    (plugin / "CHANGELOG.md").write_text("# sentrook\n\n## 0.0.1\n\n- Long ago.\n")
    before = remote_state(mirror)
    with pytest.raises(release.ReleaseError, match="CHANGELOG.md has no entry"):
        build(mirror, tmp_path / "out", plugin_dir=plugin)
    assert not (tmp_path / "out/release.json").exists()
    assert remote_state(mirror) == before


def test_the_cli_exits_nonzero_without_a_changelog_entry(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# sentrook\n\n## 0.0.1\n\n- Long ago.\n")
    assert release.main(["changelog", "--file", str(changelog), "--version", "9.9.9"]) == 1


def test_the_validator_gates_the_tag_and_the_catalog_entry():
    """What gets tagged is the tree the compatibility check validated, and nothing is pushed before it."""
    wf = yaml.safe_load(
        (release.REPO_ROOT / ".github/workflows/release-hermes-plugin.yml").read_text()
    )
    jobs = wf["jobs"]
    tree_artifact = next(
        s["with"]["name"]
        for s in jobs["build"]["steps"]
        if s.get("uses", "").startswith("actions/upload-artifact") and "tree" in s["with"]["name"]
    )
    assert jobs["compat"]["uses"] == "./.github/workflows/host-compat.yml"
    assert jobs["compat"]["with"]["plugin-artifact"] == tree_artifact
    assert jobs["compat"]["with"]["mode"] == "release"
    assert {"build", "compat"} <= set(jobs["promote"]["needs"])
    assert "compat" in jobs["catalog"]["needs"] and "promote" in jobs["catalog"]["needs"]
    assert "!inputs.dry_run" in jobs["promote"]["if"].replace(" ", "")

    # Only the promote job pushes, and only it can read the mirror token.
    for name, job in jobs.items():
        text = json.dumps(job)
        if name != "promote":
            assert "MIRROR_GITHUB_TOKEN" not in text and "release.py push" not in text, name
    assert "release.py push" in json.dumps(jobs["promote"])

    # host-compat.yml runs the check on that artifact when it is given one: downloaded to the path the
    # check is pointed at, and passed to run.sh as its plugin directory.
    compat = yaml.safe_load((release.REPO_ROOT / ".github/workflows/host-compat.yml").read_text())
    assert "plugin-artifact" in compat[True]["workflow_call"]["inputs"]  # `on:` parses as True
    steps = compat["jobs"]["compat"]["steps"]
    download = next(s for s in steps if s.get("uses", "").startswith("actions/download-artifact"))
    check = next(s for s in steps if s.get("name") == "Compatibility check")
    assert download["with"]["name"] == "${{ inputs.plugin-artifact }}"
    assert download["with"]["path"] == "${{ runner.temp }}/plugin-tree"
    assert "format('{0}/plugin-tree', runner.temp)" in check["env"]["PLUGIN_TREE"]
    assert re.search(r'run\.sh "\$\{\{ matrix\.image \}\}" "\$PLUGIN_TREE"', check["run"])
    # ...and a release with nothing to check fails instead of skipping the check.
    plan = compat["jobs"]["plan"]["steps"][-1]["run"]
    assert '"$MODE" = release ] && [ "$blocking" = \'[]\' ]' in plan


def test_the_catalog_entry_pins_a_full_sha_and_the_manifest_version(tmp_path, mirror):
    info = build(mirror, tmp_path / "out")
    out = tmp_path / "catalog"
    release.write_catalog(info, out)
    entry = yaml.safe_load((out / "plugin-catalog/sentrook.yaml").read_text())
    manifest = release.manifest()
    assert re.fullmatch(r"[0-9a-f]{40}", entry["sha"])
    assert entry["sha"] == info["sha"]
    assert entry["version"] == manifest["version"]
    assert entry["requires_hermes"] == manifest["requires_hermes"]
    assert entry["repo"] == "https://github.com/FirstDataUnion/Sentrook-hermes"
    assert entry["capabilities"]["provides_hooks"] == manifest["provides_hooks"]
    assert entry["capabilities"]["requires_env"] == [e["name"] for e in manifest["requires_env"]]
    # Quoted, as the catalog asks: a bare 2.0 would read as a number.
    text = (out / "plugin-catalog/sentrook.yaml").read_text()
    assert f'version: "{manifest["version"]}"' in text


@pytest.mark.parametrize("sha", ["abc123", "A" * 40, "g" * 40, "a" * 39])
def test_the_entry_refuses_anything_but_a_full_sha(sha):
    with pytest.raises(release.ReleaseError, match="40"):
        release.catalog_entry({"sha": sha, "version": release.manifest()["version"]})


def test_the_entry_refuses_a_version_other_than_the_manifests():
    with pytest.raises(release.ReleaseError, match="version"):
        release.catalog_entry({"sha": "b" * 40, "version": "0.0.1"})


def test_push_refuses_when_the_mirror_moved_after_the_build(tmp_path, mirror):
    info = build(mirror, tmp_path / "out")
    other = checkout(mirror, "main", tmp_path / "other")
    (other / "LICENSE").write_text("changed on the mirror\n")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qam", "x", cwd=other)
    git("push", "-q", "origin", "main", cwd=other)
    before = remote_state(mirror)
    with pytest.raises(release.ReleaseError, match="moved"):
        release.push(url(mirror), info, tmp_path / "push")
    assert remote_state(mirror) == before


def test_a_prerelease_is_a_tag_only(tmp_path, mirror):
    main_before = remote_state(mirror)["refs/heads/main"]
    info = build(mirror, tmp_path / "out")
    release.push(url(mirror), info, tmp_path / "push", tag_only=True)
    state = remote_state(mirror)
    assert state["refs/heads/main"] == main_before
    tag = f"refs/tags/hermes-plugin-v{release.manifest()['version']}"
    assert git("rev-parse", f"{tag}^{{commit}}", cwd=mirror) == info["sha"]


def test_an_unquoted_numeric_version_is_refused(tmp_path, mirror):
    plugin = tmp_path / "plugin"
    shutil.copytree(
        release.PLUGIN_DIR, plugin, ignore=shutil.ignore_patterns("tests", "__pycache__")
    )
    manifest = (plugin / "plugin.yaml").read_text()
    (plugin / "plugin.yaml").write_text(
        re.sub(r"^version: .*$", "version: 2.1", manifest, flags=re.M)
    )
    with pytest.raises(release.ReleaseError, match="quoted string"):
        build(mirror, tmp_path / "out", plugin_dir=plugin)


def test_push_never_moves_an_existing_tag(tmp_path, mirror):
    info = build(mirror, tmp_path / "out")
    release.push(url(mirror), info, tmp_path / "push")
    again = build(mirror, tmp_path / "out2")
    with pytest.raises(release.ReleaseError, match="already exists"):
        release.push(url(mirror), again, tmp_path / "push2")


# --- must stay silent -------------------------------------------------------------------------------


def test_a_dry_run_produces_the_entry_and_pr_body_and_pushes_nothing(tmp_path, mirror):
    before = remote_state(mirror)
    out = tmp_path / "out"
    assert (
        release.main(
            [
                "build",
                "--mirror",
                url(mirror),
                "--out",
                str(out),
                "--upstream-sha",
                UPSTREAM,
                "--date",
                DATE,
            ]
        )
        == 0
    )
    info = json.loads((out / "release.json").read_text())
    assert info["changed"] is True and re.fullmatch(r"[0-9a-f]{40}", info["sha"])
    assert (out / "tree/plugin.yaml").exists()

    cat = tmp_path / "catalog"
    assert release.main(["catalog", "--release", str(out / "release.json"), "--out", str(cat)]) == 0
    assert yaml.safe_load((cat / "plugin-catalog/sentrook.yaml").read_text())["sha"] == info["sha"]
    body = (cat / "pr-body.md").read_text()
    assert info["sha"] in body and "Disclosures" in body
    assert (cat / "pr-title.txt").read_text().strip()

    assert remote_state(mirror) == before


def test_after_promote_the_mirror_readme_is_the_monorepo_readme(tmp_path, mirror):
    info = build(mirror, tmp_path / "out")
    pushed = release.push(url(mirror), info, tmp_path / "push")
    assert pushed == info["sha"]

    tip = checkout(mirror, "main", tmp_path / "tip")
    assert git("rev-parse", "HEAD", cwd=tip) == info["sha"]
    assert (tip / "README.md").read_bytes() == release.README.read_bytes()
    assert (tip / "CHANGELOG.md").read_bytes() == (release.PLUGIN_DIR / "CHANGELOG.md").read_bytes()
    # Mirror-authored docs stay; the plugin replaces everything else, without its tests.
    assert (tip / "LICENSE").read_text() == "Apache License 2.0\n"
    assert (tip / "SECURITY.md").exists() and (tip / "CONTRIBUTING.md").exists()
    assert (tip / ".github/pull_request_template.md").exists()
    assert not (tip / "stale_module.py").exists()
    assert not (tip / "tests").exists() and (tip / "plugin.yaml").exists()
    assert f"upstream_sha={UPSTREAM}" in (tip / ".release-mirror").read_text()

    tag = f"refs/tags/hermes-plugin-v{release.manifest()['version']}"
    assert git("rev-parse", f"{tag}^{{commit}}", cwd=mirror) == info["sha"]


def test_the_build_is_the_commit_that_gets_pushed(tmp_path, mirror):
    """The dry run's sha is the sha a promote of the same build pushes, so the reviewed entry is exact."""
    a = build(mirror, tmp_path / "a")
    b = build(mirror, tmp_path / "b")
    assert a["sha"] == b["sha"]


def test_the_current_version_has_a_changelog_entry():
    text = (release.PLUGIN_DIR / "CHANGELOG.md").read_text()
    assert release.changelog_entry(text, release.manifest()["version"]).strip()


# --- the catalog PR ---------------------------------------------------------------------------------


def previous_entry(tmp_path, version="2.0.0-beta.9", sha="c" * 40) -> Path:
    path = tmp_path / "previous.yaml"
    path.write_text(f'name: sentrook\nsha: {sha}\nversion: "{version}"\n')
    return path


def info_for(version=None, sha="d" * 40) -> dict:
    return {"sha": sha, "version": version or release.manifest()["version"], "parent": "e" * 40}


def test_a_first_submission_reads_as_one(tmp_path):
    title, body = release.catalog_pr(info_for(), previous=None, previous_readme=None)
    assert title.startswith("Add plugin-catalog/sentrook.yaml")
    assert "Disclosures" in body and "Hermes surfaces used" in body


def test_a_bump_lists_the_changes_since_the_pinned_version_and_the_commit_range(tmp_path):
    # The release is always plugin.yaml's version, so the newest entry follows it.
    current = release.manifest()["version"]
    changelog = (
        f"# sentrook\n\n## {current}\n\n- Newest.\n\n## 2.0.0-beta.12\n\n- Twelve.\n\n"
        "## 2.0.0-beta.9\n\n- Nine.\n"
    )
    title, body = release.catalog_pr(
        info_for(),
        previous=yaml.safe_load(previous_entry(tmp_path).read_text()),
        previous_readme=release.README.read_text(),
        changelog=changelog,
    )
    assert title == f"sentrook: 2.0.0-beta.9 → {current}"
    assert "Newest" in body and "Twelve" in body and "Nine" not in body
    assert f"compare/{'c' * 40}...{'d' * 40}" in body
    assert "Disclosures: unchanged" in body


def test_a_bump_flags_a_changed_disclosure(tmp_path):
    old = release.README.read_text().replace(
        "## What is sent", "## What is sent\n\nAn older sentence about what is sent.", 1
    )
    _, body = release.catalog_pr(
        info_for(),
        previous=yaml.safe_load(previous_entry(tmp_path).read_text()),
        previous_readme=old,
    )
    assert "Disclosures changed" in body and "What is sent" in body


def test_a_security_fix_is_flagged_in_the_title(tmp_path):
    title, body = release.catalog_pr(
        info_for(),
        previous=yaml.safe_load(previous_entry(tmp_path).read_text()),
        previous_readme=release.README.read_text(),
        security_fix=True,
    )
    assert title.startswith("Security fix: sentrook:")
    assert "security fix" in body.lower()
