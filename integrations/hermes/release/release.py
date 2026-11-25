"""Hermes plugin release: from plugin.yaml's version to the mirror tag and the catalog SHA-bump PR text.

Used by .github/workflows/release-hermes-plugin.yml; each step also runs locally.

    release.py version                       plugin.yaml's version
    release.py changelog [--version V]       that version's CHANGELOG entry; exit 1 when there is none
    release.py build --mirror URL --out DIR --upstream-sha SHA [--date ISO]
        clones the mirror, replaces its content with the plugin as published (no tests), the monorepo's
        README and CHANGELOG, keeping the mirror-authored LICENSE, SECURITY.md, CONTRIBUTING.md and .github,
        and commits it locally. Writes DIR/release.json (version, tag, parent, sha, ...) and DIR/tree (the
        commit's files, what the compatibility check validates). Pushes nothing.
    release.py push --mirror URL --release release.json --out DIR
        rebuilds the same commit, checks it is the one built (same parent, same sha), pushes it to the
        mirror's main and tags it hermes-plugin-v<version>. Refuses if the mirror moved or the tag exists.
    release.py catalog --release release.json --out DIR [--previous-entry F] [--previous-readme F]
                       [--security-fix]
        writes DIR/plugin-catalog/sentrook.yaml, DIR/pr-title.txt and DIR/pr-body.md for the catalog PR.
        With the catalog's current entry (and the mirror README at its sha) it is a SHA bump: the changes
        since that version, the commit range, and any change to the disclosures or capabilities.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
PLUGIN_DIR = REPO_ROOT / "integrations/hermes/plugin"
README = REPO_ROOT / "integrations/hermes/README.md"
VERSIONS = REPO_ROOT / "integrations/hermes/compat/versions.txt"
ENTRY_TEMPLATE = HERE / "catalog-entry.yaml"
ADD_PR_TEMPLATE = HERE / "catalog-pr-add.md"

UPSTREAM_REPO = "FirstDataUnion/Sentrook"
MIRROR_REPO = "FirstDataUnion/Sentrook-hermes"
#: Authored on the mirror itself; a promote keeps them. Everything else comes from the monorepo.
MIRROR_AUTHORED = ("LICENSE", "SECURITY.md", "CONTRIBUTING.md", ".github")
#: Not published: the plugin's tests and build leftovers.
NOT_PUBLISHED = ("tests", "__pycache__", "*.pyc", "*.pyo", "*.pyd", ".pytest_cache")
#: The README sections a catalog reviewer reads as the plugin's disclosures (rule 13).
DISCLOSURE_SECTIONS = ("What is sent", "What the plugin does on your machine")
BOT = ("Sentrook Release Bot", "noreply@firstdataunion.org")
SHA = re.compile(r"[0-9a-f]{40}")


class ReleaseError(Exception):
    pass


# --- version and CHANGELOG --------------------------------------------------------------------------


def manifest(plugin_dir: Path = PLUGIN_DIR) -> dict:
    return yaml.safe_load((plugin_dir / "plugin.yaml").read_text())


def tag_for(version: str) -> str:
    return f"hermes-plugin-v{version}"


def changelog_sections(text: str) -> list[tuple[str, str]]:
    """(version, body) for each `## <version>` heading, newest first as written."""
    parts = re.split(r"^## +v?(\S+)[^\n]*\n", text, flags=re.M)
    return [(parts[i], parts[i + 1].strip()) for i in range(1, len(parts), 2)]


def changelog_entry(text: str, version: str) -> str:
    for v, body in changelog_sections(text):
        if v == version:
            if not body:
                raise ReleaseError(f"CHANGELOG.md: the entry for {version} is empty")
            return body
    raise ReleaseError(
        f"CHANGELOG.md has no entry for {version}: add a `## {version}` section first"
    )


def changelog_since(text: str, version: str, previous: str | None) -> list[tuple[str, str]]:
    """The entries from `version` down to, not including, `previous` (all from `version` if absent)."""
    sections = changelog_sections(text)
    versions = [v for v, _ in sections]
    if version not in versions:
        raise ReleaseError(f"CHANGELOG.md has no entry for {version}")
    start = versions.index(version)
    end = versions.index(previous) if previous in versions[start:] else None
    picked = sections[start:end] if end is not None else sections[start : start + 1]
    return [(v, b) for v, b in picked if b]


# --- the mirror commit ------------------------------------------------------------------------------


def git(*args: str, cwd: Path | None = None, env: dict | None = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
    )
    if proc.returncode != 0:
        # The mirror URL may carry a token: never echo the command line.
        raise ReleaseError(f"git {args[0]} failed: {proc.stderr.strip()[-500:]}")
    return proc.stdout.strip()


def _replace_content(work: Path, plugin_dir: Path, readme: Path, provenance: str) -> None:
    keep = Path(tempfile.mkdtemp())
    try:
        for name in MIRROR_AUTHORED:
            src = work / name
            if src.is_dir():
                shutil.copytree(src, keep / name, symlinks=True)
            elif src.exists():
                shutil.copy2(src, keep / name)
        for child in work.iterdir():
            if child.name == ".git":
                continue
            shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
        shutil.copytree(
            plugin_dir, work, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*NOT_PUBLISHED)
        )
        shutil.copy2(readme, work / "README.md")
        for child in keep.iterdir():
            dest = work / child.name
            if child.is_dir():
                shutil.copytree(child, dest, symlinks=True)
            else:
                shutil.copy2(child, dest)
        (work / ".release-mirror").write_text(provenance)
    finally:
        shutil.rmtree(keep)


def build(
    mirror_url: str,
    out: Path,
    *,
    upstream_sha: str,
    date: str,
    plugin_dir: Path = PLUGIN_DIR,
    readme: Path = README,
) -> dict:
    """The mirror commit for this release, built locally; nothing is pushed. Same inputs, same sha."""
    out = Path(out)
    version = manifest(plugin_dir)["version"]
    if not isinstance(version, str):
        # The catalog entry quotes the version; 2.1 unquoted in plugin.yaml would read as a number.
        raise ReleaseError(
            f'plugin.yaml version {version!r} must be a quoted string, e.g. "{version}"'
        )
    changelog = plugin_dir / "CHANGELOG.md"
    if not changelog.exists():
        raise ReleaseError(f"{changelog} is missing")
    changelog_entry(changelog.read_text(), version)  # refuses before anything is built

    out.mkdir(parents=True, exist_ok=True)
    work = out / "mirror"
    if work.exists():
        shutil.rmtree(work)
    git("clone", "--quiet", "--depth", "1", "--branch", "main", mirror_url, str(work))
    parent = git("rev-parse", "HEAD", cwd=work)

    provenance = (
        f"upstream_repo={UPSTREAM_REPO}\n"
        "upstream_path=integrations/hermes/plugin\n"
        f"upstream_sha={upstream_sha}\n"
        f"plugin_version={version}\n"
        f"promoted_at_utc={date}\n"
    )
    _replace_content(work, plugin_dir, readme, provenance)
    git("add", "-A", cwd=work)
    changed = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=work).returncode != 0
    if changed:
        identity = {
            "GIT_AUTHOR_NAME": BOT[0],
            "GIT_AUTHOR_EMAIL": BOT[1],
            "GIT_COMMITTER_NAME": BOT[0],
            "GIT_COMMITTER_EMAIL": BOT[1],
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_DATE": date,
        }
        message = (
            f"release: promote Sentrook Hermes plugin v{version}\n\n"
            f"Upstream: {UPSTREAM_REPO}@{upstream_sha}\n"
            "Source: integrations/hermes/plugin\n"
        )
        git(
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--no-verify",
            "-m",
            message,
            cwd=work,
            env=identity,
        )
    sha = git("rev-parse", "HEAD", cwd=work)

    tree = out / "tree"
    if tree.exists():
        shutil.rmtree(tree)
    shutil.copytree(work, tree, symlinks=True, ignore=shutil.ignore_patterns(".git"))

    info = {
        "version": version,
        "tag": tag_for(version),
        "parent": parent,
        "sha": sha,
        "changed": changed,
        "upstream_sha": upstream_sha,
        "date": date,
    }
    (out / "release.json").write_text(json.dumps(info, indent=2) + "\n")
    return info


def push(mirror_url: str, info: dict, out: Path, *, tag_only: bool = False) -> str:
    """Pushes the commit `build` made (rebuilt here and checked) and tags it. Returns its sha.

    With `tag_only` (a pre-release) the mirror's main stays where it is: only the tag, and with it the
    commit, is pushed, so `hermes plugins install` without a pin keeps getting the last release.
    """
    again = build(mirror_url, out, upstream_sha=info["upstream_sha"], date=info["date"])
    if again["parent"] != info["parent"]:
        raise ReleaseError(
            f"the mirror's main moved since the build ({info['parent'][:12]} → {again['parent'][:12]}): "
            "run the release again"
        )
    if again["sha"] != info["sha"]:
        raise ReleaseError(
            f"the rebuilt commit {again['sha'][:12]} is not the one validated ({info['sha'][:12]})"
        )
    work = Path(out) / "mirror"
    tag = info["tag"]
    if git("ls-remote", "--tags", mirror_url, f"refs/tags/{tag}", cwd=work):
        raise ReleaseError(
            f"tag {tag} already exists on the mirror: bump the version in plugin.yaml"
        )
    if info["changed"] and not tag_only:
        git("push", "--quiet", mirror_url, f"{info['sha']}:refs/heads/main", cwd=work)
    identity = {"GIT_COMMITTER_NAME": BOT[0], "GIT_COMMITTER_EMAIL": BOT[1]}
    git(
        "-c",
        "tag.gpgsign=false",
        "tag",
        "-a",
        tag,
        info["sha"],
        "-m",
        f"Sentrook Hermes plugin {info['version']} (upstream {info['upstream_sha']})",
        cwd=work,
        env=identity,
    )
    git("push", "--quiet", mirror_url, f"refs/tags/{tag}", cwd=work)
    return info["sha"]


# --- the catalog entry and PR -----------------------------------------------------------------------


def _scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    # A JSON string is a YAML double-quoted scalar: versions stay strings, nothing needs escaping by hand.
    return json.dumps(value, ensure_ascii=False)


def render_entry(entry: dict) -> str:
    lines = []
    for key, value in entry.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for k, v in value.items():
                lines.append(f"  {k}: {_scalar(v) if not isinstance(v, list) else json.dumps(v)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                lines += [f"  - {_scalar(v)}" for v in value]
        else:
            lines.append(f"{key}: {_scalar(value)}")
    return "\n".join(lines) + "\n"


def catalog_entry(info: dict, plugin_dir: Path = PLUGIN_DIR) -> dict:
    m = manifest(plugin_dir)
    if not SHA.fullmatch(info["sha"]):
        raise ReleaseError(
            f"the catalog pins a full 40-character lowercase sha, not {info['sha']!r}"
        )
    if info["version"] != m["version"]:
        raise ReleaseError(f"release version {info['version']} is not plugin.yaml's {m['version']}")
    if not re.fullmatch(r">=\d+\.\d+\.\d+", str(m.get("requires_hermes", ""))):
        raise ReleaseError("plugin.yaml's requires_hermes must be a SemVer floor such as >=0.23.0")
    template = yaml.safe_load(ENTRY_TEMPLATE.read_text())
    if template["name"] != m["name"]:
        raise ReleaseError(f"catalog name {template['name']} is not plugin.yaml's {m['name']}")
    entry: dict = {}
    for key, value in template.items():
        entry[key] = value
        if key == "repo":
            entry["sha"] = info["sha"]
        if key == "subdir":
            entry["version"] = m["version"]
    entry["requires_hermes"] = m["requires_hermes"]
    known = list(template.get("known_issues", []))
    if "-" in m["version"]:
        known.append(f"Pre-release: {m['version']}.")
    entry["known_issues"] = known
    entry["capabilities"] = {
        "provides_tools": list(m.get("provides_tools", [])),
        "provides_hooks": list(m.get("provides_hooks", [])),
        "provides_middleware": template["capabilities"].get("provides_middleware", []),
        "requires_env": [e["name"] for e in m.get("requires_env", [])],
    }
    # Field order as in the catalog's schema.
    order = [
        "name",
        "title",
        "repo",
        "sha",
        "subdir",
        "version",
        "description",
        "maintainer",
        "tier",
        "category",
        "requires_hermes",
        "docs_url",
        "readme",
        "platforms",
        "known_issues",
        "capabilities",
    ]
    return {k: entry[k] for k in order if k in entry} | {
        k: v for k, v in entry.items() if k not in order
    }


def readme_section(text: str, title: str) -> str:
    m = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)", text, flags=re.M | re.S)
    return m[1].strip() if m else ""


def _checks() -> str:
    pinned = dict(
        line.split()[:2]
        for line in VERSIONS.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    )
    return (
        f"On Hermes {pinned['floor']} (the declared floor) and {pinned['latest']} (the latest release), the "
        "pinned tree passes `hermes plugins validate --install-deps` (every warning a known one), installs "
        "with `hermes plugins install … --enable`, takes its credentials through `hermes config set`, passes "
        "`hermes sentrook verify` against a mock identity service and scanner, and in one real agent turn "
        "blocks one terminal call and allows the next."
    )


def _changes(entries: list[tuple[str, str]]) -> str:
    return "\n\n".join(f"### {v}\n\n{b}" for v, b in entries)


def catalog_pr(
    info: dict,
    *,
    previous: dict | None,
    previous_readme: str | None,
    changelog: str | None = None,
    security_fix: bool = False,
    plugin_dir: Path = PLUGIN_DIR,
) -> tuple[str, str]:
    """(title, body) of the catalog PR: a first submission, or a SHA bump from `previous`."""
    m = manifest(plugin_dir)
    changelog = changelog if changelog is not None else (plugin_dir / "CHANGELOG.md").read_text()
    version, sha = info["version"], info["sha"]
    fix = "Security fix: " if security_fix else ""
    fix_note = (
        "**This is a security fix**, released on its own so it can be reviewed without other changes.\n\n"
        if security_fix
        else ""
    )

    if previous is None:
        body = ADD_PR_TEMPLATE.read_text()
        values = {
            "hooks": ", ".join(f"`{h}`" for h in m.get("provides_hooks", [])),
            "requires_env": ", ".join(f"`{e['name']}`" for e in m.get("requires_env", [])),
            "version": version,
            "changelog": changelog_entry(changelog, version),
            "checks": _checks(),
            "sha": sha,
            "tag": tag_for(version),
        }
        for key, value in values.items():
            body = body.replace("{{" + key + "}}", value)
        return (
            f"{fix}Add plugin-catalog/sentrook.yaml: Sentrook, a tool-call security scanner",
            fix_note + body,
        )

    old_version, old_sha = str(previous.get("version", "")), str(previous.get("sha", ""))
    lines = [
        fix_note.rstrip("\n"),
        f"Moves `sentrook` from {old_version} (`{old_sha[:12]}`) to {version} (`{sha[:12]}`), tag "
        f"`{tag_for(version)}` on {MIRROR_REPO}.",
        "",
        f"Commit range: https://github.com/{MIRROR_REPO}/compare/{old_sha}...{sha}",
        "",
        "**Changes**",
        "",
        _changes(changelog_since(changelog, version, old_version)),
        "",
    ]

    old_caps = previous.get("capabilities") or {}
    new_caps = catalog_entry(info, plugin_dir)["capabilities"]
    cap_diff = [
        f"- `{key}`: {', '.join(old_caps.get(key) or []) or 'none'} → {', '.join(new_caps[key]) or 'none'}"
        for key in new_caps
        if "capabilities" in previous and list(old_caps.get(key) or []) != list(new_caps[key])
    ]
    lines += (
        ["**Capabilities: changed**", "", *cap_diff, ""]
        if cap_diff
        else ["**Capabilities: unchanged**", ""]
    )

    readme = README.read_text()
    changed = [
        title
        for title in DISCLOSURE_SECTIONS
        if previous_readme is None
        or readme_section(readme, title) != readme_section(previous_readme, title)
    ]
    if previous_readme is None:
        lines += [
            "**Disclosures:** the README at the previous sha was not available; the sections below are "
            "the current ones.",
            "",
        ]
    elif changed:
        lines += ["**Disclosures changed** in the README since the pinned version:", ""]
    else:
        lines += [
            "**Disclosures: unchanged** (the README's "
            + " and ".join(f'"{t}"' for t in DISCLOSURE_SECTIONS)
            + " sections).",
            "",
        ]
    for title in changed:
        lines += [
            f"<details><summary>{title} (now)</summary>",
            "",
            readme_section(readme, title),
            "",
            "</details>",
            "",
        ]
    lines += [f"**Checks.** {_checks()}", ""]
    body = "\n".join(line for line in lines if line is not None).lstrip("\n")
    return f"{fix}sentrook: {old_version} → {version}", body


def write_catalog(
    info: dict,
    out: Path,
    *,
    previous: dict | None = None,
    previous_readme: str | None = None,
    security_fix: bool = False,
) -> None:
    out = Path(out)
    entry = render_entry(catalog_entry(info))
    yaml.safe_load(entry)  # it must read back
    title, body = catalog_pr(
        info, previous=previous, previous_readme=previous_readme, security_fix=security_fix
    )
    (out / "plugin-catalog").mkdir(parents=True, exist_ok=True)
    (out / "plugin-catalog/sentrook.yaml").write_text(entry)
    (out / "pr-title.txt").write_text(title + "\n")
    (out / "pr-body.md").write_text(body)


# --- CLI --------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    c = sub.add_parser("changelog")
    c.add_argument("--file", type=Path, default=PLUGIN_DIR / "CHANGELOG.md")
    c.add_argument("--version")
    b = sub.add_parser("build")
    b.add_argument("--mirror", required=True)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--upstream-sha", required=True)
    b.add_argument("--date")
    u = sub.add_parser("push")
    u.add_argument("--mirror", default=os.environ.get("MIRROR_URL"))
    u.add_argument("--release", type=Path, required=True)
    u.add_argument("--out", type=Path, required=True)
    u.add_argument("--tag-only", action="store_true", help="a pre-release: tag, leave main alone")
    k = sub.add_parser("catalog")
    k.add_argument("--release", type=Path, required=True)
    k.add_argument("--out", type=Path, required=True)
    k.add_argument("--previous-entry", type=Path)
    k.add_argument("--previous-readme", type=Path)
    k.add_argument("--security-fix", action="store_true")
    args = p.parse_args(argv)

    try:
        if args.cmd == "version":
            print(manifest()["version"])
        elif args.cmd == "changelog":
            print(changelog_entry(args.file.read_text(), args.version or manifest()["version"]))
        elif args.cmd == "build":
            date = (
                args.date
                or subprocess.run(
                    ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()
            )
            print(
                json.dumps(
                    build(args.mirror, args.out, upstream_sha=args.upstream_sha, date=date),
                    indent=2,
                )
            )
        elif args.cmd == "push":
            if not args.mirror:
                raise ReleaseError("no mirror URL (--mirror or MIRROR_URL)")
            info = json.loads(args.release.read_text())
            print(push(args.mirror, info, args.out, tag_only=args.tag_only))
        elif args.cmd == "catalog":
            previous = None
            if (
                args.previous_entry
                and args.previous_entry.exists()
                and args.previous_entry.stat().st_size
            ):
                previous = yaml.safe_load(args.previous_entry.read_text())
            previous_readme = None
            if (
                args.previous_readme
                and args.previous_readme.exists()
                and args.previous_readme.stat().st_size
            ):
                previous_readme = args.previous_readme.read_text()
            write_catalog(
                json.loads(args.release.read_text()),
                args.out,
                previous=previous,
                previous_readme=previous_readme,
                security_fix=args.security_fix,
            )
            print((args.out / "pr-title.txt").read_text().strip())
    except ReleaseError as e:
        print(f"release: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
