"""OpenClaw plugin release: from package.json's version to one packed tarball for ClawHub and npm.

Used by .github/workflows/release-plugin.yml; each step also runs locally. Standard library only, so it runs
with the runner's python3.

    release.py version                       package.json's version
    release.py changelog [--version V]       that version's CHANGELOG entry; exit 1 when there is none
    release.py check --channel next|latest [--github-output F]
        refuses the release unless the package is bound for public npmjs, PLUGIN_VERSION (planir.ts) equals
        package.json's version, the channel fits the version (a prerelease only to next, a stable version only
        to latest), CHANGELOG.md has a non-empty entry for it and the package README (the ClawHub and npm
        listing) carries the disclosure (`docs.REQUIRED_PHRASES`). Prints name, version, tag (the npm dist-tag)
        and clawhub_tag (beta for next, latest for latest) as key=value lines.
    release.py pack --out DIR                runs `npm pack` into DIR/package and writes DIR/release.json (name,
                                             version, file, sha256): the one artifact ClawHub and npm get.
    release.py verify --release F --package DIR
                                             the tarball in DIR is the one release.json records (sha256).
    release.py validate-report FILE          reads `clawhub package validate --json` output; exit 1 unless it
                                             passes with no issues (validate itself exits 0 with findings).
    release.py notes --release F             the GitHub Release notes: the CHANGELOG entry and the install line.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
PLUGIN_DIR = REPO_ROOT / "integrations/openclaw/plugin"
sys.path.insert(0, str(REPO_ROOT / "integrations/docs"))
import docs  # noqa: E402  (the disclosure paragraph every listing carries)

PACKAGE_NAME = "@firstdataunion/sentrook-openclaw"
NPMJS_REGISTRY = "https://registry.npmjs.org"
#: npm dist-tag → ClawHub tag. `openclaw plugins install <name>@beta` is how testers take a prerelease.
CLAWHUB_TAG = {"next": "beta", "latest": "latest"}
PLUGIN_VERSION = re.compile(r'^export const PLUGIN_VERSION = "([^"]+)";', re.M)


class ReleaseError(Exception):
    pass


# --- version and CHANGELOG --------------------------------------------------------------------------


def package(plugin_dir: Path = PLUGIN_DIR) -> dict:
    return json.loads((Path(plugin_dir) / "package.json").read_text())


def plugin_version_constant(plugin_dir: Path = PLUGIN_DIR) -> str:
    m = PLUGIN_VERSION.search((Path(plugin_dir) / "planir.ts").read_text())
    if not m:
        raise ReleaseError('planir.ts: no `export const PLUGIN_VERSION = "...";`')
    return m.group(1)


def changelog_sections(text: str) -> list[tuple[str, str]]:
    """(version, body) for each `## <version>` heading, newest first as written. The same layout as the Hermes
    plugin's CHANGELOG and what `changeset version` writes."""
    parts = re.split(r"^## +v?(\S+)[^\n]*\n", text, flags=re.M)
    return [(parts[i], parts[i + 1].strip()) for i in range(1, len(parts), 2)]


def changelog_entry(text: str, version: str) -> str:
    for v, body in changelog_sections(text):
        if v == version:
            if not body:
                raise ReleaseError(f"CHANGELOG.md: the entry for {version} is empty")
            return body
    raise ReleaseError(
        f"CHANGELOG.md has no entry for {version}: add a `## {version}` section (a changeset does) first"
    )


def check(plugin_dir: Path, channel: str) -> dict:
    """Everything that can refuse a release before anything is built. Returns the publish metadata."""
    plugin_dir = Path(plugin_dir)
    pkg = package(plugin_dir)
    name, version = pkg.get("name"), pkg.get("version")
    if name != PACKAGE_NAME:
        raise ReleaseError(f"unexpected package name {name!r} (want {PACKAGE_NAME})")
    publish = pkg.get("publishConfig") or {}
    if publish.get("registry") != NPMJS_REGISTRY:
        raise ReleaseError(
            f"publishConfig.registry must be {NPMJS_REGISTRY} (got {publish.get('registry')!r})"
        )
    if publish.get("access") != "public":
        raise ReleaseError(f"publishConfig.access must be public (got {publish.get('access')!r})")
    constant = plugin_version_constant(plugin_dir)
    if constant != version:
        raise ReleaseError(
            f"PLUGIN_VERSION {constant} (planir.ts) differs from package.json {version}: "
            "the version the plugin reports must be the one published"
        )
    if channel not in CLAWHUB_TAG:
        raise ReleaseError(f"channel must be one of {', '.join(CLAWHUB_TAG)} (got {channel!r})")
    prerelease = "-" in version
    if channel == "latest" and prerelease:
        raise ReleaseError(f"channel latest refuses the prerelease {version}: use channel next")
    if channel == "next" and not prerelease:
        raise ReleaseError(f"channel next needs a prerelease version (got {version}): use latest")
    changelog = plugin_dir / "CHANGELOG.md"
    if not changelog.exists():
        raise ReleaseError(f"{changelog} is missing")
    changelog_entry(changelog.read_text(), version)
    check_listing(plugin_dir)
    return {"name": name, "version": version, "tag": channel, "clawhub_tag": CLAWHUB_TAG[channel]}


def check_listing(plugin_dir: Path = PLUGIN_DIR) -> None:
    """The package README is the listing ClawHub and npm show: refused unless it carries the disclosure."""
    readme = Path(plugin_dir) / "README.md"
    if not readme.exists():
        raise ReleaseError(f"{readme} is missing: it is the ClawHub and npm listing")
    missing = docs.missing_phrases(readme.read_text())
    if missing:
        raise ReleaseError(
            "the package README (the ClawHub listing) must disclose "
            + ", ".join(repr(p) for p in missing)
        )


# --- the artifact -----------------------------------------------------------------------------------


def sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pack(plugin_dir: Path, out: Path) -> dict:
    """`npm pack` once, into out/package (nothing else in it); the record is out/release.json."""
    plugin_dir, out = Path(plugin_dir), Path(out)
    dest = out / "package"
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ReleaseError(f"{dest} is not empty: the artifact holds exactly one tarball")
    proc = subprocess.run(
        ["npm", "pack", "--pack-destination", str(dest), "--loglevel=error"],
        cwd=plugin_dir,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise ReleaseError(f"npm pack failed: {proc.stderr.strip()[-1000:]}")
    tarballs = sorted(dest.glob("*.tgz"))
    if len(tarballs) != 1:
        raise ReleaseError(f"npm pack wrote {len(tarballs)} tarballs to {dest}")
    pkg = package(plugin_dir)
    info = {
        "name": pkg["name"],
        "version": pkg["version"],
        "file": tarballs[0].name,
        "sha256": sha256(tarballs[0]),
    }
    (out / "release.json").write_text(json.dumps(info, indent=2) + "\n")
    return info


def verify(info: dict, package_dir: Path) -> Path:
    """The tarball about to be published is the one packed and checked."""
    package_dir = Path(package_dir)
    tarballs = sorted(package_dir.glob("*.tgz"))
    if [t.name for t in tarballs] != [info["file"]]:
        raise ReleaseError(
            f"{package_dir} holds {[t.name for t in tarballs]}, want exactly {info['file']}"
        )
    got = sha256(tarballs[0])
    if got != info["sha256"]:
        raise ReleaseError(f"{info['file']}: sha256 {got} is not the packed {info['sha256']}")
    return tarballs[0]


# --- ClawHub validation -----------------------------------------------------------------------------


def validate_report(text: str) -> tuple[bool, list[str]]:
    """(passed, lines to print) from `clawhub package validate --json`; the CLI prints a line before the JSON."""
    start = text.find("{")
    try:
        report = json.loads(text[start:]) if start >= 0 else None
    except json.JSONDecodeError:
        report = None
    if not isinstance(report, dict):
        return False, ["Plugin Inspector: no JSON report in the validate output"]
    s = report.get("summary") or {}
    lines = [
        f"Plugin Inspector: {report.get('status')} breakages={s.get('breakageCount')} "
        f"warnings={s.get('warningCount')} issues={s.get('issueCount')}"
    ]
    issues = report.get("issues") or []
    for i in issues:
        what = i.get("message") or i.get("title") or json.dumps(i)
        lines.append(f"- {i.get('severity', '')} {i.get('code') or i.get('id') or ''}: {what}")
    passed = (
        str(report.get("status")).lower() == "pass"
        and s.get("issueCount") == 0
        and not s.get("breakageCount")
        and not issues
    )
    return passed, lines


# --- release notes ----------------------------------------------------------------------------------


def notes(info: dict, plugin_dir: Path = PLUGIN_DIR) -> str:
    entry = changelog_entry((Path(plugin_dir) / "CHANGELOG.md").read_text(), info["version"])
    tag = "next" if "-" in info["version"] else info["version"]
    return (
        f"## {info['name']}@{info['version']}\n\n{entry}\n\nInstall:\n\n```bash\n"
        f"openclaw plugins install npm:{info['name']}@{tag} --pin --force\n```\n"
    )


# --- CLI --------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--plugin", type=Path, default=PLUGIN_DIR, help="the plugin directory")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    c = sub.add_parser("changelog")
    c.add_argument("--version")
    k = sub.add_parser("check")
    k.add_argument("--channel", required=True)
    k.add_argument("--github-output", type=Path)
    a = sub.add_parser("pack")
    a.add_argument("--out", type=Path, required=True)
    v = sub.add_parser("verify")
    v.add_argument("--release", type=Path, required=True)
    v.add_argument("--package", type=Path, required=True)
    r = sub.add_parser("validate-report")
    r.add_argument("file", type=Path)
    n = sub.add_parser("notes")
    n.add_argument("--release", type=Path, required=True)
    # Global options are accepted after the subcommand too (`check --plugin DIR ...`).
    for sp in (c, k, a, v, r, n):
        sp.add_argument("--plugin", type=Path, default=argparse.SUPPRESS)
    args = p.parse_args(argv)

    try:
        if args.cmd == "version":
            print(package(args.plugin)["version"])
        elif args.cmd == "changelog":
            text = (args.plugin / "CHANGELOG.md").read_text()
            print(changelog_entry(text, args.version or package(args.plugin)["version"]))
        elif args.cmd == "check":
            meta = check(args.plugin, args.channel)
            lines = "".join(f"{k}={v}\n" for k, v in meta.items())
            if args.github_output:
                with args.github_output.open("a") as f:
                    f.write(lines)
            print(lines, end="")
        elif args.cmd == "pack":
            print(json.dumps(pack(args.plugin, args.out), indent=2))
        elif args.cmd == "verify":
            tgz = verify(json.loads(args.release.read_text()), args.package)
            print(f"{tgz.name}: sha256 matches the packed artifact")
        elif args.cmd == "validate-report":
            passed, lines = validate_report(args.file.read_text())
            print("\n".join(lines))
            if not passed:
                raise ReleaseError("ClawHub validate: the package must pass with no findings")
        elif args.cmd == "notes":
            print(notes(json.loads(args.release.read_text()), args.plugin), end="")
    except ReleaseError as e:
        print(f"release: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
