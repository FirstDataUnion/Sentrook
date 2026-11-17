"""Host compatibility CI helpers, shared by every host plugin. Stdlib only.

Each host has a directory (for Hermes, `integrations/hermes/compat/`) with:

- `versions.txt`: the pinned versions the blocking check runs on, one `<role> <tag>` per line. `floor`
  is the oldest host version the plugin declares; `latest` is the newest stable release. The bump job
  moves `latest`; a person moves `floor` together with the plugin's declared minimum.
- `warnings-baseline.txt`: the host validator's warnings the plugin is known to raise, normalised
  (line numbers dropped). A warning not in it fails the blocking check.
- `run.sh <image>`: the check itself, against one host image.

Subcommands (`python3 integrations/compat/compat.py <cmd> --help`):

- `matrix`: the GitHub Actions matrix for the blocking set (floor, latest) or the canary set (main,
  and the newest release candidate when it is newer than latest).
- `warnings`: compare a validator report's warnings with the baseline.
- `latest` / `bump`: the newest stable release; move `latest` and the install guide's "Tested on" line.
- `canary-issue`: open, update or close the one issue that tracks a failing canary target.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

Version = tuple[int, int, int]


@dataclass(frozen=True)
class Host:
    name: str
    title: str
    image: str
    compat_dir: Path
    readme: Path
    stable_tag: re.Pattern[str]
    rc_tag: re.Pattern[str]
    main_tag: str


HOSTS = {
    "hermes": Host(
        name="hermes",
        title="Hermes",
        image="nousresearch/hermes-agent",
        compat_dir=REPO_ROOT / "integrations/hermes/compat",
        readme=REPO_ROOT / "integrations/hermes/README.md",
        # Release images are vX.Y.Z; release candidates rc.N-vX.Y.Z, named for the release they lead to.
        # Arch and -desktop variants carry a suffix and are skipped.
        stable_tag=re.compile(r"^v(\d+)\.(\d+)\.(\d+)$"),
        rc_tag=re.compile(r"^rc\.(\d+)-v(\d+)\.(\d+)\.(\d+)$"),
        main_tag="main",
    ),
}

#: The install guide's tested-versions sentence; the bump keeps it equal to versions.txt.
TESTED_ON = re.compile(r"Tested on (v\d+\.\d+\.\d+) and (v\d+\.\d+\.\d+)\.")


# --- versions ---------------------------------------------------------------------------------------


def stable_version(host: Host, tag: str) -> Version | None:
    m = host.stable_tag.match(tag)
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def rc_version(host: Host, tag: str) -> tuple[Version, int] | None:
    """(the release it leads to, the rc number)."""
    m = host.rc_tag.match(tag)
    return ((int(m[2]), int(m[3]), int(m[4])), int(m[1])) if m else None


def read_versions(path: Path) -> dict[str, str]:
    roles: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        role, tag = line.split()
        roles[role] = tag
    missing = {"floor", "latest"} - roles.keys()
    if missing:
        raise ValueError(f"{path}: missing {', '.join(sorted(missing))}")
    return roles


def newest_stable(host: Host, tags: Iterable[str]) -> str | None:
    found = [(v, t) for t in tags if (v := stable_version(host, t))]
    return max(found)[1] if found else None


def newest_rc(host: Host, tags: Iterable[str], latest: str) -> str | None:
    """The newest release candidate for a release newer than `latest`, or None."""
    floor = stable_version(host, latest)
    if floor is None:
        raise ValueError(f"latest is not a release tag: {latest}")
    found = [(r, t) for t in tags if (r := rc_version(host, t)) and r[0] > floor]
    return max(found)[1] if found else None


def docker_hub_tags(image: str, pages: int = 5) -> list[str]:
    """Recently updated tags of a public Docker Hub image, newest first."""
    url: str | None = (
        f"https://hub.docker.com/v2/repositories/{image}/tags?page_size=100&ordering=last_updated"
    )
    tags: list[str] = []
    for _ in range(pages):
        if not url:
            break
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - fixed https host
            doc = json.load(resp)
        tags += [r["name"] for r in doc.get("results", [])]
        url = doc.get("next")
    return tags


def matrix(host: Host, which: str, tags: Iterable[str] | None = None) -> list[dict[str, str]]:
    """GitHub Actions matrix entries: {host, name, image}."""
    pinned = read_versions(host.compat_dir / "versions.txt")
    if which == "blocking":
        return [
            {
                "host": host.name,
                "name": f"floor {pinned['floor']}",
                "image": f"{host.image}:{pinned['floor']}",
            },
            {
                "host": host.name,
                "name": f"latest {pinned['latest']}",
                "image": f"{host.image}:{pinned['latest']}",
            },
        ]
    if which == "rc":
        rc = newest_rc(
            host, docker_hub_tags(host.image) if tags is None else tags, pinned["latest"]
        )
        return (
            [{"host": host.name, "name": f"rc {rc}", "image": f"{host.image}:{rc}"}] if rc else []
        )
    if which == "main":
        return [
            {"host": host.name, "name": host.main_tag, "image": f"{host.image}:{host.main_tag}"}
        ]
    raise ValueError(f"unknown set: {which}")


# --- validator warnings -----------------------------------------------------------------------------

_LINE_NO = re.compile(r"(\.py):\d+\b")


def normalize_warning(text: str) -> str:
    """Line numbers move with every edit; the warning's substance does not."""
    return " ".join(_LINE_NO.sub(r"\1", text).split())


def read_baseline(path: Path) -> list[str]:
    return [
        normalize_warning(line)
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def warnings_diff(baseline: Iterable[str], warnings: Iterable[str]) -> tuple[list[str], list[str]]:
    """(new warnings, baseline warnings no longer raised)."""
    base = {normalize_warning(w) for w in baseline}
    seen = {normalize_warning(w) for w in warnings}
    return sorted(seen - base), sorted(base - seen)


# --- bump -------------------------------------------------------------------------------------------


def bump(host: Host, tag: str) -> bool:
    """Move `latest` in versions.txt and the install guide's "Tested on" line. True when changed."""
    if stable_version(host, tag) is None:
        raise ValueError(f"not a release tag: {tag}")
    path = host.compat_dir / "versions.txt"
    pinned = read_versions(path)
    if stable_version(host, tag) <= stable_version(host, pinned["latest"]):
        return False
    text = path.read_text()
    path.write_text(re.sub(r"(?m)^latest\s+\S+", f"latest {tag}", text))
    readme = host.readme.read_text()
    new, n = TESTED_ON.subn(f"Tested on {pinned['floor']} and {tag}.", readme)
    if n != 1:
        raise ValueError(f"{host.readme}: expected one 'Tested on vX and vY.' sentence, found {n}")
    host.readme.write_text(new)
    return True


# --- canary issue -----------------------------------------------------------------------------------

ISSUE_LABEL = "host-compat"


def issue_title(host: Host, target: str) -> str:
    """One issue per host and canary target. The rc tag is left out so each new rc reuses it."""
    return f"{host.title} compatibility canary failing: {target}"


def issue_action(open_issues: list[dict], title: str, failed: bool) -> tuple[str, int | None]:
    """What to do with the tracking issue: create, comment, close or none, and on which issue.

    A failure comments on the open issue rather than opening a second one; a pass closes it."""
    match = sorted(i["number"] for i in open_issues if i.get("title") == title)
    if failed:
        return ("comment", match[0]) if match else ("create", None)
    return ("close", match[0]) if match else ("none", None)


def canary_issue(
    host: Host,
    target: str,
    failed: bool,
    run_url: str,
    detail: str,
    gh: Callable[[list[str]], str],
) -> str:
    title = issue_title(host, target)
    listed = gh(
        [
            "issue",
            "list",
            "--state",
            "open",
            "--label",
            ISSUE_LABEL,
            "--limit",
            "100",
            "--json",
            "number,title",
        ]
    )
    action, number = issue_action(json.loads(listed or "[]"), title, failed)
    if action == "create":
        body = (
            f"The nightly {host.title} compatibility check against `{target}` failed.\n\n"
            f"{detail}\n\nRun: {run_url}\n\n"
            "This issue is updated on each failing run and closed by the first passing one."
        )
        gh(
            [
                "label",
                "create",
                ISSUE_LABEL,
                "--force",
                "--color",
                "B60205",
                "--description",
                "A failing host compatibility canary",
            ]
        )
        gh(["issue", "create", "--title", title, "--label", ISSUE_LABEL, "--body", body])
    elif action == "comment":
        gh(
            [
                "issue",
                "comment",
                str(number),
                "--body",
                f"Still failing.\n\n{detail}\n\nRun: {run_url}",
            ]
        )
    elif action == "close":
        gh(
            [
                "issue",
                "close",
                str(number),
                "--comment",
                f"{detail or 'Passing again.'} Run: {run_url}",
            ]
        )
    return action if number is None else f"{action} #{number}"


def _gh(args: list[str]) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


# --- CLI --------------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Host compatibility CI helpers")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("matrix", help="print the GitHub Actions matrix as JSON")
    p.add_argument("--host", choices=HOSTS, required=True)
    p.add_argument("--set", dest="which", choices=("blocking", "rc", "main"), required=True)

    p = sub.add_parser("images", help="print the blocking set's images, one per line")
    p.add_argument("--host", choices=HOSTS, required=True)

    p = sub.add_parser("warnings", help="compare a validator report's warnings with the baseline")
    p.add_argument("--host", choices=HOSTS, required=True)
    p.add_argument("report", type=Path, help="the validator's JSON report")

    p = sub.add_parser("latest", help="print the newest stable release tag")
    p.add_argument("--host", choices=HOSTS, required=True)

    p = sub.add_parser("bump", help="move latest (and the guide's Tested on line) to a tag")
    p.add_argument("--host", choices=HOSTS, required=True)
    p.add_argument("tag")

    p = sub.add_parser("canary-issue", help="open, update or close the canary's tracking issue")
    p.add_argument("--host", choices=HOSTS, required=True)
    p.add_argument("--target", required=True, help="main or release candidate")
    p.add_argument("--result", choices=("success", "failure"), required=True)
    p.add_argument("--run-url", required=True)
    p.add_argument("--detail", default="")

    args = ap.parse_args(argv)
    host = HOSTS[args.host]
    if args.cmd == "matrix":
        print(json.dumps(matrix(host, args.which)))
    elif args.cmd == "images":
        print("\n".join(m["image"] for m in matrix(host, "blocking")))
    elif args.cmd == "warnings":
        try:
            report = json.loads(args.report.read_text())
        except (OSError, ValueError) as exc:
            print(f"FAIL no validator report: {exc}")
            return 1
        warnings = report.get("warnings", []) if isinstance(report, dict) else []
        new, gone = warnings_diff(
            read_baseline(host.compat_dir / "warnings-baseline.txt"), warnings
        )
        for w in gone:
            print(f"note: baseline warning no longer raised (remove it from the baseline): {w}")
        for w in new:
            print(f"FAIL new validator warning (fix it, or add this line to the baseline): {w}")
        if not new:
            print(f"ok   {len(warnings)} validator warnings, all in the baseline")
        return 1 if new else 0
    elif args.cmd == "latest":
        tag = newest_stable(host, docker_hub_tags(host.image))
        if not tag:
            print("no stable release tag found", file=sys.stderr)
            return 1
        print(tag)
    elif args.cmd == "bump":
        print("bumped" if bump(host, args.tag) else "current")
    elif args.cmd == "canary-issue":
        print(
            canary_issue(
                host, args.target, args.result == "failure", args.run_url, args.detail, _gh
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
