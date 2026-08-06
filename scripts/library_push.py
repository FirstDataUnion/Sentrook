#!/usr/bin/env python3
"""Push missing repo corpus examples to Rookery (repo dev tool).

Diffs local ``corpus/`` against a synced Rookery library cache, submits each
example that exists locally but not on the remote registry, stages the
submission, then releases staged examples so a new bundle is published without
manual review (trusted repo path; skips TestNest gate).

Requires ``SENTROOK_ROOKERY_API_KEY`` when the target Rookery instance enforces
auth (needed for approve; submit may be open).

Limitations (short-term / Option 1):
  - Corpus examples only — rule YAML is not pushed.
  - Additions only — changed examples (same id, different body) are reported as
    conflicts and skipped (the submissions API cannot update in place).
  - Remote-only examples are kept on Rookery and never deleted.

Usage:
  export SENTROOK_ROOKERY_API_KEY=...
  ./scripts/library-push.sh
  ./scripts/library-push.sh --dry-run
  make library-push

Prefer ``library-push.sh`` or ``make library-push`` over running ``library_push.py``
directly — the script needs the sentrook project environment (PyYAML, sentrook imports).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from sentrook import __version__ as SENTROOK_VERSION
from sentrook.corpus.hashutil import canonical_example_hash
from sentrook.corpus.models import CorpusExample, RuleCorpus
from sentrook.library.rookery_client import rookery_auth_headers
from sentrook.library.sync import sync_library

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_DIR = REPO_ROOT / "corpus"
DEFAULT_LIBRARY_DIR = Path.home() / ".sentrook" / "library"
DEFAULT_ROOKERY_URL = "https://rookery.firstdataunion.org"
PROVENANCE_SOURCE = "repo_library_push"

ExampleAction = Literal["push", "skip_exists", "skip_conflict", "skip_unknown_rule"]


@dataclass(frozen=True)
class ExampleDiff:
    rule_id: str
    example_id: str
    action: ExampleAction
    example: CorpusExample | None = None
    remote_hash: str | None = None
    local_hash: str | None = None


@dataclass(frozen=True)
class CorpusDiffReport:
    rules_compared: int
    examples: list[ExampleDiff]
    remote_only: list[tuple[str, str]]

    @property
    def to_push(self) -> list[ExampleDiff]:
        return [row for row in self.examples if row.action == "push"]

    @property
    def conflicts(self) -> list[ExampleDiff]:
        return [row for row in self.examples if row.action == "skip_conflict"]


def load_corpus_examples(corpus_dir: Path) -> dict[tuple[str, str], CorpusExample]:
    if not corpus_dir.is_dir():
        raise FileNotFoundError(f"Corpus directory not found: {corpus_dir}")

    loaded: dict[tuple[str, str], CorpusExample] = {}
    for path in sorted(corpus_dir.glob("*.yaml")) + sorted(corpus_dir.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        spec = RuleCorpus.model_validate(doc)
        for example in spec.examples:
            key = (spec.rule_id, example.id)
            if key in loaded:
                raise ValueError(f"duplicate example id {example.id!r} under {spec.rule_id}")
            loaded[key] = example
    return loaded


def diff_corpus(
    local_examples: dict[tuple[str, str], CorpusExample],
    remote_examples: dict[tuple[str, str], CorpusExample],
    *,
    known_rule_ids: set[str],
) -> CorpusDiffReport:
    rule_ids = {rule_id for rule_id, _ in local_examples} | {
        rule_id for rule_id, _ in remote_examples
    }
    rows: list[ExampleDiff] = []
    remote_only: list[tuple[str, str]] = []

    for rule_id, example_id in sorted(local_examples):
        local = local_examples[(rule_id, example_id)]
        local_hash = canonical_example_hash(local)
        if rule_id not in known_rule_ids:
            rows.append(
                ExampleDiff(
                    rule_id=rule_id,
                    example_id=example_id,
                    action="skip_unknown_rule",
                    example=local,
                    local_hash=local_hash,
                )
            )
            continue

        remote = remote_examples.get((rule_id, example_id))
        if remote is None:
            rows.append(
                ExampleDiff(
                    rule_id=rule_id,
                    example_id=example_id,
                    action="push",
                    example=local,
                    local_hash=local_hash,
                )
            )
            continue

        remote_hash = canonical_example_hash(remote)
        if local_hash == remote_hash:
            rows.append(
                ExampleDiff(
                    rule_id=rule_id,
                    example_id=example_id,
                    action="skip_exists",
                    local_hash=local_hash,
                    remote_hash=remote_hash,
                )
            )
        else:
            rows.append(
                ExampleDiff(
                    rule_id=rule_id,
                    example_id=example_id,
                    action="skip_conflict",
                    example=local,
                    local_hash=local_hash,
                    remote_hash=remote_hash,
                )
            )

    for key in sorted(remote_examples):
        if key not in local_examples:
            remote_only.append(key)

    return CorpusDiffReport(
        rules_compared=len(rule_ids),
        examples=rows,
        remote_only=remote_only,
    )


def _request_json(
    method: str,
    url: str,
    *,
    api_key: str | None,
    body: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    if params:
        query = urllib.parse.urlencode(params)
        url = f"{url}?{query}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            **rookery_auth_headers(api_key),
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def submit_example(
    base_url: str,
    rule_id: str,
    example: CorpusExample,
    *,
    api_key: str | None,
) -> dict[str, Any]:
    body = {
        "schema": "sentrook.library.submission/v1",
        "kind": "corpus_example",
        "rule_id": rule_id,
        "source": "sentrook_client",
        "example": example.model_dump(mode="json"),
        "provenance": {
            "source": PROVENANCE_SOURCE,
            "scanner_version": SENTROOK_VERSION,
            "rule_id": rule_id,
            "example_id": example.id,
        },
    }
    return _request_json(
        "POST",
        f"{base_url.rstrip('/')}/api/v1/submissions",
        api_key=api_key,
        body=body,
    )


def approve_submission(
    base_url: str,
    submission_id: int,
    *,
    api_key: str | None,
    reviewer_note: str = "auto-approved by scripts/library_push.py",
) -> dict[str, Any]:
    return _request_json(
        "POST",
        f"{base_url.rstrip('/')}/api/v1/submissions/{submission_id}/approve",
        api_key=api_key,
        params={"reviewer_note": reviewer_note},
    )


def release_staged(
    base_url: str,
    *,
    api_key: str | None,
) -> dict[str, Any]:
    """Promote staged submissions and publish a bundle (trusted repo push path)."""
    return _request_json(
        "POST",
        f"{base_url.rstrip('/')}/api/v1/release",
        api_key=api_key,
        params={"require_gate_ok": "false"},
    )


def format_report(report: CorpusDiffReport) -> str:
    push = report.to_push
    conflicts = report.conflicts
    exists = [row for row in report.examples if row.action == "skip_exists"]
    unknown = [row for row in report.examples if row.action == "skip_unknown_rule"]

    lines = [
        f"rules compared: {report.rules_compared}",
        f"to push: {len(push)}",
        f"already synced: {len(exists)}",
        f"conflicts (same id, different body): {len(conflicts)}",
        f"unknown rule on remote: {len(unknown)}",
        f"remote-only examples (kept): {len(report.remote_only)}",
    ]
    if push:
        lines.append("")
        lines.append("push:")
        for row in push:
            lines.append(f"  + {row.rule_id}/{row.example_id}")
    if conflicts:
        lines.append("")
        lines.append("conflicts (skipped):")
        for row in conflicts:
            lines.append(
                f"  ! {row.rule_id}/{row.example_id} "
                f"(local {row.local_hash[:8]} != remote {row.remote_hash[:8]})"
            )
    if unknown:
        lines.append("")
        lines.append("unknown rules (skipped):")
        for row in unknown:
            lines.append(f"  ? {row.rule_id}/{row.example_id}")
    if report.remote_only:
        preview = ", ".join(f"{rule}/{ex}" for rule, ex in report.remote_only[:8])
        if len(report.remote_only) > 8:
            preview += ", ..."
        lines.append("")
        lines.append(f"remote-only preview: {preview}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Push missing local corpus examples to Rookery and auto-approve.",
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("SENTROOK_LIBRARY_URL", DEFAULT_ROOKERY_URL),
        help="Rookery base URL (default: SENTROOK_LIBRARY_URL or production)",
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=DEFAULT_CORPUS_DIR,
        help="Local repo corpus directory",
    )
    parser.add_argument(
        "--library-dir",
        type=Path,
        default=Path(os.environ.get("SENTROOK_LIBRARY_DIR", str(DEFAULT_LIBRARY_DIR))),
        help="Synced library cache (default: ~/.sentrook/library)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the diff only; do not submit or approve",
    )
    parser.add_argument(
        "--skip-sync",
        action="store_true",
        help="Use the existing library cache without pulling from Rookery first",
    )
    args = parser.parse_args(argv)

    api_key = os.environ.get("SENTROOK_ROOKERY_API_KEY")
    if not args.dry_run and not api_key:
        print(
            "warning: SENTROOK_ROOKERY_API_KEY is unset; approve may fail if Rookery requires auth",
            file=sys.stderr,
        )

    if not args.skip_sync:
        print(f"==> Syncing library from {args.url}")
        try:
            result = sync_library(
                url=args.url,
                library_dir=args.library_dir,
                force=True,
                api_key=api_key,
            )
        except Exception as exc:
            print(f"library sync failed: {exc}", file=sys.stderr)
            return 1
        version = result.bundle_version or "unknown"
        print(f"    cache at {result.library_dir} (bundle {version})")

    remote_corpus_dir = args.library_dir / "corpus"
    rules_dir = args.library_dir / "rules"
    if not remote_corpus_dir.is_dir():
        print(f"error: synced corpus not found at {remote_corpus_dir}", file=sys.stderr)
        return 1

    known_rule_ids = {path.stem for path in rules_dir.glob("*.yaml")} | {
        path.stem for path in rules_dir.glob("*.yml")
    }

    try:
        local_examples = load_corpus_examples(args.corpus_dir)
        remote_examples = load_corpus_examples(remote_corpus_dir)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    report = diff_corpus(
        local_examples,
        remote_examples,
        known_rule_ids=known_rule_ids,
    )
    print(format_report(report))

    if args.dry_run:
        print("\ndry-run: no submissions sent")
        return 0

    if report.conflicts:
        print(
            "\nerror: conflicts detected — resolve locally or on Rookery before pushing",
            file=sys.stderr,
        )
        return 1

    to_push = report.to_push
    if not to_push:
        print("\nNothing to push.")
        return 0

    print(f"\n==> Submitting and staging {len(to_push)} example(s)")
    staged = 0
    for row in to_push:
        assert row.example is not None
        try:
            created = submit_example(
                args.url,
                row.rule_id,
                row.example,
                api_key=api_key,
            )
            submission = created["submission"]
            status = submission.get("status")
            if status == "auto_rejected":
                print(
                    f"· {row.rule_id}/{row.example_id} auto-rejected "
                    f"({submission.get('reviewer_note') or 'duplicate'})"
                )
                continue
            submission_id = int(submission["id"])
            approve_submission(
                args.url,
                submission_id,
                api_key=api_key,
            )
            staged += 1
            print(f"✓ {row.rule_id}/{row.example_id} staged")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            print(
                f"✗ {row.rule_id}/{row.example_id}: HTTP {exc.code} {detail}",
                file=sys.stderr,
            )
            return 1
        except urllib.error.URLError as exc:
            print(f"✗ {row.rule_id}/{row.example_id}: {exc}", file=sys.stderr)
            return 1

    if staged == 0:
        print("\nNothing staged; no release.")
        return 0

    try:
        released = release_staged(args.url, api_key=api_key)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"✗ release failed: HTTP {exc.code} {detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"✗ release failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"\nDone. Released {len(released.get('released_ids', []))} "
        f"→ bundle {released.get('bundle_version')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
