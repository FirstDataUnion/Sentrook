"""Prune Sentrook scan/latency JSONL logs by record ``ts`` (UTC).

Hosted entrypoint (FIDU): Rookery ``deploy/sentrook-scan/retain-logs.sh``
(``python -m sentrook.ops.retain_logs``).
Lines without a parseable ``ts`` are kept (conservative). Concurrent appenders
open/close the file per write, so an atomic replace is safe between writes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

DEFAULT_RETENTION_DAYS = 14


def parse_ts(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def cutoff_utc(*, now: datetime | None = None, days: int) -> datetime:
    if days < 1:
        raise ValueError("retention days must be >= 1")
    base = now or datetime.now(UTC)
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
    else:
        base = base.astimezone(UTC)
    return base - timedelta(days=days)


def classify_line(line: str, *, cutoff: datetime) -> tuple[str, str]:
    """Return (action, raw_line) where action is keep|drop|keep_unparsed."""
    stripped = line.strip()
    if not stripped:
        return ("drop", line)
    try:
        row = json.loads(stripped)
    except json.JSONDecodeError:
        return ("keep_unparsed", line if line.endswith("\n") else line + "\n")
    if not isinstance(row, dict):
        return ("keep_unparsed", line if line.endswith("\n") else line + "\n")
    ts = parse_ts(row.get("ts"))
    if ts is None:
        return ("keep_unparsed", line if line.endswith("\n") else line + "\n")
    normalized = line if line.endswith("\n") else line + "\n"
    if ts >= cutoff:
        return ("keep", normalized)
    return ("drop", normalized)


def prune_jsonl_file(
    path: Path,
    *,
    cutoff: datetime,
    dry_run: bool = True,
) -> dict[str, int | bool | str]:
    """Filter ``path`` in place (unless dry_run). Returns counts summary."""
    path = Path(path)
    summary: dict[str, int | bool | str] = {
        "path": str(path),
        "exists": path.is_file(),
        "kept": 0,
        "dropped": 0,
        "kept_unparsed": 0,
        "rewritten": False,
        "dry_run": dry_run,
    }
    if not path.is_file():
        return summary

    kept_lines: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            action, raw = classify_line(line, cutoff=cutoff)
            if action == "keep":
                summary["kept"] = int(summary["kept"]) + 1
                kept_lines.append(raw)
            elif action == "drop":
                summary["dropped"] = int(summary["dropped"]) + 1
            else:
                summary["kept_unparsed"] = int(summary["kept_unparsed"]) + 1
                kept_lines.append(raw)

    if dry_run or int(summary["dropped"]) == 0:
        return summary

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.writelines(kept_lines)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_path, path)
        summary["rewritten"] = True
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return summary


def default_log_paths() -> list[Path]:
    scan_log = os.environ.get("SENTROOK_LOG_PATH", "/var/log/sentrook/scan.log.jsonl")
    latency = os.environ.get("SENTROOK_LATENCY_LOG_PATH", "/var/log/sentrook/latency.log.jsonl")
    return [Path(scan_log), Path(latency)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Retain Sentrook JSONL logs by record ts (public-beta retention)."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=int(os.environ.get("SENTROOK_LOG_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)),
        help=f"Keep records with ts >= now - days (default {DEFAULT_RETENTION_DAYS})",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Rewrite files in place. Without this flag, report only (dry-run).",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="JSONL files (default: SENTROOK_LOG_PATH + SENTROOK_LATENCY_LOG_PATH)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cutoff = cutoff_utc(days=args.days)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    paths = list(args.paths) if args.paths else default_log_paths()
    dry_run = not args.apply
    print(
        f"retention_days={args.days} cutoff_utc={cutoff.isoformat()} "
        f"mode={'dry-run' if dry_run else 'apply'}"
    )

    total_dropped = 0
    for path in paths:
        summary = prune_jsonl_file(path, cutoff=cutoff, dry_run=dry_run)
        total_dropped += int(summary["dropped"])
        print(
            f"{summary['path']}: exists={summary['exists']} "
            f"kept={summary['kept']} dropped={summary['dropped']} "
            f"kept_unparsed={summary['kept_unparsed']} "
            f"rewritten={summary['rewritten']}"
        )

    if dry_run and total_dropped:
        print("dry-run only — re-run with --apply to rewrite files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
