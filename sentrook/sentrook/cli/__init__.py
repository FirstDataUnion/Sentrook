"""`sentrook` command line. WP0 ships `schema export`; `scan` and `serve` arrive with WP6."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import __version__


def _cmd_schema(args: argparse.Namespace) -> int:
    from .. import contracts

    out = Path(args.out) if args.out else None
    if args.check:
        stale = contracts.drift(out)
        if stale:
            print("schema drift: " + ", ".join(stale) + " (run `make schema`)", file=sys.stderr)
            return 1
        print("schema up to date")
        return 0
    for path in contracts.export(out):
        print(f"wrote {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentrook", description="Sentrook 2.0 scanner")
    parser.add_argument("--version", action="version", version=f"sentrook {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    schema = sub.add_parser("schema", help="JSON Schema contracts generated from the models")
    schema_sub = schema.add_subparsers(dest="schema_command", required=True)
    export = schema_sub.add_parser("export", help="write schema/*.json (or check they are current)")
    export.add_argument("--out", help="directory to write to (default: repo schema/)")
    export.add_argument("--check", action="store_true", help="exit 1 if the committed files differ")
    export.set_defaults(func=_cmd_schema)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
