"""`sentrook` command line: `schema export`, `scan FILE`, `serve`."""

from __future__ import annotations

import argparse
import json
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


def _cmd_scan(args: argparse.Namespace) -> int:
    """Scan one PlanIR JSON file, or a TestNest-style case (`{fixture, state_seed, oracle_seed}`), and
    print Response 2.0 (plus the probe envelopes with `--envelopes`). Uses the serve configuration from
    the environment; with a case file the seeds are used and the run is deterministic."""
    from ..scan import ScanOptions
    from ..serve.config import ServeConfig
    from ..serve.runtime import ServeRuntime
    from ..serve.server import testnest_options

    body = json.loads(Path(args.file).read_text(encoding="utf-8"))
    config = ServeConfig.from_env()
    case_probes = "fixture" in body and (body.get("options") or {}).get("probes")
    if (args.probes or case_probes) and not config.test_mode:
        what = "--probes" if args.probes else "a case file with options.probes"
        print(
            f"sentrook scan: {what} (probe ablation) is only available in test mode; "
            "set SENTROOK_TEST_MODE=1",
            file=sys.stderr,
        )
        return 2
    runtime = ServeRuntime.build(config)
    if "fixture" in body:
        options = testnest_options(body)
        if args.probes:
            options.probes_enabled = tuple(args.probes.split(","))
        result = runtime.scanner.scan(body["fixture"], options)
    else:
        options = ScanOptions(probes_enabled=tuple(args.probes.split(",")) if args.probes else None)
        result = runtime.scanner.scan(body, options)
    out: dict = {"response": result.response.model_dump(mode="json")}
    if args.envelopes:
        out["probes"] = [e.model_dump(mode="json") for e in result.envelopes]
        out["prepared"] = result.prepared_views
    json.dump(out if args.envelopes else out["response"], sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from ..serve.config import ServeConfig
    from ..serve.server import serve

    config = ServeConfig.from_env()
    if args.host or args.port:
        from dataclasses import replace

        config = replace(config, host=args.host or config.host, port=args.port or config.port)
    serve(config)
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

    scan = sub.add_parser(
        "scan", help="scan a PlanIR 2.0 JSON file (or a TestNest case) and print Response 2.0"
    )
    scan.add_argument("file")
    scan.add_argument(
        "--envelopes", action="store_true", help="also print the probe envelopes and prepared views"
    )
    scan.add_argument(
        "--probes", help="comma-separated probes to enable (ablation; test mode only)"
    )
    scan.set_defaults(func=_cmd_scan)

    srv = sub.add_parser(
        "serve", help="run the scan HTTP daemon (configuration from SENTROOK_* env)"
    )
    srv.add_argument("--host")
    srv.add_argument("--port", type=int)
    srv.set_defaults(func=_cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    from ..serve.config import ConfigError

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as e:
        print(f"sentrook {args.command}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
