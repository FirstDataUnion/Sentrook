"""`sentrook scan` — single PlanIR snapshot scan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from sentrook.cli.common import DEFAULT_RULES_DIR, build_scanner_config
from sentrook.formatting import format_scan_text
from sentrook.layers.l3_embed import make_scorer
from sentrook.scan import scan_plan_file


def scan_cmd(
    plan: Annotated[Path, typer.Option("--plan", help="PlanIR JSON file")],
    rules: Annotated[
        Path,
        typer.Option(
            "--rules",
            help="Rules file or directory (default: ~/.sentrook/rules/)",
        ),
    ] = DEFAULT_RULES_DIR,
    format: Annotated[
        str, typer.Option("--format", help="Output format: json or text")
    ] = "json",
    corpus: Annotated[
        Optional[Path],
        typer.Option(
            "--corpus",
            help="Layer 3 corpus directory (default: repo corpus/ or ~/.sentrook/corpus/)",
        ),
    ] = None,
    l3_policy: Annotated[
        Optional[str],
        typer.Option(
            "--l3-policy",
            help="L3 policy (default: tie_breaker; use off for L2-only)",
        ),
    ] = None,
    allow_margin: Annotated[
        Optional[float],
        typer.Option("--allow-margin", help="Override L3 allow_margin"),
    ] = None,
    fail_closed_margin: Annotated[
        Optional[float],
        typer.Option("--fail-closed-margin", help="Override L3 fail_closed_margin"),
    ] = None,
    top_k: Annotated[
        Optional[int],
        typer.Option("--top-k", help="Override L3 top_k per side"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Include matcher thresholds and L1 index keys in text output",
        ),
    ] = False,
) -> None:
    """Scan a PlanIR snapshot against YAIRA rules."""
    try:
        config = build_scanner_config(
            corpus=corpus,
            l3_policy=l3_policy,
            allow_margin=allow_margin,
            fail_closed_margin=fail_closed_margin,
            top_k=top_k,
        )
        scorer = make_scorer(config)
        result = scan_plan_file(plan, rules, config, l3_scorer=scorer, verbose=verbose)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"scan failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if format == "json":
        typer.echo(json.dumps(result.to_json_dict(), indent=2))
    elif format == "text":
        typer.echo(format_scan_text(result, verbose=verbose))
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)
