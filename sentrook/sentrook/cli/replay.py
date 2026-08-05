"""`sentrook replay` — session replay, audit, parity, and baseline commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from sentrook.cli.common import DEFAULT_RULES_DIR, build_scanner_config
from sentrook.layers.l3_embed import make_scorer
from sentrook.replay.audit import audit_openclaw_session, format_session_audit_text
from sentrook.replay.baseline import (
    ReplayBaselineReport,
    compare_baselines,
    default_baseline_path,
    format_baseline_text,
    load_baseline_file,
    run_replay_baseline,
    write_baseline_file,
)
from sentrook.replay.openclaw import replay_session, write_snapshots
from sentrook.replay.parity import compare_shadow_to_replay, format_parity_text

replay_app = typer.Typer(help="Replay host session logs into PlanIR snapshots.")


@replay_app.command("openclaw")
def replay_openclaw_cmd(
    session: Annotated[Path, typer.Option("--session", help="OpenClaw session JSONL")],
    output: Annotated[
        Path, typer.Option("--output", help="Directory for PlanIR snapshots")
    ],
    trajectory: Annotated[
        Optional[Path],
        typer.Option("--trajectory", help="Optional trajectory JSONL for run_id/intent"),
    ] = None,
    agent_id: Annotated[str, typer.Option("--agent-id")] = "main",
    max_snapshots: Annotated[
        Optional[int],
        typer.Option("--max-snapshots", help="Limit snapshots written"),
    ] = None,
) -> None:
    """Generate rolling PlanIR fixtures from an OpenClaw session transcript."""
    try:
        snapshots = replay_session(
            session,
            trajectory_path=trajectory,
            agent_id=agent_id,
            max_snapshots=max_snapshots,
        )
        paths = write_snapshots(snapshots, output)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"replay failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Wrote {len(paths)} snapshots to {output}")
    raise typer.Exit(code=0)


@replay_app.command("scan")
def replay_scan_cmd(
    session: Annotated[
        Path, typer.Option("--session", help="OpenClaw session JSONL")
    ],
    rules: Annotated[
        Path,
        typer.Option(
            "--rules",
            help="Rules file or directory (default: ~/.sentrook/rules/)",
        ),
    ] = DEFAULT_RULES_DIR,
    trajectory: Annotated[
        Optional[Path],
        typer.Option("--trajectory", help="Optional trajectory JSONL for run_id/intent"),
    ] = None,
    agent_id: Annotated[str, typer.Option("--agent-id")] = "main",
    max_snapshots: Annotated[
        Optional[int],
        typer.Option("--max-snapshots", help="Limit snapshots scanned"),
    ] = None,
    format: Annotated[
        str, typer.Option("--format", help="Output format: json or text")
    ] = "text",
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
) -> None:
    """Shadow-scan every before_tool_call moment in a replayed OpenClaw session."""
    try:
        config = build_scanner_config(
            corpus=corpus,
            l3_policy=l3_policy,
            allow_margin=allow_margin,
            fail_closed_margin=fail_closed_margin,
            top_k=top_k,
        )
        scorer = make_scorer(config)
        report = audit_openclaw_session(
            session,
            rules,
            config,
            trajectory_path=trajectory,
            agent_id=agent_id,
            max_snapshots=max_snapshots,
            l3_scorer=scorer,
        )
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"replay scan failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if format == "json":
        typer.echo(json.dumps(report.to_json_dict(), indent=2))
    elif format == "text":
        typer.echo(format_session_audit_text(report))
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@replay_app.command("parity")
def replay_parity_cmd(
    shadow_log: Annotated[
        Path, typer.Option("--shadow-log", help="Live shadow JSONL log")
    ],
    session: Annotated[
        Path, typer.Option("--session", help="OpenClaw session JSONL to replay")
    ],
    rules: Annotated[
        Path,
        typer.Option("--rules", help="Rules directory"),
    ] = DEFAULT_RULES_DIR,
    session_id: Annotated[
        Optional[str],
        typer.Option("--session-id", help="Filter shadow log to one session id"),
    ] = None,
    format: Annotated[
        str, typer.Option("--format", help="Output format: json or text")
    ] = "text",
    corpus: Annotated[Optional[Path], typer.Option("--corpus", help="Corpus dir")] = None,
    l3_policy: Annotated[Optional[str], typer.Option("--l3-policy")] = None,
) -> None:
    """Compare live shadow log decisions against replay on the same session."""
    try:
        config = build_scanner_config(
            corpus=corpus,
            l3_policy=l3_policy,
        )
        report = compare_shadow_to_replay(
            shadow_log,
            session,
            rules,
            config,
            session_id=session_id,
        )
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"replay parity failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if format == "json":
        typer.echo(json.dumps(report.to_json_dict(), indent=2))
    elif format == "text":
        typer.echo(format_parity_text(report))
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)

    if report.decision_mismatches or report.unmatched_shadow:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@replay_app.command("baseline")
def replay_baseline_cmd(
    rules: Annotated[
        Path,
        typer.Option(
            "--rules",
            help="Rules file or directory (default: ~/.sentrook/rules/)",
        ),
    ] = DEFAULT_RULES_DIR,
    format: Annotated[
        str, typer.Option("--format", help="Output format: json or text")
    ] = "text",
    compare: Annotated[
        Optional[Path],
        typer.Option(
            "--compare",
            help="Compare metrics to a pinned baseline JSON (default: replay/baselines/v0.2.0.json)",
        ),
    ] = None,
    write: Annotated[
        Optional[Path],
        typer.Option(
            "--write",
            help="Write baseline JSON to this path (default: replay/baselines/v0.2.0.json)",
        ),
    ] = None,
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
) -> None:
    """Shadow-scan canonical OpenClaw sessions and report baseline metrics."""
    try:
        config = build_scanner_config(
            corpus=corpus,
            l3_policy=l3_policy,
            allow_margin=allow_margin,
            fail_closed_margin=fail_closed_margin,
            top_k=top_k,
        )
        scorer = make_scorer(config)
        report = run_replay_baseline(rules, config, l3_scorer=scorer)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"replay baseline failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if write is not None:
        out_path = write_baseline_file(report, write)
        typer.echo(f"Wrote baseline to {out_path}", err=True)

    compare_path = compare if compare is not None else default_baseline_path()
    compare_report: ReplayBaselineReport | None = None
    if compare is not None or compare_path.exists():
        try:
            compare_report = load_baseline_file(compare_path)
        except FileNotFoundError:
            if compare is not None:
                typer.echo(f"baseline compare file not found: {compare_path}", err=True)
                raise typer.Exit(code=1)

    if format == "json":
        payload = report.to_json_dict()
        if compare_report is not None:
            payload["comparison"] = {
                "baseline_path": str(compare_path),
                "drifts": compare_baselines(report, compare_report),
            }
        typer.echo(json.dumps(payload, indent=2))
    elif format == "text":
        typer.echo(format_baseline_text(report, compare_to=compare_report))
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)

    if compare_report is not None:
        drifts = compare_baselines(report, compare_report)
        if drifts:
            raise typer.Exit(code=1)

    raise typer.Exit(code=0)
