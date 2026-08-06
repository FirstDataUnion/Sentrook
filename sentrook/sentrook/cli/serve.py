"""`sentrook serve` / ops — live HTTP scanning, analysis, verify, harvest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from sentrook.cli.common import rookery_api_key, serve_config
from sentrook.serve.analyze import analyze_scan_log, format_scan_analyze_text

serve_app = typer.Typer(help="Warm HTTP scan daemon (POST /scan with PlanIR 1.0).")


@serve_app.callback(invoke_without_command=True)
def serve_root(
    ctx: typer.Context,
    host: Annotated[
        str | None, typer.Option("--host", help="Bind host (default: 127.0.0.1)")
    ] = None,
    port: Annotated[int | None, typer.Option("--port", help="Bind port (default: 9099)")] = None,
    rules: Annotated[Path | None, typer.Option("--rules", help="Rules dir")] = None,
    corpus: Annotated[Path | None, typer.Option("--corpus", help="Corpus dir")] = None,
    l3_policy: Annotated[
        str | None, typer.Option("--l3-policy", help="L3 policy (default: tie_breaker)")
    ] = None,
    log_path: Annotated[Path | None, typer.Option("--log-path", help="Scan log JSONL path")] = None,
) -> None:
    """Run the warm scan HTTP daemon (POST /scan, GET /health)."""
    if ctx.invoked_subcommand is not None:
        return
    from sentrook.serve.server import serve

    config = serve_config(
        rules=rules,
        corpus=corpus,
        l3_policy=l3_policy,
        log_path=log_path,
        host=host,
        port=port,
    )
    serve(config)


def analyze_cmd(
    log_path: Annotated[Path, typer.Option("--log-path", help="Scan JSONL log file")],
    format: Annotated[str, typer.Option("--format", help="Output format: json or text")] = "text",
) -> None:
    """Aggregate a scan JSONL log: decisions, rule hits, exec review rate."""
    try:
        report = analyze_scan_log(log_path)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"analyze failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if format == "json":
        typer.echo(json.dumps(report.to_json_dict(), indent=2))
    elif format == "text":
        typer.echo(format_scan_analyze_text(report))
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def harvest_submit_cmd(
    log_path: Annotated[Path, typer.Option("--log-path", help="Scan JSONL log file")],
    url: Annotated[
        str,
        typer.Option("--url", help="Rookery base URL for submissions"),
    ] = "https://rookery.firstdataunion.org",
    decision: Annotated[
        str, typer.Option("--decision", help="Scan decision to harvest (default: review)")
    ] = "review",
    label: Annotated[
        str | None,
        typer.Option("--label", help="Corpus label required for submit (attack|benign)"),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Preview candidates without submitting")
    ] = False,
) -> None:
    """Harvest scan log review candidates into Rookery pending submissions."""
    from sentrook.serve.harvest import submit_harvest_candidates

    corpus_label = None
    if label is not None:
        if label not in ("attack", "benign"):
            typer.echo("--label must be attack or benign", err=True)
            raise typer.Exit(code=1)
        corpus_label = label  # type: ignore[assignment]

    try:
        results = submit_harvest_candidates(
            log_path,
            rookery_url=url,
            dry_run=dry_run,
            decision=decision,
            label=corpus_label,
            api_key=rookery_api_key(),
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"harvest-submit failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(json.dumps(results, indent=2))
    raise typer.Exit(code=0)


def verify_cmd(
    url: Annotated[
        str,
        typer.Option("--url", help="Scan sidecar base URL"),
    ] = "http://127.0.0.1:9099",
    openclaw_dir: Annotated[
        Path | None,
        typer.Option(
            "--openclaw-dir",
            help="OpenClaw compose project (enables plugin + gateway network checks)",
        ),
    ] = None,
    gateway_service: Annotated[
        str,
        typer.Option("--gateway-service", help="Compose service for the gateway"),
    ] = "openclaw-gateway",
    sidecar_service: Annotated[
        str | None,
        typer.Option(
            "--sidecar-service",
            help="Compose service for sidecar health (default sentrook-scan when --openclaw-dir is set)",
        ),
    ] = None,
    plugin_id: Annotated[
        str,
        typer.Option("--plugin-id", help="OpenClaw plugin id"),
    ] = "sentrook-scan",
    sidecar_only: Annotated[
        bool,
        typer.Option("--sidecar-only", help="Skip OpenClaw plugin checks"),
    ] = False,
    format: Annotated[
        str,
        typer.Option("--format", help="Output format: json or text"),
    ] = "text",
) -> None:
    """Verify the scan sidecar (and optionally the OpenClaw plugin) after install."""
    from sentrook.serve.verify import format_verify_text, run_scan_verify

    resolved_sidecar_service = sidecar_service
    if openclaw_dir is not None and resolved_sidecar_service is None:
        resolved_sidecar_service = "sentrook-scan"

    report = run_scan_verify(
        url=url,
        openclaw_dir=openclaw_dir,
        gateway_service=gateway_service,
        sidecar_service=resolved_sidecar_service,
        plugin_id=plugin_id,
        check_plugin=not sidecar_only and openclaw_dir is not None,
        check_gateway_fetch=not sidecar_only and openclaw_dir is not None,
    )

    if format == "json":
        payload = {
            "ok": report.ok,
            "sidecar_url": report.sidecar_url,
            "sidecar_ok": report.sidecar_ok,
            "sidecar_health": report.sidecar_health,
            "gateway_reachable": report.gateway_reachable,
            "plugin_ok": report.plugin_ok,
            "plugin_runtime": report.plugin_runtime,
            "errors": report.errors,
            "notes": report.notes,
        }
        typer.echo(json.dumps(payload, indent=2))
    elif format == "text":
        typer.echo(format_verify_text(report))
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)

    raise typer.Exit(code=0 if report.ok else 1)
