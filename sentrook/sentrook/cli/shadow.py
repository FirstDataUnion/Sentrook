"""`sentrook shadow` — live observe-only scanning, analysis, and ops commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from sentrook.cli.common import rookery_api_key, shadow_config
from sentrook.shadow.analyze import analyze_shadow_log, format_shadow_analyze_text

shadow_app = typer.Typer(help="Live observe-only (shadow) scanning for agent hosts.")


@shadow_app.command("scan")
def shadow_scan_cmd(
    input: Annotated[
        Optional[Path],
        typer.Option("--input", "-i", help="Snapshot JSON file (default: stdin)"),
    ] = None,
    rules: Annotated[
        Optional[Path], typer.Option("--rules", help="Rules dir (default: env/~/.sentrook/rules)")
    ] = None,
    corpus: Annotated[
        Optional[Path], typer.Option("--corpus", help="Layer 3 corpus directory")
    ] = None,
    l3_policy: Annotated[
        Optional[str], typer.Option("--l3-policy", help="L3 policy (default: tie_breaker)")
    ] = None,
    log_path: Annotated[
        Optional[Path], typer.Option("--log-path", help="Shadow log JSONL path")
    ] = None,
    no_log: Annotated[
        bool, typer.Option("--no-log", help="Do not append to the shadow log")
    ] = False,
) -> None:
    """Scan a single sentrook.shadow.snapshot/v1 payload and print the decision as JSON.

    Reads the snapshot from --input or stdin. This is the no-host debug path and the
    harness for live-vs-replay parity checks.
    """
    import sys

    from sentrook.shadow.log import build_log_record
    from sentrook.shadow.response import build_scan_response
    from sentrook.shadow.service import ShadowScanner
    from sentrook.shadow.snapshot import ShadowSnapshot

    try:
        raw = input.read_text(encoding="utf-8") if input is not None else sys.stdin.read()
        snapshot = ShadowSnapshot.model_validate_json(raw)
        config = shadow_config(
            rules=rules,
            corpus=corpus,
            l3_policy=l3_policy,
            log_path=log_path,
            host=None,
            port=None,
        )
        scanner = ShadowScanner(config)
        if no_log:
            result = scanner.scan(snapshot)
            record = build_log_record(result, snapshot, mode=config.mode)
        else:
            result, record = scanner.scan_and_log(snapshot)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"shadow scan failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(
        json.dumps(
            build_scan_response(config, result, record),
            indent=2,
        )
    )
    raise typer.Exit(code=0)


@shadow_app.command("analyze")
def shadow_analyze_cmd(
    log_path: Annotated[
        Path, typer.Option("--log-path", help="Shadow JSONL log file")
    ],
    format: Annotated[
        str, typer.Option("--format", help="Output format: json or text")
    ] = "text",
) -> None:
    """Aggregate a shadow JSONL log: decisions, rule hits, exec review rate."""
    try:
        report = analyze_shadow_log(log_path)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        typer.echo(f"shadow analyze failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if format == "json":
        typer.echo(json.dumps(report.to_json_dict(), indent=2))
    elif format == "text":
        typer.echo(format_shadow_analyze_text(report))
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@shadow_app.command("harvest-submit")
def shadow_harvest_submit_cmd(
    log_path: Annotated[
        Path, typer.Option("--log-path", help="Shadow JSONL log file")
    ],
    url: Annotated[
        str,
        typer.Option("--url", help="Rookery base URL for submissions"),
    ] = "https://rookery.firstdataunion.org",
    decision: Annotated[
        str, typer.Option("--decision", help="Shadow decision to harvest (default: review)")
    ] = "review",
    label: Annotated[
        Optional[str],
        typer.Option("--label", help="Corpus label required for submit (attack|benign)"),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Preview candidates without submitting")
    ] = False,
) -> None:
    """Harvest shadow log review candidates into Rookery pending submissions."""
    from sentrook.shadow.harvest import submit_harvest_candidates

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


@shadow_app.command("verify")
def shadow_verify_cmd(
    url: Annotated[
        str,
        typer.Option("--url", help="Shadow sidecar base URL"),
    ] = "http://127.0.0.1:9099",
    openclaw_dir: Annotated[
        Optional[Path],
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
        Optional[str],
        typer.Option(
            "--sidecar-service",
            help="Compose service for sidecar health (default sentrook-shadow when --openclaw-dir is set)",
        ),
    ] = None,
    plugin_id: Annotated[
        str,
        typer.Option("--plugin-id", help="OpenClaw plugin id"),
    ] = "sentrook-shadow",
    sidecar_only: Annotated[
        bool,
        typer.Option("--sidecar-only", help="Skip OpenClaw plugin checks"),
    ] = False,
    format: Annotated[
        str,
        typer.Option("--format", help="Output format: json or text"),
    ] = "text",
) -> None:
    """Verify the shadow sidecar (and optionally the OpenClaw plugin) after install."""
    from sentrook.shadow.verify import format_verify_text, run_shadow_verify

    resolved_sidecar_service = sidecar_service
    if openclaw_dir is not None and resolved_sidecar_service is None:
        resolved_sidecar_service = "sentrook-shadow"

    report = run_shadow_verify(
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


@shadow_app.command("serve")
def shadow_serve_cmd(
    host: Annotated[
        Optional[str], typer.Option("--host", help="Bind host (default: 127.0.0.1)")
    ] = None,
    port: Annotated[
        Optional[int], typer.Option("--port", help="Bind port (default: 9099)")
    ] = None,
    rules: Annotated[Optional[Path], typer.Option("--rules", help="Rules dir")] = None,
    corpus: Annotated[Optional[Path], typer.Option("--corpus", help="Corpus dir")] = None,
    l3_policy: Annotated[
        Optional[str], typer.Option("--l3-policy", help="L3 policy (default: tie_breaker)")
    ] = None,
    log_path: Annotated[
        Optional[Path], typer.Option("--log-path", help="Shadow log JSONL path")
    ] = None,
) -> None:
    """Run the warm shadow-scan HTTP daemon (POST /scan, GET /health)."""
    from sentrook.shadow.server import serve

    config = shadow_config(
        rules=rules,
        corpus=corpus,
        l3_policy=l3_policy,
        log_path=log_path,
        host=host,
        port=port,
    )
    serve(config)
