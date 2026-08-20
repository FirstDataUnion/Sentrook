"""`sentrook review-copy` — preview operator approval cards from argv."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from sentrook.serve.log import load_scan_log
from sentrook.serve.review_copy import DESCRIPTION_MAX, TITLE_MAX, ApprovalCard, build_approval_card

review_copy_app = typer.Typer(
    help="Preview OpenClaw Command / Shell Preview cards from exec argv.",
    no_args_is_help=True,
)


def _card_to_dict(card: ApprovalCard, *, source_id: str, command: str | None) -> dict[str, Any]:
    return {
        "id": source_id,
        "command": command,
        "title": card.title,
        "description": card.description,
        "command_found": card.command_found,
        "title_chars": len(card.title),
        "description_chars": len(card.description),
        "title_cap": TITLE_MAX,
        "description_cap": DESCRIPTION_MAX,
    }


def _format_text(rows: list[dict[str, Any]]) -> str:
    blocks: list[str] = []
    for row in rows:
        blocks.append(
            "\n".join(
                [
                    f"=== {row['id']} ===",
                    f"Command: {row['title']}",
                    "Shell Preview:",
                    str(row["description"]),
                ]
            )
        )
    return "\n\n".join(blocks)


def _load_jsonl_examples(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            payload = json.loads(stripped)
            rows.append(
                {
                    "id": str(payload.get("id") or f"line-{index}"),
                    "command": payload.get("command"),
                    "tool": payload.get("tool") or "exec",
                }
            )
            continue
        rows.append({"id": f"line-{index}", "command": stripped, "tool": "exec"})
    return rows


def _load_scan_log_examples(path: Path, *, limit: int | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, record in enumerate(load_scan_log(path), start=1):
        if str(record.get("decision", "allow")) != "review":
            continue
        command = record.get("pending_command_excerpt")
        tool = str(record.get("pending_tool") or "exec")
        if not command:
            continue
        rows.append(
            {
                "id": str(record.get("tool_call_id") or f"scan-{index}"),
                "command": command,
                "tool": tool,
            }
        )
        if limit is not None and len(rows) >= limit:
            break
    return rows


def _emit(rows: list[dict[str, Any]], fmt: str) -> None:
    cards = [
        _card_to_dict(
            build_approval_card(command=row.get("command"), tool=str(row.get("tool") or "exec")),
            source_id=str(row["id"]),
            command=row.get("command"),
        )
        for row in rows
    ]
    if fmt == "json":
        typer.echo(json.dumps(cards, indent=2, ensure_ascii=False))
    elif fmt == "text":
        typer.echo(_format_text(cards))
    else:
        typer.echo(f"unknown format: {fmt}", err=True)
        raise typer.Exit(code=1)


@review_copy_app.command("show")
def review_copy_show(
    command: Annotated[
        str | None,
        typer.Option("--command", "-c", help="Single exec argv to summarise"),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option("--file", "-f", help="JSONL ({command, tool?}) or one command per line"),
    ] = None,
    scan_log: Annotated[
        Path | None,
        typer.Option("--scan-log", help="Scan JSONL; uses pending_command_excerpt on review rows"),
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("--limit", help="Max examples from --scan-log"),
    ] = None,
    format: Annotated[str, typer.Option("--format", help="text or json")] = "text",
) -> None:
    """Print Command / Shell Preview cards so you can review copy quality."""
    sources = [bool(command), file is not None, scan_log is not None]
    if sum(sources) != 1:
        typer.echo("provide exactly one of --command, --file, or --scan-log", err=True)
        raise typer.Exit(code=1)

    try:
        if command is not None:
            rows = [{"id": "cli", "command": command, "tool": "exec"}]
        elif file is not None:
            rows = _load_jsonl_examples(file)
        else:
            assert scan_log is not None
            rows = _load_scan_log_examples(scan_log, limit=limit)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except json.JSONDecodeError as exc:
        typer.echo(f"invalid JSONL: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not rows:
        typer.echo("no examples to summarise", err=True)
        raise typer.Exit(code=2)

    _emit(rows, format)
    raise typer.Exit(code=0)
