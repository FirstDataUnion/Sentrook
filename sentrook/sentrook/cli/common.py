"""Shared option handling for the Sentrook CLI sub-apps."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

import typer

from sentrook.config import L3Config, L3Policy, ScannerConfig
from sentrook.corpus.loader import default_corpus_dir
from sentrook.rules.loader import DEFAULT_RULES_DIR

__all__ = [
    "DEFAULT_RULES_DIR",
    "build_scanner_config",
    "rookery_api_key",
    "emit_formatted",
    "shadow_config",
]


def rookery_api_key() -> str | None:
    return os.environ.get("SENTROOK_ROOKERY_API_KEY") or None


def build_scanner_config(
    *,
    corpus: Path | None,
    l3_policy: str | None,
    allow_margin: float | None = None,
    fail_closed_margin: float | None = None,
    top_k: int | None = None,
) -> ScannerConfig:
    """Resolve L3 flags into a ScannerConfig.

    All three layers are on by default (``tie_breaker``). Pass ``--l3-policy off``
    to run L1+L2 only.
    """
    l3_kwargs: dict[str, object] = {
        "corpus_dir": str(corpus if corpus is not None else default_corpus_dir()),
    }
    if allow_margin is not None:
        l3_kwargs["allow_margin"] = allow_margin
    if fail_closed_margin is not None:
        l3_kwargs["fail_closed_margin"] = fail_closed_margin
    if top_k is not None:
        l3_kwargs["top_k"] = top_k

    policy = L3Policy(l3_policy) if l3_policy is not None else L3Policy.TIE_BREAKER

    return ScannerConfig(l3_policy=policy, l3=L3Config(**l3_kwargs))


def shadow_config(
    *,
    rules: Path | None,
    corpus: Path | None,
    l3_policy: str | None,
    log_path: Path | None,
    host: str | None,
    port: int | None,
):
    """Build a ShadowConfig from env, then apply explicit CLI overrides."""
    from sentrook.shadow.bundle import resolve_bundle_version
    from sentrook.shadow.config import ShadowConfig

    config = ShadowConfig.from_env()
    if rules is not None:
        config.rules_path = rules
        config.bundle_version = resolve_bundle_version(rules)
    if corpus is not None:
        config.corpus_dir = corpus
    if l3_policy is not None:
        config.l3_policy = L3Policy(l3_policy)
    if log_path is not None:
        config.log_path = log_path
    if host is not None:
        config.host = host
    if port is not None:
        config.port = port
    return config


def emit_formatted(
    format: str,
    *,
    json_payload: Callable[[], Any],
    text: Callable[[], str],
) -> None:
    """Echo a report as JSON or text, exiting 1 on an unknown format."""
    if format == "json":
        typer.echo(json.dumps(json_payload(), indent=2))
    elif format == "text":
        typer.echo(text())
    else:
        typer.echo(f"unknown format: {format}", err=True)
        raise typer.Exit(code=1)
