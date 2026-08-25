"""CLI: ``hermes sentrook configure|verify``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from .auth import (
    API_KEY_VAR,
    CLIENT_ID_VAR,
    CLIENT_SECRET_VAR,
    resolve_hermes_state_dir,
)
from .verify import format_verify_report, run_verify

PLUGIN_ID = "sentrook"


def _settings_from_ctx(ctx: Any | None) -> dict:
    if ctx is None:
        return {}
    for name in ("get_settings", "settings", "plugin_settings", "get_config"):
        fn = getattr(ctx, name, None)
        if callable(fn):
            try:
                val = fn()
                if isinstance(val, dict):
                    return val
            except TypeError:
                try:
                    val = fn(PLUGIN_ID)
                    if isinstance(val, dict):
                        return val
                except Exception:
                    pass
            except Exception:
                pass
        elif isinstance(fn, dict):
            return fn
    return {}


def _write_dotenv_lines(path: Path, updates: dict[str, str]) -> None:
    existing: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("#") or "=" not in trimmed:
                continue
            key, _, value = trimmed.partition("=")
            existing[key.strip()] = value.strip()
    existing.update(updates)
    lines = [f"{key}={value}" for key, value in sorted(existing.items())]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def cmd_configure(args: argparse.Namespace, ctx: Any | None = None) -> int:
    """Write scan credentials to ~/.hermes/.env and print next steps."""
    state_dir = resolve_hermes_state_dir()
    dotenv_path = state_dir / ".env"

    client_id = (getattr(args, "client_id", None) or os.environ.get(CLIENT_ID_VAR, "")).strip()
    client_secret = (getattr(args, "client_secret", None) or "").strip()
    api_key = (getattr(args, "api_key", None) or os.environ.get(API_KEY_VAR, "")).strip()

    if not client_secret and not api_key:
        print(
            "sentrook configure: provide --client-id + --client-secret or --api-key.\n"
            "You can also pre-set env vars and re-run configure to persist them.",
            file=sys.stderr,
        )
        return 2

    updates: dict[str, str] = {}
    if client_id:
        updates[CLIENT_ID_VAR] = client_id
    if client_secret:
        updates[CLIENT_SECRET_VAR] = client_secret
    if api_key:
        updates[API_KEY_VAR] = api_key

    _write_dotenv_lines(dotenv_path, updates)
    print(f"Wrote credentials to {dotenv_path}")
    print("Enable the plugin: hermes plugins enable sentrook")
    print("Then restart the gateway / CLI session and run: hermes sentrook verify")
    return 0


def cmd_verify(args: argparse.Namespace, ctx: Any | None = None) -> int:
    """Check install, enablement, hooks, credentials, health, and OIDC mint."""
    settings = _settings_from_ctx(ctx)
    result = run_verify(
        settings=settings,
        skip_health=bool(getattr(args, "skip_health", False)),
        skip_mint=bool(getattr(args, "skip_mint", False)),
    )
    print(format_verify_report(result))
    return 0 if result.ok else 1


def _handler(args: argparse.Namespace) -> None:
    ctx = getattr(args, "_plugin_ctx", None)
    sub = getattr(args, "sentrook_command", None)
    if sub == "configure":
        raise SystemExit(cmd_configure(args, ctx))
    if sub == "verify":
        raise SystemExit(cmd_verify(args, ctx))
    print("Usage: hermes sentrook <configure|verify>", file=sys.stderr)
    raise SystemExit(2)


def setup_argparse(subparser: argparse.ArgumentParser) -> None:
    subs = subparser.add_subparsers(dest="sentrook_command")
    configure = subs.add_parser("configure", help="Write Sentrook scan credentials")
    configure.add_argument("--client-id", help="OIDC client id (or use env)")
    configure.add_argument("--client-secret", help="OIDC client secret")
    configure.add_argument("--api-key", help="Static scan API key (optional)")
    verify = subs.add_parser(
        "verify",
        help="Check install, enablement, hooks, credentials, and scan reachability",
    )
    verify.add_argument("--skip-health", action="store_true", help="Skip GET /health")
    verify.add_argument(
        "--skip-mint",
        action="store_true",
        help="Skip OIDC client_credentials token mint",
    )
    subparser.set_defaults(func=_handler)


def register_cli(ctx: Any) -> None:
    def handler_with_ctx(args: argparse.Namespace) -> None:
        args._plugin_ctx = ctx
        _handler(args)

    ctx.register_cli_command(
        name="sentrook",
        help="Sentrook scan plugin — configure and verify",
        description="Manage the Sentrook Hermes plugin",
        setup_fn=setup_argparse,
        handler_fn=handler_with_ctx,
    )
