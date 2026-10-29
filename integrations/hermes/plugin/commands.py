"""`/sentrook` in-session commands, each also a `hermes sentrook` subcommand with the same output.

Hermes runs plugin slash commands on gateway chats and in interactive `hermes chat`, without a model
request. Over the API server and `hermes chat --oneshot` the text goes to the model instead, so the
CLI form is the fallback there. Subcommands live in `COMMANDS`; both forms are built from it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .auth import env_with_hermes_dotenv, resolve_oidc_credentials
from .config import resolve_config
from .planir import PLUGIN_VERSION

logger = logging.getLogger("sentrook")


@dataclass(frozen=True)
class Subcommand:
    summary: str
    #: (text after the subcommand name, plugin settings, env or None for the process env) -> reply
    run: Callable[[str, dict[str, Any], dict[str, str] | None], str]


def run_status(rest: str, settings: dict[str, Any], env: dict[str, str] | None = None) -> str:
    """Config-derived facts only: no network calls, and credentials as present or missing, never values."""
    env = env_with_hermes_dotenv(env)
    cfg = resolve_config(settings, env)
    ep = cfg.endpoints
    scan = ep.scan.url + (" (dev endpoints)" if ep.dev else "") if ep.scan.ok else ""
    creds = resolve_oidc_credentials(settings, env, ep.issuer.url) is not None
    return "\n".join(
        (
            f"Sentrook plugin {PLUGIN_VERSION}",
            f"mode: {cfg.mode}",
            f"review at: {cfg.review_at:g}, block at: {cfg.block_at:g}",
            f"on scan error: {cfg.on_scan_error}",
            f"scan host: {scan or f'invalid ({ep.scan.reason})'}",
            "credentials: "
            + ("present" if creds else "missing (SENTROOK_SCAN_CLIENT_ID / _SECRET)"),
            "traffic log: " + (f"on, {cfg.traffic_log_path}" if cfg.traffic_log_enabled else "off"),
            f"grants: {len(cfg.grants)}",
        )
    )


def run_help(
    rest: str = "", settings: dict[str, Any] | None = None, env: dict[str, str] | None = None
) -> str:
    width = max(map(len, COMMANDS))
    lines = [f"/sentrook {name.ljust(width)}  {c.summary}" for name, c in COMMANDS.items()]
    lines.append(
        "Where /sentrook goes to the model (API server, --oneshot): hermes sentrook <command>"
    )
    return "\n".join(lines)


COMMANDS: dict[str, Subcommand] = {
    "status": Subcommand(
        "plugin version, mode, thresholds, scan host, credentials present, traffic log, grants",
        run_status,
    ),
    "help": Subcommand("this list", run_help),
}


def dispatch(raw_args: str, settings: dict[str, Any], env: dict[str, str] | None = None) -> str:
    """Run the named subcommand; empty or unknown input gets the help text."""
    name, _, rest = (raw_args or "").strip().partition(" ")
    cmd = COMMANDS.get(name.lower())
    return cmd.run(rest.strip(), settings, env) if cmd else run_help()


def register_slash(ctx: Any, settings: Callable[[], dict[str, Any]]) -> None:
    def handler(raw_args: str = "", **_context: Any) -> str:
        try:
            return dispatch(raw_args, settings())
        except Exception as exc:  # noqa: BLE001 - a reply beats a stack trace in the chat
            logger.warning("/sentrook failed: %s", exc)
            return f"/sentrook failed ({type(exc).__name__}); see the Hermes log."

    ctx.register_command(
        name="sentrook",
        handler=handler,
        description="Sentrook plugin status and help",
        args_hint=" | ".join(COMMANDS),
    )
