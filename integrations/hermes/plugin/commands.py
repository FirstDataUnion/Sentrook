"""`/sentrook` in-session commands, each also a `hermes sentrook` subcommand with the same output.

Hermes runs plugin slash commands on gateway chats and in interactive `hermes chat`, without a model
request. Over the API server and `hermes chat --oneshot` the text goes to the model instead, so the
CLI form is the fallback there. Subcommands live in `COMMANDS`; both forms are built from it.

`history` and `why` show past traffic, so only the owner may run them: both forms go through the
owner check (`owner_command`), which audits every attempt. `status` and `help` stay open.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import history
from .auth import env_with_hermes_dotenv, resolve_oidc_credentials
from .config import resolve_config
from .owner import refusal
from .planir import PLUGIN_VERSION

logger = logging.getLogger("sentrook")

#: (verb, fn) -> fn wrapped so it runs only for the owner; see `owner_command` in the package.
OwnerGate = Callable[[str, Callable[[str], str]], Callable[[str], str]]


@dataclass(frozen=True)
class Subcommand:
    summary: str
    #: (text after the subcommand name, plugin settings, env or None for the process env) -> reply
    run: Callable[[str, dict[str, Any], dict[str, str] | None], str]
    #: The optional argument, as shown in help ("[n]"); also the CLI's optional positional.
    args: str = ""
    owner_only: bool = False


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


def run_history(rest: str, settings: dict[str, Any], env: dict[str, str] | None = None) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    if not cfg.traffic_log_enabled:
        return history.LOG_OFF
    n = history.parse_count(rest)
    if n is None:
        return f"usage: /sentrook history [n], n from 1 to {history.HISTORY_MAX}"
    return history.format_history(history.recent_scans(cfg.traffic_log_path, n), "/sentrook why")


def run_why(rest: str, settings: dict[str, Any], env: dict[str, str] | None = None) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    if not cfg.traffic_log_enabled:
        return history.LOG_OFF
    match = history.parse_ref(rest)
    if match is None:
        return "usage: /sentrook why [request_id|last], with an id (or its start) from /sentrook history"
    found = history.recent_scans(cfg.traffic_log_path, 1, match)
    if found:
        return history.format_why(*found[0])
    if rest.lower() in ("", "last"):
        return history.NO_SCANS
    return f"No scan {rest} in the recent traffic log."


def run_help(
    rest: str = "", settings: dict[str, Any] | None = None, env: dict[str, str] | None = None
) -> str:
    usage = {name: f"{name} {c.args}".rstrip() for name, c in COMMANDS.items()}
    width = max(map(len, usage.values()))
    lines = [
        f"/sentrook {usage[name].ljust(width)}  {c.summary}"
        + (" (owner only)" if c.owner_only else "")
        for name, c in COMMANDS.items()
    ]
    lines.append(
        "Where /sentrook goes to the model (API server, --oneshot): hermes sentrook <command>"
    )
    return "\n".join(lines)


COMMANDS: dict[str, Subcommand] = {
    "status": Subcommand(
        "plugin version, mode, thresholds, scan host, credentials present, traffic log, grants",
        run_status,
    ),
    "history": Subcommand(
        f"last n scans (default {history.HISTORY_DEFAULT}, at most {history.HISTORY_MAX}): "
        "time, tool, risk, action, review",
        run_history,
        args="[n]",
        owner_only=True,
    ),
    "why": Subcommand(
        "one scan's risk, tier scores, reason codes and entities",
        run_why,
        args="[request_id|last]",
        owner_only=True,
    ),
    "help": Subcommand("this list", run_help),
}


def dispatch(
    raw_args: str,
    settings: dict[str, Any],
    env: dict[str, str] | None = None,
    gate: OwnerGate | None = None,
) -> str:
    """Run the named subcommand; empty or unknown input gets the help text. An owner-only
    subcommand runs through `gate`, and is refused without one."""
    name, _, rest = (raw_args or "").strip().partition(" ")
    name = name.lower()
    cmd = COMMANDS.get(name)
    if cmd is None:
        return run_help()
    if not cmd.owner_only:
        return cmd.run(rest.strip(), settings, env)
    if gate is None:
        return refusal(name)
    return gate(name, lambda r: cmd.run(r.strip(), settings, env))(rest)


def register_slash(ctx: Any, settings: Callable[[], dict[str, Any]], gate: OwnerGate) -> None:
    def handler(raw_args: str = "", **_context: Any) -> str:
        try:
            return dispatch(raw_args, settings(), gate=gate)
        except Exception as exc:  # noqa: BLE001 - a reply beats a stack trace in the chat
            logger.warning("/sentrook failed: %s", exc)
            return f"/sentrook failed ({type(exc).__name__}); see the Hermes log."

    ctx.register_command(
        name="sentrook",
        handler=handler,
        description="Sentrook plugin status, scan history and help",
        args_hint=" | ".join(f"{name} {c.args}".rstrip() for name, c in COMMANDS.items()),
    )
