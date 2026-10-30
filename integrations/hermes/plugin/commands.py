"""`/sentrook` in-session commands, each also a `hermes sentrook` subcommand with the same output.

Hermes runs plugin slash commands on gateway chats and in interactive `hermes chat`, without a model
request. Over the API server and `hermes chat --oneshot` the text goes to the model instead, so the
CLI form is the fallback there. Subcommands live in `COMMANDS`; both forms are built from it.

`history` and `why` show past traffic, `grants`, `grant`, `revoke` and `bind` list and change the
grants and channel bindings set by command, and `snooze` relaxes review prompts, so only the owner may
run them: both forms go through the owner check (`owner_command`), which audits every attempt.
`status` and `help` stay open.

`snooze` covers the session the slash command was sent from (Hermes passes its `session_id`); the CLI
has no session, so there it can only snooze every session.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from . import grants, history, snooze
from .auth import env_with_hermes_dotenv, resolve_oidc_credentials
from .config import PluginConfig, resolve_config
from .owner import refusal
from .planir import PLUGIN_VERSION
from .traffic import TrafficLog

logger = logging.getLogger("sentrook")

#: Who ran an owner-only command: {"basis", "platform", "sender_ref"}.
Who = dict[str, Any]
#: (verb, fn) -> fn wrapped so it runs only for the owner; see `owner_command` in the package.
OwnerGate = Callable[[str, Callable[[str, Who], str]], Callable[[str], str]]
#: How the owner types a subcommand, for usage and hints.
CMD = "/sentrook {}".format


@dataclass(frozen=True)
class Subcommand:
    summary: str
    #: (text after the subcommand name, plugin settings, env or None for the process env, who ran
    #: it for owner-only subcommands) -> reply
    run: Callable[[str, dict[str, Any], dict[str, str] | None, Who | None], str]
    #: The arguments, as shown in help ("[n]").
    args: str = ""
    owner_only: bool = False
    #: The CLI takes everything after the subcommand (flags included) instead of one optional word.
    cli_rest: bool = False
    #: `run` also gets the current session's id (`session_id`, "" when there is none).
    session: bool = False


def run_status(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    """Config-derived facts only: no network calls, and credentials as present or missing, never values."""
    env = env_with_hermes_dotenv(env)
    cfg = resolve_config(settings, env)
    ep = cfg.endpoints
    scan = ep.scan.url + (" (dev endpoints)" if ep.dev else "") if ep.scan.ok else ""
    creds = resolve_oidc_credentials(settings, env, ep.issuer.url) is not None
    grant_count, binding_count = grants.counts(cfg, grants.load(cfg.state_dir))
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
            f"grants: {grant_count}",
            f"channel bindings: {binding_count}",
            f"snooze: {snooze.status_line(snooze.load(cfg.state_dir), datetime.now(UTC))}",
        )
    )


def run_history(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    if not cfg.traffic_log_enabled:
        return history.LOG_OFF
    n = history.parse_count(rest)
    if n is None:
        return f"usage: /sentrook history [n], n from 1 to {history.HISTORY_MAX}"
    return history.format_history(history.recent_scans(cfg.traffic_log_path, n), "/sentrook why")


def run_why(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
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


def _changed(
    cfg: PluginConfig, result: tuple[str, dict[str, Any] | None], who: Who, kind: str = "grants"
) -> str:
    """The reply, after writing the change (if any) to the traffic log."""
    reply, record = result
    if record is not None:
        TrafficLog(cfg.traffic_log_path, cfg.traffic_log_max_bytes, cfg.traffic_log_enabled).write(
            {"kind": kind, **record, "by": who}
        )
    return reply


def run_grants(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    return grants.format_grants(cfg, grants.load(cfg.state_dir), datetime.now(UTC), CMD)


def run_grant(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    if who is None:
        return refusal("grant")
    now = datetime.now(UTC)
    return _changed(cfg, grants.add_grant(cfg.state_dir, rest, who, now, CMD), who)


def run_revoke(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    if who is None:
        return refusal("revoke")
    now = datetime.now(UTC)
    return _changed(cfg, grants.revoke(cfg.state_dir, cfg, rest, now, CMD), who)


def run_bind(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    if who is None:
        return refusal("bind")
    now = datetime.now(UTC)
    return _changed(cfg, grants.bind(cfg.state_dir, cfg, rest, who, now, CMD), who)


def run_snooze(
    rest: str,
    settings: dict[str, Any],
    env: dict[str, str] | None = None,
    who: Who | None = None,
    session_id: str = "",
) -> str:
    cfg = resolve_config(settings, env_with_hermes_dotenv(env))
    if who is None:
        return refusal("snooze")
    ref = snooze.session_ref(session_id) if session_id else None
    now = datetime.now(UTC)
    return _changed(cfg, snooze.run(cfg.state_dir, rest, ref, who, now, CMD), who, "snooze")


def run_help(
    rest: str = "",
    settings: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    who: Who | None = None,
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
    "grants": Subcommand(
        "grants in force: from config (read-only) and set by command",
        run_grants,
        owner_only=True,
    ),
    "grant": Subcommand(
        "add a grant: kind destination|file|provider; flags --persistent (default session "
        "scope), --allows read,write (file only), --expires 12h",
        run_grant,
        args="<kind> <pattern> [flags]",
        owner_only=True,
        cli_rest=True,
    ),
    "revoke": Subcommand(
        "remove a grant set by command", run_revoke, args="<id>", owner_only=True, cli_rest=True
    ),
    "bind": Subcommand(
        "list, add or remove a channel binding (an expected delivery destination)",
        run_bind,
        args="add|remove|list [channel]",
        owner_only=True,
        cli_rest=True,
    ),
    "snooze": Subcommand(
        "allow review prompts in this session (--all: every session) for a duration, default "
        "1h, at most 24h; never blocks, enforced reviews or unattended runs; off; status",
        run_snooze,
        args="[duration|off|status] [--all]",
        owner_only=True,
        cli_rest=True,
        session=True,
    ),
    "help": Subcommand("this list", run_help),
}


def dispatch(
    raw_args: str,
    settings: dict[str, Any],
    env: dict[str, str] | None = None,
    gate: OwnerGate | None = None,
    session_id: str = "",
) -> str:
    """Run the named subcommand; empty or unknown input gets the help text. An owner-only
    subcommand runs through `gate`, and is refused without one. `session_id` is the session the
    command was sent from ("" for none)."""
    name, _, rest = (raw_args or "").strip().partition(" ")
    name = name.lower()
    cmd = COMMANDS.get(name)
    if cmd is None:
        return run_help()
    if not cmd.owner_only:
        return cmd.run(rest.strip(), settings, env)
    if gate is None:
        return refusal(name)
    extra = {"session_id": session_id} if cmd.session else {}
    return gate(name, lambda r, who: cmd.run(r.strip(), settings, env, who, **extra))(rest)


def register_slash(ctx: Any, settings: Callable[[], dict[str, Any]], gate: OwnerGate) -> None:
    def handler(raw_args: str = "", **context: Any) -> str:
        try:
            sid = context.get("session_id")
            return dispatch(
                raw_args, settings(), gate=gate, session_id=sid if isinstance(sid, str) else ""
            )
        except Exception as exc:  # noqa: BLE001 - a reply beats a stack trace in the chat
            logger.warning("/sentrook failed: %s", exc)
            return f"/sentrook failed ({type(exc).__name__}); see the Hermes log."

    ctx.register_command(
        name="sentrook",
        handler=handler,
        description="Sentrook plugin status, scan history, grants, snooze and help",
        args_hint=" | ".join(f"{name} {c.args}".rstrip() for name, c in COMMANDS.items()),
    )
