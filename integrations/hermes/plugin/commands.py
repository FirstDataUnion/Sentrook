"""`/sentrook` in-session commands, each also a `hermes sentrook` subcommand with the same output.

Hermes runs plugin slash commands on gateway chats and in interactive `hermes chat`, without a model
request. Over the API server and `hermes chat --oneshot` the text goes to the model instead, so the
CLI form is the fallback there. Subcommands live in `COMMANDS`; both forms are built from it.

`history` and `why` show past traffic, `report` packs one scan for sending to Sentrook, `grants`, `grant`, `revoke` and `bind` list and change the
grants and channel bindings set by command, `snooze` relaxes review prompts, `allow` and `deny` (and `approve`, the
same as `allow`) answer a call held on an unattended run (see `hold`), `passes` lists and revokes what those
answers set (see `passes`), and `notify` and `attended` set where notices go and which extra platforms have a person
answering approvals (see `owner_settings`), so only the owner may run them: both forms go through the owner check
(`owner_command`), which audits every attempt. `status` and `help` stay open.

`notify here` stores the chat the slash command was sent in: Hermes passes the handler that chat (`source`, a
gateway SessionSource). The CLI has no chat, so there it takes `notify <platform>`.

`snooze` and a session `grant` cover the session the slash command was sent from (Hermes passes its
`session_id`). The CLI has no session, so there a snooze needs `--all` and a session grant `--session`.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from . import grants, history, hold, owner_settings, passes, report, skill_review, snooze
from .auth import missing_credentials
from .config import PluginConfig, resolve_config
from .owner import refusal
from .planir import PLUGIN_VERSION, session_ref
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
    #: `run` also gets the chat the command was sent in (`chat`: platform, chat_id, thread_id, chat_type; empty
    #: when there is none).
    chat: bool = False


def run_status(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    """Config-derived facts and counts from the local traffic log only: no network calls, and
    credentials as present or missing, never values."""
    cfg = resolve_config(settings, env)
    ep = cfg.endpoints
    scan = ep.scan.url + (" (dev endpoints)" if ep.dev else "") if ep.scan.ok else ""
    missing = missing_credentials()
    grant_count, binding_count = grants.counts(cfg, grants.load(cfg.state_dir))
    notify = owner_settings.notify_of(cfg)
    return "\n".join(
        (
            f"Sentrook plugin {PLUGIN_VERSION}",
            f"mode: {cfg.mode}",
            f"review at: {cfg.review_at:g}, block at: {cfg.block_at:g}",
            f"on scan error: {cfg.on_scan_error}",
            f"scan host: {scan or f'invalid ({ep.scan.reason})'}",
            "credentials: "
            + (f"missing {' and '.join(missing)} (set in Hermes)" if missing else "present"),
            "traffic log: " + (f"on, {cfg.traffic_log_path}" if cfg.traffic_log_enabled else "off"),
            f"grants: {grant_count}",
            f"channel bindings: {binding_count}",
            f"snooze: {snooze.status_line(snooze.load(cfg.state_dir), datetime.now(UTC))}",
            # Plain sentences, the same wherever shown: "Notices: ..." and "Attended platforms: ...".
            owner_settings.notify_line(notify, CMD),
            owner_settings.attended_line(cfg),
            f"held calls: {hold.status_line(cfg.state_dir, notify, datetime.now(UTC))}",
            f"passes: {passes.counts(cfg.state_dir, datetime.now(UTC))}",
            "skill review: "
            + skill_review.status_line(
                skill_review.setting_text(cfg.skill_review, cfg.skill_review_unknown),
                cfg.traffic_log_path if cfg.traffic_log_enabled else None,
            ),
            *(
                ("background saves: " + skill_review.HOST_ISOLATION_TEXT,)
                if skill_review.host_isolated(env)
                else ()
            ),
            "background-save notices: " + skill_review.notice_line(notify),
        )
    )


def run_history(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env)
    if not cfg.traffic_log_enabled:
        return history.LOG_OFF
    n = history.parse_count(rest)
    if n is None:
        return f"usage: /sentrook history [n], n from 1 to {history.HISTORY_MAX}"
    return history.format_history(history.recent_scans(cfg.traffic_log_path, n), "/sentrook why")


def run_why(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env)
    if not cfg.traffic_log_enabled:
        return history.LOG_OFF
    if hold.is_id(rest):
        return hold.why_text(cfg.state_dir, cfg.traffic_log_path, rest, datetime.now(UTC), CMD)
    match = history.parse_ref(rest)
    if match is None:
        return (
            "usage: /sentrook why [request_id|last], with an id (or its start) from "
            "/sentrook history, or the id in a held-call notice"
        )
    found = history.recent_scans(cfg.traffic_log_path, 1, match)
    if found:
        return history.format_why(*found[0])
    if rest.lower() in ("", "last"):
        return history.NO_SCANS
    return f"No scan {rest} in the recent traffic log."


REPORT_USAGE = (
    "usage: /sentrook report [request_id|last] [--full|--github|--save], with an id (or its start) "
    "from /sentrook history"
)


def run_report(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env)
    if not cfg.traffic_log_enabled:
        return history.LOG_OFF
    args = report.parse_args(rest)
    match = history.parse_ref(args[0]) if args is not None else None
    if args is None or match is None:
        return REPORT_USAGE
    found = report.find(cfg.traffic_log_path, match)
    if found is None:
        if args[0].lower() in ("", "last"):
            return history.NO_SCANS
        return f"No scan {args[0]} in the recent traffic log."
    return report.reply(found, args[1], CMD, cfg.state_dir)


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
    rest: str,
    settings: dict[str, Any],
    env: dict[str, str] | None = None,
    who: Who | None = None,
    session_id: str = "",
) -> str:
    cfg = resolve_config(settings, env)
    ref = session_ref(session_id) if session_id else None
    return grants.format_grants(cfg, grants.load(cfg.state_dir), datetime.now(UTC), CMD, ref)


def run_grant(
    rest: str,
    settings: dict[str, Any],
    env: dict[str, str] | None = None,
    who: Who | None = None,
    session_id: str = "",
) -> str:
    cfg = resolve_config(settings, env)
    if who is None:
        return refusal("grant")
    ref = session_ref(session_id) if session_id else None
    now = datetime.now(UTC)
    return _changed(cfg, grants.add_grant(cfg.state_dir, rest, ref, who, now, CMD), who)


def run_revoke(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env)
    if who is None:
        return refusal("revoke")
    now = datetime.now(UTC)
    return _changed(cfg, grants.revoke(cfg.state_dir, cfg, rest, now, CMD), who)


def run_bind(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env)
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
    cfg = resolve_config(settings, env)
    if who is None:
        return refusal("snooze")
    ref = session_ref(session_id) if session_id else None
    now = datetime.now(UTC)
    return _changed(cfg, snooze.run(cfg.state_dir, rest, ref, who, now, CMD), who, "snooze")


def _answer(verb: str) -> Callable[..., str]:
    def run(
        rest: str,
        settings: dict[str, Any],
        env: dict[str, str] | None = None,
        who: Who | None = None,
    ) -> str:
        cfg = resolve_config(settings, env)
        if who is None:
            return refusal(verb)
        log = TrafficLog(cfg.traffic_log_path, cfg.traffic_log_max_bytes, cfg.traffic_log_enabled)
        return hold.answer(cfg.state_dir, verb, rest, who, datetime.now(UTC), CMD, log.write)

    return run


run_allow = _answer("allow")
run_deny = _answer("deny")
run_approve = _answer("approve")


def run_passes(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env)
    if who is None:
        return refusal("passes")
    op, _, arg = rest.strip().partition(" ")
    now = datetime.now(UTC)
    if not op or op.lower() == "list":
        return passes.format_passes(cfg.state_dir, now, CMD)
    if op.lower() != "revoke":
        return f"usage: {CMD('passes')} [revoke <id>]"
    return _changed(cfg, passes.revoke(cfg.state_dir, arg, now), who, "passes")


def run_notify(
    rest: str,
    settings: dict[str, Any],
    env: dict[str, str] | None = None,
    who: Who | None = None,
    chat: dict[str, str] | None = None,
) -> str:
    cfg = resolve_config(settings, env)
    if who is None:
        return refusal("notify")
    now = datetime.now(UTC)
    result = owner_settings.run_notify(cfg, rest, chat or {}, who, now, CMD)
    return _changed(cfg, result, who, "settings")


def run_attended(
    rest: str, settings: dict[str, Any], env: dict[str, str] | None = None, who: Who | None = None
) -> str:
    cfg = resolve_config(settings, env)
    if who is None:
        return refusal("attended")
    now = datetime.now(UTC)
    return _changed(cfg, owner_settings.run_attended(cfg, rest, who, now, CMD), who, "settings")


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
    if settings is not None:
        cfg = resolve_config(settings, env)
        lines.append(owner_settings.notify_line(owner_settings.notify_of(cfg), CMD))
        lines.append(owner_settings.attended_line(cfg))
    return "\n".join(lines)


COMMANDS: dict[str, Subcommand] = {
    "status": Subcommand(
        "plugin version, mode, thresholds, scan host, credentials present, traffic log, grants, "
        "snooze, held calls, skill review",
        run_status,
    ),
    "history": Subcommand(
        f"last n scans (default {history.HISTORY_DEFAULT}, at most {history.HISTORY_MAX}): "
        "time, session, tool, risk, action, review",
        run_history,
        args="[n]",
        owner_only=True,
    ),
    "why": Subcommand(
        "one scan's risk, tier scores, reason codes and entities; for a held call's id, also the "
        "hold, the answers it offers and the grant Sentrook suggests",
        run_why,
        args="[request_id|last]",
        owner_only=True,
    ),
    "report": Subcommand(
        "a report of a scan that looks wrong, to send to Sentrook: --full adds the exact request (send "
        "it privately), --github links a public issue with the summary filled in, --save writes "
        "the report and full record to a file to email",
        run_report,
        args="[request_id|last] [--full|--github|--save]",
        owner_only=True,
        cli_rest=True,
    ),
    "grants": Subcommand(
        "grants in force: from config (read-only) and set by command",
        run_grants,
        owner_only=True,
        session=True,
    ),
    "grant": Subcommand(
        "add a grant: kind destination|file|provider|repo; flags --persistent (default: this session "
        "only, not cron jobs, subagents or other chats), --session <ref> (from history), "
        "--allows read,write (file only), --expires 12h",
        run_grant,
        args="<kind> <pattern> [flags]",
        owner_only=True,
        cli_rest=True,
        session=True,
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
        "1h, at most 24h; blocks with no clear attack signal ask instead; never other blocks, "
        "enforced reviews or unattended runs; off; status",
        run_snooze,
        args="[duration|off|status] [--all]",
        owner_only=True,
        cli_rest=True,
        session=True,
    ),
    "allow": Subcommand(
        "answer a call held on an unattended run, by the id in Sentrook's notice, within 7 days: let it "
        "through once on the job's next run (later: the same), or with always for 30 days on that job, "
        "where the notice offers it; the held call is not run again",
        run_allow,
        args="<id> [later|always]",
        owner_only=True,
        cli_rest=True,
    ),
    "deny": Subcommand(
        "refuse a call held on a cron job, by the id in Sentrook's notice: that job is refused the same "
        "call for 30 days, with no more notices",
        run_deny,
        args="<id>",
        owner_only=True,
        cli_rest=True,
    ),
    "approve": Subcommand(
        "the same as allow (kept for one release)",
        run_approve,
        args="<id>",
        owner_only=True,
        cli_rest=True,
    ),
    "passes": Subcommand(
        "passes and denials your answers to held calls set, with their use counts; revoke one by its id",
        run_passes,
        args="[revoke <id>]",
        owner_only=True,
        cli_rest=True,
    ),
    "notify": Subcommand(
        "where Sentrook's notices go (held calls on scheduled jobs and other runs nobody watches): here "
        "stores this chat; <platform> its home channel (from the terminal); off goes back to owner_channel "
        "in config; status",
        run_notify,
        args="here|off|status|<platform>",
        owner_only=True,
        cli_rest=True,
        chat=True,
    ),
    "attended": Subcommand(
        "list, add or remove a platform where a person answers Hermes's approval prompts; adding one "
        "loosens Sentrook (a review there asks instead of holding the call), and one Sentrook treats as "
        "unattended needs --confirm",
        run_attended,
        args="add|remove|list [platform] [--confirm]",
        owner_only=True,
        cli_rest=True,
    ),
    "help": Subcommand(
        "this list, and where notices go and which platforms are attended", run_help
    ),
}


def dispatch(
    raw_args: str,
    settings: dict[str, Any],
    env: dict[str, str] | None = None,
    gate: OwnerGate | None = None,
    session_id: str = "",
    chat: dict[str, str] | None = None,
) -> str:
    """Run the named subcommand; empty or unknown input gets the help text. An owner-only
    subcommand runs through `gate`, and is refused without one. `session_id` is the session the
    command was sent from ("" for none); `chat` the chat (empty for none, as on the CLI)."""
    name, _, rest = (raw_args or "").strip().partition(" ")
    name = name.lower()
    cmd = COMMANDS.get(name)
    if cmd is None:
        return run_help(settings=settings, env=env)
    if not cmd.owner_only:
        return cmd.run(rest.strip(), settings, env)
    if gate is None:
        return refusal(name)
    extra: dict[str, Any] = {"session_id": session_id} if cmd.session else {}
    if cmd.chat:
        extra["chat"] = dict(chat or {})
    return gate(name, lambda r, who: cmd.run(r.strip(), settings, env, who, **extra))(rest)


def chat_of(source: Any) -> dict[str, str]:
    """The chat a slash command was sent in, from the gateway SessionSource Hermes passes the handler: platform,
    chat id, thread id and chat type ("" for each it does not give). Empty without one (the local terminal)."""
    if source is None:
        return {}
    platform = getattr(source, "platform", None)
    platform = getattr(platform, "value", platform)

    def text(v: Any) -> str:
        return str(v).strip() if isinstance(v, (str, int)) and str(v).strip() else ""

    return {
        "platform": text(platform).lower(),
        "chat_id": text(getattr(source, "chat_id", None)),
        "thread_id": text(getattr(source, "thread_id", None)),
        "chat_type": text(getattr(source, "chat_type", None)).lower(),
    }


def register_slash(ctx: Any, settings: Callable[[], dict[str, Any]], gate: OwnerGate) -> None:
    def handler(raw_args: str = "", **context: Any) -> str:
        try:
            sid = context.get("session_id")
            platform = context.get("platform")
            if isinstance(platform, str) and platform.strip():
                gate_here: OwnerGate = functools.partial(gate, platform=platform.strip())
            else:
                gate_here = gate
            return dispatch(
                raw_args,
                settings(),
                gate=gate_here,
                session_id=sid if isinstance(sid, str) else "",
                chat=chat_of(context.get("source")),
            )
        except Exception as exc:  # noqa: BLE001 - a reply beats a stack trace in the chat
            logger.warning("/sentrook failed: %s", exc)
            return f"/sentrook failed ({type(exc).__name__}); see the Hermes log."

    ctx.register_command(
        name="sentrook",
        handler=handler,
        description=(
            "Sentrook plugin status, scan history, grants, snooze, held calls, notices, attended "
            "platforms and help"
        ),
        args_hint=" | ".join(f"{name} {c.args}".rstrip() for name, c in COMMANDS.items()),
    )
