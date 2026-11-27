"""`hermes sentrook login`: sign in and store the scan credentials (`login`). `hermes sentrook verify`: endpoints
valid, credentials present, scanner healthy, token mint works.

The `/sentrook` subcommands (`commands.COMMANDS`, except help) are `hermes sentrook` subcommands too,
with the same output. Owner-only ones go through the same owner check, where the local terminal counts
as the owner.
"""

from __future__ import annotations

import argparse
import functools
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from . import build, grants, hold, login, owner_settings, passes, setup, skill_review
from .auth import (
    ConsentWithdrawn,
    clear_scan_token_cache,
    get_scan_access_token,
    http_json,
    missing_credentials,
    resolve_oidc_credentials,
)
from .commands import COMMANDS, OwnerGate, dispatch
from .config import PluginConfig, resolve_config
from .grants import binding_problems_summary, unsent_summary


def unreached_summary(cfg: PluginConfig, now: datetime) -> str:
    """The channel bindings in force (config and command) that no message send in the traffic log would
    carry (`setup.unreached_bindings`); "" with the log off, no send in it, or every binding carried."""
    if not cfg.traffic_log_enabled:
        return ""
    ev = setup.read_evidence(cfg.traffic_log_path, cfg.review_at, now)
    force = setup.in_force(cfg, grants.load(cfg.state_dir), now)
    return ", ".join(grants._clean(p, 60) for p in setup.unreached_bindings(force, ev))


def run_verify(
    settings: dict[str, Any], env: dict[str, str] | None = None, timeout: float = 8.0
) -> list[tuple[str, bool, str]]:
    env = dict(os.environ) if env is None else env
    cfg = resolve_config(settings, env)
    ep = cfg.endpoints
    checks: list[tuple[str, bool, str]] = []
    for name, e in (("scan URL", ep.scan), ("Rookery URL", ep.rookery), ("OIDC issuer", ep.issuer)):
        checks.append(
            (name, e.ok, (e.url + (" (dev endpoints)" if ep.dev else "")) if e.ok else e.reason)
        )
    oidc = resolve_oidc_credentials(settings, env, ep.issuer.url) if ep.issuer.ok else None
    missing = missing_credentials()
    if missing:
        creds = f"not signed in: {' and '.join(missing)} not set (run hermes sentrook login, then restart Hermes)"
    elif oidc:
        creds = f"client {oidc.client_id}, audience {oidc.audience}"
    else:
        creds = "set in Hermes; not used until the OIDC issuer is valid"
    checks.append(("credentials", not missing, creds))
    if ep.scan.ok:
        try:
            status, body, _ = http_json(f"{ep.scan.url}/healthz", timeout=timeout)
            info = body if isinstance(body, dict) else {}
            checks.append(
                (
                    "scanner health",
                    status == 200 and info.get("ok") is not False,
                    f"HTTP {status} version={info.get('version', '?')} env={info.get('environment', '?')}",
                )
            )
        except OSError as exc:
            checks.append(("scanner health", False, str(exc)[:160]))
    if oidc:
        clear_scan_token_cache()
        try:
            get_scan_access_token(oidc, timeout=timeout)
            checks.append(("token mint", True, f"issued by {oidc.issuer}"))
        except ConsentWithdrawn:
            checks.append(
                (
                    "token mint",
                    False,
                    "consent for Sentrook was withdrawn on the FIDU portal; run hermes sentrook login to reconnect",
                )
            )
        except Exception as exc:  # noqa: BLE001
            detail = str(exc)[:200]
            if "invalid_client" in detail:
                detail = "the identity service refused these credentials (revoked or wrong); run hermes sentrook login"
            checks.append(("token mint", False, detail))
    checks.append(
        (
            "policy",
            True,
            f"mode={cfg.mode} review>={cfg.review_at} block>={cfg.block_at} on_scan_error={cfg.on_scan_error}",
        )
    )
    # Failed while a running Hermes process still runs a build from before the last reinstall: the fixes installed
    # since do not apply there until it restarts.
    checks.append(("running build", *build.verify_check(cfg.state_dir)))
    checks.append(
        ("traffic log", True, str(cfg.traffic_log_path) if cfg.traffic_log_enabled else "off")
    )
    # Reported, not failed: a config grant that is never sent only makes Sentrook stricter.
    unsent = unsent_summary(cfg)
    checks.append(
        (
            "config grants",
            True,
            f"{len(cfg.grants)} in config" + (f"; never sent: {unsent}" if unsent else ""),
        )
    )
    problems = binding_problems_summary(cfg)
    unreached = unreached_summary(cfg, datetime.now(UTC))
    checks.append(
        (
            "channel bindings",
            True,
            f"{len(cfg.channel_bindings)} in config"
            + (f"; cannot apply: {problems}" if problems else "")
            + (f"; no message send in the traffic log matches: {unreached}" if unreached else ""),
        )
    )
    # Reported, not failed: without a notice target a held call still waits; the owner is just not told.
    notify = owner_settings.notify_of(cfg)
    failed = owner_settings.failed_line(cfg)
    checks.append(
        (
            "notice target",
            True,
            " ".join(x for x in (owner_settings.notify_line(notify), failed) if x),
        )
    )
    checks.append(("approval prompts", True, owner_settings.attended_line(cfg)))
    target, why = hold.owner_target(notify)
    checks.append(
        (
            "held-call notices",
            True,
            f"to the {hold.target_text(target)}" if target else f"not sent: {why}",
        )
    )
    # Failed when unreadable: a pass or denial the owner set could not be applied, so the job is held again.
    state = passes.counts(cfg.state_dir, datetime.now(UTC))
    checks.append(("held-call passes", state != "passes file unreadable", state))
    # Reported, not failed: Hermes's background saves never ask, so without a notice target the owner learns of
    # one that was let through, held or blocked only from history.
    checks.append(
        (
            "background-save notices",
            True,
            skill_review.notice_line(notify),
        )
    )
    return checks


def format_report(checks: list[tuple[str, bool, str]]) -> str:
    return "\n".join(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}" for name, ok, detail in checks)


#: Command-line-only subcommands: no slash form.
LOCAL_COMMANDS = ("login", "verify")


def _login(settings: dict[str, Any], name: str | None) -> int:
    """`hermes sentrook login`, then the same checks as `verify` (Hermes's writer updates this process's
    environment, so the new credentials are checked here before the gateway restarts)."""

    def verify() -> tuple[str, bool]:
        checks = run_verify(settings)
        return format_report(checks), all(ok for _, ok, _ in checks)

    return login.run_login(settings, name=name, deps=login.LoginDeps(verify=verify))


#: argparse gives the CLI its own help.
CLI_COMMANDS = tuple(name for name in COMMANDS if name != "help")
#: `grant`'s valued flags, declared to argparse so they may come before or after the positionals;
#: the values themselves are checked by the shared parser.
GRANT_FLAGS = ("scope", "session", "allows", "expires")
#: `report`'s flags, declared so one may come without an id (`hermes sentrook report --full`).
REPORT_FLAGS = ("full", "github", "save")


def _rest(cmd: str, args: argparse.Namespace) -> str:
    """The text after the subcommand, as the slash form would receive it."""
    arg = getattr(args, "sentrook_arg", "") or ""
    words = arg if isinstance(arg, list) else [arg]
    if cmd == "grant":
        if args.persistent:
            words.append("--persistent")
        words += [f"--{f}={getattr(args, f)}" for f in GRANT_FLAGS if getattr(args, f) is not None]
    if cmd == "snooze" and args.all:
        words.append("--all")
    if cmd == "attended" and args.confirm:
        words.append("--confirm")
    if cmd == "report":
        words += [f"--{f}" for f in REPORT_FLAGS if getattr(args, f)]
    return " ".join(words)


def register_cli(ctx: Any, settings: Callable[[], dict[str, Any]], gate: OwnerGate) -> None:
    def setup(parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="sentrook_cmd")
        sub.add_parser("verify", help="Check endpoints, credentials, scanner health and token mint")
        login_parser = sub.add_parser(
            "login",
            help="Sign in with your FIDU account in a browser and store Sentrook's credentials",
        )
        login_parser.add_argument(
            "--name",
            help="How this machine is listed in your account (default: Hermes on <hostname>)",
        )
        for name in CLI_COMMANDS:
            p = sub.add_parser(name, help=COMMANDS[name].summary)
            if name == "grant":
                p.add_argument("sentrook_arg", nargs="*", metavar="<kind> <pattern>")
                p.add_argument("--persistent", action="store_true")
                for flag in GRANT_FLAGS:
                    p.add_argument(f"--{flag}")
            elif name == "report":
                p.add_argument("sentrook_arg", nargs="*", metavar="request_id|last")
                for flag in REPORT_FLAGS:
                    p.add_argument(f"--{flag}", action="store_true")
            elif name == "snooze":
                p.add_argument("sentrook_arg", nargs="*", metavar="duration|off|status")
                p.add_argument("--all", action="store_true", help="every session")
            elif name == "attended":
                p.add_argument("sentrook_arg", nargs="*", metavar="add|remove|list [platform]")
                p.add_argument(
                    "--confirm",
                    action="store_true",
                    help="add a platform Sentrook treats as unattended",
                )
            elif name == "notify":
                p.add_argument("sentrook_arg", nargs="*", metavar="<platform>|off|status")
            elif COMMANDS[name].cli_rest:
                p.add_argument(
                    "sentrook_arg", nargs=argparse.REMAINDER, metavar=COMMANDS[name].args
                )
            elif COMMANDS[name].args:
                p.add_argument("sentrook_arg", nargs="?", default="", metavar=COMMANDS[name].args)

    def handler(args: argparse.Namespace) -> None:
        cmd = getattr(args, "sentrook_cmd", None)
        if cmd in CLI_COMMANDS:
            send = functools.partial(hold.deliver, ctx)
            print(dispatch(f"{cmd} {_rest(cmd, args)}", settings(), gate=gate, send=send))
            return
        if cmd == "login":
            raise SystemExit(_login(settings(), getattr(args, "name", None)))
        if cmd != "verify":
            print(f"usage: hermes sentrook {{{','.join(LOCAL_COMMANDS + CLI_COMMANDS)}}}")
            return
        checks = run_verify(settings())
        print(format_report(checks))
        if not all(ok for _, ok, _ in checks):
            raise SystemExit(1)

    ctx.register_cli_command(
        name="sentrook",
        help=f"Sentrook plugin helpers ({', '.join(LOCAL_COMMANDS + CLI_COMMANDS)})",
        description="Sentrook plugin helpers",
        setup_fn=setup,
        handler_fn=handler,
    )
