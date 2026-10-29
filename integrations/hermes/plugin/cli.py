"""`hermes sentrook verify`: endpoints valid, credentials present, scanner healthy, token mint works.

The `/sentrook` subcommands (`commands.COMMANDS`, except help) are `hermes sentrook` subcommands too,
with the same output. Owner-only ones go through the same owner check, where the local terminal counts
as the owner.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any

from .auth import (
    clear_scan_token_cache,
    env_with_hermes_dotenv,
    get_scan_access_token,
    http_json,
    resolve_oidc_credentials,
)
from .commands import COMMANDS, OwnerGate, dispatch
from .config import resolve_config


def run_verify(
    settings: dict[str, Any], env: dict[str, str] | None = None, timeout: float = 8.0
) -> list[tuple[str, bool, str]]:
    env = env_with_hermes_dotenv(env)
    cfg = resolve_config(settings, env)
    ep = cfg.endpoints
    checks: list[tuple[str, bool, str]] = []
    for name, e in (("scan URL", ep.scan), ("Rookery URL", ep.rookery), ("OIDC issuer", ep.issuer)):
        checks.append(
            (name, e.ok, (e.url + (" (dev endpoints)" if ep.dev else "")) if e.ok else e.reason)
        )
    oidc = resolve_oidc_credentials(settings, env, ep.issuer.url) if ep.issuer.ok else None
    checks.append(
        (
            "credentials",
            oidc is not None,
            f"client {oidc.client_id}, audience {oidc.audience}"
            if oidc
            else "SENTROOK_SCAN_CLIENT_ID / _SECRET not set",
        )
    )
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
        except Exception as exc:  # noqa: BLE001
            checks.append(("token mint", False, str(exc)[:200]))
    checks.append(
        (
            "policy",
            True,
            f"mode={cfg.mode} review>={cfg.review_at} block>={cfg.block_at} on_scan_error={cfg.on_scan_error}",
        )
    )
    checks.append(
        ("traffic log", True, str(cfg.traffic_log_path) if cfg.traffic_log_enabled else "off")
    )
    return checks


def format_report(checks: list[tuple[str, bool, str]]) -> str:
    return "\n".join(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}" for name, ok, detail in checks)


#: argparse gives the CLI its own help.
CLI_COMMANDS = tuple(name for name in COMMANDS if name != "help")
#: `grant`'s valued flags, declared to argparse so they may come before or after the positionals;
#: the values themselves are checked by the shared parser.
GRANT_FLAGS = ("scope", "allows", "expires")


def _rest(cmd: str, args: argparse.Namespace) -> str:
    """The text after the subcommand, as the slash form would receive it."""
    arg = getattr(args, "sentrook_arg", "") or ""
    words = arg if isinstance(arg, list) else [arg]
    if cmd == "grant":
        if args.persistent:
            words.append("--persistent")
        words += [f"--{f}={getattr(args, f)}" for f in GRANT_FLAGS if getattr(args, f) is not None]
    return " ".join(words)


def register_cli(ctx: Any, settings: Callable[[], dict[str, Any]], gate: OwnerGate) -> None:
    def setup(parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="sentrook_cmd")
        sub.add_parser("verify", help="Check endpoints, credentials, scanner health and token mint")
        for name in CLI_COMMANDS:
            p = sub.add_parser(name, help=COMMANDS[name].summary)
            if name == "grant":
                p.add_argument("sentrook_arg", nargs="*", metavar="<kind> <pattern>")
                p.add_argument("--persistent", action="store_true")
                for flag in GRANT_FLAGS:
                    p.add_argument(f"--{flag}")
            elif COMMANDS[name].cli_rest:
                p.add_argument(
                    "sentrook_arg", nargs=argparse.REMAINDER, metavar=COMMANDS[name].args
                )
            elif COMMANDS[name].args:
                p.add_argument("sentrook_arg", nargs="?", default="", metavar=COMMANDS[name].args)

    def handler(args: argparse.Namespace) -> None:
        cmd = getattr(args, "sentrook_cmd", None)
        if cmd in CLI_COMMANDS:
            print(dispatch(f"{cmd} {_rest(cmd, args)}", settings(), gate=gate))
            return
        if cmd != "verify":
            print(f"usage: hermes sentrook {{{','.join(('verify', *CLI_COMMANDS))}}}")
            return
        checks = run_verify(settings())
        print(format_report(checks))
        if not all(ok for _, ok, _ in checks):
            raise SystemExit(1)

    ctx.register_cli_command(
        name="sentrook",
        help=f"Sentrook plugin helpers ({', '.join(('verify', *CLI_COMMANDS))})",
        description="Sentrook plugin helpers",
        setup_fn=setup,
        handler_fn=handler,
    )
