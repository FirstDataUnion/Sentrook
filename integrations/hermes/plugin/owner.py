"""Owner-only commands: who may run a slash command that changes how Sentrook behaves.

Hermes passes a command handler nothing but its raw arguments, so the sender comes from the
gateway's session context, as for scans. The owner is:
- a direct message from a sender individually on `<PLATFORM>_ALLOWED_USERS` or
  `GATEWAY_ALLOWED_USERS` (the same rule as `intent.sender_of`);
- the local terminal: the `hermes sentrook` CLI, or a slash command whose session Hermes reports
  (`ctx.session_surface()`) as the CLI, TUI or desktop app. The API server sends slash commands to
  the model as text, and cron and webhook runs do not dispatch them. Recheck this on every Hermes
  upgrade.

An empty platform is also what an unreadable session context looks like, so a slash command with no
platform and no local session surface is refused.

Hermes's own `allow_admin_from` is not used: it is off by default and, once set, refuses every slash
command except /help and /whoami to everyone else.

Every attempt, allowed or refused, is written to the traffic log as a `command` record (none when
the owner has turned the traffic log off). The sender id is stored only as a salted hash.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .intent import LOCAL_PLATFORMS, resolve_platform, sender_of
from .traffic import TrafficLog


def owner_of(
    facts: dict[str, str], env: dict[str, str], *, surface: str = "", local_cli: bool = False
) -> dict[str, Any]:
    """`surface` is Hermes's report of the calling session's client (`ctx.session_surface()`, "" when
    unknown); `local_cli` is set only by the `hermes sentrook` command line."""
    platform = resolve_platform(None, facts, env)
    if not platform:
        if local_cli or surface.strip().lower() in LOCAL_PLATFORMS:
            return {"owner": True, "basis": ["local_terminal"], "platform": ""}
        return {"owner": False, "basis": ["none"], "platform": ""}
    if platform in LOCAL_PLATFORMS:
        return {"owner": True, "basis": ["local_terminal"], "platform": platform}
    sender = sender_of(platform, facts, None, env)
    return {"owner": sender["relation"] == "owner", "basis": sender["basis"], "platform": platform}


def sender_ref(user_id: str, salt: str) -> str | None:
    if not user_id:
        return None
    return "u_" + hmac.new(salt.encode(), user_id.encode(), hashlib.sha256).hexdigest()[:16]


def audit(
    traffic: TrafficLog,
    verb: str,
    check: dict[str, Any],
    *,
    ref: str | None,
    reason: str | None = None,
) -> None:
    traffic.write(
        {
            "kind": "command",
            "verb": verb,
            "outcome": "allowed" if check["owner"] else "refused",
            "basis": check["basis"],
            "sender_ref": ref,
            "platform": check["platform"],
            **({"reason": reason} if reason else {}),
        }
    )


def gate(
    verb: str,
    traffic: TrafficLog,
    salt: str,
    *,
    facts: dict[str, str],
    env: dict[str, str],
    surface: str = "",
    local_cli: bool = False,
) -> dict[str, Any]:
    """Decide whether this command may run and audit the decision. The result also carries the
    hashed sender (`sender_ref`), for commands that record who made a change."""
    check = owner_of(facts, env, surface=surface, local_cli=local_cli)
    ref = sender_ref(facts.get("user_id") or "", salt)
    audit(traffic, verb, check, ref=ref)
    return {**check, "sender_ref": ref}


def refusal(verb: str) -> str:
    return (
        f"Only the owner can run /sentrook {verb}: send it in a direct message from an account on "
        "the platform's allowed users, or from the local terminal."
    )
