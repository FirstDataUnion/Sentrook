"""Who is behind a turn: the session platform, whether a human can answer a review, and the sender.

Hermes has no owner flag; its gateway allowlist is a yes/no admission gate. The mapping used here:
- owner (basis `host_allowlist_dm`): a direct message from a sender individually on
  `<PLATFORM>_ALLOWED_USERS` or `GATEWAY_ALLOWED_USERS`, or a local CLI/TUI turn;
- other (basis `group_chat`): any group, channel or thread message, even from a listed user;
- other (basis `host_open_access`): a DM admitted only by allow-all (or a grant the plugin cannot see);
- unknown (basis `none`): cron, subagent, API-server and webhook runs.
"""

from __future__ import annotations

import os
import sys
from typing import Any

# Chat surfaces have a human in-band even when stdin is not a TTY. Webhook and home-automation
# surfaces often have no approval UI, so they stay unattended.
ATTENDED_PLATFORMS = frozenset(
    {
        "discord",
        "telegram",
        "slack",
        "whatsapp",
        "signal",
        "matrix",
        "sms",
        "email",
        "web",
        "feishu",
        "lark",
        "yuanbao",
        "dingtalk",
        "wecom",
        "mattermost",
    }
)
UNATTENDED_PLATFORMS = frozenset({"cron", "subagent"})
LOCAL_PLATFORMS = frozenset({"cli", "tui", "local", "desktop"})
NON_CHAT_PLATFORMS = frozenset({"cron", "subagent", "api_server", "webhook", ""})
TRIGGER_BY_PLATFORM = {
    "cron": "scheduled",
    "subagent": "subagent",
    "webhook": "hook",
    "api_server": "hook",
}
CHANNELS = frozenset({"discord", "telegram", "slack", "email", "webhook"})


def session_facts() -> dict[str, str]:
    """The gateway's task-local session context (the chat this turn came from). Hermes keeps it in
    ContextVars so concurrent chats do not clobber each other; process env alone is wrong there."""
    try:
        from gateway.session_context import get_session_env
    except Exception:  # noqa: BLE001 - not running under the gateway
        return {}
    out: dict[str, str] = {}
    for name in ("PLATFORM", "SOURCE", "CHAT_TYPE", "CHAT_ID", "USER_ID", "KEY"):
        try:
            value = get_session_env(f"HERMES_SESSION_{name}", "")
        except Exception:  # noqa: BLE001
            value = ""
        out[name.lower()] = value if isinstance(value, str) else ""
    return out


def resolve_platform(turn_platform: Any, facts: dict[str, str], env: dict[str, str]) -> str:
    for value in (
        turn_platform,
        facts.get("platform"),
        env.get("HERMES_SESSION_PLATFORM"),
        env.get("HERMES_PLATFORM"),
    ):
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _approval_bypass(env: dict[str, str]) -> bool:
    """True when Hermes would auto-approve an `approve` directive (YOLO, approvals.mode off)."""
    try:
        from tools.approval import is_approval_bypass_active

        if is_approval_bypass_active():
            return True
    except Exception:  # noqa: BLE001
        pass
    return env.get("HERMES_YOLO_MODE", "").strip().lower() in ("1", "true", "yes", "on")


def is_unattended(
    platform: str,
    env: dict[str, str],
    *,
    subagent: bool = False,
    attended_platforms: frozenset[str] | set[str] = frozenset(),
) -> bool:
    """Contexts where a review cannot reach a human (or would be auto-approved): reviews become blocks.
    `attended_platforms` adds surfaces this deployment knows have a human answering approvals (for
    example an API-server front end that shows Hermes's approval prompts)."""
    if env.get("HERMES_CRON_SESSION", "").strip().lower() in ("1", "true", "yes"):
        return True
    if _approval_bypass(env):
        return True
    if subagent or platform in UNATTENDED_PLATFORMS:
        return True
    if platform in ATTENDED_PLATFORMS or platform in attended_platforms:
        return False
    try:
        return not sys.stdin.isatty()
    except Exception:  # noqa: BLE001
        return False


def trigger_kind(platform: str) -> str:
    if not platform:
        return "unknown"
    return TRIGGER_BY_PLATFORM.get(platform, "message")


def channel_of(platform: str) -> str | None:
    if not platform:
        return None
    if platform in CHANNELS:
        return platform
    if platform in LOCAL_PLATFORMS:
        return "chat"
    if platform in NON_CHAT_PLATFORMS:
        return None
    return "other"


def _env_set(env: dict[str, str], name: str) -> set[str]:
    return {s.strip() for s in env.get(name, "").split(",") if s.strip()}


def _truthy(env: dict[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in ("1", "true", "yes")


def sender_of(
    platform: str, facts: dict[str, str], sender_id: Any, env: dict[str, str]
) -> dict[str, Any]:
    if platform in LOCAL_PLATFORMS:
        return {"relation": "owner", "basis": ["host_allowlist_dm"]}
    if platform in NON_CHAT_PLATFORMS:
        return {"relation": "unknown", "basis": ["none"]}
    chat_type = (facts.get("chat_type") or "").lower()
    if chat_type and chat_type != "dm":
        return {"relation": "other", "basis": ["group_chat"]}
    if not chat_type:
        return {"relation": "unknown", "basis": ["none"]}
    up = platform.upper()
    uid = facts.get("user_id") or (str(sender_id) if sender_id else "")
    if uid and uid in (
        _env_set(env, f"{up}_ALLOWED_USERS") | _env_set(env, "GATEWAY_ALLOWED_USERS")
    ):
        return {"relation": "owner", "basis": ["host_allowlist_dm"]}
    return {"relation": "other", "basis": ["host_open_access"]}


def environ() -> dict[str, str]:
    return dict(os.environ)
