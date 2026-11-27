"""Who is behind a turn: the session platform, whether a human can answer a review, and the sender.

Hermes has no owner flag; its gateway allowlist is a yes/no admission gate. The mapping used here:
- owner (basis `host_allowlist_dm`): a direct message from a sender individually on
  `<PLATFORM>_ALLOWED_USERS` or `GATEWAY_ALLOWED_USERS`, or a local CLI/TUI turn;
- owner (basis `group_chat`): a group, channel or thread message from a sender individually on one of those lists,
  as the OpenClaw plugin sends an owner in a group. The basis keeps what needs the owner alone in the room off:
  the scanner's attended-owner ceiling, the snooze, remembered Session answers and grants, owner commands;
- other (basis `group_chat`): any other group, channel or thread message;
- other (basis `host_open_access`): a DM admitted only by allow-all (or a grant the plugin cannot see);
- unknown (basis `none`): cron, subagent, API-server and webhook runs.

A turn Hermes starts itself with a user message it wrote (a finished sub-agent or background process, a
heartbeat, a goal) is never an owner message: see `host_turns`.

The channel history Hermes puts in front of a group message is other people's words, never the sender's request
(`channel_context`).
"""

from __future__ import annotations

import os
import sys
from typing import Any

# Every platform value Hermes uses is in ATTENDED_PLATFORMS, NOT_ATTENDED_PLATFORMS or LOCAL_PLATFORMS. The Hermes
# compatibility check (integrations/hermes/compat/platforms.py) fails on a value in none of them, so a platform a new
# Hermes adds is classified on purpose.
#
# Chat surfaces have a human in-band even when stdin is not a TTY: Hermes sends its approval prompt into the chat and
# takes the reply there. The desktop app's hosted bot rooms (`bot_room`) count too: the room's controls show approvals.
ATTENDED_PLATFORMS = frozenset(
    {
        "bluebubbles",
        "bot_room",
        "buzz",
        "dingtalk",
        "discord",
        "email",
        "feishu",
        "google_chat",
        "irc",
        "lark",
        "line",
        "matrix",
        "mattermost",
        "ntfy",
        "photon",
        "qqbot",
        "signal",
        "simplex",
        "slack",
        "sms",
        "teams",
        "telegram",
        "web",
        "wecom",
        "weixin",
        "whatsapp",
        "whatsapp_cloud",
        "yuanbao",
    }
)
# Surfaces with no human answering in-band: programmatic front ends Hermes itself never asks (the API server and
# webhooks), callback and relay ingress, other agents (A2A), Raft (its adapter sends nothing; the agent posts through
# the Raft CLI, so an approval prompt reaches nobody), home automation, and runs Hermes starts itself (cron, batch runs, sub-agents, the curator, kanban
# workers, the gateway's resume and shutdown runs). None is attended unless `attended_platforms`
# names it; ordinary calls there fall back to the terminal test, and background saves never take a snooze.
NOT_ATTENDED_PLATFORMS = frozenset(
    {
        "",
        "a2a",
        "api_server",
        "batch",
        "codex",
        "cron",
        "curator",
        "gateway",
        "homeassistant",
        "kanban",
        "msgraph_webhook",
        "raft",
        "relay",
        "subagent",
        "tool",
        "webhook",
        "wecom_callback",
    }
)
UNATTENDED_PLATFORMS = frozenset({"cron", "subagent"})
LOCAL_PLATFORMS = frozenset({"cli", "tui", "local", "desktop", "acp"})
# Local front ends with their own approval card: the TUI talks to Hermes over a pipe, the desktop app talks to a
# gateway that may run as a service with no terminal (on this machine or a remote one), and an editor (ACP) talks to
# Hermes over stdio and shows its permission prompt. None has a terminal on stdin, so they are attended by platform, not
# by the terminal test the plain CLI keeps.
APP_PLATFORMS = frozenset({"tui", "desktop", "acp"})
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
    for name in ("PLATFORM", "SOURCE", "CHAT_TYPE", "CHAT_ID", "USER_ID", "ACTOR_ID", "KEY"):
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


def hermes_config() -> dict[str, Any]:
    """Effective config via Hermes's own loader (the plugin interpreter has no PyYAML)."""
    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly()
        return cfg if isinstance(cfg, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def approvals_off(cfg: dict[str, Any]) -> bool:
    """`approvals.mode` reads as off, the way Hermes reads it: YAML turns a bare `off` into False."""
    approvals = cfg.get("approvals")
    mode = approvals.get("mode") if isinstance(approvals, dict) else None
    if isinstance(mode, bool):
        return mode is False
    return isinstance(mode, str) and mode.strip().lower() == "off"


def single_query_approves(cfg: dict[str, Any]) -> bool:
    """`approvals.single_query_mode` reads as approve, the way Hermes reads it (approve, off, allow or yes, after
    `str()`; anything else, a YAML boolean included, is deny)."""
    approvals = cfg.get("approvals")
    mode = approvals.get("single_query_mode") if isinstance(approvals, dict) else None
    return str(mode).strip().lower() in ("approve", "off", "allow", "yes")


def single_query(env: dict[str, str]) -> bool:
    """A single-query run (`hermes chat -q`, or a finite `-z` turn admitted by the gateway): nobody waits to answer
    an approval prompt there. Read as Hermes reads it: the gateway's finite-turn flag, else
    `HERMES_SINGLE_QUERY_SESSION` for the session (from Hermes's session context when it has one, else the process
    environment). Anything that cannot be read counts as not single-query."""
    try:
        from gateway.session_finite import finite_turn_required

        if finite_turn_required() is True:
            return True
    except Exception:  # noqa: BLE001 - an install without the gateway package, or an older one
        pass
    value = env.get("HERMES_SINGLE_QUERY_SESSION", "")
    try:
        from gateway.session_context import get_session_env

        value = get_session_env("HERMES_SINGLE_QUERY_SESSION", "") or value
    except Exception:  # noqa: BLE001
        pass
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def unattended_turn() -> bool:
    """A `hermes -z` turn: nobody can answer a prompt, and Hermes approves every one by itself (its one-shot
    contract). Read from Hermes's gateway; False where that cannot be read (an install without it)."""
    try:
        from gateway.session_finite import unattended_turn as read

        return read() is True
    except Exception:  # noqa: BLE001 - an install without the gateway package, or an older one
        return False


def host_yolo() -> bool:
    """Hermes would approve a prompt in the current session by itself: YOLO for the process (`--yolo`), YOLO the
    owner switched on for this session (`/yolo`), or a `-z` turn, as Hermes's own approval gate reads them. Fails
    closed: when Hermes's approval module cannot be read (a plugin host outside Hermes's process, another version),
    YOLO counts as on. Used where a prompt would let a block run (a snooze's strong prompt), not for reviews."""
    try:
        from tools.approval import _yolo_active

        return bool(_yolo_active())
    except Exception:  # noqa: BLE001
        pass
    try:
        from tools.approval import is_current_session_yolo_enabled

        return bool(is_current_session_yolo_enabled()) or unattended_turn()
    except Exception:  # noqa: BLE001 - nothing readable: assume Hermes would approve it
        return True


def _approval_bypass(env: dict[str, str]) -> bool:
    """True when Hermes would auto-approve an `approve` directive: approvals are off in the config, the
    process itself runs with HERMES_YOLO_MODE (a gateway an operator started with it), a `-z` turn
    (`unattended_turn`), or a single-query run (`single_query`) where `approvals.single_query_mode` is approve. YOLO
    the owner switches on for a session (`/yolo` in a chat, `hermes chat --yolo`, which the gateway applies per
    session) is not part of Hermes's public API, so there the owner's YOLO choice also covers Sentrook's review
    prompts; a snooze's strong prompt reads it from Hermes's approval module instead (`host_yolo`)."""
    if env.get("HERMES_YOLO_MODE", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    if unattended_turn():
        return True
    cfg = hermes_config()
    if approvals_off(cfg):
        return True
    return single_query(env) and single_query_approves(cfg)


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
    if (
        platform in ATTENDED_PLATFORMS
        or platform in APP_PLATFORMS
        or platform in attended_platforms
    ):
        return False
    try:
        return not sys.stdin.isatty()
    except Exception:  # noqa: BLE001
        return False


def owner_attends(
    platform: str,
    env: dict[str, str],
    *,
    subagent: bool = False,
    attended_platforms: frozenset[str] | set[str] = frozenset(),
) -> bool:
    """The session is one the owner attends, from a positive list only: a chat platform, the TUI or the desktop app,
    the local terminal (with a terminal), or a platform in `attended_platforms`, and not a run `is_unattended` names. Any other platform (the
    curator, webhooks, the API server, an empty or unknown one) is not, whatever stdin is: the curator runs inside
    the terminal's process, and a gateway may run in a foreground terminal. Used for Hermes's background saves, whose
    snooze must never reach an unattended run; ordinary calls keep `is_unattended`."""
    if is_unattended(platform, env, subagent=subagent, attended_platforms=attended_platforms):
        return False
    return (
        platform in ATTENDED_PLATFORMS
        or platform in LOCAL_PLATFORMS
        or platform in attended_platforms
    )


#: Where Hermes shows a delegated child's approval prompt in its parent's chat. A child runs on a worker thread that
#: keeps the parent's session context, so on the gateway (the chat platforms, and the TUI and desktop app through their
#: own gateway) the child's prompt joins the parent chat's approval queue and is answered there. The classic terminal
#: and ACP answer a child's prompt on the worker thread with nobody asked: deny, or approve with
#: `delegation.subagent_auto_approve`.
CHILD_PROMPT_PLATFORMS = ATTENDED_PLATFORMS | frozenset({"tui", "desktop"})


def children_auto_approved(cfg: dict[str, Any], env: dict[str, str] | None = None) -> bool:
    """`delegation.subagent_auto_approve` is on, read as Hermes reads it (a string by its words, anything else by its
    truth): where nothing can show a sub-agent's prompt, Hermes's own callback for the sub-agent's thread approves it,
    with nobody asked. A sub-agent never asks then: its reviews are held. A config the plugin could not read, or one
    Hermes is told to ignore (`HERMES_IGNORE_USER_CONFIG`), counts as on."""
    if not cfg or _truthy(env or {}, "HERMES_IGNORE_USER_CONFIG"):
        return True
    delegation = cfg.get("delegation")
    value = delegation.get("subagent_auto_approve") if isinstance(delegation, dict) else None
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def asks_for_children(
    platform: str,
    env: dict[str, str],
    *,
    sender_relation: Any,
    sender_basis: Any = (),
    attended_platforms: frozenset[str] | set[str] = frozenset(),
) -> bool:
    """A sub-agent this session delegates to asks its reviews here, in this chat: the owner attends it
    (`owner_attends`), the turn is the owner's own (sender `owner`) outside a group chat (anyone admitted to a group
    may answer a prompt there, and the owner may not be watching a sub-agent's), and Hermes shows a child's prompt on
    this platform (`CHILD_PROMPT_PLATFORMS`). Anywhere else the sub-agent's reviews are held for the owner."""
    return (
        sender_relation == "owner"
        and "group_chat" not in (sender_basis if isinstance(sender_basis, list | tuple) else ())
        and platform in CHILD_PROMPT_PLATFORMS
        and owner_attends(platform, env, attended_platforms=attended_platforms)
    )


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


def _allowlisted(platform: str, facts: dict[str, str], sender_id: Any, env: dict[str, str]) -> bool:
    """The sender is individually on `<PLATFORM>_ALLOWED_USERS` or `GATEWAY_ALLOWED_USERS`. The sender is the turn's
    actor where Hermes names one (`HERMES_SESSION_ACTOR_ID`, who asked this turn), else the session's user (the
    session route, empty in a shared group session), else the hook's sender id."""
    up = platform.upper()
    uid = facts.get("actor_id") or facts.get("user_id") or (str(sender_id) if sender_id else "")
    return bool(uid) and uid in (
        _env_set(env, f"{up}_ALLOWED_USERS") | _env_set(env, "GATEWAY_ALLOWED_USERS")
    )


def sender_of(
    platform: str, facts: dict[str, str], sender_id: Any, env: dict[str, str]
) -> dict[str, Any]:
    if platform in LOCAL_PLATFORMS:
        return {"relation": "owner", "basis": ["host_allowlist_dm"]}
    if platform in NON_CHAT_PLATFORMS:
        return {"relation": "unknown", "basis": ["none"]}
    chat_type = (facts.get("chat_type") or "").lower()
    if chat_type and chat_type != "dm":
        if _allowlisted(platform, facts, sender_id, env):
            return {"relation": "owner", "basis": ["group_chat"]}
        return {"relation": "other", "basis": ["group_chat"]}
    if not chat_type:
        return {"relation": "unknown", "basis": ["none"]}
    if _allowlisted(platform, facts, sender_id, env):
        return {"relation": "owner", "basis": ["host_allowlist_dm"]}
    return {"relation": "other", "basis": ["host_open_access"]}


def conversation_sender_of(
    platform: str, facts: dict[str, str], sender_id: Any, env: dict[str, str]
) -> dict[str, Any]:
    """Who wrote a message in the conversation a background save is judged against: `sender_of`.

    While Hermes's write origin is its background review (the review fork or the curator, which may run in
    a context that still holds the owner's chat), nobody is the owner: the sender is unknown."""
    from .skill_review import in_background_review

    if in_background_review():
        return {"relation": "unknown", "basis": ["none"]}
    return sender_of(platform, facts, sender_id, env)


def environ() -> dict[str, str]:
    return dict(os.environ)
