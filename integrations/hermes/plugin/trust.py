"""Who the owner trusts besides themselves: trusted users and trusted chats.

A trusted user (`trust-user add <platform>:<user id>`, or `trusted_senders` in the config) is a person the owner
knows. Their messages are sent as `relation: trusted` (basis `plugin_allowlist:sender`, plus `group_chat` in a group),
not as someone else's (`other`). A trusted chat (`trust-chat add <platform>:<chat id>`, or `trusted_chats`) is a group
or server channel where the owner knows everyone who can post: every member's message there is `trusted` (basis
`plugin_allowlist:chat` and `group_chat`). A thread or topic in a trusted chat is covered too (Hermes names its parent
chat). The owner's own messages stay the owner's.

A trusted Discord server (`trust-chat add discord:server:<server id>`, or the same text in `trusted_chats`) covers every
channel and thread in that server, including ones created later: a turn matches when Hermes reports that server for it
(`HERMES_SESSION_SCOPE_ID`, the Discord guild id). The `server:` word keeps a server entry apart from a channel entry,
so a channel id is never read as a server id or the other way round (on Discord an old #general channel can share its
server's id). A direct message is never covered by a server entry. Only Discord for now; a server entry on another
platform, or on a Hermes that does not report the server, is refused when it is added.

Trusted is never the owner. Grants, bindings, settings, the setup screen and every owner command stay the owner's
alone, from a direct message or the terminal; the scanner's floors apply whoever sent the turn; a trusted turn is not
one the owner attends (no snooze, no grant set by approving a review).

**Reviews in a trusted chat.** Hermes lets any member it admits answer an approval prompt in a channel (unless
`approvals.approvers` narrows it, and even then the member who asked may answer their own). So by default members of
a trusted chat answer its reviews, and a Session answer there is kept for that chat (`session_allow`) without setting a
grant. A chat added with `--owner-only` holds its reviews for the owner instead: the agent says it is waiting, the owner
gets a notice and answers it with `allow <id>` from a direct message or the terminal (`hold`).

Both lists are owner-only, changed only from a direct message or the terminal (the owner check refuses a group),
and every change is written to the traffic log as a `settings` record that names the platform, never an id. A chat
the command was sent from (a direct chat) cannot be trusted as a chat: a person is a trusted user. The settings file
that cannot be read trusts nothing beyond the config.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import intent
from .config import PluginConfig
from .intent import ATTENDED_PLATFORMS
from .store import Store

#: Chat platforms a person can write from: the only ones a trusted user or chat can be on.
PLATFORMS = ATTENDED_PLATFORMS
_PLATFORM = re.compile(r"[a-z0-9_]{1,40}")
#: A chat or user id as Hermes names it: no spaces or control characters (a Matrix room id has colons).
_ID = re.compile(r"[^\s\x00-\x1f\x7f]{1,200}")
#: Entries kept per list.
MAX_ENTRIES = 200
OWNER_ONLY = "--owner-only"
#: The word that makes a trusted-chat entry a whole server: `discord:server:<server id>`.
SERVER = "server:"
#: Platforms whose server id Hermes reports per turn and a server entry can name.
SERVER_PLATFORMS = frozenset({"discord"})
#: A Discord server (guild) id: a number.
_SERVER_ID = re.compile(r"[0-9]{1,25}")


def is_server(key: str) -> bool:
    """`platform:server:<id>`: a whole-server entry."""
    return key.partition(":")[2].startswith(SERVER)


def server_support() -> str | None:
    """None when this Hermes reports a turn's server id (`HERMES_SESSION_SCOPE_ID`); else why not."""
    return intent.scope_support()


@dataclass(frozen=True)
class Trust:
    """The trusted users (`platform:user id`) and chats (`platform:chat id` -> owner-only) in force."""

    senders: frozenset[str] = frozenset()
    chats: dict[str, bool] = field(default_factory=dict)

    def sender(self, platform: str, uid: str) -> bool:
        return bool(uid) and f"{platform}:{uid}" in self.senders

    def chat(self, platform: str, facts: dict[str, str]) -> tuple[str, bool] | None:
        """The trusted chat this turn is in, by its chat id or (for a thread or topic) its parent's, or by the server
        Hermes reports for it (`scope_id`, Discord only): (`platform:chat id` or `platform:server:<id>`, owner-only),
        or None. A chat id is only ever matched against chat entries and the server id against server entries. When a
        chat and its server are both trusted, the chat's key is given, owner-only when either entry says so."""
        found: list[str] = []
        for cid in (facts.get("chat_id"), facts.get("parent_chat_id")):
            if isinstance(cid, str) and cid and not cid.startswith(SERVER):
                key = f"{platform}:{cid}"
                if key in self.chats:
                    found.append(key)
                    break
        scope = facts.get("scope_id")
        if platform in SERVER_PLATFORMS and isinstance(scope, str) and _SERVER_ID.fullmatch(scope):
            key = f"{platform}:{SERVER}{scope}"
            if key in self.chats:
                found.append(key)
        if not found:
            return None
        return found[0], any(self.chats[k] for k in found)


def parse_ref(raw: Any) -> tuple[str, str] | None:
    """`<platform>:<id>` as (platform, id), or None. The platform must be a chat platform. A server entry
    (`discord:server:<server id>`, id `server:<number>`) must be on a platform in `SERVER_PLATFORMS`."""
    if not isinstance(raw, str):
        return None
    platform, sep, ident = raw.strip().partition(":")
    platform = platform.lower()
    if not sep or not _PLATFORM.fullmatch(platform) or platform not in PLATFORMS:
        return None
    if not _ID.fullmatch(ident):
        return None
    if ident.lower().startswith(SERVER):
        sid = ident[len(SERVER) :]
        if platform not in SERVER_PLATFORMS or not _SERVER_ID.fullmatch(sid):
            return None
        return platform, SERVER + sid
    return platform, ident


def server_problem(raw: Any) -> str | None:
    """Why `raw`, written as a server entry, cannot be one; None when it is not written as one or is fine."""
    if not isinstance(raw, str):
        return None
    platform, _, ident = raw.strip().partition(":")
    if not ident.lower().startswith(SERVER):
        return None
    if platform.lower() not in SERVER_PLATFORMS:
        return (
            f"A whole server can be trusted only on Discord for now; on {_clean(platform.lower(), 40)}, trust each "
            "chat by its id instead"
        )
    if not _SERVER_ID.fullmatch(ident[len(SERVER) :]):
        return "A Discord server id is a number: write it as discord:server:<server id>"
    return None


def _config_chats(raw: Any) -> dict[str, bool]:
    """`trusted_chats` from the config: a list of `platform:chat id`, or of `{chat, owner_only}`."""
    out: dict[str, bool] = {}
    items = raw if isinstance(raw, (list, tuple)) else ([raw] if isinstance(raw, str) else [])
    for item in items:
        owner_only = False
        if isinstance(item, dict):
            owner_only = item.get("owner_only") is True
            item = item.get("chat")
        if isinstance(item, str):
            for part in item.split(","):
                ref = parse_ref(part)
                if ref:
                    key = ":".join(ref)
                    out[key] = out.get(key, False) or owner_only
    return out


def _config_senders(raw: Any) -> set[str]:
    items = raw if isinstance(raw, (list, tuple)) else ([raw] if isinstance(raw, str) else [])
    out: set[str] = set()
    for item in items:
        for part in str(item).split(",") if isinstance(item, (str, int)) else []:
            ref = parse_ref(part)
            if ref:
                out.add(":".join(ref))
    return out


def _stored(data: dict[str, Any] | None) -> tuple[dict[str, bool], set[str]]:
    chats: dict[str, bool] = {}
    for e in (data or {}).get("trusted_chats") or []:
        ref = parse_ref(e.get("chat")) if isinstance(e, dict) else None
        if ref:
            chats[":".join(ref)] = e.get("owner_only") is True
    senders: set[str] = set()
    for e in (data or {}).get("trusted_senders") or []:
        ref = parse_ref(e.get("user")) if isinstance(e, dict) else None
        if ref:
            senders.add(":".join(ref))
    return chats, senders


def of(cfg: PluginConfig) -> Trust:
    """The config's lists and those the owner set by command. A chat in both is owner-only when either says so."""
    data = Store(cfg.state_dir).load_settings()
    chats, senders = _stored(data)
    for key, owner_only in _config_chats(cfg.trusted_chats).items():
        chats[key] = chats.get(key, False) or owner_only
    return Trust(frozenset(senders | _config_senders(cfg.trusted_senders)), chats)


def verify_check(cfg: PluginConfig) -> tuple[bool, str]:
    """`verify`'s trusted-chats line: what is trusted, and, failed, a trusted server this Hermes cannot match (it does
    not report a turn's server, so the entry never covers a message)."""
    line = trust_line(cfg).split(". ")[0]
    servers = [k for k in of(cfg).chats if is_server(k)]
    why = server_support() if servers else None
    if why:
        return (
            False,
            f"{line}; the trusted servers never match: {why}. Trust each chat by its id instead",
        )
    return True, line


# ---- the explanations ---------------------------------------------------------------------------------

TRUSTED_IS = (
    "Trusted is not the owner: their messages count as from someone you know, not a stranger, but grants, "
    "settings and Sentrook commands stay yours alone, from a direct message or the terminal, and Sentrook still "
    "stops anything risky."
)


def trust_line(cfg: PluginConfig) -> str:
    t = of(cfg)
    if not t.chats and not t.senders:
        return "Trusted chats and users: none. Messages from anyone but you in a group count as a stranger's."
    owner_only = sum(1 for v in t.chats.values() if v)
    servers = sum(1 for k in t.chats if is_server(k))
    chats = f"{len(t.chats)} trusted chat{'s' if len(t.chats) != 1 else ''}"
    notes = []
    if servers:
        notes.append(f"{servers} whole server{'s' if servers != 1 else ''}")
    if owner_only:
        notes.append(f"{owner_only} hold reviews for you")
    if notes:
        chats += f" ({', '.join(notes)})"
    users = f"{len(t.senders)} trusted user{'s' if len(t.senders) != 1 else ''}"
    return f"Trusted: {chats}, {users}. {TRUSTED_IS}"


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(s: Any, cap: int = 60) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


def chat_warning(key: str, owner_only: bool, open_platform: bool, cmd: Any) -> str:
    server = is_server(key)
    where = (
        "in any channel or thread of this server, including ones created later,"
        if server
        else "in this chat,"
    )
    who = (
        f"Hermes lets anyone at all write to the agent on this platform, so everyone who can post {where} now and "
        "later, counts as someone you trust"
        if open_platform
        else f"Everyone who can post {where} now and later, counts as someone you trust"
        if server
        else "Everyone who can post there, now and later, counts as someone you trust"
    )
    reviews = (
        "Sentrook will hold its reviews for you: you answer them from a direct message or the terminal."
        if owner_only
        else "Any member Hermes lets answer may approve a review there (narrow that with approvals.approvers in "
        f"Hermes's config, or add the chat with {OWNER_ONLY} to have reviews held for you)."
    )
    flag = f" {OWNER_ONLY}" if owner_only else ""
    when = (
        "server only when you know every member and who can join it"
        if server
        else "chat only on a private server where you know every member"
    )
    return (
        f"Warning: {who}. {reviews} {TRUSTED_IS} Trust a {when}, never an open or public group. "
        f"To trust it: {cmd('trust-chat add')} {key}{flag} --confirm"
    )


def user_warning(key: str, cmd: Any) -> str:
    return (
        f"Warning: messages from {key} will count as from someone you trust, in any chat. {TRUSTED_IS} "
        f"To trust them: {cmd('trust-user add')} {key} --confirm"
    )


def _usage(kind: str, cmd: Any) -> str:
    c = cmd(f"trust-{kind}")
    ref = (
        "<platform>:<chat id>|discord:server:<server id>"
        if kind == "chat"
        else "<platform>:<user id>"
    )
    extra = f" [{OWNER_ONLY}]" if kind == "chat" else ""
    return f"usage: {c} add {ref}{extra} [--confirm], {c} remove {ref} or {c} list"


def _list(cfg: PluginConfig, kind: str) -> str:
    t = of(cfg)
    if kind == "chat":
        rows = [
            f"- {k}{' (every channel and thread in this server)' if is_server(k) else ''}"
            f"{' (reviews held for you)' if v else ''}"
            for k, v in sorted(t.chats.items())
        ]
    else:
        rows = [f"- {k}" for k in sorted(t.senders)]
    head = trust_line(cfg)
    return "\n".join([head, *rows]) if rows else head


def run(
    cfg: PluginConfig,
    kind: str,
    rest: str,
    by: dict[str, Any],
    chat: dict[str, str],
    env: dict[str, str],
    now: datetime,
    cmd: Any,
    change: Any,
) -> tuple[str, dict[str, Any] | None]:
    """`trust-chat ...` or `trust-user ...` (`kind` chat or user): the reply and the change record for the traffic
    log, or None when nothing changed. `chat` is the chat the command was sent from (a direct chat, or none from the
    terminal); `change` applies a change to the settings file under its lock (`owner_settings._change`)."""
    words = rest.split()
    flags = {w for w in words if w.startswith("--")}
    words = [w for w in words if not w.startswith("--")]
    allowed = {"--confirm", OWNER_ONLY} if kind == "chat" else {"--confirm"}
    unknown = sorted(flags - allowed)
    if unknown:
        return f"Unknown option {_clean(unknown[0], 40)}.\n{_usage(kind, cmd)}", None
    op = words[0].lower() if words else "list"
    if op == "list" and len(words) <= 1:
        return _list(cfg, kind), None
    if op not in ("add", "remove") or len(words) != 2:
        return _usage(kind, cmd), None
    ref = parse_ref(words[1])
    problem = server_problem(words[1]) if kind == "chat" else None
    if problem:
        return f"{problem}. Nothing was changed.\n{_usage(kind, cmd)}", None
    if ref is None:
        return (
            f'"{_clean(words[1])}" is not a {kind} on a chat platform: write it as <platform>:<id>, for example '
            f"discord:1234567890.\n{_usage(kind, cmd)}",
            None,
        )
    platform, ident = ref
    key = f"{platform}:{ident}"
    field_name, list_name = (
        ("chat", "trusted_chats") if kind == "chat" else ("user", "trusted_senders")
    )
    configured = (
        key in _config_chats(cfg.trusted_chats)
        if kind == "chat"
        else key in _config_senders(cfg.trusted_senders)
    )
    record = {"op": f"trust_{kind}_{op}", "platform": platform}

    if op == "remove":
        if configured:
            return f"{key} is set in the plugin config ({list_name}); remove it there.", None

        def drop(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
            items = data.get(list_name) or []
            kept = [e for e in items if not (isinstance(e, dict) and e.get(field_name) == key)]
            if len(kept) == len(items):
                return f"{key} was not trusted by command. Nothing was changed.", None
            data[list_name] = kept
            gone = (
                "its members' messages count as strangers' again"
                if kind == "chat"
                else ("their messages count as a stranger's again")
            )
            return f"Removed {key}: {gone}.", record

        return change(drop)

    if op == "add" and is_server(key):
        why = server_support()
        if why:
            return (
                f"A whole server cannot be trusted here: {why}. Trust each chat by its id instead. Nothing was changed.",
                None,
            )
    if kind == "chat" and chat.get("chat_id") and chat.get("chat_id") == ident:
        return (
            "This is your direct chat with the agent; a chat is trusted for a group's members. To trust a person, "
            f"use {cmd('trust-user add')} <platform>:<user id>. Nothing was changed."
        ), None
    owner_only = OWNER_ONLY in flags
    if configured:
        return (
            f"{key} is already trusted ({list_name} in the plugin config; change it there). Nothing was changed.",
            None,
        )
    if "--confirm" not in flags:
        if kind == "chat":
            open_platform = any(
                env.get(n, "").strip().lower() in ("1", "true", "yes")
                for n in (f"{platform.upper()}_ALLOW_ALL_USERS", "GATEWAY_ALLOW_ALL_USERS")
            )
            return chat_warning(key, owner_only, open_platform, cmd), None
        return user_warning(key, cmd), None

    def add(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        items = data.get(list_name)
        if not isinstance(items, list):
            items = []
        same = [e for e in items if isinstance(e, dict) and e.get(field_name) == key]
        if same and (kind == "user" or bool(same[0].get("owner_only")) == owner_only):
            return f"{key} is already trusted. Nothing was changed.", None
        if not same and len(items) >= MAX_ENTRIES:
            return f"At most {MAX_ENTRIES} can be trusted; remove one first.", None
        entry: dict[str, Any] = {field_name: key, "set_at": _show(now), "set_by": by}
        if kind == "chat":
            entry["owner_only"] = owner_only
        data[list_name] = [e for e in items if e not in same] + [entry]
        undo = f"To undo: {cmd(f'trust-{kind} remove')} {key}."
        if kind == "user":
            return f"Trusted {key}. {TRUSTED_IS} {undo}", record
        reviews = (
            "Its reviews are held for you."
            if owner_only
            else "Members there may answer its reviews."
        )
        whom = (
            "messages from its members in every channel and thread, including ones created later, count"
            if is_server(key)
            else "its members' messages count"
        )
        return (
            f"Trusted {key}: {whom} as from someone you trust. {reviews} {undo}",
            record,
        )

    return change(add)
