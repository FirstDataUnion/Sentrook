"""Two settings the owner sets by command, kept in `<hermes home>/sentrook/settings.json`.

`notify here|off|status|<platform>`: where Sentrook's notices go (held calls on unattended runs, scan failures there,
background saves). `here` stores the chat the command was sent in (its platform, chat id and thread), and notices
are sent there with `hermes send --to <platform>:<chat id>[:<thread>]`. The chat must be the one the owner check
judged (same platform, same chat id when the check had one, a direct message). Each new target gets a test notice,
sent like any other notice; when it is not delivered (on some platforms Hermes reaches a new chat only once it has
listed it), `notify status`, `status` and `verify` say so (`failed_line`) until a later notice gets through or the
target changes. When Hermes does not say which chat it was,
`here` stores the platform and notices go to its home channel (`/sethome`), and the reply says so and names that
channel. `notify <platform>` (the form for the terminal, which has no chat) stores a platform with a home channel.
A target set by command wins over `owner_channel` in the config; `off` removes it, so `owner_channel` applies again.

`attended add|remove|list <platform> [--confirm]`: platforms where a person answers Hermes's approval prompts,
added to `attended_platforms` in the config. Adding one loosens Sentrook: a review there shows an approval prompt
instead of holding the call for the owner. Only front ends that can put a person in front of those prompts (the API
server, webhooks, A2A peers, relays and the like: `CONFIRMABLE`) can be added, each with `--confirm` after a warning.
Runs Hermes starts itself (cron, subagents, batch runs, the curator, kanban workers, ...) can never be added: where
nobody answers, Hermes may approve a prompt itself (its cron and unattended approval modes), so a risky call could run
unseen. Nor can Raft, whose prompts reach nobody, or the local terminal (`cli`, `local`), which is attended only with
a terminal; adding it would make a scripted `hermes chat -q` count as attended. A platform outside `CONFIRMABLE` in
the file is ignored.

Both are owner-only (the owner check audits every attempt) and every change is written to the traffic log as a
`settings` record that names the platform, never a chat id. A file that cannot be read sets nothing: no notice
target (the config one applies) and no extra attended platform. Status, verify, help, `notify status` and
`attended list` show the same explanation of each (`notify_line`, `attended_line`).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PluginConfig
from .intent import (
    APP_PLATFORMS,
    ATTENDED_PLATFORMS,
    LOCAL_PLATFORMS,
    NON_CHAT_PLATFORMS,
    NOT_ATTENDED_PLATFORMS,
    UNATTENDED_PLATFORMS,
)
from .store import LockTimeout, Store, file_lock

#: Serialises read-modify-write of the file within this process; `file_lock` does across processes.
_LOCK = threading.Lock()
_PLATFORM = re.compile(r"[a-z0-9_]{1,40}")
#: A chat or thread id as Hermes gives it: printable, no spaces (`-1001234`, `C0123`, `!room:server`, `+1555...`).
_CHAT_ID = re.compile(r"[^\s]{1,200}")
MAX_ATTENDED = 50

#: (subcommand) -> the command as the owner types it, e.g. "/sentrook notify".
Cmd = Callable[[str], str]

#: Every platform name Sentrook knows, for `attended add`.
KNOWN_PLATFORMS = frozenset(
    (ATTENDED_PLATFORMS | NOT_ATTENDED_PLATFORMS | LOCAL_PLATFORMS | APP_PLATFORMS) - {""}
)
#: Attended without being added: a review there already shows an approval prompt.
ATTENDED_BY_DEFAULT = ATTENDED_PLATFORMS | APP_PLATFORMS
#: Runs Hermes starts itself, where an approval nobody answers may be approved by Hermes, and Raft, whose approval
#: prompts reach nobody: never attended.
SELF_STARTED = UNATTENDED_PLATFORMS | frozenset(
    {"batch", "codex", "curator", "gateway", "kanban", "raft", "tool"}
)
#: The local terminal, attended only when it has a terminal (`intent.is_unattended`): never added.
TERMINAL = LOCAL_PLATFORMS - APP_PLATFORMS
#: Front ends that can put a person in front of Hermes's approval prompts: the only platforms `attended add` takes.
CONFIRMABLE = KNOWN_PLATFORMS - ATTENDED_BY_DEFAULT - SELF_STARTED - TERMINAL

#: Where a test notice that was not delivered is remembered: {"to": the target, "at": when}.
FAILED_KEY = "test_notice_failed"
#: The reply's line about the test notice; `where` is "this chat" or "the <platform> home channel".
TEST_SENT = (
    "A test notice was sent to {where}. If it does not arrive within a minute, see /sentrook notify status, "
    "which says whether it was delivered."
)
FAILED_TEXT = (
    "The last test notice to the {where} was not delivered: check the Hermes log for why, then send "
    "/sentrook notify here again (on some platforms Hermes reaches a new chat only after a few minutes)."
)

#: Sent once where notices now go, so the owner sees they arrive.
TEST_NOTICE = (
    "Sentrook test notice: Sentrook's notices will come here. You set this with /sentrook notify; "
    "/sentrook notify off undoes it."
)

NOTICE_WHY = (
    "When a scheduled job or another run nobody watches tries something Sentrook wants you to check, "
    "Sentrook stops that call and tells you there."
)


@dataclass(frozen=True)
class Notify:
    """The notice target in force."""

    #: "" when none is set.
    platform: str = ""
    #: "" for the platform's home channel.
    chat_id: str = ""
    thread_id: str = ""
    #: "command", "config" or "" (none set).
    source: str = ""
    #: `owner_channel` from the config, "" when unset (shown when a command-set target overrides it).
    config: str = ""

    @property
    def to(self) -> str:
        """The target as `hermes send --to` takes it."""
        if not self.chat_id:
            return self.platform
        # A thread is kept only when the chat id itself has no colon. Hermes reads everything after the platform of a
        # Matrix (or XMPP) target as the room id, so `!room:server:$event` would name a room that does not exist;
        # dropping the thread there is deliberate, and the notice goes to the room itself.
        thread = f":{self.thread_id}" if self.thread_id and ":" not in self.chat_id else ""
        return f"{self.platform}:{self.chat_id}{thread}"


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(state_dir: Path) -> dict[str, Any] | None:
    return Store(state_dir).load_settings()


def _stored_notify(data: dict[str, Any] | None) -> dict[str, str] | None:
    """The command-set notice target when it is well formed."""
    raw = (data or {}).get("notify")
    if not isinstance(raw, dict):
        return None
    platform, chat, thread = raw.get("platform"), raw.get("chat_id", ""), raw.get("thread_id", "")
    if not isinstance(platform, str) or not _PLATFORM.fullmatch(platform):
        return None
    for v in (chat, thread):
        if not isinstance(v, str) or (v and not _CHAT_ID.fullmatch(v)):
            return None
    return {"platform": platform, "chat_id": chat, "thread_id": thread}


def notify_of(cfg: PluginConfig) -> Notify:
    """The notice target in force: set by command, else `owner_channel`, else none."""
    found = _stored_notify(load(cfg.state_dir))
    if found:
        return Notify(**found, source="command", config=cfg.owner_channel)
    if cfg.owner_channel:
        return Notify(cfg.owner_channel, source="config", config=cfg.owner_channel)
    return Notify()


def _stored_attended(data: dict[str, Any] | None) -> list[str]:
    out: list[str] = []
    for e in (data or {}).get("attended") or []:
        p = e.get("platform") if isinstance(e, dict) else None
        if isinstance(p, str) and p in CONFIRMABLE and p not in out:
            out.append(p)
    return out


def attended_of(cfg: PluginConfig) -> frozenset[str]:
    """`attended_platforms` from the config and the platforms added by command."""
    return cfg.attended_platforms | frozenset(_stored_attended(load(cfg.state_dir)))


# ---- the explanations ---------------------------------------------------------------------------------


def notify_line(n: Notify, cmd: Cmd | None = None) -> str:
    """Where notices go and why it matters, in plain words: the same text everywhere it is shown."""
    c = cmd or _cmd
    if not n.platform:
        return (
            "Notices not set: calls held on scheduled jobs and other runs nobody watches are held "
            f"silently. In the chat where you want notices, send {c('notify here')}."
        )
    where = (
        f"the {n.platform} chat where you sent {c('notify here')}"
        if n.chat_id
        else f"the {n.platform} home channel"
    )
    if n.source == "command":
        over = f"; owner_channel {n.config} in config is not used" if n.config else ""
        how = f"set by command{over}"
    else:
        how = "owner_channel in config"
    return f"Notices: {where} ({how}). {NOTICE_WHY}"


def attended_line(cfg: PluginConfig) -> str:
    """Which extra platforms count as attended, and what that means: the same text everywhere it is shown."""
    added = _stored_attended(load(cfg.state_dir))
    shown = [f"{p} (config)" for p in sorted(cfg.attended_platforms)] + [
        f"{p} (set by command)" for p in added if p not in cfg.attended_platforms
    ]
    if not shown:
        return (
            "Attended platforms: none added. Reviews in chats, the terminal and the Hermes apps show you "
            "an approval prompt; elsewhere outside chat they are held for you."
        )
    return (
        f"Attended platforms: {', '.join(shown)}. Reviews there show you an approval prompt. "
        "Elsewhere outside chat they are held for you."
    )


def _cmd(sub: str) -> str:
    return f"/sentrook {sub}"


# ---- changes ------------------------------------------------------------------------------------------


def _change(
    state_dir: Path, fn: Callable[[dict[str, Any]], tuple[str, dict[str, Any] | None]]
) -> tuple[str, dict[str, Any] | None]:
    """Read the file, apply `fn` (reply, change record or None) and write it back when it changed."""
    store = Store(state_dir)
    path = state_dir / "settings.json"
    try:
        with _LOCK, file_lock(path):
            data = store.load_settings()
            if data is None:
                return f"The settings file {path} could not be read; fix or remove it first.", None
            reply, record = fn(data)
            if record is not None:
                store.save_settings(data)
            return reply, record
    except LockTimeout:
        return (
            f"The settings file {path} is locked by another process; nothing was changed. Try again.",
            None,
        )


def _clean(s: Any, cap: int = 40) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


def notify_usage(cmd: Cmd) -> str:
    c = cmd("notify")
    return (
        f"usage: {c} here (in the chat where you want notices), {c} <platform> (its home channel), "
        f"{c} off or {c} status"
    )


def _status(cfg: PluginConfig, cmd: Cmd) -> str:
    from .hold import owner_target, target_text

    n = notify_of(cfg)
    lines = [notify_line(n, cmd)]
    if n.platform:
        to, why = owner_target(n)
        lines.append(
            f"Delivery: to the {target_text(to)}." if to else f"Delivery: not sent ({why})."
        )
    if failed := failed_line(cfg):
        lines.append(failed)
    return "\n".join(lines)


def run_notify(
    cfg: PluginConfig,
    rest: str,
    chat: dict[str, str],
    by: dict[str, Any],
    now: datetime,
    cmd: Cmd,
    send: Callable[[str, str], None] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """`notify ...` sent from `chat` (the platform, chat id, thread id and chat type Hermes gave the command, and
    the chat id and type the owner check judged; empty for the terminal): the reply and the change record for the
    traffic log, or None when nothing changed. Once a target is set, `send` (target, text) sends it a test
    notice."""
    from .hold import home_channel_name, home_platforms

    words = rest.split()
    op = words[0].lower() if words else "status"
    if len(words) > 1:
        return notify_usage(cmd), None
    if op == "status":
        return _status(cfg, cmd), None
    if op == "off":
        return _change(cfg.state_dir, lambda data: _off(cfg, data, cmd))
    if op == "here":
        entry = _here(chat, by, home_platforms, home_channel_name, cmd)
    elif _PLATFORM.fullmatch(op):
        entry = _platform(op, home_platforms(), home_channel_name, cmd)
    else:
        return notify_usage(cmd), None
    if isinstance(entry, str):
        return entry, None
    stored, said = entry
    target = Notify(stored["platform"], stored.get("chat_id", ""), stored.get("thread_id", ""))
    where = (
        "this chat" if target.chat_id and op == "here" else f"the {target.platform} home channel"
    )
    reached = TEST_SENT.format(where=where)
    stored.update(set_at=_show(now), set_by=by)

    def fn(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        data["notify"] = stored
        data[FAILED_KEY] = None
        n = Notify(
            stored["platform"],
            stored.get("chat_id", ""),
            stored.get("thread_id", ""),
            "command",
            cfg.owner_channel,
        )
        reply = "\n".join(
            x
            for x in (
                said,
                notify_line(n, cmd),
                reached if send else "",
                f"To undo: {cmd('notify off')}.",
            )
            if x
        )
        op_name = "notify_here" if op == "here" else "notify_platform"
        return reply, {
            "op": op_name,
            "platform": stored["platform"],
            "chat": bool(stored.get("chat_id")),
        }

    reply, record = _change(cfg.state_dir, fn)
    if record is not None and send is not None:
        to, state_dir = target.to, cfg.state_dir
        send(
            to,
            TEST_NOTICE,
            on_fail=lambda: test_notice_failed(state_dir, to),
            on_ok=lambda: notice_delivered(state_dir, to),
        )
    return reply, record


def test_notice_failed(state_dir: Path, to: str) -> None:
    """Remembers that the test notice to `to` was not delivered, while `to` is still the target set by command."""

    def fn(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        current = _stored_notify(data)
        if current is None or Notify(**current).to != to:
            return "", None
        data[FAILED_KEY] = {"to": to, "at": _show(datetime.now(UTC))}
        return "", {}

    _change(state_dir, fn)


def notice_delivered(state_dir: Path, to: str) -> None:
    """A notice to `to` got through: forgets a test notice to it that was not. Reads before it locks, so a notice
    with nothing to forget costs one read."""
    failed = (load(state_dir) or {}).get(FAILED_KEY)
    if not isinstance(failed, dict) or failed.get("to") != to:
        return

    def fn(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        known = data.get(FAILED_KEY)
        if not isinstance(known, dict) or known.get("to") != to:
            return "", None
        data[FAILED_KEY] = None
        return "", {}

    _change(state_dir, fn)


def failed_line(cfg: PluginConfig) -> str:
    """The warning that the last test notice to the target in force was not delivered; "" when there is none. It
    names the platform, never the chat id."""
    failed = (load(cfg.state_dir) or {}).get(FAILED_KEY)
    n = notify_of(cfg)
    if not isinstance(failed, dict) or n.source != "command" or failed.get("to") != n.to:
        return ""
    where = f"{n.platform} chat" if n.chat_id else f"{n.platform} home channel"
    return FAILED_TEXT.format(where=where)


def _no_chat(cmd: Cmd) -> str:
    return (
        "There is no chat here Sentrook can send notices to. Send "
        f"{cmd('notify here')} in a direct message to the agent on a chat platform, or name a platform "
        f"with a home channel: {cmd('notify <platform>')}."
    )


def _here(
    chat: dict[str, str],
    by: dict[str, Any],
    homes: Callable[[], list[str]],
    home_name: Callable[[str], str],
    cmd: Cmd,
) -> tuple[dict[str, str], str] | str:
    """What `notify here` stores, with what the reply says first; or why it is refused."""
    platform = (chat.get("platform") or "").strip().lower()
    if (
        not _PLATFORM.fullmatch(platform)
        or platform in LOCAL_PLATFORMS
        or platform in NON_CHAT_PLATFORMS
        or platform in NOT_ATTENDED_PLATFORMS
    ):
        return _no_chat(cmd)
    # The owner check judged the chat Hermes bound for this command; the chat to store must be that one: the same
    # platform, the same chat id when the check had one, and never a chat when the check passed the local terminal.
    unsure = "Sentrook could not tell which chat this is; nothing was changed."
    if "local_terminal" in (by.get("basis") or []) or by.get("platform") != platform:
        return unsure
    judged = chat.get("owner_chat_id") or ""
    if judged and judged != (chat.get("chat_id") or ""):
        return unsure
    if (chat.get("chat_type") or chat.get("owner_chat_type") or "").lower() != "dm":
        return (
            f"Send {cmd('notify here')} in a direct message to the agent: notices go to you alone."
        )
    chat_id, thread = chat.get("chat_id") or "", chat.get("thread_id") or ""
    if chat_id and _CHAT_ID.fullmatch(chat_id):
        stored = {"platform": platform, "chat_id": chat_id}
        if thread and _CHAT_ID.fullmatch(thread):
            stored["thread_id"] = thread
        return stored, ""
    if platform not in homes():
        return (
            f"Hermes did not say which chat this is, and {platform} has no home channel, so notices "
            f"cannot be sent from here. To fix it, send /sethome in the chat where you want notices, "
            f"then {cmd('notify here')} again."
        )
    name = _clean(home_name(platform), 60) or "unnamed"
    return {"platform": platform}, (
        f"Hermes did not say which chat this is, so notices will go to {platform}'s home channel, which "
        f"is {name}, not this chat."
    )


def _platform(
    platform: str, homes: list[str], home_name: Callable[[str], str], cmd: Cmd
) -> tuple[dict[str, str], str] | str:
    """What `notify <platform>` stores, with what the reply says first; or why it is refused."""
    if platform not in homes:
        known = f" Platforms with one: {', '.join(homes)}." if homes else ""
        return (
            f"{platform} has no home channel Hermes knows of, so notices cannot go there.{known} To fix it, "
            f"send /sethome in the chat where you want notices, or send {cmd('notify here')} there."
        )
    name = _clean(home_name(platform), 60) or "unnamed"
    return {
        "platform": platform
    }, f"Notices will go to the {platform} home channel, which is {name}."


def _off(cfg: PluginConfig, data: dict[str, Any], cmd: Cmd) -> tuple[str, dict[str, Any] | None]:
    current = _stored_notify(data)
    if current is None and data.get("notify") is None:
        return f"No notice target was set by command. {notify_line(notify_of(cfg), cmd)}", None
    data["notify"] = None
    data[FAILED_KEY] = None
    if cfg.owner_channel:
        then = f"owner_channel {cfg.owner_channel} in config applies again. " + notify_line(
            Notify(cfg.owner_channel, source="config", config=cfg.owner_channel), cmd
        )
    else:
        then = notify_line(Notify(), cmd)
    record = {"op": "notify_off", "platform": (current or {}).get("platform")}
    return f"Notice target set by command removed. {then}", record


def attended_usage(cmd: Cmd) -> str:
    c = cmd("attended")
    return f"usage: {c} add <platform> [--confirm], {c} remove <platform> or {c} list"


def _list(cfg: PluginConfig) -> str:
    return "\n".join(
        (
            attended_line(cfg),
            "Attended by default: chat platforms, the local terminal, the TUI, the desktop app and "
            "editors (ACP).",
        )
    )


def _warning(platform: str, cmd: Cmd) -> str:
    return (
        f"Warning: Sentrook treats {platform} as a place nobody watches. Adding it means a review there shows "
        "an approval prompt instead of holding the call for you. If nobody is there to answer, or the agent "
        "or a program can answer it, a risky call may run. Add it only if a person answers Hermes's approval "
        f"prompts on {platform}. To add it anyway: {cmd('attended add')} {platform} --confirm"
    )


def run_attended(
    cfg: PluginConfig, rest: str, by: dict[str, Any], now: datetime, cmd: Cmd
) -> tuple[str, dict[str, Any] | None]:
    """`attended ...`: the reply and the change record for the traffic log, or None when nothing changed."""
    words = rest.split()
    confirm = "--confirm" in words
    words = [w for w in words if w != "--confirm"]
    for w in words:
        if w.startswith("--"):
            return f"Unknown option {_clean(w)}.\n{attended_usage(cmd)}", None
    op = words[0].lower() if words else "list"
    if op == "list" and len(words) <= 1:
        return _list(cfg), None
    if op not in ("add", "remove") or len(words) != 2:
        return attended_usage(cmd), None
    platform = words[1].lower()
    if platform not in KNOWN_PLATFORMS:
        return (
            f'Unknown platform "{_clean(words[1])}". Known platforms: {", ".join(sorted(KNOWN_PLATFORMS))}.',
            None,
        )
    in_config = platform in cfg.attended_platforms
    if op == "remove":
        if in_config:
            return (
                f"{platform} is set in the plugin config (attended_platforms); remove it there.",
                None,
            )

        def drop(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
            before = len(data["attended"])
            data["attended"] = [
                e
                for e in data["attended"]
                if not (isinstance(e, dict) and e.get("platform") == platform)
            ]
            if len(data["attended"]) == before:
                return f"{platform} was not added by command. {attended_line(cfg)}", None
            return (
                f"Removed {platform}: reviews there are held for you again.",
                {"op": "attended_remove", "platform": platform},
            )

        reply, record = _change(cfg.state_dir, drop)
        return (f"{reply}\n{attended_line(cfg)}" if record else reply), record

    if platform in ATTENDED_BY_DEFAULT:
        return (
            f"{platform} is already attended: Sentrook asks you there by default. Nothing was changed.",
            None,
        )
    if platform in SELF_STARTED:
        return (
            f"{platform} cannot be added: Hermes starts these runs itself, or their approval prompts reach "
            "nobody, and where nobody answers Hermes may approve a prompt on its own, so a risky call could run "
            "unseen. Sentrook holds their reviews for you. Nothing was changed."
        ), None
    if platform in TERMINAL:
        return (
            f"{platform} cannot be added: the local terminal is already attended when it has a terminal, and "
            "adding it would make scripted runs without one (such as hermes chat -q) count as attended. "
            "Nothing was changed."
        ), None
    if in_config:
        return f"{platform} is already attended (attended_platforms in the plugin config).", None
    if not confirm:
        return _warning(platform, cmd), None

    def add(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        if any(isinstance(e, dict) and e.get("platform") == platform for e in data["attended"]):
            return f"{platform} is already added. {attended_line(cfg)}", None
        if len(data["attended"]) >= MAX_ATTENDED:
            return f"At most {MAX_ATTENDED} platforms can be added; remove one first.", None
        data["attended"].append({"platform": platform, "set_at": _show(now), "set_by": by})
        return (
            f"Added {platform}. This loosens Sentrook: on {platform} a review shows an approval prompt "
            f"instead of holding the call for you. To undo: {cmd('attended remove')} {platform}.",
            {"op": "attended_add", "platform": platform},
        )

    reply, record = _change(cfg.state_dir, add)
    return (f"{reply}\n{attended_line(cfg)}" if record else reply), record
