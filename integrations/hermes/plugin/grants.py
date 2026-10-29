"""Grants and channel bindings set by command, kept in `<hermes home>/sentrook/grants.json`.

Grants and channel bindings in the plugin settings stay where they are: the commands list them as
read-only and never change them. A scan sends config grants, config bindings, then the file's live
grants and bindings, in that order, so adding by command never renumbers a config grant.

A grant set by command has the PlanIR grant fields (kind, pattern, scope, allows, granted_at) plus an
id, who set it (`set_by`: the owner basis, platform and hashed sender) and an optional `expires_at`.
Scope is `session` unless the owner asks for `persistent`; any other value is refused. An expired
grant is not sent, and is dropped from the file on the next change. Patterns are passed on as typed:
Sentrook itself refuses patterns too broad to relieve on.

Every change is written to the traffic log as a `grants` record (none when the owner has turned the
traffic log off).
"""

from __future__ import annotations

import re
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .config import PluginConfig, parse_grants
from .store import Store

KINDS = ("destination", "file", "provider")
ALLOWS = ("read", "write", "edit", "delete", "exec")
SCOPES = ("session", "persistent")
MAX_PATTERN = 256
MAX_EXPIRY = timedelta(days=365)
_DURATION = re.compile(r"([0-9]{1,6})([mhd])")
#: The only time form read back from the file; both plugins accept exactly this.
_ISO = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?(Z|[+-][0-9]{2}:[0-9]{2})?"
)
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}
#: Serialises read-modify-write of the file within this process; writes are atomic across processes.
_LOCK = threading.Lock()

#: (subcommand) -> the command as the owner types it, e.g. "/sentrook bind".
Cmd = Callable[[str], str]


def load(state_dir: Path) -> dict[str, Any] | None:
    """The file's contents; empty when there is no file, None when it cannot be read."""
    return Store(state_dir).load_grants()


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _when(raw: Any) -> datetime | None:
    """An ISO time with a `T` (no offset means UTC); anything else is unreadable."""
    if not isinstance(raw, str) or not _ISO.fullmatch(raw.strip()):
        return None
    try:
        dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _clean(s: Any, cap: int = 200) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


def expired(entry: dict[str, Any], now: datetime) -> bool:
    """Past its expiry. An expiry that cannot be read counts as past, so it never widens relief."""
    if "expires_at" not in entry:
        return False
    at = _when(entry["expires_at"])
    return at is None or at <= now


def _file_grants(data: dict[str, Any] | None) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """(stored entry, PlanIR grant) for each usable entry, expired ones included."""
    out = []
    for raw in (data or {}).get("grants") or []:
        parsed = parse_grants([raw])
        if parsed:
            out.append((raw, parsed[0]))
    return out


def _file_bindings(data: dict[str, Any] | None) -> list[dict[str, Any]]:
    return [
        b
        for b in (data or {}).get("bindings") or []
        if isinstance(b, dict) and isinstance(b.get("pattern"), str) and b["pattern"].strip()
    ]


def effective(
    cfg: PluginConfig, data: dict[str, Any] | None, now: datetime
) -> list[dict[str, Any]]:
    """Every grant a scan may send: config grants, config bindings, then live file entries."""
    out = [dict(g) for g in cfg.grants]
    out += [
        {"kind": "destination", "pattern": p, "scope": "persistent"} for p in cfg.channel_bindings
    ]
    out += [g for raw, g in _file_grants(data) if not expired(raw, now)]
    for b in _file_bindings(data):
        g = {"kind": "destination", "pattern": b["pattern"].strip(), "scope": "persistent"}
        if isinstance(b.get("granted_at"), str) and b["granted_at"].strip():
            g["granted_at"] = b["granted_at"].strip()
        out.append(g)
    return out


# ---- listing ------------------------------------------------------------------------------------------


def _set_by(entry: dict[str, Any]) -> list[str]:
    at = _when(entry.get("granted_at"))
    by = entry.get("set_by") if isinstance(entry.get("set_by"), dict) else {}
    basis = [str(b) for b in by.get("basis") or [] if isinstance(b, str)]
    text = "set" + (f" {_show(at)}" if at else "") + (f" ({'+'.join(basis)})" if basis else "")
    return [_clean(text)] if text != "set" else []


def _table(header: tuple[str, ...], rows: list[tuple[str, ...]], cap: int = 40) -> list[str]:
    widths = [min(cap, max(len(r[i]) for r in [header, *rows])) for i in range(len(header) - 1)]
    return [
        "  ".join([*(c.ljust(w) for c, w in zip(r, widths, strict=False)), r[-1]]).rstrip()
        for r in [header, *rows]
    ]


def format_grants(cfg: PluginConfig, data: dict[str, Any] | None, now: datetime, cmd: Cmd) -> str:
    rows = []
    for i, g in enumerate(cfg.grants, 1):
        details = [f"allows {','.join(g['allows'])}"] if g.get("allows") else []
        rows.append(
            (
                f"cfg-{i}",
                g["kind"],
                g["scope"],
                g["pattern"],
                "; ".join([*details, "config, read-only"]),
            )
        )
    file_rows = _file_grants(data)
    for raw, g in file_rows:
        details = [f"allows {','.join(g['allows'])}"] if g.get("allows") else []
        if "expires_at" in raw:
            at = _when(raw["expires_at"])
            past = expired(raw, now)
            details.append(f"{'expired' if past else 'expires'} {_show(at) if at else '?'}")
        rows.append(
            (
                str(raw.get("id") or "-"),
                g["kind"],
                g["scope"],
                g["pattern"],
                "; ".join(details + _set_by(raw)),
            )
        )
    rows = [tuple(_clean(c) for c in r) for r in rows]
    lines = [f"Grants: {len(cfg.grants)} in config, {len(file_rows)} by command"]
    if data is None:
        lines.append("The grants file could not be read, so no grants set by command apply.")
    if rows:
        lines += _table(("id", "kind", "scope", "pattern", "details"), rows)
    lines.append(
        f"Channel bindings: {len(cfg.channel_bindings)} in config, "
        f"{len(_file_bindings(data))} by command; see {cmd('bind')} list"
    )
    return "\n".join(lines)


def format_bindings(cfg: PluginConfig, data: dict[str, Any] | None) -> str:
    rows = [(p, "config, read-only") for p in cfg.channel_bindings]
    rows += [(b["pattern"].strip(), "; ".join(_set_by(b))) for b in _file_bindings(data)]
    rows = [tuple(_clean(c) for c in r) for r in rows]
    lines = [
        f"Channel bindings: {len(cfg.channel_bindings)} in config, "
        f"{len(_file_bindings(data))} by command"
    ]
    if data is None:
        lines.append("The grants file could not be read, so no bindings set by command apply.")
    if rows:
        lines += _table(("channel", "details"), rows)
    return "\n".join(lines)


def counts(cfg: PluginConfig, data: dict[str, Any] | None) -> tuple[str, str]:
    """The `grants:` and `channel bindings:` lines of status."""
    return (
        f"{len(cfg.grants)} in config, {len(_file_grants(data))} by command",
        f"{len(cfg.channel_bindings)} in config, {len(_file_bindings(data))} by command",
    )


# ---- changes ------------------------------------------------------------------------------------------


def grant_usage(grant_cmd: str) -> str:
    return (
        f"usage: {grant_cmd} <kind> <pattern> [--persistent | --scope session|persistent] "
        "[--allows read,write] [--expires 12h]\n"
        "kind is destination, file or provider; --allows is for file grants; scope defaults to session"
    )


def parse_grant(rest: str) -> dict[str, Any] | str:
    """The grant typed after `grant`, or the reason it is refused ("" for a plain usage error)."""
    tokens = rest.split()
    pos: list[str] = []
    opts: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if not tok.startswith("--"):
            pos.append(tok)
            continue
        name, eq, value = tok[2:].partition("=")
        if name == "persistent" and not eq:
            opts["scope"] = "persistent"
            continue
        if name not in ("scope", "allows", "expires"):
            return f"Unknown option --{_clean(name, 40)}."
        if not eq:
            if i >= len(tokens):
                return f"--{name} needs a value."
            value = tokens[i]
            i += 1
        opts[name] = value
    if len(pos) != 2:
        return ""
    kind, pattern = pos[0].lower(), pos[1]
    if kind not in KINDS:
        return f'Unknown grant kind "{_clean(pos[0], 40)}": use destination, file or provider.'
    if len(pattern) > MAX_PATTERN or not pattern.isprintable():
        return f"The pattern must be at most {MAX_PATTERN} printable characters."
    scope = opts.get("scope", "session")
    if scope not in SCOPES:
        return f'Unknown scope "{_clean(scope, 40)}": use session or persistent.'
    grant: dict[str, Any] = {"kind": kind, "pattern": pattern, "scope": scope}
    if "allows" in opts:
        if kind != "file":
            return "--allows applies to file grants only."
        allows = [a.strip() for a in opts["allows"].split(",") if a.strip()]
        if not allows:
            return "--allows needs a value."
        for a in allows:
            if a not in ALLOWS:
                return f'Unknown allows value "{_clean(a, 40)}": use read, write, edit, delete or exec.'
        grant["allows"] = list(dict.fromkeys(allows))
    if "expires" in opts:
        m = _DURATION.fullmatch(opts["expires"])
        span = timedelta(**{_UNITS[m.group(2)]: int(m.group(1))}) if m else None
        if span is None or not timedelta(minutes=1) <= span <= MAX_EXPIRY:
            return (
                f'Unknown expiry "{_clean(opts["expires"], 40)}": '
                "use a number with m, h or d, from 1m to 365d."
            )
        grant["expires_in"] = span
    return grant


def _unreadable(state_dir: Path) -> str:
    return f"The grants file {state_dir / 'grants.json'} could not be read; fix or remove it first."


def _change(
    state_dir: Path,
    now: datetime,
    fn: Callable[[dict[str, Any]], tuple[str, dict[str, Any] | None]],
) -> tuple[str, dict[str, Any] | None]:
    """Read the file, apply `fn` (reply, change record or None), and write it back if it changed.
    A write also drops expired grants; `fn` still sees them, so revoking one works."""
    store = Store(state_dir)
    with _LOCK:
        data = store.load_grants()
        if data is None:
            return _unreadable(state_dir), None
        reply, record = fn(data)
        if record is not None:
            data["grants"] = [
                g for g in data["grants"] if not (isinstance(g, dict) and expired(g, now))
            ]
            store.save_grants(data)
        return reply, record


def add_grant(
    state_dir: Path, rest: str, by: dict[str, Any], now: datetime, cmd: Cmd
) -> tuple[str, dict[str, Any] | None]:
    parsed = parse_grant(rest)
    if isinstance(parsed, str):
        usage = grant_usage(cmd("grant"))
        return (f"{parsed}\n{usage}" if parsed else usage), None

    def fn(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        taken = {g.get("id") for g in data["grants"] if isinstance(g, dict)}
        gid = f"gr-{secrets.token_hex(3)}"
        while gid in taken:
            gid = f"gr-{secrets.token_hex(3)}"
        span = parsed.pop("expires_in", None)
        entry = {"id": gid, **parsed, "granted_at": _iso(now)}
        if span is not None:
            entry["expires_at"] = _iso(now + span)
        entry["set_by"] = by
        data["grants"].append(entry)
        details = [entry["scope"]]
        if entry.get("allows"):
            details.append(f"allows {','.join(entry['allows'])}")
        if span is not None:
            details.append(f"expires {_show(now + span)}")
        reply = f"Granted {gid}: {entry['kind']} {entry['pattern']} ({', '.join(details)})."
        return reply, {"op": "grant", "entry": entry}

    return _change(state_dir, now, fn)


def revoke(
    state_dir: Path, cfg: PluginConfig, rest: str, now: datetime, cmd: Cmd
) -> tuple[str, dict[str, Any] | None]:
    gid = rest.strip()
    if not gid or len(gid.split()) != 1:
        return f"usage: {cmd('revoke')} <id>, with an id from {cmd('grants')}", None
    if re.fullmatch(r"cfg-\d+", gid) and 1 <= int(gid[4:]) <= len(cfg.grants):
        return f"{gid} is set in the plugin config; remove it there.", None

    def fn(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        for i, g in enumerate(data["grants"]):
            if isinstance(g, dict) and g.get("id") == gid:
                del data["grants"][i]
                return (
                    f"Revoked {gid}: {_clean(g.get('kind'))} {_clean(g.get('pattern'))}.",
                    {"op": "revoke", "entry": g},
                )
        return f"No grant {_clean(gid, 40)}; see {cmd('grants')}.", None

    return _change(state_dir, now, fn)


def bind(
    state_dir: Path, cfg: PluginConfig, rest: str, by: dict[str, Any], now: datetime, cmd: Cmd
) -> tuple[str, dict[str, Any] | None]:
    words = rest.split()
    op = words[0].lower() if words else "list"
    if op == "list" and len(words) <= 1:
        return format_bindings(cfg, load(state_dir)), None
    if op not in ("add", "remove") or len(words) != 2:
        return f"usage: {cmd('bind')} add|remove <channel>, or {cmd('bind')} list", None
    channel = words[1]
    if len(channel) > MAX_PATTERN or not channel.isprintable():
        return f"The channel must be at most {MAX_PATTERN} printable characters.", None
    if channel in cfg.channel_bindings:
        if op == "add":
            return f"{channel} is already bound in the plugin config.", None
        return f"{channel} is bound in the plugin config; remove it there.", None

    def fn(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        found = next(
            (
                i
                for i, b in enumerate(data["bindings"])
                if isinstance(b, dict) and b.get("pattern") == channel
            ),
            None,
        )
        if op == "add":
            if found is not None:
                return f"{channel} is already bound.", None
            entry = {"pattern": channel, "granted_at": _iso(now), "set_by": by}
            data["bindings"].append(entry)
            return f"Channel binding added: {channel}.", {"op": "bind_add", "entry": entry}
        if found is None:
            return f"{channel} is not bound.", None
        entry = data["bindings"].pop(found)
        return f"Channel binding removed: {channel}.", {"op": "bind_remove", "entry": entry}

    return _change(state_dir, now, fn)
