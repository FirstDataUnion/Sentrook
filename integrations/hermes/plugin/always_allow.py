"""What an Always answer on a review of an MCP tool call lets through later: that tool on that server.

Hermes remembers an Always answer under the rule key the prompt carried (`_rule_key`). For a call whose approval
fingerprint names only its MCP server, that key also holds the call's arguments, so one approval never covers every
call of the tool. An MCP write tool's arguments change on every call (another page, other text), so that key never
repeats, and Always would mean Once.

So, on the owner's own turn, an Always answer to a review of an MCP tool call is also kept here, in
`<hermes home>/sentrook/always-allows.json`, as a standing allowance for that tool on that server: the tool, the
server's identity as the scan names the provider (its address, or the package it runs; a server the host config does
not describe has none, and keeps nothing), and every party the review named other than a path (a host, a recipient, a
channel: a call that sends somewhere else asks again). The path a call names is left out: an update tool names
another page on every call. A later review is let through when it matches as a Session answer's repeats do
(`session_allow.fits`): at most `session_allow.MARGIN` points above the answer and below the block line, no warning
the answered review lacked, nothing enforced, no floor, a complete scan. Each answer is kept on its own (a later call
is covered by one answer's risk and warnings, never a mix), for `MAX_AGE` from that answer.

Where the Always answer also sets the review's suggested grant, nothing is kept here: the grant goes to the scanner.

The match key is an HMAC under the install's salt; each entry also keeps the tool, the server's name and identity,
for the owner's list (`grants`) and `revoke <id>`. The file is changed under its own cross-process lock.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import session_allow
from .store import Store, file_lock, read_time

#: How long one Always answer lets later calls through (as long as a grant Always sets).
MAX_AGE = timedelta(days=30)
#: Tools and servers kept (the least recently answered go first), and answers kept for each.
MAX_ENTRIES = 200
MAX_ANSWERS = 5
#: Party kinds left out of the key: what an MCP tool writes, which differs on every call.
UNKEYED_KINDS = frozenset({"path"})

_LOCK = threading.Lock()
FILE = "always-allows.json"


def _path(state_dir: Path) -> Path:
    return Path(state_dir) / FILE


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def server_of(provider: Any) -> tuple[str, str] | None:
    """(name, identity) of an MCP server the call's provider names; None for any other provider, or a server with
    no identity."""
    if not isinstance(provider, dict) or provider.get("kind") != "mcp":
        return None
    identity, name = provider.get("identity"), provider.get("name")
    if not isinstance(identity, str) or not identity.strip():
        return None
    return (name if isinstance(name, str) and name else identity), identity


def key(tool: str, provider: Any, resp: dict[str, Any], secret: str) -> str | None:
    """The allowance key of a call of `tool` on the MCP server `provider` names; None when it is not an MCP call
    with a server identity."""
    server = server_of(provider)
    if server is None or not tool:
        return None
    named = [(k, d) for k, d in session_allow.parties(resp) if k not in UNKEYED_KINDS]
    material = "\n".join([tool, server[1], *(f"{k}\t{d}" for k, d in named)])
    return hmac.new(
        ("sentrook always allow v1|" + secret).encode(), material.encode(), hashlib.sha256
    ).hexdigest()[:24]


def load(state_dir: Path) -> dict[str, Any] | None:
    """The file, empty when absent; None when it exists but cannot be read."""
    path = _path(state_dir)
    store = Store(state_dir)
    if not path.exists():
        return {"version": 1, "allows": []}
    data = store._read(path, None)
    if not isinstance(data, dict):
        return None
    data.setdefault("allows", [])
    return data if isinstance(data["allows"], list) else None


def _live_answers(entry: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    out = []
    for a in entry.get("answers") or []:
        at = read_time(a.get("at")) if isinstance(a, dict) else None
        if at is not None and now - at <= MAX_AGE:
            out.append(a)
    return out


def live(data: dict[str, Any] | None, now: datetime) -> list[dict[str, Any]]:
    """Entries with at least one answer still in force."""
    return [
        e for e in (data or {}).get("allows") or [] if isinstance(e, dict) and _live_answers(e, now)
    ]


def covering(
    data: dict[str, Any] | None,
    k: str | None,
    resp: dict[str, Any],
    now: datetime,
    block_at: float,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(the entry, the answer) that lets this review through, or None. Never at or above `block_at`."""
    now_risk = session_allow.risk_of(resp)
    if k is None or not session_allow.eligible(resp) or now_risk is None or now_risk >= block_at:
        return None
    for e in live(data, now):
        if e.get("key") != k:
            continue
        for a in _live_answers(e, now):
            if session_allow.fits(a.get("risk"), a.get("warnings"), resp):
                return e, a
    return None


def add(
    state_dir: Path,
    *,
    k: str,
    tool: str,
    server: str,
    identity: str,
    risk: float,
    seen: list[str],
    request_id: str,
    now: datetime,
) -> dict[str, Any] | None:
    """Keep the allowance an Always answer gave; returns the entry, or None when the file cannot be read."""
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = load(state_dir)
        if data is None:
            return None
        kept = live(data, now)
        entry = next((e for e in kept if e.get("key") == k), None)
        if entry is None:
            taken = {e.get("id") for e in kept}
            aid = f"aa-{secrets.token_hex(3)}"
            while aid in taken:
                aid = f"aa-{secrets.token_hex(3)}"
            entry = {"id": aid, "key": k, "tool": tool, "server": server, "identity": identity}
        else:
            kept.remove(entry)
        answers = [a for a in _live_answers(entry, now) if a.get("request_id") != request_id]
        answers.append(
            {
                "risk": risk,
                "warnings": sorted(set(seen)),
                "request_id": request_id,
                "at": _iso(now),
            }
        )
        entry["answers"] = answers[-MAX_ANSWERS:]
        entry["set_at"] = _iso(now)
        kept.append(entry)
        data["allows"] = kept[-MAX_ENTRIES:]
        store._write(_path(state_dir), data)
        return entry


def revoke(state_dir: Path, aid: str, now: datetime) -> tuple[str, dict[str, Any] | None] | None:
    """(reply, change) when `aid` names an allowance kept here; None when it names none (or the file cannot be
    read), so the caller can say there is no such grant."""
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = load(state_dir)
        if data is None:
            return None
        kept = live(data, now)
        for i, e in enumerate(kept):
            if e.get("id") == aid:
                del kept[i]
                data["allows"] = kept
                store._write(_path(state_dir), data)
                return (
                    f"Revoked {aid}: Always for {_clean(e.get('tool'))} on {_clean(e.get('server'))}.",
                    {
                        "op": "revoke_always",
                        "entry": {k: e.get(k) for k in ("id", "tool", "server")},
                    },
                )
    return None


def _clean(s: Any, cap: int = 120) -> str:
    text = " ".join(str(s or "").split())
    return text if len(text) <= cap else text[: cap - 1] + "…"


def format_lines(state_dir: Path, now: datetime, cmd: Any) -> list[str]:
    """The `grants` listing's lines for these allowances; none when there are none."""
    entries = live(load(state_dir), now)
    if not entries:
        return []
    lines = ["Always answers (an MCP tool on its server, at a similar risk):"]
    for e in entries:
        until = max(read_time(a.get("at")) or now for a in _live_answers(e, now)) + MAX_AGE
        lines.append(
            f"  {e.get('id')}  {_clean(e.get('tool'))} on {_clean(e.get('server'))} "
            f"({_clean(e.get('identity'))}); expires {until.strftime('%Y-%m-%d %H:%M')} UTC"
        )
    lines.append(f"Remove one with {cmd('revoke')} <id>.")
    return lines


def count(state_dir: Path, now: datetime) -> int:
    return len(live(load(state_dir), now))
