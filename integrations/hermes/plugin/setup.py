"""The owner's setup screen: `/sentrook setup` lists what would stop Sentrook asking about routine work, and
`/sentrook setup apply <code>` sets it.

The screen is a numbered list of items, each a grant or a channel binding, from three places:
- **Your config.** Each cron job's delivery target (a room, not a person) that is not bound yet, as a channel binding;
  each MCP server that no grant in force covers, as a provider grant named as a scan names its provider. Cron jobs can
  be written by the agent, so their items carry a warning.
- **Reviews you approved** (`approved_suggestions`): the grant Sentrook suggested on a review counts only when the
  owner approved that review, the call came from the owner's own message (`grants.may_remember`), the scanner flagged
  no exposure anywhere in that session, and the suggested grant is exactly the item's kind, pattern and allows; a
  broader pattern never inherits the count. Reviews older than `EVIDENCE_WINDOW` do not count, and an item needs
  `EVIDENCE_MIN` of them. With the traffic log off there is no evidence.
- **The agent's proposals** (`<state>/proposals.json`, `load_proposals`): items the agent suggested, each with its
  reason, shown last as a quoted note. A proposal lasts `PROPOSAL_TTL`.

Every item is described in the plugin's words, from its kind, pattern, allows and lifetime. Every candidate, from
config, reviews and proposals alike, must be one the grant or bind command would accept (one printable word, no
backtick), so nothing an agent wrote into a config file can end a line or a code span; the rest are counted and left
out. Patterns, job ids, server names and the agent's reason (only ever a note, last) are shown neutralised in code
spans, where chat apps turn no link, mention or emphasis on. A name in `xn--` form is flagged like one with letters
that are not plain ASCII. Warnings name what to check: characters that are not plain ASCII (with
the registrable domain in ASCII), deleting files, a folder at or above the home folder, a whole package registry, a
grant in force that already covers the item, a cron job's target, and, for the agent's items, a proposing chat where
the scanner flagged exposure (or the traffic log is off, so it could not be checked). Whether a pattern is too broad
to relieve anything is the scanner's call: the plugin passes patterns on as typed.

Lifetimes: a grant backed by reviews the owner approved lasts until revoked; any other lasts 30 days (`hold.GRANT_TTL`,
as for a grant set from a suggestion), or less when the agent asked for less. A channel binding lasts until removed.
`apply <code> --expires 90d` or `--until-revoked` sets every grant's lifetime instead.

Applying needs the four-digit code the screen ends with: it is new each time the screen is shown, lasts `CODE_TTL`,
works once, and is kept with the items as shown (`setup.json`), so `apply` sets exactly what the owner read even if
the proposals changed since. One locked pass writes the grants file and the proposals file: grants are persistent,
each record says who set it (`set_by`) and where it came from (`source`: `config`, `reviews` or the proposal id), an
item already set is not set again, and an agent proposal is closed once nothing readable is left in it.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import grants, history, hold
from .config import PluginConfig
from .planir import binding_problem, server_identity
from .store import Store, file_lock, read_time

#: Reviews the owner approved that an item needs before it counts as seen.
EVIDENCE_MIN = 2
#: How far back approved reviews count.
EVIDENCE_WINDOW = timedelta(days=30)
#: How long the screen's code works.
CODE_TTL = timedelta(minutes=15)
#: How long an agent proposal waits for the owner.
PROPOSAL_TTL = timedelta(hours=24)
#: Items on one screen; the rest wait for the next.
MAX_ITEMS = 30
#: Minutes an unseen grant lasts.
DEFAULT_MINUTES = int(hold.GRANT_TTL.total_seconds() // 60)

PROPOSAL_ID = re.compile(r"p-[0-9a-f]{6}")
_GRANT_ID = re.compile(r"gr-[0-9a-f]{6}")
_DURATION = re.compile(r"([0-9]{1,6})([mhd])")
_MINUTES = {"m": 1, "h": 60, "d": 1440}
_MAX_MINUTES = int(grants.MAX_EXPIRY.total_seconds() // 60)

#: (subcommand) -> the command as the owner types it.
Cmd = Callable[[str], str]
#: Writes one record to the traffic log.
Record = Callable[[dict[str, Any]], None]


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _spanned(s: Any, cap: int) -> str:
    """`s` neutralised and capped, without backslashes (a chat format may read one as an escape of the closing
    backtick), for a code span."""
    return hold.inert(s, cap).replace("\\", "")


def _span(s: Any, cap: int) -> str:
    """Text someone else chose (a job id, a server name), neutralised and in a code span, where chat apps turn no
    link, mention or emphasis on."""
    return f"`{_spanned(s, cap) or '?'}`"


def grant_label(gid: Any) -> str:
    """How a grant in force is named on the screen: an id the plugin made as it is; any other text someone wrote
    into the file in a code span; anything that is not text as `?`."""
    if isinstance(gid, str) and _GRANT_ID.fullmatch(gid):
        return gid
    return _span(gid, 20) if isinstance(gid, str) else "`?`"


def note_line(reason: Any) -> str | None:
    """The agent's reason as the screen shows it: neutralised, capped and in a code span, so a link, a bare domain,
    a mention or emphasis in it does nothing; None when nothing is left of it."""
    text = _spanned(reason, 200) if isinstance(reason, str) else ""
    return f"Agent's note: `{text}`" if text.strip() else None


def minutes_of(text: Any) -> int | None:
    """A lifetime as `grant --expires` takes it (`4h`, `30d`), in minutes; None when it is not one."""
    m = _DURATION.fullmatch(text) if isinstance(text, str) else None
    if m is None:
        return None
    minutes = int(m.group(1)) * _MINUTES[m.group(2)]
    return minutes if 1 <= minutes <= _MAX_MINUTES else None


# ---- evidence ---------------------------------------------------------------------------------------------------


def exposure_flagged(resp: Any) -> bool:
    """The scan response says the agent had read content aimed at steering it: an `exposure.*` reason, or the
    exposure or session_exposure score above 0."""
    if not isinstance(resp, dict):
        return False
    for r in resp.get("reasons") or []:
        code = r.get("code") if isinstance(r, dict) else None
        if isinstance(code, str) and code.startswith("exposure."):
            return True
    tree = resp.get("tree") if isinstance(resp.get("tree"), dict) else {}
    suspicion = tree.get("suspicion") if isinstance(tree.get("suspicion"), dict) else {}
    for k in ("exposure", "session_exposure"):
        v = suspicion.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
            return True
    return False


def key_of(item: dict[str, Any]) -> str:
    """What makes two items the same: a binding's channel, or a grant's kind, pattern and allows (in any order)."""
    if item.get("binding"):
        return json.dumps(["binding", item["pattern"]], ensure_ascii=False, separators=(",", ":"))
    allows = sorted(item["allows"]) if item.get("allows") else None
    return json.dumps(
        [item["kind"], item["pattern"], allows], ensure_ascii=False, separators=(",", ":")
    )


def _grant_key(item: dict[str, Any]) -> str:
    """The key of the grant an item sets: a binding is a destination grant for its channel."""
    if item.get("binding"):
        return key_of({"kind": "destination", "pattern": item["pattern"]})
    return key_of(item)


class Evidence:
    """What the traffic log says: the grants Sentrook suggested on reviews the owner approved (`approved`, by
    `key_of`, each with its count and the time of the last), and the sessions where the scanner flagged exposure.
    `available` is False when the traffic log is off."""

    def __init__(self, available: bool) -> None:
        self.available = available
        self.approved: dict[str, dict[str, Any]] = {}
        self.exposed: set[str] = set()

    def backing(self, item: dict[str, Any]) -> dict[str, Any] | None:
        """The approved reviews that back `item`, when there are enough of them."""
        found = self.approved.get(_grant_key(item))
        return found if found and found["count"] >= EVIDENCE_MIN else None


def read_evidence(log: Path | None, review_at: float, now: datetime) -> Evidence:
    """The evidence in the traffic log at `log` (None when the log is off), as of `now`. The suggested grant of a
    review is the one its prompt named: the first the grant command accepts that brings the call below `review_at`."""
    if log is None:
        return Evidence(False)
    ev = Evidence(True)
    since = now - EVIDENCE_WINDOW
    resolutions: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    found: list[tuple[str, dict[str, Any], datetime]] = []
    for rec in history.records_backward(log):
        rid = rec.get("request_id")
        if not isinstance(rid, str):
            continue
        if rec.get("kind") == "resolution":
            resolutions.setdefault(rid, rec)
            continue
        if rec.get("kind") != "scan" or rid in seen:
            continue
        seen.add(rid)
        resp, sref = rec.get("response"), rec.get("session_ref")
        if exposure_flagged(resp) and isinstance(sref, str):
            ev.exposed.add(sref)
        at = read_time(rec.get("ts"))
        planir = rec.get("planir")
        if (
            at is None
            or not since <= at <= now
            or not isinstance(sref, str)
            or not isinstance(resp, dict)
            or not isinstance(planir, dict)
        ):
            continue
        resolution = resolutions.get(rid)
        if history.review_of(history.action_of(rec, resolution), resolution) != "approved":
            continue
        if not grants.may_remember(planir):
            continue
        grant = hold.grant_hint(resp, review_at)
        if grant is not None:
            found.append((sref, grant, at))
    for sref, grant, at in found:
        if sref in ev.exposed:
            continue
        entry = ev.approved.setdefault(key_of(grant), {"grant": grant, "count": 0, "last": at})
        entry["count"] += 1
        entry["last"] = max(entry["last"], at)
    return ev


def approved_suggestions(ev: Evidence) -> list[dict[str, Any]]:
    """The suggested grants with enough approved reviews behind them, most reviews first, then the most recent."""
    rows = [e for e in ev.approved.values() if e["count"] >= EVIDENCE_MIN]
    return sorted(rows, key=lambda e: (-e["count"], -e["last"].timestamp(), key_of(e["grant"])))


def last_text(now: datetime, last: datetime) -> str:
    """How long ago, by UTC calendar day."""
    days = (now.astimezone(UTC).date() - last.astimezone(UTC).date()).days
    return "today" if days <= 0 else "yesterday" if days == 1 else f"{days} days ago"


# ---- sources ----------------------------------------------------------------------------------------------------

_PHONE_PLATFORMS = frozenset({"sms", "whatsapp", "signal", "imessage"})
_ROOM_PREFIX = re.compile(r"(?:channel|group|thread):")
_PERSON_PREFIX = re.compile(r"(?:user|dm):")
_ROOM_ID = re.compile(r"#[A-Za-z0-9_-]{2,}|-?[A-Za-z0-9_-]{3,}")


def room_pattern(platform: str, to: str) -> str | None:
    """A delivery to `to` on `platform` as a channel binding (`<platform>:<channel>`), when it names a room; None for
    a person, a phone number, a direct message, a thread or anything else. The OpenClaw plugin reads a cron job's
    delivery with the same rule."""
    platform = platform.strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{1,20}", platform) or platform == "last":
        return None
    to = to.strip()
    if to.lower().startswith(f"{platform}:"):
        to = to[len(platform) + 1 :]
    if _PERSON_PREFIX.match(to.lower()):
        return None
    room = bool(_ROOM_PREFIX.match(to.lower()))
    if room:
        to = to[to.index(":") + 1 :]
    if not _ROOM_ID.fullmatch(to):
        return None
    if not room and platform in _PHONE_PLATFORMS:
        return None
    # A Telegram chat with a positive id is a private chat with one person; groups and channels are negative.
    if not room and platform == "telegram" and re.fullmatch(r"[0-9]+", to):
        return None
    # Slack ids: `U…`/`W…` are people, `D…` a direct message.
    if not room and platform == "slack" and re.fullmatch(r"[UWD][A-Z0-9]{6,}", to):
        return None
    return f"{platform}:{to}"


def cron_targets(home: Path) -> list[tuple[str, str]]:
    """(job id, channel) for each enabled cron job's explicit delivery to a room, from Hermes's job file
    (`<home>/cron/jobs.json`, read directly as `_cron_job_prompt` does). `origin`, `local`, a platform's home channel
    and other routing tokens are the host's choice, not a channel to bind."""
    try:
        data = json.loads((home / "cron" / "jobs.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    jobs = data.get("jobs") if isinstance(data, dict) else data
    out: list[tuple[str, str]] = []
    for job in jobs if isinstance(jobs, list) else []:
        if not isinstance(job, dict) or job.get("enabled") is False:
            continue
        jid = job.get("id")
        if not isinstance(jid, str) or not jid.strip():
            continue
        deliver = job.get("deliver")
        tokens = (
            deliver
            if isinstance(deliver, list)
            else deliver.split(",")
            if isinstance(deliver, str)
            else []
        )
        for token in tokens:
            platform, sep, to = str(token).strip().partition(":")
            # Hermes's own rooms and bot chats are not a chat platform's channels.
            own = platform.strip().lower() in ("room", "bot-chat")
            pattern = room_pattern(platform, to) if sep and not own else None
            if pattern and (jid.strip(), pattern) not in out:
                out.append((jid.strip(), pattern))
    return out


def mcp_providers(servers: Any) -> list[tuple[str, str | None]]:
    """(server name, provider identity) for each configured MCP server, by name; the identity is None when the
    entry names none."""
    out: list[tuple[str, str | None]] = []
    for name in (
        sorted(n for n in servers if isinstance(n, str)) if isinstance(servers, dict) else []
    ):
        cfg = servers[name]
        out.append((name, server_identity(cfg)[0] if isinstance(cfg, dict) else None))
    return out


# ---- proposals --------------------------------------------------------------------------------------------------


def _raw_ok(p: Any) -> bool:
    """A pattern as written can be shown and set: one printable word, no backtick, no backslash at its end. Checked
    before anything trims it, so both plugins read the same patterns."""
    return _printable_word(p) and "`" not in p and not p.endswith("\\")


def _printable_word(p: Any) -> bool:
    return (
        isinstance(p, str)
        and 0 < len(p) <= grants.MAX_PATTERN
        and p.isprintable()
        and not any(c.isspace() for c in p)
    )


def proposal_item(raw: Any) -> dict[str, Any] | None:
    """One item of an agent proposal as the screen shows it; None when it is not one the owner could set by command
    (an `attended` platform, an unknown kind, a pattern the grant command refuses, a binding that could never
    apply)."""
    if not isinstance(raw, dict):
        return None
    reason = raw.get("reason") if isinstance(raw.get("reason"), str) else None
    expires = raw.get("expires")
    minutes = None
    if expires is not None:
        minutes = minutes_of(expires)
        if minutes is None:
            return None
    if raw.get("binding") is True:
        pattern = raw.get("pattern")
        if raw.get("kind") not in (None, "destination") or raw.get("allows") is not None:
            return None
        if minutes is not None or not _raw_ok(pattern) or binding_problem(pattern):
            return None
        return {"binding": True, "kind": "destination", "pattern": pattern, "reason": reason}
    if raw.get("binding") not in (None, False) or not _raw_ok(raw.get("pattern")):
        return None
    grant = grants.hint_grant(
        {"kind": raw.get("kind"), "pattern": raw.get("pattern"), "allows": raw.get("allows")}
    )
    if grant is None:
        return None
    return {"binding": False, **grant, "minutes": minutes, "reason": reason}


def _live_proposals(raw: Any, now: datetime) -> list[dict[str, Any]]:
    """The stored proposals that have not expired, as stored."""
    out = []
    for p in raw.get("proposals") or [] if isinstance(raw, dict) else []:
        if not isinstance(p, dict) or not isinstance(p.get("id"), str):
            continue
        created, expires = read_time(p.get("created_at")), read_time(p.get("expires_at"))
        if created is None or expires is None:
            continue
        if created <= now < min(expires, created + PROPOSAL_TTL):
            out.append(p)
    return out


def load_proposals(state_dir: Path, now: datetime) -> list[dict[str, Any]] | None:
    """The agent's live proposals, oldest first: id, session_ref (None when unreadable), created_at, the readable
    items and how many were not (`dropped`). None when the file cannot be read."""
    raw = Store(state_dir).load_proposals()
    if raw is None:
        return None
    out = []
    for p in _live_proposals(raw, now):
        if not PROPOSAL_ID.fullmatch(p["id"]):
            continue
        items = p.get("items") if isinstance(p.get("items"), list) else []
        readable = [i for i in map(proposal_item, items) if i is not None]
        ref = p.get("session_ref")
        out.append(
            {
                "id": p["id"],
                "session_ref": ref
                if isinstance(ref, str) and grants.SESSION_REF.fullmatch(ref)
                else None,
                "created_at": read_time(p["created_at"]),
                "items": readable,
                "dropped": len(items) - len(readable),
            }
        )
    return sorted(out, key=lambda p: (p["created_at"], p["id"]))


# ---- the rules each item is checked against --------------------------------------------------------------------


def in_force(
    cfg: PluginConfig, data: dict[str, Any] | None, now: datetime
) -> list[tuple[str, dict[str, Any]]]:
    """(label, grant) for each grant in force everywhere: persistent config and file grants that have not expired,
    and every channel binding as a destination grant."""
    out: list[tuple[str, dict[str, Any]]] = [
        (f"cfg-{i + 1}", g) for i, g in enumerate(cfg.grants) if g["scope"] == "persistent"
    ]
    out += [
        ("a channel binding", {"kind": "destination", "pattern": p}) for p in cfg.channel_bindings
    ]
    for raw, g in grants._file_grants(data):
        if g["scope"] == "persistent" and not grants.expired(raw, now):
            out.append((grant_label(raw.get("id")), g))
    out += [
        ("a channel binding", {"kind": "destination", "pattern": b["pattern"].strip()})
        for b in grants._file_bindings(data)
    ]
    return out


def covers(existing: dict[str, Any], cand: dict[str, Any]) -> bool:
    """`existing` already lets through everything `cand` would: the same kind, allows no narrower, and the same
    pattern (case ignored except for files), `*.` over its domain and every name under it, or a folder's `/*` over
    a file directly in it."""
    if existing.get("kind") != cand.get("kind"):
        return False
    have, want = existing.get("allows"), cand.get("allows")
    if have and (not want or not set(want) <= set(have)):
        return False
    e, c = existing["pattern"], cand["pattern"]
    if cand["kind"] == "file":
        if e == c:
            return True
        head = e[:-1]
        rest = c[len(head) :]
        return (
            e.endswith("/*")
            and "*" not in head
            and c.startswith(head)
            and bool(rest)
            and "/" not in rest
        )
    e, c = e.lower(), c.lower()
    if e == c:
        return True
    i = e.find("*.")
    if i < 0 or "*" in e[:i] or "*" in e[i + 2 :]:
        return False
    head, domain = e[:i], e[i + 2 :]
    rest = c[len(head) :]
    return c.startswith(head) and (rest == domain or rest.endswith("." + domain))


def host_of(item: dict[str, Any]) -> str | None:
    """The host an item's pattern names, if any, without `*.`, a port or a path."""
    p = item["pattern"].strip().lower()
    kind = "destination" if item.get("binding") else item["kind"]
    if kind == "credential":
        p = p.partition("@")[2]
    elif kind == "provider":
        if not p.startswith("remote:"):
            return None
        p = p[7:]
    elif kind in ("destination", "repo"):
        p = re.sub(r"^[a-z][a-z0-9+.-]*://", "", p).split("/", 1)[0].rpartition("@")[2]
    else:
        return None
    p = p.split(":", 1)[0]
    p = p[2:] if p.startswith("*.") else p
    return p.rstrip(".") or None


def registrable(host: str | None) -> str | None:
    """The registrable domain of `host` (the last two labels, three under a shared country second level such as
    `co.uk`), in ASCII; None when it has fewer than two labels."""
    labels = (host or "").split(".")
    if len(labels) < 2 or not all(labels):
        return None
    n = (
        3
        if len(labels) >= 3 and labels[-2] in grants._SHARED_SECOND_LEVEL and len(labels[-1]) == 2
        else 2
    )
    try:
        return ".".join(
            label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
            for label in labels[-n:]
        )
    except UnicodeError:
        return None


_HOME_OR_ABOVE = re.compile(r"/(?:(?:home|Users)(?:/[^/*?\[\]]+)?|root|var/root)")


def above_home(pattern: str) -> bool:
    """A file pattern for the home folder or a folder above it."""
    s = pattern.strip().rstrip("/*")
    return s in ("", "~", "$HOME", "${HOME}") or bool(_HOME_OR_ABOVE.fullmatch(s))


def whole_registry(pattern: str) -> bool:
    """A provider pattern with nothing literal after its registry: every package, or every server."""
    rest = pattern.split(":", 1)[1] if ":" in pattern else pattern
    return not re.sub(r"[*?\[\]@/\s]", "", rest)


#: A label in its ASCII (punycode) form, which a name with look-alike letters becomes.
_ENCODED = re.compile(r"(?:^|[.:@/*])xn--", re.IGNORECASE)


def valid_item(cand: dict[str, Any]) -> dict[str, Any] | None:
    """`cand` as the grant or bind command would accept it (one printable word, no backtick), whatever it came from;
    None when it would not be."""
    pattern = cand.get("pattern")
    if not _raw_ok(pattern):
        return None
    if cand.get("binding"):
        if binding_problem(pattern):
            return None
        return {"binding": True, "kind": "destination", "pattern": pattern, "allows": None}
    grant = grants.hint_grant(cand)
    if grant is None or not _raw_ok(grant["pattern"]):
        return None
    return {"binding": False, "allows": None, **grant}


def item_warnings(item: dict[str, Any]) -> list[str]:
    """The warnings an item carries from its own kind, pattern and allows."""
    out = []
    if not item["pattern"].isascii() or _ENCODED.search(item["pattern"]):
        domain = registrable(host_of(item))
        out.append(
            "the name has characters that are not plain ASCII, or is written in their xn-- form, and may imitate "
            "another name" + (f" (registrable domain {_span(domain, 300)})" if domain else "")
        )
    if not item.get("binding") and item["kind"] == "file":
        if not item.get("allows") or "delete" in item["allows"]:
            out.append("this lets the agent delete files")
        if above_home(item["pattern"]):
            out.append("this covers your whole home folder or more")
    if not item.get("binding") and item["kind"] == "provider" and whole_registry(item["pattern"]):
        out.append("this covers a whole package registry or every server")
    return out


# ---- the text ---------------------------------------------------------------------------------------------------

_VERBS = {"read": "read", "write": "write", "edit": "edit", "delete": "delete", "exec": "run"}


def lifetime_text(item: dict[str, Any], minutes: int | None) -> str:
    if minutes is None:
        return "until you remove it" if item.get("binding") else "until you revoke it"
    for size, unit in ((1440, "day"), (60, "hour"), (1, "minute")):
        if minutes % size == 0:
            n = minutes // size
            return f"for {n} {unit}{'' if n == 1 else 's'}"
    return f"for {minutes} minutes"  # pragma: no cover - every whole number is a whole number of minutes


def describe(item: dict[str, Any], minutes: int | None) -> str:
    """The item's first line, in the plugin's words: what it lets through, from where, and for how long."""
    p = item["pattern"]
    if item.get("binding"):
        what = f"Send messages to the channel `{p}`"
    elif item["kind"] == "destination":
        what = (
            f"Send data to `{p[2:]}` and every name under it"
            if p.startswith("*.")
            else f"Send data to `{p}`"
        )
    elif item["kind"] == "file":
        verbs = [_VERBS[a] for a in grants.ALLOWS if a in (item.get("allows") or grants.ALLOWS)]
        listed = verbs[0] if len(verbs) == 1 else f"{', '.join(verbs[:-1])} and {verbs[-1]}"
        what = f"{listed[0].upper()}{listed[1:]} files matching `{p}`"
    elif item["kind"] == "provider":
        what = f"Use tools from the provider `{p}`"
    elif item["kind"] == "repo":
        what = f"Run install scripts from the repository `{p}`"
    else:
        name, _, host = p.partition("@")
        what = f"Send the key `{name}` to `{host}`"
    return f"{what}, from any chat or job, {lifetime_text(item, minutes)}."


# ---- the screen -------------------------------------------------------------------------------------------------


def build(
    cfg: PluginConfig,
    data: dict[str, Any] | None,
    cron: list[tuple[str, str]],
    mcp: list[tuple[str, str | None]],
    ev: Evidence,
    proposals: list[dict[str, Any]],
    now: datetime,
) -> tuple[list[dict[str, Any]], list[str]]:
    """The screen's items, in order, and its notes. Each item has its grant (`binding`, kind, pattern, allows), its
    lifetime in minutes (None: until revoked or removed), its sources, its text lines under the first, and the
    sources' tags for the grants file (`tags`). Every candidate, whatever its source, must be one the grant or bind
    command would accept: anything else (a config entry with a newline or a space in it) is left out and counted."""
    items: dict[str, dict[str, Any]] = {}
    dropped = {"config": 0}

    def add(raw: dict[str, Any] | None, source: dict[str, Any]) -> None:
        cand = valid_item(raw) if raw is not None else None
        if cand is None:
            if source["from"] in ("cron", "mcp"):
                dropped["config"] += 1
            return
        k = key_of(cand)
        if k not in items:
            items[k] = {
                "binding": bool(cand.get("binding")),
                "kind": cand["kind"],
                "pattern": cand["pattern"],
                "allows": list(cand["allows"]) if cand.get("allows") else None,
                "sources": [],
            }
        items[k]["sources"].append(source)

    for jid, pattern in cron:
        add(
            {"binding": True, "kind": "destination", "pattern": pattern},
            {"from": "cron", "job": jid},
        )
    for name, identity in mcp:
        add(
            {"kind": "provider", "pattern": identity} if identity else None,
            {"from": "mcp", "server": name},
        )
    for e in approved_suggestions(ev):
        add(e["grant"], {"from": "reviews"})
    notes = []
    if dropped["config"]:
        n = dropped["config"]
        notes.append(
            f"From your config: {n} item{'' if n == 1 else 's'} could not be read and "
            f"{'is' if n == 1 else 'are'} left out."
        )
    for p in proposals:
        for it in p["items"]:
            add(
                it,
                {
                    "from": "proposal",
                    "id": p["id"],
                    "session_ref": p["session_ref"],
                    "reason": it.get("reason"),
                    "minutes": it.get("minutes"),
                },
            )
        if p["dropped"]:
            n = p["dropped"]
            notes.append(
                f"Proposal {p['id']}: {n} item{'' if n == 1 else 's'} could not be read and "
                f"{'is' if n == 1 else 'are'} left out."
            )
    force = in_force(cfg, data, now)
    out = []
    for item in items.values():
        cand = {"kind": "destination", "pattern": item["pattern"]} if item["binding"] else item
        covering = next((label for label, g in force if covers(g, cand)), None)
        agent = [s for s in item["sources"] if s["from"] == "proposal"]
        if covering is not None and not agent:
            continue
        backed = ev.backing(item)
        if item["binding"]:
            minutes = None
        else:
            asked = [s["minutes"] for s in agent if s["minutes"] is not None]
            if backed:
                minutes = min(asked) if asked else None
            else:
                minutes = min([*asked, DEFAULT_MINUTES])
        lines = []
        for s in item["sources"]:
            if s["from"] == "cron":
                lines.append(f"From your config: cron job {_span(s['job'], 40)} delivers here.")
            elif s["from"] == "mcp":
                lines.append(f"From your config: MCP server {_span(s['server'], 40)}.")
        if backed:
            n = backed["count"]
            lines.append(
                f"Sentrook suggested this in {n} reviews you approved, the last one "
                f"{last_text(now, backed['last'])}."
            )
        for pid in dict.fromkeys(s["id"] for s in agent):
            lines.append(f"Proposed by the agent ({pid})" + ("." if backed else ", not seen yet."))
        warnings = item_warnings(item)
        if covering is not None:
            warnings.append(f"a grant in force already covers this ({covering})")
        if any(s["from"] == "cron" for s in item["sources"]):
            warnings.append(
                "cron jobs can be changed by the agent; check that you chose this channel"
            )
        if any(s["from"] == "mcp" for s in item["sources"]):
            warnings.append(
                "MCP servers in the config can be changed by the agent; check that you added this one"
            )
        for s in agent:
            if not ev.available:
                warnings.append(
                    "could not check what the proposing chat had read (the traffic log is off)"
                )
            elif s["session_ref"] is None:
                warnings.append("could not check what the proposing chat had read")
            elif s["session_ref"] in ev.exposed:
                warnings.append(
                    "the chat that proposed this had read content that tried to steer the agent"
                )
        lines += [f"Warning: {w}." for w in dict.fromkeys(warnings)]
        lines += [line for s in agent if (line := note_line(s["reason"])) is not None]
        tags = ["config"] if any(s["from"] in ("cron", "mcp") for s in item["sources"]) else []
        tags += ["reviews"] if backed else []
        tags += [s["id"] for s in agent]
        out.append(
            {
                "binding": item["binding"],
                "kind": item["kind"],
                "pattern": item["pattern"],
                "allows": item["allows"],
                "minutes": minutes,
                "tags": list(dict.fromkeys(tags)),
                "proposals": list(dict.fromkeys(s["id"] for s in agent)),
                "lines": lines,
            }
        )
    if len(out) > MAX_ITEMS:
        n = len(out) - MAX_ITEMS
        notes.append(
            f"{n} more item{'' if n == 1 else 's'} not shown: apply or discard some first."
        )
        out = out[:MAX_ITEMS]
    return out, notes


def render(
    items: list[dict[str, Any]], notes: list[str], ev: Evidence, code: str | None, cmd: Cmd
) -> str:
    n = len(items)
    if not n:
        lines = ["Sentrook setup: nothing to set up right now."]
    else:
        lines = [
            f"Sentrook setup: {n} item{'' if n == 1 else 's'}. Sentrook describes each one from what it found; "
            "read them before you set any."
        ]
    if not ev.available:
        lines.append(
            "Evidence unavailable: the traffic log is off, so no reviews you approved are counted."
        )
    for i, item in enumerate(items, 1):
        lines += [
            "",
            f"{i}. {describe(item, item['minutes'])}",
            *(f"   {line}" for line in item["lines"]),
        ]
    if notes:
        lines += ["", *notes]
    if n:
        setup = cmd("setup")
        lines += [
            "",
            f"To set them all, send: {setup} apply {code}",
            f"To set some, list their numbers: {setup} apply {code} 1,3",
            "Add --expires 90d or --until-revoked to change how long the grants last; channels stay until you "
            f"remove them. The code works for {int(CODE_TTL.total_seconds() // 60)} minutes.",
        ]
        if any(item["proposals"] for item in items):
            lines.append(f"To drop an agent proposal: {setup} discard <id>")
    return "\n".join(lines)


def new_code() -> str:
    return f"{secrets.randbelow(10000):04d}"


def show(
    cfg: PluginConfig,
    now: datetime,
    cmd: Cmd,
    *,
    home: Path,
    host_cfg: dict[str, Any],
    code: Callable[[], str] = new_code,
) -> str:
    """Builds the screen, keeps its items with a new code (`setup.json`), and returns its text."""
    data = grants.load(cfg.state_dir)
    if data is None:
        return f"The grants file {cfg.state_dir / 'grants.json'} could not be read; fix or remove it first."
    ev = read_evidence(
        cfg.traffic_log_path if cfg.traffic_log_enabled else None, cfg.review_at, now
    )
    proposals = load_proposals(cfg.state_dir, now)
    notes_before = (
        []
        if proposals is not None
        else ["The agent's proposals could not be read, so none are shown."]
    )
    items, notes = build(
        cfg,
        data,
        cron_targets(home),
        mcp_providers(host_cfg.get("mcp_servers")),
        ev,
        proposals or [],
        now,
    )
    shown = code() if items else None
    store = Store(cfg.state_dir)
    with file_lock(cfg.state_dir / "setup.json"):
        store.save_setup(
            {
                "version": 1,
                "code": shown,
                "shown_at": _iso(now),
                "items": [{k: v for k, v in i.items() if k != "lines"} for i in items],
            }
        )
    return render(items, notes_before + notes, ev, shown, cmd)


# ---- apply and discard -----------------------------------------------------------------------------------------


def usage(cmd: Cmd) -> str:
    return f"usage: {cmd('setup')} [apply <code> [1,3] [--expires 90d | --until-revoked] | discard <id>]"


def _open(cmd: Cmd) -> str:
    return f"open {cmd('setup')} to see the list and its code."


def parse_apply(rest: str, cmd: Cmd) -> dict[str, Any] | str:
    """`apply <code> [numbers] [--expires <d> | --until-revoked]`, or the reason it is refused."""
    tokens = rest.split()
    code: str | None = None
    numbers: list[int] = []
    minutes: int | None = None
    until = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if tok == "--until-revoked":
            until = True
            continue
        if tok.startswith("--"):
            name, eq, value = tok[2:].partition("=")
            if name != "expires":
                return f"Unknown option --{hold.inert(name, 40)}."
            if not eq:
                if i >= len(tokens):
                    return "--expires needs a value."
                value = tokens[i]
                i += 1
            minutes = minutes_of(value)
            if minutes is None:
                return f'Unknown expiry "{hold.inert(value, 40)}": use a number with m, h or d, from 1m to 365d.'
            continue
        if code is None:
            code = tok
            continue
        for part in tok.split(","):
            if not part:
                continue
            if not re.fullmatch(r"[0-9]{1,4}", part):
                return f'"{hold.inert(part, 20)}" is not an item number: {_open(cmd)}'
            numbers.append(int(part))
    if until and minutes is not None:
        return "Use --expires or --until-revoked, not both."
    if code is None:
        return f"apply needs the code from the setup screen: {_open(cmd)}"
    return {"code": code, "numbers": numbers, "minutes": minutes, "until_revoked": until}


def _code_ok(kept: Any, code: str, now: datetime) -> bool:
    if not isinstance(kept, dict) or not isinstance(kept.get("code"), str):
        return False
    shown = read_time(kept.get("shown_at"))
    return (
        shown is not None
        and shown <= now < shown + CODE_TTL
        and hmac.compare_digest(kept["code"].encode(), code.encode())
    )


def _stored_item(raw: Any) -> dict[str, Any] | None:
    """An item as `show` kept it, checked again as the grant command would."""
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("pattern"), str)
        or "`" in raw["pattern"]
    ):
        return None
    minutes = raw.get("minutes")
    if minutes is not None and (not isinstance(minutes, int) or not 1 <= minutes <= _MAX_MINUTES):
        return None
    tags = [t for t in raw.get("tags") or [] if isinstance(t, str)]
    props = [
        p for p in raw.get("proposals") or [] if isinstance(p, str) and PROPOSAL_ID.fullmatch(p)
    ]
    if raw.get("binding") is True:
        if not _printable_word(raw["pattern"]) or binding_problem(raw["pattern"]):
            return None
        grant = {"kind": "destination", "pattern": raw["pattern"]}
    else:
        grant = grants.hint_grant(raw)
        if grant is None:
            return None
    return {
        "binding": raw.get("binding") is True,
        **grant,
        "minutes": minutes,
        "tags": tags,
        "proposals": props,
    }


def apply(
    cfg: PluginConfig,
    rest: str,
    who: dict[str, Any],
    now: datetime,
    cmd: Cmd,
    record: Record,
) -> str:
    """`apply <code> ...`: sets the chosen items of the screen the code belongs to, in one locked pass."""
    parsed = parse_apply(rest, cmd)
    if isinstance(parsed, str):
        return parsed
    refused = f"That is not the code on the setup screen, or it has expired: {_open(cmd)}"
    state = cfg.state_dir
    store = Store(state)
    with (
        grants._LOCK,
        file_lock(state / "setup.json"),
        file_lock(state / "grants.json"),
        file_lock(state / "proposals.json"),
    ):
        kept = store.load_setup()
        if not _code_ok(kept, parsed["code"], now):
            return refused
        shown = kept.get("items") if isinstance(kept.get("items"), list) else []
        for n in parsed["numbers"]:
            if not 1 <= n <= len(shown):
                return f"There is no item {n} on the setup screen: {_open(cmd)}"
        data = store.load_grants()
        if data is None:
            return f"The grants file {state / 'grants.json'} could not be read; fix or remove it first."
        raw_props = store.load_proposals()
        if raw_props is None:
            return f"The proposals file {state / 'proposals.json'} could not be read; fix or remove it first."
        live = {p["id"]: p for p in _live_proposals(raw_props, now)}
        chosen = sorted(set(parsed["numbers"])) or list(range(1, len(shown) + 1))
        lines, changes, applied = [], [], []
        for n in chosen:
            item = _stored_item(shown[n - 1])
            if item is None:
                lines.append(f"{n}. Not set: this item could not be read again; {_open(cmd)}")
                continue
            gone = [p for p in item["proposals"] if p not in live]
            if gone and not [t for t in item["tags"] if t not in gone]:
                lines.append(
                    f"{n}. Not set: proposal {gone[0]} was discarded or has expired since the screen was shown."
                )
                continue
            tags = [t for t in item["tags"] if t not in gone]
            line, change = _apply_one(cfg, data, item, tags, parsed, who, now, n)
            lines.append(line)
            if change is not None:
                changes.append(change)
            applied.append(item)
        if changes:
            data["grants"] = [
                g for g in data["grants"] if not (isinstance(g, dict) and grants.expired(g, now))
            ]
            store.save_grants(data)
        closed = _close(raw_props, live, applied, now)
        if closed is not None:
            store.save_proposals(raw_props)
        store.save_setup({**kept, "code": None})
    for change in changes:
        record({"kind": "grants", **change, "by": who})
    record(
        {
            "kind": "setup",
            "op": "apply",
            "items": chosen,
            "closed": closed or [],
            "by": who,
        }
    )
    end = (
        f"Remove a grant with {cmd('revoke')} <id> and a channel with {cmd('bind')} remove <channel>; "
        f"{cmd('grants')} lists what is in force."
    )
    return "\n".join(["Set from the setup screen:", *lines, end])


def _apply_one(
    cfg: PluginConfig,
    data: dict[str, Any],
    item: dict[str, Any],
    tags: list[str],
    parsed: dict[str, Any],
    who: dict[str, Any],
    now: datetime,
    n: int,
) -> tuple[str, dict[str, Any] | None]:
    p = item["pattern"]
    if item["binding"]:
        bound = p in cfg.channel_bindings or any(
            isinstance(b, dict) and b.get("pattern") == p for b in data["bindings"]
        )
        if bound:
            return f"{n}. Already set: channel `{p}`.", None
        entry = {"pattern": p, "granted_at": _iso(now), "set_by": who, "source": tags}
        data["bindings"].append(entry)
        return f"{n}. Channel binding added: `{p}` (until you remove it).", {
            "op": "bind_add",
            "entry": entry,
        }
    want = sorted(item["allows"]) if item.get("allows") else None
    for g in data["grants"]:
        if (
            isinstance(g, dict)
            and g.get("kind") == item["kind"]
            and g.get("pattern") == p
            and (sorted(g["allows"]) if isinstance(g.get("allows"), list) and g["allows"] else None)
            == want
            and g.get("scope") == "persistent"
            and not grants.expired(g, now)
        ):
            return f"{n}. Already set: {item['kind']} `{p}` ({hold.inert(g.get('id'), 20)}).", None
    minutes = (
        None
        if parsed["until_revoked"]
        else parsed["minutes"]
        if parsed["minutes"] is not None
        else item["minutes"]
    )
    taken = {g.get("id") for g in data["grants"] if isinstance(g, dict)}
    gid = f"gr-{secrets.token_hex(3)}"
    while gid in taken:
        gid = f"gr-{secrets.token_hex(3)}"
    entry: dict[str, Any] = {"id": gid, "kind": item["kind"], "pattern": p}
    if item.get("allows"):
        entry["allows"] = list(item["allows"])
    entry.update({"scope": "persistent", "granted_at": _iso(now)})
    if minutes is not None:
        entry["expires_at"] = _iso(now + timedelta(minutes=minutes))
    entry.update({"set_by": who, "source": tags})
    data["grants"].append(entry)
    allows = f", allows {','.join(entry['allows'])}" if entry.get("allows") else ""
    life = (
        "until you revoke it"
        if minutes is None
        else f"expires {_show(now + timedelta(minutes=minutes))}"
    )
    return f"{n}. Granted {gid}: {item['kind']} `{p}`{allows} (persistent, {life}).", {
        "op": "grant",
        "entry": entry,
    }


def _close(
    raw: dict[str, Any],
    live: dict[str, dict[str, Any]],
    applied: list[dict[str, Any]],
    now: datetime,
) -> list[str] | None:
    """Takes the applied items out of their proposals and closes each proposal with nothing readable left; drops
    expired proposals. Returns the closed ids, or None when the file needs no change."""
    done: dict[str, set[str]] = {}
    for item in applied:
        for pid in item["proposals"]:
            done.setdefault(pid, set()).add(key_of(item))
    stored = raw.get("proposals") if isinstance(raw.get("proposals"), list) else []
    kept, closed = [], []
    for p in stored:
        if not isinstance(p, dict) or p.get("id") not in live:
            continue
        keys = done.get(p["id"], set())
        items = [
            i
            for i in (p.get("items") if isinstance(p.get("items"), list) else [])
            if not ((it := proposal_item(i)) is not None and key_of(it) in keys)
        ]
        if keys and not any(proposal_item(i) is not None for i in items):
            closed.append(p["id"])
            continue
        kept.append({**p, "items": items} if keys else p)
    if not closed and not done and len(kept) == len(stored):
        return None
    raw["proposals"] = kept
    return closed


def discard(
    cfg: PluginConfig, rest: str, who: dict[str, Any], now: datetime, cmd: Cmd, record: Record
) -> str:
    pid = rest.strip()
    if not PROPOSAL_ID.fullmatch(pid):
        if pid:
            return f"No proposal {hold.inert(pid, 40)}: open {cmd('setup')} to see the proposals."
        return f"usage: {cmd('setup')} discard <id>, with a proposal id from {cmd('setup')}"
    store = Store(cfg.state_dir)
    with file_lock(cfg.state_dir / "proposals.json"):
        raw = store.load_proposals()
        if raw is None:
            return f"The proposals file {cfg.state_dir / 'proposals.json'} could not be read; fix or remove it first."
        live = _live_proposals(raw, now)
        found = next((p for p in live if p["id"] == pid), None)
        if found is None:
            return f"No proposal {pid}: open {cmd('setup')} to see the proposals."
        raw["proposals"] = [p for p in live if p is not found]
        store.save_proposals(raw)
    record({"kind": "setup", "op": "discard", "proposal": pid, "by": who})
    n = len(found.get("items") if isinstance(found.get("items"), list) else [])
    return f"Discarded proposal {pid} ({n} item{'' if n == 1 else 's'}); nothing from it was set."


def run(
    cfg: PluginConfig,
    rest: str,
    who: dict[str, Any],
    now: datetime,
    cmd: Cmd,
    record: Record,
    *,
    home: Path,
    host_cfg: dict[str, Any],
    code: Callable[[], str] = new_code,
) -> str:
    """`setup`, `setup apply ...` or `setup discard <id>`."""
    verb, _, more = rest.strip().partition(" ")
    verb = verb.lower()
    if not verb:
        return show(cfg, now, cmd, home=home, host_cfg=host_cfg, code=code)
    if verb == "apply":
        return apply(cfg, more, who, now, cmd, record)
    if verb == "discard":
        return discard(cfg, more, who, now, cmd, record)
    return usage(cmd)
