"""The read-only dashboard's model: recent scans and each scan's risk tree, from the traffic log.

It holds only what the scanner returned (risk, the tier and leaf scores, floors, relief, reason codes and
texts, entity display strings) plus the plugin's own labels for what it did. The PlanIR as sent, the call's
arguments, `reasons[].detail` and failure details are never included, as with `/sentrook why`; a scan's report
panel (`report_of`) holds only its summary, links and commands. One exception, off by default: with
`dashboard_show_calls` the owner lets each scan carry its call (tool and arguments, as sent to the scanner and so
redacted, bounded by `call_of`), knowing anyone who can open the dashboard can then read it. The OpenClaw plugin
builds the same model for the same log (fixtures/traffic-log/dashboard).

`dashboard/plugin_api.py` serves it to the Hermes dashboard tab; the page cannot change anything.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import grants, report, snooze
from .config import PluginConfig
from .history import (
    HISTORY_DEFAULT,
    HISTORY_MAX,
    _lines_backward,
    _response,
    _text,
    action_of,
    parse_ref,
    recent_scans,
    review_of,
)
from .store import Store, read_time

MODEL_VERSION = 1

#: The leaves of each tier, in the order the page shows them; any other numeric key follows, sorted.
TIERS: list[tuple[str, list[str]]] = [
    (
        "suspicion",
        [
            "misalignment",
            "concealment",
            "overreach",
            "distrust",
            "request_origin",
            "retry_after_denial",
            "untrusted_origin",
            "exposure",
            "session_exposure",
        ],
    ),
    ("consequence", ["sensitivity", "reach", "irreversibility", "self_modification"]),
    ("confidence", ["agreement", "coverage", "model_certainty"]),
]

#: Plugin marks on a scan record worth showing next to the action.
FLAGS = ["snoozed", "relaxed", "hold", "notice", "skill_review", "self_edit", "host_process"]

_LIMIT = re.compile(r"[0-9]{1,4}")
_ENTITY_NUM = re.compile(r"[0-9]+")

CMD = "/sentrook {}".format


def _number(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return v


def _unit(v: Any) -> float | None:
    n = _number(v)
    return None if n is None else min(max(n, 0), 1)


def _str(v: Any, limit: int) -> str | None:
    return _text(v, limit) if isinstance(v, str) and v.strip() else None


def _obj(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _list(v: Any) -> list[dict[str, Any]]:
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _step(v: Any) -> int | None:
    """A whole-number step, as JavaScript's Number.isInteger reads it (3.0 counts)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return None


def _tiers(tree: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for name, known in TIERS:
        t = _obj(tree.get(name))
        extra = sorted(
            k for k, v in t.items() if k != "score" and k not in known and _number(v) is not None
        )
        out.append(
            {
                "name": name,
                "score": _unit(t.get("score")),
                "leaves": [{"name": leaf, "value": _unit(t.get(leaf))} for leaf in known + extra],
            }
        )
    return out


def _entity_order(key: str) -> tuple[float, str]:
    tail = key[1:]
    return (int(tail) if _ENTITY_NUM.fullmatch(tail) else math.inf, key)


def bucket_of(scan: dict[str, Any], action: str) -> str:
    """Which total a scan counts towards."""
    if _response(scan) is None:
        return "scan_error"
    if action.startswith("blocked"):
        return "blocked"
    if action.startswith(("review", "held", "staged", "sent to Hermes to stage")):
        return "review"
    if action.startswith("observed"):
        return "observed"
    return "allowed"


#: Bounds on the call the page shows, counted in code points as JavaScript's `[...s]` does.
CALL_STRING_MAX = 8000
CALL_TOTAL_MAX = 24000
CALL_ITEMS_MAX = 100
CALL_DEPTH_MAX = 8
CALL_KEY_MAX = 200
#: Integers past this lose precision in JavaScript, which reads every JSON number as a double.
_SAFE_INT = 2**53
_INDEX = re.compile(r"(?:0|[1-9][0-9]*)")


def _js_keys(d: dict[str, Any]) -> list[str]:
    """An object's keys in JavaScript's order: array-index keys first, ascending, then the rest as written."""
    index = [k for k in d if _INDEX.fullmatch(k) and int(k) < 4294967295]
    rest = [k for k in d if k not in index]
    return sorted(index, key=int) + rest


def _key(k: str) -> str:
    return k if len(k) <= CALL_KEY_MAX else k[:CALL_KEY_MAX] + "…"


def _cut(s: str, budget: list[int]) -> str:
    take = min(len(s), CALL_STRING_MAX, budget[0])
    budget[0] -= take
    return s if take == len(s) else f"{s[:take]}… ({len(s) - take} more characters)"


def _bounded(v: Any, budget: list[int], depth: int) -> Any:
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        if -_SAFE_INT <= v <= _SAFE_INT:
            return v
        try:
            v = float(v)  # as JavaScript reads it
        except OverflowError:
            return None
    if isinstance(v, float):
        return v if math.isfinite(v) else None
    if isinstance(v, str):
        return _cut(v, budget)
    if depth >= CALL_DEPTH_MAX:
        return "… (nested too deep)"
    if isinstance(v, list):
        out = [_bounded(x, budget, depth + 1) for x in v[:CALL_ITEMS_MAX]]
        if len(v) > CALL_ITEMS_MAX:
            out.append(f"… ({len(v) - CALL_ITEMS_MAX} more items)")
        return out
    if isinstance(v, dict):
        keys = _js_keys(v)
        obj = {_key(k): _bounded(v[k], budget, depth + 1) for k in keys[:CALL_ITEMS_MAX]}
        if len(keys) > CALL_ITEMS_MAX:
            obj["…"] = f"{len(keys) - CALL_ITEMS_MAX} more keys"
        return obj
    return None


def call_of(scan: dict[str, Any]) -> dict[str, Any] | None:
    """The call as sent to the scanner (`planir.pending_call`, already redacted on the host): its tool and
    arguments, each string at most CALL_STRING_MAX code points and CALL_TOTAL_MAX in all, lists and objects at most
    CALL_ITEMS_MAX entries, CALL_DEPTH_MAX deep, keys at most CALL_KEY_MAX. Nothing else from the PlanIR. None for a
    record without one."""
    call = _obj(_obj(scan.get("planir")).get("pending_call"))
    if not call:
        return None
    args = call.get("arguments")
    return {
        "tool": _str(call.get("tool"), 80),
        "arguments": _bounded({} if args is None else args, [CALL_TOTAL_MAX], 0),
    }


def scan_model(
    scan: dict[str, Any], resolution: dict[str, Any] | None, with_call: bool = False
) -> dict[str, Any]:
    resp = _response(scan)
    r = resp or {}
    action = action_of(scan, resolution)
    entities = _obj(r.get("entities"))
    step = scan.get("step")
    enforced = r.get("enforced")
    call = {"call": call_of(scan)} if with_call else {}
    return {
        **call,
        "id": str(scan.get("request_id")),
        "ts": scan.get("ts") if isinstance(scan.get("ts"), str) else None,
        "session": _str(scan.get("session_ref"), 80),
        "tool": _str(scan.get("tool"), 80),
        "step": _step(step),
        "mode": _str(scan.get("mode"), 20),
        "action": action,
        "review": review_of(action, resolution),
        "bucket": bucket_of(scan, action),
        "flags": [f for f in FLAGS if scan.get(f) is True],
        # An approval prompt that had no answer when the log was read: still open if recent (`pending_of`).
        "open_review": resp is not None
        and scan.get("mode") != "observe"
        and scan.get("verdict") == "review"
        and scan.get("decision") == "review_timed_out"
        and resolution is None,
        "failure": (_str(_obj(scan.get("failure")).get("kind"), 40) or "unknown")
        if resp is None
        else None,
        "risk": _number(r.get("risk")),
        "enforced": enforced if enforced in ("review", "block") else None,
        "ceiling": _str(r.get("ceiling"), 20),
        "tiers": [] if resp is None else _tiers(_obj(r.get("tree"))),
        "floors": [
            {
                "floor": _str(f.get("floor"), 80),
                "min_risk": _unit(f.get("min_risk")),
                "subject": _str(f.get("subject"), 12),
            }
            for f in _list(r.get("floors_applied"))
        ],
        "relief": [
            {
                "effect": _str(f.get("effect"), 80),
                "grant_ref": _str(f.get("grant_ref"), 40),
                "subject": _str(f.get("subject"), 12),
            }
            for f in _list(r.get("relief_applied"))
        ],
        "reasons": [
            {
                "code": _text(x["code"], 80),
                "signal": _str(x.get("signal"), 60),
                "subject": _str(x.get("subject"), 12),
                "text": _str(x.get("text"), 200),
            }
            for x in _list(r.get("reasons"))
            if isinstance(x.get("code"), str) and x["code"]
        ],
        "entities": [
            {
                "id": _text(k, 12),
                "kind": _str(_obj(entities[k]).get("kind"), 20),
                "display": _text(entities[k]["display"], 200),
            }
            for k in sorted(entities, key=_entity_order)
            if isinstance(_obj(entities[k]).get("display"), str)
        ],
    }


def scans_model(path: Path, enabled: bool, limit: int) -> dict[str, Any]:
    """The scans part of the model; both plugins build the same JSON for the same log."""
    scans = [scan_model(s, res) for s, res in recent_scans(path, limit)] if enabled else []
    return {
        "version": MODEL_VERSION,
        "log": "on" if enabled else "off",
        "limit": limit,
        "scans": scans,
        "totals": _totals(scans),
    }


def _totals(scans: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"blocked": 0, "review": 0, "observed": 0, "allowed": 0, "scan_error": 0}
    for s in scans:
        totals[s["bucket"]] = totals.get(s["bucket"], 0) + 1
    return totals


def limit_of(raw: str | None) -> int:
    """`?n=` from the page's limit buttons: the history default when absent or malformed, at most the max."""
    if not raw or not _LIMIT.fullmatch(raw) or int(raw) < 1:
        return HISTORY_DEFAULT
    return min(int(raw), HISTORY_MAX)


# --- Searching the log.
#
# The traffic log is a plain JSON-lines file, newest last, rotated once to `<path>.1`, so there is no index. A
# query reads it backwards from the end, as history does, and keeps the cost down three ways:
# - every line starts `{"ts": "...", "kind": "...", "request_id": "..."`, so a scan outside the time window, or
#   one before the paging cursor, is skipped on its first bytes without parsing the line (scan lines carry the
#   whole PlanIR and are the large ones);
# - reading stops at the window's start, at a full page, or after QUERY_BUDGET_BYTES;
# - a page is at most HISTORY_MAX scans, and "older" continues from the last scan shown (a request-id cursor).
# Resolution lines are small and always read, so a scan on any page is joined to its answer.
# The OpenClaw plugin's dashboard.ts reads the same way and gives the same pages.

QUERY_BUDGET_BYTES = 64 * 1024 * 1024
_MB = 1024 * 1024


def budget_for(max_bytes: int) -> int:
    """Enough to read the whole log (the file and its one rotation) at the configured size, 16 to 256 MB."""
    return min(max(2 * max_bytes + _MB, 16 * _MB), 256 * _MB)


OUTCOMES = ("blocked", "review", "observed", "allowed", "scan_error")
_CURSOR = re.compile(r"[0-9a-fA-F-]{4,40}")
_RISK = re.compile(r"[0-9]{1,3}")
_ZONED = re.compile(r".*(Z|[+-]\d\d:\d\d)")
_HEAD = re.compile(
    r'\{"ts": ?"([^"]{10,40})", ?"kind": ?"([a-z_]{1,20})"(?:, ?"request_id": ?"([^"]{1,64})")?'
)


@dataclass
class Query:
    limit: int
    #: Older than this scan: the request id of the last scan on the page before.
    before: str | None = None
    #: Time window, epoch ms, inclusive.
    start: int | None = None
    end: int | None = None
    #: Tool name contains this, ignoring case.
    tool: str | None = None
    outcome: str | None = None
    min_risk: int | None = None
    session: str | None = None


def _ms(v: Any) -> int | None:
    """Epoch ms of an ISO time with a zone, as JavaScript's Date.parse reads the plugins' `ts`."""
    at = _ts(v)
    return None if at is None else int(round(at.timestamp() * 1000))


def query_of(params: dict[str, str | None]) -> Query:
    """Reads the page's query string; anything malformed is left out rather than refused."""

    def time(k: str) -> int | None:
        v = params.get(k)
        # With an explicit zone only, so both plugins read it the same (the page sends UTC).
        if not v or len(v) > 40 or not _ZONED.fullmatch(v):
            return None
        return _ms(v)

    def text(k: str, cap: int) -> str | None:
        v = (params.get(k) or "").strip()
        return v if v and len(v) <= cap else None

    before = params.get("before")
    outcome = params.get("outcome")
    risk = params.get("risk")
    return Query(
        limit=limit_of(params.get("n")),
        before=before.lower() if before and _CURSOR.fullmatch(before) else None,
        start=time("from"),
        end=time("to"),
        tool=text("tool", 80),
        outcome=outcome if outcome in OUTCOMES else None,
        min_risk=int(risk) if risk and _RISK.fullmatch(risk) and int(risk) <= 100 else None,
        session=text("session", 80),
    )


def _query_echo(q: Query) -> dict[str, Any]:
    def iso(v: int | None) -> str | None:
        if v is None:
            return None
        at = datetime.fromtimestamp(v / 1000, UTC)
        return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"

    return {
        "limit": q.limit,
        "before": q.before,
        "from": iso(q.start),
        "to": iso(q.end),
        "tool": q.tool,
        "outcome": q.outcome,
        "min_risk": q.min_risk,
        "session": q.session,
    }


def _lines(path: Path, budget: list[int]) -> Iterator[str]:
    """Lines of `path` then `<path>.1`, newest first; stops when the budget is spent."""
    for p in (path, path.with_name(path.name + ".1")):
        for line in _lines_backward(p, budget):
            yield line.decode("utf-8", errors="replace")
        if budget[0] <= 0:
            return


def _head(line: str) -> tuple[int, str, str | None] | None:
    """The time, kind and request id from a line's first bytes; None when it does not start as written."""
    m = _HEAD.match(line[:200])
    if not m:
        return None
    at = _ms(m.group(1))
    return None if at is None else (at, m.group(2), m.group(3))


def _parse(line: str) -> dict[str, Any] | None:
    try:
        v = json.loads(line)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def _matches(s: dict[str, Any], q: Query) -> bool:
    if q.tool is not None and q.tool.lower() not in (s["tool"] or "").lower():
        return False
    if q.outcome is not None and s["bucket"] != q.outcome:
        return False
    if q.min_risk is not None and not (
        isinstance(s["risk"], (int, float)) and s["risk"] >= q.min_risk
    ):
        return False
    return not (q.session is not None and s["session"] != q.session)


def query_scans(
    path: Path, q: Query, budget_bytes: int = QUERY_BUDGET_BYTES, with_calls: bool = False
) -> dict[str, Any]:
    """One page of scans matching `q`, newest first. `more`: the page filled up, so older matches may follow
    from `next` (the last scan's id). `budget_hit`: the read stopped at the budget before the log or window
    ran out. `cursor_lost`: the `before` scan was not found (rotated away)."""
    budget = [budget_bytes]
    resolutions: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    scans: list[dict[str, Any]] = []
    passed = q.before is None
    stopped = False
    exhausted = True
    for line in _lines(path, budget):
        if not line.strip():
            continue
        head = _head(line)
        rec: dict[str, Any] | None = None
        if head is None:
            rec = _parse(line)
            at = _ms(rec.get("ts")) if rec else None
            if rec is None or at is None:
                continue
            rid = rec.get("request_id")
            head = (at, str(rec.get("kind")), rid if isinstance(rid, str) else None)
        at, kind, rid = head
        if kind == "resolution":
            rec = rec or _parse(line)
            r = rec.get("request_id") if rec else None
            if isinstance(r, str) and r not in resolutions:
                resolutions[r] = rec
            continue
        if kind != "scan" or rid is None:
            continue
        if not passed:
            if rid.lower() == q.before:
                passed = True
            continue
        if q.end is not None and at > q.end:
            continue
        if q.start is not None and at < q.start:
            exhausted = False
            stopped = True
            break
        if rid in seen:
            continue
        # A tool name the line does not contain cannot match: skip it unparsed.
        if q.tool is not None and q.tool.lower() not in line.lower():
            continue
        rec = rec or _parse(line)
        if rec is None or rec.get("request_id") != rid:
            continue
        seen.add(rid)
        model = scan_model(rec, resolutions.get(rid), with_calls)
        if not _matches(model, q):
            continue
        scans.append(model)
        if len(scans) >= q.limit:
            exhausted = False
            stopped = True
            break
    budget_hit = not stopped and budget[0] <= 0
    if budget_hit:
        exhausted = False
    full = len(scans) >= q.limit
    return {
        "scans": scans,
        "totals": _totals(scans),
        "query": _query_echo(q),
        "page": {
            "more": full,
            "next": scans[-1]["id"] if full else None,
            "read_bytes": budget_bytes - budget[0],
            "budget_hit": budget_hit,
            "cursor_lost": not passed,
            "reached_start": exhausted and passed,
        },
    }


#: How the page names this host's commands: the plugin's own (prefix + verb) and Hermes's approval answers.
COMMANDS = {
    "prefix": "/sentrook ",
    #: The setting that lets each scan show its call, as the owner sets it in this host's config.
    "call_setting": "hermes config set plugins.entries.sentrook.settings.dashboard_show_calls true",
    "review_answer": [
        "Answer in the chat where it was asked, with Hermes's own commands:",
        "/approve",
        "/approve session",
        "/approve always",
        "/deny",
    ],
}

#: Hermes's `approvals.timeout` default, in seconds.
DEFAULT_REVIEW_WINDOW_S = 300


def _ts(v: Any) -> datetime | None:
    if not isinstance(v, str):
        return None
    try:
        at = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo else at.replace(tzinfo=UTC)


def pending_of(
    path: Path,
    enabled: bool,
    state_dir: Path,
    now: datetime,
    window_s: float,
    budget_bytes: int = QUERY_BUDGET_BYTES,
    with_calls: bool = False,
) -> dict[str, Any]:
    """What waits for the owner, read on its own so it does not depend on the page's search: approval prompts
    still inside their answer window (the host's approval timeout), and held calls (unattended reviews) not yet
    approved or expired, newest first, each with its scan when that is still in the log. Reading stops at the
    oldest of these."""
    holds: list[dict[str, Any]] = []
    readable = True
    try:
        data = Store(state_dir).load_holds()
        if data is None:
            readable = False
        for h in (data or {}).get("holds") or []:
            if not isinstance(h, dict) or not isinstance(h.get("id"), str):
                continue
            expires = read_time(h.get("expires_at"))
            if expires is None or expires <= now:
                continue
            grant = grants.hint_grant(h.get("hint"))
            holds.append(
                {
                    "id": _text(h["id"], 12),
                    "request_id": _str(h.get("request_id"), 40),
                    "tool": _str(h.get("tool"), 80),
                    "where": _str(h.get("where"), 200),
                    "held_at": h.get("held_at") if isinstance(h.get("held_at"), str) else None,
                    "expires_at": h.get("expires_at")
                    if isinstance(h.get("expires_at"), str)
                    else None,
                    "grant": grants.describe_grant(grant) if grant else None,
                    "scan": None,
                }
            )
        holds.reverse()
    except Exception:  # noqa: BLE001 - the page still shows the scans
        readable = False
    reviews: list[dict[str, Any]] = []
    now_ms = int(round(now.timestamp() * 1000))
    window_start = now_ms - int(round(window_s * 1000))
    start = window_start
    wanted: dict[str, dict[str, Any]] = {}
    for h in holds:
        if h["request_id"]:
            wanted[h["request_id"]] = h
        at = _ms(h["held_at"])
        # A hold is made right after its scan; a minute's margin covers the scan's own time.
        if at is not None:
            start = min(start, at - 60_000)
    if enabled:
        budget = [budget_bytes]
        resolutions: dict[str, dict[str, Any]] = {}
        for line in _lines(path, budget):
            head = _head(line)
            if head is None:
                continue
            at, kind, rid = head
            if at < start:
                break
            if kind == "resolution":
                rec = _parse(line)
                r = rec.get("request_id") if rec else None
                if isinstance(r, str) and r not in resolutions:
                    resolutions[r] = rec
                continue
            if kind != "scan" or rid is None:
                continue
            hold = wanted.get(rid)
            recent = window_start <= at <= now_ms
            if hold is None and not recent:
                continue
            rec = _parse(line)
            if rec is None or rec.get("request_id") != rid:
                continue
            model = scan_model(rec, resolutions.get(rid), with_calls)
            if hold is not None and hold["scan"] is None:
                hold["scan"] = model
            if recent and model["open_review"] and all(r["id"] != model["id"] for r in reviews):
                reviews.append(model)
    return {
        "reviews": reviews,
        "holds": holds,
        "holds_readable": readable,
        "review_window_s": round(window_s),
    }


def report_of(cfg: PluginConfig, ref: str | None, budget: int) -> dict[str, Any] | None:
    """The report panel for the scan the page asked about (`report=<request id or its start>`), or None when it
    asked about none: the summary `/sentrook report` prints, the issue and email links, and the owner's commands
    for the full record, which the model never holds."""
    ref = (ref or "").strip()
    if not ref:
        return None
    match = parse_ref(ref) if ref.lower() != "last" else None
    found = (
        report.find(cfg.traffic_log_path, match, budget)
        if match is not None and cfg.traffic_log_enabled
        else None
    )
    return report.model(found, CMD) if found is not None else {"id": ref[:36], "missing": True}


def build_model(
    cfg: PluginConfig,
    q: Query,
    now: datetime | None = None,
    review_window_s: float = DEFAULT_REVIEW_WINDOW_S,
    report_ref: str | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    enabled = cfg.traffic_log_enabled
    budget = budget_for(cfg.traffic_log_max_bytes)
    if enabled:
        page = query_scans(cfg.traffic_log_path, q, budget, cfg.dashboard_show_calls)
    else:
        page = {
            "scans": [],
            "totals": _totals([]),
            "query": _query_echo(q),
            "page": {
                "more": False,
                "next": None,
                "read_bytes": 0,
                "budget_hit": False,
                "cursor_lost": False,
                "reached_start": True,
            },
        }
    try:
        grants_text = grants.format_grants(cfg, grants.load(cfg.state_dir), now, CMD, None)
    except Exception:  # noqa: BLE001 - the page still shows the scans
        grants_text = "Grants could not be read."
    try:
        snooze_text = snooze.status_line(snooze.load(cfg.state_dir), now)
    except Exception:  # noqa: BLE001 - the page still shows the scans
        snooze_text = "Snooze state could not be read."
    model: dict[str, Any] = {
        "version": MODEL_VERSION,
        "log": "on" if enabled else "off",
        "limit": q.limit,
        **page,
        "host": "hermes",
        "lines": {"review_at": cfg.review_at, "block_at": cfg.block_at},
        "mode": cfg.mode,
        "state": {"grants": grants_text, "snooze": snooze_text},
        "pending": pending_of(
            cfg.traffic_log_path,
            enabled,
            cfg.state_dir,
            now,
            review_window_s,
            budget,
            cfg.dashboard_show_calls,
        ),
        "commands": COMMANDS,
        "show_calls": cfg.dashboard_show_calls,
    }
    panel = report_of(cfg, report_ref, budget)
    if panel is not None:
        model["report"] = panel
    return model
