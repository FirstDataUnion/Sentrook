"""Scan history read back from the local traffic log, for `/sentrook history` and `/sentrook why`.

The log is read backwards from its end and on into the rotated `<path>.1`, and reading stops once
enough scans are found or `READ_BUDGET_BYTES` have been read, so only the tail is read. A review
resolution is written after its scan, so reading backwards it comes first and is joined to its scan
by `request_id`. A line that does not parse (a write cut off mid-line, or one still being written)
is skipped.

Only what the scanner returned is shown: risk, tier scores, reason codes and entity display strings.
The PlanIR as sent, with the call's arguments, and reason or failure details are never shown.
The OpenClaw plugin prints the same text for the same log.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from .decision import tiers_of

HISTORY_DEFAULT = 10
HISTORY_MAX = 50
READ_BUDGET_BYTES = 16 * 1024 * 1024
_CHUNK = 64 * 1024

LOG_OFF = "The traffic log is off, so there is no scan history."
NO_SCANS = "No scans in the traffic log yet."

_APPROVED = frozenset(
    {"once", "session", "always", "allow-once", "allow_once", "allow-always", "allow_always"}
)
_REVIEW = {"deny": "denied", "timeout": "timed out", "cancelled": "cancelled"}
_ID = re.compile(r"[0-9a-fA-F-]{4,36}")
_SPACE = re.compile(r"\s+")
_COUNT = re.compile(r"[0-9]{1,6}")


def _lines_backward(path: Path, budget: list[int]) -> Iterator[bytes]:
    try:
        f = open(path, "rb")  # noqa: SIM115 - closed by the with below
    except OSError:
        return
    with f:
        pos = f.seek(0, os.SEEK_END)
        head = b""
        while pos > 0 and budget[0] > 0:
            step = min(_CHUNK, pos, budget[0])
            pos -= step
            budget[0] -= step
            f.seek(pos)
            parts = (f.read(step) + head).split(b"\n")
            head = parts[0]
            yield from reversed(parts[1:])
        if pos == 0:
            yield head


def records_backward(path: Path, budget: int = READ_BUDGET_BYTES) -> Iterator[dict[str, Any]]:
    """Traffic-log records, newest first, from `path` and then `<path>.1`."""
    left = [budget]
    for p in (path, path.with_name(path.name + ".1")):
        for line in _lines_backward(p, left):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield rec


def recent_scans(
    path: Path, limit: int, match: Callable[[str], bool] | None = None
) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    """Up to `limit` scan records, newest first, each with its review resolution (or None)."""
    resolutions: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    out: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for rec in records_backward(path):
        rid = rec.get("request_id")
        if not isinstance(rid, str):
            continue
        if rec.get("kind") == "resolution":
            resolutions.setdefault(rid, rec)
        elif rec.get("kind") == "scan" and rid not in seen:
            seen.add(rid)
            if match is None or match(rid):
                out.append((rec, resolutions.get(rid)))
                if len(out) >= limit:
                    break
    return out


def parse_count(rest: str) -> int | None:
    """`history [n]`: 10 when empty, at most 50; None when it is not a positive whole number."""
    if not rest:
        return HISTORY_DEFAULT
    if not _COUNT.fullmatch(rest) or int(rest) < 1:
        return None
    return min(int(rest), HISTORY_MAX)


def parse_ref(rest: str) -> Callable[[str], bool] | None:
    """`why [request_id|last]`: a matcher on request ids (a prefix will do); None when malformed."""
    if rest.lower() in ("", "last"):
        return lambda _rid: True
    if not _ID.fullmatch(rest):
        return None
    prefix = rest.lower()
    return lambda rid: rid.lower().startswith(prefix)


def _text(v: Any, limit: int) -> str:
    s = _SPACE.sub(" ", str(v)).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _response(scan: dict[str, Any]) -> dict[str, Any] | None:
    resp = scan.get("response")
    return resp if isinstance(resp, dict) else None


def _half_up(v: float) -> int:
    """Rounds halves up, as JavaScript's Math.round does, so both plugins print the same numbers."""
    return math.floor(v + 0.5)


def _risk(resp: dict[str, Any] | None) -> str:
    v = (resp or {}).get("risk")
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return "-"
    return str(_half_up(v))


def _scores(resp: dict[str, Any]) -> str:
    """The tree's tier scores on the 0-100 scale of `risk`, each held to 0-1; empty when none."""
    return ", ".join(
        f"{name} {_half_up(min(max(v, 0.0), 1.0) * 100)}"
        for name, v in tiers_of(resp).items()
        if v is not None and math.isfinite(v)
    )


def _time(ts: Any) -> str:
    return f"{ts[:10]} {ts[11:19]}" if isinstance(ts, str) and len(ts) >= 19 else "?"


def action_of(scan: dict[str, Any], resolution: dict[str, Any] | None) -> str:
    """What the plugin did with the call."""
    verdict, decision = scan.get("verdict"), scan.get("decision")
    if _response(scan) is None:
        if resolution is not None:
            return "review (scan error)"
        return "blocked (scan error)" if decision == "blocked_on_error" else "allowed (scan error)"
    if scan.get("mode") == "observe":
        return f"observed (would {verdict})" if verdict in ("review", "block") else "allowed"
    if verdict == "block":
        return "blocked"
    if verdict == "review":
        if decision == "allowed" and scan.get("snoozed") is True:
            return "allowed (snoozed)"
        return "blocked (no reviewer)" if decision == "blocked" else "review"
    if verdict == "allow":
        return "allowed"
    return _text(decision or "?", 30)


def review_of(action: str, resolution: dict[str, Any] | None) -> str:
    """How the review was answered; `-` when there was none."""
    if resolution is None:
        return "no answer" if action.startswith("review") else "-"
    choice = str(resolution.get("resolution") or "").strip().lower()
    return "approved" if choice in _APPROVED else _REVIEW.get(choice, "not approved")


def format_history(
    scans: list[tuple[dict[str, Any], dict[str, Any] | None]], why_command: str
) -> str:
    if not scans:
        return NO_SCANS
    table = [("id", "time (UTC)", "session", "tool", "risk", "action", "review")]
    for scan, resolution in scans:
        action = action_of(scan, resolution)
        table.append(
            (
                str(scan["request_id"])[:8],
                _time(scan.get("ts")),
                _text(scan.get("session_ref") or "-", 20),
                _text(scan.get("tool") or "?", 40),
                _risk(_response(scan)),
                action,
                review_of(action, resolution),
            )
        )
    widths = [max(len(row[i]) for row in table) for i in range(len(table[0]))]
    rows = [
        "  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip() for row in table
    ]
    n = len(scans)
    return "\n".join(
        (
            f"Last {n} scan{'' if n == 1 else 's'}, newest first:",
            *rows,
            f"Details: {why_command} <id>",
        )
    )


def _entity_order(key: str) -> tuple[float, str]:
    """E1, E2, ..., E10 in number order."""
    digits = key[1:]
    return (float(digits) if digits.isdigit() else math.inf, key)


def format_why(scan: dict[str, Any], resolution: dict[str, Any] | None) -> str:
    resp = _response(scan)
    action = action_of(scan, resolution)
    step = scan.get("step")
    lines = [
        f"scan: {scan['request_id']}",
        f"time: {_time(scan.get('ts'))} UTC",
        f"tool: {_text(scan.get('tool') or '?', 80)}"
        + (f", step {step}" if isinstance(step, int) else ""),
    ]
    if resp is None:
        failure = scan.get("failure") if isinstance(scan.get("failure"), dict) else {}
        status = failure.get("status")
        lines.append(
            f"risk: - (scan failed: {_text(failure.get('kind') or 'unknown', 40)}"
            + (f", HTTP {status}" if isinstance(status, int) else "")
            + ")"
        )
    else:
        floor = resp.get("enforced")
        lines.append(
            f"risk: {_risk(resp)}"
            + (f", scanner floor: {floor}" if floor in ("review", "block") else "")
        )
    lines += [f"action: {action}", f"review: {review_of(action, resolution)}"]
    resp = resp or {}
    scores = _scores(resp)
    if scores:
        lines.append(f"scores: {scores}")
    codes: list[str] = []
    for r in resp.get("reasons") or []:
        code = r.get("code") if isinstance(r, dict) else None
        if isinstance(code, str) and code and _text(code, 80) not in codes:
            codes.append(_text(code, 80))
    lines.append(f"reasons: {', '.join(codes) or 'none'}")
    entities = resp.get("entities") if isinstance(resp.get("entities"), dict) else {}
    shown = [
        f"  {_text(key, 12)} {_text(e.get('kind') or '?', 20)}: {_text(e.get('display'), 200)}"
        for key, e in sorted(entities.items(), key=lambda kv: _entity_order(str(kv[0])))
        if isinstance(e, dict) and isinstance(e.get("display"), str)
    ]
    lines += ["entities:", *shown] if shown else ["entities: none"]
    return "\n".join(lines)
