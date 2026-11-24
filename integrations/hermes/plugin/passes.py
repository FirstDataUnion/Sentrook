"""Passes and denials: what the owner's answer to a held call sets for the run that made it.

A held call (`hold`) is answered with `allow`, `allow always` or `deny`. Each answer is kept here, in
`<hermes home>/sentrook/passes.json`, bound to the cron job the held call came from and to the action:

- `allow` (once): a one-use pass. The job's next run that makes the same call goes through once.
- `allow always`: a standing pass for the job, for 30 days, with a use count.
- `deny`: a standing denial for the job, for 30 days. A matching call gets `DECLINED_TEXT` and no notice is sent.

The job is the one Hermes's run metadata names (`current_cron_execution().job_id`), never text from the prompt. A
hold on a run that is not a cron job has no job to bind to: there `allow` gives a one-use pass bound to the call's
exact arguments, for 7 days, and nothing else is offered.

A later call matches on the same terms as a Session answer in a chat (`session_allow`), with the job as the scope:
a call of the same tool about the same parties (the entities its reasons and description name), scoring no higher,
with no warning the held call lacked, which the scanner neither enforced nor applied a floor to, and on a complete
scan. A pass also needs the scan's `owner_pass` at or above its own level (`level_of`): a call that has since picked
up a strong signal is never passed. When the call names no party, or its approval fingerprint names nothing, the
match also binds to the call's exact arguments (hashed), and only a one-use pass is offered. A denial matches the
job and action whatever the scan says: refusing is always safe.

The match key is an HMAC under the install's salt, so the file reveals nothing about the action; it keeps the
tool, the run's description of the call (as the hold's notice showed it) and the job, for the owner's list.
`passes.json` is changed under the same cross-process lock as `holds.json` and `grants.json`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import session_allow
from .store import Store, file_lock, read_time

#: How long a standing pass, a denial and a job's one-use pass last.
PASS_TTL = timedelta(days=30)
#: How long a one-use pass bound to exact arguments (a hold that is not on a cron job) lasts.
ARGS_TTL = timedelta(days=7)
MAX_PASSES = 200
_ID = re.compile(r"p-[0-9a-f]{6}")
_LOCK = threading.Lock()

DECLINED_TEXT = (
    "The owner declined this action for this job, so Sentrook did not run it. Continue without it."
)

#: The scan's `owner_pass` levels, lowest first. A scanner that sends no `owner_pass` predates it: its scans read as
#: `once` (allow once, never always).
LEVELS = ("once", "always")

#: The verbs an answer can use, as the notice lists them.
ALLOW, ALLOW_LATER, ALLOW_ALWAYS, DENY = "allow", "allow later", "allow always", "deny"


def level_of(resp: dict[str, Any]) -> str | None:
    """How far the scanner lets the owner pass this call: `always`, `once`, or None (not at all). A response
    without the field comes from a scanner that predates it and reads as `once`; any value but the two is None."""
    if "owner_pass" not in resp:
        return "once"
    value = resp.get("owner_pass")
    return value if value in LEVELS else None


def level_covers(have: str | None, need: str | None) -> bool:
    """Whether a scan at level `have` may use a pass set at level `need`."""
    return have in LEVELS and need in LEVELS and LEVELS.index(have) >= LEVELS.index(need)


def job_ref(job_id: str | None) -> str | None:
    """A cron job's ref, hashed as `session_ref` is."""
    if not job_id:
        return None
    return "j_" + hashlib.sha256(job_id.encode()).hexdigest()[:12]


def names_nothing(fingerprint: Any) -> bool:
    """The approval fingerprint names nothing the call acts on (`afp1:<kind>` alone, or with only the tool's
    provider), or there is none."""
    if not isinstance(fingerprint, str) or not fingerprint:
        return True
    return not [p for p in fingerprint.split("|")[1:] if p and not p.startswith("prov:")]


def match_of(
    tool: str, resp: dict[str, Any], args: Any, secret: str, exact: bool = False
) -> dict[str, Any]:
    """What a pass for this call binds to: `key` (the tool and parties, plus the exact arguments when `named` is
    false), the `risk` it was held at and its `warnings`. `exact`: always bind to the exact arguments (a run that
    is not a cron job)."""
    named = session_allow.parties(resp)
    fp = resp.get("approval_fingerprint") or resp.get("action_fingerprint")
    bound = bool(named) and not names_nothing(fp) and not exact
    material = "\n".join([tool, *(f"{k}\t{d}" for k, d in named)])
    if not bound:
        arguments = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
        material += "\nargs:" + hashlib.sha256(arguments.encode()).hexdigest()
    key = hmac.new(
        ("sentrook pass v1|" + secret).encode(), material.encode(), hashlib.sha256
    ).hexdigest()[:24]
    return {
        "key": key,
        "named": bound,
        "risk": session_allow.risk_of(resp),
        "warnings": session_allow.warnings(resp),
    }


def covers(held: dict[str, Any], later: dict[str, Any]) -> bool:
    """Whether a call matched as `later` is the same action as `held` at no higher risk and with no new warning:
    a repeat of a waiting hold, or a call a pass set from it covers (with `session_allow.eligible` checked apart)."""
    if not isinstance(held, dict) or held.get("key") != later.get("key"):
        return False
    risk, held_risk = later.get("risk"), held.get("risk")
    if not isinstance(risk, (int, float)) or not isinstance(held_risk, (int, float)):
        return False
    return risk <= held_risk and not set(later.get("warnings") or []) - set(held.get("warnings") or [])


def offers(
    job_id: str | None, level: str | None, named: bool, risk: float | None, block_at: float
) -> list[str]:
    """The answers a hold offers, in the notice's order. On a cron job: `allow` when the scanner lets the owner
    pass the call at all, `allow always` when it lets it pass for good and the call names its parties below the
    block line, and `deny`. Elsewhere only `allow` (bound to the exact call). `allow later` is accepted wherever
    `allow` is: until the plugin can start a job's run itself, both use the job's next run."""
    if not job_id:
        return [ALLOW] if level is not None else []
    out: list[str] = []
    if level is not None:
        out.append(ALLOW)
        if level == "always" and named and risk is not None and risk < block_at:
            out.append(ALLOW_ALWAYS)
    out.append(DENY)
    return out


# ---- the file -----------------------------------------------------------------------------------------


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _clean(s: Any, cap: int = 200) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


def _live(p: Any, now: datetime) -> bool:
    if not isinstance(p, dict) or p.get("kind") not in ("allow", "deny"):
        return False
    at = read_time(p.get("expires_at"))
    return at is not None and at > now


def _path(state_dir: Path) -> Path:
    return Path(state_dir) / "passes.json"


def load(state_dir: Path) -> dict[str, Any] | None:
    return Store(state_dir).load_passes()


def live(data: dict[str, Any] | None, now: datetime) -> list[dict[str, Any]]:
    return [p for p in (data or {}).get("passes") or [] if _live(p, now)]


def add(
    state_dir: Path,
    *,
    kind: str,
    uses: str,
    level: str | None,
    hold: dict[str, Any],
    who: dict[str, Any],
    now: datetime,
) -> dict[str, Any] | None:
    """Stores a pass (`kind` allow) or denial (`deny`) set from `hold`; returns the entry, or None when the file
    cannot be read. `uses`: `once` or `standing`. Called with the holds file locked."""
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = store.load_passes()
        if data is None:
            return None
        data["passes"] = live(data, now)
        taken = {p.get("id") for p in data["passes"]}
        pid = f"p-{secrets.token_hex(3)}"
        while pid in taken:
            pid = f"p-{secrets.token_hex(3)}"
        ttl = PASS_TTL if hold.get("job_ref") else ARGS_TTL
        entry = {
            "id": pid,
            "kind": kind,
            "uses": uses,
            "level": level if kind == "allow" else None,
            "job_id": hold.get("job_id"),
            "job_ref": hold.get("job_ref"),
            "tool": hold.get("tool"),
            "description": hold.get("description"),
            "match": hold.get("match"),
            "hold_id": hold.get("id"),
            "set_at": _iso(now),
            "expires_at": _iso(now + ttl),
            "set_by": who,
            "use_count": 0,
            "last_used_at": None,
        }
        data["passes"].append(entry)
        data["passes"] = data["passes"][-MAX_PASSES:]
        store.save_passes(data)
        return entry


def check(
    state_dir: Path,
    ref: str | None,
    match: dict[str, Any],
    resp: dict[str, Any],
    now: datetime,
) -> dict[str, Any] | None:
    """The denial or pass that settles this held-to-be call, or None. A denial of the same job and action wins
    over any pass. A pass applies only to an eligible scan (`session_allow.eligible`) that the pass covers
    (`covers`) at an `owner_pass` level at or above the pass's own. A one-use pass is used up; a standing one
    counts the use. A file that cannot be read settles nothing (the call is held as before)."""
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = store.load_passes()
        if data is None:
            return None
        found = live(data, now)
        same = [
            p
            for p in found
            if p.get("job_ref") == ref
            and isinstance(p.get("match"), dict)
            and p["match"].get("key") == match.get("key")
        ]
        hit = next((p for p in same if p["kind"] == "deny" and ref is not None), None)
        if hit is None and session_allow.eligible(resp):
            have = level_of(resp)
            hit = next(
                (
                    p
                    for p in same
                    if p["kind"] == "allow"
                    and covers(p["match"], match)
                    and level_covers(have, p.get("level"))
                ),
                None,
            )
        if hit is None:
            if len(found) != len(data["passes"]):
                data["passes"] = found
                store.save_passes(data)
            return None
        hit["use_count"] = int(hit.get("use_count") or 0) + 1
        hit["last_used_at"] = _iso(now)
        data["passes"] = [p for p in found if not (p is hit and p.get("uses") == "once")]
        store.save_passes(data)
        return dict(hit)


def revoke(state_dir: Path, rest: str, now: datetime) -> tuple[str, dict[str, Any] | None]:
    """`passes revoke <id>`: removes a pass or denial; returns the reply and the change to record."""
    pid = rest.strip()
    if not _ID.fullmatch(pid):
        return "usage: passes revoke <id>, with an id from the passes list (p- and 6 hex digits)", None
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = store.load_passes()
        if data is None:
            return f"The passes file {_path(state_dir)} could not be read; fix or remove it first.", None
        kept = live(data, now)
        found = next((p for p in kept if p.get("id") == pid), None)
        if found is None:
            return f"No pass or denial {_clean(pid, 40)}: the id is unknown, used up or expired.", None
        data["passes"] = [p for p in kept if p is not found]
        store.save_passes(data)
    what = "denial" if found["kind"] == "deny" else "pass"
    return (
        f"Revoked {what} {pid}.",
        {"op": "revoke", "id": pid, "pass_kind": found["kind"], "job_ref": found.get("job_ref")},
    )


def _job(p: dict[str, Any]) -> str:
    return f"job {_clean(p.get('job_id'), 40)}" if p.get("job_id") else "an unattended run"


def describe(p: dict[str, Any]) -> str:
    """One pass or denial, as the list and the dashboard show it."""
    at = read_time(p.get("expires_at"))
    until = show(at) if at else "?"
    call = f"{_clean(p.get('tool') or '?', 60)}: {_clean(p.get('description') or '?', 120)}"
    if p.get("kind") == "deny":
        return f"denied on {_job(p)} until {until}: {call}"
    if p.get("uses") == "once":
        return f"allowed once on {_job(p)}'s next run, until {until}: {call}"
    used = int(p.get("use_count") or 0)
    return f"allowed on {_job(p)} until {until}, used {used} time{'s' * (used != 1)}: {call}"


def format_passes(state_dir: Path, now: datetime, cmd: Any) -> str:
    data = load(state_dir)
    if data is None:
        return f"The passes file {_path(state_dir)} could not be read; fix or remove it first."
    found = live(data, now)
    if not found:
        return (
            "No passes or denials. Answering a held call sets one: "
            f"{cmd('allow')} <id> [always], {cmd('deny')} <id>."
        )
    lines = [f"{p['id']}  {describe(p)}" for p in found]
    lines.append(f"Remove one with {cmd('passes')} revoke <id>.")
    return "\n".join(lines)


def counts(state_dir: Path, now: datetime) -> str:
    """Passes and denials in force, for status and verify."""
    data = load(state_dir)
    if data is None:
        return "passes file unreadable"
    found = live(data, now)
    standing = sum(1 for p in found if p["kind"] == "allow" and p.get("uses") != "once")
    once = sum(1 for p in found if p["kind"] == "allow" and p.get("uses") == "once")
    denials = sum(1 for p in found if p["kind"] == "deny")
    return f"{standing} standing, {once} once, {denials} denial{'s' * (denials != 1)}"


def is_id(text: str) -> bool:
    return bool(_ID.fullmatch(text))
