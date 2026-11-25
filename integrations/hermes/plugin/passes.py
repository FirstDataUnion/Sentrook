"""Passes and denials: what the owner's answer to a held call sets for the run that made it.

A held call (`hold`) is answered with `allow`, `allow always` or `deny`. Each answer is kept here, in
`<hermes home>/sentrook/passes.json`, bound to the cron job the held call came from and to the action:

- `allow` (once): a one-use pass. When the plugin starts a new run of the job for the answer (`run_now`), the pass
  is bound to that run (`runs`, below); otherwise the job's next run that makes the same call goes through once.
- `allow always`: a standing pass for the job, for 30 days, with a use count.
- `deny`: a standing denial for the job, for 30 days. A matching call gets `DECLINED_TEXT` and no notice is sent.

The job is the one Hermes's run metadata names (`current_cron_execution().job_id`), never text from the prompt.

A hold on another unattended run is bound to the run's source instead (`source_of`), when Hermes's run metadata
names one: a subagent's parent session, a webhook's route, an API-server key's name. Its `allow` is a one-use pass
for the next matching call from the same source within 7 days (nothing is started), and `allow always` and `deny`
are bound to the same source. The source is hashed as `session_ref` is (`source_ref`), and never read from the
prompt or the call. A run with no source the plugin can name has nothing to bind to: there `allow` gives a one-use
pass bound to the call's exact arguments, for 7 days, and nothing else is offered.

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

A pass bound to a run the plugin started (`run_bound`) has a record in the file's `runs` list: the job, when it was
asked for, the held run (which never counts as the new one) and, once a scan or the run's end finds it, the run it is
bound to. A run counts as the started one when it is that run, or (before one is bound) when it is not the held run
and started after the answer. The record notes whether the call went through and the holds the run made, so the owner
gets one line when the run ends (`outcome_text`); a run-bound pass the run did not use ends with it.
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
#: How long a one-use pass that is not on a cron job (bound to a source, or to exact arguments) lasts.
ARGS_TTL = timedelta(days=7)
MAX_PASSES = 200
_ID = re.compile(r"p-[0-9a-f]{6}")
_LOCK = threading.Lock()

DECLINED_TEXT = (
    "The owner declined this action for this job, so Sentrook did not run it. Continue without it."
)

#: The scan's `owner_pass` levels, lowest first. A response without `owner_pass` (a scanner that predates it) reads
#: as null: no pass.
LEVELS = ("once", "always")

#: The verbs an answer can use, as the notice lists them.
ALLOW, ALLOW_LATER, ALLOW_ALWAYS, DENY = "allow", "allow later", "allow always", "deny"
#: `allow` that starts the job again even though the held run had already acted (`acts`).
ALLOW_NOW = "allow now"

#: A call acted (sent or wrote something a new run would do again) when it ran with one of these tool kinds, or when
#: the scan described it with one of these categories.
ACTING_KINDS = frozenset({"file_edit", "file_write", "memory_write", "message_send"})
ACTING_CATEGORIES = frozenset(
    {
        "deletes_data",
        "modifies_agent_or_host_config",
        "sends_data_off_host",
        "sends_message_to_person",
        "writes_local_files",
    }
)
#: How long a run the plugin started for an answer counts as still pending (so another answer does not start a second
#: run of the job) until the plugin sees it end.
PENDING_RUN = timedelta(hours=1)
#: How much earlier than the answer a run may say it started and still count as the one started for it (clocks).
RUN_SLACK = timedelta(seconds=2)


def acts(kind: Any, resp: dict[str, Any] | None) -> bool:
    """Whether a call of tool kind `kind`, scanned as `resp`, sends or writes something (`ACTING_KINDS`,
    `ACTING_CATEGORIES`)."""
    desc = (resp or {}).get("tool_description")
    category = desc.get("category") if isinstance(desc, dict) else None
    return kind in ACTING_KINDS or category in ACTING_CATEGORIES


def level_of(resp: dict[str, Any]) -> str | None:
    """How far the scanner lets the owner pass this call: `always`, `once`, or None (not at all). A response
    without the field (a scanner that predates it), null or any value but the two is None: the scanner sends it on
    every scan, and only the scanner decides that a call may be passed."""
    value = resp.get("owner_pass")
    return value if value in LEVELS else None


def offered_level(resp: dict[str, Any]) -> str | None:
    """The level a hold of this scan offers (`level_of`), or None when no pass could ever let it through: a scan the
    scanner enforced, applied a floor to, or did not finish (`session_allow.eligible`). Such a hold offers only
    `deny` (or nothing, off a cron job)."""
    return level_of(resp) if session_allow.eligible(resp) else None


def level_covers(have: str | None, need: str | None) -> bool:
    """Whether a scan at level `have` may use a pass set at level `need`."""
    return have in LEVELS and need in LEVELS and LEVELS.index(have) >= LEVELS.index(need)


def job_ref(job_id: str | None) -> str | None:
    """A cron job's ref, hashed as `session_ref` is."""
    if not job_id:
        return None
    return "j_" + hashlib.sha256(job_id.encode()).hexdigest()[:12]


#: The kinds of unattended run, other than a cron job, whose answers can be bound to where the run came from: a
#: heartbeat (its agent; OpenClaw), a webhook or event run (its hook or route), a subagent (its parent session) and
#: an API-server run (its key's name).
SOURCE_KINDS = ("heartbeat", "hook", "subagent", "api")
_SOURCE_PREFIX = {"heartbeat": "a_", "hook": "w_", "subagent": "p_", "api": "k_"}
#: How the owner's texts name a source: what its passes are on, and who makes its calls.
_SOURCE_TEXT = {
    "heartbeat": "the heartbeat of agent {name}",
    "hook": "webhook {name}",
    "subagent": "subagents of session {name}",
    "api": "API key {name}",
}


def source_ref(kind: str, value: str | None) -> str | None:
    """A source's ref: the kind and the host's value, hashed as `session_ref` is. None with no value."""
    if not isinstance(value, str) or not value.strip() or kind not in _SOURCE_PREFIX:
        return None
    digest = hashlib.sha256(f"{kind}\n{value.strip()}".encode()).hexdigest()[:12]
    return _SOURCE_PREFIX[kind] + digest


def source_of(kind: str, value: str | None, name: str | None = None) -> dict[str, str] | None:
    """The source of kind `kind` named by the host's `value` (`name` shown, default the value): `{kind, ref,
    name}`; None with no value."""
    ref = source_ref(kind, value)
    if ref is None:
        return None
    return {"kind": kind, "ref": ref, "name": str(name if name is not None else value).strip()}


def scope_ref(e: Any) -> str | None:
    """What a pass, denial or hold is bound to: its job's ref, else its source's ref, else None (exact
    arguments)."""
    if not isinstance(e, dict):
        return None
    src = e.get("source") if isinstance(e.get("source"), dict) else {}
    ref = e.get("job_ref") or e.get("source_ref") or src.get("ref")
    return ref if isinstance(ref, str) and ref else None


def source_text(kind: Any, name: Any) -> str:
    """A source as the owner's texts name it, with a name the host's settings chose quoted."""
    if kind not in _SOURCE_TEXT:
        return "an unattended run"
    if kind == "subagent":
        shown = _clean(name if name is not None else "?", 40)
    else:
        bare = re.sub(r"[\[\]()<>|@`]", "", str(name if name is not None else "?"))
        shown = json.dumps(_clean(bare, 60), ensure_ascii=False)
    return _SOURCE_TEXT[kind].format(name=shown)


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
    return risk <= held_risk and not set(later.get("warnings") or []) - set(
        held.get("warnings") or []
    )


def offers(
    job_id: str | None,
    level: str | None,
    named: bool,
    risk: float | None,
    block_at: float,
    acted: bool = False,
    source: bool = False,
) -> list[str]:
    """The answers a hold offers, in the notice's order. On a cron job: `allow` when the scanner lets the owner
    pass the call at all, then `allow later` (`allow` starts the job again now), or `allow now` when the held run had
    already acted (`allow` then waits for the next run); `allow always` when the scanner lets it pass for good and
    the call names its parties below the block line; and `deny`. On another run with a source (`source`): the same
    without `allow later` or `allow now` (nothing is started). Elsewhere only `allow` (bound to the exact call)."""
    if not job_id and not source:
        return [ALLOW] if level is not None else []
    out: list[str] = []
    if level is not None:
        out.append(ALLOW)
        if job_id:
            out.append(ALLOW_NOW if acted else ALLOW_LATER)
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


def _live_runs(data: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    out = []
    for r in data.get("runs") or []:
        at = read_time(r.get("expires_at")) if isinstance(r, dict) else None
        if at is not None and at > now:
            out.append(r)
    return out


def add(
    state_dir: Path,
    *,
    kind: str,
    uses: str,
    level: str | None,
    hold: dict[str, Any],
    who: dict[str, Any],
    now: datetime,
    run_bound: bool = False,
) -> dict[str, Any] | None:
    """Stores a pass (`kind` allow) or denial (`deny`) set from `hold`; returns the entry, or None when the file
    cannot be read. `uses`: `once` or `standing`. `run_bound`: a one-use pass for a run the plugin is about to start,
    with its record in `runs`. Called with the holds file locked."""
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
        # a source's one-use pass lasts as long as a hold may be answered; standing ones as long as a job's
        source = hold.get("source") if not hold.get("job_ref") else None
        source = source if isinstance(source, dict) and source.get("ref") else None
        ttl = PASS_TTL if hold.get("job_ref") or (source and uses != "once") else ARGS_TTL
        entry = {
            "id": pid,
            "kind": kind,
            "uses": uses,
            "level": level if kind == "allow" else None,
            "job_id": hold.get("job_id"),
            "job_ref": hold.get("job_ref"),
            "source_kind": source.get("kind") if source else None,
            "source_ref": source.get("ref") if source else None,
            "source_name": source.get("name") if source else None,
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
        data["runs"] = _live_runs(data, now)
        if run_bound:
            # an earlier started run of the job whose end was never seen must not capture this one
            for old in data["runs"]:
                if old.get("job_ref") == hold.get("job_ref") and not old.get("ended"):
                    _end(data, old)
            entry["run_bound"] = True
            data["runs"].append(
                {
                    "id": pid,
                    "hold_id": hold.get("id"),
                    "job_id": hold.get("job_id"),
                    "job_ref": hold.get("job_ref"),
                    "requested_at": _iso(now),
                    "not_run": hold.get("run_key"),
                    "run_id": None,
                    "run_key": None,
                    "passed": False,
                    "held": [],
                    "expires_at": entry["expires_at"],
                }
            )
            data["runs"] = data["runs"][-MAX_PASSES:]
        data["passes"].append(entry)
        data["passes"] = data["passes"][-MAX_PASSES:]
        store.save_passes(data)
        return entry


def pending_run(state_dir: Path, ref: str | None, now: datetime) -> bool:
    """Whether a run the plugin started for an answer on job `ref` has not been seen to end yet (asked for within
    `PENDING_RUN`): another answer must not start the job again meanwhile. An unreadable file says no."""
    data = Store(state_dir).load_passes()
    for r in _live_runs(data or {}, now):
        asked = read_time(r.get("requested_at"))
        if (
            r.get("job_ref") == ref
            and not r.get("ended")
            and asked is not None
            and now - asked < PENDING_RUN
        ):
            return True
    return False


def _change_run(state_dir: Path, pid: str, change: Any) -> dict[str, Any] | None:
    """Runs `change(data, record)` on the run record of pass `pid` under the lock and saves; returns a copy of the
    record, or None when there is none."""
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = store.load_passes()
        if data is None:
            return None
        rec = next(
            (r for r in data.get("runs") or [] if isinstance(r, dict) and r.get("id") == pid), None
        )
        if rec is None:
            return None
        change(data, rec)
        store.save_passes(data)
        return dict(rec)


def started(state_dir: Path, pid: str, run_id: str | None) -> None:
    """The run started for pass `pid`, with the host's id for it when the host gave one."""

    def change(_data: dict[str, Any], rec: dict[str, Any]) -> None:
        if run_id:
            rec["run_id"] = run_id

    _change_run(state_dir, pid, change)


def not_started(state_dir: Path, pid: str) -> None:
    """The run for pass `pid` could not be started: the pass is left for the job's next run, as `allow later`."""

    def change(data: dict[str, Any], rec: dict[str, Any]) -> None:
        data["runs"] = [r for r in data["runs"] if r is not rec]
        for p in data.get("passes") or []:
            if isinstance(p, dict) and p.get("id") == pid:
                p.pop("run_bound", None)

    _change_run(state_dir, pid, change)


def _after(started_at: datetime | None, rec: dict[str, Any]) -> bool:
    asked = read_time(rec.get("requested_at"))
    return started_at is None or asked is None or started_at >= asked - RUN_SLACK


def _is_run(rec: dict[str, Any], run_key: str | None, started_at: datetime | None) -> bool:
    """Whether the run `run_key` (started at `started_at`, None when unknown) is the one started for `rec`."""
    if rec.get("ended") or not run_key:
        return False
    if rec.get("run_key"):
        return bool(rec["run_key"] == run_key)
    if rec.get("run_id"):
        return bool(rec["run_id"] == run_key)
    return run_key != rec.get("not_run") and _after(started_at, rec)


def run_of(
    state_dir: Path,
    ref: str | None,
    run_key: str | None,
    started_at: datetime | None,
    now: datetime,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """(the record of the run the plugin started for an answer that this run of job `ref` is, now bound to it, or
    None; the records of earlier started runs of the job that ended without the plugin seeing their end, now ended).
    A file that cannot be read gives neither."""
    if ref is None or not run_key:
        return None, []
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = store.load_passes()
        if data is None:
            return None, []
        runs = _live_runs(data, now)
        changed = len(runs) != len(data.get("runs") or [])
        mine = next(
            (r for r in runs if r.get("job_ref") == ref and _is_run(r, run_key, started_at)),
            None,
        )
        if mine is not None and mine.get("run_key") != run_key:
            mine["run_key"] = run_key
            changed = True
        gone = [
            r
            for r in runs
            if r.get("job_ref") == ref
            and r is not mine
            and not r.get("ended")
            and r.get("run_key")
            and r["run_key"] != run_key
        ]
        for r in gone:
            _end(data, r)
            changed = True
        data["runs"] = runs
        if changed:
            store.save_passes(data)
        return (dict(mine) if mine is not None else None), [dict(r) for r in gone]


def note(state_dir: Path, pid: str, *, passed: bool = False, held: str | None = None) -> None:
    """Notes on the record of the run started for pass `pid` that the call went through, or a hold it made."""

    def change(_data: dict[str, Any], rec: dict[str, Any]) -> None:
        if passed:
            rec["passed"] = True
        if held and held not in rec.setdefault("held", []):
            rec["held"].append(held)

    _change_run(state_dir, pid, change)


def _end(data: dict[str, Any], rec: dict[str, Any]) -> None:
    """Marks a started run ended and drops its pass if the run did not use it."""
    rec["ended"] = True
    data["passes"] = [
        p
        for p in data.get("passes") or []
        if not (isinstance(p, dict) and p.get("id") == rec.get("id") and p.get("run_bound"))
    ]


def run_end(
    state_dir: Path,
    ref: str | None,
    run_key: str | None,
    started_at: datetime | None,
    now: datetime,
) -> dict[str, Any] | None:
    """The run `run_key` of job `ref` ended: when it is a run the plugin started for an answer, its record, now
    ended (its pass dropped if unused); else None."""
    if ref is None or not run_key:
        return None
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = store.load_passes()
        if data is None:
            return None
        runs = _live_runs(data, now)
        mine = next(
            (r for r in runs if r.get("job_ref") == ref and _is_run(r, run_key, started_at)), None
        )
        if mine is None:
            return None
        mine["run_key"] = run_key
        _end(data, mine)
        data["runs"] = runs
        store.save_passes(data)
        return dict(mine)


def outcome_text(rec: dict[str, Any], texts: dict[str, str]) -> str:
    """The owner's one line when a started run ended, from `texts` (the `outcomes` the shared fixture gives)."""
    held = [h for h in rec.get("held") or [] if isinstance(h, str)]
    kind = (
        ("passed_held" if held else "passed") if rec.get("passed") else "held" if held else "none"
    )
    return texts[kind].format(job=_clean(rec.get("job_id"), 40), hold=", ".join(held))


def check(
    state_dir: Path,
    ref: str | None,
    match: dict[str, Any],
    resp: dict[str, Any],
    now: datetime,
    in_run: str | None = None,
) -> dict[str, Any] | None:
    """The denial or pass that settles this held-to-be call, or None. `ref`: the call's job ref, else its source's
    ref (`scope_ref`), else None (only a pass bound to exact arguments can settle it). `in_run`: the pass whose
    started run this call is in (`run_of`); a run-bound pass serves no other run. A denial of the same job or source
    and action wins over any pass. A pass applies only to an eligible scan (`session_allow.eligible`) that the pass covers
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
            if scope_ref(p) == ref
            and isinstance(p.get("match"), dict)
            and p["match"].get("key") == match.get("key")
            # a pass bound to a run the plugin started serves that run only
            and (not p.get("run_bound") or (in_run is not None and p.get("id") == in_run))
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
        return (
            "usage: passes revoke <id>, with an id from the passes list (p- and 6 hex digits)",
            None,
        )
    store = Store(state_dir)
    with _LOCK, file_lock(_path(state_dir)):
        data = store.load_passes()
        if data is None:
            return (
                f"The passes file {_path(state_dir)} could not be read; fix or remove it first.",
                None,
            )
        kept = live(data, now)
        found = next((p for p in kept if p.get("id") == pid), None)
        if found is None:
            return (
                f"No pass or denial {_clean(pid, 40)}: the id is unknown, used up or expired.",
                None,
            )
        data["passes"] = [p for p in kept if p is not found]
        store.save_passes(data)
    what = "denial" if found["kind"] == "deny" else "pass"
    return (
        f"Revoked {what} {pid}.",
        {
            "op": "revoke",
            "id": pid,
            "pass_kind": found["kind"],
            "job_ref": found.get("job_ref"),
            **(
                {"source_kind": found.get("source_kind"), "source_ref": found["source_ref"]}
                if found.get("source_ref")
                else {}
            ),
        },
    )


def _job(p: dict[str, Any]) -> str:
    return f"job {_clean(p.get('job_id'), 40)}" if p.get("job_id") else "an unattended run"


def describe(p: dict[str, Any]) -> str:
    """One pass or denial, as the list and the dashboard show it; one bound to a source names its kind and name."""
    at = read_time(p.get("expires_at"))
    until = show(at) if at else "?"
    call = f"{_clean(p.get('tool') or '?', 60)}: {_clean(p.get('description') or '?', 120)}"
    if not p.get("job_ref") and p.get("source_ref"):
        src = source_text(p.get("source_kind"), p.get("source_name"))
        if p.get("kind") == "deny":
            return f"denied from {src} until {until}: {call}"
        if p.get("uses") == "once":
            return f"allowed once from {src}, until {until}: {call}"
        used = int(p.get("use_count") or 0)
        return f"allowed from {src} until {until}, used {used} time{'s' * (used != 1)}: {call}"
    if p.get("kind") == "deny":
        return f"denied on {_job(p)} until {until}: {call}"
    if p.get("uses") == "once" and p.get("run_bound"):
        return f"allowed once in the run of {_job(p)} started for it, until {until}: {call}"
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
