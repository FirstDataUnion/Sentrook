"""Holds: a review on an unattended run waits for the owner instead of becoming a block.

Nobody can answer a review prompt on a cron job, a subagent, a run with approvals off or YOLO, or a
process with no terminal. There the plugin holds the call:
- the call does not run, and the agent is told it is held for the owner's approval and must not be
  retried in this run (`HELD_TEXT`);
- the owner gets one notice on the home channel of the platform in `owner_channel`: which run, the
  tool and its target as a review prompt names them, the block category, the hold's id and the answers it
  offers. Hermes copies what `send_message` sends into the agent's own transcript, so the notice carries
  nothing a steered agent could use; the owner reads the risk, reasons and suggested grant with `why <id>`;
- the owner answers within 7 days (`answer`):
  - `allow <id>` (also `allow <id> later`): a one-use pass for this job and action, used by the job's next
    run (`passes`). The held call itself is not run again. Until the plugin can start the job's run itself,
    both forms wait for the next run; `_run_now` is where that will plug in.
  - `allow <id> always`: a standing pass for this job and action, for 30 days. Offered only when the scan's
    `owner_pass` is `always` and the call names its parties.
  - `deny <id>`: a standing denial for this job and action, for 30 days. A matching call is refused with a
    plain declined result and no notice.
  - `approve <id>` is the same as `allow <id>`, kept for one release.
  A hold on a run that is not a cron job has no job to bind to: it offers `allow` only, bound to the call's
  exact arguments. The notice lists only the answers the hold offers. A wider grant the scanner suggests is
  never set by an answer: `why` shows its command, for the owner to set by hand.
- A later hold of the same job and action, at no higher risk and with no new warning, updates the waiting
  hold (its count and when it was last seen) and sends no new notice.
- After 7 days the hold expires and nothing runs. Expiry is found and recorded when the holds are next
  changed (a new hold or an answer).

`holds.json` is version 2. Its entries keep no raw arguments: the match key is a hash (`passes.match_of`).
Holds from before (no `v`) stay answerable as before until they expire: `allow` or `approve` sets the
suggested grant (if any), and nothing else applies to them.

Hermes's own background skill and memory saves are held without an entry here (`skill_review`): approving
could not make the save.

A block (at the block line, or one the scanner enforces) is never held, except a retry of a review nobody
answered that the scanner caps at review (`decision.unattended_view`). Attended runs are unchanged: a review there
is still a review prompt.

The traffic log gets the scan with decision `held` and, later, a `resolution` record with resolution
`hold_allowed`, `hold_allowed_always`, `hold_denied` (`hold_approved` for an older hold) or `hold_expired`,
joined by `request_id` as review answers are; a call a pass or denial settles is logged with decision
`allowed_by_pass` or `denied_by_owner`. Holds are kept in
`<hermes home>/sentrook/holds.json`; the OpenClaw plugin keeps the same file and prints the same
notice text.

The notice goes out with Hermes's own `hermes send` command, run as a child process through Hermes's `hermes`
launcher (`send_route`, `_hermes_launcher`). Hermes 0.23
registers no `send_message` tool in any process, the gateway included, so `ctx.dispatch_tool("send_message", ...)`
answers "Unknown tool"; `hermes send` calls the same sender directly and works from any process (the gateway, the
desktop app's `hermes serve`, the command line, cron). On a Hermes that has no `hermes send` but registers a
`send_message` tool, the notice goes through `ctx.dispatch_tool` instead (it does not run tool hooks either, so the
plugin never scans its own notice). With neither, the notice is recorded unsent with the reason, and status, verify
and the startup log say so. Hermes attaches a file that `MEDIA:<path>` names in the text, so every notice is
`defuse`d first.

Either way the send runs on a worker thread with an empty context: a cron run's own delivery target is bound to the
run's context, and Hermes skips a send to that target from inside the run, which would swallow the notice when the
job delivers to the home channel. The child process gets no `HERMES_CRON_AUTO_DELIVER_*` variables either, the
other place Hermes looks for that target. It is pinned to this process's Hermes home, so a profile made sticky with
`hermes profile use` cannot change where the notice goes; a turn this process serves for another profile's home is
not sent with it (`send_route`).
"""

from __future__ import annotations

import contextvars
import importlib.util
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import grants, passes
from .decision import BLOCK_CATEGORIES, block_category, describe
from .store import Store, file_lock, read_time

logger = logging.getLogger("sentrook")

HOLD_TTL = timedelta(days=7)
#: How long a hold from before version 2 could be answered.
V1_HOLD_TTL = timedelta(hours=24)
GRANT_TTL = timedelta(days=30)
#: The held calls a repeated hold remembers, for setting their history once it is answered.
MAX_HELD = 20
MAX_HOLDS = 200
_ID = re.compile(r"h-[0-9a-f]{6}")
#: Serialises read-modify-write of the file within this process; `file_lock` does across processes.
_LOCK = threading.Lock()

HELD_TEXT = (
    "Sentrook held this tool call for the owner's approval, so it did not run. Do not retry this "
    "call in this run."
)

#: (subcommand) -> the command as the owner types it, e.g. "/sentrook approve".
Cmd = Callable[[str], str]
#: Writes one record to the traffic log.
Record = Callable[[dict[str, Any]], None]


def grant_hint(resp: dict[str, Any], review_at: float | None = None) -> dict[str, Any] | None:
    """The grant the scan response suggests for this call, if any: the first of its `grant_hints` that the
    grant command would accept and (with `review_at`) that brings the call below this plugin's review line.

    Grant hints are optional: a response without one makes a hold that approving sets nothing for. A hold
    stores what this returns, and approval reads it again with `grants.hint_grant`, which refuses anything
    that is not a plain grant."""
    found = grants.response_hints(resp, review_at)
    return found[0] if found else None


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _show(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _clean(s: Any, cap: int = 200) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(s))[:cap]


#: Link, mention and code markup in chat formats (Discord and Telegram `[text](url)`, Slack
#: `<url|text>`, `@everyone`, backticks): taken out of every notice field the agent can influence.
_MARKUP = re.compile(r"[\[\]()<>|@`]")


def inert(s: Any, cap: int) -> str:
    """`s` with chat markup taken out and non-printable characters replaced, at most `cap` long."""
    return _clean(_MARKUP.sub("", str(s)), cap)


# ---- the text ---------------------------------------------------------------------------------------


def where_text(
    run: str, session_ref: str, job_id: str | None = None, job_name: str | None = None
) -> str:
    """Which run a hold belongs to: a cron job by its id, with its name quoted and labelled as the
    job's name (whoever made the job chose it, possibly the agent, so it must read as a name, never as
    an instruction), else the kind of run; then the session."""
    if job_id:
        name = (
            f", job name {json.dumps(inert(job_name, 60), ensure_ascii=False)}" if job_name else ""
        )
        return f"cron job {inert(job_id, 40)}{name}, session {session_ref}"
    return f"{run}, session {session_ref}"


#: The notice's line for each answer a hold offers; `{c}` is the command, `{id}` the hold's id.
_OFFER_LINES = {
    passes.ALLOW: "- let this call through once, on the job's next run: {c} {id}",
    passes.ALLOW_ALWAYS: "- let this job make this call for 30 days: {c} {id} always",
    passes.DENY: "- refuse it on this job for 30 days, with no more notices: {c} {id}",
}
#: A hold that is not on a cron job: `allow` is bound to the exact call.
_EXACT_LINE = "- let this exact call through once, within 7 days: {c} {id}"


def notice_text(
    resp: dict[str, Any],
    tool: str,
    where: str,
    hold_id: str,
    offers: list[str],
    cmd: Cmd,
    on_job: bool = True,
) -> str:
    """The owner's notice. It may be copied into the agent's own transcript (Hermes keeps what
    `send_message` sends), so it carries only what a steered agent cannot use: that a call was held,
    which run, the tool and its target as a review prompt names them, the block category, and the ids
    and the commands of the answers this hold offers (`offers`, from `passes.offers`). The risk, reason
    codes, scores and entities are for the owner, through `why`. `cmd`: a verb (allow, deny, why) -> the
    command as the owner types it."""
    lines = [
        "Sentrook held a tool call on an unattended run; it did not run.",
        f"Run: {_clean(where, 200)}",
        f"Tool: {inert(tool, 80)}: {inert(describe(resp, tool), 160)}",
        f"Held because {BLOCK_CATEGORIES[block_category(resp)]}.",
    ]
    if offers:
        lines.append("Reply within 7 days:")
        for verb in offers:
            line = _EXACT_LINE if verb == passes.ALLOW and not on_job else _OFFER_LINES[verb]
            lines.append(line.format(c=cmd("deny" if verb == passes.DENY else "allow"), id=hold_id))
    else:
        lines.append("Sentrook offers no way to let this call through.")
    lines.append(f"For the reasons: {cmd('why')} {hold_id}")
    return "\n".join(lines)


# ---- the file ---------------------------------------------------------------------------------------


def _live(h: Any, now: datetime) -> bool:
    if not isinstance(h, dict):
        return False
    at = read_time(h.get("expires_at"))
    return at is not None and at > now


def _sweep(data: dict[str, Any], now: datetime, record: Record) -> list[dict[str, Any]]:
    """Drops the expired holds from `data` (unreadable entries too) and records each expiry."""
    keep, gone = [], []
    for h in data["holds"]:
        (keep if _live(h, now) else gone).append(h)
    data["holds"] = keep
    for h in gone:
        if not isinstance(h, dict):
            continue
        rids = [x.get("request_id") for x in h.get("held") or [] if isinstance(x, dict)]
        for rid in rids or [h.get("request_id")]:
            if isinstance(rid, str):
                record(
                    {
                        "kind": "resolution",
                        "request_id": rid,
                        "resolution": "hold_expired",
                        "decision": "held",
                        "hold_id": h.get("id"),
                    }
                )
    return [h for h in gone if isinstance(h, dict)]


def sweep(state_dir: Path, now: datetime, record: Record) -> None:
    """Records and drops every expired hold; a file that cannot be read is left alone."""
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return
        if _sweep(data, now, record):
            store.save_holds(data)


def _repeat_of(
    data: dict[str, Any], job_ref: str | None, match: dict[str, Any]
) -> dict[str, Any] | None:
    """The waiting hold a new hold of the same job and action repeats: same job, same match key, at no higher
    risk and with no new warning (`passes.covers`). Only holds on a cron job repeat."""
    if job_ref is None:
        return None
    return next(
        (
            h
            for h in data["holds"]
            if isinstance(h, dict)
            and h.get("v") == 2
            and h.get("job_ref") == job_ref
            and passes.covers(h.get("match") or {}, match)
        ),
        None,
    )


def create(
    state_dir: Path,
    *,
    request_id: str,
    session_ref: str,
    tool: str,
    where: str,
    hint: dict[str, Any] | None,
    notice: dict[str, Any],
    now: datetime,
    record: Record,
    sid: str = "",
    job_id: str | None = None,
    match: dict[str, Any] | None = None,
    level: str | None = None,
    offers: list[str] | None = None,
    description: str = "",
) -> tuple[str | None, bool]:
    """Stores a new hold, or counts a repeat of a waiting one (`_repeat_of`); returns its id (None when the file
    cannot be read: the call is still held, but cannot be answered) and whether it was a repeat (no new notice)."""
    store = Store(state_dir)
    ref = passes.job_ref(job_id)
    match = match or {}
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return None, False
        _sweep(data, now, record)
        data["version"] = 2
        same = _repeat_of(data, ref, match)
        if same is not None:
            same["count"] = int(same.get("count") or 1) + 1
            same["last_seen_at"] = _iso(now)
            same["held"] = [*(same.get("held") or []), {"sid": sid, "request_id": request_id}][
                -MAX_HELD:
            ]
            store.save_holds(data)
            return str(same["id"]), True
        taken = {h.get("id") for h in data["holds"] if isinstance(h, dict)}
        hid = f"h-{secrets.token_hex(3)}"
        while hid in taken:
            hid = f"h-{secrets.token_hex(3)}"
        data["holds"].append(
            {
                "v": 2,
                "id": hid,
                "request_id": request_id,
                "session_ref": session_ref,
                "held": [{"sid": sid, "request_id": request_id}],
                "tool": tool,
                "description": description,
                "where": where,
                "job_id": job_id,
                "job_ref": ref,
                "match": match,
                "level": level,
                "offers": list(offers or []),
                "held_at": _iso(now),
                "last_seen_at": _iso(now),
                "count": 1,
                "expires_at": _iso(now + HOLD_TTL),
                "hint": hint,
                "notice": notice,
            }
        )
        data["holds"] = data["holds"][-MAX_HOLDS:]
        store.save_holds(data)
        return hid, False


def waiting(state_dir: Path, now: datetime) -> int | None:
    """How many holds wait for the owner; None when the file cannot be read."""
    data = Store(state_dir).load_holds()
    return None if data is None else sum(1 for h in data["holds"] if _live(h, now))


def repeated(state_dir: Path, now: datetime) -> list[dict[str, Any]]:
    """The waiting holds held more than once, for status."""
    data = Store(state_dir).load_holds() or {"holds": []}
    return [h for h in data["holds"] if _live(h, now) and int(h.get("count") or 1) > 1]


def _approve_v1(
    store: Store,
    state_dir: Path,
    data: dict[str, Any],
    found: dict[str, Any],
    gone: list[dict[str, Any]],
    hid: str,
    who: dict[str, Any],
    now: datetime,
    cmd: Cmd,
    record: Record,
) -> str:
    """A hold from before version 2, answered as `approve` answered it: sets the suggested grant (if any)."""
    change: dict[str, Any] | None = None
    reply = ""
    grant = grants.hint_grant(found.get("hint"))
    if grant is not None:
        try:
            reply, change = grants.add_suggested(state_dir, grant, who, now, GRANT_TTL, hid)
        except Exception as exc:  # noqa: BLE001 - reported, and the hold is kept
            reply, change = f"The grants file could not be written ({_clean(exc, 160)}).", None
        if change is None:
            if gone:
                store.save_holds(data)
            return f"Not approved: {reply} {hid} is still waiting; approve it again once that is fixed."
    if change is not None and not change.get("existing"):
        record({"kind": "grants", **change, "by": who})
    data["holds"].remove(found)
    try:
        store.save_holds(data)
    except Exception as exc:  # noqa: BLE001 - the grant stands; a second approve finishes
        return (
            f"Not finished: {reply} The hold could not be marked answered ({_clean(exc, 160)}); "
            f"approve {hid} again to finish."
        )
    done = {
        "kind": "resolution",
        "request_id": found.get("request_id"),
        "resolution": "hold_approved",
        "decision": "held",
        "hold_id": hid,
        "by": who,
    }
    if change is None:
        record(done)
        return (
            f"Approved {hid}. Sentrook suggested no grant for this call, so nothing was set: the next "
            f"run is scanned as before. To let it pass, add a grant with {cmd('grant')}. The held call "
            "is not run again."
        )
    record({**done, "grant_id": change["entry"]["id"]})
    return f"Approved {hid}. {reply} The held call is not run again; the next run is scanned with this grant."


def _run_now(found: dict[str, Any]) -> str | None:
    """Starts the held call's job again now, for `allow`; returns None when it did, else why not (then the pass
    waits for the job's next run). This plugin does not start runs yet: every `allow` waits."""
    return "not available"


def _refusal(found: dict[str, Any], want: str, hid: str, cmd: Cmd) -> str:
    """Why a hold does not offer the answer `want`; the hold keeps waiting."""
    on_job = bool(found.get("job_ref"))
    level = found.get("level")
    why = f"{cmd('why')} {hid} shows the reasons"
    if want == passes.DENY:
        return (
            f"Not set: {hid} is not on a cron job, so there is no job to refuse it for. Leave it and it "
            "expires; the call never runs."
        )
    if level is None:
        alt = (
            f"{cmd('deny')} {hid} refuses it on this job with no more notices; "
            if on_job
            else "leave it and it expires; "
        )
        return f"Not allowed: Sentrook does not offer to let this call through. {alt}{why}."
    if not on_job:
        return (
            f"Not set: {hid} is not on a cron job, so there is no job to let this call through for good. "
            f"{cmd('allow')} {hid} lets this exact call through once."
        )
    if level != "always":
        return (
            "Not set: Sentrook offers to let this call through on every run only when it judges that safe, "
            f"and for this one it offers it once. {cmd('allow')} {hid} lets it through on the job's next run."
        )
    match = found.get("match") or {}
    if not match.get("named"):
        return (
            "Not set: this call names nothing a standing pass could be bound to, so only a one-time pass "
            f"bound to its exact arguments is offered: {cmd('allow')} {hid}."
        )
    return (
        "Not set: this call scored at the block line, so it can only be let through once: "
        f"{cmd('allow')} {hid}."
    )


def _settle_history(state_dir: Path, held: list[Any], decision: str) -> None:
    """Sets the held calls' entries in their sessions' history to `decision`, so a retry in the same session is
    scored as one after the owner's answer, not after a review nobody answered."""
    store = Store(state_dir)
    for h in held:
        if not isinstance(h, dict) or not h.get("sid") or not isinstance(h.get("request_id"), str):
            continue
        sid = str(h["sid"])
        try:
            with store.session_lock(sid):
                sess = store.load_session(sid)
                hit = [
                    e
                    for e in sess.get("history") or []
                    if isinstance(e, dict) and e.get("request_id") == h["request_id"]
                ]
                if not hit:
                    continue
                for e in hit:
                    e["decision"] = decision
                store.save_session(sid, sess, max(len(sess["history"]), 1))
        except Exception as exc:  # noqa: BLE001 - the answer stands
            logger.warning("sentrook could not update a held call's history: %s", exc)


def _parse(verb: str, rest: str) -> tuple[str, str] | None:
    """(hold id, answer) from `allow <id> [later|always]`, `approve <id>` or `deny <id>`; None when malformed."""
    words = rest.split()
    if not words or not _ID.fullmatch(words[0]):
        return None
    if verb == "deny":
        return (words[0], passes.DENY) if len(words) == 1 else None
    mode = words[1].lower() if len(words) > 1 else ""
    if len(words) > 2 or mode not in ("", "later", "once", "always"):
        return None
    return words[0], passes.ALLOW_ALWAYS if mode == "always" else passes.ALLOW


def answer(
    state_dir: Path,
    verb: str,
    rest: str,
    who: dict[str, Any],
    now: datetime,
    cmd: Cmd,
    record: Record,
) -> str:
    """`allow <id> [later|always]`, `approve <id>` or `deny <id>`: sets the pass or denial the hold offers,
    removes the hold and records the answer; the reply says what was set and how to undo it."""
    parsed = _parse(verb, rest)
    if parsed is None:
        form = {
            "deny": f"{cmd('deny')} <id>",
            "approve": f"{cmd('approve')} <id>",
        }.get(verb, f"{cmd('allow')} <id> [later|always]")
        return f"usage: {form}, with the id from Sentrook's notice (h- and 6 hex digits)"
    hid, want = parsed
    store = Store(state_dir)
    entry: dict[str, Any] | None = None
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return f"The holds file {state_dir / 'holds.json'} could not be read; fix or remove it first."
        gone = _sweep(data, now, record)
        found = next((h for h in data["holds"] if h.get("id") == hid), None)
        if found is None:
            if gone:
                store.save_holds(data)
            old = next((h for h in gone if h.get("id") == hid), None)
            if old is not None:
                days = "7 days" if old.get("v") == 2 else "24 hours"
                return (
                    f"Held call {hid} expired: a hold can be answered for {days}. Nothing was set; the "
                    "next run is scanned as before."
                )
            return (
                f"No held call {_clean(hid, 40)}: the id is unknown, already answered or expired."
            )
        if found.get("v") != 2:
            if want != passes.ALLOW:
                if gone:
                    store.save_holds(data)
                return (
                    f"Held call {hid} was made by an earlier version of the plugin: only {cmd('allow')} {hid} "
                    "answers it, as approve did (it sets the grant Sentrook suggested, if any)."
                )
            return _approve_v1(store, state_dir, data, found, gone, hid, who, now, cmd, record)
        if want not in (found.get("offers") or []):
            if gone:
                store.save_holds(data)
            return _refusal(found, want, hid, cmd)
        # The hold is marked answered first, so a failure never leaves two passes for one answer.
        data["holds"].remove(found)
        try:
            store.save_holds(data)
        except Exception as exc:  # noqa: BLE001 - nothing set; the hold waits
            return f"Not set: the holds file could not be written ({_clean(exc, 160)}); {hid} is still waiting."
        failed = ""
        try:
            entry = passes.add(
                state_dir,
                kind="deny" if want == passes.DENY else "allow",
                uses="once" if want == passes.ALLOW else "standing",
                level="always" if want == passes.ALLOW_ALWAYS else "once",
                hold=found,
                who=who,
                now=now,
            )
        except Exception as exc:  # noqa: BLE001 - the hold goes back
            failed = _clean(exc, 160)
        if entry is None:
            data["holds"].append(found)
            try:
                store.save_holds(data)
            except Exception:  # noqa: BLE001 - reported below
                return f"Not set: the passes file could not be written ({failed or 'unreadable'}), and {hid} could not be put back."
            return f"Not set: the passes file could not be written ({failed or 'unreadable'}); {hid} is still waiting."
    resolution = {
        passes.ALLOW: "hold_allowed",
        passes.ALLOW_ALWAYS: "hold_allowed_always",
        passes.DENY: "hold_denied",
    }[want]
    held = found.get("held") or [{"sid": "", "request_id": found.get("request_id")}]
    record(
        {
            "kind": "passes",
            "op": "add",
            "id": entry["id"],
            "pass_kind": entry["kind"],
            "uses": entry["uses"],
            "job_ref": entry.get("job_ref"),
            "hold_id": hid,
            "expires_at": entry["expires_at"],
            "by": who,
        }
    )
    for h in held:
        if isinstance(h, dict) and isinstance(h.get("request_id"), str):
            record(
                {
                    "kind": "resolution",
                    "request_id": h["request_id"],
                    "resolution": resolution,
                    "decision": "held",
                    "hold_id": hid,
                    "pass_id": entry["id"],
                    "by": who,
                }
            )
    _settle_history(
        state_dir, held, "denied_by_user" if want == passes.DENY else "approved_by_user"
    )
    until = read_time(entry["expires_at"])
    shown = passes.show(until) if until else "?"
    job = f"Job {_clean(found.get('job_id'), 40)}"
    undo = f"Undo: {cmd('passes')} revoke {entry['id']}."
    if want == passes.DENY:
        return f"{job} will not make this call until {shown}; you won't be told again. {undo}"
    if want == passes.ALLOW_ALWAYS:
        return f"{job} may make this call until {shown}. {undo}"
    if not found.get("job_ref"):
        return (
            f"The next identical call from an unattended run may go through once, until {shown}. The held "
            f"call itself is not run again. {undo}"
        )
    _run_now(found)  # the seam for starting the job now; until then the pass waits for the next run
    return (
        f"{job}'s next run may make this call once. The held call itself is not run again. {undo}"
    )


def find(state_dir: Path, hold_id: str) -> dict[str, Any] | None:
    """The hold with this id while it waits; None when unknown, answered, expired or unreadable."""
    data = Store(state_dir).load_holds()
    return next(
        (
            h
            for h in (data or {}).get("holds") or []
            if isinstance(h, dict) and h.get("id") == hold_id
        ),
        None,
    )


def is_id(text: str) -> bool:
    return bool(_ID.fullmatch(text))


def why_text(
    state_dir: Path, log: Path, hold_id: str, now: datetime, cmd: Cmd = "/sentrook {}".format
) -> str:
    """`why <hold id>`: the held call's scan as `why` shows any scan, then the hold itself."""
    from .history import format_why, recent_scans, records_backward

    rid = next(
        (
            r.get("request_id")
            for r in records_backward(log)
            if r.get("kind") == "scan"
            and isinstance(r.get("hold"), dict)
            and r["hold"].get("id") == hold_id
        ),
        None,
    )
    found = recent_scans(log, 1, lambda x: x == rid) if isinstance(rid, str) else []
    if not found:
        return f"No held call {hold_id} in the recent traffic log."
    lines = [format_why(*found[0])]
    waiting = find(state_dir, hold_id)
    if waiting is not None:
        at = read_time(waiting.get("expires_at"))
        lines.append(f"hold: waiting, until {_show(at) if at else '?'}")
        count = int(waiting.get("count") or 1)
        if count > 1:
            lines.append(f"held {count} times since {_clean(waiting.get('held_at'), 20)}")
        grant = grants.hint_grant(waiting.get("hint"))
        trig = ((found[0][0].get("planir") or {}).get("trigger") or {}) if found else {}
        if waiting.get("v") != 2:
            lines.append(
                "suggested grant: "
                + (f"{grants.describe_grant(grant)} (persistent, 30 days)" if grant else "none")
            )
        else:
            offered = waiting.get("offers") or []
            lines.append("answers: " + (", ".join(offered) if offered else "none offered"))
            if grant:
                # an answer never sets a wider grant: the owner may set it by hand
                lines.append(
                    f"suggested grant: {grants.describe_grant(grant)}; to set it yourself: "
                    f"{grants.grant_command(grant, cmd)}"
                )
        if grant and trig.get("kind") in grants.HOST_TASK_KINDS:
            # nobody asked for this in a chat: say which run did, before the owner approves it
            lines.append(
                grants.HOLD_CONTEXT.format(
                    kind=trig["kind"], where=_clean(waiting.get("where") or "?", 200)
                )
            )
    else:
        lines.append("hold: answered or expired")
    return "\n".join(lines)


# ---- where the notice goes ----------------------------------------------------------------------------


def home_platforms() -> list[str]:
    """The connected platforms with a home channel, as Hermes's gateway config names them; empty when
    the config cannot be read."""
    try:
        from gateway.config import load_gateway_config

        config = load_gateway_config()
        out = []
        for p in config.get_connected_platforms():
            if config.get_home_channel(p):
                out.append(str(getattr(p, "value", p)))
        return sorted(out)
    except Exception as exc:  # noqa: BLE001 - no gateway config: no home channel
        logger.debug("home channels not readable: %s", exc)
        return []


NO_OWNER_CHANNEL = (
    "owner_channel is not set; set it to the platform whose home channel gets held-call notices"
)


def notice_target(owner_channel: str, homes: list[str]) -> tuple[str | None, str]:
    """(platform whose home channel gets the notice, or None; why there is none). The owner names the
    platform: a home channel is not assumed to be the owner's just because it is the only one."""
    if not owner_channel:
        return None, NO_OWNER_CHANNEL
    if owner_channel in homes:
        return owner_channel, ""
    return None, f"owner_channel {owner_channel} has no home channel"


#: How a notice is sent (`send_route`).
HERMES_SEND = "hermes send"
SEND_TOOL = "send_message tool"
#: Seconds `hermes send` may take: Hermes's command line starts slowly, and a platform may be slow to answer.
SEND_TIMEOUT = 60.0
#: Where Hermes finds a cron run's own delivery target outside the run's context (see the module note).
_CRON_DELIVERY_ENV = "HERMES_CRON_AUTO_DELIVER_"


def _hermes_launcher() -> str | None:
    """Hermes's own `hermes` command for this install, which `hermes send` runs with; None without one.

    Hermes starts its own processes with its checkout on `sys.path` (`python -I -c ...`), not with an installed
    `hermes_cli`, so `python -m hermes_cli.main` fails outside the checkout (the desktop backend runs in the owner's
    project folder). The launcher sets that up itself: `.hermes/bin/hermes` in the checkout (Hermes's installer), else
    the `hermes` script beside this interpreter (a pip or Docker install), else `hermes` on PATH."""
    try:
        if importlib.util.find_spec("hermes_cli.send_cmd") is None:
            return None
        spec = importlib.util.find_spec("hermes_cli")
        root = Path(spec.origin).resolve().parents[1] if spec and spec.origin else None
    except Exception:  # noqa: BLE001 - not importable: no hermes send
        return None
    here = [root / ".hermes" / "bin" / "hermes"] if root else []
    if sys.executable:
        here.append(Path(sys.executable).parent / "hermes")
    for path in here:
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return shutil.which("hermes")


def _hermes_send_available() -> bool:
    return _hermes_launcher() is not None


def _send_tool_registered() -> bool:
    """Whether Hermes's tool registry in this process has a `send_message` tool (Hermes 0.23 has none)."""
    try:
        from tools.registry import registry

        return registry.get_entry("send_message") is not None
    except Exception:  # noqa: BLE001 - no registry: no tool
        return False


def process_name() -> str:
    """This process as the owner would start it, e.g. `hermes serve`, for the reports."""
    argv = [a for a in sys.argv[:2] if a]
    if not argv:
        return f"process {os.getpid()}"
    name = Path(argv[0]).name
    # Hermes's launcher runs `python -I -c ...` (argv[0] "-c"); `python -m hermes_cli.main` gives main.py
    if name.startswith("-") or name.endswith(".py"):
        name = "hermes"
    return _clean(" ".join([name, *argv[1:]]), 60)


def _other_home() -> str | None:
    """The current turn's Hermes home when it is not this process's own (a Hermes serving several profiles, which
    scopes each turn to its own profile); None otherwise, or when Hermes cannot say."""
    try:
        from hermes_constants import get_hermes_home, get_process_hermes_home

        turn, own = os.path.realpath(get_hermes_home()), os.path.realpath(get_process_hermes_home())
    except Exception:  # noqa: BLE001 - an older or stand-in Hermes: one home per process
        return None
    return turn if turn != own else None


def send_route(can_dispatch: bool = True) -> tuple[str | None, str]:
    """(how this process sends the owner's notices for the current turn, `HERMES_SEND` or `SEND_TOOL`, or None; why
    there is none). `can_dispatch`: the plugin context has `dispatch_tool`.

    `hermes send` runs with this process's own environment, which holds its own profile's credentials, so it is not
    used for a turn another profile's home is serving: the notice could go out with the wrong platform account."""
    other = _other_home()
    launcher = _hermes_launcher()
    if launcher is not None and other is None:
        return HERMES_SEND, ""
    if can_dispatch and _send_tool_registered():
        return SEND_TOOL, ""
    if launcher is not None:
        return None, (
            f"{process_name()} is serving this turn for the Hermes home {_clean(other, 120)}, not its own, and "
            "hermes send would send with its own profile's credentials"
        )
    return None, (
        f"{process_name()} cannot send them: Hermes's hermes send command is not available to it and it has no "
        "send_message tool"
    )


def owner_target(owner_channel: str, can_dispatch: bool = True) -> tuple[str | None, str]:
    """`notice_target` for this process: also None, with the reason, when it has no way to send (`send_route`)."""
    target, why = notice_target(owner_channel, home_platforms())
    if target:
        route, no_route = send_route(can_dispatch)
        if route is None:
            return None, no_route
    return target, why


def status_line(state_dir: Path, owner_channel: str, now: datetime) -> str:
    target, why = owner_target(owner_channel)
    count = waiting(state_dir, now)
    held = "holds file unreadable" if count is None else f"{count} waiting"
    again = repeated(state_dir, now) if count else []
    if again:
        most = max(again, key=lambda h: int(h.get("count") or 1))
        held += (
            f" ({most.get('id')} held {int(most.get('count') or 1)} times since "
            f"{_clean(most.get('held_at'), 20)})"
        )
    where = f"notices to the {target} home channel" if target else f"notices not sent ({why})"
    return f"{held}; {where}"


#: Notice threads still running, so a test (or a short-lived process) can wait for them.
_threads: list[threading.Thread] = []


#: What Hermes's sender would act on in a message: a `MEDIA:` tag (matched in any case, as Hermes matches it) attaches
#: the file it names, and these flags change how.
_MEDIA = re.compile(r"MEDIA(?=:)", re.IGNORECASE)
_DELIVERY_FLAGS = ("[[as_document]]", "[[audio_as_voice]]")


def defuse(text: str) -> str:
    """`text` with nothing Hermes's sender would act on: each `MEDIA:` (any case) becomes `MEDIA :`, which Hermes reads
    as text, and the delivery flags are taken out. A notice names a call's target, which the agent chooses."""
    while any(flag in text for flag in _DELIVERY_FLAGS):
        for flag in _DELIVERY_FLAGS:
            text = text.replace(flag, "")
    return _MEDIA.sub(lambda m: m.group(0) + " ", text)


def _delivered(out: Any) -> bool:
    return (
        isinstance(out, dict)
        and not out.get("error")
        and not out.get("skipped")
        and bool(out.get("success"))
    )


def _answer(stdout: str) -> Any:
    """The answer `hermes send --json` prints, whatever Hermes prints around it: the first JSON object on a line of its
    own that says `success`, `error` or `skipped`; None when there is none."""
    decoder = json.JSONDecoder()
    for m in re.finditer(r"(?m)^\{", stdout):
        try:
            found = decoder.raw_decode(stdout, m.start())[0]
        except ValueError:
            continue
        if isinstance(found, dict) and found.keys() & {"success", "error", "skipped"}:
            return found
    return None


def _with_hermes_send(platform: str, text: str) -> tuple[bool, str]:
    """(delivered, what Hermes said) for one `hermes send` of `text` to `platform`'s home channel."""
    launcher = _hermes_launcher()
    if launcher is None:
        return False, "Hermes's hermes command is not available"
    env = {k: v for k, v in os.environ.items() if not k.startswith(_CRON_DELIVERY_ENV)}
    # Hermes's own pin for its children: never switch to the profile `hermes profile use` made sticky.
    env["HERMES_GATEWAY_PROFILE_PIN"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"  # the text goes on stdin as UTF-8 whatever the locale
    argv = [launcher, "send", "--to", platform, "--file", "-", "--json"]
    try:
        proc = subprocess.run(
            argv,
            input=text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=SEND_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"no answer in {SEND_TIMEOUT:g} seconds"
    except Exception as exc:  # noqa: BLE001 - could not start it
        return False, _clean(exc, 300)
    out = _answer(proc.stdout or "")
    if proc.returncode == 0 and _delivered(out):
        return True, ""
    said = out if out is not None else (proc.stderr or proc.stdout or "").strip()[-300:]
    return False, f"exit {proc.returncode}: {_clean(said, 300)}"


def _with_send_tool(ctx: Any, platform: str, text: str) -> tuple[bool, str]:
    raw = ctx.dispatch_tool("send_message", {"action": "send", "target": platform, "message": text})
    out = json.loads(raw) if isinstance(raw, str) else raw
    return (True, "") if _delivered(out) else (False, _clean(raw, 300))


def _send(
    ctx: Any,
    route: str | None,
    platform: str,
    text: str,
    on_fail: Callable[[], None] | None = None,
) -> None:
    delivered, said = False, "no way to send it from this process"
    try:
        if route == HERMES_SEND:
            delivered, said = _with_hermes_send(platform, defuse(text))
        elif route == SEND_TOOL:
            delivered, said = _with_send_tool(ctx, platform, defuse(text))
        if not delivered:
            logger.warning(
                "sentrook hold notice to %s not delivered with %s: %s",
                platform,
                route or "no route",
                said,
            )
    except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
        logger.warning("sentrook hold notice to %s failed with %s: %s", platform, route, exc)
    if not delivered and on_fail is not None:
        try:
            on_fail()
        except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
            logger.warning("sentrook could not undo an undelivered notice: %s", exc)


def deliver(ctx: Any, platform: str, text: str, on_fail: Callable[[], None] | None = None) -> None:
    """Sends `text` to `platform`'s home channel from a worker thread with an empty context, with `hermes send` or
    the send_message tool as `send_route` chooses for the current turn (see the module note). The thread is not a daemon, so a `hermes cron run` process waits
    for it. `on_fail` runs on that thread when the notice was not delivered."""
    _threads[:] = [t for t in _threads if t.is_alive()]
    t = threading.Thread(
        target=contextvars.Context().run,
        # the route is chosen here, in the turn's context, which the thread does not have
        args=(
            _send,
            ctx,
            send_route(callable(getattr(ctx, "dispatch_tool", None)))[0],
            platform,
            text,
            on_fail,
        ),
        name="sentrook-hold-notice",
        daemon=False,
    )
    _threads.append(t)
    t.start()


def wait_for_notices(timeout: float = 10.0) -> None:
    for t in list(_threads):
        t.join(timeout)
