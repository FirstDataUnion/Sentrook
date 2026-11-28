"""Holds: a review on an unattended run waits for the owner instead of becoming a block.

Nobody can answer a review prompt on a cron job, a subagent, a run with approvals off or YOLO, or a
process with no terminal. There the plugin holds the call:
- the call does not run, and the agent is told it is held for the owner's approval and must not be
  retried in this run (`HELD_TEXT`);
- the owner gets one notice, in the chat set by `/sentrook notify here` or else on the home channel of the
  platform set by `notify <platform>` or `owner_channel` (see `owner_settings`); with none of them set, in the chat the
  cron job delivers to, else the owner's direct message where Hermes can address one (`fallback_target`), never a
  home channel or group the job does not deliver to: which run, the
  tool and its target as a review prompt names them, the block category, the hold's id and the answers it
  offers. Hermes copies what `send_message` sends into the agent's own transcript, so the notice carries
  nothing a steered agent could use; the owner reads the risk, reasons and suggested grant with `why <id>`;
- the owner answers within 7 days (`answer`):
  - `allow <id>`: a one-use pass for this job and action, bound to a new run of the job, which the plugin starts
    now (`run_now`). The held call itself is never run by the plugin: the job runs again, and the same call goes
    through once in that run. When the run ends, the owner gets one line saying what happened (`passes.outcome_text`).
    Nothing is started, and the pass waits for the job's next run, when the job cannot be started now (the reply says
    why: observe mode, the job gone, finished, paused, running or changed since the hold), or when the held run had
    already sent or written something before the held call (`acted`): a new run would do that again, so only
    `allow <id> now` starts it then. A hold is answered once, so it starts at most one run.
  - `allow <id> later`: the same pass, for the job's next run; nothing is started.
  - `allow <id> always`: a standing pass for this job and action, for 30 days. Offered only when the scan's
    `owner_pass` is `always` and the call names its parties.
  - `deny <id>`: a standing denial for this job and action, for 30 days. A matching call is refused with a
    plain declined result and no notice.
  - `approve <id>` is the same as `allow <id>`, kept for one release.
  A hold on another unattended run is bound to where the run came from, when Hermes names it (`passes.source_of`:
  a subagent's parent session, a webhook's route, an API-server key's name): `allow` is a one-use pass for the
  next matching call from that source within 7 days, with nothing started, and `allow always` and `deny` are
  bound to the source. A run with no source has nothing to bind to: it offers `allow` only, bound to the call's
  exact arguments. The notice lists only the answers the hold offers. A wider grant the scanner suggests is
  never set by an answer: `why` shows its command, for the owner to set by hand.
- A later hold of the same job (or source) and action, at no higher risk and with no new warning, updates the waiting
  hold (its count and when it was last seen) and sends no new notice.
- One notice per cron run: the first hold of a run (`run_key`, a sub-agent of the run included) sends the notice and
  leads the run's group; a later hold of another action in the same run joins the group (`lead`) and sends nothing
  then. When the run ends (`end_of_run`), one line lists the group's holds that no line listed yet, by tool and
  description, with their ids. `allow <lead> all` then answers the lead and every hold a line listed (`shown`) in one
  started run: each gets a one-use pass of its own and is still gated by its own scan. A hold whose call itself sends
  or writes (`acts`) is never covered by `all`: it is answered on its own id. A hold that joins after its run's line
  went out gets a notice of its own. A group whose run never ended where the plugin could see it gets its line when
  the job's next run makes its first hold (`stale_groups`).
- After 7 days the hold expires and nothing runs. Expiry is found and recorded when the holds are next
  changed (a new hold or an answer).
- `/sentrook dismiss <id>` (or `all`) takes waiting holds off the list as if they had expired now (`dismiss`), on
  any hold, whatever answers it offers: nothing is set and the session history is left as an expiry leaves it, so a
  call like it is held again.

`holds.json` is version 2. Its entries keep no raw arguments: the match key is a hash (`passes.match_of`).
Holds from before (no `v`) stay answerable as before until they expire: `allow` or `approve` sets the
suggested grant (if any), and nothing else applies to them.

Hermes's own background skill and memory saves are held without an entry here (`skill_review`): approving
could not make the save.

A block (at the block line, or one the scanner enforces) is never held, except a retry of a review nobody
answered that the scanner caps at review (`decision.unattended_view`). Attended runs are unchanged: a review there
is still a review prompt.

The traffic log gets the scan with decision `held` and, later, a `resolution` record with resolution
`hold_allowed`, `hold_allowed_always`, `hold_denied` (`hold_approved` for an older hold), `hold_dismissed` or
`hold_expired`,
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

A notice to one chat that `hermes send` could not resolve (Hermes reaches some platforms' chats only once its channel
directory lists them) is kept and tried again in the background for up to 10 minutes, then sent to the platform's
home channel when it has one (`notice_retry`).
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
from typing import TYPE_CHECKING, Any

from . import grants, notice_retry, passes
from .config import HIDE_SETTING
from .decision import BLOCK_CATEGORIES, block_category, describe
from .store import Store, file_lock, read_time

if TYPE_CHECKING:
    from .owner_settings import Notify

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
#: A call held in a chat the owner trusts with reviews held for them (`trust`): the people there are waiting.
HELD_CHAT_TEXT = (
    "Sentrook held this tool call for the owner's approval, so it did not run. Tell the people in this chat "
    "that you are waiting for the owner to approve it. Do not retry it until someone says the owner has "
    "allowed it; then the same call can run once."
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


#: How the notice's run line names a source, before its name.
_SOURCE_LABELS = {
    "heartbeat": "agent",
    "hook": "hook",
    "subagent": "parent session",
    "api": "API key",
}


def where_text(
    run: str,
    session_ref: str,
    job_id: str | None = None,
    job_name: str | None = None,
    source: dict[str, Any] | None = None,
    subagent: bool = False,
) -> str:
    """Which run a hold belongs to: a cron job by its id, with its name quoted and labelled as the
    job's name (whoever made the job chose it, possibly the agent, so it must read as a name, never as
    an instruction), and `subagent` when a sub-agent of the job's run made the call; else the kind of run and, when
    the run has a source, the source by its name (quoted, as a job's name is; a parent session by its ref); then the
    session."""
    if job_id:
        name = (
            f", job name {json.dumps(inert(job_name, 60), ensure_ascii=False)}" if job_name else ""
        )
        by = "a sub-agent of " if subagent else ""
        return f"{by}cron job {inert(job_id, 40)}{name}, session {session_ref}"
    label = _SOURCE_LABELS.get(str((source or {}).get("kind")))
    if source and label:
        shown = (
            inert(source.get("name"), 40)
            if source.get("kind") == "subagent"
            else json.dumps(inert(source.get("name"), 60), ensure_ascii=False)
        )
        return f"{run}, {label} {shown}, session {session_ref}"
    return f"{run}, session {session_ref}"


#: The notice's line for each answer a hold offers; `{c}` is the command, `{id}` the hold's id.
_OFFER_LINES = {
    passes.ALLOW: "- run the job again now, letting this call through once: {c} {id}",
    passes.ALLOW_LATER: "- let it through once on the job's next scheduled run instead: {c} {id} later",
    passes.ALLOW_NOW: "- run the whole job again now, repeating what it already sent or wrote: {c} {id} now",
    passes.ALLOW_ALWAYS: "- let this job make this call for 30 days: {c} {id} always",
    passes.DENY: "- refuse it on this job for 30 days, with no more notices: {c} {id}",
}
#: `allow` on a hold whose run had already acted: it waits for the next run (`allow now` starts one).
_NEXT_RUN_LINE = "- let this call through once, on the job's next scheduled run: {c} {id}"
#: A hold that is not on a cron job: `allow` is bound to the exact call.
_EXACT_LINE = "- let this exact call through once, within 7 days: {c} {id}"
#: A hold bound to a source: the answers name the source by its kind (`{src}`, from `_SOURCE_NOUNS`).
_SOURCE_LINES = {
    passes.ALLOW: "- let this call through once more from {src}, within 7 days: {c} {id}",
    passes.ALLOW_ALWAYS: "- let {src} make this call for 30 days: {c} {id} always",
    passes.DENY: "- refuse it from {src} for 30 days, with no more notices: {c} {id}",
}
_SOURCE_NOUNS = {
    "heartbeat": "this agent's heartbeat",
    "hook": "this hook",
    "subagent": "subagents of the same parent session",
    "api": "this API key",
}


def notice_text(
    resp: dict[str, Any],
    tool: str,
    where: str,
    hold_id: str,
    offers: list[str],
    cmd: Cmd,
    scope: str | None = "job",
) -> str:
    """The owner's notice. It may be copied into the agent's own transcript (Hermes keeps what
    `send_message` sends), so it carries only what a steered agent cannot use: that a call was held,
    which run, the tool and its target as a review prompt names them, the block category, and the ids
    and the commands of the answers this hold offers (`offers`, from `passes.offers`). The risk, reason
    codes, scores and entities are for the owner, through `why`. `cmd`: a verb (allow, deny, why) -> the
    command as the owner types it. `scope`: what the answers are bound to: `job`, a source kind
    (`passes.SOURCE_KINDS`), or None (the exact call)."""
    lines = [
        "Sentrook held a tool call on an unattended run; it did not run.",
        f"Run: {_clean(where, 200)}",
        f"Tool: {inert(tool, 80)}: {inert(describe(resp, tool), 160)}",
        f"Held because {BLOCK_CATEGORIES[block_category(resp)]}.",
    ]
    if offers:
        lines.append("Reply within 7 days:")
        for verb in offers:
            noun = _SOURCE_NOUNS.get(str(scope))
            line = (
                _SOURCE_LINES[verb].replace("{src}", noun)
                if noun
                else _EXACT_LINE
                if verb == passes.ALLOW and not scope
                else _NEXT_RUN_LINE
                if verb == passes.ALLOW and passes.ALLOW_NOW in offers
                else _OFFER_LINES[verb]
            )
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
    data: dict[str, Any], ref: str | None, match: dict[str, Any]
) -> dict[str, Any] | None:
    """The waiting hold a new hold of the same job (or source) and action repeats: same job or source, same match
    key, at no higher risk and with no new warning (`passes.covers`). Only holds on a cron job or a source
    repeat."""
    if ref is None:
        return None
    return next(
        (
            h
            for h in data["holds"]
            if isinstance(h, dict)
            and h.get("v") == 2
            and passes.scope_ref(h) == ref
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
    source: dict[str, Any] | None = None,
    match: dict[str, Any] | None = None,
    level: str | None = None,
    offers: list[str] | None = None,
    description: str = "",
    job_digest: str | None = None,
    acted: bool = False,
    run_key: str | None = None,
    acts: bool = False,
    group_out: dict[str, Any] | None = None,
) -> tuple[str | None, bool]:
    """Stores a new hold, or counts a repeat of a waiting one (`_repeat_of`); returns its id (None when the file
    cannot be read: the call is still held, but cannot be answered) and whether it was a repeat (no new notice).
    `job_digest`: the job's settings as `run_now.digest` gives them; `acted`: the held run had sent or written
    something before the held call; `run_key`: the held run, which never counts as one started for an answer. A
    repeat keeps the first notice's digest, takes the latest run, and has acted when any of its runs had.
    `source`: where a run that is not a cron job came from (`passes.source_of`); its answers are bound to it.
    `acts`: the held call itself sends or writes (`passes.acts`). A new hold of a cron run that already has a waiting
    lead whose end line has not gone out joins its group: `group_out["lead"]` is set to the lead's id, and the caller
    sends no notice."""
    store = Store(state_dir)
    ref = passes.job_ref(job_id)
    source = source if ref is None and isinstance(source, dict) and source.get("ref") else None
    match = match or {}
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return None, False
        _sweep(data, now, record)
        data["version"] = 2
        same = _repeat_of(data, ref or (source or {}).get("ref"), match)
        if same is not None:
            same["count"] = int(same.get("count") or 1) + 1
            same["last_seen_at"] = _iso(now)
            same["held"] = [*(same.get("held") or []), {"sid": sid, "request_id": request_id}][
                -MAX_HELD:
            ]
            # the job as it was at the first notice (unreadable then: unknown for good), so an edit since still
            # counts as a change
            if same.get("run_key") != run_key:
                # a new run repeats it: that run's other holds join it and get their own end line
                same.pop("end_line_at", None)
            same["run_key"] = run_key
            same["acted"] = bool(same.get("acted")) or acted
            store.save_holds(data)
            return str(same["id"]), True
        taken = {h.get("id") for h in data["holds"] if isinstance(h, dict)}
        hid = f"h-{secrets.token_hex(3)}"
        while hid in taken:
            hid = f"h-{secrets.token_hex(3)}"
        lead = _run_lead(data, ref, run_key)
        if lead is not None:
            lead["group"] = [*(lead.get("group") or []), hid]
            if group_out is not None:
                group_out["lead"] = lead["id"]
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
                "source": (
                    {"kind": source["kind"], "ref": source["ref"], "name": source.get("name")}
                    if source
                    else None
                ),
                "match": match,
                "level": level,
                "offers": list(offers or []),
                "held_at": _iso(now),
                "last_seen_at": _iso(now),
                "count": 1,
                "expires_at": _iso(now + HOLD_TTL),
                "hint": hint,
                "notice": notice,
                "job_digest": job_digest,
                "acted": acted,
                "run_key": run_key,
                "acts": acts,
                **({"lead": lead["id"]} if lead is not None else {}),
            }
        )
        data["holds"] = data["holds"][-MAX_HOLDS:]
        store.save_holds(data)
        return hid, False


def _run_lead(data: dict[str, Any], ref: str | None, run_key: str | None) -> dict[str, Any] | None:
    """The waiting hold that leads cron run `run_key` of job `ref`: the run's first hold, whose end line has not gone
    out yet. None off a cron job, without a run key, or when the run has no lead."""
    if not ref or not run_key:
        return None
    return next(
        (
            h
            for h in data["holds"]
            if isinstance(h, dict)
            and h.get("v") == 2
            and h.get("job_ref") == ref
            and h.get("run_key") == run_key
            and not h.get("lead")
            and not h.get("end_line_at")
        ),
        None,
    )


def _unlisted(data: dict[str, Any], lead_id: Any, ref: Any) -> list[dict[str, Any]]:
    """The waiting holds that joined the group of lead `lead_id` (of job `ref`) and no end line has listed yet."""
    return [
        h
        for h in data["holds"]
        if isinstance(h, dict)
        and h.get("v") == 2
        and h.get("lead") == lead_id
        and h.get("job_ref") == ref
        and not h.get("listed")
    ]


#: (the lead, or what is left of it when it was answered or expired first; the holds to list; whether `all` is
#: offered: only while the lead waits).
Group = tuple[dict[str, Any], list[dict[str, Any]], bool]


def _list(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for m in members:
        m["listed"] = True
    return [dict(m) for m in members]


def _close_group(data: dict[str, Any], lead: dict[str, Any], now: datetime) -> Group | None:
    """Marks `lead`'s end line as sent and its unlisted holds as listed (`shown` on the lead); the group to list, or
    None when there is nothing to list."""
    lead["end_line_at"] = _iso(now)
    members = _unlisted(data, lead.get("id"), lead.get("job_ref"))
    if not members:
        return None
    lead["shown"] = [*(lead.get("shown") or []), *(m["id"] for m in members)]
    return dict(lead), _list(members), True


def _orphans(data: dict[str, Any], ref: str, keep: Callable[[dict[str, Any]], bool]) -> list[Group]:
    """The unlisted holds of job `ref` whose lead no longer waits (answered or expired before the run's end line),
    for which `keep` holds, grouped by their lead: they are listed too, with no `all` (nothing leads them now)."""
    waiting = {h.get("id") for h in data["holds"] if isinstance(h, dict)}
    by_lead: dict[str, list[dict[str, Any]]] = {}
    for h in data["holds"]:
        if (
            isinstance(h, dict)
            and h.get("v") == 2
            and h.get("job_ref") == ref
            and h.get("lead")
            and h["lead"] not in waiting
            and not h.get("listed")
            and keep(h)
        ):
            by_lead.setdefault(str(h["lead"]), []).append(h)
    return [
        ({"id": lead, "job_id": members[0].get("job_id"), "job_ref": ref}, _list(members), False)
        for lead, members in by_lead.items()
    ]


def end_of_run(state_dir: Path, ref: str | None, run_key: str | None, now: datetime) -> list[Group]:
    """Cron run `run_key` of job `ref` ended: its group's end line is due. Returns each group to list
    (`end_line_text`), now marked listed; [] when the run had no group or nothing more was held. Holds whose lead was
    answered or expired first are listed too (`_orphans`)."""
    if not ref or not run_key:
        return []
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return []
        out: list[Group] = []
        for h in data["holds"]:
            if (
                isinstance(h, dict)
                and h.get("v") == 2
                and h.get("job_ref") == ref
                and h.get("run_key") == run_key
                and not h.get("lead")
                and not h.get("end_line_at")
            ):
                closed = _close_group(data, h, now)
                if closed is not None:
                    out.append(closed)
        out += _orphans(data, ref, lambda h: h.get("run_key") == run_key)
        store.save_holds(data)
        return out


def stale_groups(
    state_dir: Path,
    ref: str | None,
    run_key: str | None,
    started_at: datetime | None,
    now: datetime,
) -> list[Group]:
    """The groups of job `ref`'s runs that started before run `run_key` (started at `started_at`) and whose end
    was never seen: their end lines are due before that run makes its first notice. A run that started later (one
    still going while a late call of an earlier run is held) is left alone. Same shape as `end_of_run`."""
    if not ref or not run_key or started_at is None:
        return []

    def earlier(h: dict[str, Any]) -> bool:
        at = read_time(h.get("held_at"))
        return h.get("run_key") not in (None, run_key) and at is not None and at < started_at

    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return []
        out: list[Group] = []
        for h in data["holds"]:
            if (
                isinstance(h, dict)
                and h.get("v") == 2
                and h.get("job_ref") == ref
                and not h.get("lead")
                and not h.get("end_line_at")
                and h.get("group")
                and earlier(h)
            ):
                closed = _close_group(data, h, now)
                if closed is not None:
                    out.append(closed)
        out += _orphans(data, ref, earlier)
        if out:
            store.save_holds(data)
        return out


def end_line_text(
    lead: dict[str, Any], members: list[dict[str, Any]], cmd: Cmd, can_all: bool = True
) -> str:
    """The run's end line: the holds of `lead`'s group no line listed yet, each by its id, tool and description (as
    the notice shows them, and no more), and how to answer them. `all` is offered only while the lead waits
    (`can_all`) and at least one listed call does not itself send or write (`acts`)."""
    texts = RUN_GROUP
    lines = [
        texts["head"].format(job=inert(lead.get("job_id"), 40), n=len(members), lead=lead.get("id"))
    ]
    for m in members:
        own = texts["own_answer"] if m.get("acts") else ""
        lines.append(
            texts["item"].format(
                id=m.get("id"),
                tool=inert(m.get("tool"), 80),
                description=inert(m.get("description"), 160),
                own=own,
            )
        )
    if can_all and any(
        not m.get("acts") and passes.ALLOW in (m.get("offers") or []) for m in members
    ):
        lines.append(texts["all"].format(allow=cmd("allow"), lead=lead.get("id")))
    lines.append(texts["each"].format(allow=cmd("allow"), deny=cmd("deny"), why=cmd("why")))
    return "\n".join(lines)


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


#: Why `allow` did not start the job now (`run_now`); the shared fixture's `run_now.reasons`.
RUN_NOW_REASONS = {
    "observe": "Sentrook is in observe mode",
    "unknown": "Sentrook could not read the job, so it cannot check that the job is unchanged since the hold",
    "missing": "the job no longer exists",
    "paused": "the job is paused",
    "terminal": "the job has finished and is not scheduled to run again",
    "running": "the job is running now, or a run started for an earlier answer has not finished",
    "changed": "the job was changed since the call was held",
    "acted": "the held run had already sent or written something before this call, and a new run would do it again",
    "unavailable": "Sentrook cannot start the job from here",
    "failed": "starting it failed",
}
#: The owner's reply to `allow` on a cron job's hold; the shared fixture's `run_now.replies`.
RUN_NOW_REPLIES = {
    "started": "Running job {job} again now; this call will be let through once in that run. Undo: {passes} revoke {pass}.",
    "started_now": (
        "Running job {job} again now; this call will be let through once in that run. The whole job runs again, so "
        "what it already sent or wrote before this call happens again. Undo: {passes} revoke {pass}."
    ),
    "later": (
        "Job {job} may make this call once, on its next scheduled run, until {until}. Sentrook does not run the held "
        "call itself. Undo: {passes} revoke {pass}."
    ),
    "fallback": (
        "Job {job} may make this call once, on its next scheduled run, until {until}. It was not run again now: "
        "{reason}. Undo: {passes} revoke {pass}."
    ),
}
#: The owner's line when a run started for an answer ends; the shared fixture's `run_now.outcomes`.
OUTCOMES = {
    "passed": "Sentrook: cron job {job} ran again, and the call you allowed went through once.",
    "passed_held": (
        "Sentrook: cron job {job} ran again, and the call you allowed went through once. It also made a different "
        "call, held as {hold}."
    ),
    "held": (
        "Sentrook: cron job {job} ran again but did not make the call you allowed; it made a different call, held "
        "as {hold}."
    ),
    "none": "Sentrook: cron job {job} ran again without using your answer.",
}

#: The run's end line (`end_line_text`) and the replies to `allow <lead> all`; shared with the OpenClaw plugin
#: (`integrations/fixtures/hold/cases.json`, `run_group`).
RUN_GROUP = {
    "head": "Sentrook: the run of cron job {job} that held {lead} also held {n} other call(s); none of them ran:",
    "item": "- {id}: {tool}: {description}{own}",
    "own_answer": " (it sends or writes: answer it on its own)",
    "all": "Let {lead} and the calls listed here through once, in one new run of the job: {allow} {lead} all",
    "each": "Or answer each by its id: {allow} <id>, {deny} <id>. For the reasons: {why} <id>",
    "covered": "In that run, these listed calls may also go through once: {ids}.",
    "left": "Not covered, answer each on its own: {ids}.",
    "none_listed": "No other call of this run has been listed yet, so this answers {lead} alone.",
    "not_lead": "{id} is one of the calls held in the run that {lead} leads: answer it on its own id, or all of them "
    "with {allow} {lead} all.",
}


class RunNow:
    """What `answer` needs to start a held call's job again (`run_now.Adapter` on Hermes): `guard(hold)`, why it may
    not be started now or None; `start(hold)`, (started, the host's run id or None, why not: `unavailable` when this
    process has no way to start it)."""

    def guard(self, hold: dict[str, Any]) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError

    def start(self, hold: dict[str, Any]) -> tuple[bool, str | None, str]:  # pragma: no cover
        raise NotImplementedError


def source_of_hold(found: dict[str, Any]) -> dict[str, Any] | None:
    """The source a version 2 hold off a cron job is bound to, or None."""
    src = None if found.get("job_ref") else found.get("source")
    return src if isinstance(src, dict) and isinstance(src.get("ref"), str) and src["ref"] else None


def _subject(found: dict[str, Any]) -> str:
    """Who makes the calls a hold's answer is bound to, to start the owner's reply: the job, else the source."""
    src = source_of_hold(found)
    if src is None:
        return f"Job {_clean(found.get('job_id'), 40)}"
    text = passes.source_text(src.get("kind"), src.get("name"))
    return text[:1].upper() + text[1:]


#: A hold with nothing to bind an answer to beyond the exact call.
_UNBOUND = "comes from a run with no cron job or other source Sentrook can bind an answer to"


def _refusal(found: dict[str, Any], want: str, hid: str, cmd: Cmd) -> str:
    """Why a hold does not offer the answer `want`; the hold keeps waiting."""
    on_job = bool(found.get("job_ref"))
    src = source_of_hold(found)
    level = found.get("level")
    why = f"{cmd('why')} {hid} shows the reasons"
    if want == passes.DENY:
        return (
            f"Not set: {hid} {_UNBOUND}, so there is nothing to refuse it for. Leave it and it expires; "
            "the call never runs."
        )
    if level is None:
        on = (
            "on this job"
            if on_job
            else f"from {passes.source_text(src.get('kind'), src.get('name'))}"
            if src
            else None
        )
        alt = (
            f"{cmd('deny')} {hid} refuses it {on} with no more notices; "
            if on
            else "leave it and it expires; "
        )
        return f"Not allowed: Sentrook does not offer to let this call through. {alt}{why}."
    if not on_job and src is None:
        return (
            f"Not set: {hid} {_UNBOUND}, so it cannot be let through for good. "
            f"{cmd('allow')} {hid} lets this exact call through once."
        )
    if level != "always":
        return (
            "Not set: Sentrook offers to let this call through on every run only when it judges that safe, "
            f"and for this one it offers it once. {cmd('allow')} {hid} lets it through once."
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


def _parse(verb: str, rest: str) -> tuple[str, str, str] | None:
    """(hold id, answer, mode) from `allow <id> [now|later|always|all]`, `approve <id>` or `deny <id>`; None when
    malformed. The mode is `now`, `later`, `all` (the run's group, `answer`) or "" for an `allow` once."""
    words = rest.split()
    if not words or not _ID.fullmatch(words[0]):
        return None
    if verb == "deny":
        return (words[0], passes.DENY, "") if len(words) == 1 else None
    mode = words[1].lower() if len(words) > 1 else ""
    if len(words) > 2 or mode not in ("", "now", "later", "once", "always", "all"):
        return None
    if mode == "always":
        return words[0], passes.ALLOW_ALWAYS, ""
    return words[0], passes.ALLOW, "" if mode == "once" else mode


def _not_waiting(hold_id: str, gone: list[dict[str, Any]]) -> str:
    """The reply for an id no hold waits under: expired (it went in this sweep, `gone`), or unknown."""
    old = next((h for h in gone if h.get("id") == hold_id), None)
    if old is not None:
        days = "7 days" if old.get("v") == 2 else "24 hours"
        return (
            f"Held call {hold_id} expired: a hold can be answered for {days}. Nothing was set; the "
            "next run is scanned as before."
        )
    return f"No held call {_clean(hold_id, 40)}: the id is unknown, already answered or expired."


#: The replies to `dismiss`; the shared fixture's `dismiss` (shared with the OpenClaw plugin).
DISMISS_TEXT = {
    "one": "Dismissed {id}: the held call does not run and nothing was set. A call like it is held again next time.",
    "all": (
        "Dismissed {n} held call(s): {ids}. None of them runs and nothing was set. Calls like them are held again "
        "next time."
    ),
    "none": "No held calls are waiting.",
    "usage": "usage: {dismiss} <id>|all, with the id from Sentrook's notice (h- and 6 hex digits)",
}


def dismiss(
    state_dir: Path, rest: str, who: dict[str, Any], now: datetime, cmd: Cmd, record: Record
) -> str:
    """`dismiss <id>` or `dismiss all`: takes waiting holds off the list as if they had expired now, whatever answers
    they offer (an older hold, one that offers nothing, one on a run with no source). The held call never runs and
    nothing is set: no pass, denial or grant, and the held calls' history is left as an expiry leaves it, so a call
    like it is held again, with a notice. Each held call gets a `hold_dismissed` resolution."""
    words = rest.split()
    every = len(words) == 1 and words[0].lower() == "all"
    if len(words) != 1 or (not every and not _ID.fullmatch(words[0])):
        return DISMISS_TEXT["usage"].format(dismiss=cmd("dismiss"))
    hid = words[0]
    store = Store(state_dir)
    with _LOCK, file_lock(state_dir / "holds.json"):
        data = store.load_holds()
        if data is None:
            return f"The holds file {state_dir / 'holds.json'} could not be read; fix or remove it first."
        gone = _sweep(data, now, record)
        # after the sweep every entry is a live hold
        taken = [h for h in data["holds"] if every or h.get("id") == hid]
        if not taken:
            if gone:
                store.save_holds(data)
            return DISMISS_TEXT["none"] if every else _not_waiting(hid, gone)
        data["holds"] = [h for h in data["holds"] if not any(h is t for t in taken)]
        try:
            store.save_holds(data)
        except Exception as exc:  # noqa: BLE001 - nothing changed
            return f"Not dismissed: the holds file could not be written ({_clean(exc, 160)}); nothing changed."
    for h in taken:
        held = [x for x in h.get("held") or [] if isinstance(x, dict)] or [
            {"request_id": h.get("request_id")}
        ]
        for x in held:
            if isinstance(x.get("request_id"), str):
                record(
                    {
                        "kind": "resolution",
                        "request_id": x["request_id"],
                        "resolution": "hold_dismissed",
                        "decision": "held",
                        "hold_id": h.get("id"),
                        "by": who,
                    }
                )
    if not every:
        return DISMISS_TEXT["one"].format(id=hid)
    return DISMISS_TEXT["all"].format(n=len(taken), ids=", ".join(str(h.get("id")) for h in taken))


def answer(
    state_dir: Path,
    verb: str,
    rest: str,
    who: dict[str, Any],
    now: datetime,
    cmd: Cmd,
    record: Record,
    run_now: RunNow | None = None,
) -> str:
    """`allow <id> [now|later|always|all]`, `approve <id>` or `deny <id>`: sets the pass or denial the hold offers,
    removes the hold and records the answer; the reply says what was set and how to undo it. On a cron job's hold,
    `allow` also starts the job again now through `run_now` unless a guard applies (see the module note)."""
    parsed = _parse(verb, rest)
    if parsed is None:
        form = {
            "deny": f"{cmd('deny')} <id>",
            "approve": f"{cmd('approve')} <id>",
        }.get(verb, f"{cmd('allow')} <id> [now|later|always|all]")
        return f"usage: {form}, with the id from Sentrook's notice (h- and 6 hex digits)"
    hid, want, mode = parsed
    #: Whether this answer starts the job again now, else why not (None: not asked to, `later` or not a job).
    start = False
    why_not: str | None = None
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
            return _not_waiting(hid, gone)
        if found.get("v") != 2:
            if want != passes.ALLOW:
                if gone:
                    store.save_holds(data)
                return (
                    f"Held call {hid} was made by an earlier version of the plugin: only {cmd('allow')} {hid} "
                    "answers it, as approve did (it sets the grant Sentrook suggested, if any)."
                )
            return _approve_v1(store, state_dir, data, found, gone, hid, who, now, cmd, record)
        if mode == "all" and found.get("lead"):
            if gone:
                store.save_holds(data)
            return RUN_GROUP["not_lead"].format(id=hid, lead=found["lead"], allow=cmd("allow"))
        if want not in (found.get("offers") or []):
            if gone:
                store.save_holds(data)
            return _refusal(found, want, hid, cmd)
        # `all`: the waiting holds of this lead's group an end line listed, that offer allow and whose call does not
        # itself send or write
        covered = (
            [
                m
                for m in _unlisted_or_listed(data, found)
                if m.get("listed") and not m.get("acts") and passes.ALLOW in (m.get("offers") or [])
            ]
            if mode == "all"
            else []
        )
        if want == passes.ALLOW and found.get("job_ref") and mode != "later":
            try:
                why_not = run_now.guard(found) if run_now is not None else "unavailable"
            except Exception as exc:  # noqa: BLE001 - not started; the pass waits
                logger.warning("sentrook could not check the held call's job: %s", exc)
                why_not = "unknown"
            if (
                why_not is None
                and (found.get("acted") or any(m.get("acted") for m in covered))
                and mode != "now"
            ):
                why_not = "acted"
            start = why_not is None
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
                run_bound=start,
            )
        except Exception as exc:  # noqa: BLE001 - the hold goes back
            failed = _clean(exc, 160)
        group: list[tuple[dict[str, Any], dict[str, Any]]] = []
        left: list[str] = []
        if entry is not None and mode == "all":
            group, left = _allow_group(
                store, state_dir, data, found, covered, who, now, entry["id"] if start else None
            )
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
            **(
                {"source_kind": entry.get("source_kind"), "source_ref": entry["source_ref"]}
                if entry.get("source_ref")
                else {}
            ),
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
    for member, member_entry in group:
        _record_group_answer(member, member_entry, who, record)
        _settle_history(
            state_dir,
            member.get("held") or [{"sid": "", "request_id": member.get("request_id")}],
            "approved_by_user",
        )
    group_note = _group_note(mode, found, group, left)
    until = read_time(entry["expires_at"])
    shown = passes.show(until) if until else "?"
    job = _subject(found)
    undo = f"Undo: {cmd('passes')} revoke {entry['id']}."
    if want == passes.DENY:
        return f"{job} will not make this call until {shown}; you won't be told again. {undo}"
    if want == passes.ALLOW_ALWAYS:
        return f"{job} may make this call until {shown}. {undo}"
    if not found.get("job_ref") and source_of_hold(found):
        return (
            f"{job} may make this call once more, until {shown}. Sentrook does not run the held call "
            f"itself. {undo}"
        )
    if not found.get("job_ref"):
        return (
            f"The next identical call from an unattended run may go through once, until {shown}. Sentrook "
            f"does not run the held call itself. {undo}"
        )
    if start and run_now is not None:
        try:
            started, run_id, failed = run_now.start(found)
        except Exception as exc:  # noqa: BLE001 - not started; the pass waits
            started, run_id, failed = False, None, _clean(exc, 200)
        try:
            if started:
                passes.started(state_dir, entry["id"], run_id)
            else:
                passes.not_started(state_dir, entry["id"])
        except Exception as exc:  # noqa: BLE001 - the pass stands as set
            logger.warning("sentrook could not record the run started for %s: %s", hid, exc)
        if not started:
            # a guard reason the host itself gave, `unavailable`, or else a failure
            why_not = failed if failed != "failed" and failed in RUN_NOW_REASONS else "failed"
        record(
            {
                "kind": "run_now",
                "op": "start",
                "hold_id": hid,
                "pass_id": entry["id"],
                "job_ref": entry.get("job_ref"),
                "started": started,
                **({"run_id": run_id} if run_id else {}),
                **({"reason": why_not, "detail": _clean(failed, 200)} if not started else {}),
                "by": who,
            }
        )
    elif why_not is not None:
        record(
            {
                "kind": "run_now",
                "op": "start",
                "hold_id": hid,
                "pass_id": entry["id"],
                "job_ref": entry.get("job_ref"),
                "started": False,
                "reason": why_not,
                "by": who,
            }
        )
    fields = {
        "job": _clean(found.get("job_id"), 40),
        "pass": entry["id"],
        "passes": cmd("passes"),
        "until": shown,
    }
    if start and why_not is None:
        kind = "started_now" if found.get("acted") else "started"
        return RUN_NOW_REPLIES[kind].format(**fields) + group_note
    if why_not is None:
        return RUN_NOW_REPLIES["later"].format(**fields) + group_note
    return (
        RUN_NOW_REPLIES["fallback"].format(**fields, reason=RUN_NOW_REASONS[why_not]) + group_note
    )


def _unlisted_or_listed(data: dict[str, Any], lead: dict[str, Any]) -> list[dict[str, Any]]:
    """Every waiting hold of `lead`'s group (same lead id and job), listed or not."""
    return [
        h
        for h in data["holds"]
        if isinstance(h, dict)
        and h.get("v") == 2
        and h.get("lead") == lead.get("id")
        and h.get("job_ref") == lead.get("job_ref")
    ]


def _allow_group(
    store: Store,
    state_dir: Path,
    data: dict[str, Any],
    lead: dict[str, Any],
    covered: list[dict[str, Any]],
    who: dict[str, Any],
    now: datetime,
    run_with: str | None,
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[str]]:
    """`allow <lead> all`: a one-use job pass for each hold in `covered` (listed, offering allow, not `acts`), which
    serves only the run started for the lead's pass (`run_with`; with no run started, the job's next run, as the
    lead's own pass). The holds are marked answered first, so a failure never leaves two passes for one hold; a
    hold whose pass could not be set goes back. Returns ((hold, pass) for each answered, the listed ids left for
    their own answer). Called with the holds file locked, after the lead's own pass."""
    left = [
        str(m.get("id"))
        for m in _unlisted_or_listed(data, lead)
        if m.get("listed") and not any(m is c for c in covered)
    ]
    if not covered:
        return [], left
    for m in covered:
        data["holds"].remove(m)
    try:
        store.save_holds(data)
    except Exception as exc:  # noqa: BLE001 - nothing set for them; they keep waiting
        logger.warning("sentrook could not mark the run's holds answered: %s", exc)
        data["holds"].extend(covered)
        return [], left + [str(m.get("id")) for m in covered]
    done: list[tuple[dict[str, Any], dict[str, Any]]] = []
    back: list[dict[str, Any]] = []
    for m in covered:
        try:
            got = passes.add(
                state_dir,
                kind="allow",
                uses="once",
                level="once",
                hold=m,
                who=who,
                now=now,
                run_with=run_with,
            )
        except Exception as exc:  # noqa: BLE001 - it goes back to waiting
            logger.warning("sentrook could not set a pass for %s: %s", m.get("id"), exc)
            got = None
        if got is None:
            back.append(m)
        else:
            done.append((m, got))
    if back:
        data["holds"].extend(back)
        try:
            store.save_holds(data)
        except Exception as exc:  # noqa: BLE001 - those holds are gone with no pass: held again next run
            logger.warning("sentrook could not put back the run's holds: %s", exc)
        left += [str(m.get("id")) for m in back]
    return done, left


def _record_group_answer(
    member: dict[str, Any], entry: dict[str, Any], who: dict[str, Any], record: Record
) -> None:
    record(
        {
            "kind": "passes",
            "op": "add",
            "id": entry["id"],
            "pass_kind": entry["kind"],
            "uses": entry["uses"],
            "job_ref": entry.get("job_ref"),
            "hold_id": member.get("id"),
            "group_lead": member.get("lead"),
            "expires_at": entry["expires_at"],
            "by": who,
        }
    )
    for h in member.get("held") or [{"request_id": member.get("request_id")}]:
        if isinstance(h, dict) and isinstance(h.get("request_id"), str):
            record(
                {
                    "kind": "resolution",
                    "request_id": h["request_id"],
                    "resolution": "hold_allowed",
                    "decision": "held",
                    "hold_id": member.get("id"),
                    "pass_id": entry["id"],
                    "by": who,
                }
            )


def _group_note(
    mode: str,
    lead: dict[str, Any],
    group: list[tuple[dict[str, Any], dict[str, Any]]],
    left: list[str],
) -> str:
    """What `allow <lead> all` added to the reply: the listed calls it covered and those left for their own answer."""
    if mode != "all":
        return ""
    if not lead.get("shown"):
        return " " + RUN_GROUP["none_listed"].format(lead=lead.get("id"))
    note = ""
    if group:
        note += " " + RUN_GROUP["covered"].format(ids=", ".join(str(m.get("id")) for m, _ in group))
    if left:
        note += " " + RUN_GROUP["left"].format(ids=", ".join(left))
    return note


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
    state_dir: Path,
    log: Path,
    hold_id: str,
    now: datetime,
    cmd: Cmd = "/sentrook {}".format,
    show_call: bool = True,
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
    lines = [format_why(*found[0], show_call=show_call, hidden_by=HIDE_SETTING)]
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


def home_channel_name(platform: str) -> str:
    """The name Hermes's gateway config gives `platform`'s home channel; "" when there is none or it cannot be read."""
    try:
        from gateway.config import Platform, load_gateway_config

        home = load_gateway_config().get_home_channel(Platform(platform))
        name = getattr(home, "name", "") if home else ""
        return name if isinstance(name, str) else ""
    except Exception as exc:  # noqa: BLE001 - no gateway config: no name
        logger.debug("home channel name not readable: %s", exc)
        return ""


NO_OWNER_CHANNEL = (
    "no notice target is set; send /sentrook notify here in the chat where you want notices"
)


def notice_target(n: Notify, homes: list[str]) -> tuple[str | None, str]:
    """(the target `hermes send --to` takes, or None; why there is none). A chat set by `notify here` is sent to
    directly; a platform needs a home channel. The owner names the platform: a home channel is not assumed to be
    the owner's just because it is the only one."""
    if not n.platform:
        return None, NO_OWNER_CHANNEL
    if n.chat_id or n.platform in homes:
        return n.to, ""
    if n.source == "command":
        return None, f"{n.platform}, set by command, has no home channel"
    return None, f"owner_channel {n.platform} has no home channel"


def connected_platforms() -> list[str]:
    """The platforms Hermes's gateway config connects, by name; empty when the config cannot be read."""
    try:
        from gateway.config import load_gateway_config

        return sorted(
            str(getattr(p, "value", p)) for p in load_gateway_config().get_connected_platforms()
        )
    except Exception as exc:  # noqa: BLE001 - no gateway config: nothing connected
        logger.debug("connected platforms not readable: %s", exc)
        return []


# ---- where the notice goes when no target is set ------------------------------------------------------------------

#: How a notice found a target with none set (`fallback_target`): the chat the cron job delivers to, or the owner's
#: direct message.
VIA_JOB = "job_delivery"
VIA_DM = "owner_dm"
#: Origins Hermes never sends a cron job's output to (it cannot push there).
_NON_PUSH = frozenset({"api_server"})
_PLATFORM_NAME = re.compile(r"[a-z][a-z0-9_-]{1,40}")
#: Delivery tokens that name no chat: no delivery, a broadcast to every home channel, Hermes's own rooms and bot chats.
_NO_CHAT = frozenset({"local", "all", "room", "bot-chat"})
_CHAT = re.compile(r"[^\s:]{1,200}")
#: Platforms where a person's user id is also the chat id of their direct message with the bot, so Hermes can send
#: to it: on Telegram a private chat's id is the user's id (positive; groups and channels are negative).
_DM_BY_USER_ID = {"telegram": re.compile(r"[1-9][0-9]{0,19}")}


def _chat(v: Any) -> str | None:
    s = str(v).strip() if isinstance(v, (str, int)) and not isinstance(v, bool) else ""
    return s if _CHAT.fullmatch(s) else None


def _origin_chat(origin: Any, platform: str | None = None) -> str | None:
    """`platform:chat[:thread]` for the chat a job was made in, when Hermes can deliver to it (and it is on
    `platform`, when given)."""
    if not isinstance(origin, dict):
        return None
    p = str(origin.get("platform") or "").strip().lower()
    chat = _chat(origin.get("chat_id"))
    if not _PLATFORM_NAME.fullmatch(p) or p in _NON_PUSH or chat is None:
        return None
    if platform is not None and p != platform:
        return None
    thread = _chat(origin.get("thread_id")) if origin.get("thread_id") not in (None, "") else None
    return f"{p}:{chat}" + (f":{thread}" if thread else "")


def job_delivery_target(job: Any, homes: list[str]) -> str | None:
    """Where cron job `job` (its record in Hermes's job file) delivers its own output, as `hermes send --to` takes
    it; None when it delivers nowhere the plugin can name for certain. Its first delivery that is one of:
    - `origin`: the chat the job was made in (Hermes's own `origin` record). With no origin Hermes picks a home channel
      itself, which is not the job's own choice, so none;
    - `<platform>:<chat>`: that chat;
    - `<platform>`: that platform's home channel, else the job's origin chat on that platform, as Hermes resolves it.
    `local`, `all` (a broadcast to every home channel), Hermes's own rooms and bot chats name no chat."""
    if not isinstance(job, dict):
        return None
    deliver = job.get("deliver")
    tokens = (
        deliver
        if isinstance(deliver, list)
        else deliver.split(",")
        if isinstance(deliver, str)
        else []
    )
    for token in tokens:
        t = str(token).strip()
        low = t.lower()
        if low == "origin":
            if found := _origin_chat(job.get("origin")):
                return found
            continue
        platform, sep, rest = low.partition(":")
        if not _PLATFORM_NAME.fullmatch(platform) or platform in _NO_CHAT:
            continue
        if sep:
            chat = t.partition(":")[2].strip()
            if chat and not any(c.isspace() for c in chat) and len(chat) <= 200:
                return f"{platform}:{chat}"
            continue
        if platform in homes:
            return platform
        if found := _origin_chat(job.get("origin"), platform):
            return found
    return None


def owner_dm_target(env: dict[str, str], connected: list[str]) -> str | None:
    """The owner's direct message, as `hermes send --to` takes it, when Hermes's allowlist names exactly one person
    on a connected platform where a user id is also their chat with the bot (`_DM_BY_USER_ID`); else None. Several
    people on the list, a wildcard, or `GATEWAY_ALLOWED_USERS` (not tied to one platform) name no one owner."""
    for platform, user_id in sorted(_DM_BY_USER_ID.items()):
        if platform not in connected:
            continue
        ids = {
            s.strip()
            for s in env.get(f"{platform.upper()}_ALLOWED_USERS", "").split(",")
            if s.strip()
        }
        if len(ids) == 1 and user_id.fullmatch(only := next(iter(ids))):
            return f"{platform}:{only}"
    return None


def fallback_target(
    job: Any, env: dict[str, str], homes: list[str], connected: list[str]
) -> tuple[str | None, str]:
    """(where a notice goes when the owner has set no target, or None; how: `VIA_JOB` or `VIA_DM`, "" for none).
    The cron job's own delivery first (`job_delivery_target`, None for a run of no job), then the owner's direct
    message (`owner_dm_target`). Never a home channel or group the job does not deliver to."""
    if to := job_delivery_target(job, homes):
        return to, VIA_JOB
    if to := owner_dm_target(env, connected):
        return to, VIA_DM
    return None, ""


def fallback_note(via: str, cmd: Cmd) -> str:
    """The line a notice sent by `fallback_target` ends with: where it went and how to set a target."""
    notify = cmd("notify")
    if via == VIA_JOB:
        return (
            "No notice target is set, so this notice went to the chat this job delivers to. Answer it in a direct "
            f"message to the agent, and send {notify} here there to choose where notices go."
        )
    return (
        "No notice target is set, so this notice went to your direct message. Send "
        f"{notify} here in the chat where you want notices."
    )


#: Status and verify, when calls are held and no target is set.
UNSET_WARNING = (
    "WARNING: {n} held call(s) waiting and no notice target is set, so their notices go only to a job's own "
    "delivery chat or your direct message where Sentrook can find one. Send /sentrook notify here in a direct "
    "message to the agent"
)


def unset_warning(state_dir: Path, n: Notify, now: datetime) -> str:
    """`UNSET_WARNING` when holds are waiting and the owner has set no notice target; "" otherwise."""
    if notice_target(n, [])[1] != NO_OWNER_CHANNEL:
        return ""
    count = waiting(state_dir, now)
    return UNSET_WARNING.format(n=count) if count else ""


def target_label(to: str) -> str:
    """The target as the traffic log records it: the platform, and "chat" for one chat, never its id."""
    platform, chat, _ = to.partition(":")
    return f"{platform} chat" if chat else platform


def target_text(to: str | None) -> str:
    """The target as status and verify show it, after "to the"."""
    if not to:
        return ""
    platform, chat, _ = to.partition(":")
    return (
        f"{platform} chat where you sent /sentrook notify here"
        if chat
        else f"{platform} home channel"
    )


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


def owner_target(n: Notify, can_dispatch: bool = True) -> tuple[str | None, str]:
    """`notice_target` for this process: also None, with the reason, when it has no way to send (`send_route`)."""
    target, why = notice_target(n, home_platforms())
    if target:
        route, no_route = send_route(can_dispatch)
        if route is None:
            return None, no_route
    return target, why


def status_line(state_dir: Path, n: Notify, now: datetime) -> str:
    target, why = owner_target(n)
    count = waiting(state_dir, now)
    held = "holds file unreadable" if count is None else f"{count} waiting"
    again = repeated(state_dir, now) if count else []
    if again:
        most = max(again, key=lambda h: int(h.get("count") or 1))
        held += (
            f" ({most.get('id')} held {int(most.get('count') or 1)} times since "
            f"{_clean(most.get('held_at'), 20)})"
        )
    where = f"notices to the {target_text(target)}" if target else f"notices not sent ({why})"
    warning = unset_warning(state_dir, n, now)
    return f"{held}; {where}" + (f"; {warning}" if warning else "")


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
    """(delivered, what Hermes said) for one `hermes send` of `text` to `platform`: a platform's home channel, or
    `platform:chat_id[:thread_id]` for one chat (`notify here`)."""
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


def _unnamed(said: str, to: str) -> str:
    """What Hermes said about a send, without the chat or thread id in `to`: the log names the platform only, as the
    traffic log does (on Telegram a direct message's chat id is the person's own id)."""
    for part in sorted(to.partition(":")[2].split(":"), key=len, reverse=True):
        if len(part) >= 4:  # shorter ones identify nobody, and would blank out ordinary text
            said = said.replace(part, "<chat>")
    return said


def _send(
    ctx: Any,
    route: str | None,
    platform: str,
    text: str,
    on_fail: Callable[[], None] | None = None,
    on_ok: Callable[[], None] | None = None,
    state_dir: Path | None = None,
) -> None:
    delivered, said, kept = False, "no way to send it from this process", False
    try:
        if route == HERMES_SEND:
            delivered, said = _with_hermes_send(platform, defuse(text))
        elif route == SEND_TOOL:
            delivered, said = _with_send_tool(ctx, platform, defuse(text))
        if not delivered:
            logger.warning(
                "sentrook hold notice to %s not delivered with %s: %s",
                target_label(platform),
                route or "no route",
                _unnamed(said, platform),
            )
            if (
                route == HERMES_SEND
                and state_dir is not None
                and notice_retry.retryable(platform, said)
            ):
                # A kept notice still counts as sent: `on_fail` runs only if its last try fails too.
                kept = notice_retry.keep(state_dir, platform, text, on_fail)
    except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
        logger.warning(
            "sentrook hold notice to %s failed with %s: %s",
            target_label(platform),
            route,
            _unnamed(str(exc), platform),
        )
    if not delivered and not kept and on_fail is not None:
        try:
            on_fail()
        except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
            logger.warning("sentrook could not undo an undelivered notice: %s", exc)
    if delivered and on_ok is not None:
        try:
            on_ok()
        except Exception as exc:  # noqa: BLE001 - nobody to tell but the log
            logger.warning("sentrook could not record a delivered notice: %s", exc)


def deliver(
    ctx: Any,
    platform: str,
    text: str,
    on_fail: Callable[[], None] | None = None,
    on_ok: Callable[[], None] | None = None,
    state_dir: Path | None = None,
) -> None:
    """Sends `text` to `platform` (a home channel, or one chat as `notice_target` gives it) from a worker thread with an empty context, with `hermes send` or
    the send_message tool as `send_route` chooses for the current turn (see the module note). The thread is not a daemon, so a `hermes cron run` process waits
    for it. `on_fail` runs on that thread when the notice was not delivered, `on_ok` when it was. With `state_dir`, a notice to one chat that `hermes send`
    could not resolve is also kept and tried again (`notice_retry`), and notices kept earlier are looked at."""
    if state_dir is not None:
        notice_retry.resume(state_dir)
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
            on_ok,
            state_dir,
        ),
        name="sentrook-hold-notice",
        daemon=False,
    )
    _threads.append(t)
    t.start()


def wait_for_notices(timeout: float = 10.0) -> None:
    for t in list(_threads):
        t.join(timeout)
