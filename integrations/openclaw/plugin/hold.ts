/**
 * Holds: a review on an unattended run waits for the owner instead of being asked of nobody.
 *
 * Nobody can answer a review on a cron job, a heartbeat, a hook or a subagent (the scheduled intent kinds).
 * There the plugin holds the call:
 * - the call does not run, and the agent is told it is held for the owner's approval and must not be retried in
 *   this run (`HELD_TEXT`);
 * - the owner gets one notice as a direct message, on the channel where they ran `/sentrook-notify here`: which
 *   run, the tool and its target as a review names them, the block category, the hold's id and the answers it
 *   offers. It carries nothing a steered agent could use (the Hermes plugin's notice can reach the agent's
 *   transcript, and both send the same text); the owner reads the risk, reasons and suggested grant with
 *   `/sentrook-why <id>`;
 * - the owner answers within 7 days (`answer`):
 *   - `/sentrook-allow <id>` (also `<id> later`): a one-use pass for this job and action, used by the job's next run
 *     (passes.ts). The held call itself is not run again. Until the plugin can start the job's run itself, both
 *     forms wait for the next run; `runNow` is where that will plug in.
 *   - `/sentrook-allow <id> always`: a standing pass for this job and action, for 30 days. Offered only when the
 *     scan's `owner_pass` is `always` and the call names its parties.
 *   - `/sentrook-deny <id>`: a standing denial for this job and action, for 30 days. A matching call is refused with a
 *     plain declined result and no notice.
 *   - `/sentrook-approve <id>` is the same as `/sentrook-allow <id>`, kept for one release.
 *   A hold on a run that is not a cron job has no job to bind to: it offers allow only, bound to the call's exact
 *   arguments. The notice lists only the answers the hold offers. A wider grant the scanner suggests is never set by
 *   an answer: `why` shows its command, for the owner to set by hand.
 * - A later hold of the same job and action, at no higher risk and with no new warning, updates the waiting hold
 *   (its count and when it was last seen) and sends no new notice.
 * - After 7 days the hold expires and nothing runs. Expiry is found and recorded when the holds are next changed
 *   (a new hold or an answer).
 *
 * `holds.json` is version 2. Its entries keep no raw arguments: the match key is a hash (`passes.matchOf`). Holds
 * from before (no `v`) stay answerable as before until they expire: allow or approve sets the suggested grant (if
 * any), and nothing else applies to them.
 *
 * A block (at the block line, or one the scanner enforces) is never held, except a retry of a review nobody answered
 * that the scanner caps at review (`unattendedView`). Attended runs are unchanged: a review there is still the host's
 * approval prompt. OpenClaw's own background saves are held here too when nothing better applies (backgroundSave.ts).
 *
 * The traffic log gets the scan with decision `held` and, later, a `resolution` record with resolution
 * `hold_allowed`, `hold_allowed_always`, `hold_denied` (`hold_approved` for an older hold) or `hold_expired`, joined
 * by `request_id` as review answers are; a call a pass or denial settles is logged with decision `allowed_by_pass`
 * or `denied_by_owner`. Holds are kept in `<state>/sentrook/holds.json` and the notice target in `notify.json`; the
 * Hermes plugin keeps the same holds file and prints the same notice text.
 */

import { randomBytes } from "node:crypto";
import path from "node:path";

import { BLOCK_CATEGORIES, blockCategory, describe } from "./decision.ts";
import { formatWhy, recentScans, recordsBackward } from "./history.ts";
import * as grants from "./grants.ts";
import { OwnerRefused } from "./owner.ts";
import * as passes from "./passes.ts";
import type { ScanResponse } from "./scanClient.ts";
import { type HoldsFile, type NotifyTarget, readTime, Store, withFileLock } from "./store.ts";

export { LockTimeoutError } from "./store.ts";

export const HOLD_TTL_MS = 7 * 24 * 3600_000;
export const GRANT_TTL_MS = 30 * 24 * 3600_000;
const MAX_HOLDS = 200;
/** The held calls a repeated hold remembers, for setting their history once it is answered. */
const MAX_HELD = 20;
const ID = /^h-[0-9a-f]{6}$/;

export const HELD_TEXT =
  "Sentrook held this tool call for the owner's approval, so it did not run. Do not retry this call in this run.";

type Entry = Record<string, any>;

const holdsFile = (stateDir: string) => path.join(stateDir, "holds.json");
/** Writes one record to the traffic log. */
export type RecordFn = (record: Record<string, unknown>) => void;

/**
 * The grant the scan response suggests for this call, if any: the first of its `grant_hints` that the grant command
 * would accept and (with `reviewAt`) that brings the call below this plugin's review line.
 *
 * Grant hints are optional: a response without one makes a hold that approving sets nothing for. A hold stores what
 * this returns, and approval reads it again with `grants.hintGrant`, which refuses anything that is not a plain grant.
 */
export function grantHint(resp: ScanResponse, reviewAt?: number): Entry | null {
  return grants.responseHints(resp, reviewAt)[0] ?? null;
}

const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;

function clean(s: unknown, cap = 200): string {
  return Array.from(String(s), (c) => (/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]|[^\P{Zs} ]/u.test(c) ? "?" : c))
    .slice(0, cap)
    .join("");
}

/**
 * Link, mention and code markup in chat formats (Discord and Telegram `[text](url)`, Slack `<url|text>`,
 * `@everyone`, backticks): taken out of every notice field the agent can influence.
 */
const MARKUP = /[[\]()<>|@`]/g;

/** `s` with chat markup taken out and non-printable characters replaced, at most `cap` long. */
export function inert(s: unknown, cap: number): string {
  return clean(String(s).replace(MARKUP, ""), cap);
}

// ---- the text -----------------------------------------------------------------------------------------

/**
 * Which run a hold belongs to: a cron job by its id, with its name quoted and labelled as the job's name (whoever
 * made the job chose it, possibly the agent, so it must read as a name, never as an instruction), else the kind of
 * run; then the session.
 */
export function whereText(run: string, sessionRef: string, jobId?: string | null, jobName?: string | null): string {
  if (jobId) {
    const name = jobName ? `, job name ${JSON.stringify(inert(jobName, 60))}` : "";
    return `cron job ${inert(jobId, 40)}${name}, session ${sessionRef}`;
  }
  return `${run}, session ${sessionRef}`;
}

/** The job id and name OpenClaw puts before a cron run's prompt (`[cron:<id> <name>]`); null for other runs. */
export function cronJobOf(prompt: unknown): { id: string; name: string | null } | null {
  const m = typeof prompt === "string" ? /^\[cron:([^\]\s]+)(?: ([^\]]*))?\]/.exec(prompt) : null;
  if (!m) return null;
  const name = m[2]?.trim();
  return { id: m[1]!, name: name && name !== m[1] ? name : null };
}

/**
 * The cron job OpenClaw's run metadata names for a cron run: `inputProvenance.jobId`, else the agent hook's `jobId`,
 * from the call's context or, failing that, the run's first agent hook. Only when the trigger is `cron`; never read
 * from the prompt (the `[cron:...]` tag is text the run could have been given). Null for any other run.
 */
export function cronJobId(ctx: any, run: any): string | null {
  const trigger = ctx?.trigger ?? run?.trigger;
  if (trigger !== "cron") return null;
  for (const v of [ctx?.inputProvenance?.jobId, run?.inputProvenance?.jobId, ctx?.jobId, run?.jobId]) {
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return null;
}

/** The notice's line for each answer a hold offers; `{c}` is the command, `{id}` the hold's id. */
const OFFER_LINES: Record<string, string> = {
  [passes.ALLOW]: "- let this call through once, on the job's next run: {c} {id}",
  [passes.ALLOW_ALWAYS]: "- let this job make this call for 30 days: {c} {id} always",
  [passes.DENY]: "- refuse it on this job for 30 days, with no more notices: {c} {id}",
};
/** A hold that is not on a cron job: allow is bound to the exact call. */
const EXACT_LINE = "- let this exact call through once, within 7 days: {c} {id}";

/**
 * The owner's notice: that a call was held, which run, the tool and its target as a review names them, the block
 * category, and the ids and the commands of the answers this hold offers (`offers`, from `passes.offers`). The risk,
 * reason codes, scores and entities are for the owner, through `why`: the same text can reach the agent's own
 * transcript on Hermes. `cmd`: a verb (allow, deny, why) -> the command as the owner types it.
 */
export function noticeText(
  resp: ScanResponse,
  tool: string,
  where: string,
  holdId: string,
  offers: string[],
  cmd: (verb: string) => string,
  onJob = true,
): string {
  const lines = [
    "Sentrook held a tool call on an unattended run; it did not run.",
    `Run: ${clean(where, 200)}`,
    `Tool: ${inert(tool, 80)}: ${inert(describe(resp, tool), 160)}`,
    `Held because ${BLOCK_CATEGORIES[blockCategory(resp)]}.`,
  ];
  if (offers.length) {
    lines.push("Reply within 7 days:");
    for (const verb of offers) {
      const line = verb === passes.ALLOW && !onJob ? EXACT_LINE : OFFER_LINES[verb]!;
      lines.push(line.replace("{c}", cmd(verb === passes.DENY ? "deny" : "allow")).replace("{id}", holdId));
    }
  } else {
    lines.push("Sentrook offers no way to let this call through.");
  }
  lines.push(`For the reasons: ${cmd("why")} ${holdId}`);
  return lines.join("\n");
}

// ---- the file -----------------------------------------------------------------------------------------

function live(h: unknown, now: Date): boolean {
  if (!h || typeof h !== "object") return false;
  const at = readTime((h as Entry).expires_at);
  return at !== null && at.getTime() > now.getTime();
}

/** Drops the expired holds from `data` (unreadable entries too) and records each expiry; true when any went. */
function sweepData(data: HoldsFile, now: Date, record: RecordFn): { changed: boolean; gone: Entry[] } {
  const keep: unknown[] = [];
  const gone: Entry[] = [];
  for (const h of data.holds) {
    if (live(h, now)) keep.push(h);
    else if (h && typeof h === "object") gone.push(h as Entry);
  }
  const changed = keep.length !== data.holds.length;
  data.holds = keep;
  for (const h of gone) {
    const rids = Array.isArray(h.held) ? h.held.map((x: Entry) => x?.request_id) : [];
    for (const rid of rids.length ? rids : [h.request_id]) {
      if (typeof rid === "string") {
        record({ kind: "resolution", request_id: rid, resolution: "hold_expired", decision: "held", hold_id: h.id ?? null });
      }
    }
  }
  return { changed, gone };
}

/** Records and drops every expired hold; a file that cannot be read is left alone. */
export function sweep(stateDir: string, now: Date, record: RecordFn): void {
  const store = new Store(stateDir);
  withFileLock(holdsFile(stateDir), () => {
    const data = store.loadHolds();
    if (data === null) return;
    if (sweepData(data, now, record).changed) store.saveHolds(data);
  });
}

export interface NewHold {
  requestId: string;
  sessionRef: string;
  tool: string;
  where: string;
  hint: Entry | null;
  notice: Record<string, unknown>;
  /** The session the call was made in, for setting its history once the hold is answered. */
  sid?: string;
  /** The cron job OpenClaw names for the run; null for any other run. */
  jobId?: string | null;
  match?: passes.Match | null;
  level?: passes.Level | null;
  offers?: string[];
  /** The call as the notice describes it, for the passes list. */
  description?: string;
}

/**
 * The waiting hold a new hold of the same job and action repeats: same job, same match key, at no higher risk and
 * with no new warning (`passes.covers`). Only holds on a cron job repeat.
 */
function repeatOf(data: HoldsFile, jobRef: string | null, match: passes.Match | null | undefined): Entry | null {
  if (jobRef === null || !match) return null;
  return (
    (data.holds.find(
      (h) => !!h && typeof h === "object" && (h as Entry).v === 2 && (h as Entry).job_ref === jobRef && passes.covers((h as Entry).match, match),
    ) as Entry | undefined) ?? null
  );
}

/**
 * Stores a new hold, or counts a repeat of a waiting one (`repeatOf`); returns its id (null when the file cannot be
 * read: still held, not answerable) and whether it was a repeat (no new notice).
 */
export function create(stateDir: string, hold: NewHold, now: Date, record: RecordFn): { id: string | null; repeat: boolean } {
  return withFileLock(holdsFile(stateDir), () => createLocked(stateDir, hold, now, record));
}

function createLocked(stateDir: string, hold: NewHold, now: Date, record: RecordFn): { id: string | null; repeat: boolean } {
  const store = new Store(stateDir);
  const data = store.loadHolds();
  if (data === null) return { id: null, repeat: false };
  sweepData(data, now, record);
  data.version = 2;
  const ref = passes.jobRef(hold.jobId);
  const held = { sid: hold.sid ?? "", request_id: hold.requestId };
  const same = repeatOf(data, ref, hold.match);
  if (same) {
    same.count = Number(same.count ?? 1) + 1;
    same.last_seen_at = iso(now);
    same.held = [...(Array.isArray(same.held) ? same.held : []), held].slice(-MAX_HELD);
    store.saveHolds(data);
    return { id: String(same.id), repeat: true };
  }
  const taken = new Set(data.holds.map((h) => (h as Entry)?.id));
  let id = `h-${randomBytes(3).toString("hex")}`;
  while (taken.has(id)) id = `h-${randomBytes(3).toString("hex")}`;
  data.holds.push({
    v: 2,
    id,
    request_id: hold.requestId,
    session_ref: hold.sessionRef,
    held: [held],
    tool: hold.tool,
    description: hold.description ?? "",
    where: hold.where,
    job_id: hold.jobId ?? null,
    job_ref: ref,
    match: hold.match ?? {},
    level: hold.level ?? null,
    offers: [...(hold.offers ?? [])],
    held_at: iso(now),
    last_seen_at: iso(now),
    count: 1,
    expires_at: iso(new Date(now.getTime() + HOLD_TTL_MS)),
    hint: hold.hint,
    notice: hold.notice,
  });
  data.holds = data.holds.slice(-MAX_HOLDS);
  store.saveHolds(data);
  return { id, repeat: false };
}

/** How many holds wait for the owner; null when the file cannot be read. */
export function waiting(stateDir: string, now: Date): number | null {
  const data = new Store(stateDir).loadHolds();
  return data === null ? null : data.holds.filter((h) => live(h, now)).length;
}

/** The waiting holds held more than once, for status. */
export function repeated(stateDir: string, now: Date): Entry[] {
  const data = new Store(stateDir).loadHolds();
  return (data?.holds ?? []).filter((h): h is Entry => live(h, now) && Number((h as Entry).count ?? 1) > 1);
}

/** Starts the held call's job again now, for allow; null when it did, else why not (then the pass waits for the
 * job's next run). This plugin does not start runs yet: every allow waits. */
function runNow(_hold: Entry): string | null {
  return "not available";
}

/** Why a hold does not offer the answer `want`; the hold keeps waiting. */
function refusal(found: Entry, want: string, id: string, cmd: grants.Cmd): string {
  const onJob = !!found.job_ref;
  const level = found.level ?? null;
  const why = `${cmd("why")} ${id} shows the reasons`;
  if (want === passes.DENY) {
    return `Not set: ${id} is not on a cron job, so there is no job to refuse it for. Leave it and it expires; the call never runs.`;
  }
  if (level === null) {
    const alt = onJob ? `${cmd("deny")} ${id} refuses it on this job with no more notices; ` : "leave it and it expires; ";
    return `Not allowed: Sentrook does not offer to let this call through. ${alt}${why}.`;
  }
  if (!onJob) {
    return `Not set: ${id} is not on a cron job, so there is no job to let this call through for good. ${cmd("allow")} ${id} lets this exact call through once.`;
  }
  if (level !== "always") {
    return (
      "Not set: Sentrook offers to let this call through on every run only when it judges that safe, and for this one " +
      `it offers it once. ${cmd("allow")} ${id} lets it through on the job's next run.`
    );
  }
  if (!found.match?.named) {
    return `Not set: this call names nothing a standing pass could be bound to, so only a one-time pass bound to its exact arguments is offered: ${cmd("allow")} ${id}.`;
  }
  return `Not set: this call scored at the block line, so it can only be let through once: ${cmd("allow")} ${id}.`;
}

/** (hold id, answer) from `allow <id> [later|always]`, `approve <id>` or `deny <id>`; null when malformed. */
function parseAnswer(verb: string, rest: string): [string, string] | null {
  const words = rest.trim().split(/\s+/).filter(Boolean);
  if (!words.length || !ID.test(words[0]!)) return null;
  if (verb === "deny") return words.length === 1 ? [words[0]!, passes.DENY] : null;
  const mode = (words[1] ?? "").toLowerCase();
  if (words.length > 2 || !["", "later", "once", "always"].includes(mode)) return null;
  return [words[0]!, mode === "always" ? passes.ALLOW_ALWAYS : passes.ALLOW];
}

/** A held call to set in its session's history once answered. */
export interface HeldCall {
  sid: string;
  request_id: string;
}

/** What an answer set, for the caller to finish: the held calls' history (`settle`). */
export interface Answered {
  reply: string;
  /** The held calls whose history entries become `decision`; empty when nothing was set. */
  held: HeldCall[];
  decision: "approved_by_user" | "denied_by_user" | null;
}

/** A hold from before version 2, answered as approve answered it: sets the suggested grant (if any). */
function approveV1(
  stateDir: string,
  store: Store,
  data: HoldsFile,
  found: Entry,
  changed: boolean,
  id: string,
  by: Entry,
  now: Date,
  cmd: grants.Cmd,
  record: RecordFn,
  beforeWrite: () => void,
): string {
  const grant = grants.hintGrant(found.hint);
  let reply = "";
  let change: grants.Change | null = null;
  if (grant) {
    try {
      ({ reply, change } = grants.addSuggested(stateDir, grant, by, now, GRANT_TTL_MS, id, beforeWrite));
    } catch (err) {
      if (err instanceof OwnerRefused) throw err;
      reply = `The grants file could not be written (${clean(String(err), 160)}).`;
    }
    if (!change) {
      if (changed) store.saveHolds(data);
      return `Not approved: ${reply} ${id} is still waiting; approve it again once that is fixed.`;
    }
  }
  if (change && !change.existing) record({ kind: "grants", ...change, by });
  beforeWrite();
  data.holds = data.holds.filter((h) => h !== found);
  try {
    store.saveHolds(data);
  } catch (err) {
    return `Not finished: ${reply} The hold could not be marked answered (${clean(String(err), 160)}); approve ${id} again to finish.`;
  }
  const done = { kind: "resolution", request_id: found.request_id, resolution: "hold_approved", decision: "held", hold_id: id, by };
  if (!change) {
    record(done);
    return (
      `Approved ${id}. Sentrook suggested no grant for this call, so nothing was set: the next run is scanned as ` +
      `before. To let it pass, add a grant with ${cmd("grant")}. The held call is not run again.`
    );
  }
  record({ ...done, grant_id: change.entry.id });
  return `Approved ${id}. ${reply} The held call is not run again; the next run is scanned with this grant.`;
}

/**
 * `allow <id> [later|always]`, `approve <id>` or `deny <id>`: sets the pass or denial the hold offers, removes the
 * hold and records the answer; the reply says what was set and how to undo it. The caller sets the held calls'
 * history (`Answered.held`).
 */
export function answer(
  stateDir: string,
  verb: "allow" | "deny" | "approve",
  rest: string,
  by: Entry,
  now: Date,
  cmd: grants.Cmd,
  record: RecordFn,
  beforeWrite: () => void,
): Answered {
  const none = (reply: string): Answered => ({ reply, held: [], decision: null });
  const parsed = parseAnswer(verb, rest);
  if (!parsed) {
    const form = verb === "deny" ? `${cmd("deny")} <id>` : verb === "approve" ? `${cmd("approve")} <id>` : `${cmd("allow")} <id> [later|always]`;
    return none(`usage: ${form}, with the id from Sentrook's notice (h- and 6 hex digits)`);
  }
  const [id, want] = parsed;
  const store = new Store(stateDir);
  type Outcome = { done: string } | { found: Entry; entry: Entry };
  const outcome = withFileLock(holdsFile(stateDir), (): Outcome => {
    const data = store.loadHolds();
    if (data === null) return { done: `The holds file ${holdsFile(stateDir)} could not be read; fix or remove it first.` };
    const { changed, gone } = sweepData(data, now, record);
    const save = () => {
      if (changed) {
        beforeWrite();
        store.saveHolds(data);
      }
    };
    const found = data.holds.find((h) => (h as Entry)?.id === id) as Entry | undefined;
    if (!found) {
      save();
      const old = gone.find((h) => h.id === id);
      if (old) {
        const span = old.v === 2 ? "7 days" : "24 hours";
        return { done: `Held call ${id} expired: a hold can be answered for ${span}. Nothing was set; the next run is scanned as before.` };
      }
      return { done: `No held call ${clean(id, 40)}: the id is unknown, already answered or expired.` };
    }
    if (found.v !== 2) {
      if (want !== passes.ALLOW) {
        save();
        return {
          done: `Held call ${id} was made by an earlier version of the plugin: only ${cmd("allow")} ${id} answers it, as approve did (it sets the grant Sentrook suggested, if any).`,
        };
      }
      return { done: approveV1(stateDir, store, data, found, changed, id, by, now, cmd, record, beforeWrite) };
    }
    if (!(Array.isArray(found.offers) ? found.offers : []).includes(want)) {
      save();
      return { done: refusal(found, want, id, cmd) };
    }
    // The hold is marked answered first, so a failure never leaves two passes for one answer.
    beforeWrite();
    data.holds = data.holds.filter((h) => h !== found);
    try {
      store.saveHolds(data);
    } catch (err) {
      return { done: `Not set: the holds file could not be written (${clean(String(err), 160)}); ${id} is still waiting.` };
    }
    let entry: Entry | null = null;
    let failed = "";
    try {
      entry = passes.add(
        stateDir,
        {
          kind: want === passes.DENY ? "deny" : "allow",
          uses: want === passes.ALLOW ? "once" : "standing",
          level: want === passes.ALLOW_ALWAYS ? "always" : "once",
          hold: found,
          by,
          now,
        },
        beforeWrite,
      );
    } catch (err) {
      failed = clean(String(err), 160);
      if (err instanceof OwnerRefused) {
        data.holds.push(found);
        store.saveHolds(data);
        throw err;
      }
    }
    if (!entry) {
      data.holds.push(found);
      try {
        store.saveHolds(data);
      } catch {
        return { done: `Not set: the passes file could not be written (${failed || "unreadable"}), and ${id} could not be put back.` };
      }
      return { done: `Not set: the passes file could not be written (${failed || "unreadable"}); ${id} is still waiting.` };
    }
    return { found, entry };
  });
  if ("done" in outcome) return none(outcome.done);
  const { found, entry } = outcome;
  const resolution = want === passes.DENY ? "hold_denied" : want === passes.ALLOW_ALWAYS ? "hold_allowed_always" : "hold_allowed";
  const held: HeldCall[] = (Array.isArray(found.held) && found.held.length ? found.held : [{ sid: "", request_id: found.request_id }]).filter(
    (h: Entry): h is HeldCall => !!h && typeof h.request_id === "string",
  );
  record({
    kind: "passes",
    op: "add",
    id: entry.id,
    pass_kind: entry.kind,
    uses: entry.uses,
    job_ref: entry.job_ref ?? null,
    hold_id: id,
    expires_at: entry.expires_at,
    by,
  });
  for (const h of held) {
    record({ kind: "resolution", request_id: h.request_id, resolution, decision: "held", hold_id: id, pass_id: entry.id, by });
  }
  const until = readTime(entry.expires_at);
  const shown = until ? passes.show(until) : "?";
  const job = `Job ${clean(found.job_id, 40)}`;
  const undo = `Undo: ${cmd("passes")} revoke ${entry.id}.`;
  const decision = want === passes.DENY ? "denied_by_user" : "approved_by_user";
  let reply: string;
  if (want === passes.DENY) reply = `${job} will not make this call until ${shown}; you won't be told again. ${undo}`;
  else if (want === passes.ALLOW_ALWAYS) reply = `${job} may make this call until ${shown}. ${undo}`;
  else if (!found.job_ref) {
    reply = `The next identical call from an unattended run may go through once, until ${shown}. The held call itself is not run again. ${undo}`;
  } else {
    runNow(found); // the seam for starting the job now; until then the pass waits for the next run
    reply = `${job} may make this call once: on its next run, or if the held run retries it. Sentrook does not run the held call itself. ${undo}`;
  }
  return { reply, held: held.filter((h) => !!h.sid), decision };
}

/**
 * Sets the held calls' entries in their sessions' history to `decision`, so a retry in the same session is scored as
 * one after the owner's answer, not after a review nobody answered. Never throws: the answer stands.
 */
export async function settle(stateDir: string, held: HeldCall[], decision: string): Promise<void> {
  const store = new Store(stateDir);
  for (const h of held) {
    try {
      // under the session's lock, which a scan of the same session holds for the whole scan
      await store.withSession(h.sid, () => {
        const sess = store.loadSession(h.sid);
        const hit = sess.history.filter((e) => e.request_id === h.request_id);
        if (!hit.length) return;
        for (const e of hit) e.decision = decision as typeof e.decision;
        store.saveSession(h.sid, sess, Math.max(sess.history.length, 1));
      });
    } catch {
      // the answer stands
    }
  }
}

/** The hold with this id while it waits; null when unknown, answered, expired or unreadable. */
export function find(stateDir: string, id: string): Entry | null {
  const data = new Store(stateDir).loadHolds();
  return ((data?.holds ?? []).find((h) => h && typeof h === "object" && (h as Entry).id === id) as Entry) ?? null;
}

export const isId = (text: string) => ID.test(text);

const showTime = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

/** `why <hold id>`: the held call's scan as `why` shows any scan, then the hold itself. */
export function whyText(stateDir: string, log: string, id: string, cmd: grants.Cmd = (sub) => `/sentrook-${sub}`): string {
  let rid: string | null = null;
  for (const r of recordsBackward(log)) {
    if (r.kind === "scan" && r.hold && typeof r.hold === "object" && (r.hold as Entry).id === id && typeof r.request_id === "string") {
      rid = r.request_id;
      break;
    }
  }
  const [found] = rid ? recentScans(log, 1, (x) => x === rid) : [];
  if (!found) return `No held call ${id} in the recent traffic log.`;
  const lines = [formatWhy(...found)];
  const waiting = find(stateDir, id);
  if (waiting) {
    const at = readTime(waiting.expires_at);
    lines.push(`hold: waiting, until ${at ? showTime(at) : "?"}`);
    const count = Number(waiting.count ?? 1);
    if (count > 1) lines.push(`held ${count} times since ${clean(waiting.held_at, 20)}`);
    const grant = grants.hintGrant(waiting.hint);
    const trig = (found[0] as Entry)?.planir?.trigger ?? {};
    if (waiting.v !== 2) {
      lines.push(`suggested grant: ${grant ? `${grants.describeGrant(grant)} (persistent, 30 days)` : "none"}`);
    } else {
      const offered: string[] = Array.isArray(waiting.offers) ? waiting.offers : [];
      lines.push(`answers: ${offered.length ? offered.join(", ") : "none offered"}`);
      // an answer never sets a wider grant: the owner may set it by hand
      if (grant) lines.push(`suggested grant: ${grants.describeGrant(grant)}; to set it yourself: ${grants.grantCommand(grant, cmd)}`);
    }
    if (grant && grants.HOST_TASK_KINDS.has(trig.kind)) {
      // nobody asked for this in a chat: say which run did, before the owner approves it
      lines.push(grants.HOLD_CONTEXT.replace("{kind}", trig.kind).replace("{where}", clean(waiting.where ?? "?", 200)));
    }
  } else {
    lines.push("hold: answered or expired");
  }
  return lines.join("\n");
}

// ---- where the notice goes ----------------------------------------------------------------------------

export const NOTIFY_UNSET = "no notify target is set; run /sentrook-notify here from your direct message";

/** The target as status shows it; the recipient id is not shown. */
export function targetText(t: NotifyTarget): string {
  return `a direct message on ${clean(t.channel, 40)}`;
}

export function statusLine(stateDir: string, target: NotifyTarget | null, now: Date): string {
  const count = waiting(stateDir, now);
  let held = count === null ? "holds file unreadable" : `${count} waiting`;
  const again = count ? repeated(stateDir, now) : [];
  if (again.length) {
    const most = again.reduce((a, b) => (Number(b.count ?? 1) > Number(a.count ?? 1) ? b : a));
    held += ` (${most.id} held ${Number(most.count ?? 1)} times since ${clean(most.held_at, 20)})`;
  }
  return `${held}; ${target ? `notices by ${targetText(target)}` : `notices not sent (${NOTIFY_UNSET})`}`;
}

/** The fields of a command context `/sentrook-notify here` reads, as OpenClaw passes them. */
export interface NotifyContext {
  channel?: unknown;
  senderId?: unknown;
  from?: unknown;
  to?: unknown;
  sessionKey?: unknown;
  accountId?: unknown;
  messageThreadId?: unknown;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

/**
 * Whether a command came from a direct message, as far as the context says: OpenClaw names the chat in the session
 * key and the reply address (`...:direct:...` or `user:` for one person, `...:group:...`, `channel:` and the like
 * for many). `unknown` when neither says, as in the agent's main session.
 */
export function chatKindOf(ctx: NotifyContext): "direct" | "group" | "unknown" {
  const said = [ctx.sessionKey, ctx.to, ctx.from].map(str).filter((v): v is string => v !== undefined);
  if (said.some((v) => /(^|:)(group|channel|room|space|thread|topic)(:|$)/i.test(v))) return "group";
  if (said.some((v) => /(^|:)(direct|dm|user)(:|$)/i.test(v))) return "direct";
  return "unknown";
}

/** Channels whose sends take a thread id, as OpenClaw's own device-pair plugin forwards one. */
const THREAD_CHANNELS = new Set(["telegram", "slack"]);

/**
 * The direct-message target of the sender of a command, as OpenClaw's device-pair plugin builds one (`user:<id>` on
 * Discord); a reason it cannot be one otherwise. Only the sender counts: never the chat it was sent in, so a
 * notice never goes to a group. A thread is kept only for a direct message on a channel that takes one.
 */
export function targetOf(ctx: NotifyContext, by: Entry, now: Date): NotifyTarget | string {
  const channel = str(ctx.channel);
  if (!channel || ["webchat", "control-ui", "cli"].includes(channel.toLowerCase())) {
    return "Run /sentrook-notify here as a direct message to the agent on a chat channel: it records that chat as where held-call notices go.";
  }
  const sender = str(ctx.senderId);
  if (!sender) return "OpenClaw did not say who sent this, so there is no one to send notices to; nothing was changed.";
  const kind = chatKindOf(ctx);
  if (kind === "group" || sender.startsWith("channel:")) {
    return "Run /sentrook-notify here in a direct message to the agent, not in a group or channel: notices go to you alone.";
  }
  const to = channel === "discord" && !sender.startsWith("user:") ? `user:${sender}` : sender;
  const raw = ctx.messageThreadId;
  const threadId =
    kind === "direct" && THREAD_CHANNELS.has(channel) && raw !== undefined && raw !== null && raw !== ""
      ? channel === "slack"
        ? String(raw)
        : (raw as string | number)
      : undefined;
  return {
    channel,
    to,
    ...(str(ctx.accountId) ? { accountId: str(ctx.accountId) } : {}),
    ...(threadId !== undefined ? { threadId } : {}),
    set_at: iso(now),
    set_by: by,
  };
}

/** `/sentrook-notify here|off|status`; returns the reply and the change to record (none for status). */
export function runNotify(
  stateDir: string,
  rest: string,
  ctx: NotifyContext,
  by: Entry,
  now: Date,
  beforeWrite: () => void,
): { reply: string; change: Record<string, unknown> | null } {
  const store = new Store(stateDir);
  const op = rest.trim().toLowerCase() || "status";
  const current = store.loadNotify();
  if (op === "status") {
    return {
      reply: current ? `Held-call notices go by ${targetText(current)}.` : `Held-call notices are not sent: ${NOTIFY_UNSET}.`,
      change: null,
    };
  }
  if (op === "off") {
    if (!current) return { reply: "No notify target is set.", change: null };
    beforeWrite();
    store.saveNotify(null);
    return { reply: "Held-call notices are off; held calls still wait for /sentrook-allow or /sentrook-deny.", change: { op: "notify_off", channel: current.channel } };
  }
  if (op !== "here") return { reply: "usage: /sentrook-notify here|off|status", change: null };
  const target = targetOf(ctx, by, now);
  if (typeof target === "string") return { reply: target, change: null };
  beforeWrite();
  store.saveNotify(target);
  return {
    reply: `Held-call notices now go to you by ${targetText(target)}.`,
    change: { op: "notify_here", channel: target.channel, ...(target.accountId ? { account_id: target.accountId } : {}) },
  };
}

/** What a scan needs to send a notice; the host's outbound adapter for a channel. */
export interface Outbound {
  loadAdapter: (channel: string) => Promise<{ sendText?: (req: Record<string, unknown>) => Promise<unknown> } | undefined | null>;
}

/** Sends `text` to `target`; resolves with null when sent, else why not. Never throws. */
export async function deliver(outbound: Outbound | undefined, cfg: unknown, target: NotifyTarget, text: string): Promise<string | null> {
  try {
    if (!outbound?.loadAdapter) return "this OpenClaw has no outbound adapters for plugins";
    const send = (await outbound.loadAdapter(target.channel))?.sendText;
    if (typeof send !== "function") return `no outbound adapter for ${target.channel}`;
    await send({
      cfg,
      to: target.to,
      text,
      ...(target.accountId ? { accountId: target.accountId } : {}),
      ...(target.threadId !== undefined ? { threadId: target.threadId } : {}),
    });
    return null;
  } catch (err) {
    return String(err).replace(/\s+/g, " ").slice(0, 200);
  }
}

/** Notices still being sent, so a test (or a caller shutting down) can wait for them. */
const pending = new Set<Promise<unknown>>();

export function track(p: Promise<unknown>): void {
  pending.add(p);
  void p.finally(() => pending.delete(p));
}

export async function waitForNotices(): Promise<void> {
  await Promise.allSettled([...pending]);
}
