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
 *   - `/sentrook-allow <id>`: a one-use pass for this job and action, bound to a new run of the job, which the plugin
 *     starts now (runNow.ts). The held call itself is never run by the plugin: the job runs again, and the same call
 *     goes through once in that run. When the run ends, the owner gets one line saying what happened
 *     (`passes.outcomeText`). Nothing is started, and the pass waits for the job's next run, when the job cannot be
 *     started now (the reply says why: observe mode, the job gone, finished, disabled, running or changed since the
 *     hold), or when the held run had already sent or written something before the held call (`acted`): a new run
 *     would do that again, so only `/sentrook-allow <id> now` starts it then. A hold is answered once, so it starts
 *     at most one run.
 *   - `/sentrook-allow <id> later`: the same pass, for the job's next run; nothing is started.
 *   - `/sentrook-allow <id> always`: a standing pass for this job and action, for 30 days. Offered only when the
 *     scan's `owner_pass` is `always` and the call names its parties.
 *   - `/sentrook-deny <id>`: a standing denial for this job and action, for 30 days. A matching call is refused with a
 *     plain declined result and no notice.
 *   - `/sentrook-approve <id>` is the same as `/sentrook-allow <id>`, kept for one release.
 *   A hold on another unattended run is bound to where the run came from, when OpenClaw names it (`passes.Source`: a
 *   heartbeat's agent, a webhook's hook, a subagent's parent session): allow is a one-use pass for the next matching
 *   call from that source within 7 days, with nothing started, and allow always and deny are bound to the source. A
 *   run with no source has nothing to bind to: it offers allow only, bound to the call's exact arguments. The notice
 *   lists only the answers the hold offers. A wider grant the scanner suggests is never set by an answer: `why` shows
 *   its command, for the owner to set by hand.
 * - A later hold of the same job (or source) and action, at no higher risk and with no new warning, updates the waiting hold
 *   (its count and when it was last seen) and sends no new notice.
 * - One notice per cron run: the first hold of a run (`runKey`, a sub-agent of the run included) sends the notice and
 *   leads the run's group; a later hold of another action in the same run joins the group (`lead`) and sends nothing
 *   then. When the run ends (`endOfRun`), one line lists the group's holds that no line listed yet, by tool and
 *   description, with their ids (`listed`); holds whose lead was answered or expired first are listed too, with no
 *   `all`. `/sentrook-allow <lead> all` then answers the lead and every hold of its group a line listed, in one started
 *   run: each gets a one-use pass of its own that serves only that run (`run_with`), and is still gated by its own
 *   scan. A hold whose call itself sends or writes (`acts`) is never covered by `all`: it is answered on its own id;
 *   and when a covered call, like the lead, came after its run had sent or written something, nothing is started
 *   (the passes wait for the next run, unless `now`). A hold that joins after its run's line went out gets a notice of
 *   its own. A group of a run that started before the current one and never ended where the plugin could see it gets
 *   its line when the job's next run makes its first hold (`staleGroups`).
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

/** How the notice's run line names a source, before its name. */
const SOURCE_LABELS: Record<passes.SourceKind, string> = {
  heartbeat: "agent",
  hook: "hook",
  subagent: "parent session",
  api: "API key",
};

/**
 * Which run a hold belongs to: a cron job by its id, with its name quoted and labelled as the job's name (whoever
 * made the job chose it, possibly the agent, so it must read as a name, never as an instruction), and `subagent` when
 * a sub-agent of the job's run made the call; else the kind of run and, when the run has a source, the source by its
 * name (quoted, as a job's name is; a parent session by its ref); then the session.
 */
export function whereText(
  run: string,
  sessionRef: string,
  jobId?: string | null,
  jobName?: string | null,
  source?: { kind: string; name: string } | null,
  subagent = false,
): string {
  if (jobId) {
    const name = jobName ? `, job name ${JSON.stringify(inert(jobName, 60))}` : "";
    const by = subagent ? "a sub-agent of " : "";
    return `${by}cron job ${inert(jobId, 40)}${name}, session ${sessionRef}`;
  }
  const label = source ? SOURCE_LABELS[source.kind as passes.SourceKind] : undefined;
  if (source && label) {
    const name = source.kind === "subagent" ? inert(source.name, 40) : JSON.stringify(inert(source.name, 60));
    return `${run}, ${label} ${name}, session ${sessionRef}`;
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
  [passes.ALLOW]: "- run the job again now, letting this call through once: {c} {id}",
  [passes.ALLOW_LATER]: "- let it through once on the job's next scheduled run instead: {c} {id} later",
  [passes.ALLOW_NOW]: "- run the whole job again now, repeating what it already sent or wrote: {c} {id} now",
  [passes.ALLOW_ALWAYS]: "- let this job make this call for 30 days: {c} {id} always",
  [passes.DENY]: "- refuse it on this job for 30 days, with no more notices: {c} {id}",
};
/** allow on a hold whose run had already acted: it waits for the next run (allow now starts one). */
const NEXT_RUN_LINE = "- let this call through once, on the job's next scheduled run: {c} {id}";
/** A hold that is not on a cron job: allow is bound to the exact call. */
const EXACT_LINE = "- let this exact call through once, within 7 days: {c} {id}";
/** A hold bound to a source: the answers name the source by its kind (`{src}`, from SOURCE_NOUNS). */
const SOURCE_LINES: Record<string, string> = {
  [passes.ALLOW]: "- let this call through once more from {src}, within 7 days: {c} {id}",
  [passes.ALLOW_ALWAYS]: "- let {src} make this call for 30 days: {c} {id} always",
  [passes.DENY]: "- refuse it from {src} for 30 days, with no more notices: {c} {id}",
};
const SOURCE_NOUNS: Record<passes.SourceKind, string> = {
  heartbeat: "this agent's heartbeat",
  hook: "this hook",
  subagent: "subagents of the same parent session",
  api: "this API key",
};

/** What a hold's answers are bound to: a cron job, a source of this kind, or nothing (the exact call). */
export type Scope = "job" | passes.SourceKind | null;

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
  scope: Scope = "job",
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
      const noun = scope && scope !== "job" ? SOURCE_NOUNS[scope] : undefined;
      const line = noun
        ? SOURCE_LINES[verb]!.replace("{src}", noun)
        : verb === passes.ALLOW && !scope
          ? EXACT_LINE
          : verb === passes.ALLOW && offers.includes(passes.ALLOW_NOW)
            ? NEXT_RUN_LINE
            : OFFER_LINES[verb]!;
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
  /** Where a run that is not a cron job came from, when OpenClaw names it; its answers are bound to it. */
  source?: passes.Source | null;
  match?: passes.Match | null;
  level?: passes.Level | null;
  offers?: string[];
  /** The call as the notice describes it, for the passes list. */
  description?: string;
  /** The job's definition as `runNow.digest` gives it; null when it could not be read. */
  jobDigest?: string | null;
  /** The held run had sent or written something before the held call. */
  acted?: boolean;
  /** The held run, which never counts as one started for an answer. */
  runKey?: string | null;
  /** The held call itself sends or writes (`passes.acts`): `allow <lead> all` never covers it. */
  acts?: boolean;
}

/**
 * The waiting hold a new hold of the same job (or source) and action repeats: same job or source, same match key, at
 * no higher risk and with no new warning (`passes.covers`). Only holds on a cron job or a source repeat.
 */
function repeatOf(data: HoldsFile, ref: string | null, match: passes.Match | null | undefined): Entry | null {
  if (ref === null || !match) return null;
  return (
    (data.holds.find(
      (h) => !!h && typeof h === "object" && (h as Entry).v === 2 && passes.scopeRef(h as Entry) === ref && passes.covers((h as Entry).match, match),
    ) as Entry | undefined) ?? null
  );
}

/** What `create` did: the hold's id, whether it was a repeat, and the lead of the run's group it joined. */
export interface Created {
  id: string | null;
  repeat: boolean;
  /** Set when the new hold joined its run's group: the lead's id. The caller sends no notice for it. */
  lead?: string;
}

/**
 * Stores a new hold, or counts a repeat of a waiting one (`repeatOf`); returns its id (null when the file cannot be
 * read: still held, not answerable) and whether it was a repeat (no new notice). A new hold of a cron run that already
 * has a waiting lead whose end line has not gone out joins its group (`lead`), and the caller sends no notice.
 */
export function create(stateDir: string, hold: NewHold, now: Date, record: RecordFn): Created {
  return withFileLock(holdsFile(stateDir), () => createLocked(stateDir, hold, now, record));
}

function createLocked(stateDir: string, hold: NewHold, now: Date, record: RecordFn): Created {
  const store = new Store(stateDir);
  const data = store.loadHolds();
  if (data === null) return { id: null, repeat: false };
  sweepData(data, now, record);
  data.version = 2;
  const ref = passes.jobRef(hold.jobId);
  const source = ref === null ? (hold.source ?? null) : null;
  const held = { sid: hold.sid ?? "", request_id: hold.requestId };
  const same = repeatOf(data, ref ?? source?.ref ?? null, hold.match);
  if (same) {
    same.count = Number(same.count ?? 1) + 1;
    same.last_seen_at = iso(now);
    same.held = [...(Array.isArray(same.held) ? same.held : []), held].slice(-MAX_HELD);
    // the job as it was at the first notice (unreadable then: unknown for good, so an edit since still counts as a
    // change), the latest run, and acted when any of its runs had
    // a new run repeats it: that run's other holds join it and get their own end line
    if ((same.run_key ?? null) !== (hold.runKey ?? null)) delete same.end_line_at;
    same.run_key = hold.runKey ?? null;
    same.acted = !!same.acted || !!hold.acted;
    store.saveHolds(data);
    return { id: String(same.id), repeat: true };
  }
  const taken = new Set(data.holds.map((h) => (h as Entry)?.id));
  let id = `h-${randomBytes(3).toString("hex")}`;
  while (taken.has(id)) id = `h-${randomBytes(3).toString("hex")}`;
  const lead = runLead(data, ref, hold.runKey ?? null);
  if (lead) lead.group = [...(Array.isArray(lead.group) ? lead.group : []), id];
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
    source: source ? { kind: source.kind, ref: source.ref, name: source.name } : null,
    match: hold.match ?? {},
    level: hold.level ?? null,
    offers: [...(hold.offers ?? [])],
    held_at: iso(now),
    last_seen_at: iso(now),
    count: 1,
    expires_at: iso(new Date(now.getTime() + HOLD_TTL_MS)),
    hint: hold.hint,
    notice: hold.notice,
    job_digest: hold.jobDigest ?? null,
    acted: !!hold.acted,
    run_key: hold.runKey ?? null,
    acts: !!hold.acts,
    ...(lead ? { lead: lead.id } : {}),
  });
  data.holds = data.holds.slice(-MAX_HOLDS);
  store.saveHolds(data);
  return lead ? { id, repeat: false, lead: String(lead.id) } : { id, repeat: false };
}

// ---- one notice per cron run --------------------------------------------------------------------------

/** A version 2 hold of job `ref` that leads its own group (no `lead` of its own) and whose end line has not gone out. */
function openLead(h: unknown, ref: string): h is Entry {
  return (
    !!h &&
    typeof h === "object" &&
    (h as Entry).v === 2 &&
    (h as Entry).job_ref === ref &&
    !(h as Entry).lead &&
    !(h as Entry).end_line_at
  );
}

/**
 * The waiting hold that leads cron run `runKey` of job `ref`: the run's first hold, whose end line has not gone out
 * yet. Null off a cron job, without a run key, or when the run has no lead.
 */
function runLead(data: HoldsFile, ref: string | null, runKey: string | null): Entry | null {
  if (!ref || !runKey) return null;
  return (data.holds.find((h) => openLead(h, ref) && h.run_key === runKey) as Entry | undefined) ?? null;
}

/** The waiting holds that joined the group of lead `leadId` (of job `ref`) and no end line has listed yet. */
function unlisted(data: HoldsFile, leadId: unknown, ref: unknown): Entry[] {
  return data.holds.filter(
    (h): h is Entry => !!h && typeof h === "object" && (h as Entry).v === 2 && (h as Entry).lead === leadId && (h as Entry).job_ref === ref && !(h as Entry).listed,
  );
}

/** Every waiting hold of `lead`'s group (same lead id and job), listed or not. */
function groupOf(data: HoldsFile, lead: Entry): Entry[] {
  return data.holds.filter(
    (h): h is Entry => !!h && typeof h === "object" && (h as Entry).v === 2 && (h as Entry).lead === lead.id && (h as Entry).job_ref === lead.job_ref,
  );
}

/**
 * A group to list: the lead (or what is left of it, `{id, job_id, job_ref}`, when it was answered or expired first),
 * the holds to list, and whether `all` is offered (only while the lead waits).
 */
export type Group = [lead: Entry, members: Entry[], canAll: boolean];

/** Marks `members` listed; copies of them. */
function list(members: Entry[]): Entry[] {
  for (const m of members) m.listed = true;
  return members.map((m) => ({ ...m }));
}

/**
 * Marks `lead`'s end line as sent and its unlisted holds as listed (`shown` on the lead); the group to list, or null
 * when there is nothing to list.
 */
function closeGroup(data: HoldsFile, lead: Entry, now: Date): Group | null {
  lead.end_line_at = iso(now);
  const members = unlisted(data, lead.id, lead.job_ref);
  if (!members.length) return null;
  lead.shown = [...(Array.isArray(lead.shown) ? lead.shown : []), ...members.map((m) => m.id)];
  return [{ ...lead }, list(members), true];
}

/**
 * The unlisted holds of job `ref` whose lead no longer waits (answered or expired before the run's end line), for
 * which `keep` holds, grouped by their lead: they are listed too, with no `all` (nothing leads them now).
 */
function orphans(data: HoldsFile, ref: string, keep: (h: Entry) => boolean): Group[] {
  const waiting = new Set(data.holds.filter((h): h is Entry => !!h && typeof h === "object").map((h) => h.id));
  const byLead = new Map<string, Entry[]>();
  for (const h of data.holds) {
    if (!h || typeof h !== "object") continue;
    const e = h as Entry;
    if (e.v !== 2 || e.job_ref !== ref || !e.lead || waiting.has(e.lead) || e.listed || !keep(e)) continue;
    const key = String(e.lead);
    byLead.set(key, [...(byLead.get(key) ?? []), e]);
  }
  return [...byLead].map(([lead, members]): Group => [{ id: lead, job_id: members[0]!.job_id ?? null, job_ref: ref }, list(members), false]);
}

/**
 * Cron run `runKey` of job `ref` ended: its group's end line is due. Returns each group to list (`endLineText`), now
 * marked listed; [] when the run had no group or nothing more was held. Holds whose lead was answered or expired first
 * are listed too (`orphans`).
 */
export function endOfRun(stateDir: string, ref: string | null, runKey: string | null, now: Date): Group[] {
  if (!ref || !runKey) return [];
  return withFileLock(holdsFile(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadHolds();
    if (data === null) return [];
    const out: Group[] = [];
    for (const h of data.holds) {
      if (!openLead(h, ref) || h.run_key !== runKey) continue;
      const closed = closeGroup(data, h, now);
      if (closed) out.push(closed);
    }
    out.push(...orphans(data, ref, (h) => h.run_key === runKey));
    store.saveHolds(data);
    return out;
  });
}

/**
 * The groups of job `ref`'s runs that started before run `runKey` (started at `startedAt`) and whose end was never
 * seen: their end lines are due before that run makes its first notice. A run that started later (one still going
 * while a late call of an earlier run is held) is left alone; so is everything when the run's start is unknown. Same
 * shape as `endOfRun`.
 */
export function staleGroups(stateDir: string, ref: string | null, runKey: string | null, startedAt: Date | null, now: Date): Group[] {
  if (!ref || !runKey || startedAt === null) return [];
  const earlier = (h: Entry): boolean => {
    const at = readTime(h.held_at);
    return h.run_key != null && h.run_key !== runKey && at !== null && at.getTime() < startedAt.getTime();
  };
  return withFileLock(holdsFile(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadHolds();
    if (data === null) return [];
    const out: Group[] = [];
    for (const h of data.holds) {
      if (!openLead(h, ref) || !(Array.isArray(h.group) && h.group.length) || !earlier(h)) continue;
      const closed = closeGroup(data, h, now);
      if (closed) out.push(closed);
    }
    out.push(...orphans(data, ref, earlier));
    if (out.length) store.saveHolds(data);
    return out;
  });
}

/**
 * The run's end line and the replies to `allow <lead> all`; the shared fixture's `run_group` (shared with the Hermes
 * plugin).
 */
export const RUN_GROUP: Record<string, string> = {
  head: "Sentrook: the run of cron job {job} that held {lead} also held {n} other call(s); none of them ran:",
  item: "- {id}: {tool}: {description}{own}",
  own_answer: " (it sends or writes: answer it on its own)",
  all: "Let {lead} and the calls listed here through once, in one new run of the job: {allow} {lead} all",
  each: "Or answer each by its id: {allow} <id>, {deny} <id>. For the reasons: {why} <id>",
  covered: "In that run, these listed calls may also go through once: {ids}.",
  left: "Not covered, answer each on its own: {ids}.",
  none_listed: "No other call of this run has been listed yet, so this answers {lead} alone.",
  not_lead:
    "{id} is one of the calls held in the run that {lead} leads: answer it on its own id, or all of them with " +
    "{allow} {lead} all.",
};

/**
 * The run's end line: the holds of `lead`'s group no line listed yet, each by its id, tool and description (as the
 * notice shows them, and no more), and how to answer them. `all` is offered only while the lead waits (`canAll`) and
 * at least one listed call does not itself send or write (`acts`) and offers allow.
 */
export function endLineText(lead: Entry, members: Entry[], cmd: (verb: string) => string, canAll = true): string {
  const t = RUN_GROUP;
  const lines = [passes.fill(t.head!, { job: inert(lead.job_id, 40), n: String(members.length), lead: String(lead.id) })];
  for (const m of members) {
    lines.push(
      passes.fill(t.item!, {
        id: String(m.id),
        tool: inert(m.tool, 80),
        description: inert(m.description, 160),
        own: m.acts ? t.own_answer! : "",
      }),
    );
  }
  if (canAll && members.some((m) => !m.acts && Array.isArray(m.offers) && m.offers.includes(passes.ALLOW))) {
    lines.push(passes.fill(t.all!, { allow: cmd("allow"), lead: String(lead.id) }));
  }
  lines.push(passes.fill(t.each!, { allow: cmd("allow"), deny: cmd("deny"), why: cmd("why") }));
  return lines.join("\n");
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

/** Why allow did not start the job now (runNow.ts); the shared fixture's `run_now.reasons`. */
export const RUN_NOW_REASONS: Record<string, string> = {
  observe: "Sentrook is in observe mode",
  unknown: "Sentrook could not read the job, so it cannot check that the job is unchanged since the hold",
  missing: "the job no longer exists",
  paused: "the job is paused",
  terminal: "the job has finished and is not scheduled to run again",
  running: "the job is running now, or a run started for an earlier answer has not finished",
  changed: "the job was changed since the call was held",
  acted: "the held run had already sent or written something before this call, and a new run would do it again",
  unavailable: "Sentrook cannot start the job from here",
  failed: "starting it failed",
};
/** The owner's reply to allow on a cron job's hold; the shared fixture's `run_now.replies`. */
export const RUN_NOW_REPLIES: Record<string, string> = {
  started: "Running job {job} again now; this call will be let through once in that run. Undo: {passes} revoke {pass}.",
  started_now:
    "Running job {job} again now; this call will be let through once in that run. The whole job runs again, so " +
    "what it already sent or wrote before this call happens again. Undo: {passes} revoke {pass}.",
  later:
    "Job {job} may make this call once, on its next scheduled run, until {until}. Sentrook does not run the held " +
    "call itself. Undo: {passes} revoke {pass}.",
  fallback:
    "Job {job} may make this call once, on its next scheduled run, until {until}. It was not run again now: " +
    "{reason}. Undo: {passes} revoke {pass}.",
};
/** The owner's line when a run started for an answer ends; the shared fixture's `run_now.outcomes`. */
export const OUTCOMES: Record<string, string> = {
  passed: "Sentrook: cron job {job} ran again, and the call you allowed went through once.",
  passed_held:
    "Sentrook: cron job {job} ran again, and the call you allowed went through once. It also made a different " +
    "call, held as {hold}.",
  held:
    "Sentrook: cron job {job} ran again but did not make the call you allowed; it made a different call, held " +
    "as {hold}.",
  none: "Sentrook: cron job {job} ran again without using your answer.",
};

/**
 * What answer needs to start a held call's job again (runNow.Adapter): `guard(hold)`, why it may not be started now
 * or null; `start(hold)`, whether it started, OpenClaw's run id for it, and why not (`unavailable` when this process
 * has no way to start it).
 */
export interface RunNow {
  guard(hold: Entry): string | null;
  start(hold: Entry): Promise<{ started: boolean; runId: string | null; why: string }>;
}

/** The source a version 2 hold off a cron job is bound to, or null. */
export function sourceOfHold(found: Entry): { kind: string; ref: string; name: string } | null {
  const src = found.job_ref ? null : found.source;
  return src && typeof src === "object" && typeof src.ref === "string" && src.ref ? (src as { kind: string; ref: string; name: string }) : null;
}

/** Who makes the calls a hold's answer is bound to, to start the owner's reply: the job, else the source. */
export function subjectOf(found: Entry): string {
  const src = sourceOfHold(found);
  if (!src) return `Job ${clean(found.job_id, 40)}`;
  const text = passes.sourceText(src.kind, src.name);
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** A hold with nothing to bind an answer to beyond the exact call. */
const UNBOUND = "comes from a run with no cron job or other source Sentrook can bind an answer to";

/** Why a hold does not offer the answer `want`; the hold keeps waiting. */
function refusal(found: Entry, want: string, id: string, cmd: grants.Cmd): string {
  const onJob = !!found.job_ref;
  const src = sourceOfHold(found);
  const level = found.level ?? null;
  const why = `${cmd("why")} ${id} shows the reasons`;
  if (want === passes.DENY) {
    return `Not set: ${id} ${UNBOUND}, so there is nothing to refuse it for. Leave it and it expires; the call never runs.`;
  }
  if (level === null) {
    const on = onJob ? "on this job" : src ? `from ${passes.sourceText(src.kind, src.name)}` : null;
    const alt = on ? `${cmd("deny")} ${id} refuses it ${on} with no more notices; ` : "leave it and it expires; ";
    return `Not allowed: Sentrook does not offer to let this call through. ${alt}${why}.`;
  }
  if (!onJob && !src) {
    return `Not set: ${id} ${UNBOUND}, so it cannot be let through for good. ${cmd("allow")} ${id} lets this exact call through once.`;
  }
  if (level !== "always") {
    return (
      "Not set: Sentrook offers to let this call through on every run only when it judges that safe, and for this one " +
      `it offers it once. ${cmd("allow")} ${id} lets it through once.`
    );
  }
  if (!found.match?.named) {
    return `Not set: this call names nothing a standing pass could be bound to, so only a one-time pass bound to its exact arguments is offered: ${cmd("allow")} ${id}.`;
  }
  return `Not set: this call scored at the block line, so it can only be let through once: ${cmd("allow")} ${id}.`;
}

/**
 * (hold id, answer, mode) from `allow <id> [now|later|always|all]`, `approve <id>` or `deny <id>`; null when malformed.
 * The mode is `now`, `later`, `all` (the run's group, `answer`) or "" for an allow once.
 */
function parseAnswer(verb: string, rest: string): [string, string, string] | null {
  const words = rest.trim().split(/\s+/).filter(Boolean);
  if (!words.length || !ID.test(words[0]!)) return null;
  if (verb === "deny") return words.length === 1 ? [words[0]!, passes.DENY, ""] : null;
  const mode = (words[1] ?? "").toLowerCase();
  if (words.length > 2 || !["", "now", "later", "once", "always", "all"].includes(mode)) return null;
  if (mode === "always") return [words[0]!, passes.ALLOW_ALWAYS, ""];
  return [words[0]!, passes.ALLOW, mode === "once" ? "" : mode];
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
 * `allow <id> [now|later|always|all]`, `approve <id>` or `deny <id>`: sets the pass or denial the hold offers, removes the
 * hold and records the answer; the reply says what was set and how to undo it. On a cron job's hold, allow also starts
 * the job again now through `runNow` unless a guard applies (see the module note). The caller sets the held calls'
 * history (`Answered.held`).
 */
export async function answer(
  stateDir: string,
  verb: "allow" | "deny" | "approve",
  rest: string,
  by: Entry,
  now: Date,
  cmd: grants.Cmd,
  record: RecordFn,
  beforeWrite: () => void,
  runNow: RunNow | null = null,
): Promise<Answered> {
  const none = (reply: string): Answered => ({ reply, held: [], decision: null });
  const parsed = parseAnswer(verb, rest);
  if (!parsed) {
    const form = verb === "deny" ? `${cmd("deny")} <id>` : verb === "approve" ? `${cmd("approve")} <id>` : `${cmd("allow")} <id> [now|later|always|all]`;
    return none(`usage: ${form}, with the id from Sentrook's notice (h- and 6 hex digits)`);
  }
  const [id, want, mode] = parsed;
  const store = new Store(stateDir);
  /** Whether this answer starts the job again now, else why not (null: not asked to, `later`, or not a job). */
  let start = false;
  let whyNot: string | null = null;
  type Outcome = { done: string } | { found: Entry; entry: Entry; group: Array<[Entry, Entry]>; left: string[] };
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
    if (mode === "all" && found.lead) {
      save();
      return { done: passes.fill(RUN_GROUP.not_lead!, { id, lead: String(found.lead), allow: cmd("allow") }) };
    }
    if (!(Array.isArray(found.offers) ? found.offers : []).includes(want)) {
      save();
      return { done: refusal(found, want, id, cmd) };
    }
    // `all`: the waiting holds of this lead's group an end line listed, that offer allow and whose call does not itself
    // send or write
    const covered =
      mode === "all" ? groupOf(data, found).filter((m) => m.listed && !m.acts && Array.isArray(m.offers) && m.offers.includes(passes.ALLOW)) : [];
    if (want === passes.ALLOW && found.job_ref && mode !== "later") {
      try {
        whyNot = runNow ? runNow.guard(found) : "unavailable";
      } catch {
        whyNot = "unknown";
      }
      // a covered call that came after its run had acted counts as the lead's would
      if (whyNot === null && (found.acted || covered.some((m) => m.acted)) && mode !== "now") whyNot = "acted";
      start = whyNot === null;
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
          runBound: start,
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
    const { group, left } =
      mode === "all" ? allowGroup(stateDir, store, data, found, covered, by, now, beforeWrite, start ? String(entry.id) : null) : { group: [], left: [] };
    return { found, entry, group, left };
  });
  if ("done" in outcome) return none(outcome.done);
  const { found, entry, group, left } = outcome;
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
    ...(entry.source_ref ? { source_kind: entry.source_kind ?? null, source_ref: entry.source_ref } : {}),
    hold_id: id,
    expires_at: entry.expires_at,
    by,
  });
  for (const h of held) {
    record({ kind: "resolution", request_id: h.request_id, resolution, decision: "held", hold_id: id, pass_id: entry.id, by });
  }
  for (const [member, memberEntry] of group) {
    held.push(...recordGroupAnswer(member, memberEntry, by, record));
  }
  const groupNote = groupNoteOf(mode, found, group, left);
  const until = readTime(entry.expires_at);
  const shown = until ? passes.show(until) : "?";
  const job = subjectOf(found);
  const undo = `Undo: ${cmd("passes")} revoke ${entry.id}.`;
  const decision = want === passes.DENY ? "denied_by_user" : "approved_by_user";
  let reply: string;
  if (want === passes.DENY) reply = `${job} will not make this call until ${shown}; you won't be told again. ${undo}`;
  else if (want === passes.ALLOW_ALWAYS) reply = `${job} may make this call until ${shown}. ${undo}`;
  else if (!found.job_ref && sourceOfHold(found)) {
    reply = `${job} may make this call once more, until ${shown}. Sentrook does not run the held call itself. ${undo}`;
  } else if (!found.job_ref) {
    reply = `The next identical call from an unattended run may go through once, until ${shown}. Sentrook does not run the held call itself. ${undo}`;
  } else {
    if (start && runNow) {
      let got: { started: boolean; runId: string | null; why: string };
      try {
        got = await runNow.start(found);
      } catch (err) {
        got = { started: false, runId: null, why: clean(String(err), 200) };
      }
      try {
        if (got.started) passes.started(stateDir, entry.id, got.runId);
        else passes.notStarted(stateDir, entry.id);
      } catch {
        // the pass stands as set
      }
      if (!got.started) whyNot = got.why !== "failed" && Object.hasOwn(RUN_NOW_REASONS, got.why) ? got.why : "failed";
      record({
        kind: "run_now",
        op: "start",
        hold_id: id,
        pass_id: entry.id,
        job_ref: entry.job_ref ?? null,
        started: got.started,
        ...(got.runId ? { run_id: got.runId } : {}),
        ...(got.started ? {} : { reason: whyNot, detail: clean(got.why, 200) }),
        by,
      });
    } else if (whyNot !== null) {
      record({ kind: "run_now", op: "start", hold_id: id, pass_id: entry.id, job_ref: entry.job_ref ?? null, started: false, reason: whyNot, by });
    }
    const fields = { job: clean(found.job_id, 40), pass: String(entry.id), passes: cmd("passes"), until: shown };
    if (start && whyNot === null) reply = passes.fill(RUN_NOW_REPLIES[found.acted ? "started_now" : "started"]!, fields);
    else if (whyNot === null) reply = passes.fill(RUN_NOW_REPLIES.later!, fields);
    else reply = passes.fill(RUN_NOW_REPLIES.fallback!, { ...fields, reason: RUN_NOW_REASONS[whyNot]! });
    reply += groupNote;
  }
  return { reply, held: held.filter((h) => !!h.sid), decision };
}

/**
 * `allow <lead> all`: a one-use job pass for each hold in `covered` (listed, offering allow, not `acts`), which serves
 * only the run started for the lead's pass (`runWith`; with no run started, the job's next run, as the lead's own
 * pass). The holds are marked answered first, so a failure never leaves two passes for one hold; a hold whose pass
 * could not be set goes back. Returns ((hold, pass) for each answered, the listed ids left for their own answer).
 * Called with the holds file locked, after the lead's own pass.
 */
function allowGroup(
  stateDir: string,
  store: Store,
  data: HoldsFile,
  lead: Entry,
  covered: Entry[],
  by: Entry,
  now: Date,
  beforeWrite: () => void,
  runWith: string | null,
): { group: Array<[Entry, Entry]>; left: string[] } {
  const left = groupOf(data, lead)
    .filter((m) => m.listed && !covered.includes(m))
    .map((m) => String(m.id));
  if (!covered.length) return { group: [], left };
  data.holds = data.holds.filter((h) => !covered.includes(h as Entry));
  try {
    beforeWrite();
    store.saveHolds(data);
  } catch {
    // nothing set for them; they keep waiting
    data.holds.push(...covered);
    return { group: [], left: [...left, ...covered.map((m) => String(m.id))] };
  }
  const group: Array<[Entry, Entry]> = [];
  const back: Entry[] = [];
  for (const m of covered) {
    let got: Entry | null = null;
    try {
      got = passes.add(stateDir, { kind: "allow", uses: "once", level: "once", hold: m, by, now, runWith }, beforeWrite);
    } catch {
      got = null; // it goes back to waiting
    }
    if (got) group.push([m, got]);
    else back.push(m);
  }
  if (back.length) {
    data.holds.push(...back);
    try {
      store.saveHolds(data);
    } catch {
      // those holds are gone with no pass: held again on the next run
    }
    left.push(...back.map((m) => String(m.id)));
  }
  return { group, left };
}

/** Records the pass `allow <lead> all` set for a listed hold and its held calls' resolution; returns those calls. */
function recordGroupAnswer(member: Entry, entry: Entry, by: Entry, record: RecordFn): HeldCall[] {
  record({
    kind: "passes",
    op: "add",
    id: entry.id,
    pass_kind: entry.kind,
    uses: entry.uses,
    job_ref: entry.job_ref ?? null,
    hold_id: member.id,
    group_lead: member.lead ?? null,
    expires_at: entry.expires_at,
    by,
  });
  const held: HeldCall[] = (Array.isArray(member.held) && member.held.length ? member.held : [{ sid: "", request_id: member.request_id }]).filter(
    (h: Entry): h is HeldCall => !!h && typeof h.request_id === "string",
  );
  for (const h of held) {
    record({ kind: "resolution", request_id: h.request_id, resolution: "hold_allowed", decision: "held", hold_id: member.id, pass_id: entry.id, by });
  }
  return held;
}

/** What `allow <lead> all` adds to the reply: the listed calls it covered and those left for their own answer. */
function groupNoteOf(mode: string, lead: Entry, group: Array<[Entry, Entry]>, left: string[]): string {
  if (mode !== "all") return "";
  if (!(Array.isArray(lead.shown) && lead.shown.length)) return ` ${passes.fill(RUN_GROUP.none_listed!, { lead: String(lead.id) })}`;
  let note = "";
  if (group.length) note += ` ${passes.fill(RUN_GROUP.covered!, { ids: group.map(([m]) => String(m.id)).join(", ") })}`;
  if (left.length) note += ` ${passes.fill(RUN_GROUP.left!, { ids: left.join(", ") })}`;
  return note;
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
