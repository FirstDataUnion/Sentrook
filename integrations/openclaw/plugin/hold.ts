/**
 * Holds: a review on an unattended run waits for the owner instead of being asked of nobody.
 *
 * Nobody can answer a review on a cron job, a heartbeat, a hook or a subagent (the scheduled intent kinds).
 * There the plugin holds the call:
 * - the call does not run, and the agent is told it is held for the owner's approval and must not be retried in
 *   this run (`HELD_TEXT`);
 * - the owner gets one notice as a direct message, on the channel where they ran `/sentrook-notify here`: which
 *   run, the tool and its target as a review names them, the block category, and an approve id. It carries
 *   nothing a steered agent could use (the Hermes plugin's notice can reach the agent's transcript, and both
 *   send the same text); the owner reads the risk, reasons and suggested grant with `/sentrook-why <id>`;
 * - `/sentrook-approve <id>` within 24 hours sets the suggested grant as a persistent grant that ends after 30
 *   days. The held call is not run again; the next run of the job is scanned with the grant. With no suggested
 *   grant, approving sets nothing and the reply says so.
 * - After 24 hours the hold expires and nothing runs. Expiry is found and recorded when the holds are next changed
 *   (a new hold or an approval).
 *
 * A block (at the block line, or one the scanner enforces) is never held, and attended runs are unchanged: a
 * review there is still the host's approval prompt.
 *
 * The traffic log gets the scan with decision `held` and, later, a `resolution` record with resolution
 * `hold_approved` or `hold_expired`, joined by `request_id` as review answers are. Holds are kept in
 * `<state>/sentrook/holds.json` and the notice target in `notify.json`; the Hermes plugin keeps the same holds
 * file and prints the same notice text.
 */

import { randomBytes } from "node:crypto";
import path from "node:path";

import { BLOCK_CATEGORIES, blockCategory, describe } from "./decision.ts";
import { formatWhy, recentScans, recordsBackward } from "./history.ts";
import * as grants from "./grants.ts";
import { OwnerRefused } from "./owner.ts";
import type { ScanResponse } from "./scanClient.ts";
import { type HoldsFile, type NotifyTarget, readTime, Store, withFileLock } from "./store.ts";

export { LockTimeoutError } from "./store.ts";

export const HOLD_TTL_MS = 24 * 3600_000;
export const GRANT_TTL_MS = 30 * 24 * 3600_000;
const MAX_HOLDS = 200;
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
 * The owner's notice: that a call was held, which run, the tool and its target as a review names them, the block
 * category, and the ids and commands. The risk, reason codes, scores and entities are for the owner, through
 * `why`: the same text can reach the agent's own transcript on Hermes.
 */
export function noticeText(resp: ScanResponse, tool: string, where: string, holdId: string, approve: string, why: string): string {
  return [
    "Sentrook held a tool call on an unattended run; it did not run.",
    `Run: ${clean(where, 200)}`,
    `Tool: ${inert(tool, 80)}: ${inert(describe(resp, tool), 160)}`,
    `Held because ${BLOCK_CATEGORIES[blockCategory(resp)]}.`,
    `To approve within 24 hours: ${approve} ${holdId}`,
    `For the reasons: ${why} ${holdId}`,
  ].join("\n");
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
    if (typeof h.request_id === "string") {
      record({ kind: "resolution", request_id: h.request_id, resolution: "hold_expired", decision: "held", hold_id: h.id ?? null });
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
}

/** Stores a new hold and returns its approve id; null when the file cannot be read (still held, not approvable). */
export function create(stateDir: string, hold: NewHold, now: Date, record: RecordFn): string | null {
  return withFileLock(holdsFile(stateDir), () => createLocked(stateDir, hold, now, record));
}

function createLocked(stateDir: string, hold: NewHold, now: Date, record: RecordFn): string | null {
  const store = new Store(stateDir);
  const data = store.loadHolds();
  if (data === null) return null;
  sweepData(data, now, record);
  const taken = new Set(data.holds.map((h) => (h as Entry)?.id));
  let id = `h-${randomBytes(3).toString("hex")}`;
  while (taken.has(id)) id = `h-${randomBytes(3).toString("hex")}`;
  data.holds.push({
    id,
    request_id: hold.requestId,
    session_ref: hold.sessionRef,
    tool: hold.tool,
    where: hold.where,
    held_at: iso(now),
    expires_at: iso(new Date(now.getTime() + HOLD_TTL_MS)),
    hint: hold.hint,
    notice: hold.notice,
  });
  data.holds = data.holds.slice(-MAX_HOLDS);
  store.saveHolds(data);
  return id;
}

/** How many holds wait for the owner; null when the file cannot be read. */
export function waiting(stateDir: string, now: Date): number | null {
  const data = new Store(stateDir).loadHolds();
  return data === null ? null : data.holds.filter((h) => live(h, now)).length;
}

/** `approve <id>`: sets the held call's suggested grant (if any) and records the answer. */
export function approve(
  stateDir: string,
  rest: string,
  by: Entry,
  now: Date,
  cmd: grants.Cmd,
  record: RecordFn,
  beforeWrite: () => void,
): string {
  const id = rest.trim();
  if (!ID.test(id)) return `usage: ${cmd("approve")} <id>, with the id from Sentrook's notice (h- and 6 hex digits)`;
  const store = new Store(stateDir);
  type Outcome =
    | { kind: "unreadable" }
    | { kind: "missing"; expired: boolean }
    | { kind: "kept"; reply: string }
    | { kind: "unsaved"; reply: string; why: string }
    | { kind: "approved"; found: Entry; reply: string; change: grants.Change | null };
  const outcome = withFileLock(holdsFile(stateDir), (): Outcome => {
    const data = store.loadHolds();
    if (data === null) return { kind: "unreadable" };
    const { changed, gone } = sweepData(data, now, record);
    const found = data.holds.find((h) => (h as Entry)?.id === id) as Entry | undefined;
    if (!found) {
      if (changed) {
        beforeWrite();
        store.saveHolds(data);
      }
      return { kind: "missing", expired: gone.some((h) => h.id === id) };
    }
    // The grant first: when it cannot be written, the hold stays and can be approved again.
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
        return { kind: "kept", reply };
      }
    }
    if (change && !change.existing) record({ kind: "grants", ...change, by });
    beforeWrite();
    data.holds = data.holds.filter((h) => h !== found);
    try {
      store.saveHolds(data);
    } catch (err) {
      return { kind: "unsaved", reply, why: clean(String(err), 160) };
    }
    return { kind: "approved", found, reply, change };
  });
  if (outcome.kind === "unreadable") return `The holds file ${holdsFile(stateDir)} could not be read; fix or remove it first.`;
  if (outcome.kind === "missing") {
    return outcome.expired
      ? `Held call ${id} expired: holds last 24 hours. Nothing was approved; the next run is scanned as before.`
      : `No held call ${clean(id, 40)}: the id is unknown, already answered or expired.`;
  }
  if (outcome.kind === "kept") return `Not approved: ${outcome.reply} ${id} is still waiting; approve it again once that is fixed.`;
  if (outcome.kind === "unsaved") {
    return `Not finished: ${outcome.reply} The hold could not be marked answered (${outcome.why}); approve ${id} again to finish.`;
  }
  const { found, reply, change } = outcome;
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

/** The hold with this id while it waits; null when unknown, answered, expired or unreadable. */
export function find(stateDir: string, id: string): Entry | null {
  const data = new Store(stateDir).loadHolds();
  return ((data?.holds ?? []).find((h) => h && typeof h === "object" && (h as Entry).id === id) as Entry) ?? null;
}

export const isId = (text: string) => ID.test(text);

const showTime = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

/** `why <hold id>`: the held call's scan as `why` shows any scan, then the hold itself. */
export function whyText(stateDir: string, log: string, id: string): string {
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
    const grant = grants.hintGrant(waiting.hint);
    lines.push(`suggested grant: ${grant ? `${grants.describeGrant(grant)} (persistent, 30 days)` : "none"}`);
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
  const held = count === null ? "holds file unreadable" : `${count} waiting`;
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
    return { reply: "Held-call notices are off; held calls still wait for /sentrook-approve.", change: { op: "notify_off", channel: current.channel } };
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
