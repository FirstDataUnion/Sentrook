/**
 * Holds: a review on an unattended run waits for the owner instead of being asked of nobody.
 *
 * Nobody can answer a review on a cron job, a heartbeat, a hook or a subagent (the scheduled intent kinds).
 * There the plugin holds the call:
 * - the call does not run, and the agent is told it is held for the owner's approval and must not be retried in
 *   this run (`HELD_TEXT`);
 * - the owner gets one notice as a direct message, on the channel where they ran `/sentrook-notify here`: where
 *   the call was held, the tool and what it does, the block category, the scanner's suggested grant when there
 *   is one, and an approve id;
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

import { BLOCK_CATEGORIES, blockCategory, reviewMessage } from "./decision.ts";
import * as grants from "./grants.ts";
import type { ScanResponse } from "./scanClient.ts";
import { type HoldsFile, type NotifyTarget, readTime, Store } from "./store.ts";

export const HOLD_TTL_MS = 24 * 3600_000;
export const GRANT_TTL_MS = 30 * 24 * 3600_000;
const MAX_HOLDS = 200;
const ID = /^h-[0-9a-f]{6}$/;

export const HELD_TEXT =
  "Sentrook held this tool call for the owner's approval, so it did not run. Do not retry this call in this run.";

type Entry = Record<string, any>;
/** Writes one record to the traffic log. */
export type RecordFn = (record: Record<string, unknown>) => void;

/**
 * The grant the scan response suggests for this call, if any.
 *
 * Grant hints are optional: the scan response does not carry one yet, so every hold is made without one, and
 * approving it sets nothing. A hold stores whatever this returns, and approval reads it with `grants.hintGrant`,
 * which refuses anything that is not a plain grant.
 */
export function grantHint(_resp: ScanResponse): Entry | null {
  return null;
}

const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;

function clean(s: unknown, cap = 200): string {
  return Array.from(String(s), (c) => (/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]|[^\P{Zs} ]/u.test(c) ? "?" : c))
    .slice(0, cap)
    .join("");
}

// ---- the text -----------------------------------------------------------------------------------------

/**
 * The owner's notice. `where` names the job or session, `approve` is the approve command as the owner types it.
 * The review line is the one a review shows; nothing more is added.
 */
export function noticeText(
  resp: ScanResponse,
  tool: string,
  where: string,
  holdId: string,
  hint: unknown,
  approve: string,
): string {
  const grant = grants.hintGrant(hint);
  const relief = grant
    ? `Approving sets a persistent grant for 30 days: ${grants.describeGrant(grant)}, so the next run passes.`
    : "Sentrook suggested no grant for this call, so approving sets nothing; the next run is scanned as before.";
  return [
    `Sentrook held a tool call on an unattended run (${clean(where)}); it did not run.`,
    `Tool: ${clean(tool, 80)}. ${reviewMessage(resp, tool)}`,
    `Held because ${BLOCK_CATEGORIES[blockCategory(resp)]}.`,
    relief,
    `To approve within 24 hours: ${approve} ${holdId}`,
    "The held call is not run again either way.",
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
  const data = store.loadHolds();
  if (data === null) return;
  if (sweepData(data, now, record).changed) store.saveHolds(data);
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
  const data = store.loadHolds();
  if (data === null) return `The holds file ${path.join(stateDir, "holds.json")} could not be read; fix or remove it first.`;
  const found = data.holds.find((h) => live(h, now) && (h as Entry).id === id) as Entry | undefined;
  beforeWrite();
  const { changed, gone } = sweepData(data, now, record);
  if (found) data.holds = data.holds.filter((h) => h !== found);
  if (changed || found) store.saveHolds(data);
  if (!found) {
    if (gone.some((h) => h.id === id)) {
      return `Held call ${id} expired: holds last 24 hours. Nothing was approved; the next run is scanned as before.`;
    }
    return `No held call ${clean(id, 40)}: the id is unknown, already answered or expired.`;
  }
  const grant = grants.hintGrant(found.hint);
  const done = { kind: "resolution", request_id: found.request_id, resolution: "hold_approved", decision: "held", hold_id: id, by };
  if (!grant) {
    record(done);
    return (
      `Approved ${id}. Sentrook suggested no grant for this call, so nothing was set: the next run is scanned as ` +
      `before. To let it pass, add a grant with ${cmd("grant")}. The held call is not run again.`
    );
  }
  const { reply, change } = grants.addSuggested(stateDir, grant, by, now, GRANT_TTL_MS, id, beforeWrite);
  if (!change) {
    record(done);
    return `Approved ${id}, but no grant was set. ${reply}`;
  }
  record({ kind: "grants", ...change, by });
  record({ ...done, grant_id: change.entry.id });
  return `Approved ${id}. ${reply} The held call is not run again; the next run is scanned with this grant.`;
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
  accountId?: unknown;
  messageThreadId?: unknown;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() ? v.trim() : undefined);

/** The direct-message target of the sender of a command, as OpenClaw's device-pair plugin records one. */
export function targetOf(ctx: NotifyContext, by: Entry, now: Date): NotifyTarget | null {
  const channel = str(ctx.channel);
  const to = str(ctx.senderId) ?? str(ctx.from);
  if (!channel || !to || ["webchat", "control-ui", "cli"].includes(channel.toLowerCase())) return null;
  const threadId = typeof ctx.messageThreadId === "number" ? ctx.messageThreadId : str(ctx.messageThreadId);
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
  if (!target) {
    return {
      reply: "Run /sentrook-notify here as a direct message to the agent on a chat channel: it records that chat as where held-call notices go.",
      change: null,
    };
  }
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
