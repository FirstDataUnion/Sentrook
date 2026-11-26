/**
 * Snooze: the owner's relief from review prompts, kept in `<state>/sentrook/snooze.json`.
 *
 * A snooze covers the session the command was sent from, or every session with `--all`, for a
 * duration from 1 minute to 24 hours (default 1 hour). While one applies, a review the plugin would
 * ask about is allowed instead; the call is still scanned and its traffic record says `snoozed: true`.
 * A snooze never allows:
 * - a block, or a block it turned into a review;
 * - a review the scanner enforces (`enforced` is review or block);
 * - any run not started by a human message (cron, heartbeat, subagent, hook, or a trigger the plugin
 *   could not tell), where the review stands;
 * - a scan error, or observe mode.
 *
 * In a chat the owner attends, a snooze also turns a block the scanner marks `relaxable` (the owner
 * attends, nothing independent points to an attack and nothing is enforced: the score alone blocks) into
 * a review that always asks, at critical severity; it is never allowed silently.
 *
 * Beta (`BLOCKS_ASK`): in a chat the owner attends, a snooze turns every other block into such a review too: a block
 * with a floor, a strong signal or `enforced: block`, from an older scanner too. Its card warns, naming the reason it
 * would be blocked, and says to allow it only for exactly the call the owner asked for; it offers Allow once and Deny
 * only. Only a fully informed scan asks (`informed`: status ok and the rule-based probe answered); without it a block
 * stays a block, since a change to Sentrook itself is found by that probe. While a snooze is on, a review of an action
 * the session was asked about this way asks again with the same warning (`askedBefore`), never snoozed through.
 * Attended here is what the scanner's attended-owner check reads from the request (`ownerAttends`): the owner's
 * own message on the main agent, outside a group chat or a host open to anyone, on a chat the plugin could tell apart.
 * A change to Sentrook itself (a `guardrail_tampering` floor that blocks: a write into its state folder, turning the
 * plugin off, a Sentrook command only the owner runs) stays a block: a snooze is never a way for the agent to switch
 * Sentrook off. With `BLOCKS_ASK` off, only a block marked `relaxable` asks.
 *
 * A session is named by its `session_ref`, the same hash a scan sends. A command with no current
 * session (the command line) can only snooze every session.
 *
 * Expiry is mandatory: an entry with no readable expiry, or one more than 24 hours away, never applies.
 * A file that cannot be read relaxes nothing and is never overwritten. Expired entries are dropped on
 * the next change. A change holds the file's cross-process lock, because the gateway and the command line can
 * change it at the same time; when another process keeps the lock longer than the wait, nothing is changed and
 * the owner is told to try again. Every change is written to the traffic log as a `snooze` record (none when the
 * owner has turned the traffic log off). The Hermes plugin keeps the same file format and prints the
 * same text.
 */

import path from "node:path";

import type { Cmd, Entry } from "./grants.ts";
/** What an entry is keyed on. */
export { sessionRef } from "./planir.ts";
import { LockTimeoutError, readTime, type SnoozeFile, Store, withFileLock } from "./store.ts";

const MINUTE = 60_000;
const DEFAULT_MS = 3600_000;
const MAX_MS = 24 * 3600_000;
const MAX_ENTRIES = 200;
const DURATION = /^(\d{1,5})([mh])$/;
/**
 * Beta: during a snooze, every block in a chat the owner attends asks, with a warning, except a change to Sentrook
 * itself. False: only a block the scanner marks `relaxable` asks; every other block stays a block.
 */
export const BLOCKS_ASK: boolean = true;
export const RULE = BLOCKS_ASK
  ? "A snoozed review is allowed and logged. In beta, a block in a chat you attend asks you instead, with a warning; " +
    "a change to Sentrook itself stays blocked, and enforced reviews and unattended runs are never snoozed."
  : "A snoozed review is allowed and logged. A block with no clear attack signal asks you instead; " +
    "other blocks, enforced reviews and unattended runs are never snoozed.";
/** The tail of the reply to a snooze that was set. */
const SET_RULE = BLOCKS_ASK
  ? "In beta, blocks in a chat you attend ask you instead, with a warning; changes to Sentrook itself stay blocked, " +
    "and enforced reviews and unattended runs are not snoozed."
  : "Blocks with no clear attack signal ask you instead; other blocks, enforced reviews and unattended runs are not snoozed.";
/** Sender bases of a room others can write to, and bases that say nothing about how the sender was known. */
const SHARED_BASIS = new Set(["group_chat", "host_open_access"]);
const NO_BASIS = new Set(["none", "unknown"]);
/** How many actions a session remembers it asked about with the strong warning (`noteAsked`). */
export const ASKED_MAX = 50;

/** A change to write to the traffic log, with the reply. */
export interface SnoozeResult {
  reply: string;
  change: { op: "set"; entry: Entry } | { op: "off"; entries: Entry[] } | null;
}

export function load(stateDir: string): SnoozeFile | null {
  return new Store(stateDir).loadSnooze();
}

export const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;
const show = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

function left(ms: number): string {
  const minutes = Math.max(1, Math.ceil(ms / MINUTE));
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return [h ? `${h}h` : "", m ? `${m}m` : ""].filter(Boolean).join(" ");
}

function clean(s: unknown, cap = 40): string {
  return Array.from(String(s), (c) => (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(c) ? "?" : c))
    .slice(0, cap)
    .join("");
}

/** The entry's expiry while it applies: a known scope and an expiry within the next 24 hours. */
function live(e: unknown, now: Date): Date | null {
  if (!e || typeof e !== "object" || Array.isArray(e)) return null;
  const x = e as Entry;
  if (x.scope === "session") {
    if (typeof x.session_ref !== "string" || !x.session_ref) return null;
  } else if (x.scope !== "all") return null;
  const at = readTime(x.expires_at);
  return at && at.getTime() > now.getTime() && at.getTime() <= now.getTime() + MAX_MS ? at : null;
}

function entries(data: SnoozeFile | null, now: Date): Array<[Entry, Date]> {
  const out: Array<[Entry, Date]> = [];
  for (const e of data?.snoozes ?? []) {
    const at = live(e, now);
    if (at) out.push([e as Entry, at]);
  }
  return out;
}

const appliesTo = (e: Entry, ref: string | null) => e.scope === "all" || (ref !== null && e.session_ref === ref);

/** Whether a snooze covers the session `ref` now. */
export function active(data: SnoozeFile | null, ref: string, now: Date): boolean {
  return entries(data, now).some(([e]) => appliesTo(e, ref));
}

/** A snooze may relax this review: the scanner did not enforce it. */
/**
 * A snooze may relax this review: the scanner did not enforce it, and its score is under the block line (a block
 * the scanner's ceiling lowered to a review always asks).
 */
export function applies(resp: { enforced?: string | null; risk?: number | null }, blockAt: number): boolean {
  if (resp.enforced === "review" || resp.enforced === "block") return false;
  return (resp.risk ?? 0) < blockAt;
}

/**
 * A snooze in a chat the owner attends turns this block into a review that always asks: the block comes from the
 * score and the scanner marks it `relaxable` (only a JSON true counts; an older scanner sends none).
 */
export function relaxes(resp: { enforced?: string | null; relaxable?: unknown }, verdict: string): boolean {
  return verdict === "block" && resp.relaxable === true && resp.enforced !== "review" && resp.enforced !== "block";
}

/**
 * The owner is in the conversation, as the scanner's attended-owner check reads the request: a message turn from the
 * owner on the main agent, outside a group chat or a host open to anyone, on a basis that says how the plugin knows
 * (not `none` alone), and no host background process behind the call (`self_edit`).
 */
export function ownerAttends(planir: any): boolean {
  const trig = planir?.trigger && typeof planir.trigger === "object" ? planir.trigger : {};
  const sender = trig.sender && typeof trig.sender === "object" ? trig.sender : {};
  const basis: string[] = Array.isArray(sender.basis) ? sender.basis.filter((b: unknown) => typeof b === "string") : [];
  return (
    trig.kind === "message" &&
    sender.relation === "owner" &&
    planir?.session?.agent_role === "main" &&
    !basis.some((b) => SHARED_BASIS.has(b)) &&
    basis.some((b) => !NO_BASIS.has(b)) &&
    (planir?.self_edit ?? null) === null
  );
}

/**
 * The call changes Sentrook itself at the blocking tier: a `guardrail_tampering` floor that does not only ask
 * (`enforce` review), or a reason that says so. The guardrail's review tier is not this: it asks already.
 */
export function tampering(resp: { floors_applied?: unknown; reasons?: unknown }): boolean {
  const floors: unknown = resp.floors_applied;
  for (const f of Array.isArray(floors) ? floors : []) {
    if (f && typeof f === "object" && (f as any).floor === "guardrail_tampering" && (f as any).enforce !== "review") return true;
  }
  const reasons: unknown = resp.reasons;
  for (const r of Array.isArray(reasons) ? reasons : []) {
    const code: unknown = r && typeof r === "object" ? (r as any).code : undefined;
    if (typeof code !== "string") continue;
    if (code === "floor.guardrail_tampering") {
      const detail: unknown = (r as any).detail;
      const behind: unknown = detail && typeof detail === "object" ? (detail as any).reason : undefined;
      if (!(typeof behind === "string" && behind.endsWith("_review"))) return true;
    } else if (code.startsWith("guardrail.") && !code.endsWith("_review")) return true;
  }
  return false;
}

/**
 * The scan is complete: status `ok` and the rule-based probe (`aira`, which finds a change to Sentrook itself)
 * answered `ok` in `metadata.probes`. A response that does not say reads as not informed.
 */
export function informed(resp: { status?: unknown; metadata?: unknown }): boolean {
  if (resp.status !== "ok") return false;
  const meta: any = resp.metadata && typeof resp.metadata === "object" ? resp.metadata : {};
  const probes: unknown[] = Array.isArray(meta.probes) ? meta.probes : [];
  return probes.some((p: any) => p && typeof p === "object" && p.step === "aira" && p.status === "ok");
}

const fingerprintOf = (resp: { action_fingerprint?: unknown }): string | null =>
  typeof resp.action_fingerprint === "string" && resp.action_fingerprint ? resp.action_fingerprint : null;

/** Remember in the session that its owner was asked about this action with the strong warning (the last `ASKED_MAX`). */
export function noteAsked(sess: { snoozeAsked?: string[] }, resp: { action_fingerprint?: unknown }): void {
  const fp = fingerprintOf(resp);
  if (fp === null) return;
  const kept = (Array.isArray(sess.snoozeAsked) ? sess.snoozeAsked : []).filter((x) => typeof x === "string" && x !== fp);
  sess.snoozeAsked = [...kept, fp].slice(-ASKED_MAX);
}

/**
 * The session's owner was asked about this action with the strong warning (`noteAsked`): a review of it again, say
 * one the scanner scored lower after the owner allowed it once, asks the same way and is never snoozed.
 */
export function askedBefore(sess: { snoozeAsked?: string[] }, resp: { action_fingerprint?: unknown }): boolean {
  const fp = fingerprintOf(resp);
  return fp !== null && Array.isArray(sess.snoozeAsked) && sess.snoozeAsked.includes(fp);
}

/**
 * What a snooze in a session on a run the owner attends does with this verdict: `relaxed` for a block the scanner
 * marks `relaxable` (today's question), `strong` for any other block in the owner's own chat (`BLOCKS_ASK`; the card
 * warns and nothing allows it silently), null where it stays as it is (not a block, a change to Sentrook itself, a
 * scan that is not fully informed, another sender or a shared room, or `BLOCKS_ASK` off). The caller checks the
 * snooze, the run and the mode.
 */
export function asks(resp: Record<string, any>, verdict: string, planir: any, blocksAsk: boolean = BLOCKS_ASK): "relaxed" | "strong" | null {
  if (verdict !== "block") return null;
  if (relaxes(resp, verdict)) return "relaxed";
  if (blocksAsk && informed(resp) && !tampering(resp) && ownerAttends(planir)) return "strong";
  return null;
}

// ---- status ----------------------------------------------------------------------------------------

const latest = (dates: Date[]): Date | null =>
  dates.reduce<Date | null>((a, d) => (a === null || d.getTime() > a.getTime() ? d : a), null);

/** `snooze status`, as seen from the session `ref` (null: no current session). */
export function formatStatus(data: SnoozeFile | null, ref: string | null, now: Date): string {
  if (data === null) return `The snooze file could not be read, so no snooze applies.\n${RULE}`;
  const all = entries(data, now);
  const lines: string[] = [];
  const here = all.find(([e]) => e.scope === "session" && e.session_ref === ref)?.[1] ?? null;
  const every = latest(all.filter(([e]) => e.scope === "all").map(([, at]) => at));
  if (here) lines.push(`Snooze: on in this session until ${show(here)} (${left(here.getTime() - now.getTime())} left)`);
  if (every) lines.push(`Snooze: on in every session until ${show(every)} (${left(every.getTime() - now.getTime())} left)`);
  if (!here && !every) lines.push("Snooze: off");
  const others = new Set(all.filter(([e]) => e.scope === "session").map(([e]) => e.session_ref as string));
  if (ref !== null) others.delete(ref);
  if (others.size) lines.push(`${ref !== null ? "Other sessions" : "Sessions"} snoozed: ${others.size}`);
  lines.push(RULE);
  return lines.join("\n");
}

/** The `snooze:` line of status. */
export function statusLine(data: SnoozeFile | null, now: Date): string {
  if (data === null) return "unreadable, none applies";
  const all = entries(data, now);
  const parts: string[] = [];
  const every = latest(all.filter(([e]) => e.scope === "all").map(([, at]) => at));
  if (every) parts.push(`every session until ${show(every)}`);
  const n = new Set(all.filter(([e]) => e.scope === "session").map(([e]) => e.session_ref)).size;
  if (n) parts.push(`${n} session${n === 1 ? "" : "s"}`);
  return parts.join(", ") || "off";
}

// ---- changes ---------------------------------------------------------------------------------------

export function usage(cmd: Cmd): string {
  const c = cmd("snooze");
  return (
    `usage: ${c} [duration] [--all], ${c} off [--all] or ${c} status\n` +
    "duration is 1m to 24h (default 1h); a snooze covers this session unless --all; off ends the " +
    "snoozes that apply here (this session's and an --all one), off --all ends every snooze"
  );
}

type Parsed =
  | { op: "off"; all: boolean }
  | { op: "status"; all: boolean }
  | { op: "set"; all: boolean; ms: number; text: string };

/** The snooze typed after `snooze`, or the reason it is refused ("" for a plain usage error). */
export function parse(rest: string): Parsed | string {
  let words = rest.split(/\s+/).filter(Boolean);
  const all = words.includes("--all");
  words = words.filter((w) => w !== "--all");
  for (const w of words) if (w.startsWith("--")) return `Unknown option ${clean(w)}.`;
  if (words.length > 1) return "";
  const arg = (words[0] ?? "").toLowerCase();
  if (arg === "off" || arg === "status") return { op: arg, all };
  if (!arg) return { op: "set", all, ms: DEFAULT_MS, text: "1h" };
  const m = DURATION.exec(arg);
  const ms = m ? Number(m[1]) * (m[2] === "m" ? MINUTE : 3600_000) : NaN;
  if (!(ms >= MINUTE && ms <= MAX_MS)) return `Unknown duration "${clean(arg)}": use a number with m or h, from 1m to 24h.`;
  return { op: "set", all, ms, text: arg };
}

function noSession(cmd: Cmd): string {
  return (
    "There is no current session here, so a snooze cannot be bound to one; " +
    `use ${cmd("snooze")} --all to snooze every session.`
  );
}

/**
 * `snooze ...` from the session `ref` (null: no current session): the reply and the change for the
 * traffic log. `beforeWrite` runs before the file is written and may throw to stop it.
 */
export function run(
  stateDir: string,
  rest: string,
  ref: string | null,
  by: Entry,
  now: Date,
  cmd: Cmd,
  beforeWrite: () => void,
): SnoozeResult {
  const parsed = parse(rest);
  if (typeof parsed === "string") return { reply: parsed ? `${parsed}\n${usage(cmd)}` : usage(cmd), change: null };
  if (parsed.op === "status") return { reply: formatStatus(load(stateDir), ref, now), change: null };
  if (parsed.op === "set" && !parsed.all && ref === null) return { reply: noSession(cmd), change: null };

  const file = path.join(stateDir, "snooze.json");
  try {
    return withFileLock(file, () => change(stateDir, parsed, ref, by, now, beforeWrite));
  } catch (err) {
    if (!(err instanceof LockTimeoutError)) throw err;
    return { reply: `The snooze file ${file} is locked by another process; no snooze was changed. Try again.`, change: null };
  }
}

/** The change `parsed` asks for, read and written while the caller holds the file's lock. */
function change(
  stateDir: string,
  parsed: Exclude<Parsed, { op: "status" }>,
  ref: string | null,
  by: Entry,
  now: Date,
  beforeWrite: () => void,
): SnoozeResult {
  const store = new Store(stateDir);
  const data = store.loadSnooze();
  if (data === null) {
    return {
      reply: `The snooze file ${path.join(stateDir, "snooze.json")} could not be read; fix or remove it first.`,
      change: null,
    };
  }
  const kept = data.snoozes.filter((e) => live(e, now)) as Entry[];
  if (parsed.op === "off") {
    const every = parsed.all || ref === null;
    const ended = kept.filter((e) => every || appliesTo(e, ref));
    if (!ended.length) return { reply: "No snooze was on.", change: null };
    data.snoozes = kept.filter((e) => !ended.includes(e));
    beforeWrite();
    store.saveSnooze(data);
    const n = ended.length;
    return { reply: `Snooze off: ended ${n} snooze${n === 1 ? "" : "s"}.`, change: { op: "off", entries: ended } };
  }
  const entry: Entry = { scope: parsed.all ? "all" : "session" };
  if (!parsed.all) entry.session_ref = ref;
  const until = new Date(now.getTime() + parsed.ms);
  Object.assign(entry, { set_at: iso(now), expires_at: iso(until), set_by: by });
  data.snoozes = [...kept.filter((x) => !(x.scope === entry.scope && x.session_ref === entry.session_ref)), entry].slice(
    -MAX_ENTRIES,
  );
  beforeWrite();
  store.saveSnooze(data);
  const where = parsed.all ? "in every session" : "in this session";
  return {
    reply:
      `Snoozed reviews ${where} for ${parsed.text}, until ${show(until)}. ` +
      SET_RULE,
    change: { op: "set", entry },
  };
}
