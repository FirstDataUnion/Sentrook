/**
 * Snooze: the owner's relief from review prompts, kept in `<state>/sentrook/snooze.json`.
 *
 * A snooze covers the session the command was sent from, or every session with `--all`, for a
 * duration from 1 minute to 24 hours (default 1 hour). While one applies, a review the plugin would
 * ask about is allowed instead; the call is still scanned and its traffic record says `snoozed: true`.
 * A snooze never applies to:
 * - a block;
 * - a review the scanner enforces (`enforced` is review or block);
 * - any run not started by a human message (cron, heartbeat, subagent, hook, or a trigger the plugin
 *   could not tell), where the review stands;
 * - a scan error, or observe mode.
 *
 * A session is named by its `session_ref`, the same hash a scan sends. A command with no current
 * session (the command line) can only snooze every session.
 *
 * Expiry is mandatory: an entry with no readable expiry, or one more than 24 hours away, never applies.
 * A file that cannot be read relaxes nothing and is never overwritten. Expired entries are dropped on
 * the next change. Every change is written to the traffic log as a `snooze` record (none when the
 * owner has turned the traffic log off). The Hermes plugin keeps the same file format and prints the
 * same text.
 */

import path from "node:path";

import type { Cmd, Entry } from "./grants.ts";
import { hash12 } from "./planir.ts";
import { type SnoozeFile, Store } from "./store.ts";

const MINUTE = 60_000;
const DEFAULT_MS = 3600_000;
const MAX_MS = 24 * 3600_000;
const MAX_ENTRIES = 200;
const DURATION = /^(\d{1,5})([mh])$/;
/** The only time form read back from the file; both plugins accept exactly this. */
const ISO = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)(Z|[+-]\d{2}:\d{2})?$/;
export const RULE =
  "A snoozed review is allowed and logged; blocks, enforced reviews and unattended runs are never snoozed.";

/** A change to write to the traffic log, with the reply. */
export interface SnoozeResult {
  reply: string;
  change: { op: "set"; entry: Entry } | { op: "off"; entries: Entry[] } | null;
}

/** The session's name in the file: the `session_ref` a scan of that session sends. */
export function sessionRef(sid: string): string {
  return `s_${hash12(sid)}`;
}

export function load(stateDir: string): SnoozeFile | null {
  return new Store(stateDir).loadSnooze();
}

export const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;
const show = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

/**
 * An ISO time with a `T` (no offset means UTC); anything else is unreadable. A field out of range
 * (`24:00`, `02-30`) is unreadable too, as it is to the Hermes plugin, rather than rolled forward.
 */
export function when(raw: unknown): Date | null {
  const m = typeof raw === "string" ? ISO.exec(raw.trim()) : null;
  if (!m) return null;
  const [y, mo, d, h, mi, s = 0] = m[1]!.split(/[-T:]/).map(Number) as number[];
  const local = new Date(Date.UTC(y!, mo! - 1, d!, h!, mi!, Math.floor(s)));
  if (
    local.getUTCFullYear() !== y ||
    local.getUTCMonth() !== mo! - 1 ||
    local.getUTCDate() !== d ||
    local.getUTCHours() !== h ||
    local.getUTCMinutes() !== mi ||
    local.getUTCSeconds() !== Math.floor(s)
  ) {
    return null;
  }
  const at = new Date(`${m[1]}${m[2] ?? "Z"}`);
  return Number.isNaN(at.getTime()) ? null : at;
}

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
  const at = when(x.expires_at);
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
export function applies(resp: { enforced?: string | null }): boolean {
  return resp.enforced !== "review" && resp.enforced !== "block";
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
      "Blocks, enforced reviews and unattended runs are not snoozed.",
    change: { op: "set", entry },
  };
}
