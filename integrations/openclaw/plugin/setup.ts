/**
 * The owner's setup screen: `/sentrook-setup` lists what would stop Sentrook asking about routine work, and
 * `/sentrook-setup apply <code>` sets it.
 *
 * The screen is a numbered list of items, each a grant or a channel binding, from three places:
 * - **Your config.** Each cron job's delivery target (a room, not a person) that is not bound yet, as a channel
 *   binding; each MCP server that no grant in force covers, as a provider grant named as a scan names its provider.
 *   Cron jobs can be written by the agent, so their items carry a warning.
 * - **Reviews you approved** (`approvedSuggestions`): the grant Sentrook suggested on a review counts only when the
 *   owner approved that review, the call came from the owner's own message (`grants.mayRemember`), the scanner
 *   flagged no exposure anywhere in that session, and the suggested grant is exactly the item's kind, pattern and
 *   allows; a broader pattern never inherits the count. Reviews older than `EVIDENCE_WINDOW_MS` do not count, and an
 *   item needs `EVIDENCE_MIN` of them. With the traffic log off there is no evidence.
 * - **The agent's proposals** (`<state>/proposals.json`, `loadProposals`): items the agent suggested, each with its
 *   reason, shown last as a quoted note. A proposal lasts `PROPOSAL_TTL_MS`.
 *
 * Every item is described in the plugin's words, from its kind, pattern, allows and lifetime. Every candidate, from
 * config, reviews and proposals alike, must be one the grant or bind command would accept (one printable word, no
 * backtick), so nothing an agent wrote into a config file can end a line or a code span; the rest are counted and
 * left out. Patterns, job ids, server names and the agent's reason (only ever a note, last) are shown neutralised in
 * code spans, where chat apps turn no link, mention or emphasis on. A name in `xn--` form is flagged like one with
 * letters that are not plain ASCII. In a group or channel room the command refuses (`commands.ts`). OpenClaw writes a command's reply into the session transcript, so
 * the agent may read the screen afterwards: everything on it is the plugin's own text. Warnings name what to check:
 * characters that are not plain ASCII (with the registrable domain in ASCII), deleting files, a folder at or above the
 * home folder, a whole package registry, a grant in force that already covers the item, a cron job's target, and,
 * for the agent's items, a proposing chat where the scanner flagged exposure (or the traffic log is off, so it could
 * not be checked). A destination with a wildcard over more than one registrable domain (`*.com`) is refused as the
 * grant command refuses it; whether any other pattern is too broad to relieve anything is the scanner's call.
 *
 * Lifetimes: a grant backed by reviews the owner approved lasts until revoked; any other lasts 30 days
 * (`hold.GRANT_TTL_MS`, as for a grant set from a suggestion), or less when the agent asked for less. A channel
 * binding lasts until removed. `apply <code> --expires 90d` or `--until-revoked` sets every grant's lifetime instead.
 *
 * Applying needs the four-digit code the screen ends with: it is new each time the screen is shown, lasts
 * `CODE_TTL_MS`, works once, and is kept with the items as shown (`setup.json`), so `apply` sets exactly what the
 * owner read even if the proposals changed since. One locked pass writes the grants file and the proposals file:
 * grants are persistent, each record says who set it (`set_by`) and where it came from (`source`: `config`, `reviews`
 * or the proposal id), an item already set is not set again, and an agent proposal is closed once nothing readable is
 * left in it. The Hermes plugin keeps the same files and prints the same text.
 */

import { randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import path from "node:path";

import { destinationOk, type PluginConfig, SHARED_SECOND_LEVEL } from "./config.ts";
import { listCronJobs, roomPattern } from "./cronDelivery.ts";
import * as folders from "./folders.ts";
import * as grants from "./grants.ts";
import { actionOf, recordsBackward, reviewOf } from "./history.ts";
import * as hold from "./hold.ts";
import { bindingProblem, callPlatform, relevantGrants, serverIdentity } from "./planir.ts";
import { type GrantsFile, type ProposalsFile, readTime, Store, withFileLock } from "./store.ts";
import * as trust from "./trust.ts";

type Entry = Record<string, any>;

/** Reviews the owner approved that an item needs before it counts as seen. */
export const EVIDENCE_MIN = 2;
/** How far back approved reviews count. */
export const EVIDENCE_WINDOW_MS = 30 * 24 * 3600_000;
/** How many logged message sends a binding is checked against (`unreachedBindings`). */
export const MAX_SENDS = 2000;
/** How long the screen's code works. */
export const CODE_TTL_MS = 15 * 60_000;
/** How long an agent proposal waits for the owner. */
export const PROPOSAL_TTL_MS = 24 * 3600_000;
/** Items on one screen; the rest wait for the next. */
export const MAX_ITEMS = 30;
/** Minutes an unseen grant lasts. */
export const DEFAULT_MINUTES = Math.floor(hold.GRANT_TTL_MS / 60_000);
/** The warning on an agent's item when the chat had read content no scan had seen yet as the agent proposed it. */
export const UNCHECKED_WARNING = "Sentrook could not check what this chat read just before the agent proposed this";

export const PROPOSAL_ID = /^p-[0-9a-f]{6}$/;
const GRANT_ID = /^gr-[0-9a-f]{6}$/;
const DURATION = /^([0-9]{1,6})([mhd])$/;
const UNIT_MINUTES: Record<string, number> = { m: 1, h: 60, d: 1440 };
const MAX_MINUTES = Math.floor(grants.MAX_EXPIRY_MS / 60_000);

export type Cmd = (sub: string) => string;
export type RecordFn = (record: Record<string, unknown>) => void;

const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;
const show = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
/**
 * Text someone else chose (a job id, a server name), neutralised and in a code span, where chat apps turn no link,
 * mention or emphasis on.
 */
/**
 * `s` neutralised and capped, without backslashes (a chat format may read one as an escape of the closing backtick),
 * for a code span.
 */
const spanned = (s: unknown, cap: number) => hold.inert(s, cap).replaceAll("\\", "");
const span = (s: unknown, cap: number) => `\`${spanned(s, cap) || "?"}\``;

/**
 * How a grant in force is named on the screen: an id the plugin made as it is; any other text someone wrote into the
 * file in a code span; anything that is not text as `?`.
 */
export function grantLabel(gid: unknown): string {
  if (typeof gid === "string" && GRANT_ID.test(gid)) return gid;
  return typeof gid === "string" ? span(gid, 20) : "`?`";
}

/** Strings in code point order, as Python sorts them (not UTF-16 code units). */
function byCodePoint(a: string, b: string): number {
  const x = Array.from(a, (c) => c.codePointAt(0)!);
  const y = Array.from(b, (c) => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return x.length - y.length;
}

/**
 * The agent's reason as the screen shows it: neutralised, capped and in a code span, so a link, a bare domain, a
 * mention or emphasis in it does nothing; null when nothing is left of it.
 */
export function noteLine(reason: unknown): string | null {
  const text = typeof reason === "string" ? spanned(reason, 200) : "";
  return text.trim() ? `Agent's note: \`${text}\`` : null;
}
const isAscii = (s: string) => /^[\x00-\x7f]*$/.test(s);
const plural = (n: number) => (n === 1 ? "" : "s");

/** A lifetime as `grant --expires` takes it (`4h`, `30d`), in minutes; null when it is not one. */
export function minutesOf(text: unknown): number | null {
  const m = typeof text === "string" ? DURATION.exec(text) : null;
  if (!m) return null;
  const minutes = Number(m[1]) * UNIT_MINUTES[m[2]!]!;
  return minutes >= 1 && minutes <= MAX_MINUTES ? minutes : null;
}

// ---- evidence -----------------------------------------------------------------------------------------------------

/**
 * The scan response says the agent had read content aimed at steering it: an `exposure.*` reason. The scanner gives
 * one when this call's check scores at its reason line or above, and on every later call of a session it judged
 * tainted. The exposure and session_exposure scores alone say nothing: almost any content scores a little.
 */
export function exposureFlagged(resp: unknown): boolean {
  if (!resp || typeof resp !== "object" || Array.isArray(resp)) return false;
  const r = resp as Entry;
  for (const reason of Array.isArray(r.reasons) ? r.reasons : []) {
    if (typeof reason?.code === "string" && reason.code.startsWith("exposure.")) return true;
  }
  return false;
}

/** What makes two items the same: a binding's channel, or a grant's kind, pattern and allows (in any order). */
export function keyOf(item: Entry): string {
  if (item.binding) return JSON.stringify(["binding", item.pattern]);
  if (TRUST_KINDS.has(item.kind)) return JSON.stringify([item.kind, item.pattern]);
  const allows = Array.isArray(item.allows) && item.allows.length ? [...item.allows].sort() : null;
  const key: unknown[] = [item.kind, item.pattern, allows];
  if (item.follow) key.push(item.follow);
  return JSON.stringify(key);
}

/** The key of the grant an item sets: a binding is a destination grant for its channel. */
function grantKey(item: Entry): string {
  return item.binding ? keyOf({ kind: "destination", pattern: item.pattern }) : keyOf(item);
}

/** A group chat as the traffic log saw it (`Evidence.groups`). */
export interface GroupSeen {
  scans: number;
  senders: Set<string>;
  owner: number;
  last: Date;
}

/** Group chats kept in the evidence; the rest are left out. */
export const MAX_GROUPS = 50;

/** Counts a scan made in a group chat (`group` on its record) into `ev.groups`. */
function countGroup(ev: Evidence, rec: Entry, planir: unknown, at: Date | null, since: number, now: Date): void {
  const group = rec.group;
  if (at === null || at.getTime() < since || at.getTime() > now.getTime() || !group || typeof group !== "object" || Array.isArray(group)) return;
  const chat = group.chat;
  if (typeof chat !== "string" || trust.parseRef(chat) === null) return;
  if (!ev.groups.has(chat) && ev.groups.size >= MAX_GROUPS) return;
  const entry = ev.groups.get(chat) ?? { scans: 0, senders: new Set<string>(), owner: 0, last: at };
  ev.groups.set(chat, entry);
  entry.scans += 1;
  if (at.getTime() > entry.last.getTime()) entry.last = at;
  if (typeof group.sender === "string") entry.senders.add(group.sender);
  const sender = (planir as Entry | null)?.trigger?.sender;
  if (sender && typeof sender === "object" && sender.relation === "owner") entry.owner += 1;
}

export interface Approved {
  grant: Entry;
  count: number;
  last: Date;
}

/** A tally of approved reviews with nothing to suggest, by tool. */
export interface Unsuggested {
  tool: string;
  count: number;
  last: Date;
}

/** A tally of a key the scanner saw sent only to its own service, by name and host. */
export interface OwnService {
  name: string;
  host: string;
  count: number;
  last: Date;
}

/**
 * What the traffic log says: the grants Sentrook suggested on reviews the owner approved (`approved`, by `keyOf`, each
 * with its count and the time of the last), and the sessions where the scanner flagged exposure. `available` is false
 * when the traffic log is off.
 *
 * Also, under the same rule (the owner's own message, no exposure flagged in the session): the approved reviews with no
 * grant to suggest, by tool (`unsuggested`), and the keys the scanner saw sent only to their own service, by name and
 * host (`ownService`, see `ownServiceKeys`); each with its count and last time. `scans` counts the scan records read
 * and `oldest` is the time of the oldest record read, so a reader can tell how far back the log went.
 */
export class Evidence {
  approved = new Map<string, Approved>();
  exposed = new Set<string>();
  unsuggested = new Map<string, Unsuggested>();
  ownService = new Map<string, OwnService>();
  /** The message sends in the window, as logged (at most `MAX_SENDS`, newest first), with their platform. */
  sends: Array<{ args: unknown; platform: string | null }> = [];
  scans = 0;
  oldest: Date | null = null;
  /**
   * The group chats seen in the window (`group` on a scan record), by `platform:chat id`: scans, the distinct senders
   * (by keyed id, never the id), the owner's scans there, and the last time.
   */
  groups = new Map<string, GroupSeen>();
  readonly available: boolean;
  constructor(available: boolean) {
    this.available = available;
  }

  /** The approved reviews that back `item`, when there are enough of them. */
  backing(item: Entry): Approved | null {
    const found = this.approved.get(grantKey(item));
    return found && found.count >= EVIDENCE_MIN ? found : null;
  }
}

/**
 * The evidence in the traffic log at `log` (null when the log is off), as of `now`, over `windowMs`. The suggested
 * grant of a review is the one its prompt named: the first the grant command accepts that brings the call below
 * `reviewAt`.
 */
export function readEvidence(log: string | null, reviewAt: number, now: Date, windowMs = EVIDENCE_WINDOW_MS): Evidence {
  if (log === null) return new Evidence(false);
  const ev = new Evidence(true);
  const since = now.getTime() - windowMs;
  const resolutions = new Map<string, Entry>();
  const seen = new Set<string>();
  const found: Array<[string, Entry, Date]> = [];
  const bare: Array<[string, string, Date]> = [];
  const sent: Array<[string, string, string, Date]> = [];
  for (const rec of recordsBackward(log)) {
    const stamp = readTime(rec.ts);
    if (stamp !== null && (ev.oldest === null || stamp.getTime() < ev.oldest.getTime())) ev.oldest = stamp;
    const rid = rec.request_id;
    if (typeof rid !== "string") continue;
    if (rec.kind === "resolution") {
      if (!resolutions.has(rid)) resolutions.set(rid, rec);
      continue;
    }
    if (rec.kind !== "scan" || seen.has(rid)) continue;
    seen.add(rid);
    ev.scans += 1;
    const resp = rec.response;
    const sref = rec.session_ref;
    if (exposureFlagged(resp) && typeof sref === "string") ev.exposed.add(sref);
    const at = stamp;
    const planir = rec.planir;
    countGroup(ev, rec, planir, at, since, now);
    const pc = planir && typeof planir === "object" ? (planir as Entry).pending_call : null;
    if (
      at !== null &&
      at.getTime() >= since &&
      at.getTime() <= now.getTime() &&
      pc?.tool_kind === "message_send" &&
      ev.sends.length < MAX_SENDS
    ) {
      const reported = typeof pc.send_platform === "string" ? pc.send_platform : null;
      ev.sends.push({ args: pc.arguments ?? {}, platform: callPlatform(pc.arguments ?? {}, "message_send", reported) });
    }
    if (
      at === null ||
      at.getTime() < since ||
      at.getTime() > now.getTime() ||
      typeof sref !== "string" ||
      !resp ||
      typeof resp !== "object" ||
      Array.isArray(resp) ||
      !planir ||
      typeof planir !== "object" ||
      Array.isArray(planir)
    ) {
      continue;
    }
    if (!grants.mayRemember(planir)) continue;
    for (const [name, host] of ownServiceKeys(planir, resp)) sent.push([sref, name, host, at]);
    const resolution = resolutions.get(rid) ?? null;
    if (reviewOf(actionOf(rec, resolution), resolution) !== "approved") continue;
    const grant = hold.grantHint(resp, reviewAt);
    if (grant) found.push([sref, grant, at]);
    else if (typeof rec.tool === "string") bare.push([sref, rec.tool, at]);
  }
  const count = <T extends { count: number; last: Date }>(into: Map<string, T>, key: string, row: Omit<T, "count" | "last">, at: Date) => {
    const entry = into.get(key) ?? ({ ...row, count: 0, last: at } as T);
    entry.count += 1;
    if (at.getTime() > entry.last.getTime()) entry.last = at;
    into.set(key, entry);
  };
  for (const [sref, grant, at] of found) {
    if (!ev.exposed.has(sref)) count<Approved>(ev.approved, keyOf(grant), { grant }, at);
  }
  for (const [sref, tool, at] of bare) {
    if (!ev.exposed.has(sref)) count<Unsuggested>(ev.unsuggested, tool, { tool }, at);
  }
  for (const [sref, name, host, at] of sent) {
    if (!ev.exposed.has(sref)) count<OwnService>(ev.ownService, JSON.stringify([name, host]), { name, host }, at);
  }
  return ev;
}

/**
 * An environment name shaped like a credential, as the scanner reads one (words joined by `_` ending in a key, token,
 * secret or password word).
 */
export const CREDENTIAL_NAME = new RegExp(
  "(?<![A-Za-z0-9_])(" +
    "[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_?KEY|KEY|KEY_ID|TOKEN|SECRET|SECRET_KEY|PASSWORD|PASSWD|PASS|PAT" +
    "|AUTH|AUTH_TOKEN|CREDENTIALS?|ACCESS_KEY|ACCESS_KEY_ID|PRIVATE_KEY)" +
    ")(?![A-Za-z0-9_])",
  "g",
);
/** What the scanner's relief for a key sent only to its own service removes; it names no grant. */
const OWN_SERVICE_EFFECTS = new Set(["sensitivity", "sensitivity+distrust+untrusted_origin"]);

function stringsIn(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringsIn);
  if (value && typeof value === "object") return Object.values(value).flatMap(stringsIn);
  return [];
}

/**
 * [key name, host] for a scan the scanner relieved because the call sent its keys only to their own service: a relief
 * that names no grant and takes sensitivity off a host. The scanner holds that only when every credential-shaped name
 * the call uses is one that host's service issues, so the names are those in the call's arguments as logged; nothing
 * else of the arguments is kept.
 */
export function ownServiceKeys(planir: Entry, resp: Entry): Array<[string, string]> {
  const entities = resp?.entities && typeof resp.entities === "object" && !Array.isArray(resp.entities) ? resp.entities : {};
  const hosts: string[] = [];
  for (const r of Array.isArray(resp?.relief_applied) ? resp.relief_applied : []) {
    if (!r || typeof r !== "object" || (r.grant_ref ?? null) !== null) continue;
    if (!OWN_SERVICE_EFFECTS.has(r.effect)) continue;
    const ent = typeof r.subject === "string" && Object.hasOwn(entities, r.subject) ? entities[r.subject] : null;
    if (ent && typeof ent === "object" && ent.kind === "host" && typeof ent.display === "string") {
      if (!hosts.includes(ent.display)) hosts.push(ent.display);
    }
  }
  if (!hosts.length) return [];
  const call = planir?.pending_call && typeof planir.pending_call === "object" ? planir.pending_call : {};
  const names = new Set<string>();
  for (const text of stringsIn(call.arguments)) for (const m of text.matchAll(CREDENTIAL_NAME)) names.add(m[1]!);
  return [...names].sort().flatMap((n) => hosts.map((h): [string, string] => [n, h]));
}

/** The suggested grants with enough approved reviews behind them, most reviews first, then the most recent. */
export function approvedSuggestions(ev: Evidence): Approved[] {
  return [...ev.approved.values()]
    .filter((e) => e.count >= EVIDENCE_MIN)
    .sort((a, b) => b.count - a.count || b.last.getTime() - a.last.getTime() || (keyOf(a.grant) < keyOf(b.grant) ? -1 : 1));
}

/** How long ago, by UTC calendar day. */
export function lastText(now: Date, last: Date): string {
  const day = (d: Date) => Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  const days = Math.round((day(now) - day(last)) / 86_400_000);
  return days <= 0 ? "today" : days === 1 ? "yesterday" : `${days} days ago`;
}

// ---- sources ------------------------------------------------------------------------------------------------------

/**
 * (job id, channel) for each enabled cron job's delivery to a room, from OpenClaw's job store. `last`, no `to`, a
 * webhook and a person give none.
 */
export function cronTargets(openclawDir: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const job of listCronJobs(openclawDir)) {
    if (!job.enabled) continue;
    const d = job.delivery as Entry | null;
    if (!d || typeof d !== "object" || d.mode !== "announce" || typeof d.channel !== "string" || typeof d.to !== "string") continue;
    const pattern = roomPattern(d.channel, d.to);
    if (pattern && !out.some(([id, p]) => id === job.id && p === pattern)) out.push([job.id, pattern]);
  }
  return out;
}

/** (server name, provider identity) for each configured MCP server, by name; the identity is null when the entry names none. */
export function mcpProviders(servers: unknown): Array<[string, string | null]> {
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return [];
  return Object.keys(servers)
    .sort(byCodePoint)
    .map((name) => {
      const cfg = (servers as Entry)[name];
      return [name, cfg && typeof cfg === "object" ? serverIdentity(cfg).identity : null];
    });
}

// ---- proposals ----------------------------------------------------------------------------------------------------

/**
 * A pattern as written can be shown and set: one printable word, no backtick, no backslash at its end. Checked before
 * anything trims it, so both plugins read the same patterns.
 */
function rawOk(p: unknown): p is string {
  return printableWord(p) && !p.includes("`") && !p.endsWith("\\");
}

function printableWord(p: unknown): p is string {
  return typeof p === "string" && p.length > 0 && p.length <= grants.MAX_PATTERN && grants.printable(p) && !/\s/u.test(p);
}

/** A proposal's trust fields, by the item kind each makes. */
export const TRUST_FIELDS: Record<string, string> = { trusted_chat: "trusted_chat", trusted_sender: "trusted_user" };
export const TRUST_KINDS: ReadonlySet<string> = new Set(Object.values(TRUST_FIELDS));

/**
 * One item of an agent proposal as the screen shows it; null when it is not one the owner could set by command (an
 * `attended` platform, an unknown kind, a pattern the grant command refuses, a binding that could never apply).
 */
export function proposalItem(raw: unknown): Entry | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Entry;
  const reason = typeof r.reason === "string" ? r.reason : null;
  let minutes: number | null = null;
  if (r.expires !== undefined && r.expires !== null) {
    minutes = minutesOf(r.expires);
    if (minutes === null) return null;
  }
  for (const [field, kind] of Object.entries(TRUST_FIELDS)) {
    if (!Object.hasOwn(r, field)) continue;
    const ref = trust.parseRef(r[field]);
    const extra = Object.keys(r).filter((k) => k !== field && k !== "reason" && k !== "owner_only");
    if (ref === null || extra.length || (kind === "trusted_user" && Object.hasOwn(r, "owner_only"))) return null;
    if (Object.hasOwn(r, "owner_only") && typeof r.owner_only !== "boolean") return null;
    return {
      binding: false,
      kind,
      pattern: ref.join(":"),
      allows: null,
      owner_only: r.owner_only === true,
      minutes: null,
      reason,
    };
  }
  if (r.binding === true) {
    if ((r.kind !== undefined && r.kind !== null && r.kind !== "destination") || (r.allows !== undefined && r.allows !== null)) {
      return null;
    }
    if (minutes !== null || !rawOk(r.pattern) || bindingProblem(r.pattern)) return null;
    return { binding: true, kind: "destination", pattern: r.pattern, reason };
  }
  if ((r.binding !== undefined && r.binding !== null && r.binding !== false) || !rawOk(r.pattern)) return null;
  const grant = grants.hintGrant(
    {
      kind: r.kind,
      pattern: r.pattern,
      allows: r.allows,
      ...(r.follow !== undefined && r.follow !== null ? { follow: r.follow } : {}),
    },
    { folder: true },
  );
  if (!grant) return null;
  return { binding: false, ...grant, minutes, reason };
}

/** The stored proposals that have not expired, as stored. */
export function liveProposals(raw: ProposalsFile | null, now: Date): Entry[] {
  const out: Entry[] = [];
  for (const p of raw?.proposals ?? []) {
    if (!p || typeof p !== "object" || typeof (p as Entry).id !== "string") continue;
    const created = readTime((p as Entry).created_at);
    const expires = readTime((p as Entry).expires_at);
    if (!created || !expires) continue;
    const t = now.getTime();
    if (created.getTime() <= t && t < Math.min(expires.getTime(), created.getTime() + PROPOSAL_TTL_MS)) out.push(p as Entry);
  }
  return out;
}

export interface Proposal {
  id: string;
  session_ref: string | null;
  created_at: Date;
  items: Entry[];
  dropped: number;
  /** The chat had read content no scan had seen yet when the agent proposed it. */
  unchecked: boolean;
}

/**
 * The agent's live proposals, oldest first: id, session_ref (null when unreadable), created_at, the readable items
 * and how many were not (`dropped`). Null when the file cannot be read.
 */
export function loadProposals(stateDir: string, now: Date): Proposal[] | null {
  const raw = new Store(stateDir).loadProposals();
  if (raw === null) return null;
  const out: Proposal[] = [];
  for (const p of liveProposals(raw, now)) {
    if (!PROPOSAL_ID.test(p.id)) continue;
    const items: unknown[] = Array.isArray(p.items) ? p.items : [];
    const readable = items.map(proposalItem).filter((i): i is Entry => i !== null);
    const ref = p.session_ref;
    out.push({
      id: p.id,
      session_ref: typeof ref === "string" && grants.SESSION_REF.test(ref) ? ref : null,
      created_at: readTime(p.created_at)!,
      items: readable,
      dropped: items.length - readable.length,
      unchecked: p.unchecked === true,
    });
  }
  return out.sort((a, b) => a.created_at.getTime() - b.created_at.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

// ---- the rules each item is checked against -----------------------------------------------------------------------

/**
 * [label, grant] for each grant in force everywhere: persistent config and file grants that have not expired, and
 * every channel binding as a destination grant. A destination Sentrook ignores as too broad is not in force.
 */
export function inForce(cfg: PluginConfig, data: GrantsFile | null, now: Date): Array<[string, Entry]> {
  const out: Array<[string, Entry]> = [];
  cfg.grants.forEach((g, i) => {
    if (g.scope === "persistent" && !(i in cfg.unsentGrants)) out.push([`cfg-${i + 1}`, g]);
  });
  for (const p of cfg.channelBindings) out.push(["a channel binding", { kind: "destination", pattern: p }]);
  for (const [raw, g] of grants.fileGrants(data)) {
    // An id the plugin made is shown as it is; anything else someone wrote into the file, in a code span.
    if (g.scope === "persistent" && !grants.expired(raw, now)) {
      out.push([grantLabel(raw.id), g]);
    }
  }
  for (const b of grants.fileBindings(data)) out.push(["a channel binding", { kind: "destination", pattern: b.pattern.trim() }]);
  return out.filter(([, g]) => g.kind !== "destination" || destinationOk(g.pattern));
}

/**
 * The channel bindings in force (`inForce`) that no message send in the evidence would carry, as written: the plugin
 * sends a binding only with a send that shows its channel (`planir.relevantGrants`), so one written another way than
 * the host's sends write the channel never relieves anything. None when the window holds no message send.
 */
export function unreachedBindings(force: Array<[string, Entry]>, ev: Evidence): string[] {
  if (!ev.sends.length) return [];
  const out: string[] = [];
  for (const [label, g] of force) {
    if (label !== "a channel binding" || out.includes(g.pattern)) continue;
    const grant = { kind: "destination", pattern: String(g.pattern), scope: "persistent" as const };
    const carried = ev.sends.some(
      (s) => relevantGrants([grant], JSON.stringify(s.args ?? {}), { platform: s.platform }).length > 0,
    );
    if (!carried) out.push(g.pattern);
  }
  return out;
}

/**
 * `existing` already lets through everything `cand` would: the same kind, allows no narrower, and the same pattern
 * (case ignored except for files), `*.` over its domain and every name under it, or a folder's `/*` over a file
 * directly in it.
 */
export function covers(existing: Entry, cand: Entry): boolean {
  if (existing.kind !== cand.kind) return false;
  const have: string[] | null = Array.isArray(existing.allows) && existing.allows.length ? existing.allows : null;
  const want: string[] | null = Array.isArray(cand.allows) && cand.allows.length ? cand.allows : null;
  if (have && (!want || !want.every((a) => have.includes(a)))) return false;
  let e: string = existing.pattern;
  let c: string = cand.pattern;
  if (cand.kind === "file") {
    if (e === c) return true;
    const head = e.slice(0, -1);
    const rest = c.slice(head.length);
    return e.endsWith("/*") && !head.includes("*") && c.startsWith(head) && rest.length > 0 && !rest.includes("/");
  }
  e = e.toLowerCase();
  c = c.toLowerCase();
  if (e === c) return true;
  const i = e.indexOf("*.");
  if (i < 0 || e.slice(0, i).includes("*") || e.slice(i + 2).includes("*")) return false;
  const head = e.slice(0, i);
  const domain = e.slice(i + 2);
  const rest = c.slice(head.length);
  return c.startsWith(head) && (rest === domain || rest.endsWith(`.${domain}`));
}

/** The host an item's pattern names, if any, without `*.`, a port or a path. */
export function hostOf(item: Entry): string | null {
  let p: string = item.pattern.trim().toLowerCase();
  const kind = item.binding ? "destination" : item.kind;
  if (kind === "credential") {
    p = p.includes("@") ? p.slice(p.indexOf("@") + 1) : "";
  } else if (kind === "provider") {
    if (!p.startsWith("remote:")) return null;
    p = p.slice(7);
  } else if (kind === "destination" || kind === "repo") {
    p = p.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split("/")[0]!;
    p = p.slice(p.lastIndexOf("@") + 1);
  } else {
    return null;
  }
  p = p.split(":")[0]!;
  if (p.startsWith("*.")) p = p.slice(2);
  p = p.replace(/\.+$/, "");
  return p || null;
}

/**
 * The registrable domain of `host` (the last two labels, three under a shared country second level such as `co.uk`),
 * in ASCII; null when it has fewer than two labels.
 */
export function registrable(host: string | null): string | null {
  const labels = (host ?? "").split(".");
  if (labels.length < 2 || labels.some((l) => !l)) return null;
  const n =
    labels.length >= 3 && SHARED_SECOND_LEVEL.has(labels.at(-2)!) && labels.at(-1)!.length === 2 ? 3 : 2;
  const ascii = labels.slice(-n).map((l) => (isAscii(l) ? l : punycodeLabel(l)));
  return ascii.every((l) => l) ? ascii.join(".") : null;
}

/** One label as `xn--` and its punycode (RFC 3492, as Python's `punycode` codec writes it); "" when it cannot be. */
function punycodeLabel(label: string): string {
  const BASE = 36;
  const cps = Array.from(label, (c) => c.codePointAt(0)!);
  const basic = cps.filter((c) => c < 0x80);
  let out = String.fromCodePoint(...basic);
  let h = basic.length;
  const b = basic.length;
  if (b > 0) out += "-";
  let n = 0x80;
  let delta = 0;
  let bias = 72;
  const digit = (d: number) => String.fromCharCode(d + 22 + 75 * (d < 26 ? 1 : 0));
  const adapt = (d: number, numPoints: number, first: boolean) => {
    d = first ? Math.floor(d / 700) : Math.floor(d / 2);
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > ((BASE - 1) * 26) >> 1) {
      d = Math.floor(d / (BASE - 1));
      k += BASE;
    }
    return k + Math.floor(((BASE - 1 + 1) * d) / (d + 38));
  };
  while (h < cps.length) {
    const m = Math.min(...cps.filter((c) => c >= n));
    delta += (m - n) * (h + 1);
    n = m;
    for (const c of cps) {
      if (c < n) delta++;
      if (c === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
          if (q < t) break;
          out += digit(t + ((q - t) % (BASE - t)));
          q = Math.floor((q - t) / (BASE - t));
        }
        out += digit(q);
        bias = adapt(delta, h + 1, h === b);
        delta = 0;
        h++;
      }
    }
    delta++;
    n++;
  }
  return `xn--${out}`;
}

const HOME_OR_ABOVE = /^\/(?:(?:home|Users)(?:\/[^/*?[\]]+)?|root|var\/root)$/;

/** A file pattern for the home folder or a folder above it. */
export function aboveHome(pattern: string): boolean {
  const s = pattern.trim().replace(/[/*]+$/, "");
  return ["", "~", "$HOME", "${HOME}"].includes(s) || HOME_OR_ABOVE.test(s);
}

/** A provider pattern with nothing literal after its registry: every package, or every server. */
export function wholeRegistry(pattern: string): boolean {
  const rest = pattern.includes(":") ? pattern.slice(pattern.indexOf(":") + 1) : pattern;
  return rest.replace(/[*?[\]@/\s]/gu, "") === "";
}

/** A label in its ASCII (punycode) form, which a name with look-alike letters becomes. */
const ENCODED = /(?:^|[.:@/*])xn--/i;

/**
 * `cand` as the grant or bind command would accept it (one printable word, no backtick), whatever it came from; null
 * when it would not be.
 */
export function validItem(cand: Entry): Entry | null {
  const pattern = cand.pattern;
  if (!rawOk(pattern)) return null;
  if (TRUST_KINDS.has(cand.kind)) {
    if (cand.binding || trust.parseRef(pattern) === null) return null;
    return {
      binding: false,
      kind: cand.kind,
      pattern,
      allows: null,
      owner_only: cand.kind === "trusted_chat" && cand.owner_only === true,
    };
  }
  if (cand.binding) {
    if (bindingProblem(pattern)) return null;
    return { binding: true, kind: "destination", pattern, allows: null };
  }
  const grant = grants.hintGrant(cand, { folder: true });
  if (!grant || !rawOk(grant.pattern)) return null;
  return { binding: false, allows: null, ...grant };
}

/** The warnings an item carries from its own kind, pattern and allows. */
export function itemWarnings(item: Entry): string[] {
  const out: string[] = [];
  if (item.kind === "trusted_chat" && trust.isServer(item.pattern)) {
    out.push(
      "everyone who can post in any channel or thread of this server, including ones created later, counts as " +
        "someone you trust; trust a server only when you know every member and who can join it, never an open or " +
        "public one",
    );
    if (!item.owner_only) out.push("members there may approve the agent's reviews");
    return out;
  }
  if (item.kind === "trusted_chat") {
    out.push(
      "everyone who can post in this chat, now and later, counts as someone you trust; trust only a chat on a " +
        "private server where you know every member, never an open or public group",
    );
    if (!item.owner_only) out.push("members there may approve the agent's reviews");
    return out;
  }
  if (item.kind === "trusted_user") {
    out.push("this person's messages count as from someone you trust, in any chat");
    return out;
  }
  if (!isAscii(item.pattern) || ENCODED.test(item.pattern)) {
    const domain = registrable(hostOf(item));
    out.push(
      "the name has characters that are not plain ASCII, or is written in their xn-- form, and may imitate another name" +
        (domain ? ` (registrable domain ${span(domain, 300)})` : ""),
    );
  }
  if (!item.binding && item.kind === "file") {
    if (!item.allows?.length || item.allows.includes("delete")) out.push("this lets the agent delete files");
    if (aboveHome(item.pattern)) out.push("this covers your whole home folder or more");
  }
  if (!item.binding && item.kind === "provider" && wholeRegistry(item.pattern)) {
    out.push("this covers a whole package registry or every server");
  }
  if (!item.binding && item.kind === "folder") {
    out.push(
      "the agent follows what these files say as your own instructions; trust only a folder you write and " +
        "maintain yourself",
    );
    if (item.follow) {
      out.push(`anyone who can push to ${item.follow} on that remote, the agent included if it can, decides what is trusted`);
    }
  }
  return out;
}

/**
 * Where the trust an item sets is already in force (as is, or a chat set with reviews held for the owner when the item
 * would let members answer), or null.
 */
function trustedAlready(t: trust.Trust, item: Entry): string | null {
  const key = String(item.pattern).toLowerCase();
  if (item.kind === "trusted_user") return t.senders.has(key) ? "a trusted user" : null;
  const held = t.chats.get(key);
  if (held === undefined || (held === false && item.owner_only)) return null;
  return "a trusted chat";
}

// ---- the text -----------------------------------------------------------------------------------------------------

const VERBS: Record<string, string> = { read: "read", write: "write", edit: "edit", delete: "delete", exec: "run" };

export function lifetimeText(item: Entry, minutes: number | null): string {
  if (minutes === null) return item.binding ? "until you remove it" : "until you revoke it";
  for (const [size, unit] of [
    [1440, "day"],
    [60, "hour"],
    [1, "minute"],
  ] as const) {
    if (minutes % size === 0) return `for ${minutes / size} ${unit}${plural(minutes / size)}`;
  }
  return `for ${minutes} minutes`;
}

/** The item's first line, in the plugin's words: what it lets through, from where, and for how long. */
export function describe(item: Entry, minutes: number | null): string {
  const p: string = item.pattern;
  if (item.kind === "trusted_chat" && trust.isServer(p)) {
    const held = item.owner_only ? "; its reviews are held for you" : "";
    return (
      `Trust the whole server \`${p}\`: messages from its members in every channel and thread, including ones ` +
      `created later, count as from someone you know, not a stranger (never as yours)${held}, until you remove it.`
    );
  }
  if (item.kind === "trusted_chat") {
    const held = item.owner_only ? "; its reviews are held for you" : "";
    return (
      `Trust the chat \`${p}\`: its members' messages count as from someone you know, not a stranger (never as ` +
      `yours)${held}, until you remove it.`
    );
  }
  if (item.kind === "trusted_user") {
    return (
      `Trust the person \`${p}\`: their messages count as from someone you know, not a stranger (never as ` +
      "yours), until you remove them."
    );
  }
  let what: string;
  if (item.binding) what = `Send messages to the channel \`${p}\``;
  else if (item.kind === "destination") what = p.startsWith("*.") ? `Send data to \`${p.slice(2)}\` and every name under it` : `Send data to \`${p}\``;
  else if (item.kind === "file") {
    const allowed: string[] = item.allows?.length ? item.allows : grants.ALLOWS;
    const verbs = grants.ALLOWS.filter((a) => allowed.includes(a)).map((a) => VERBS[a]!);
    const listed = verbs.length === 1 ? verbs[0]! : `${verbs.slice(0, -1).join(", ")} and ${verbs.at(-1)}`;
    what = `${listed[0]!.toUpperCase()}${listed.slice(1)} files matching \`${p}\``;
  } else if (item.kind === "provider") what = `Use tools from the provider \`${p}\``;
  else if (item.kind === "repo") what = `Run install scripts from the repository \`${p}\``;
  else if (item.kind === "folder") {
    what = item.follow
      ? `Count the files in \`${p}\` as your own while they match \`${item.follow}\` on its remote`
      : `Count the files in \`${p}\` as your own while they are as they are now`;
  } else {
    const at = p.indexOf("@");
    what = `Send the key \`${p.slice(0, at)}\` to \`${p.slice(at + 1)}\``;
  }
  return `${what}, from any chat or job, ${lifetimeText(item, minutes)}.`;
}

// ---- the screen ---------------------------------------------------------------------------------------------------

export interface Item {
  binding: boolean;
  kind: string;
  pattern: string;
  allows: string[] | null;
  /** A folder grant's followed branch (`origin/main`), when it has one. */
  follow?: string;
  /** A trusted chat's: whether its reviews are held for the owner (trust.ts). */
  owner_only?: boolean;
  /** Null: until revoked or removed. */
  minutes: number | null;
  /** Where it came from, for the grants file. */
  tags: string[];
  proposals: string[];
  /** The text lines under the first. */
  lines: string[];
}

/** The screen's items, in order, and its notes. */
export function build(
  cfg: PluginConfig,
  data: GrantsFile | null,
  cron: Array<[string, string]>,
  mcp: Array<[string, string | null]>,
  ev: Evidence,
  proposals: Proposal[],
  now: Date,
): { items: Item[]; notes: string[] } {
  const items = new Map<string, Entry>();
  // Every candidate, whatever its source, must be one the grant or bind command would accept: anything else (a config
  // entry with a newline or a space in it) is left out and counted.
  let droppedConfig = 0;
  const add = (raw: Entry | null, source: Entry) => {
    const cand = raw === null ? null : validItem(raw);
    if (cand === null) {
      if (source.from === "cron" || source.from === "mcp") droppedConfig++;
      return;
    }
    const k = keyOf(cand);
    if (!items.has(k)) {
      items.set(k, {
        binding: !!cand.binding,
        kind: cand.kind,
        pattern: cand.pattern,
        allows: Array.isArray(cand.allows) && cand.allows.length ? [...cand.allows] : null,
        ...(cand.follow ? { follow: cand.follow } : {}),
        ...(TRUST_KINDS.has(cand.kind) ? { owner_only: cand.owner_only } : {}),
        sources: [],
      });
    }
    items.get(k)!.sources.push(source);
  };
  for (const [job, pattern] of cron) add({ binding: true, kind: "destination", pattern }, { from: "cron", job });
  for (const [server, identity] of mcp) add(identity ? { kind: "provider", pattern: identity } : null, { from: "mcp", server });
  for (const e of approvedSuggestions(ev)) add(e.grant, { from: "reviews" });
  const notes: string[] = [];
  if (droppedConfig) {
    const n = droppedConfig;
    notes.push(`From your config: ${n} item${plural(n)} could not be read and ${n === 1 ? "is" : "are"} left out.`);
  }
  for (const p of proposals) {
    for (const it of p.items) {
      add(it, {
        from: "proposal",
        id: p.id,
        session_ref: p.session_ref,
        reason: it.reason ?? null,
        minutes: it.minutes ?? null,
        unchecked: p.unchecked === true,
      });
    }
    if (p.dropped) {
      const n = p.dropped;
      notes.push(`Proposal ${p.id}: ${n} item${plural(n)} could not be read and ${n === 1 ? "is" : "are"} left out.`);
    }
  }
  const force = inForce(cfg, data, now);
  const trusted = trust.of(cfg);
  const out: Item[] = [];
  for (const item of items.values()) {
    const trustItem = TRUST_KINDS.has(item.kind);
    const cand = item.binding ? { kind: "destination", pattern: item.pattern } : item;
    const covering = trustItem ? trustedAlready(trusted, item) : (force.find(([, g]) => covers(g, cand))?.[0] ?? null);
    const agent: Entry[] = item.sources.filter((s: Entry) => s.from === "proposal");
    if (covering !== null && !agent.length) continue;
    const backed = trustItem ? null : ev.backing(item);
    let minutes: number | null;
    if (item.binding || trustItem) minutes = null;
    else {
      const asked: number[] = agent.map((s) => s.minutes).filter((m): m is number => m !== null);
      minutes = backed ? (asked.length ? Math.min(...asked) : null) : Math.min(...asked, DEFAULT_MINUTES);
    }
    const lines: string[] = [];
    for (const s of item.sources) {
      if (s.from === "cron") lines.push(`From your config: cron job ${span(s.job, 40)} delivers here.`);
      else if (s.from === "mcp") lines.push(`From your config: MCP server ${span(s.server, 40)}.`);
    }
    if (backed) {
      lines.push(`Sentrook suggested this in ${backed.count} reviews you approved, the last one ${lastText(now, backed.last)}.`);
    }
    const ids = [...new Set(agent.map((s) => s.id as string))];
    for (const id of ids) lines.push(`Proposed by the agent (${id})${backed ? "." : ", not seen yet."}`);
    if (item.kind === "trusted_chat" && ev.available && !trust.isServer(item.pattern)) {
      const seen = ev.groups.get(item.pattern);
      if (seen === undefined) lines.push("Sentrook has not seen the agent used in this chat lately.");
      else {
        const n = seen.senders.size;
        lines.push(
          `Seen lately: ${seen.scans} calls from ${n} ${n === 1 ? "person" : "people"} in this chat, the last ` +
            `${lastText(now, seen.last)}.`,
        );
      }
    }
    const warnings = itemWarnings(item);
    if (covering !== null) {
      warnings.push(trustItem ? `this is already trusted (${covering})` : `a grant in force already covers this (${covering})`);
    }
    if (item.sources.some((s: Entry) => s.from === "cron")) {
      warnings.push("cron jobs can be changed by the agent; check that you chose this channel");
    }
    if (item.sources.some((s: Entry) => s.from === "mcp")) {
      warnings.push("MCP servers in the config can be changed by the agent; check that you added this one");
    }
    for (const s of agent) {
      if (!ev.available) warnings.push("could not check what the proposing chat had read (the traffic log is off)");
      else if (s.session_ref === null) warnings.push("could not check what the proposing chat had read");
      else if (ev.exposed.has(s.session_ref)) warnings.push("the chat that proposed this had read content that tried to steer the agent");
      if (s.unchecked) warnings.push(UNCHECKED_WARNING);
    }
    for (const w of new Set(warnings)) lines.push(`Warning: ${w}.`);
    for (const s of agent) {
      const note = noteLine(s.reason);
      if (note !== null) lines.push(note);
    }
    const tags = [
      ...(item.sources.some((s: Entry) => s.from === "cron" || s.from === "mcp") ? ["config"] : []),
      ...(backed ? ["reviews"] : []),
      ...ids,
    ];
    out.push({
      binding: item.binding,
      kind: item.kind,
      pattern: item.pattern,
      allows: item.allows,
      ...(item.follow ? { follow: item.follow } : {}),
      ...(Object.hasOwn(item, "owner_only") ? { owner_only: item.owner_only } : {}),
      minutes,
      tags: [...new Set(tags)],
      proposals: ids,
      lines,
    });
  }
  if (out.length > MAX_ITEMS) {
    const n = out.length - MAX_ITEMS;
    notes.push(`${n} more item${plural(n)} not shown: apply or discard some first.`);
    out.length = MAX_ITEMS;
  }
  return { items: out, notes };
}

/** Shown above the apply lines whenever the list has items. */
export const CAVEAT =
  "Please check that each item looks right before you set it: a grant lets calls like it through without asking " +
  "you. Set only what you recognise as routine for your agent; you can revoke any grant later.";

export function render(items: Item[], notes: string[], ev: Evidence, code: string | null, cmd: Cmd): string {
  const n = items.length;
  const lines = [
    n
      ? `Sentrook setup: ${n} item${plural(n)}. Sentrook describes each one from what it found; read them before you set any.`
      : "Sentrook setup: nothing to set up right now.",
  ];
  if (!ev.available) lines.push("Evidence unavailable: the traffic log is off, so no reviews you approved are counted.");
  items.forEach((item, i) => {
    lines.push("", `${i + 1}. ${describe(item, item.minutes)}`, ...item.lines.map((l) => `   ${l}`));
  });
  if (notes.length) lines.push("", ...notes);
  if (n) {
    const setup = cmd("setup");
    lines.push(
      "",
      CAVEAT,
      `To set them all, send: ${setup} apply ${code}`,
      `To set some, list their numbers: ${setup} apply ${code} 1,3`,
      "Add --expires 90d or --until-revoked to change how long the grants last; channels stay until you remove them. " +
        `The code works for ${CODE_TTL_MS / 60_000} minutes.`,
    );
    if (items.some((i) => i.proposals.length)) lines.push(`To drop an agent proposal: ${setup} discard <id>`);
  }
  return lines.join("\n");
}

export const newCode = () => String(randomInt(0, 10_000)).padStart(4, "0");

/** Where the screen reads what it lists from, besides the plugin's own state. */
export interface Sources {
  /** OpenClaw's state directory (its job store). */
  openclawDir: string;
  /** OpenClaw's config (its MCP servers). */
  hostConfig: unknown;
  code?: () => string;
}

/** Builds the screen, keeps its items with a new code (`setup.json`), and returns its text. */
export function showScreen(cfg: PluginConfig, now: Date, cmd: Cmd, src: Sources, beforeWrite: () => void): string {
  const data = grants.load(cfg.stateDir);
  if (data === null) return `The grants file ${path.join(cfg.stateDir, "grants.json")} could not be read; fix or remove it first.`;
  const ev = readEvidence(cfg.trafficLog.enabled ? cfg.trafficLog.path : null, cfg.reviewAt, now);
  const proposals = loadProposals(cfg.stateDir, now);
  const before = proposals === null ? ["The agent's proposals could not be read, so none are shown."] : [];
  const { items, notes } = build(
    cfg,
    data,
    cronTargets(src.openclawDir),
    mcpProviders((src.hostConfig as Entry | undefined)?.mcp?.servers),
    ev,
    proposals ?? [],
    now,
  );
  const code = items.length ? (src.code ?? newCode)() : null;
  withFileLock(path.join(cfg.stateDir, "setup.json"), () => {
    beforeWrite();
    new Store(cfg.stateDir).saveSetup({
      version: 1,
      code,
      shown_at: iso(now),
      items: items.map(({ lines: _lines, ...rest }) => rest),
    });
  });
  return render(items, [...before, ...notes], ev, code, cmd);
}

// ---- apply and discard --------------------------------------------------------------------------------------------

export const usage = (cmd: Cmd) => `usage: ${cmd("setup")} [apply <code> [1,3] [--expires 90d | --until-revoked] | discard <id>]`;
const openText = (cmd: Cmd) => `open ${cmd("setup")} to see the list and its code.`;

export interface ApplyArgs {
  code: string;
  numbers: number[];
  minutes: number | null;
  untilRevoked: boolean;
}

/** `apply <code> [numbers] [--expires <d> | --until-revoked]`, or the reason it is refused. */
export function parseApply(rest: string, cmd: Cmd): ApplyArgs | string {
  const tokens = rest.split(/\s+/).filter(Boolean);
  let code: string | null = null;
  const numbers: number[] = [];
  let minutes: number | null = null;
  let until = false;
  for (let i = 0; i < tokens.length; ) {
    const tok = tokens[i++]!;
    if (tok === "--until-revoked") {
      until = true;
      continue;
    }
    if (tok.startsWith("--")) {
      const eq = tok.indexOf("=");
      const name = eq < 0 ? tok.slice(2) : tok.slice(2, eq);
      if (name !== "expires") return `Unknown option --${hold.inert(name, 40)}.`;
      let value: string;
      if (eq >= 0) value = tok.slice(eq + 1);
      else {
        if (i >= tokens.length) return "--expires needs a value.";
        value = tokens[i++]!;
      }
      minutes = minutesOf(value);
      if (minutes === null) return `Unknown expiry "${hold.inert(value, 40)}": use a number with m, h or d, from 1m to 365d.`;
      continue;
    }
    if (code === null) {
      code = tok;
      continue;
    }
    for (const part of tok.split(",")) {
      if (!part) continue;
      if (!/^[0-9]{1,4}$/.test(part)) return `"${hold.inert(part, 20)}" is not an item number: ${openText(cmd)}`;
      numbers.push(Number(part));
    }
  }
  if (until && minutes !== null) return "Use --expires or --until-revoked, not both.";
  if (code === null) return `apply needs the code from the setup screen: ${openText(cmd)}`;
  return { code, numbers, minutes, untilRevoked: until };
}

function codeOk(kept: Entry, code: string, now: Date): boolean {
  if (typeof kept.code !== "string") return false;
  const shown = readTime(kept.shown_at);
  if (!shown || shown.getTime() > now.getTime() || now.getTime() >= shown.getTime() + CODE_TTL_MS) return false;
  const a = Buffer.from(kept.code);
  const b = Buffer.from(code);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** An item as the screen kept it, checked again as the grant command would. */
function storedItem(raw: unknown): (Entry & { tags: string[]; proposals: string[] }) | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Entry;
  if (typeof r.pattern !== "string" || r.pattern.includes("`")) return null;
  const minutes = r.minutes ?? null;
  if (minutes !== null && !(Number.isInteger(minutes) && minutes >= 1 && minutes <= MAX_MINUTES)) return null;
  const tags = (Array.isArray(r.tags) ? r.tags : []).filter((t: unknown): t is string => typeof t === "string");
  const proposals = (Array.isArray(r.proposals) ? r.proposals : []).filter(
    (p: unknown): p is string => typeof p === "string" && PROPOSAL_ID.test(p),
  );
  let grant: Entry | null;
  if (TRUST_KINDS.has(r.kind)) {
    if (r.binding !== false || minutes !== null) return null;
    grant = validItem(r);
    if (!grant) return null;
  } else if (r.binding === true) {
    if (!printableWord(r.pattern) || bindingProblem(r.pattern)) return null;
    grant = { kind: "destination", pattern: r.pattern };
  } else {
    grant = grants.hintGrant(r, { folder: true });
    if (!grant) return null;
  }
  return { binding: r.binding === true, ...grant, minutes, tags, proposals };
}

/** `apply <code> ...`: sets the chosen items of the screen the code belongs to, in one locked pass. */
export function apply(cfg: PluginConfig, rest: string, by: Entry, now: Date, cmd: Cmd, record: RecordFn, beforeWrite: () => void): string {
  const parsed = parseApply(rest, cmd);
  if (typeof parsed === "string") return parsed;
  const refused = `That is not the code on the setup screen, or it has expired: ${openText(cmd)}`;
  const state = cfg.stateDir;
  const store = new Store(state);
  const lock = <T>(file: string, fn: () => T) => withFileLock(path.join(state, file), fn);
  const result = lock("setup.json", () =>
    lock("grants.json", () =>
      lock("proposals.json", (): { reply: string; changes: Entry[]; trusts: Entry[]; chosen: number[]; closed: string[] } | string => {
        const kept = store.loadSetup();
        if (!codeOk(kept, parsed.code, now)) return refused;
        const shown: unknown[] = Array.isArray(kept.items) ? kept.items : [];
        for (const n of parsed.numbers) {
          if (n < 1 || n > shown.length) return `There is no item ${n} on the setup screen: ${openText(cmd)}`;
        }
        const data = store.loadGrants();
        if (data === null) return `The grants file ${path.join(state, "grants.json")} could not be read; fix or remove it first.`;
        const rawProps = store.loadProposals();
        if (rawProps === null) return `The proposals file ${path.join(state, "proposals.json")} could not be read; fix or remove it first.`;
        const live = new Map(liveProposals(rawProps, now).map((p) => [p.id as string, p]));
        const chosen = parsed.numbers.length
          ? [...new Set(parsed.numbers)].sort((a, b) => a - b)
          : Array.from({ length: shown.length }, (_, i) => i + 1);
        const lines: string[] = [];
        const changes: Entry[] = [];
        const trusts: Entry[] = [];
        const applied: Entry[] = [];
        for (const n of chosen) {
          const item = storedItem(shown[n - 1]);
          if (!item) {
            lines.push(`${n}. Not set: this item could not be read again; ${openText(cmd)}`);
            continue;
          }
          const gone = item.proposals.filter((p) => !live.has(p));
          const tags = item.tags.filter((t) => !gone.includes(t));
          if (gone.length && !tags.length) {
            lines.push(`${n}. Not set: proposal ${gone[0]} was discarded or has expired since the screen was shown.`);
            continue;
          }
          const [line, change] = TRUST_KINDS.has(item.kind)
            ? applyTrust(cfg, item, tags, by, now, n, beforeWrite)
            : applyOne(cfg, data, item, tags, parsed, by, now, n);
          lines.push(line);
          if (change) (change.kind === "settings" ? trusts : changes).push(change);
          applied.push(item);
        }
        const closed = close(rawProps, live, applied);
        beforeWrite();
        if (changes.length) {
          data.grants = data.grants.filter((g) => !(g && typeof g === "object" && grants.expired(g as Entry, now)));
          store.saveGrants(data);
        }
        if (closed !== null) store.saveProposals(rawProps);
        store.saveSetup({ ...kept, code: null });
        return { reply: lines.join("\n"), changes, trusts, chosen, closed: closed ?? [] };
      }),
    ),
  );
  if (typeof result === "string") return result;
  for (const change of result.changes) record({ kind: "grants", ...change, by });
  for (const change of result.trusts) record({ ...change, by });
  record({ kind: "setup", op: "apply", items: result.chosen, closed: result.closed, by });
  const end = `Remove a grant with ${cmd("revoke")} <id> and a channel with ${cmd("bind")} remove <channel>; ${cmd("grants")} lists what is in force.`;
  return ["Set from the setup screen:", result.reply, end].join("\n");
}

function applyOne(
  cfg: PluginConfig,
  data: GrantsFile,
  item: Entry,
  tags: string[],
  parsed: ApplyArgs,
  by: Entry,
  now: Date,
  n: number,
): [string, Entry | null] {
  const p: string = item.pattern;
  if (item.binding) {
    const bound = cfg.channelBindings.includes(p) || data.bindings.some((b) => (b as Entry)?.pattern === p);
    if (bound) return [`${n}. Already set: channel \`${p}\`.`, null];
    const entry: Entry = { pattern: p, granted_at: iso(now), set_by: by, source: tags };
    data.bindings.push(entry);
    return [`${n}. Channel binding added: \`${p}\` (until you remove it).`, { op: "bind_add", entry }];
  }
  if (item.kind === "folder") return applyFolder(cfg, data, item, tags, parsed, by, now, n);
  const sorted = (a: unknown) => (Array.isArray(a) && a.length ? JSON.stringify([...a].sort()) : "null");
  const want = sorted(item.allows);
  const existing = data.grants.find((g) => {
    const e = g as Entry;
    return (
      e &&
      typeof e === "object" &&
      e.kind === item.kind &&
      e.pattern === p &&
      sorted(e.allows) === want &&
      e.scope === "persistent" &&
      !grants.expired(e, now)
    );
  }) as Entry | undefined;
  if (existing) return [`${n}. Already set: ${item.kind} \`${p}\` (${hold.inert(existing.id, 20)}).`, null];
  const minutes = parsed.untilRevoked ? null : (parsed.minutes ?? item.minutes);
  const taken = new Set(data.grants.map((g) => (g as Entry)?.id));
  let id = `gr-${randomBytes(3).toString("hex")}`;
  while (taken.has(id)) id = `gr-${randomBytes(3).toString("hex")}`;
  const entry: Entry = { id, kind: item.kind, pattern: p };
  if (Array.isArray(item.allows) && item.allows.length) entry.allows = [...item.allows];
  entry.scope = "persistent";
  entry.granted_at = iso(now);
  const until = minutes === null ? null : new Date(now.getTime() + minutes * 60_000);
  if (until) entry.expires_at = iso(until);
  entry.set_by = by;
  entry.source = tags;
  data.grants.push(entry);
  const allows = entry.allows ? `, allows ${entry.allows.join(",")}` : "";
  const life = until ? `expires ${show(until)}` : "until you revoke it";
  return [`${n}. Granted ${id}: ${item.kind} \`${p}\`${allows} (persistent, ${life}).`, { op: "grant", entry }];
}

/**
 * A trusted chat or user from the screen, set as `trust-chat add` / `trust-user add` would set it (the owner read the
 * warning on the screen). The change goes to the traffic log as a `settings` record (its `kind`).
 */
function applyTrust(
  cfg: PluginConfig,
  item: Entry,
  tags: string[],
  by: Entry,
  now: Date,
  n: number,
  beforeWrite: () => void,
): [string, Entry | null] {
  const kind = item.kind === "trusted_chat" ? "chat" : "user";
  const rest = `add ${item.pattern}${item.owner_only ? " --owner-only" : ""} --confirm`;
  const { reply, change } = trust.run(cfg, kind, rest, by, {}, {}, now, (sub) => `/sentrook-${sub}`, beforeWrite);
  if (change === null) return [`${n}. Not set: ${reply}`, null];
  return [`${n}. ${reply}`, { ...change, kind: "settings", source: tags }];
}

/**
 * A folder item: records what the folder holds now (`grants.recordFolder`) and replaces any folder grant on the same
 * folder, as `grant folder` does.
 */
function applyFolder(
  cfg: PluginConfig,
  data: GrantsFile,
  item: Entry,
  tags: string[],
  parsed: ApplyArgs,
  by: Entry,
  now: Date,
  n: number,
): [string, Entry | null] {
  const got = grants.recordFolder(cfg.stateDir, item.pattern, item.follow ?? null, now);
  if (typeof got === "string") return [`${n}. ${got}`, null];
  const [pattern, manifest] = got;
  const gone = grants.dropFolder(data, pattern);
  const minutes = parsed.untilRevoked ? null : (parsed.minutes ?? item.minutes);
  const taken = new Set([...data.grants.map((g) => (g as Entry)?.id), ...gone.map((g) => g.id)]);
  let id = `gr-${randomBytes(3).toString("hex")}`;
  while (taken.has(id)) id = `gr-${randomBytes(3).toString("hex")}`;
  folders.save(cfg.stateDir, id, manifest);
  for (const g of gone) if (typeof g.id === "string") folders.remove(cfg.stateDir, g.id);
  const entry: Entry = { id, kind: "folder", pattern };
  if (item.follow) entry.follow = item.follow;
  entry.scope = "persistent";
  entry.granted_at = iso(now);
  const until = minutes === null ? null : new Date(now.getTime() + minutes * 60_000);
  if (until) entry.expires_at = iso(until);
  entry.set_by = by;
  entry.source = tags;
  data.grants.push(entry);
  const life = until ? `expires ${show(until)}` : "until you revoke it";
  const replaced = gone.length ? `, replaces ${gone.map((g) => String(g.id)).join(", ")}` : "";
  return [`${n}. Trusted ${id}: folder \`${pattern}\` (${folders.describe(manifest)}, ${life}${replaced}).`, { op: "grant", entry }];
}

/**
 * Takes the applied items out of their proposals and closes each proposal with nothing readable left; drops expired
 * proposals. Returns the closed ids, or null when the file needs no change.
 */
function close(raw: ProposalsFile, live: Map<string, Entry>, applied: Entry[]): string[] | null {
  const done = new Map<string, Set<string>>();
  for (const item of applied) {
    for (const pid of item.proposals as string[]) {
      if (!done.has(pid)) done.set(pid, new Set());
      done.get(pid)!.add(keyOf(item));
    }
  }
  const stored = raw.proposals;
  const kept: unknown[] = [];
  const closed: string[] = [];
  for (const p of stored) {
    if (!p || typeof p !== "object" || !live.has((p as Entry).id)) continue;
    const keys = done.get((p as Entry).id);
    if (!keys) {
      kept.push(p);
      continue;
    }
    const items = (Array.isArray((p as Entry).items) ? (p as Entry).items : []).filter((i: unknown) => {
      const it = proposalItem(i);
      return !(it !== null && keys.has(keyOf(it)));
    });
    if (!items.some((i: unknown) => proposalItem(i) !== null)) {
      closed.push((p as Entry).id);
      continue;
    }
    kept.push({ ...(p as Entry), items });
  }
  if (!closed.length && !done.size && kept.length === stored.length) return null;
  raw.proposals = kept;
  return closed;
}

export function discard(cfg: PluginConfig, rest: string, by: Entry, now: Date, cmd: Cmd, record: RecordFn, beforeWrite: () => void): string {
  const pid = rest.trim();
  if (!PROPOSAL_ID.test(pid)) {
    if (pid) return `No proposal ${hold.inert(pid, 40)}: open ${cmd("setup")} to see the proposals.`;
    return `usage: ${cmd("setup")} discard <id>, with a proposal id from ${cmd("setup")}`;
  }
  const store = new Store(cfg.stateDir);
  const result = withFileLock(path.join(cfg.stateDir, "proposals.json"), (): Entry | string => {
    const raw = store.loadProposals();
    if (raw === null) return `The proposals file ${path.join(cfg.stateDir, "proposals.json")} could not be read; fix or remove it first.`;
    const live = liveProposals(raw, now);
    const found = live.find((p) => p.id === pid);
    if (!found) return `No proposal ${pid}: open ${cmd("setup")} to see the proposals.`;
    beforeWrite();
    raw.proposals = live.filter((p) => p !== found);
    store.saveProposals(raw);
    return found;
  });
  if (typeof result === "string") return result;
  record({ kind: "setup", op: "discard", proposal: pid, by });
  const n = Array.isArray(result.items) ? result.items.length : 0;
  return `Discarded proposal ${pid} (${n} item${plural(n)}); nothing from it was set.`;
}

/** `setup`, `setup apply ...` or `setup discard <id>`. */
export function run(
  cfg: PluginConfig,
  rest: string,
  by: Entry,
  now: Date,
  cmd: Cmd,
  record: RecordFn,
  beforeWrite: () => void,
  src: Sources,
): string {
  const trimmed = rest.trim();
  const space = trimmed.search(/\s/);
  const verb = (space < 0 ? trimmed : trimmed.slice(0, space)).toLowerCase();
  const more = space < 0 ? "" : trimmed.slice(space + 1);
  if (!verb) return showScreen(cfg, now, cmd, src, beforeWrite);
  if (verb === "apply") return apply(cfg, more, by, now, cmd, record, beforeWrite);
  if (verb === "discard") return discard(cfg, more, by, now, cmd, record, beforeWrite);
  return usage(cmd);
}
