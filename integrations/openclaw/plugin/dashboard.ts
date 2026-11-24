/**
 * The read-only dashboard: a Control UI tab showing recent scans and each scan's risk tree.
 *
 * `buildModel` turns the tail of the traffic log into the JSON the page draws. It holds only what the scanner
 * returned (risk, the tier and leaf scores, floors, relief, reason codes and texts, entity display strings) plus
 * the plugin's own labels for what it did. The PlanIR as sent, the call's arguments, `reasons[].detail` and
 * failure details are never included, as with `/sentrook-why`; a scan's report panel (`reportOf`) holds only its
 * summary, links and commands. One exception, off by default: with `dashboardShowCalls` the owner lets each scan
 * carry its call (tool and arguments, as sent to the scanner and so redacted, bounded by `callOf`), knowing anyone
 * who can open the tab can then read it. The Hermes plugin builds the same model for the same log
 * (fixtures/traffic-log/dashboard).
 *
 * The page is served on a Gateway route with `auth: "gateway"`. Inside the Control UI tab the browser holds a
 * short-lived grant that allows only GET and HEAD with `operator.read`, so the page cannot change anything;
 * the route refuses every other method too. Changes stay with the owner commands.
 */

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { type FileHandle, open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { PluginConfig } from "./config.ts";
import * as grants from "./grants.ts";
import * as passes from "./passes.ts";
import { actionOf, HISTORY_DEFAULT, HISTORY_MAX, parseRef, recentScans, responseOf, reviewOf, text } from "./history.ts";
import * as report from "./report.ts";
import * as snooze from "./snooze.ts";
import { readTime, Store } from "./store.ts";

type Rec = Record<string, any>;

export const ROUTE = "/sentrook";
/** The answers a held call can offer, as the page shows them. */
const ANSWERS: string[] = [passes.ALLOW, passes.ALLOW_ALWAYS, passes.DENY];
export const MODEL_VERSION = 1;

/** The leaves of each tier, in the order the page shows them; any other numeric key follows, sorted. */
export const TIERS: Array<[string, string[]]> = [
  [
    "suspicion",
    ["misalignment", "concealment", "overreach", "distrust", "request_origin", "retry_after_denial", "untrusted_origin", "exposure", "session_exposure"],
  ],
  ["consequence", ["sensitivity", "reach", "irreversibility", "self_modification"]],
  ["confidence", ["agreement", "coverage", "model_certainty"]],
];

/** Plugin marks on a scan record worth showing next to the action. */
const FLAGS = ["snoozed", "relaxed", "lenient", "hold", "notice", "skill_review", "self_edit", "host_process"];

function unit(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? Math.min(Math.max(v, 0), 1) : null;
}

function finite(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function str(v: unknown, limit: number): string | null {
  return typeof v === "string" && v.trim() ? text(v, limit) : null;
}

function obj(v: unknown): Rec {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {};
}

function list(v: unknown): Rec[] {
  return Array.isArray(v) ? v.filter((x) => x && typeof x === "object" && !Array.isArray(x)) : [];
}

function tiers(tree: Rec): Rec[] {
  return TIERS.map(([name, known]) => {
    const t = obj(tree[name]);
    const extra = Object.keys(t)
      .filter((k) => k !== "score" && !known.includes(k) && typeof t[k] === "number")
      .sort();
    return {
      name,
      score: unit(t.score),
      leaves: [...known, ...extra].map((leaf) => ({ name: leaf, value: unit(t[leaf]) })),
    };
  });
}

/** E1, E2, ..., E10 in number order. */
function entityOrder(a: string, b: string): number {
  const num = (k: string) => (/^\d+$/.test(k.slice(1)) ? Number(k.slice(1)) : Number.POSITIVE_INFINITY);
  return num(a) - num(b) || (a < b ? -1 : a > b ? 1 : 0);
}

/**
 * Which total a scan counts towards. A background save sent to the drafts waits for the owner (review); one OpenClaw
 * did not keep was not made (blocked).
 */
export function bucketOf(scan: Rec, action: string): string {
  if (responseOf(scan) === null) return "scan_error";
  if (action.startsWith("blocked") || action.startsWith("not saved")) return "blocked";
  if (["review", "held", "drafted", "sent to drafts"].some((p) => action.startsWith(p))) return "review";
  if (action.startsWith("observed")) return "observed";
  return "allowed";
}

/** Bounds on the call a scan carries when the owner turned calls on, counted in code points as Python counts. */
export const CALL_STRING_MAX = 8000;
export const CALL_TOTAL_MAX = 24000;
export const CALL_ITEMS_MAX = 100;
export const CALL_DEPTH_MAX = 8;
export const CALL_KEY_MAX = 200;

function key(k: string): string {
  const c = [...k];
  return c.length <= CALL_KEY_MAX ? k : `${c.slice(0, CALL_KEY_MAX).join("")}…`;
}

function cut(s: string, budget: { left: number }): string {
  const c = [...s];
  const take = Math.min(c.length, CALL_STRING_MAX, budget.left);
  budget.left -= take;
  return take === c.length ? s : `${c.slice(0, take).join("")}… (${c.length - take} more characters)`;
}

function bounded(v: unknown, budget: { left: number }, depth: number): unknown {
  if (v === null || typeof v === "boolean") return v;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string") return cut(v, budget);
  if (typeof v !== "object") return null;
  if (depth >= CALL_DEPTH_MAX) return "… (nested too deep)";
  if (Array.isArray(v)) {
    const out = v.slice(0, CALL_ITEMS_MAX).map((x) => bounded(x, budget, depth + 1));
    if (v.length > CALL_ITEMS_MAX) out.push(`… (${v.length - CALL_ITEMS_MAX} more items)`);
    return out;
  }
  const keys = Object.keys(v);
  const out: Rec = {};
  for (const k of keys.slice(0, CALL_ITEMS_MAX)) out[key(k)] = bounded((v as Rec)[k], budget, depth + 1);
  if (keys.length > CALL_ITEMS_MAX) out["…"] = `${keys.length - CALL_ITEMS_MAX} more keys`;
  return out;
}

/**
 * The call as sent to the scanner (`planir.pending_call`, already redacted on the host): its tool and arguments,
 * each string at most CALL_STRING_MAX code points and CALL_TOTAL_MAX in all, lists and objects at most
 * CALL_ITEMS_MAX entries, CALL_DEPTH_MAX deep, keys at most CALL_KEY_MAX. Nothing else from the PlanIR. Null for a
 * record without one.
 */
export function callOf(scan: Rec): Rec | null {
  const call = obj(obj(scan.planir).pending_call);
  if (!Object.keys(call).length) return null;
  return { tool: str(call.tool, 80), arguments: bounded(call.arguments ?? {}, { left: CALL_TOTAL_MAX }, 0) };
}

export function scanModel(scan: Rec, resolution: Rec | null, withCall = false): Rec {
  const resp = responseOf(scan);
  const r: Rec = resp ?? {};
  const action = actionOf(scan, resolution);
  const entities = obj(r.entities);
  const call = withCall ? { call: callOf(scan) } : {};
  return {
    ...call,
    id: String(scan.request_id),
    ts: typeof scan.ts === "string" ? scan.ts : null,
    session: str(scan.session_ref, 80),
    tool: str(scan.tool, 80),
    step: Number.isInteger(scan.step) ? scan.step : null,
    mode: str(scan.mode, 20),
    action,
    review: reviewOf(action, resolution),
    bucket: bucketOf(scan, action),
    flags: FLAGS.filter((f) => scan[f] === true),
    // An approval prompt that had no answer when the log was read: still open if it is recent (`pendingOf`).
    open_review: resp !== null && scan.mode !== "observe" && scan.verdict === "review" && scan.decision === "review_timed_out" && resolution === null,
    failure: resp === null ? (str(obj(scan.failure).kind, 40) ?? "unknown") : null,
    risk: finite(r.risk),
    enforced: r.enforced === "review" || r.enforced === "block" ? r.enforced : null,
    ceiling: str(r.ceiling, 20),
    tiers: resp === null ? [] : tiers(obj(r.tree)),
    floors: list(r.floors_applied).map((f) => ({ floor: str(f.floor, 80), min_risk: unit(f.min_risk), subject: str(f.subject, 12) })),
    relief: list(r.relief_applied).map((f) => ({ effect: str(f.effect, 80), grant_ref: str(f.grant_ref, 40), subject: str(f.subject, 12) })),
    reasons: list(r.reasons)
      .filter((x) => typeof x.code === "string" && x.code)
      .map((x) => ({ code: text(x.code, 80), signal: str(x.signal, 60), subject: str(x.subject, 12), text: str(x.text, 200) })),
    entities: Object.keys(entities)
      .sort(entityOrder)
      .filter((k) => typeof obj(entities[k]).display === "string")
      .map((k) => ({ id: text(k, 12), kind: str(entities[k].kind, 20), display: text(entities[k].display, 200) })),
  };
}

/** The scans part of the model; both plugins build the same JSON for the same log. */
export function scansModel(file: string, enabled: boolean, limit: number): Rec {
  const scans = enabled ? recentScans(file, limit).map(([s, res]) => scanModel(s, res)) : [];
  return { version: MODEL_VERSION, log: enabled ? "on" : "off", limit, scans, totals: totalsOf(scans) };
}

function totalsOf(scans: Rec[]): Record<string, number> {
  const totals: Record<string, number> = { blocked: 0, review: 0, observed: 0, allowed: 0, scan_error: 0 };
  for (const s of scans) totals[s.bucket] = (totals[s.bucket] ?? 0) + 1;
  return totals;
}

/** `?n=` from the page's limit links: the history default when absent or malformed, at most the history max. */
export function limitOf(raw: string | null): number {
  if (!raw || !/^[0-9]{1,4}$/.test(raw) || Number(raw) < 1) return HISTORY_DEFAULT;
  return Math.min(Number(raw), HISTORY_MAX);
}

// --- Searching the log.
//
// The traffic log is a plain JSON-lines file, newest last, rotated once to `<path>.1`, so there is no index. A
// query reads it backwards from the end, as history does, and keeps the cost down three ways:
// - every line starts `{"ts": "...", "kind": "...", "request_id": "..."`, so a scan outside the time window, or
//   one before the paging cursor, is skipped on its first bytes without parsing the line (scan lines carry the
//   whole PlanIR and are the large ones);
// - reading stops at the window's start, at a full page, or after QUERY_BUDGET_BYTES;
// - a page is at most HISTORY_MAX scans, and "older" continues from the last scan shown (a request-id cursor).
// Resolution lines are small and always read, so a scan on any page is joined to its answer.

export const QUERY_BUDGET_BYTES = 64 * 1024 * 1024;
const MB = 1024 * 1024;

/** Enough to read the whole log (the file and its one rotation) at the configured size, within 16 to 256 MB. */
export function budgetFor(maxBytes: number): number {
  return Math.min(Math.max(2 * maxBytes + MB, 16 * MB), 256 * MB);
}
const CHUNK = 64 * 1024;
const OUTCOMES = ["blocked", "review", "observed", "allowed", "scan_error"];
const CURSOR = /^[0-9a-fA-F-]{4,40}$/;
const HEAD = /^\{"ts": ?"([^"]{10,40})", ?"kind": ?"([a-z_]{1,20})"(?:, ?"request_id": ?"([^"]{1,64})")?/;

export interface Query {
  limit: number;
  /** Older than this scan: the request id of the last scan on the page before. */
  before: string | null;
  /** Time window, epoch ms, inclusive. */
  from: number | null;
  to: number | null;
  /** Tool name contains this, ignoring case. */
  tool: string | null;
  outcome: string | null;
  minRisk: number | null;
  session: string | null;
}

/** Reads the page's query string; anything malformed is left out rather than refused. */
export function queryOf(params: URLSearchParams): Query {
  const time = (k: string) => {
    const v = params.get(k);
    // With an explicit zone only, so both plugins read it the same (the page sends UTC).
    const at = v && v.length <= 40 && /(Z|[+-]\d\d:\d\d)$/.test(v) ? Date.parse(v) : Number.NaN;
    return Number.isFinite(at) ? at : null;
  };
  const textParam = (k: string, max: number) => {
    const v = (params.get(k) ?? "").trim();
    return v && v.length <= max ? v : null;
  };
  const before = params.get("before");
  const outcome = params.get("outcome");
  const risk = params.get("risk");
  return {
    limit: limitOf(params.get("n")),
    before: before && CURSOR.test(before) ? before.toLowerCase() : null,
    from: time("from"),
    to: time("to"),
    tool: textParam("tool", 80),
    outcome: outcome && OUTCOMES.includes(outcome) ? outcome : null,
    minRisk: risk && /^[0-9]{1,3}$/.test(risk) && Number(risk) <= 100 ? Number(risk) : null,
    session: textParam("session", 80),
  };
}

/** The query as the page shows it back (times as ISO strings). */
function queryEcho(q: Query): Rec {
  const iso = (v: number | null) => (v === null ? null : new Date(v).toISOString());
  return { limit: q.limit, before: q.before, from: iso(q.from), to: iso(q.to), tool: q.tool, outcome: q.outcome, min_risk: q.minRisk, session: q.session };
}

/** Lines of `file` then `<file>.1`, newest first, with the bytes read so far; stops when the budget is spent. */
async function* linesBackward(file: string, budget: { left: number; read: number }): AsyncGenerator<string> {
  for (const f of [file, `${file}.1`]) {
    let fh: FileHandle;
    try {
      fh = await open(f, "r");
    } catch {
      continue;
    }
    try {
      let pos = (await fh.stat()).size;
      let head = Buffer.alloc(0);
      while (pos > 0 && budget.left > 0) {
        const step = Math.min(CHUNK, pos, budget.left);
        pos -= step;
        budget.left -= step;
        budget.read += step;
        const chunk = Buffer.alloc(step);
        await fh.read(chunk, 0, step, pos);
        const buf = Buffer.concat([chunk, head]);
        const parts: string[] = [];
        let end = buf.length;
        for (let i = buf.length - 1; i >= 0; i--) {
          if (buf[i] === 0x0a) {
            parts.push(buf.subarray(i + 1, end).toString("utf8"));
            end = i;
          }
        }
        head = buf.subarray(0, end);
        yield* parts;
      }
      if (pos === 0 && head.length) yield head.toString("utf8");
      if (budget.left <= 0) return;
    } finally {
      await fh.close();
    }
  }
}

interface Head {
  at: number;
  kind: string;
  rid: string | null;
}

/** The time, kind and request id from a line's first bytes; null when the line does not start as the plugins write. */
function headOf(line: string): Head | null {
  const m = HEAD.exec(line.slice(0, 200));
  if (!m) return null;
  const at = Date.parse(m[1]!);
  return Number.isFinite(at) ? { at, kind: m[2]!, rid: m[3] ?? null } : null;
}

function parse(line: string): Rec | null {
  try {
    const v = JSON.parse(line);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

function matches(s: Rec, q: Query): boolean {
  if (q.tool !== null && !(s.tool ?? "").toLowerCase().includes(q.tool.toLowerCase())) return false;
  if (q.outcome !== null && s.bucket !== q.outcome) return false;
  if (q.minRisk !== null && !(typeof s.risk === "number" && s.risk >= q.minRisk)) return false;
  if (q.session !== null && s.session !== q.session) return false;
  return true;
}

/**
 * One page of scans matching `q`, newest first. `more`: the page filled up, so older matches may follow from
 * `next` (the last scan's id). `budget_hit`: the read stopped at the budget before the log or window ran out.
 * `cursor_lost`: the `before` scan was not found (rotated away), so nothing older could be listed.
 */
export async function queryScans(file: string, q: Query, budgetBytes = QUERY_BUDGET_BYTES, withCalls = false): Promise<Rec> {
  const budget = { left: budgetBytes, read: 0 };
  const resolutions = new Map<string, Rec>();
  const seen = new Set<string>();
  const scans: Rec[] = [];
  let passed = q.before === null;
  let stopped = false;
  let exhausted = true;
  for await (const line of linesBackward(file, budget)) {
    if (!line.trim()) continue;
    let head = headOf(line);
    let rec: Rec | null = null;
    if (head === null) {
      rec = parse(line);
      const at = typeof rec?.ts === "string" ? Date.parse(rec.ts) : Number.NaN;
      if (!rec || !Number.isFinite(at)) continue;
      head = { at, kind: String(rec.kind), rid: typeof rec.request_id === "string" ? rec.request_id : null };
    }
    if (head.kind === "resolution") {
      rec ??= parse(line);
      const rid = rec?.request_id;
      if (typeof rid === "string" && !resolutions.has(rid)) resolutions.set(rid, rec!);
      continue;
    }
    if (head.kind !== "scan" || head.rid === null) continue;
    if (!passed) {
      if (head.rid.toLowerCase() === q.before) passed = true;
      continue;
    }
    if (q.to !== null && head.at > q.to) continue;
    if (q.from !== null && head.at < q.from) {
      exhausted = false;
      stopped = true;
      break;
    }
    if (seen.has(head.rid)) continue;
    // A tool name the line does not contain cannot match: skip it unparsed.
    if (q.tool !== null && !line.toLowerCase().includes(q.tool.toLowerCase())) continue;
    rec ??= parse(line);
    if (!rec || rec.request_id !== head.rid) continue;
    seen.add(head.rid);
    const model = scanModel(rec, resolutions.get(head.rid) ?? null, withCalls);
    if (!matches(model, q)) continue;
    scans.push(model);
    if (scans.length >= q.limit) {
      exhausted = false;
      stopped = true;
      break;
    }
  }
  const budgetHit = !stopped && budget.left <= 0;
  if (budgetHit) exhausted = false;
  const full = scans.length >= q.limit;
  return {
    scans,
    totals: totalsOf(scans),
    query: queryEcho(q),
    page: {
      more: full,
      next: full ? scans.at(-1)!.id : null,
      read_bytes: budget.read,
      budget_hit: budgetHit,
      cursor_lost: !passed,
      reached_start: exhausted && passed,
    },
  };
}

const CMD: grants.Cmd = (sub) => `/sentrook-${sub}`;

/**
 * What waits for the owner, read on its own so it does not depend on the page's search: approval prompts still
 * inside their answer window (`windowMs`, the host's approval timeout), and held calls (unattended reviews) not
 * yet approved or expired, newest first, each with its scan when that is still in the log. Reading stops at the
 * oldest of these.
 */
export async function pendingOf(
  file: string,
  enabled: boolean,
  stateDir: string,
  now: Date,
  windowMs: number,
  budgetBytes = QUERY_BUDGET_BYTES,
  withCalls = false,
): Promise<Rec> {
  let holds: Rec[] = [];
  let holdsReadable = true;
  try {
    const data = new Store(stateDir).loadHolds();
    if (data === null) holdsReadable = false;
    holds = (data?.holds ?? [])
      .filter((h): h is Rec => !!h && typeof h === "object" && typeof (h as Rec).id === "string")
      .filter((h) => (readTime(h.expires_at)?.getTime() ?? 0) > now.getTime())
      .map((h) => {
        const grant = grants.hintGrant(h.hint);
        return {
          id: text(h.id, 12),
          request_id: str(h.request_id, 40),
          tool: str(h.tool, 80),
          where: str(h.where, 200),
          held_at: typeof h.held_at === "string" ? h.held_at : null,
          expires_at: typeof h.expires_at === "string" ? h.expires_at : null,
          grant: grant ? grants.describeGrant(grant) : null,
          scan: null as Rec | null,
          // the answers a hold offers (passes.offers); null for a hold from before they were kept
          offers: h.v === 2 && Array.isArray(h.offers) ? h.offers.filter((o: unknown) => ANSWERS.includes(o as string)) : null,
          count: Number.isInteger(h.count) && h.count > 0 ? h.count : 1,
        };
      })
      .reverse();
  } catch {
    holdsReadable = false;
  }
  const reviews: Rec[] = [];
  const windowStart = now.getTime() - windowMs;
  let start = windowStart;
  const wanted = new Map<string, Rec>();
  for (const h of holds) {
    if (h.request_id) wanted.set(h.request_id, h);
    const at = h.held_at ? Date.parse(h.held_at) : Number.NaN;
    // A hold is made right after its scan; a minute's margin covers the scan's own time.
    if (Number.isFinite(at)) start = Math.min(start, at - 60_000);
  }
  if (enabled) {
    const budget = { left: budgetBytes, read: 0 };
    const resolutions = new Map<string, Rec>();
    for await (const line of linesBackward(file, budget)) {
      const head = headOf(line);
      if (head === null) continue;
      if (head.at < start) break;
      if (head.kind === "resolution") {
        const rec = parse(line);
        if (rec && typeof rec.request_id === "string" && !resolutions.has(rec.request_id)) resolutions.set(rec.request_id, rec);
        continue;
      }
      if (head.kind !== "scan" || head.rid === null) continue;
      const hold = wanted.get(head.rid);
      const recent = head.at >= windowStart && head.at <= now.getTime();
      if (!hold && !recent) continue;
      const rec = parse(line);
      if (!rec || rec.request_id !== head.rid) continue;
      const model = scanModel(rec, resolutions.get(head.rid) ?? null, withCalls);
      if (hold && hold.scan === null) hold.scan = model;
      if (recent && model.open_review && !reviews.some((r) => r.id === model.id)) reviews.push(model);
    }
  }
  return { reviews, holds, holds_readable: holdsReadable, review_window_s: Math.round(windowMs / 1000) };
}

/**
 * The report panel for the scan the page asked about (`report=<request id or its start>`), or null when it asked
 * about none: the summary `/sentrook-report` prints, the issue and email links, and the owner's commands for the
 * full record, which the model never holds.
 */
export function reportOf(cfg: PluginConfig, ref: string | null | undefined, budget: number): Rec | null {
  const r = (ref ?? "").trim();
  if (!r) return null;
  const match = r.toLowerCase() === "last" ? null : parseRef(r);
  const found = match !== null && cfg.trafficLog.enabled ? report.find(cfg.trafficLog.path, match, budget) : null;
  return found !== null ? report.model(found, CMD) : { id: r.slice(0, 36), missing: true };
}

export async function buildModel(cfg: PluginConfig, q: Query, now: Date = new Date(), reportRef: string | null = null): Promise<Rec> {
  const enabled = cfg.trafficLog.enabled;
  const budget = budgetFor(cfg.trafficLog.maxBytes);
  const calls = cfg.dashboardShowCalls;
  const page = enabled ? await queryScans(cfg.trafficLog.path, q, budget, calls) : { scans: [], totals: totalsOf([]), query: queryEcho(q), page: { more: false, next: null, read_bytes: 0, budget_hit: false, cursor_lost: false, reached_start: true } };
  let passesText: string;
  try {
    passesText = passes.formatPasses(cfg.stateDir, now, CMD);
  } catch {
    passesText = "Passes could not be read.";
  }
  let grantsText: string;
  let snoozeText: string;
  try {
    grantsText = grants.formatGrants(cfg, grants.load(cfg.stateDir), now, CMD, null);
  } catch {
    grantsText = "Grants could not be read.";
  }
  try {
    snoozeText = snooze.statusLine(snooze.load(cfg.stateDir), now);
  } catch {
    snoozeText = "Snooze state could not be read.";
  }
  const model: Rec = {
    version: MODEL_VERSION,
    log: enabled ? "on" : "off",
    limit: q.limit,
    ...page,
    host: "openclaw",
    lines: { review_at: cfg.reviewAt, block_at: cfg.blockAt },
    mode: cfg.mode,
    state: { grants: grantsText, passes: passesText, snooze: snoozeText },
    pending: await pendingOf(cfg.trafficLog.path, enabled, cfg.stateDir, now, cfg.approval.interactiveTimeoutMs, budget, calls),
    commands: COMMANDS,
    show_calls: calls,
  };
  const panel = reportOf(cfg, reportRef, budget);
  if (panel !== null) model.report = panel;
  return model;
}

/** How the page names this host's commands: the plugin's own (prefix + verb) and the host's approval answers. */
export const COMMANDS = {
  prefix: "/sentrook-",
  /** The setting that lets each scan show its call, as the owner writes it in this host's config. */
  call_setting: "openclaw config set plugins.entries.sentrook.config.dashboardShowCalls true",
  review_answer: [
    "Answer on the approval card in the chat where it was asked, or with OpenClaw's own command and the id the prompt shows:",
    "/approve <approval id> allow-once",
    "/approve <approval id> allow-always",
    "/approve <approval id> deny",
  ],
};

let viewSource: string | null = null;

/** The browser script, shared byte for byte with the Hermes plugin's dashboard bundle. */
export function viewScript(): string {
  if (viewSource !== null) return viewSource;
  const here = path.dirname(fileURLToPath(import.meta.url));
  // Next to index.ts when run from source; one level up from dist/index.js when bundled.
  for (const dir of [here, path.dirname(here)]) {
    try {
      viewSource = readFileSync(path.join(dir, "dashboardView.js"), "utf8");
      return viewSource;
    } catch {
      // Try the next place.
    }
  }
  viewSource = "document.body.textContent = 'The Sentrook dashboard script is missing from this install.';";
  return viewSource;
}

/** JSON safe inside a `<script>` element: no `<`, `>` or `&`, and no line separators. */
export function scriptJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export function renderPage(model: unknown, nonce: string, script: string = viewScript()): string {
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Sentrook</title></head>",
    '<body><div id="sentrook-root"></div>',
    `<script type="application/json" id="sentrook-model">${scriptJson(model)}</script>`,
    `<script nonce="${nonce}">${script.replace(/<\/script/gi, "<\\/script")}</script>`,
    "</body></html>",
  ].join("\n");
}

interface Req {
  method?: string;
  url?: string;
}
interface Res {
  statusCode: number;
  setHeader: (name: string, value: string) => void;
  end: (body?: string) => void;
}

function send(res: Res, status: number, type: string, body: string, head: boolean, extra: Record<string, string> = {}): true {
  res.statusCode = status;
  res.setHeader("Content-Type", type);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(head ? undefined : body);
  return true;
}

/**
 * The route handler: GET or HEAD of `/sentrook` (or `/sentrook/`) draws the page; nothing else is served. A path
 * that only shares the prefix (`/sentrook-x`) is not ours and is left to the Gateway (false).
 */
export async function handleRequest(req: Req, res: Res, loadConfig: () => PluginConfig, now: () => Date = () => new Date()): Promise<boolean> {
  const pathname = new URL(req.url ?? ROUTE, "http://gateway.invalid").pathname;
  if (pathname !== ROUTE && !pathname.startsWith(`${ROUTE}/`)) return false;
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    return send(res, 405, "text/plain; charset=utf-8", "The Sentrook dashboard is read-only.", false, { Allow: "GET, HEAD" });
  }
  const head = method === "HEAD";
  const url = new URL(req.url ?? ROUTE, "http://gateway.invalid");
  if (url.pathname !== ROUTE && url.pathname !== `${ROUTE}/`) {
    return send(res, 404, "text/plain; charset=utf-8", "Not found.", head);
  }
  let model: unknown;
  try {
    model = await buildModel(loadConfig(), queryOf(url.searchParams), now(), url.searchParams.get("report"));
  } catch {
    return send(res, 500, "text/plain; charset=utf-8", "The Sentrook dashboard could not read its state.", head);
  }
  const nonce = randomBytes(16).toString("base64");
  return send(res, 200, "text/html; charset=utf-8", renderPage(model, nonce), head, {
    "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`,
  });
}

/** The Control UI tab: the Gateway draws the route in a sandboxed frame. */
export const TAB = {
  surface: "tab",
  id: "sentrook",
  label: "Sentrook",
  description: "Recent Sentrook scans and their risk scores (read-only).",
  icon: "shield",
  group: "control",
  path: ROUTE,
  requiredScopes: ["operator.read"],
} as const;
