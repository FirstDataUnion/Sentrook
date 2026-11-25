/**
 * Passes and denials: what the owner's answer to a held call sets for the run that made it.
 *
 * A held call (hold.ts) is answered with `/sentrook-allow`, `/sentrook-allow <id> always` or `/sentrook-deny`. Each
 * answer is kept here, in `<state>/sentrook/passes.json`, bound to the cron job the held call came from and to the
 * action:
 * - allow (once): a one-use pass. When the plugin starts a new run of the job for the answer (runNow.ts), the pass is
 *   bound to that run (`runs`, below); otherwise the job's next run that makes the same call goes through once.
 * - allow always: a standing pass for the job, for 30 days, with a use count.
 * - deny: a standing denial for the job, for 30 days. A matching call gets `DECLINED_TEXT` and no notice is sent.
 *
 * The job is the one OpenClaw's run metadata names on a cron run (`ctx.inputProvenance.jobId`, else the agent hook's
 * `jobId`, when `ctx.trigger` is `cron`), never the `[cron:...]` tag in the prompt. A hold on a run that is not a
 * cron job has no job to bind to: there allow gives a one-use pass bound to the call's exact arguments, for 7 days,
 * and nothing else is offered.
 *
 * A later call matches on the same terms as the Hermes plugin's Session answer in a chat, with the job as the scope:
 * a call of the same tool about the same parties (the entities its reasons and description name), scoring no
 * higher, with no warning the held call lacked, which the scanner neither enforced nor applied a floor to, and on a
 * complete scan. A pass also needs the scan's `owner_pass` at or above its own level (`levelOf`): a call that has
 * since picked up a strong signal is never passed. When the call names no party, or its approval fingerprint names
 * nothing, the match also binds to the call's exact arguments (hashed), and only a one-use pass is offered. A denial
 * matches the job and action whatever the scan says: refusing is always safe. Both plugins check the same table
 * (`integrations/fixtures/hold/cases.json`, `passes`).
 *
 * The match key is an HMAC under the install's salt, so the file reveals nothing about the action; it keeps the
 * tool, the run's description of the call (as the hold's notice showed it) and the job, for the owner's list.
 * `passes.json` is changed under the same cross-process lock as `holds.json` and `grants.json`.
 *
 * A pass bound to a run the plugin started (`run_bound`) has a record in the file's `runs` list: the job, when it was
 * asked for, the run id `openclaw cron run` returned, and, once a scan or the run's end finds it, the run it is bound
 * to. A run is the started one when its running receipt names that run id, or (before the id is recorded) when it is
 * not the held run and started after the answer. The record notes whether the call went through and the holds the run
 * made, so the owner gets one line when the run ends (`outcomeText`); a run-bound pass the run did not use ends with it.
 */

import { createHash, createHmac, randomBytes } from "node:crypto";
import path from "node:path";

import type { ScanResponse } from "./scanClient.ts";
import { type PassesFile, readTime, Store, withFileLock } from "./store.ts";

type Entry = Record<string, any>;

const DAY_MS = 24 * 3600_000;
/** How long a standing pass, a denial and a job's one-use pass last. */
export const PASS_TTL_MS = 30 * DAY_MS;
/** How long a one-use pass bound to exact arguments (a hold that is not on a cron job) lasts. */
export const ARGS_TTL_MS = 7 * DAY_MS;
const MAX_PASSES = 200;
const ID = /^p-[0-9a-f]{6}$/;

export const DECLINED_TEXT =
  "The owner declined this action for this job, so Sentrook did not run it. Continue without it.";

/** The scan's `owner_pass` levels, lowest first. */
export const LEVELS = ["once", "always"] as const;
export type Level = (typeof LEVELS)[number];

/** The verbs an answer can use, as the notice lists them. */
export const ALLOW = "allow";
export const ALLOW_ALWAYS = "allow always";
export const DENY = "deny";
export const ALLOW_LATER = "allow later";
/** allow that starts the job again even though the held run had already acted (`acts`). */
export const ALLOW_NOW = "allow now";

/**
 * A call acted (sent or wrote something a new run would do again) when it ran with one of these tool kinds, or when the
 * scan described it with one of these categories.
 */
export const ACTING_KINDS = new Set(["file_edit", "file_write", "memory_write", "message_send"]);
export const ACTING_CATEGORIES = new Set([
  "deletes_data",
  "modifies_agent_or_host_config",
  "sends_data_off_host",
  "sends_message_to_person",
  "writes_local_files",
]);
/**
 * How long a run the plugin started for an answer counts as still pending (so another answer does not start a second
 * run of the job) until the plugin sees it end.
 */
const PENDING_RUN_MS = 3600_000;
/** How much earlier than the answer a run may say it started and still count as the one started for it (clocks). */
const RUN_SLACK_MS = 2_000;

/** Whether a call of tool kind `kind`, scanned as `resp`, sends or writes something. */
export function acts(kind: unknown, resp: ScanResponse | Entry | null | undefined): boolean {
  const desc = (resp as Entry | null | undefined)?.tool_description;
  const category = desc && typeof desc === "object" ? desc.category : null;
  return ACTING_KINDS.has(String(kind)) || ACTING_CATEGORIES.has(String(category));
}

// ---- the match (the same terms as the Hermes plugin's Session answer) ------------------------------------

/**
 * Reason codes that are the scanner's scoring and wording notes, not warnings; every other code is a warning, so a
 * code the scanner adds later counts as one. The same list as the Hermes plugin's (`session_allow.NOTES`).
 */
const NOTE_PREFIXES = ["jev.", "call.", "relief.", "cap.", "coverage.", "agreement.", "trigger."];
const NOTES = new Set([
  "send.off_host",
  "retry.none",
  "reputation.unknown_host_as_data_destination",
  "reputation.unknown_channel_as_recipient",
  "reputation.unknown_recipient_as_recipient",
  "reputation.unknown_mcp_server_as_data_destination",
  "reputation.unknown_mcp_server_as_tool_provider",
  "reputation.unknown_plugin_as_data_destination",
  "origin.agent_generated",
  "origin.request_named",
  "origin.owner_config",
  "origin.granted",
  "origin.self_recipient",
  "origin.host_configured_provider",
  "origin.recipient_mail_domain",
  "origin.agent_created_visible",
  "origin.sibling_only",
  "exposure.instructions",
  "exposure.authority",
  "exposure.session_tainted",
]);

const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort();

/** The entities the response's reasons and its tool description name, as `[kind, display]`, sorted and once each. */
export function parties(resp: ScanResponse | Entry): [string, string][] {
  const r = resp as Entry;
  const ents = r.entities && typeof r.entities === "object" && !Array.isArray(r.entities) ? r.entities : {};
  const ids = new Set<string>();
  for (const reason of Array.isArray(r.reasons) ? r.reasons : []) {
    if (reason && typeof reason === "object" && typeof reason.subject === "string") ids.add(reason.subject);
  }
  const template = r.tool_description && typeof r.tool_description === "object" ? r.tool_description.template : null;
  if (typeof template === "string") for (const m of template.matchAll(/\{(E\d+)\}/g)) ids.add(m[1]!);
  const out = new Map<string, [string, string]>();
  for (const id of ids) {
    const ent = ents[id];
    if (ent && typeof ent === "object" && typeof ent.display === "string") {
      const pair: [string, string] = [String(ent.kind ?? ""), ent.display];
      out.set(JSON.stringify(pair), pair);
    }
  }
  return [...out.values()].sort((a, b) => (a[0] === b[0] ? cmp(a[1], b[1]) : cmp(a[0], b[0])));
}

/** Code-point order, as Python sorts strings. */
function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The response's reason codes that are warnings (any but the notes), sorted and once each. */
export function warnings(resp: ScanResponse | Entry): string[] {
  const out: string[] = [];
  for (const reason of Array.isArray((resp as Entry).reasons) ? (resp as Entry).reasons : []) {
    const code = reason && typeof reason === "object" ? reason.code : null;
    if (typeof code === "string" && !NOTES.has(code) && !NOTE_PREFIXES.some((p) => code.startsWith(p))) out.push(code);
  }
  return sorted(out);
}

export function riskOf(resp: ScanResponse | Entry): number | null {
  const r = (resp as Entry).risk;
  return typeof r === "number" && Number.isFinite(r) ? r : null;
}

/**
 * Whether an earlier answer may cover this scan at all: it has a risk, the scanner neither enforced it nor applied a
 * floor, and it is complete (a `degraded` scan was scored without a check that failed).
 */
export function eligible(resp: ScanResponse | Entry): boolean {
  const r = resp as Entry;
  const floors = r.floors_applied;
  return (
    riskOf(r) !== null &&
    (r.enforced === null || r.enforced === undefined) &&
    !(Array.isArray(floors) ? floors.length : floors) &&
    (r.status ?? "ok") === "ok"
  );
}

/**
 * How far the scanner lets the owner pass this call: `always`, `once`, or null (not at all). A response without the
 * field (a scanner that predates it), null or any value but the two is null: the scanner sends it on every scan, and
 * only the scanner decides that a call may be passed.
 */
export function levelOf(resp: ScanResponse | Entry): Level | null {
  const v = (resp as Entry).owner_pass;
  return (LEVELS as readonly unknown[]).includes(v) ? (v as Level) : null;
}

/**
 * The level a hold of this scan offers (`levelOf`), or null when no pass could ever let it through: a scan the
 * scanner enforced, applied a floor to, or did not finish (`eligible`). Such a hold offers only deny (or nothing,
 * off a cron job).
 */
export function offeredLevel(resp: ScanResponse | Entry): Level | null {
  return eligible(resp) ? levelOf(resp) : null;
}

/** Whether a scan at level `have` may use a pass set at level `need`. */
export function levelCovers(have: unknown, need: unknown): boolean {
  const h = (LEVELS as readonly unknown[]).indexOf(have);
  const n = (LEVELS as readonly unknown[]).indexOf(need);
  return h >= 0 && n >= 0 && h >= n;
}

/** A cron job's ref, hashed as `session_ref` is. */
export function jobRef(jobId: string | null | undefined): string | null {
  return jobId ? `j_${createHash("sha256").update(jobId).digest("hex").slice(0, 12)}` : null;
}

/** The approval fingerprint names nothing the call acts on (`afp1:<kind>` alone, or only the provider), or none. */
export function namesNothing(fingerprint: unknown): boolean {
  if (typeof fingerprint !== "string" || !fingerprint) return true;
  return !fingerprint.split("|").slice(1).some((p) => p && !p.startsWith("prov:"));
}

/** Sorted-key JSON, for hashing a call's exact arguments. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical((v as Entry)[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

export interface Match {
  key: string;
  /** The call names its parties: the key holds them, not the exact arguments. */
  named: boolean;
  risk: number | null;
  warnings: string[];
}

/**
 * What a pass for this call binds to: `key` (the tool and parties, plus the exact arguments when `named` is false),
 * the `risk` it was held at and its `warnings`. `exact`: always bind to the exact arguments (not a cron job).
 */
export function matchOf(tool: string, resp: ScanResponse | Entry, args: unknown, secret: string, exact = false): Match {
  const named = parties(resp);
  const r = resp as Entry;
  const bound = named.length > 0 && !namesNothing(r.approval_fingerprint || r.action_fingerprint) && !exact;
  let material = [tool, ...named.map(([k, d]) => `${k}\t${d}`)].join("\n");
  if (!bound) material += `\nargs:${createHash("sha256").update(canonical(args)).digest("hex")}`;
  const key = createHmac("sha256", `sentrook pass v1|${secret}`).update(material).digest("hex").slice(0, 24);
  return { key, named: bound, risk: riskOf(resp), warnings: warnings(resp) };
}

/** Whether `later` is the same action as `held` at no higher risk and with no new warning. */
export function covers(held: Entry | null | undefined, later: Match | Entry): boolean {
  if (!held || typeof held !== "object" || held.key !== later.key) return false;
  const risk = later.risk;
  const heldRisk = held.risk;
  if (typeof risk !== "number" || typeof heldRisk !== "number") return false;
  const seen = new Set<string>(Array.isArray(held.warnings) ? held.warnings : []);
  return risk <= heldRisk && (Array.isArray(later.warnings) ? later.warnings : []).every((w: string) => seen.has(w));
}

/**
 * The answers a hold offers, in the notice's order. On a cron job: allow when the scanner lets the owner pass the
 * call at all, then allow later (allow starts the job again now), or allow now when the held run had already acted
 * (allow then waits for the next run); allow always when it lets it pass for good and the call names its parties below
 * the block line; and deny. Elsewhere only allow (bound to the exact call).
 */
export function offers(
  jobId: string | null,
  level: Level | null,
  named: boolean,
  risk: number | null,
  blockAt: number,
  acted = false,
): string[] {
  if (!jobId) return level !== null ? [ALLOW] : [];
  const out: string[] = [];
  if (level !== null) {
    out.push(ALLOW);
    out.push(acted ? ALLOW_NOW : ALLOW_LATER);
    if (level === "always" && named && risk !== null && risk < blockAt) out.push(ALLOW_ALWAYS);
  }
  out.push(DENY);
  return out;
}

// ---- the file -----------------------------------------------------------------------------------------

const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;
export const show = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
const file = (stateDir: string) => path.join(stateDir, "passes.json");

function clean(s: unknown, cap = 200): string {
  return Array.from(String(s), (c) => (/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]|[^\P{Zs} ]/u.test(c) ? "?" : c))
    .slice(0, cap)
    .join("");
}

function isLive(p: unknown, now: Date): p is Entry {
  if (!p || typeof p !== "object" || !["allow", "deny"].includes((p as Entry).kind)) return false;
  const at = readTime((p as Entry).expires_at);
  return at !== null && at.getTime() > now.getTime();
}

export function load(stateDir: string): PassesFile | null {
  return new Store(stateDir).loadPasses();
}

export function live(data: PassesFile | null, now: Date): Entry[] {
  return (data?.passes ?? []).filter((p): p is Entry => isLive(p, now));
}

function liveRuns(data: PassesFile, now: Date): Entry[] {
  const runs = Array.isArray(data.runs) ? (data.runs as unknown[]) : [];
  return runs.filter((r): r is Entry => {
    const at = r && typeof r === "object" ? readTime((r as Entry).expires_at) : null;
    return at !== null && at.getTime() > now.getTime();
  });
}

/**
 * Stores a pass (`kind` allow) or denial (deny) set from `hold`; returns the entry, or null when the file cannot be
 * read. `uses`: once or standing. `runBound`: a one-use pass for a run the plugin is about to start, with its record in
 * `runs`.
 */
export function add(
  stateDir: string,
  b: { kind: "allow" | "deny"; uses: "once" | "standing"; level: Level | null; hold: Entry; by: Entry; now: Date; runBound?: boolean },
  beforeWrite: () => void = () => {},
): Entry | null {
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadPasses();
    if (data === null) return null;
    data.passes = live(data, b.now);
    const taken = new Set(data.passes.map((p) => (p as Entry).id));
    let id = `p-${randomBytes(3).toString("hex")}`;
    while (taken.has(id)) id = `p-${randomBytes(3).toString("hex")}`;
    const ttl = b.hold.job_ref ? PASS_TTL_MS : ARGS_TTL_MS;
    const entry: Entry = {
      id,
      kind: b.kind,
      uses: b.uses,
      level: b.kind === "allow" ? b.level : null,
      job_id: b.hold.job_id ?? null,
      job_ref: b.hold.job_ref ?? null,
      tool: b.hold.tool ?? null,
      description: b.hold.description ?? null,
      match: b.hold.match ?? null,
      hold_id: b.hold.id ?? null,
      set_at: iso(b.now),
      expires_at: iso(new Date(b.now.getTime() + ttl)),
      set_by: b.by,
      use_count: 0,
      last_used_at: null,
    };
    const runs = liveRuns(data, b.now);
    if (b.runBound) {
      // an earlier started run of the job whose end was never seen must not capture this one
      for (const old of runs) if (old.job_ref === (b.hold.job_ref ?? null) && !old.ended) endRun(data, old);
      entry.run_bound = true;
      runs.push({
        id,
        hold_id: b.hold.id ?? null,
        job_id: b.hold.job_id ?? null,
        job_ref: b.hold.job_ref ?? null,
        requested_at: iso(b.now),
        not_run: b.hold.run_key ?? null,
        run_id: null,
        run_key: null,
        passed: false,
        held: [],
        expires_at: entry.expires_at,
      });
    }
    data.runs = runs.slice(-MAX_PASSES);
    data.passes.push(entry);
    data.passes = data.passes.slice(-MAX_PASSES);
    beforeWrite();
    store.savePasses(data);
    return entry;
  });
}

/**
 * The denial or pass that settles this call, or null. A denial of the same job and action wins over any pass. A pass
 * applies only to an eligible scan that it covers at an `owner_pass` level at or above its own. A one-use pass is used
 * up; a standing one counts the use. A file that cannot be read settles nothing (the call is held as before).
 */
export function check(
  stateDir: string,
  ref: string | null,
  match: Match,
  resp: ScanResponse | Entry,
  now: Date,
  inRun: string | null = null,
): Entry | null {
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadPasses();
    if (data === null) return null;
    const found = live(data, now);
    const same = found.filter(
      (p) =>
        p.job_ref === ref &&
        p.match &&
        typeof p.match === "object" &&
        p.match.key === match.key &&
        // a pass bound to a run the plugin started serves that run only (`inRun`, from runOf)
        (!p.run_bound || (inRun !== null && p.id === inRun)),
    );
    let hit = ref !== null ? (same.find((p) => p.kind === "deny") ?? null) : null;
    if (hit === null && eligible(resp)) {
      const have = levelOf(resp);
      hit = same.find((p) => p.kind === "allow" && covers(p.match, match) && levelCovers(have, p.level)) ?? null;
    }
    if (hit === null) {
      if (found.length !== data.passes.length) {
        data.passes = found;
        store.savePasses(data);
      }
      return null;
    }
    hit.use_count = Number(hit.use_count ?? 0) + 1;
    hit.last_used_at = iso(now);
    const used = hit;
    data.passes = found.filter((p) => !(p === used && p.uses === "once"));
    store.savePasses(data);
    return { ...hit };
  });
}

/** `passes revoke <id>`: removes a pass or denial; the reply and the change to record. */
export function revoke(stateDir: string, rest: string, now: Date, beforeWrite: () => void = () => {}): { reply: string; change: Entry | null } {
  const id = rest.trim();
  if (!ID.test(id)) return { reply: "usage: passes revoke <id>, with an id from the passes list (p- and 6 hex digits)", change: null };
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadPasses();
    if (data === null) return { reply: `The passes file ${file(stateDir)} could not be read; fix or remove it first.`, change: null };
    const kept = live(data, now);
    const found = kept.find((p) => p.id === id);
    if (!found) return { reply: `No pass or denial ${clean(id, 40)}: the id is unknown, used up or expired.`, change: null };
    data.passes = kept.filter((p) => p !== found);
    beforeWrite();
    store.savePasses(data);
    return {
      reply: `Revoked ${found.kind === "deny" ? "denial" : "pass"} ${id}.`,
      change: { op: "revoke", id, pass_kind: found.kind, job_ref: found.job_ref ?? null },
    };
  });
}

const jobText = (p: Entry) => (p.job_id ? `job ${clean(p.job_id, 40)}` : "an unattended run");

/** One pass or denial, as the list and the dashboard show it. */
export function describe(p: Entry): string {
  const at = readTime(p.expires_at);
  const until = at ? show(at) : "?";
  const call = `${clean(p.tool ?? "?", 60)}: ${clean(p.description ?? "?", 120)}`;
  if (p.kind === "deny") return `denied on ${jobText(p)} until ${until}: ${call}`;
  if (p.uses === "once" && p.run_bound) return `allowed once in the run of ${jobText(p)} started for it, until ${until}: ${call}`;
  if (p.uses === "once") return `allowed once on ${jobText(p)}'s next run, until ${until}: ${call}`;
  const used = Number(p.use_count ?? 0);
  return `allowed on ${jobText(p)} until ${until}, used ${used} time${used === 1 ? "" : "s"}: ${call}`;
}

export function formatPasses(stateDir: string, now: Date, cmd: (sub: string) => string): string {
  const data = load(stateDir);
  if (data === null) return `The passes file ${file(stateDir)} could not be read; fix or remove it first.`;
  const found = live(data, now);
  if (!found.length) {
    return `No passes or denials. Answering a held call sets one: ${cmd("allow")} <id> [always], ${cmd("deny")} <id>.`;
  }
  return [...found.map((p) => `${p.id}  ${describe(p)}`), `Remove one with ${cmd("passes")} revoke <id>.`].join("\n");
}

/** Passes and denials in force, for status and verify. */
export function counts(stateDir: string, now: Date): string {
  const data = load(stateDir);
  if (data === null) return "passes file unreadable";
  const found = live(data, now);
  const standing = found.filter((p) => p.kind === "allow" && p.uses !== "once").length;
  const once = found.filter((p) => p.kind === "allow" && p.uses === "once").length;
  const denials = found.filter((p) => p.kind === "deny").length;
  return `${standing} standing, ${once} once, ${denials} denial${denials === 1 ? "" : "s"}`;
}

export const isId = (text: string) => ID.test(text);

// ---- runs started for an answer (runNow.ts) -------------------------------------------------------------

/**
 * Whether a run the plugin started for an answer on job `ref` has not been seen to end yet (asked for within an hour):
 * another answer must not start the job again meanwhile. An unreadable file says no.
 */
export function pendingRun(stateDir: string, ref: string | null, now: Date): boolean {
  const data = new Store(stateDir).loadPasses();
  if (!data) return false;
  return liveRuns(data, now).some((r) => {
    const asked = readTime(r.requested_at);
    return r.job_ref === ref && !r.ended && asked !== null && now.getTime() - asked.getTime() < PENDING_RUN_MS;
  });
}

/** Runs `change(data, record)` on the run record of pass `id` under the lock and saves; a copy of it, or null. */
function changeRun(stateDir: string, id: string, change: (data: PassesFile, rec: Entry) => void): Entry | null {
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadPasses();
    if (data === null) return null;
    const rec = (Array.isArray(data.runs) ? (data.runs as Entry[]) : []).find((r) => r && r.id === id);
    if (!rec) return null;
    change(data, rec);
    store.savePasses(data);
    return { ...rec };
  });
}

/** The run started for pass `id`, with the run id OpenClaw gave it. */
export function started(stateDir: string, id: string, runId: string | null): void {
  changeRun(stateDir, id, (_data, rec) => {
    if (runId) rec.run_id = runId;
  });
}

/** The run for pass `id` could not be started: the pass is left for the job's next run, as allow later. */
export function notStarted(stateDir: string, id: string): void {
  changeRun(stateDir, id, (data, rec) => {
    data.runs = (data.runs as Entry[]).filter((r) => r !== rec);
    for (const p of data.passes as Entry[]) if (p && p.id === id) delete p.run_bound;
  });
}

function isRun(rec: Entry, runKey: string | null, startedAt: Date | null): boolean {
  if (rec.ended || !runKey) return false;
  if (rec.run_key) return rec.run_key === runKey;
  if (rec.run_id) return rec.run_id === runKey;
  const asked = readTime(rec.requested_at);
  const after = startedAt === null || asked === null || startedAt.getTime() >= asked.getTime() - RUN_SLACK_MS;
  return runKey !== rec.not_run && after;
}

/** Marks a started run ended and drops its pass if the run did not use it. */
function endRun(data: PassesFile, rec: Entry): void {
  rec.ended = true;
  data.passes = (data.passes as Entry[]).filter((p) => !(p && p.id === rec.id && p.run_bound));
}

/**
 * (the record of the run the plugin started for an answer that this run of job `ref` is, now bound to it, or null;
 * the records of earlier started runs of the job that ended without the plugin seeing their end, now ended).
 */
export function runOf(
  stateDir: string,
  ref: string | null,
  runKey: string | null,
  startedAt: Date | null,
  now: Date,
): { mine: Entry | null; gone: Entry[] } {
  if (ref === null || !runKey) return { mine: null, gone: [] };
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadPasses();
    if (data === null) return { mine: null, gone: [] };
    const runs = liveRuns(data, now);
    let changed = runs.length !== (Array.isArray(data.runs) ? data.runs.length : 0);
    const mine = runs.find((r) => r.job_ref === ref && isRun(r, runKey, startedAt)) ?? null;
    if (mine && mine.run_key !== runKey) {
      mine.run_key = runKey;
      changed = true;
    }
    const gone = runs.filter((r) => r.job_ref === ref && r !== mine && !r.ended && r.run_key && r.run_key !== runKey);
    for (const r of gone) {
      endRun(data, r);
      changed = true;
    }
    data.runs = runs;
    if (changed) store.savePasses(data);
    return { mine: mine ? { ...mine } : null, gone: gone.map((r) => ({ ...r })) };
  });
}

/** Notes on the record of the run started for pass `id` that the call went through, or a hold it made. */
export function note(stateDir: string, id: string, what: { passed?: boolean; held?: string }): void {
  changeRun(stateDir, id, (_data, rec) => {
    if (what.passed) rec.passed = true;
    if (what.held) {
      if (!Array.isArray(rec.held)) rec.held = [];
      if (!rec.held.includes(what.held)) rec.held.push(what.held);
    }
  });
}

/**
 * The run `runKey` of job `ref` ended: when it is a run the plugin started for an answer, its record, now ended (its
 * pass dropped if unused); else null.
 */
export function runEnd(stateDir: string, ref: string | null, runKey: string | null, startedAt: Date | null, now: Date): Entry | null {
  if (ref === null || !runKey) return null;
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadPasses();
    if (data === null) return null;
    const runs = liveRuns(data, now);
    const mine = runs.find((r) => r.job_ref === ref && isRun(r, runKey, startedAt));
    if (!mine) return null;
    mine.run_key = runKey;
    endRun(data, mine);
    data.runs = runs;
    store.savePasses(data);
    return { ...mine };
  });
}

/** The owner's one line when a started run ended, from `texts` (the `outcomes` the shared fixture gives). */
export function outcomeText(rec: Entry, texts: Record<string, string>): string {
  const held: string[] = (Array.isArray(rec.held) ? rec.held : []).filter((h: unknown): h is string => typeof h === "string");
  const kind = rec.passed ? (held.length ? "passed_held" : "passed") : held.length ? "held" : "none";
  return fill(texts[kind]!, { job: clean(rec.job_id, 40), hold: held.join(", ") });
}

/** `template` with each `{name}` replaced by `values[name]`, in one pass (as Python's `str.format`). */
export function fill(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (all, name: string) => (Object.hasOwn(values, name) ? values[name]! : all));
}
