/**
 * A cron job's own delivery target, as a destination grant for that job's run.
 *
 * The owner says where a cron job's output goes when setting it up (`delivery.channel` and `delivery.to`). When the
 * run's agent posts there itself with the message tool, that channel is the owner's choice for this run, not one the
 * agent picked. So on a cron run the plugin sends a destination grant for the job's configured target, scoped to the
 * run's session, with a `grant_ref` that names the job.
 *
 * Only the job's own configured target counts. The job is the one the host says the run belongs to (the hook's
 * `jobId`, else the run's `agent:<id>:cron:<jobId>` session key); its delivery is read from OpenClaw's job store
 * (`<state>/state/openclaw.sqlite`, table `cron_jobs`; `<state>/cron/jobs.json` on older releases), because neither
 * the hook context nor the plugin API's cron job carries it. Nothing in the run's text or content is read. A job
 * created or changed after the run began, or one the agent changed with its cron tool in this session, gives no
 * grant: the agent may have pointed it somewhere else. A target that is a person (a `user:` or `dm:` target, a
 * handle, a phone number, a Telegram private chat) gives none either.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import type { GrantConfig } from "./config.ts";
import type { HistoryEntry, RunContext } from "./store.ts";

/** The `grant_ref` prefix of a job's delivery grant; the job id follows. */
export const DELIVERY_REF = "cron_delivery:";

/** The run of a cron job, as OpenClaw keys it: `agent:<id>:cron:<jobId>`, optionally `:run:<session id>`. */
const CRON_SESSION = /^agent:[^:]+:cron:([^:]+)(?::run:[^:]+)?$/i;

/** The job a cron run belongs to, as the host gives it: the hook's `jobId`, else the run's session key. */
export function cronJobIdOf(run: RunContext, sessionKey: unknown): string | null {
  if (typeof run.jobId === "string" && run.jobId.trim()) return run.jobId.trim();
  const m = typeof sessionKey === "string" ? CRON_SESSION.exec(sessionKey.trim()) : null;
  return m ? m[1]! : null;
}

export interface CronJob {
  agentId?: string;
  delivery?: unknown;
  createdAtMs?: number;
  /** When the job's definition last changed, as the store records it. */
  updatedAtMs?: number;
}

const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);

function jobOf(raw: unknown, updatedAt?: unknown): CronJob | null {
  if (!raw || typeof raw !== "object") return null;
  const j = raw as Record<string, unknown>;
  const times = [num(updatedAt), num(j.updatedAtMs)].filter((t): t is number => t !== undefined);
  return {
    ...(typeof j.agentId === "string" ? { agentId: j.agentId } : {}),
    delivery: j.delivery,
    ...(num(j.createdAtMs) !== undefined ? { createdAtMs: num(j.createdAtMs) } : {}),
    ...(times.length ? { updatedAtMs: Math.max(...times) } : {}),
  };
}

/** `node:sqlite`, looked up when a store is first read; undefined on a Node without it. */
let sqlite: any;
function sqliteModule(): any {
  if (sqlite === undefined) {
    try {
      sqlite = process.getBuiltinModule?.("node:sqlite") ?? null;
    } catch {
      sqlite = null;
    }
  }
  return sqlite;
}

/**
 * The job from OpenClaw's job store under its state directory, or null when the store does not hold it or cannot be
 * read. A job id held more than once (by two stores in the table) reads as unknown.
 */
export function readCronJob(openclawDir: string, jobId: string): CronJob | null {
  const db = path.join(openclawDir, "state", "openclaw.sqlite");
  const DatabaseSync = sqliteModule()?.DatabaseSync;
  if (DatabaseSync) {
    let conn: any;
    try {
      conn = new DatabaseSync(db, { readOnly: true, timeout: 200 });
      const rows = conn.prepare("SELECT job_json, updated_at FROM cron_jobs WHERE job_id = ?").all(jobId) as any[];
      if (rows.length === 1) return jobOf(JSON.parse(String(rows[0].job_json)), rows[0].updated_at);
      if (rows.length > 1) return null;
    } catch {
      // no table, or a store that is not a database: try the older file
    } finally {
      try {
        conn?.close();
      } catch {
        // already closed
      }
    }
  }
  try {
    const data = JSON.parse(readFileSync(path.join(openclawDir, "cron", "jobs.json"), "utf8"));
    const jobs: unknown[] = Array.isArray(data?.jobs) ? data.jobs : [];
    const found = jobs.filter((j: any) => j?.id === jobId);
    return found.length === 1 ? jobOf(found[0]) : null;
  } catch {
    return null;
  }
}

/** Chat platforms whose bare target is a phone number: a person. */
const PHONE_PLATFORMS = new Set(["sms", "whatsapp", "signal", "imessage"]);
/** Target kinds that name a room; `user:` and `dm:` name a person. */
const ROOM_PREFIX = /^(?:channel|group|thread):/;
const PERSON_PREFIX = /^(?:user|dm):/;
/** A channel name or id: `#name`, an id of three or more word characters, or a negative (Telegram group) id. */
const ROOM_ID = /^(?:#[\w-]{2,}|-?[A-Za-z0-9_-]{3,})$/;

/**
 * The destination pattern for a job's delivery, written the way a channel grant matches a send
 * (`<platform>:<channel id>`): only for an `announce` delivery that names its platform and a room. Null for no
 * delivery, a webhook, the host's own choice (`last`, or no `to`), or a person.
 */
export function deliveryPattern(delivery: unknown): string | null {
  if (!delivery || typeof delivery !== "object") return null;
  const d = delivery as Record<string, unknown>;
  if (d.mode !== "announce" || typeof d.channel !== "string" || typeof d.to !== "string") return null;
  const platform = d.channel.trim().toLowerCase();
  if (!/^[a-z][a-z0-9_-]{1,20}$/.test(platform) || platform === "last") return null;
  let to = d.to.trim();
  if (to.toLowerCase().startsWith(`${platform}:`)) to = to.slice(platform.length + 1);
  if (PERSON_PREFIX.test(to.toLowerCase())) return null;
  const room = ROOM_PREFIX.test(to.toLowerCase());
  if (room) to = to.slice(to.indexOf(":") + 1);
  if (!ROOM_ID.test(to)) return null;
  if (!room && PHONE_PLATFORMS.has(platform)) return null;
  // A Telegram chat with a positive id is a private chat with one person; groups and channels are negative.
  if (!room && platform === "telegram" && /^\d+$/.test(to)) return null;
  return `${platform}:${to}`;
}

/** The agent's scheduler tool (`cron` is its permanent alias) and the actions that only read or run a job. */
const CRON_TOOLS = new Set(["automations", "cron"]);
const CRON_READS = new Set(["status", "list", "get", "runs", "next_check", "run", "wake"]);

/** The session's calls include one of the cron tool that may have created, changed or removed a job. */
function cronChanged(history: HistoryEntry[]): boolean {
  return history.some((h) => CRON_TOOLS.has(h.tool) && !CRON_READS.has(String(h.arguments?.action ?? "")));
}

/**
 * The run-scoped destination grant for the job's own delivery target, or null. Only on a cron run (`trigger: cron`,
 * not a subagent child) of the agent that owns the job, whose definition is older than the run, in a session where
 * the agent has not changed a job with its cron tool.
 */
export function deliveryGrant(b: {
  run: RunContext;
  kind: string;
  sessionKey: unknown;
  agentId: string | undefined;
  history: HistoryEntry[];
  sessionRef: string;
  openclawDir: string;
}): GrantConfig | null {
  if (b.kind !== "scheduled" || b.run.trigger !== "cron") return null;
  const jobId = cronJobIdOf(b.run, b.sessionKey);
  const began = num(b.run.seenAtMs);
  if (!jobId || began === undefined || cronChanged(b.history)) return null;
  const job = readCronJob(b.openclawDir, jobId);
  if (!job || job.updatedAtMs === undefined || job.updatedAtMs >= began) return null;
  if (job.createdAtMs !== undefined && job.createdAtMs >= began) return null;
  if ((job.agentId ?? "main") !== (b.agentId ?? "main")) return null;
  const pattern = deliveryPattern(job.delivery);
  if (!pattern) return null;
  return { kind: "destination", pattern, scope: "session", session_ref: b.sessionRef, ref: `${DELIVERY_REF}${jobId}` };
}
