/**
 * A cron job's own delivery target, as a destination grant for that job's run.
 *
 * The owner says where a cron job's output goes when setting it up (`delivery.channel` and `delivery.to`). When the
 * run's agent posts there itself with the message tool, that channel is the owner's choice for this run, not one the
 * agent picked. So on a cron run the plugin sends a destination grant for the job's configured target, scoped to the
 * run's session, with a `grant_ref` that names it as a cron job's delivery target.
 *
 * Only the job's own configured target counts:
 * - The job is the one the host says the run belongs to (the agent hooks' `jobId`). Nothing in the run's text or
 *   content is read.
 * - Its delivery is read from OpenClaw's job store (`<state>/state/openclaw.sqlite`, table `cron_jobs`; on a release
 *   without that store, `<state>/cron/jobs.json`), because neither the hook context nor the plugin API's cron job
 *   carries it.
 * - It is read at the run's first agent hook, before any of the run's tool calls, and kept in the run's context in
 *   the plugin's own folder. At each call the job is read again, and the grant is sent only while the job still gives
 *   that same target and was last changed before the run began. A job the agent changed during the run (with its cron
 *   tool, or by writing the store) gives no grant, nor one it pointed somewhere else.
 * - Only a channel or group counts. A person (a `user:` or `dm:` target, a handle, a phone number, a Telegram private
 *   chat, a Slack user or direct-message id) gives no grant.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import type { GrantConfig } from "./config.ts";
import { hash12 } from "./planir.ts";
import type { HistoryEntry, RunContext } from "./store.ts";

/** The `grant_ref` prefix of a job's delivery grant; the hashed job id follows. */
export const DELIVERY_REF = "cron_delivery:";

export const deliveryRef = (jobId: string) => `${DELIVERY_REF}j_${hash12(jobId)}`;

export interface CronJob {
  agentId?: string;
  delivery?: unknown;
  createdAtMs?: number;
  /** When the job's definition last changed, as the store records it. */
  updatedAtMs?: number;
}

/** The job's target, as read at the run's first agent hook (kept in the run's context). */
export interface DeliverySnapshot {
  jobId: string;
  pattern: string;
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

/** `node:sqlite`, looked up when a store is first read; null on a Node without it. */
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
 * read. Where the database store exists, only it is read (an older `jobs.json` may linger beside it after the move).
 * A job id held more than once (by two stores in the table) reads as unknown.
 */
export function readCronJob(openclawDir: string, jobId: string): CronJob | null {
  const db = path.join(openclawDir, "state", "openclaw.sqlite");
  if (existsSync(db)) {
    const DatabaseSync = sqliteModule()?.DatabaseSync;
    if (!DatabaseSync) return null;
    let conn: any;
    try {
      conn = new DatabaseSync(db, { readOnly: true, timeout: 200 });
      const rows = conn.prepare("SELECT job_json, updated_at FROM cron_jobs WHERE job_id = ?").all(jobId) as any[];
      return rows.length === 1 ? jobOf(JSON.parse(String(rows[0].job_json)), rows[0].updated_at) : null;
    } catch {
      return null;
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
  // Slack ids: `U…`/`W…` are people, `D…` a direct message.
  if (!room && platform === "slack" && /^[UWD][A-Z0-9]{6,}$/.test(to)) return null;
  return `${platform}:${to}`;
}

const agentKey = (id: unknown): string | null => (typeof id === "string" && id.trim() ? id.trim().toLowerCase() : null);

/**
 * The agent OpenClaw runs a job on when the job names none, as OpenClaw picks it: the agent marked `default`, else the
 * only agent, else `main` when no agents are listed. Null when the config does not say (several, none marked).
 */
function defaultAgent(hostConfig: any): string | null {
  const list: any[] = Array.isArray(hostConfig?.agents?.list) ? hostConfig.agents.list : [];
  if (!list.length) return "main";
  const chosen = list.find((a) => a?.default === true) ?? (list.length === 1 ? list[0] : null);
  return agentKey(chosen?.id);
}

/** The pattern for the job's own target, when the job is this agent's; null otherwise. */
function patternFor(job: CronJob | null, agentId: string | undefined, hostConfig: any): string | null {
  if (!job) return null;
  const owner = agentKey(job.agentId) ?? defaultAgent(hostConfig);
  const running = agentKey(agentId) ?? defaultAgent(hostConfig);
  if (!owner || owner !== running) return null;
  return deliveryPattern(job.delivery);
}

/**
 * At the run's first agent hook (before any of its tool calls): the job's target, for a cron run whose hook gives the
 * job id. Null when there is none to keep.
 */
export function snapshot(b: {
  trigger: unknown;
  jobId: unknown;
  agentId: string | undefined;
  hostConfig: any;
  openclawDir: string;
}): DeliverySnapshot | null {
  if (b.trigger !== "cron" || typeof b.jobId !== "string" || !b.jobId.trim()) return null;
  const jobId = b.jobId.trim();
  const pattern = patternFor(readCronJob(b.openclawDir, jobId), b.agentId, b.hostConfig);
  return pattern ? { jobId, pattern } : null;
}

/** The agent's scheduler tool (`cron` is its permanent alias) and the actions that only read or run a job. */
const CRON_TOOLS = new Set(["automations", "cron"]);
const CRON_READS = new Set(["status", "list", "get", "runs", "next_check", "run", "wake"]);

/** The session's calls include one of the cron tool that may have created, changed or removed a job. */
function cronChanged(history: HistoryEntry[]): boolean {
  return history.some((h) => CRON_TOOLS.has(h.tool) && !CRON_READS.has(String(h.arguments?.action ?? "")));
}

/**
 * The run-scoped destination grant for the job's own delivery target, or null: only on a cron run (`trigger: cron`,
 * not a subagent child) that kept the job's target at its first agent hook, for a call that names that target, while
 * the job still gives the same target and was last changed before the run began, in a session where the agent has
 * not changed a job with its cron tool.
 */
export function deliveryGrant(b: {
  run: RunContext;
  kind: string;
  argsText: string;
  agentId: string | undefined;
  hostConfig: any;
  history: HistoryEntry[];
  sessionRef: string;
  openclawDir: string;
}): GrantConfig | null {
  const kept = b.run.jobDelivery as DeliverySnapshot | undefined;
  if (b.kind !== "scheduled" || b.run.trigger !== "cron" || !kept?.jobId || !kept.pattern) return null;
  const began = num(b.run.seenAtMs);
  if (began === undefined || cronChanged(b.history)) return null;
  // The grant only matters to a call that shows the target; any other call need not read the store.
  const id = kept.pattern.slice(kept.pattern.indexOf(":") + 1).replace(/^#/, "").toLowerCase();
  if (!b.argsText.toLowerCase().includes(id)) return null;
  const job = readCronJob(b.openclawDir, kept.jobId);
  if (!job || job.updatedAtMs === undefined || job.updatedAtMs >= began) return null;
  if (job.createdAtMs !== undefined && job.createdAtMs >= began) return null;
  if (patternFor(job, b.agentId, b.hostConfig) !== kept.pattern) return null;
  return { kind: "destination", pattern: kept.pattern, scope: "session", session_ref: b.sessionRef, ref: deliveryRef(kept.jobId) };
}
