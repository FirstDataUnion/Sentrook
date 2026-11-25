/**
 * Run now: `/sentrook-allow` on a held call of a cron job starts the job again, so the owner's answer acts at once.
 *
 * OpenClaw lets no plugin keep a cron call waiting for a person, so the held call is never run by the plugin itself: the
 * job runs again, and the one-use pass the answer set lets the same call through in that run (passes.ts, `run_bound`).
 *
 * - The job is read from OpenClaw's job store, `<state>/state/openclaw.sqlite` (table `cron_jobs`, as
 *   cronDelivery.ts reads it; on a release without that store, `<state>/cron/jobs.json`). A hold keeps a digest of the
 *   job's definition (`digest`: everything but whether it is enabled and its run state), so a job changed since the
 *   hold is not run again.
 * - A run is known by OpenClaw's run receipt (`cron_run_receipts`): the running receipt of a job names the run id that
 *   `openclaw cron run` returned (`request_run_id`). That id is what a started run's pass is bound to (`runKey`).
 * - `guard` says why a run is not started: observe mode, the job cannot be read, it is gone, finished (a one-shot that
 *   ran), disabled, running now (a running receipt, or a run the plugin started for an earlier answer that has not
 *   ended), or changed since the hold.
 * - `start` runs `openclaw cron run <job> --json` as a child process: an external plugin cannot call the gateway's
 *   `cron.run` itself. It is the same OpenClaw the gateway runs (`process.argv[1]`), else `openclaw` on the PATH. The
 *   command asks the gateway to queue the run and prints its run id; the plugin waits for that answer without blocking
 *   the gateway. No extra prompt is ever given: the job runs as it is.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import path from "node:path";

import * as passes from "./passes.ts";

type Entry = Record<string, any>;

/** The job store's view of one job: its definition, whether it is enabled, its run state. */
export interface JobRow {
  job: Entry;
  enabled: boolean;
  state: Entry;
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

function withDb<T>(openclawDir: string, fn: (conn: any) => T): T | undefined {
  const db = path.join(openclawDir, "state", "openclaw.sqlite");
  if (!existsSync(db)) return undefined;
  const DatabaseSync = sqliteModule()?.DatabaseSync;
  if (!DatabaseSync) throw new Error("node:sqlite is not available");
  const conn = new DatabaseSync(db, { readOnly: true, timeout: 200 });
  try {
    return fn(conn);
  } finally {
    try {
      conn.close();
    } catch {
      // already closed
    }
  }
}

const obj = (v: unknown): Entry => (v && typeof v === "object" && !Array.isArray(v) ? (v as Entry) : {});

/**
 * The job from OpenClaw's job store: the row, `"missing"` when the store has no such job, null when it cannot be read
 * (or holds the id more than once).
 */
export function readJob(openclawDir: string, jobId: string): JobRow | "missing" | null {
  try {
    const fromDb = withDb(openclawDir, (conn) => {
      const rows = conn.prepare("SELECT job_json, enabled, state_json FROM cron_jobs WHERE job_id = ?").all(jobId) as any[];
      if (!rows.length) return "missing" as const;
      if (rows.length > 1) return null;
      const job = obj(JSON.parse(String(rows[0].job_json)));
      return {
        job,
        enabled: Number(rows[0].enabled) !== 0 && job.enabled !== false,
        state: { ...obj(job.state), ...obj(JSON.parse(String(rows[0].state_json ?? "{}"))) },
      };
    });
    if (fromDb !== undefined) return fromDb;
  } catch {
    return null;
  }
  try {
    const data = JSON.parse(readFileSync(path.join(openclawDir, "cron", "jobs.json"), "utf8"));
    const jobs: unknown[] = Array.isArray(data?.jobs) ? data.jobs : [];
    const found = jobs.filter((j: any) => j?.id === jobId);
    if (!found.length) return "missing";
    if (found.length > 1) return null;
    const job = obj(found[0]);
    return { job, enabled: job.enabled !== false, state: obj(job.state) };
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === "ENOENT" ? "missing" : null;
  }
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Entry;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

/** What the digest leaves out: whether the job is enabled, and its run state. */
const RUN_STATE = new Set(["enabled", "state", "updatedAtMs"]);

/** A digest of the job's definition. */
export function digest(job: Entry): string {
  const kept = Object.fromEntries(Object.entries(job).filter(([k]) => !RUN_STATE.has(k)));
  return createHash("sha256").update(canonical(kept)).digest("hex").slice(0, 24);
}

/** The digest a hold of job `jobId` keeps; null when the job cannot be read. */
export function jobDigest(openclawDir: string, jobId: string | null): string | null {
  if (!jobId) return null;
  const row = readJob(openclawDir, jobId);
  return row && row !== "missing" ? digest(row.job) : null;
}

/** The job's running run, as its receipt names it: (the run id, when it started); null when none or unreadable. */
export function activeRun(openclawDir: string, jobId: string): { runKey: string; startedAt: Date | null } | null {
  try {
    const found = withDb(openclawDir, (conn) => {
      const rows = conn
        .prepare(
          "SELECT receipt_id, request_run_id, started_at_ms FROM cron_run_receipts WHERE job_id = ? AND status = 'running' ORDER BY started_at_ms DESC LIMIT 1",
        )
        .all(jobId) as any[];
      return rows[0] ?? null;
    });
    if (found) {
      const key = typeof found.request_run_id === "string" && found.request_run_id ? found.request_run_id : String(found.receipt_id);
      const at = Number(found.started_at_ms);
      return { runKey: key, startedAt: Number.isFinite(at) ? new Date(at) : null };
    }
  } catch {
    // no receipts table: not known
  }
  return null;
}

/** Why the job of `hold` is not started now (a key of the shared fixture's `run_now.reasons`); null when it may be. */
export function guard(openclawDir: string, hold: Entry, observe: boolean, stateDir: string | null = null): string | null {
  if (observe) return "observe";
  const jobId = typeof hold.job_id === "string" ? hold.job_id : null;
  const row = jobId ? readJob(openclawDir, jobId) : null;
  if (row === null) return "unknown";
  if (row === "missing") return "missing";
  if (!row.enabled) {
    // a one-shot that has run is finished; any other disabled job is paused
    return obj(row.job.schedule).kind === "at" && row.state.lastRunAtMs != null ? "terminal" : "paused";
  }
  if (activeRun(openclawDir, jobId!) !== null || typeof row.state.runningAtMs === "number") return "running";
  // a run the plugin started for an earlier answer that it has not seen end (it may still be queued)
  if (stateDir !== null && passes.pendingRun(stateDir, hold.job_ref ?? null, new Date())) return "running";
  if (!hold.job_digest) return "unknown";
  if (hold.job_digest !== digest(row.job)) return "changed";
  return null;
}

function executable(p: string): boolean {
  try {
    accessSync(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** How to run OpenClaw's command line: the gateway's own entry script under this Node, else `openclaw` on the PATH. */
export function openclawCommand(argv: string[] = process.argv, env: NodeJS.ProcessEnv = process.env): string[] | null {
  const entry = argv[1];
  if (entry && /(^|[\\/])openclaw(\.m?js)?$/.test(entry) && existsSync(entry)) return [process.execPath, entry];
  for (const dir of (env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, "openclaw");
    if (executable(p)) return [p];
  }
  return null;
}

/** Seconds `openclaw cron run` may take to queue the run. */
export const START_TIMEOUT_MS = 60_000;

/** What `openclaw cron run --json` printed: the first JSON object in its output that says `ok`. */
export function answerOf(stdout: string): Entry | null {
  for (let i = stdout.indexOf("{"); i >= 0; i = stdout.indexOf("{", i + 1)) {
    for (let j = stdout.lastIndexOf("}"); j > i; j = stdout.lastIndexOf("}", j - 1)) {
      try {
        const v = JSON.parse(stdout.slice(i, j + 1));
        if (v && typeof v === "object" && "ok" in v) return v as Entry;
      } catch {
        // not this span
      }
    }
  }
  return null;
}

/** OpenClaw's reasons for not queueing a run, as the guards name them. */
const HOST_REASONS: Record<string, string> = { "already-running": "running", disabled: "paused" };

export interface Started {
  started: boolean;
  runId: string | null;
  /** Why not: `unavailable` (no way to run it), a guard reason OpenClaw gave, or what failed. */
  why: string;
}

/** A child process runner, replaceable in tests: resolves with the exit code and output. */
export type Runner = (argv: string[], timeoutMs: number) => Promise<{ code: number | null; stdout: string; stderr: string }>;

export const runChild: Runner = (argv, timeoutMs) =>
  new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let child;
    try {
      child = spawn(argv[0]!, argv.slice(1), { stdio: ["ignore", "pipe", "pipe"], env: process.env });
    } catch (err) {
      resolve({ code: null, stdout: "", stderr: String(err) });
      return;
    }
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.stdout.on("data", (d) => (stdout += String(d)));
    child.stderr.on("data", (d) => (stderr += String(d)));
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ code: null, stdout, stderr: stderr + String(err) });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });

/** Starts job `jobId` now with `openclaw cron run <job> --json`; never throws. */
export async function start(jobId: string, run: Runner = runChild, command = openclawCommand()): Promise<Started> {
  if (!command) return { started: false, runId: null, why: "unavailable" };
  const out = await run([...command, "cron", "run", jobId, "--json"], START_TIMEOUT_MS);
  const said = answerOf(out.stdout);
  if (said?.ok && said.enqueued) {
    return { started: true, runId: typeof said.runId === "string" ? said.runId : null, why: "" };
  }
  if (said?.ok && typeof said.reason === "string") {
    return { started: false, runId: null, why: HOST_REASONS[said.reason] ?? said.reason };
  }
  const tail = (out.stderr || out.stdout).replace(/\s+/g, " ").trim().slice(-200);
  return { started: false, runId: null, why: `exit ${out.code ?? "?"}: ${tail}` };
}

/** What hold.answer needs to start a held call's job: `guard` and `start` for this OpenClaw. */
export class Adapter {
  private readonly openclawDir: string;
  private readonly observe: boolean;
  private readonly run: Runner;
  private readonly command: string[] | null;
  private readonly stateDir: string | null;

  constructor(
    openclawDir: string,
    observe: boolean,
    run: Runner = runChild,
    command: string[] | null = openclawCommand(),
    stateDir: string | null = null,
  ) {
    this.openclawDir = openclawDir;
    this.stateDir = stateDir;
    this.observe = observe;
    this.run = run;
    this.command = command;
  }

  guard(hold: Entry): string | null {
    return guard(this.openclawDir, hold, this.observe, this.stateDir);
  }

  start(hold: Entry): Promise<Started> {
    return start(String(hold.job_id), this.run, this.command);
  }
}
