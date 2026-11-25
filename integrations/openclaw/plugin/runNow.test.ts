/**
 * `/sentrook-allow` on a held call of a cron job runs the job again now, and the same call goes through once in that run.
 *
 * The plugin never runs the held call itself: it runs `openclaw cron run <job> --json` as a child process, and the
 * one-use pass is bound to the run id that command returns (the job's running receipt names it). When the run ends
 * (`agent_end`) the owner gets one line on how it went. Nothing is started, and the pass waits for the job's next run,
 * when a guard applies. The texts are shared with the Hermes plugin (`integrations/fixtures/hold/cases.json`,
 * `run_now`).
 *
 * The job store is a real `state/openclaw.sqlite` with OpenClaw's `cron_jobs` and `cron_run_receipts` tables, and the
 * `openclaw` command is a stand-in script on the PATH that records its arguments and prints what OpenClaw prints.
 */

import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import * as hold from "./hold.ts";
import plugin from "./index.ts";
import * as passes from "./passes.ts";
import * as runNow from "./runNow.ts";
import { readTime } from "./store.ts";

const FIXTURES = JSON.parse(readFileSync(fileURLToPath(new URL("../../fixtures/hold/cases.json", import.meta.url)), "utf8"));
const RUN_NOW = FIXTURES.run_now;
const SEND = FIXTURES.notices[0];
const NAMED = {
  risk: 47,
  enforced: null,
  owner_pass: "once",
  approval_fingerprint: "afp1:message_send|ch:discord:#ops-reports",
  reasons: [{ code: "trigger.scheduled" }, { code: "send.unbound_channel", subject: "E1" }],
};
const GENERAL = { E1: { kind: "channel", display: "discord:#general" } };
const HELD = { block: true, blockReason: FIXTURES.held_text };
const JOB = {
  id: "job-j",
  agentId: "main",
  name: "Daily brief",
  enabled: true,
  schedule: { kind: "cron", expr: "0 9 * * *" },
  sessionTarget: "isolated",
  wakeMode: "now",
  payload: { kind: "agentTurn", message: "Post the daily brief to the ops channel." },
  delivery: { mode: "announce", channel: "discord", to: "channel:123456" },
  state: {},
};
const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_DEV_ENDPOINTS", "SENTROOK_SCAN_URL", "SENTROOK_OIDC_ISSUER", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE", "PATH"];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let dir = "";
let stateDir = "";
let reply: Record<string, unknown> = {};
/** What the stand-in `openclaw` prints, and where it records its arguments. */
let cliOut = "";
let cliLog = "";

function db(): DatabaseSync {
  mkdirSync(path.join(dir, "state"), { recursive: true });
  const conn = new DatabaseSync(path.join(dir, "state", "openclaw.sqlite"));
  conn.exec(
    "CREATE TABLE IF NOT EXISTS cron_jobs (store_key TEXT NOT NULL, job_id TEXT NOT NULL, name TEXT NOT NULL, " +
      "enabled INTEGER NOT NULL, job_json TEXT NOT NULL, state_json TEXT NOT NULL DEFAULT '{}', updated_at INTEGER NOT NULL, " +
      "PRIMARY KEY (store_key, job_id))",
  );
  conn.exec(
    "CREATE TABLE IF NOT EXISTS cron_run_receipts (receipt_id TEXT PRIMARY KEY, store_key TEXT NOT NULL, job_id TEXT NOT NULL, " +
      "config_revision TEXT NOT NULL, agent_id TEXT NOT NULL, request_run_id TEXT, status TEXT NOT NULL, owner_pid INTEGER NOT NULL, " +
      "started_at_ms INTEGER NOT NULL, finished_at_ms INTEGER)",
  );
  return conn;
}

function putJob(job: Record<string, unknown> = JOB, state: Record<string, unknown> = {}): void {
  const conn = db();
  conn.prepare("DELETE FROM cron_jobs WHERE job_id = ?").run(String(job.id));
  conn
    .prepare("INSERT INTO cron_jobs (store_key, job_id, name, enabled, job_json, state_json, updated_at) VALUES ('s', ?, ?, ?, ?, ?, ?)")
    .run(String(job.id), String(job.name), job.enabled === false ? 0 : 1, JSON.stringify(job), JSON.stringify(state), Date.now());
  conn.close();
}

function removeJobs(): void {
  const conn = db();
  conn.exec("DELETE FROM cron_jobs");
  conn.close();
}

/** OpenClaw's receipt for a run of job-j: running until `finish`. */
function receipt(runId: string, startedAt = Date.now()): void {
  const conn = db();
  conn
    .prepare("INSERT INTO cron_run_receipts VALUES (?, 's', 'job-j', 'rev', 'main', ?, 'running', 1, ?, NULL)")
    .run(`receipt-${runId}`, runId, startedAt);
  conn.close();
}

function finish(runId: string): void {
  const conn = db();
  conn.prepare("UPDATE cron_run_receipts SET status = 'ok', finished_at_ms = ? WHERE request_run_id = ?").run(Date.now(), runId);
  conn.close();
}

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  dir = mkdtempSync(path.join(tmpdir(), "sentrook-runnow-"));
  const bin = path.join(dir, "bin");
  mkdirSync(bin);
  cliLog = path.join(dir, "cli.log");
  cliOut = JSON.stringify({ ok: true, enqueued: true, runId: "cron-request.started-1" });
  // the stand-in reads what to print from a file, so a test can change it
  writeFileSync(path.join(dir, "cli.out"), cliOut);
  writeFileSync(path.join(bin, "openclaw"), `#!/bin/sh\necho "$@" >> "${cliLog}"\necho "Gateway: ok"\ncat "${path.join(dir, "cli.out")}"\n`);
  chmodSync(path.join(bin, "openclaw"), 0o755);
  Object.assign(process.env, {
    OPENCLAW_STATE_DIR: dir,
    SENTROOK_DEV_ENDPOINTS: "1",
    SENTROOK_SCAN_URL: "http://scan.test",
    SENTROOK_OIDC_ISSUER: "http://idp.test",
    SENTROOK_SCAN_CLIENT_ID: "client",
    SENTROOK_SCAN_CLIENT_SECRET: "secret-value",
    PATH: `${bin}${path.delimiter}${savedEnv.PATH ?? ""}`,
  });
  delete process.env.SENTROOK_MODE;
  stateDir = path.join(dir, "sentrook");
  reply = { ...NAMED };
  clearScanTokenCache();
  putJob();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      const body: Record<string, unknown> = { ...SEND.response, ...reply, request_id: planir.request_id, state: `state-${planir.session.step}` };
      for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
      return json(200, body);
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  globalThis.fetch = realFetch;
});

const DM = {
  senderId: "100200300",
  channel: "telegram",
  accountId: "default",
  senderIsOwner: true,
  assertOwnerCurrent: () => undefined,
  sessionKey: "agent:main:telegram:direct:100200300",
  sessionId: "D1",
};

function registered(pluginConfig: Record<string, unknown> = {}) {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  const sent: any[] = [];
  plugin.register({
    pluginConfig,
    registrationMode: "full",
    config: { tools: { exec: { mode: "full" } } },
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
    runtime: { channel: { outbound: { loadAdapter: async (channel: string) => ({ sendText: async (req: any) => sent.push({ channel, ...req }) }) } } },
  } as any);
  const fire = async (hook: string, event: any, ctx: any) => {
    let out: any;
    for (const h of on[hook] ?? []) out = await h(event, ctx);
    return out;
  };
  const records = (kind: string) =>
    readFileSync(path.join(stateDir, "traffic.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l))
      .filter((r) => r.kind === kind);
  const ctxOf = (n: number, job = "job-j") => {
    const sid = `cron-${job}-${n}`;
    return {
      sessionKey: `agent:main:cron:${sid}`,
      sessionId: sid,
      agentId: "main",
      runId: `r-${sid}`,
      trigger: "cron",
      inputProvenance: { kind: "internal_system", sourceTool: "cron", jobId: job },
    };
  };
  /** One call in run `n` of cron job `job` (each run its own session and agent run). */
  const call = async (
    n: number,
    opts: { job?: string; id?: string; target?: string; tool?: string; params?: Record<string, unknown> } = {},
  ) => {
    const ctx = ctxOf(n, opts.job);
    await fire("before_prompt_build", { runId: ctx.runId, prompt: "post the brief" }, ctx);
    const out = await fire(
      "before_tool_call",
      {
        toolName: opts.tool ?? "message",
        toolCallId: opts.id ?? "c1",
        runId: ctx.runId,
        params: opts.params ?? { action: "send", channel: "discord", target: opts.target ?? "#ops-reports", message: `Daily brief ${n}` },
      },
      ctx,
    );
    await hold.waitForNotices();
    return { out, rec: records("scan").at(-1) };
  };
  const end = async (n: number, job = "job-j") => {
    const ctx = ctxOf(n, job);
    await fire("agent_end", { runId: ctx.runId, success: true }, ctx);
    await hold.waitForNotices();
  };
  const command = async (name: string, args: string) => (await commands[name].handler({ ...DM, args })).text as string;
  return { fire, sent, records, call, end, command };
}

const holds = () => JSON.parse(readFileSync(path.join(stateDir, "holds.json"), "utf8")).holds;
const stored = () => {
  const file = path.join(stateDir, "passes.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")).passes : [];
};
const runsOf = () => JSON.parse(readFileSync(path.join(stateDir, "passes.json"), "utf8")).runs ?? [];
const cliCalls = () => (existsSync(cliLog) ? readFileSync(cliLog, "utf8").trim().split("\n").filter(Boolean) : []);
const fill = (t: string, v: Record<string, string>) => passes.fill(t, { passes: "/sentrook-passes", ...v });
const untilOf = (p: any) => passes.show(readTime(p.expires_at)!);
const notices = (r: ReturnType<typeof registered>) => r.sent.map((s) => s.text as string);

/** A send held in run 1 of job-j, whose receipt then finishes; the registered plugin and the hold's id. */
async function heldSend() {
  const r = registered();
  await r.command("sentrook-notify", "here");
  receipt("held-run");
  const { out, rec } = await r.call(1);
  assert.deepEqual(out, HELD);
  finish("held-run");
  return { r, id: rec.hold.id as string };
}

// ---- the shared texts -------------------------------------------------------------------------------------

test("the texts are the shared fixtures", () => {
  assert.deepEqual(hold.RUN_NOW_REASONS, RUN_NOW.reasons);
  assert.deepEqual(hold.RUN_NOW_REPLIES, RUN_NOW.replies);
  assert.deepEqual(hold.OUTCOMES, RUN_NOW.outcomes);
  assert.deepEqual([...passes.ACTING_KINDS].sort(), RUN_NOW.acting_kinds);
  assert.deepEqual([...passes.ACTING_CATEGORIES].sort(), RUN_NOW.acting_categories);
  for (const c of RUN_NOW.acts) {
    const resp = c.category ? { tool_description: { category: c.category } } : {};
    assert.equal(passes.acts(c.tool_kind, resp), c.acts, JSON.stringify(c));
  }
});

// ---- must stay silent ----------------------------------------------------------------------------------------

test("allow starts the job and the same send passes once in that run, and the outcome says it went through", async () => {
  const { r, id } = await heldSend();
  const [entry] = holds();
  assert.equal(entry.job_digest, runNow.digest(JOB));
  assert.equal(entry.acted, false);
  assert.equal(entry.run_key, "held-run");
  const answer = await r.command("sentrook-allow", id);
  const [p] = stored();
  assert.equal(answer, fill(RUN_NOW.replies.started, { job: "job-j", pass: p.id }));
  assert.deepEqual(cliCalls(), ["cron run job-j --json"], "started at once, with no prompt of its own");
  assert.equal(p.run_bound, true);
  assert.equal(runsOf()[0].run_id, "cron-request.started-1");
  const [start] = r.records("run_now");
  assert.deepEqual([start.op, start.started, start.hold_id, start.pass_id, start.run_id], ["start", true, id, p.id, "cron-request.started-1"]);
  // the started run: its receipt names the run id the command returned
  receipt("cron-request.started-1");
  const { out, rec } = await r.call(2);
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed_by_pass");
  assert.equal(rec.pass.id, p.id);
  assert.deepEqual(stored(), []);
  await r.end(2);
  finish("cron-request.started-1");
  assert.equal(notices(r).at(-1), fill(RUN_NOW.outcomes.passed, { job: "job-j" }));
  const ended = r.records("run_now").at(-1);
  assert.deepEqual([ended.op, ended.passed, ended.held], ["ended", true, []]);
  // only once
  assert.deepEqual((await r.call(3)).out, HELD);
});

test("a run that is the started one before its run id is recorded still counts (it started after the answer)", async () => {
  const { r, id } = await heldSend();
  writeFileSync(path.join(dir, "cli.out"), JSON.stringify({ ok: true, enqueued: true }));
  await r.command("sentrook-allow", id);
  receipt("cron-request.unknown");
  assert.equal((await r.call(2)).out, undefined);
});

test("allow later starts nothing and the job's next run uses the pass", async () => {
  const { r, id } = await heldSend();
  const answer = await r.command("sentrook-allow", `${id} later`);
  const [p] = stored();
  assert.equal(answer, fill(RUN_NOW.replies.later, { job: "job-j", pass: p.id, until: untilOf(p) }));
  assert.deepEqual(cliCalls(), []);
  assert.equal(p.run_bound, undefined);
  receipt("next-run");
  assert.equal((await r.call(2)).out, undefined);
});

test("allow on a hold that is not on a cron job starts nothing", async () => {
  const r = registered();
  // a cron-triggered run OpenClaw names no job for
  const ctx = { sessionKey: "agent:main:cron:x", sessionId: "cron-x", agentId: "main", runId: "r-x", trigger: "cron" };
  await r.fire("before_prompt_build", { runId: "r-x", prompt: "post the brief" }, ctx);
  await r.fire("before_tool_call", { toolName: "message", toolCallId: "c1", runId: "r-x", params: { action: "send", target: "#ops-reports", message: "x" } }, ctx);
  await hold.waitForNotices();
  const [entry] = holds();
  const answer = await r.command("sentrook-allow", entry.id);
  assert.ok(answer.startsWith("The next identical call from an unattended run may go through once"), answer);
  assert.deepEqual(cliCalls(), []);
});

// ---- must fire ---------------------------------------------------------------------------------------------------

test("a started run that sends elsewhere is held, and the outcome names the new hold", async () => {
  const { r, id } = await heldSend();
  await r.command("sentrook-allow", id);
  receipt("cron-request.started-1");
  reply = { ...NAMED, entities: GENERAL };
  const { out, rec } = await r.call(2, { target: "#general" });
  assert.deepEqual(out, HELD);
  const fresh = rec.hold.id;
  assert.notEqual(fresh, id);
  await r.end(2);
  assert.equal(notices(r).at(-1), fill(RUN_NOW.outcomes.held, { job: "job-j", hold: fresh }));
  assert.deepEqual(stored(), [], "the pass was bound to that run: it ended with it");
});

test("a started run that makes the call and another held one says both", async () => {
  const { r, id } = await heldSend();
  await r.command("sentrook-allow", id);
  receipt("cron-request.started-1");
  assert.equal((await r.call(2)).out, undefined);
  reply = { ...NAMED, entities: GENERAL };
  const { rec } = await r.call(2, { id: "c2", target: "#general" });
  await r.end(2);
  assert.equal(notices(r).at(-1), fill(RUN_NOW.outcomes.passed_held, { job: "job-j", hold: rec.hold.id }));
});

test("a started run that does not make the call says so and drops the pass", async () => {
  const { r, id } = await heldSend();
  await r.command("sentrook-allow", id);
  receipt("cron-request.started-1");
  await r.end(2);
  finish("cron-request.started-1");
  assert.equal(notices(r).at(-1), fill(RUN_NOW.outcomes.none, { job: "job-j" }));
  assert.deepEqual(stored(), []);
  receipt("later-run");
  assert.deepEqual((await r.call(3)).out, HELD);
});

test("the run-bound pass never serves the held run, another run or another job", async () => {
  const { r, id } = await heldSend();
  await r.command("sentrook-allow", id);
  // the held run retries (its receipt is done; its own agent run id is the key)
  assert.deepEqual((await r.call(1, { id: "c2" })).out, HELD);
  // another job
  assert.deepEqual((await r.call(1, { job: "job-k" })).out, HELD);
  // a run of the job other than the one started
  receipt("some-other-run");
  assert.deepEqual((await r.call(9)).out, HELD);
  assert.equal(stored().length, 1);
});

const GUARDS: [string, () => void, string][] = [
  ["removed", () => removeJobs(), "missing"],
  ["disabled", () => putJob({ ...JOB, enabled: false }), "paused"],
  ["a one-shot that ran", () => putJob({ ...JOB, enabled: false, schedule: { kind: "at", at: "2026-11-24T09:00:00Z" } }, { lastRunAtMs: 1 }), "terminal"],
  ["running", () => receipt("someone-else"), "running"],
  ["its message edited", () => putJob({ ...JOB, payload: { kind: "agentTurn", message: "Post it to #general instead." } }), "changed"],
  ["its delivery edited", () => putJob({ ...JOB, delivery: { mode: "announce", channel: "discord", to: "channel:999" } }), "changed"],
  ["an unreadable store", () => writeFileSync(path.join(dir, "state", "openclaw.sqlite"), "not a database"), "unknown"],
];
for (const [name, change, reason] of GUARDS) {
  test(`a job that cannot be run now is not started, and the reply says why: ${name}`, async () => {
    const { r, id } = await heldSend();
    change();
    const answer = await r.command("sentrook-allow", id);
    const [p] = stored();
    assert.equal(answer, fill(RUN_NOW.replies.fallback, { job: "job-j", pass: p.id, until: untilOf(p), reason: RUN_NOW.reasons[reason] }));
    assert.deepEqual(cliCalls(), []);
    assert.equal(p.run_bound, undefined);
    assert.equal(r.records("run_now").at(-1).reason, reason);
  });
}

test("run state does not count as a changed job", async () => {
  const { r, id } = await heldSend();
  putJob({ ...JOB, updatedAtMs: Date.now() }, { nextRunAtMs: Date.now() + 3600_000, lastRunAtMs: Date.now(), lastStatus: "ok" });
  assert.ok((await r.command("sentrook-allow", id)).startsWith("Running job job-j again now"));
});

test("OpenClaw's own refusal is the reply's reason", async () => {
  const { r, id } = await heldSend();
  writeFileSync(path.join(dir, "cli.out"), JSON.stringify({ ok: true, ran: false, reason: "already-running" }));
  const answer = await r.command("sentrook-allow", id);
  assert.ok(answer.includes(`It was not run again now: ${RUN_NOW.reasons.running}.`), answer);
  assert.equal(stored()[0].run_bound, undefined);
  assert.deepEqual(runsOf(), []);
});

test("a command that fails leaves the pass for the next run", async () => {
  const { r, id } = await heldSend();
  writeFileSync(path.join(dir, "cli.out"), "gateway closed (1006)");
  const answer = await r.command("sentrook-allow", id);
  assert.ok(answer.includes(`It was not run again now: ${RUN_NOW.reasons.failed}.`), answer);
  receipt("next-run");
  assert.equal((await r.call(2)).out, undefined);
});

test("a second allow on the same hold starts no second run", async () => {
  const { r, id } = await heldSend();
  await r.command("sentrook-allow", id);
  assert.ok((await r.command("sentrook-allow", id)).startsWith(`No held call ${id}`));
  assert.ok((await r.command("sentrook-allow", `${id} now`)).startsWith(`No held call ${id}`));
  assert.equal(cliCalls().length, 1);
});

/** A run that posts a status message (it runs), then makes the held send. */
async function actedHold() {
  const r = registered();
  await r.command("sentrook-notify", "here");
  receipt("held-run");
  reply = { ...NAMED, risk: 12, tool_description: { category: "sends_message_to_person" } };
  assert.equal((await r.call(1, { id: "c0", target: "#status" })).out, undefined);
  reply = { ...NAMED };
  const { out, rec } = await r.call(1, { id: "c1" });
  assert.deepEqual(out, HELD);
  finish("held-run");
  return { r, rec };
}

test("a hold whose run had already sent something waits unless allow now", async () => {
  const { r, rec } = await actedHold();
  assert.deepEqual(rec.hold.offers, ["allow", "allow now", "deny"]);
  assert.equal(holds()[0].acted, true);
  const answer = await r.command("sentrook-allow", rec.hold.id);
  const [p] = stored();
  assert.equal(answer, fill(RUN_NOW.replies.fallback, { job: "job-j", pass: p.id, until: untilOf(p), reason: RUN_NOW.reasons.acted }));
  assert.deepEqual(cliCalls(), []);
});

test("allow now runs the whole job again, with a warning", async () => {
  const { r, rec } = await actedHold();
  const answer = await r.command("sentrook-allow", `${rec.hold.id} now`);
  const [p] = stored();
  assert.equal(answer, fill(RUN_NOW.replies.started_now, { job: "job-j", pass: p.id }));
  assert.equal(cliCalls().length, 1);
});

test("an earlier call that was held, so never ran, does not count as acted", async () => {
  const r = registered();
  receipt("held-run");
  reply = { ...NAMED, tool_description: { category: "sends_message_to_person" } };
  assert.deepEqual((await r.call(1, { id: "c0", target: "#status" })).out, HELD);
  reply = { ...NAMED, entities: GENERAL };
  const { rec } = await r.call(1, { id: "c1", target: "#general" });
  assert.equal(holds().at(-1).acted, false);
  assert.ok(rec.hold.offers.includes("allow later"));
});

test("observe mode starts nothing", async () => {
  const { id } = await heldSend();
  process.env.SENTROOK_MODE = "observe";
  const r = registered();
  const answer = await r.command("sentrook-allow", id);
  assert.ok(answer.includes(`It was not run again now: ${RUN_NOW.reasons.observe}.`), answer);
  assert.deepEqual(cliCalls(), []);
});

test("without a run end the job's next scan sends the outcome", async () => {
  const { r, id } = await heldSend();
  await r.command("sentrook-allow", id);
  receipt("cron-request.started-1");
  assert.equal((await r.call(2)).out, undefined);
  finish("cron-request.started-1");
  receipt("next-run");
  await r.call(3);
  assert.ok(notices(r).includes(fill(RUN_NOW.outcomes.passed, { job: "job-j" })));
});

// ---- starting the job ----------------------------------------------------------------------------------------

test("the command is the gateway's own OpenClaw, else openclaw on the PATH", () => {
  const entry = path.join(dir, "openclaw.mjs");
  writeFileSync(entry, "");
  assert.deepEqual(runNow.openclawCommand(["node", entry], { PATH: "" }), [process.execPath, entry]);
  assert.deepEqual(runNow.openclawCommand(["node", "/x/test.ts"], process.env), [path.join(dir, "bin", "openclaw")]);
  assert.equal(runNow.openclawCommand(["node", "/x/test.ts"], { PATH: "" }), null);
});

test("start reads OpenClaw's answer and never throws", async () => {
  const ran: string[][] = [];
  const runner = (out: string, code = 0): runNow.Runner => async (argv) => {
    ran.push(argv);
    return { code, stdout: out, stderr: "" };
  };
  assert.deepEqual(await runNow.start("job-j", runner('noise\n{"ok":true,"enqueued":true,"runId":"cron-request.1"}\n'), ["openclaw"]), {
    started: true,
    runId: "cron-request.1",
    why: "",
  });
  assert.deepEqual(ran[0], ["openclaw", "cron", "run", "job-j", "--json"]);
  assert.equal((await runNow.start("job-j", runner('{"ok":true,"ran":false,"reason":"disabled"}'), ["openclaw"])).why, "paused");
  assert.match((await runNow.start("job-j", runner("boom", 1), ["openclaw"])).why, /^exit 1: boom/);
  assert.equal((await runNow.start("job-j", runner(""), null)).why, "unavailable");
});

test("two holds of one job allowed back to back start one run", async () => {
  const { r, id } = await heldSend();
  receipt("held-run-2");
  reply = { ...NAMED, entities: GENERAL };
  const { rec } = await r.call(5, { target: "#general" });
  finish("held-run-2");
  assert.ok((await r.command("sentrook-allow", id)).startsWith("Running job job-j again now"));
  const answer = await r.command("sentrook-allow", rec.hold.id);
  assert.ok(answer.includes(`It was not run again now: ${RUN_NOW.reasons.running}.`), answer);
  assert.equal(cliCalls().length, 1);
});

test("a job edited after the first notice counts as changed, even after a repeat", async () => {
  const { r, id } = await heldSend();
  putJob({ ...JOB, payload: { kind: "agentTurn", message: "Post it to #general instead." } });
  receipt("held-run-2");
  const { rec } = await r.call(2);
  finish("held-run-2");
  assert.equal(rec.hold.repeat, true);
  assert.equal(rec.hold.id, id);
  const answer = await r.command("sentrook-allow", id);
  assert.ok(answer.includes(`It was not run again now: ${RUN_NOW.reasons.changed}.`), answer);
  assert.deepEqual(cliCalls(), []);
});
