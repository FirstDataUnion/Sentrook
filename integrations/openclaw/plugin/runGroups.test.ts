/**
 * One notice per cron run: the run's first hold sends the notice, later holds of other actions in the same run join its
 * group, and the run's end (`agent_end`) sends one line listing them. `/sentrook-allow <lead> all` answers the lead and
 * every call a line listed, in one started run; a call that itself sends or writes is left for its own answer. The
 * texts are shared with the Hermes plugin (`integrations/fixtures/hold/cases.json`, `run_group`).
 *
 * The harness is the run-now one (`runNow.test.ts`): a real job store and a stand-in `openclaw` command.
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

const FIXTURES = JSON.parse(readFileSync(fileURLToPath(new URL("../../fixtures/hold/cases.json", import.meta.url)), "utf8"));
const SEND = FIXTURES.notices[0];
const NAMED = {
  risk: 47,
  enforced: null,
  owner_pass: "once",
  approval_fingerprint: "afp1:message_send|ch:discord:#ops-reports",
  reasons: [{ code: "trigger.scheduled" }, { code: "send.unbound_channel", subject: "E1" }],
};
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

/** OpenClaw's receipt for a run of job-j, running. */
function receipt(runId: string, startedAt = Date.now()): void {
  const conn = db();
  conn
    .prepare("INSERT INTO cron_run_receipts VALUES (?, 's', 'job-j', 'rev', 'main', ?, 'running', 1, ?, NULL)")
    .run(`receipt-${runId}`, runId, startedAt);
  conn.close();
}

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  dir = mkdtempSync(path.join(tmpdir(), "sentrook-rungroups-"));
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
const cliCalls = () => (existsSync(cliLog) ? readFileSync(cliLog, "utf8").trim().split("\n").filter(Boolean) : []);
const notices = (r: ReturnType<typeof registered>) => r.sent.map((s) => s.text as string);

const GROUP = Object.fromEntries(Object.entries(FIXTURES.run_group as Record<string, string>).filter(([k]) => !k.startsWith("_")));
/** The scanner's category for each tool's call: only the send's call itself sends or writes (`passes.acts`). */
const CATEGORY: Record<string, string> = {
  exec: "runs_code_or_installer",
  web_fetch: "fetches_remote_content",
  read: "reads_local_data",
  message: "sends_data_off_host",
};

/** One call of `tool` in run `n` of `job`: each tool is a different action. */
async function groupCall(r: ReturnType<typeof registered>, n: number, tool: string, id: string, job = "job-j") {
  reply = { ...NAMED, tool_description: { category: CATEGORY[tool], template: "Runs {E1}" } };
  return r.call(n, { job, tool, id, params: { command: `step ${id}`, url: "https://example.test/a" } });
}

/** Run `n` holds three different calls: an exec, a web fetch and a send. Returns the plugin and their hold ids. */
async function threeHolds(r?: ReturnType<typeof registered>, n = 1) {
  if (!r) {
    r = registered();
    await r.command("sentrook-notify", "here");
  }
  const ids: string[] = [];
  for (const [i, tool] of ["exec", "web_fetch", "message"].entries()) {
    const { out, rec } = await groupCall(r, n, tool, `c${i}`);
    assert.deepEqual(out, HELD);
    ids.push(rec.hold.id);
  }
  return { r, ids };
}

/** A send from a sub-agent of run `n` of job-j, spawned from the run's session. */
async function childCall(r: ReturnType<typeof registered>, n: number, name = "a1") {
  const parent = { sessionKey: `agent:main:cron:cron-job-j-${n}`, sessionId: `cron-job-j-${n}`, agentId: "main", runId: `r-cron-job-j-${n}`, trigger: "cron", inputProvenance: { kind: "internal_system", sourceTool: "cron", jobId: "job-j" } };
  await r.fire("before_prompt_build", { runId: parent.runId, prompt: "post the brief" }, parent);
  const key = `agent:main:subagent:${parent.sessionId}-${name}`;
  await r.fire("subagent_spawned", { childSessionKey: key, runId: `r-${key}` }, { childSessionKey: key, requesterSessionKey: parent.sessionKey });
  const ctx = { sessionKey: key, sessionId: `sub-${parent.sessionId}-${name}`, agentId: "main", runId: `r-sub-${parent.sessionId}-${name}`, trigger: "user" };
  await r.fire("before_prompt_build", { runId: ctx.runId, prompt: "Post the brief." }, ctx);
  reply = { ...NAMED };
  const out = await r.fire(
    "before_tool_call",
    { toolName: "message", toolCallId: "s1", runId: ctx.runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: `Daily brief ${n}` } },
    ctx,
  );
  await hold.waitForNotices();
  return { out, rec: r.records("scan").at(-1) };
}

// ---- the shared texts ---------------------------------------------------------------------------------------

test("the texts are the shared fixtures", () => {
  assert.deepEqual(hold.RUN_GROUP, GROUP);
});

// ---- must stay silent: one notice --------------------------------------------------------------------------

test("a run that holds three calls sends one notice and one end line", async () => {
  const { r, ids } = await threeHolds();
  const [lead, second, third] = ids as [string, string, string];
  assert.equal(notices(r).length, 1, "only the run's first hold sends a notice");
  const byId = Object.fromEntries(holds().map((h: any) => [h.id, h]));
  assert.equal(byId[second].lead, lead);
  assert.equal(byId[third].lead, lead);
  assert.deepEqual(byId[lead].group, [second, third]);
  assert.equal(byId[third].acts, true);
  assert.equal(byId[second].acts, false);
  const scan = r.records("scan").at(-1);
  assert.deepEqual(scan.hold.notice, { status: "not_sent", target: null, reason: "in the run's group", lead });
  await r.end(1);
  const sent = notices(r);
  assert.equal(sent.length, 2);
  const line = sent.at(-1)!;
  assert.equal(line.split("\n")[0], passes.fill(GROUP.head!, { job: "job-j", n: "2", lead }));
  assert.ok(line.includes(`- ${second}: web_fetch: `), line);
  assert.ok(line.includes(`- ${third}: message: `), line);
  assert.equal(line.split(GROUP.own_answer!).length - 1, 1);
  assert.ok(line.includes(passes.fill(GROUP.all!, { allow: "/sentrook-allow", lead })), line);
  assert.ok(line.includes(passes.fill(GROUP.each!, { allow: "/sentrook-allow", deny: "/sentrook-deny", why: "/sentrook-why" })), line);
  const [rec] = r.records("run_group");
  assert.deepEqual([rec.op, rec.lead, rec.listed, rec.job_ref], ["end_line", lead, [second, third], passes.jobRef("job-j")]);
  assert.equal(rec.notice.status, "queued");
  await r.end(1);
  assert.equal(notices(r).length, 2, "a run's end line goes out once");
});

test("allow all after the end line lets the listed calls through in one started run", async () => {
  const { r, ids } = await threeHolds();
  const [lead, second, third] = ids as [string, string, string];
  await r.end(1);
  const reply_ = await r.command("sentrook-allow", `${lead} all`);
  assert.deepEqual(cliCalls(), ["cron run job-j --json"], "one run is started");
  assert.ok(reply_.includes(` ${passes.fill(GROUP.covered!, { ids: second })}`), reply_);
  assert.ok(reply_.includes(` ${passes.fill(GROUP.left!, { ids: third })}`), reply_);
  assert.deepEqual(
    holds().map((h: any) => h.id),
    [third],
    "the send is left for its own answer",
  );
  const added = r.records("passes").filter((p) => p.group_lead === lead);
  assert.deepEqual(
    added.map((p) => p.hold_id),
    [second],
  );
  receipt("cron-request.started-1");
  let got = await groupCall(r, 2, "exec", "c0");
  assert.equal(got.out, undefined);
  assert.equal(got.rec.decision, "allowed_by_pass");
  got = await groupCall(r, 2, "web_fetch", "c1");
  assert.equal(got.out, undefined);
  assert.equal(got.rec.decision, "allowed_by_pass");
  got = await groupCall(r, 2, "message", "c2");
  assert.deepEqual(got.out, HELD, "not covered by all");
});

// ---- must fire ------------------------------------------------------------------------------------------------

test("allow all before the end line covers only the first call", async () => {
  const { r, ids } = await threeHolds();
  const [lead, second] = ids as [string, string, string];
  const reply_ = await r.command("sentrook-allow", `${lead} all`);
  assert.ok(reply_.endsWith(` ${passes.fill(GROUP.none_listed!, { lead })}`), reply_);
  receipt("cron-request.started-1");
  let got = await groupCall(r, 2, "exec", "c0");
  assert.equal(got.out, undefined);
  assert.equal(got.rec.decision, "allowed_by_pass");
  got = await groupCall(r, 2, "web_fetch", "c1");
  assert.deepEqual(got.out, HELD, "never shown to the owner, so not covered");
  assert.ok(holds().some((h: any) => h.id === second));
});

test("a call held after the end line gets a notice of its own", async () => {
  const { r } = await threeHolds();
  await r.end(1);
  const before = notices(r).length;
  const { out, rec } = await groupCall(r, 1, "read", "c9");
  assert.deepEqual(out, HELD);
  assert.equal(notices(r).length, before + 1);
  assert.equal(holds().find((h: any) => h.id === rec.hold.id).lead, undefined);
});

test("a group member cannot answer for the group", async () => {
  const { r, ids } = await threeHolds();
  const [lead, second] = ids as [string, string, string];
  await r.end(1);
  const reply_ = await r.command("sentrook-allow", `${second} all`);
  assert.equal(reply_, passes.fill(GROUP.not_lead!, { id: second, lead, allow: "/sentrook-allow" }));
  assert.deepEqual(cliCalls(), []);
  assert.equal(holds().length, 3, "nothing answered");
});

test("the next run gets its own notice", async () => {
  const { r } = await threeHolds();
  await r.end(1);
  const before = notices(r).length;
  const { out } = await groupCall(r, 2, "read", "c5");
  assert.deepEqual(out, HELD);
  assert.equal(notices(r).length, before + 1);
});

test("two jobs keep separate groups", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  await groupCall(r, 1, "exec", "c0");
  await groupCall(r, 1, "exec", "c0", "job-k");
  assert.equal(notices(r).length, 2);
});

test("a run whose end was not seen gets its end line when the next run holds", async () => {
  const { r, ids } = await threeHolds();
  const [lead] = ids as [string, string, string];
  const before = notices(r).length;
  await groupCall(r, 2, "read", "c5");
  const sent = notices(r).slice(before);
  assert.equal(sent.length, 2, "the earlier run's end line, then the new run's notice");
  assert.equal(sent[0]!.split("\n")[0], passes.fill(GROUP.head!, { job: "job-j", n: "2", lead }));
});

test("a repeat in a new run clears the hold's end line, so that run's other holds join it", async () => {
  const { r, ids } = await threeHolds();
  const [lead] = ids as [string, string, string];
  await r.end(1);
  assert.ok(holds().find((h: any) => h.id === lead).end_line_at);
  // run 2 repeats the lead's call, then holds a new one
  const again = await groupCall(r, 2, "exec", "c0");
  assert.equal(again.rec.hold.repeat, true);
  assert.equal(holds().find((h: any) => h.id === lead).end_line_at, undefined);
  const before = notices(r).length;
  const { rec } = await groupCall(r, 2, "read", "c9");
  assert.equal(holds().find((h: any) => h.id === rec.hold.id).lead, lead);
  assert.equal(notices(r).length, before, "joined the repeated lead's group");
});

test("a sub-agent of the run joins the run's group", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  const first = await groupCall(r, 1, "exec", "c0");
  const { out, rec } = await childCall(r, 1);
  assert.deepEqual(out, HELD);
  assert.equal(holds().find((h: any) => h.id === rec.hold.id).lead, first.rec.hold.id);
  assert.equal(notices(r).length, 1);
});
