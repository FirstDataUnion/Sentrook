/**
 * A cron job's own delivery target: on a run of that job, a send to the channel the owner configured for it carries a
 * destination grant for that channel, scoped to the run's session. Only the job's own configured target counts, read
 * from OpenClaw's job store by the job id the host gives the run, at its first agent hook; a job changed after the run
 * began counts for nothing.
 */

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import { deliveryPattern, deliveryRef, readCronJob } from "./cronDelivery.ts";
import plugin from "./index.ts";
import { callPlatform, relevantGrants, sendPlatformOf, sessionRef } from "./planir.ts";
import * as setup from "./setup.ts";

const JOB = "561a1f55-c5e9-41fb-930b-1ee7b8e31373";
const RUN_SESSION = "ee5a6348-31d9-4614-9762-867dbceaeabe";
const SESSION_KEY = `agent:sgt-johnson:cron:${JOB}:run:${RUN_SESSION}`;
const CHANNEL = "1519377377082216448";
const DELIVERY = { mode: "announce", channel: "discord", to: CHANNEL, bestEffort: false };

const ENV_KEYS = [
  "OPENCLAW_STATE_DIR",
  "SENTROOK_DEV_ENDPOINTS",
  "SENTROOK_SCAN_URL",
  "SENTROOK_OIDC_ISSUER",
  "SENTROOK_SCAN_CLIENT_ID",
  "SENTROOK_SCAN_CLIENT_SECRET",
  "SENTROOK_MODE",
];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let dir = "";
let scans: any[] = [];
let hostConfig: any = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  dir = mkdtempSync(path.join(tmpdir(), "sentrook-cron-"));
  Object.assign(process.env, {
    OPENCLAW_STATE_DIR: dir,
    SENTROOK_DEV_ENDPOINTS: "1",
    SENTROOK_SCAN_URL: "http://scan.test",
    SENTROOK_OIDC_ISSUER: "http://idp.test",
    SENTROOK_SCAN_CLIENT_ID: "client",
    SENTROOK_SCAN_CLIENT_SECRET: "secret-value",
  });
  delete process.env.SENTROOK_MODE;
  scans = [];
  hostConfig = { tools: { exec: { mode: "full" } } };
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      scans.push(planir);
      return json(200, {
        response_version: "2.0",
        request_id: planir.request_id,
        status: "ok",
        risk: 5,
        enforced: null,
        tree: { suspicion: { score: 0.1 }, consequence: { score: 0.1 } },
        reasons: [],
        action_fingerprint: `afp1:x|step:${planir.session.step}`,
        state: `state-${planir.session.step}`,
      });
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

/** OpenClaw's job store as 2026.11 keeps it: one `cron_jobs` row per job, the definition in `job_json`. */
function storeJob(job: Record<string, unknown>, updatedAt: number, jobId = JOB) {
  mkdirSync(path.join(dir, "state"), { recursive: true });
  const db = new DatabaseSync(path.join(dir, "state", "openclaw.sqlite"));
  db.exec(
    "CREATE TABLE IF NOT EXISTS cron_jobs (store_key TEXT NOT NULL, job_id TEXT NOT NULL, name TEXT NOT NULL, " +
      "job_json TEXT NOT NULL, state_json TEXT NOT NULL DEFAULT '{}', runtime_updated_at_ms INTEGER, " +
      "updated_at INTEGER NOT NULL, PRIMARY KEY (store_key, job_id)) STRICT",
  );
  db.prepare("INSERT OR REPLACE INTO cron_jobs (store_key, job_id, name, job_json, updated_at) VALUES (?, ?, ?, ?, ?)").run(
    "/home/node/.openclaw/cron/jobs.json",
    jobId,
    "workout",
    JSON.stringify({ id: jobId, agentId: "sgt-johnson", name: "workout", createdAtMs: updatedAt - 1000, ...job }),
    updatedAt,
  );
  db.close();
}

const LONG_AGO = Date.parse("2026-10-21T16:01:52Z");

function registered() {
  const on: Record<string, any[]> = {};
  plugin.register({
    pluginConfig: {},
    registrationMode: "full",
    config: hostConfig,
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: () => undefined,
    runtime: { channel: { outbound: { loadAdapter: async () => ({ sendText: async () => ({ ok: true }) }) } } },
  } as any);
  const fire = async (hook: string, event: any, ctx: any) => {
    let out: any;
    for (const h of on[hook] ?? []) out = await h(event, ctx);
    return out;
  };
  return { fire };
}

/** A cron run's hook context as OpenClaw 2026.11 builds it (the agent hooks carry the job id). */
const TOOL_CTX = {
  sessionKey: SESSION_KEY,
  sessionId: RUN_SESSION,
  agentId: "sgt-johnson",
  runId: "r-cron",
  channelId: `channel:${CHANNEL}`,
  requester: { channel: "discord", accountId: "sgt-johnson" },
};
const AGENT_CTX = { ...TOOL_CTX, trigger: "cron", jobId: JOB, channel: "discord", channelId: CHANNEL, accountId: "sgt-johnson" };

const send = (id: string, target: string, platform: string | null = "discord") => ({
  toolName: "message",
  toolCallId: id,
  runId: "r-cron",
  params: { action: "send", ...(platform ? { channel: platform } : {}), target, message: "Time to train.", accountId: "sgt-johnson" },
});

/** Starts the run (its first hook), then sends each call in it; returns the grants each scan carried. */
async function cronRun(calls: any[], opts: { agentCtx?: Record<string, unknown>; toolCtx?: Record<string, unknown>; between?: () => void } = {}) {
  const r = registered();
  const agentCtx = { ...AGENT_CTX, ...opts.agentCtx };
  await r.fire("before_prompt_build", { runId: "r-cron", prompt: `[cron:${JOB} workout] post the reminder` }, agentCtx);
  await r.fire("before_agent_run", { runId: "r-cron" }, agentCtx);
  opts.between?.();
  for (const c of calls) await r.fire("before_tool_call", c, { ...TOOL_CTX, ...opts.toolCtx, toolCallId: c.toolCallId });
  return scans.map((p) => p.grants);
}

const EXPECTED = {
  grant_ref: deliveryRef(JOB),
  kind: "destination",
  pattern: `discord:${CHANNEL}`,
  scope: "session",
  session_ref: sessionRef(RUN_SESSION),
};

// ---- must relieve ----------------------------------------------------------------------------------

test("a cron run's send to its job's own delivery channel carries a session grant for that channel", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const [grants] = await cronRun([send("c1", `channel:${CHANNEL}`)]);
  assert.deepEqual(grants, [EXPECTED]);
});

test("the target is matched written with or without the platform prefix, in the call and in the job", async () => {
  for (const to of [CHANNEL, `channel:${CHANNEL}`, `discord:${CHANNEL}`, `discord:channel:${CHANNEL}`]) {
    scans = [];
    storeJob({ delivery: { ...DELIVERY, to } }, LONG_AGO);
    const all = await cronRun([
      send("c1", `channel:${CHANNEL}`),
      send("c2", CHANNEL),
      send("c3", `discord:${CHANNEL}`, null),
    ]);
    for (const grants of all) assert.deepEqual(grants, [EXPECTED], `job to ${to}`);
  }
});

test("a cron run whose hooks give no job id carries no grant", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const [grants] = await cronRun([send("c1", `channel:${CHANNEL}`)], { agentCtx: { jobId: undefined } });
  assert.deepEqual(grants, []);
});

test("an older OpenClaw's jobs.json store is read when there is no job table", async () => {
  mkdirSync(path.join(dir, "cron"), { recursive: true });
  const job = { id: JOB, agentId: "sgt-johnson", createdAtMs: LONG_AGO - 1000, updatedAtMs: LONG_AGO, delivery: DELIVERY };
  writeFileSync(path.join(dir, "cron", "jobs.json"), JSON.stringify({ version: 1, jobs: [job] }));
  const [grants] = await cronRun([send("c1", `channel:${CHANNEL}`)]);
  assert.deepEqual(grants, [EXPECTED]);
});

// ---- must not ----------------------------------------------------------------------------------------

test("a send to a different channel carries no grant", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const [grants] = await cronRun([send("c1", "channel:1519377377082216449")]);
  assert.deepEqual(grants, []);
});

test("a direct message to a user is not the job's channel; nor does a job that delivers to a person give a grant", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  // A `<platform>:<id>` grant is sent for the id as a channel target only, never inside a person's `user:<id>`; the
  // scanner never reads a channel grant as covering a person either (sentrook/tests/test_cron_delivery_grant.py).
  const [dm] = await cronRun([send("c1", `user:${CHANNEL}`)]);
  assert.deepEqual(dm, []);
  for (const delivery of [
    { ...DELIVERY, to: `user:${CHANNEL}` },
    { ...DELIVERY, channel: "telegram", to: "5150123" },
    { ...DELIVERY, channel: "whatsapp", to: "+15551234567" },
    { ...DELIVERY, channel: "telegram", to: "@someone" },
    { ...DELIVERY, channel: "slack", to: "U0B0QV5434G" },
    { ...DELIVERY, channel: "slack", to: "D0B0QV5434G" },
  ]) assert.equal(deliveryPattern(delivery), null, JSON.stringify(delivery));
  assert.equal(deliveryPattern({ ...DELIVERY, channel: "telegram", to: "-1001234567890" }), "telegram:-1001234567890");
  assert.equal(deliveryPattern({ ...DELIVERY, channel: "slack", to: "C0B0QV5434G" }), "slack:C0B0QV5434G");
});

test("an attended chat carries no job grant, even with a job id in its context", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const chat = { sessionKey: "agent:sgt-johnson:discord:channel:1519377377082216448", trigger: "user", jobId: JOB };
  const [grants] = await cronRun([send("c1", `channel:${CHANNEL}`)], {
    agentCtx: chat,
    toolCtx: { sessionKey: chat.sessionKey, requester: { channel: "discord", senderIsOwner: true } },
  });
  assert.deepEqual(grants, []);
});

test("a cron job without a delivery target carries no grant", async () => {
  for (const delivery of [undefined, { mode: "none" }, { mode: "announce", channel: "last" }, { mode: "announce", channel: "discord" }, { mode: "webhook", to: "https://hooks.example/x" }]) {
    scans = [];
    storeJob(delivery ? { delivery } : {}, LONG_AGO);
    const [grants] = await cronRun([send("c1", `channel:${CHANNEL}`)]);
    assert.deepEqual(grants, [], JSON.stringify(delivery));
  }
});

test("a job saved again after the run began carries no grant", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const all = await cronRun([send("c1", `channel:${CHANNEL}`)], {
    between: () => storeJob({ delivery: DELIVERY }, Date.now() + 5),
  });
  assert.deepEqual(all[0], []);
});

test("a job store written during the run cannot move the grant to another channel", async () => {
  // The agent writes the store directly (an exec of sqlite3), pointing the job at its own channel and backdating it.
  const OTHER = "1519377377082216449";
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const all = await cronRun([send("c1", `channel:${OTHER}`), send("c2", `channel:${CHANNEL}`)], {
    between: () => storeJob({ delivery: { ...DELIVERY, to: OTHER } }, LONG_AGO),
  });
  assert.deepEqual(all, [[], []]);
});

test("with the database store present, a lingering jobs.json is not read", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO, "another-job");
  mkdirSync(path.join(dir, "cron"), { recursive: true });
  const job = { id: JOB, agentId: "sgt-johnson", createdAtMs: LONG_AGO - 1000, updatedAtMs: LONG_AGO, delivery: DELIVERY };
  writeFileSync(path.join(dir, "cron", "jobs.json"), JSON.stringify({ version: 1, jobs: [job] }));
  assert.equal(readCronJob(dir, JOB), null);
  assert.deepEqual((await cronRun([send("c1", `channel:${CHANNEL}`)]))[0], []);
});

for (const tool of ["cron", "automations"]) {
  test(`a job the agent changed with its ${tool} tool in this run carries no grant`, async () => {
    storeJob({ delivery: DELIVERY }, LONG_AGO);
    const edit = { toolName: tool, toolCallId: "e1", runId: "r-cron", params: { action: "update", jobId: JOB, patch: { delivery: DELIVERY } } };
    const all = await cronRun([edit, send("c1", `channel:${CHANNEL}`)]);
    assert.deepEqual(all[1], []);
  });
}

test("reading a job with the cron tool is not changing it", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const read = { toolName: "cron", toolCallId: "g1", runId: "r-cron", params: { action: "get", jobId: JOB } };
  assert.deepEqual((await cronRun([read, send("c1", `channel:${CHANNEL}`)]))[1], [EXPECTED]);
});

test("another agent's job carries no grant", async () => {
  storeJob({ delivery: DELIVERY, agentId: "clawtana" }, LONG_AGO);
  assert.deepEqual((await cronRun([send("c1", `channel:${CHANNEL}`)]))[0], []);
});

test("a job that names no agent is not another agent's run's: with no agents listed the default is main", async () => {
  storeJob({ delivery: DELIVERY, agentId: undefined }, LONG_AGO);
  assert.deepEqual((await cronRun([send("c1", `channel:${CHANNEL}`)]))[0], []);
});

test("a job that names no agent belongs to the agent the config marks as default", async () => {
  storeJob({ delivery: DELIVERY, agentId: undefined }, LONG_AGO);
  // written with capitals in the config, as OpenClaw allows
  hostConfig = { tools: { exec: { mode: "full" } }, agents: { list: [{ id: "main" }, { id: "Sgt-Johnson", default: true }] } };
  assert.deepEqual((await cronRun([send("c2", `channel:${CHANNEL}`)]))[0], [EXPECTED]);
});

test("a job target written as a #name is kept for a send to that channel by name", async () => {
  storeJob({ delivery: { ...DELIVERY, to: "#workouts" } }, LONG_AGO);
  const [grants] = await cronRun([send("c1", "channel:workouts")]);
  assert.deepEqual(grants, [{ ...EXPECTED, pattern: "discord:#workouts" }]);
});

test("a job the store does not hold carries no grant", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  assert.deepEqual((await cronRun([send("c1", `channel:${CHANNEL}`)], { agentCtx: { jobId: "0000" } }))[0], []);
});

// ---- a send that names only its account --------------------------------------------------------------

/** OpenClaw's config with the job's agent posting as a Discord account, and another agent on Telegram. */
const ACCOUNTS = {
  tools: { exec: { mode: "full" } },
  channels: {
    discord: { accounts: { "sgt-johnson": { token: "x" } } },
    telegram: { accounts: { "drill-bot": { botToken: "x" } } },
  },
};

test("a send naming only a Discord account carries the grant, and the scan is told the account's platform", async () => {
  hostConfig = ACCOUNTS;
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  for (const target of [`channel:${CHANNEL}`, CHANNEL]) {
    scans = [];
    const [grants] = await cronRun([send("c1", target, null)]);
    assert.deepEqual(grants, [EXPECTED], target);
    assert.equal(scans[0].pending_call.send_platform, "discord");
  }
});

test("a send naming no platform and no account is on the session's own chat platform", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const { accountId: _drop, ...noAccount } = send("c1", `channel:${CHANNEL}`, null).params;
  const [grants] = await cronRun([{ ...send("c1", "", null), params: noAccount }]);
  assert.deepEqual(grants, [EXPECTED]);
  assert.equal(scans[0].pending_call.send_platform, "discord");
});

test("a send naming only its account: no grant to a person, another channel, or on another platform's account", async () => {
  hostConfig = ACCOUNTS;
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  for (const target of [`user:${CHANNEL}`, `dm:${CHANNEL}`, "channel:1519377377082216449"]) {
    scans = [];
    assert.deepEqual((await cronRun([send("c1", target, null)]))[0], [], target);
  }
  scans = [];
  const telegram = send("c1", `channel:${CHANNEL}`, null);
  telegram.params.accountId = "drill-bot";
  assert.deepEqual((await cronRun([telegram]))[0], []);
  assert.equal(scans[0].pending_call.send_platform, "telegram");
});

test("an account the config does not place gives no platform, whatever the session's channel", async () => {
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const [grants] = await cronRun([send("c1", `channel:${CHANNEL}`, null)]);
  assert.deepEqual(grants, []);
  assert.equal(scans[0].pending_call.send_platform, undefined);
});

test("a send that names its platform itself is not told one", async () => {
  hostConfig = ACCOUNTS;
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  await cronRun([send("c1", `channel:${CHANNEL}`)]);
  assert.equal(scans[0].pending_call.send_platform, undefined);
});

test("the binding setup proposes for a job's delivery is sent with the job's own sends", async () => {
  hostConfig = ACCOUNTS;
  storeJob({ delivery: DELIVERY }, LONG_AGO);
  const [[, pattern]] = setup.cronTargets(dir);
  const params = send("c1", `channel:${CHANNEL}`, null).params;
  const platform = callPlatform(params, "message_send", sendPlatformOf(params, "message_send", ACCOUNTS, "discord"));
  assert.equal(relevantGrants([{ kind: "destination", pattern: pattern! }], JSON.stringify(params), { platform }).length, 1);
});

test("the platform of a send that names none", () => {
  const params = (accountId?: string) => ({ action: "send", target: `channel:${CHANNEL}`, ...(accountId ? { accountId } : {}) });
  const both = { channels: { discord: { accounts: { ops: {} } }, slack: { accounts: { OPS: {} } } } };
  for (const [args, config, session, want] of [
    [params("Sgt-Johnson"), ACCOUNTS, null, "discord"], // account ids compare without case
    [params("drill-bot"), ACCOUNTS, "discord", "telegram"], // the account wins over the session
    [params("nobody"), ACCOUNTS, "discord", null], // an account the config does not place
    [params("ops"), both, "discord", null], // an account on two platforms
    [params("default"), {}, "Discord", "discord"], // OpenClaw's implicit account: the session's platform
    [params(), ACCOUNTS, "slack", "slack"],
    [params(), ACCOUNTS, "webchat", null], // not a chat platform
    [{ ...params("sgt-johnson"), channel: "slack" }, ACCOUNTS, null, null], // names its own
  ] as const) {
    assert.equal(sendPlatformOf(args, "message_send", config, session), want, JSON.stringify([args, session]));
  }
  assert.equal(sendPlatformOf(params("sgt-johnson"), "web_fetch", ACCOUNTS, "discord"), null);
});

// ---- pieces ------------------------------------------------------------------------------------------

test("an unreadable store reads as no job", () => {
  mkdirSync(path.join(dir, "state"), { recursive: true });
  writeFileSync(path.join(dir, "state", "openclaw.sqlite"), "not a database");
  assert.equal(readCronJob(dir, JOB), null);
});
