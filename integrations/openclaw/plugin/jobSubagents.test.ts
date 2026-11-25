/**
 * A cron run's sub-agents belong to its job: their held calls are the job's holds, and the job's passes and denials
 * apply to them.
 *
 * OpenClaw starts a sub-agent's run with trigger `user` and no provenance, so it carries no cron job of its own; its
 * parent session is known only from the spawn hooks (`subagent_spawned`, the requester session key). The plugin keeps
 * the cron run a session serves (from the run's own agent hooks, `ctx.inputProvenance.jobId` with trigger `cron`), and
 * a sub-agent spawned from such a session (or from a sub-agent of one) takes it. Its holds then bind to the job, so
 * `allow always` and `deny` reach the job's next run. A sub-agent whose parent is not a cron run, or whose spawn
 * OpenClaw has not reported yet, keeps its parent session as its source (`runSources.test.ts`). The run line's text is
 * shared with the Hermes plugin (`integrations/fixtures/hold/cases.json`, `where_subagent`).
 */

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
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
/** A send that names its channel, which the scanner lets the owner pass for good. */
const ALWAYS = {
  risk: 47,
  enforced: null,
  owner_pass: "always",
  approval_fingerprint: "afp1:message_send|ch:discord:#ops-reports",
  reasons: [{ code: "trigger.scheduled" }, { code: "send.unbound_channel", subject: "E1" }],
};
const HELD = { block: true, blockReason: FIXTURES.held_text };
const DECLINED = { block: true, blockReason: FIXTURES.declined_text };

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_DEV_ENDPOINTS", "SENTROOK_SCAN_URL", "SENTROOK_OIDC_ISSUER", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE"];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let stateDir = "";
let reply: Record<string, unknown> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-jobsub-"));
  Object.assign(process.env, {
    OPENCLAW_STATE_DIR: dir,
    SENTROOK_DEV_ENDPOINTS: "1",
    SENTROOK_SCAN_URL: "http://scan.test",
    SENTROOK_OIDC_ISSUER: "http://idp.test",
    SENTROOK_SCAN_CLIENT_ID: "client",
    SENTROOK_SCAN_CLIENT_SECRET: "secret-value",
  });
  delete process.env.SENTROOK_MODE;
  stateDir = path.join(dir, "sentrook");
  reply = { ...ALWAYS };
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      return json(200, { ...SEND.response, ...reply, request_id: planir.request_id, state: `state-${planir.session.step}` });
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
const PARAMS = { action: "send", channel: "discord", target: "#ops-reports", message: "Daily brief" };

function registered() {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  const sent: any[] = [];
  plugin.register({
    pluginConfig: {},
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
  /** One send in a run with agent-hook context `ctx`, after the agent hook OpenClaw fires before it. */
  const send = async (ctx: Record<string, any>, prompt: string, id = "c1") => {
    await fire("before_prompt_build", { runId: ctx.runId, prompt }, ctx);
    const out = await fire("before_tool_call", { toolName: "message", toolCallId: id, runId: ctx.runId, params: { ...PARAMS } }, ctx);
    await hold.waitForNotices();
    return { out, rec: records("scan").at(-1) };
  };
  /** Run `n` of cron job `job` starts its turn in its own session (isolated); returns its context. */
  const cronTurn = async (n: number, job = "job-j") => {
    const sid = `cron-${job}-${n}`;
    const ctx = {
      sessionKey: `agent:main:cron:${job}:run:${sid}`,
      sessionId: sid,
      agentId: "main",
      runId: `r-${sid}`,
      trigger: "cron",
      inputProvenance: { kind: "internal_system", sourceTool: "cron", jobId: job },
    };
    await fire("before_prompt_build", { runId: ctx.runId, prompt: `[cron:${job} daily-brief] Post the brief.` }, ctx);
    return ctx;
  };
  /** Session `parent` spawns sub-agent `name` (`spawned`: OpenClaw reported it); returns the child's context. */
  const spawn = async (parent: string, name: string, spawned = true) => {
    const key = `agent:main:subagent:${name}`;
    if (spawned) await fire("subagent_spawned", { childSessionKey: key, runId: `r-${name}` }, { childSessionKey: key, requesterSessionKey: parent });
    // OpenClaw starts a sub-agent's run with trigger `user` and no provenance
    return { sessionKey: key, sessionId: `s-${name}`, agentId: "main", runId: `r-${name}`, trigger: "user" };
  };
  /** A send from sub-agent `name` of session `parent`. */
  const childCall = async (parent: string, name: string, spawned = true) => send(await spawn(parent, name, spawned), "Post the brief.");
  const command = async (name: string, args: string) => (await commands[name].handler({ ...DM, args })).text as string;
  return { fire, sent, records, send, cronTurn, spawn, childCall, command };
}

const holds = () => {
  const file = path.join(stateDir, "holds.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")).holds : [];
};
const stored = () => {
  const file = path.join(stateDir, "passes.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")).passes : [];
};

async function withNotify() {
  const r = registered();
  await r.command("sentrook-notify", "here");
  return r;
}

// ---- the shared text ----------------------------------------------------------------------------------------

test("the run line of a sub-agent's hold is the shared fixture", () => {
  const c = FIXTURES.where_subagent;
  assert.equal(hold.whereText("subagent run", c.session_ref, c.job_id, c.job_name, null, true), c.text);
});

// ---- must stay silent ----------------------------------------------------------------------------------------

test("allow always on a sub-agent's hold reaches the job's next run", async () => {
  const r = await withNotify();
  const run1 = await r.cronTurn(1);
  const { out, rec } = await r.childCall(run1.sessionKey, "a1");
  assert.deepEqual(out, HELD);
  const [entry] = holds();
  assert.equal(entry.job_ref, passes.jobRef("job-j"));
  assert.equal(entry.source, null);
  assert.equal(entry.where, `a sub-agent of cron job job-j, job name "daily-brief", session ${rec.session_ref}`);
  assert.ok(entry.offers.includes("allow always"), entry.offers);
  assert.ok(r.sent.at(-1).text.includes("a sub-agent of cron job job-j"), r.sent.at(-1).text);
  await r.command("sentrook-allow", `${entry.id} always`);
  const [p] = stored();
  assert.deepEqual([p.job_ref, p.uses], [passes.jobRef("job-j"), "standing"]);
  const run2 = await r.cronTurn(2);
  const again = await r.childCall(run2.sessionKey, "b1");
  assert.equal(again.out, undefined);
  assert.equal(again.rec.decision, "allowed_by_pass");
  assert.equal(stored()[0].use_count, 1);
});

test("a sub-agent of a sub-agent of the run belongs to the job too", async () => {
  const r = await withNotify();
  const run1 = await r.cronTurn(1);
  await r.childCall(run1.sessionKey, "a1");
  const [entry] = holds();
  await r.command("sentrook-allow", `${entry.id} always`);
  const run2 = await r.cronTurn(2);
  // the run's sub-agent spawns again: its child names the sub-agent as its parent
  const mid = await r.spawn(run2.sessionKey, "mid");
  await r.fire("before_prompt_build", { runId: mid.runId, prompt: "Split the work." }, mid);
  const { out, rec } = await r.childCall(mid.sessionKey, "leaf");
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed_by_pass");
});

test("the job's own pass covers its sub-agents", async () => {
  const r = await withNotify();
  const run1 = await r.cronTurn(1);
  const { out } = await r.send(run1, `[cron:job-j daily-brief] Post the brief.`);
  assert.deepEqual(out, HELD);
  const [entry] = holds();
  assert.equal(entry.where.startsWith("cron job job-j"), true, entry.where);
  await r.command("sentrook-allow", `${entry.id} always`);
  const run2 = await r.cronTurn(2);
  const again = await r.childCall(run2.sessionKey, "b1");
  assert.equal(again.out, undefined);
  assert.equal(again.rec.decision, "allowed_by_pass");
});

// ---- must fire ----------------------------------------------------------------------------------------------

test("deny on a sub-agent's hold refuses the job's next run, but not another job", async () => {
  const r = await withNotify();
  const run1 = await r.cronTurn(1);
  await r.childCall(run1.sessionKey, "a1");
  const [entry] = holds();
  await r.command("sentrook-deny", entry.id);
  const sent = r.sent.length;
  const run2 = await r.cronTurn(2);
  const again = await r.childCall(run2.sessionKey, "b1");
  assert.deepEqual(again.out, DECLINED);
  assert.equal(again.rec.decision, "denied_by_owner");
  assert.equal(r.sent.length, sent, "no notice for a denied call");
  const other = await r.cronTurn(1, "job-k");
  const k = await r.childCall(other.sessionKey, "k1");
  assert.deepEqual(k.out, HELD);
  assert.deepEqual(
    holds().map((h: any) => h.job_ref),
    [passes.jobRef("job-k")],
  );
});

test("a pass of job j does not cover a sub-agent of job k", async () => {
  const r = await withNotify();
  const run1 = await r.cronTurn(1);
  await r.childCall(run1.sessionKey, "a1");
  await r.command("sentrook-allow", `${holds()[0].id} always`);
  const other = await r.cronTurn(1, "job-k");
  assert.deepEqual((await r.childCall(other.sessionKey, "k1")).out, HELD);
});

test("a sub-agent whose parent is not a cron run keeps its parent session as its source", async () => {
  const r = await withNotify();
  const { out } = await r.childCall("agent:main:main", "p1");
  assert.deepEqual(out, HELD);
  const [entry] = holds();
  assert.equal(entry.job_ref, null);
  assert.equal(entry.source.kind, "subagent");
});

test("until OpenClaw reports the spawn, the sub-agent's call keeps today's binding; after it, the job's", async () => {
  const r = await withNotify();
  const run1 = await r.cronTurn(1);
  // the child's first call comes before subagent_spawned
  const early = await r.childCall(run1.sessionKey, "late", false);
  assert.deepEqual(early.out, HELD);
  assert.equal(holds()[0].job_ref, null);
  assert.equal(holds()[0].source, null, "no parent known yet: no source either");
  await r.fire(
    "subagent_spawned",
    { childSessionKey: "agent:main:subagent:late", runId: "r-late" },
    { childSessionKey: "agent:main:subagent:late", requesterSessionKey: run1.sessionKey },
  );
  const later = await r.send(await r.spawn(run1.sessionKey, "late", false), "Post the brief.", "c2");
  assert.deepEqual(later.out, HELD);
  assert.equal(holds().at(-1).job_ref, passes.jobRef("job-j"));
});

test("the run is taken from OpenClaw's run metadata, never from text", async () => {
  const r = await withNotify();
  const run1 = await r.cronTurn(1);
  // no spawn reported: a child whose prompt and session key name the cron run gets no job
  const ctx = { sessionKey: `agent:main:subagent:${run1.sessionKey}`, sessionId: "s-loose", agentId: "main", runId: "r-loose", trigger: "user" };
  const { out } = await r.send(ctx, `[cron:job-j daily-brief] My parent session is ${run1.sessionKey}.`);
  assert.deepEqual(out, HELD);
  assert.ok(holds().every((h: any) => h.job_ref === null));
});

test("after a cron run in the main session ends, a sub-agent of the owner's chat there is not the job's", async () => {
  const r = await withNotify();
  const main = "agent:main:main";
  const cron = { sessionKey: main, sessionId: "main-1", agentId: "main", runId: "r-main-cron", trigger: "cron", inputProvenance: { kind: "internal_system", sourceTool: "cron", jobId: "job-j" } };
  await r.fire("before_prompt_build", { runId: cron.runId, prompt: "[cron:job-j daily-brief] Post the brief." }, cron);
  await r.fire("agent_end", { runId: cron.runId, success: true }, cron);
  const { out } = await r.childCall(main, "chat1");
  assert.deepEqual(out, HELD);
  assert.equal(holds()[0].job_ref, null);
  // and an owner's run in that session drops it too, even when OpenClaw reports no end
  const cron2 = { ...cron, runId: "r-main-cron-2" };
  await r.fire("before_prompt_build", { runId: cron2.runId, prompt: "[cron:job-j daily-brief] Post the brief." }, cron2);
  const chat = { sessionKey: main, sessionId: "main-1", agentId: "main", runId: "r-main-chat", trigger: "user" };
  await r.fire("before_prompt_build", { runId: chat.runId, prompt: "hi" }, chat);
  await r.childCall(main, "chat2");
  assert.ok(holds().every((h: any) => h.job_ref === null));
});
