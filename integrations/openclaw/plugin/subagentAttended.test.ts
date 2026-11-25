/**
 * A subagent of the owner's attended chat asks its reviews in that chat.
 *
 * OpenClaw starts a subagent's run (`agent:<id>:subagent:<uuid>`) with trigger `user` on the parent chat's route, and
 * sends a plugin's prompt from the child there. Such a run is sent as trigger `subagent`, and it is attended exactly
 * when its parent session is the owner's own message in a chat they attend (or a subagent that asks in its own
 * parent's chat): a review there is a prompt the owner answers in that chat. When the prompt times out, or OpenClaw
 * cancels it (no approval route), the call is held for the owner, bound to the parent session. A subagent of a cron
 * job, a heartbeat, a webhook, another unattended subagent, a shared room or someone else's chat is unattended.
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
const NAMED = {
  risk: 47,
  enforced: null,
  owner_pass: "once",
  approval_fingerprint: "afp1:message_send|ch:discord:#ops-reports",
  reasons: [{ code: "send.unbound_channel", subject: "E1" }],
};
const QUIET = { risk: 5, enforced: null, owner_pass: null, reasons: [] };
const HELD = { block: true, blockReason: FIXTURES.held_text };
const OWNER = "100200300";
const DM_KEY = `agent:main:telegram:direct:${OWNER}`;

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_DEV_ENDPOINTS", "SENTROOK_SCAN_URL", "SENTROOK_OIDC_ISSUER", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE"];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let stateDir = "";
let reply: Record<string, unknown> = {};
let scans: any[] = [];

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-subagent-"));
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
  reply = { ...NAMED };
  scans = [];
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      scans.push(planir);
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
  senderId: OWNER,
  channel: "telegram",
  accountId: "default",
  senderIsOwner: true,
  assertOwnerCurrent: () => undefined,
  sessionKey: DM_KEY,
  sessionId: "D1",
};

interface Parent {
  key: string;
  trigger: string;
  requester?: Record<string, unknown>;
  jobId?: string;
}

/** The owner's direct message on Telegram. */
const OWNER_DM: Parent = { key: DM_KEY, trigger: "user", requester: { senderIsOwner: true, channel: "telegram", senderId: OWNER } };

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
  let n = 0;
  /** One call from a run with agent-hook context `ctx` (its own runId) and tool-hook context `toolCtx`. */
  const call = async (ctx: Record<string, any>, toolName: string, params: Record<string, unknown>) => {
    n += 1;
    await fire("before_prompt_build", { runId: ctx.runId, prompt: ctx.trigger === "cron" ? "[cron:abc research] run" : "research the vendors" }, ctx);
    const out = await fire(
      "before_tool_call",
      { toolName, toolCallId: `c${n}`, runId: ctx.runId, params },
      { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId, agentId: "main", runId: ctx.runId, requester: ctx.requester },
    );
    await hold.waitForNotices();
    return { out, rec: records("scan").at(-1) };
  };
  /** The parent session spawns subagent `child`: its own `sessions_spawn` call, scanned quietly, then the spawn hook. */
  const spawn = async (parent: Parent, child: string) => {
    const kept = reply;
    reply = { ...QUIET };
    const { out } = await call(
      { sessionKey: parent.key, sessionId: `s-${parent.key}`, runId: `r-${parent.key}-${n}`, trigger: parent.trigger, jobId: parent.jobId, channel: "telegram", requester: parent.requester },
      "sessions_spawn",
      { task: "Compare the vendors' docs." },
    );
    reply = kept;
    assert.equal(out, undefined);
    await fire("subagent_spawned", { childSessionKey: child, runId: `r-${child}` }, { childSessionKey: child, requesterSessionKey: parent.key });
  };
  /** A review-band send from subagent session `child`: started with trigger `user`, no provenance, as OpenClaw does. */
  const childSend = (child: string, run = 1) =>
    call(
      { sessionKey: child, sessionId: `s-${child}`, runId: `r-${child}-${run}`, trigger: "user", channel: "telegram" },
      "message",
      { action: "send", channel: "discord", target: "#ops-reports", message: `Vendor summary ${run}` },
    );
  const command = async (name: string, args: string) => (await commands[name].handler({ ...DM, args })).text as string;
  return { fire, sent, records, spawn, childSend, command };
}

const holds = () => {
  const file = path.join(stateDir, "holds.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")).holds : [];
};

async function withNotify() {
  const r = registered();
  await r.command("sentrook-notify", "here");
  return r;
}

const CHILD = "agent:main:subagent:5b1e-1";

// ---- must ask (a prompt in the parent chat) --------------------------------------------------------------------

test("a subagent of the owner's direct chat asks there, as trigger subagent, and approving runs the call", async () => {
  const r = await withNotify();
  await r.spawn(OWNER_DM, CHILD);
  const { out, rec } = await r.childSend(CHILD);
  assert.ok(out.requireApproval, "a prompt, not a hold");
  assert.equal(rec.decision, "review_timed_out", "provisional until the owner answers");
  assert.equal(rec.parent_chat, true);
  assert.equal(scans.at(-1).trigger.kind, "subagent");
  assert.equal(scans.at(-1).session.agent_role, "subagent");
  assert.deepEqual(holds(), []);
  await out.requireApproval.onResolution("allow-once");
  const res = r.records("resolution").at(-1);
  assert.deepEqual([res.resolution, res.decision], ["allow-once", "approved_by_user"]);
  assert.equal(res.hold, undefined);
});

test("a strong signal with no owner pass is still a prompt with its reasons", async () => {
  reply = { ...NAMED, owner_pass: null, reasons: [...NAMED.reasons, { code: "origin.untrusted_destination" }] };
  const r = await withNotify();
  await r.spawn(OWNER_DM, CHILD);
  const { out, rec } = await r.childSend(CHILD);
  assert.ok(out.requireApproval);
  assert.ok(out.requireApproval.description, "the full card");
  assert.equal(rec.hold, undefined);
});

test("a subagent of an asking subagent asks in the same chat", async () => {
  const r = await withNotify();
  await r.spawn(OWNER_DM, CHILD);
  await r.spawn({ key: CHILD, trigger: "user" }, "agent:main:subagent:5b1e-2");
  const { out, rec } = await r.childSend("agent:main:subagent:5b1e-2");
  assert.ok(out.requireApproval);
  assert.equal(rec.parent_chat, true);
});

test("a denied prompt is the owner's denial, not a hold", async () => {
  const r = await withNotify();
  await r.spawn(OWNER_DM, CHILD);
  const { out } = await r.childSend(CHILD);
  await out.requireApproval.onResolution("deny");
  assert.equal(r.records("resolution").at(-1).decision, "denied_by_user");
  assert.deepEqual(holds(), []);
});

// ---- must fire (held, or blocked) ---------------------------------------------------------------------------

for (const decision of ["timeout", "cancelled"] as const) {
  test(`a prompt that ends ${decision} falls back to a hold bound to the parent session`, async () => {
    const r = await withNotify();
    await r.spawn(OWNER_DM, CHILD);
    const { out } = await r.childSend(CHILD);
    const before = r.sent.length;
    await out.requireApproval.onResolution(decision);
    await hold.waitForNotices();
    const res = r.records("resolution").at(-1);
    assert.equal(res.decision, "held");
    assert.ok(res.hold?.id);
    const [entry] = holds();
    assert.equal(entry.source.kind, "subagent");
    assert.equal(entry.source.ref, passes.sourceRef("subagent", scans.at(-1).session.parent_session_ref));
    assert.equal(r.sent.length, before + 1, "the owner is told, as for any hold");
    // the owner's allow lets the next matching call from a subagent of the same parent through once
    await r.command("sentrook-allow", res.hold.id);
    const next = await r.childSend(CHILD, 2);
    assert.equal(next.out, undefined);
    assert.equal(next.rec.decision, "allowed_by_pass");
  });
}

const UNATTENDED: [string, Parent][] = [
  ["a cron job", { key: "agent:main:cron:job-1", trigger: "cron", jobId: "job-1" }],
  ["a heartbeat", { key: "agent:main:main", trigger: "heartbeat" }],
  ["a webhook or event run", { key: "agent:main:hook:gh-1", trigger: "event" }],
  ["someone else's chat", { key: "agent:main:telegram:direct:555", trigger: "user", requester: { senderIsOwner: false, channel: "telegram", senderId: "555" } }],
  ["a shared room", { key: "agent:main:telegram:group:-100", trigger: "user", requester: { senderIsOwner: true, channel: "telegram", senderId: OWNER } }],
];
for (const [what, parent] of UNATTENDED) {
  test(`a subagent of ${what} is held, bound to the parent session`, async () => {
    const r = await withNotify();
    await r.spawn(parent, CHILD);
    const { out, rec } = await r.childSend(CHILD);
    assert.deepEqual(out, HELD);
    assert.equal(rec.decision, "held");
    assert.equal(rec.parent_chat, undefined);
    assert.equal(scans.at(-1).trigger.kind, "subagent");
    assert.equal(holds()[0].source.kind, "subagent");
  });
}

test("a subagent whose spawn OpenClaw never reported is held", async () => {
  const r = await withNotify();
  const { out } = await r.childSend(CHILD);
  assert.deepEqual(out, HELD);
});

test("a subagent of a held subagent is held", async () => {
  const r = await withNotify();
  await r.spawn({ key: "agent:main:cron:job-1", trigger: "cron", jobId: "job-1" }, CHILD);
  await r.spawn({ key: CHILD, trigger: "user" }, "agent:main:subagent:5b1e-2");
  const { out } = await r.childSend("agent:main:subagent:5b1e-2");
  assert.deepEqual(out, HELD);
});

for (const [what, extra] of [
  ["over the block line", { risk: 95 }],
  ["an enforced block", { risk: 40, enforced: "block" }],
] as const) {
  test(`${what} in a subagent of the owner's chat stays a block`, async () => {
    const r = await withNotify();
    await r.spawn(OWNER_DM, CHILD);
    reply = { ...NAMED, ...extra };
    const { out, rec } = await r.childSend(CHILD);
    assert.equal(out.block, true);
    assert.equal(rec.decision, "blocked");
  });
}
