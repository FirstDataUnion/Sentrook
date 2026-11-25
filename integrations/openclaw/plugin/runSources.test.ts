/**
 * Held calls on unattended runs that are not cron jobs: the answers bind to where the run came from.
 *
 * OpenClaw names a heartbeat's agent (`ctx.agentId`, one heartbeat per agent in its settings) and a subagent's parent
 * session (the spawn hooks' requester session key). On a hold from such a run `/sentrook-allow` is a one-use pass for
 * the next matching call from the same source within 7 days (nothing is started), and `/sentrook-allow <id> always`
 * and `/sentrook-deny` are bound to the same source. A webhook or event run has no source OpenClaw names (no hook or
 * mapping id reaches plugins; job, run and session ids are new per request): it keeps allow alone, bound to the exact
 * call. The texts are shared with the Hermes plugin (`integrations/fixtures/hold/cases.json`, `sources`).
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
import { readTime } from "./store.ts";

const FIXTURES = JSON.parse(readFileSync(fileURLToPath(new URL("../../fixtures/hold/cases.json", import.meta.url)), "utf8"));
const SOURCES = FIXTURES.sources;
const SEND = FIXTURES.notices[0];
const FP = "afp1:message_send|ch:discord:#ops-reports";
const ALWAYS = {
  risk: 47,
  enforced: null,
  owner_pass: "always",
  approval_fingerprint: FP,
  reasons: [{ code: "trigger.scheduled" }, { code: "send.unbound_channel", subject: "E1" }],
};
const NAMED = { ...ALWAYS, owner_pass: "once" };
const HELD = { block: true, blockReason: FIXTURES.held_text };
const DECLINED = { block: true, blockReason: FIXTURES.declined_text };
const DAY = 24 * 3600_000;

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_DEV_ENDPOINTS", "SENTROOK_SCAN_URL", "SENTROOK_OIDC_ISSUER", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE"];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let stateDir = "";
let reply: Record<string, unknown> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-sources-"));
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
  /** One send from a run with `ctx` (its own runId), after the agent hooks OpenClaw fires before it. */
  const send = async (ctx: Record<string, unknown>, id = "c1") => {
    await fire("before_prompt_build", { runId: ctx.runId, prompt: "post the brief" }, ctx);
    const out = await fire(
      "before_tool_call",
      { toolName: "message", toolCallId: id, runId: ctx.runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: "Daily brief" } },
      { sessionKey: ctx.sessionKey, sessionId: ctx.sessionId, agentId: ctx.agentId, runId: ctx.runId },
    );
    await hold.waitForNotices();
    return { out, rec: records("scan").at(-1) };
  };
  /** Heartbeat run `n` of agent `agent`. */
  const beat = (n: number, agent = "main") =>
    send({ sessionKey: `agent:${agent}:main`, sessionId: `beat-${agent}-${n}`, agentId: agent, runId: `r-beat-${agent}-${n}`, trigger: "heartbeat" });
  /** Subagent run `n` spawned from session `parent` (null: a spawn OpenClaw never reported). */
  const sub = async (n: number, parent: string | null = "agent:main:main") => {
    const key = `agent:main:subagent:${parent ?? "none"}-${n}`;
    if (parent) await fire("subagent_spawned", { childSessionKey: key, runId: `r-sub-${n}` }, { childSessionKey: key, requesterSessionKey: parent });
    return send({
      sessionKey: key,
      sessionId: `sub-${parent}-${n}`,
      agentId: "main",
      runId: `r-sub-${parent}-${n}`,
      trigger: "user",
      inputProvenance: { kind: "inter_session", sourceRole: "subagent" },
    });
  };
  /** Webhook run `n`: OpenClaw gives it a new job, run and session key every time. */
  const hook = (n: number) =>
    send({ sessionKey: `agent:main:cron:${n}-uuid:run:s${n}`, sessionId: `hook-${n}`, agentId: "main", runId: `r-hook-${n}`, trigger: "event" });
  const command = async (name: string, args: string) => (await commands[name].handler({ ...DM, args })).text as string;
  return { fire, sent, records, beat, sub, hook, command };
}

const holds = () => JSON.parse(readFileSync(path.join(stateDir, "holds.json"), "utf8")).holds;
const stored = () => {
  const file = path.join(stateDir, "passes.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")).passes : [];
};

async function withNotify() {
  const r = registered();
  await r.command("sentrook-notify", "here");
  return r;
}

// ---- must stay silent -------------------------------------------------------------------------------------

test("allow on a heartbeat hold of agent A: A's next heartbeat makes the same call and it passes once", async () => {
  const r = await withNotify();
  let { out, rec } = await r.beat(1);
  assert.deepEqual(out, HELD);
  assert.deepEqual(rec.hold.offers, ["allow", "deny"], "the scanner offers it once: never always, and nothing is started");
  const [entry] = holds();
  assert.deepEqual(entry.source, passes.sourceOf("heartbeat", "main"));
  assert.equal(entry.source.ref, SOURCES.refs.find((x: any) => x.kind === "heartbeat" && x.value === "main").ref);
  assert.equal(entry.where, `heartbeat run, agent "main", session ${rec.session_ref}`);
  assert.match(r.sent.at(-1).text, /let this call through once more from this agent's heartbeat, within 7 days: \/sentrook-allow h-/);
  const answer = await r.command("sentrook-allow", rec.hold.id);
  const [p] = stored();
  assert.equal(
    answer,
    passes.fill(SOURCES.replies.allow, {
      subject: 'The heartbeat of agent "main"',
      until: passes.show(readTime(p.expires_at)!),
      passes: "/sentrook-passes",
      pass: p.id,
    }),
  );
  assert.deepEqual([p.kind, p.uses, p.source_kind, p.source_ref], ["allow", "once", "heartbeat", entry.source.ref]);
  assert.equal(readTime(p.expires_at)!.getTime() - readTime(p.set_at)!.getTime(), 7 * DAY);
  assert.deepEqual(r.records("run_now"), [], "nothing is started");
  ({ out, rec } = await r.beat(2));
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed_by_pass");
  assert.deepEqual(stored(), [], "used up");
  ({ out } = await r.beat(3));
  assert.deepEqual(out, HELD);
});

test("allow always on a heartbeat hold lets the agent's heartbeat make the call for 30 days", async () => {
  reply = { ...ALWAYS };
  const r = await withNotify();
  const { rec } = await r.beat(1);
  assert.deepEqual(rec.hold.offers, ["allow", "allow always", "deny"]);
  const answer = await r.command("sentrook-allow", `${rec.hold.id} always`);
  assert.ok(answer.startsWith('The heartbeat of agent "main" may make this call until '), answer);
  const [p] = stored();
  assert.equal(readTime(p.expires_at)!.getTime() - readTime(p.set_at)!.getTime(), 30 * DAY);
  for (const n of [2, 3, 4]) assert.equal((await r.beat(n)).out, undefined);
  assert.equal(stored()[0].use_count, 3);
  const listed = await r.command("sentrook-passes", "");
  assert.ok(listed.includes('allowed from the heartbeat of agent "main" until ') && listed.includes("used 3 times"), listed);
});

test("allow on a subagent hold lets the next matching call from a subagent of the same parent through once", async () => {
  const r = await withNotify();
  const { out, rec } = await r.sub(1);
  assert.deepEqual(out, HELD);
  assert.deepEqual(rec.hold.offers, ["allow", "deny"]);
  const [entry] = holds();
  assert.equal(entry.source.kind, "subagent");
  assert.match(entry.source.name, /^h_[0-9a-f]{12}$/, "the parent session's ref, never its key");
  assert.equal(entry.source.ref, passes.sourceRef("subagent", entry.source.name));
  await r.command("sentrook-allow", rec.hold.id);
  assert.equal((await r.sub(2)).out, undefined);
  assert.deepEqual((await r.sub(3)).out, HELD);
});

// ---- must fire ----------------------------------------------------------------------------------------------

test("the same call from agent B's heartbeat is held", async () => {
  const r = await withNotify();
  const { rec } = await r.beat(1, "main");
  await r.command("sentrook-allow", rec.hold.id);
  const { out } = await r.beat(1, "ops");
  assert.deepEqual(out, HELD);
  assert.equal(stored().length, 1, "agent main's pass is still there");
});

test("a subagent of a different parent session is held", async () => {
  const r = await withNotify();
  const { rec } = await r.sub(1, "agent:main:main");
  await r.command("sentrook-allow", rec.hold.id);
  const { out } = await r.sub(1, "agent:main:telegram:direct:42");
  assert.deepEqual(out, HELD);
});

test("deny is bound to the source: the agent's heartbeat is refused with no notice, another agent's is held", async () => {
  const r = await withNotify();
  const { rec } = await r.beat(1, "main");
  const answer = await r.command("sentrook-deny", rec.hold.id);
  assert.ok(answer.startsWith('The heartbeat of agent "main" will not make this call until '), answer);
  const sent = r.sent.length;
  const again = await r.beat(2, "main");
  assert.deepEqual(again.out, DECLINED);
  assert.equal(again.rec.decision, "denied_by_owner");
  assert.equal(r.sent.length, sent, "no notice for a denied call");
  assert.deepEqual((await r.beat(1, "ops")).out, HELD);
  assert.equal(r.sent.length, sent + 1);
  assert.match(await r.command("sentrook-passes", ""), /denied from the heartbeat of agent "main" until /);
});

test("a source that cannot be determined offers no always or deny: a webhook run, a subagent with no reported parent", async () => {
  reply = { ...ALWAYS };
  const r = await withNotify();
  for (const made of [await r.hook(1), await r.sub(1, null)]) {
    assert.deepEqual(made.out, HELD);
    assert.deepEqual(made.rec.hold.offers, ["allow"]);
    assert.match(await r.command("sentrook-deny", made.rec.hold.id), /no cron job or other source/);
    assert.match(await r.command("sentrook-allow", `${made.rec.hold.id} always`), /no cron job or other source/);
  }
  assert.equal(holds()[0].source, null);
});

test("a heartbeat's pass does not cover the same call from a run with no source", async () => {
  const r = await withNotify();
  const { rec } = await r.beat(1);
  await r.command("sentrook-allow", rec.hold.id);
  assert.deepEqual((await r.hook(1)).out, HELD);
});

// ---- must stay the same -------------------------------------------------------------------------------------

test("a repeat of a waiting heartbeat hold counts on it and sends no new notice", async () => {
  const r = await withNotify();
  await r.beat(1);
  await r.beat(2);
  const [entry] = holds();
  assert.equal(entry.count, 2);
  assert.equal(r.sent.length, 1);
});

// ---- the shared texts ---------------------------------------------------------------------------------------

test("source refs: the shared table", () => {
  for (const c of SOURCES.refs) assert.equal(passes.sourceRef(c.kind, c.value), c.ref, `${c.kind}:${c.value}`);
});

test("the passes list names the source", () => {
  for (const want of ["allow", "allow always", "deny"]) {
    const p = {
      id: "p-000000",
      kind: want === "deny" ? "deny" : "allow",
      uses: want === "allow" ? "once" : "standing",
      job_ref: null,
      source_kind: "heartbeat",
      source_ref: passes.sourceRef("heartbeat", "main"),
      source_name: "main",
      tool: "message",
      description: "Sends a message to discord:#ops-reports",
      expires_at: "2026-12-01T10:00:00Z",
      use_count: 2,
    };
    const want_ = passes.fill(SOURCES.passes_list[want], {
      source: 'the heartbeat of agent "main"',
      until: "2026-12-01 10:00 UTC",
      tool: "message",
      description: "Sends a message to discord:#ops-reports",
      used: "2",
    });
    assert.equal(passes.describe(p), want_, want);
  }
});

test("reply subjects: the shared table", () => {
  // the reply to deny names who will not make the call; each source by its kind and name
  for (const c of SOURCES.subjects) {
    const found = { v: 2, job_ref: null, source: { kind: c.kind, ref: "x_1", name: c.name } };
    assert.equal(hold.subjectOf(found), c.subject, c.subject);
  }
});
