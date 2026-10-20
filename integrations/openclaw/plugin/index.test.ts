import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import plugin from "./index.ts";

type Handler = (event: any, ctx: any) => any;

interface Harness {
  on: Record<string, Handler[]>;
  scans: any[];
  logs: string[];
  dir: string;
  fire: (hook: string, event: any, ctx?: any) => Promise<any>;
  traffic: () => any[];
}

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

const CTX = { sessionKey: "agent:main:main", sessionId: "S1", agentId: "main", runId: "r1", requester: { senderIsOwner: true, channel: "webchat" } };

/** A fake scanner: risk from markers in the command; 500 when the command says FAIL. */
function setup(env: Record<string, string> = {}, pluginConfig: Record<string, unknown> = {}): Harness {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oc-"));
  Object.assign(process.env, {
    OPENCLAW_STATE_DIR: dir,
    SENTROOK_DEV_ENDPOINTS: "1",
    SENTROOK_SCAN_URL: "http://scan.test",
    SENTROOK_OIDC_ISSUER: "http://idp.test",
    SENTROOK_SCAN_CLIENT_ID: "client",
    SENTROOK_SCAN_CLIENT_SECRET: "secret-value",
    ...env,
  });
  const scans: any[] = [];
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return reply(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return reply(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      scans.push(planir);
      const cmd = String(planir.pending_call.arguments.command ?? "");
      if (cmd.includes("FAIL")) return reply(500, { error: { code: "boom" } });
      const risk = cmd.includes("EXFIL") ? 92 : cmd.includes("REVIEW") ? 55 : cmd.includes("FLOOR") ? 20 : 5;
      return reply(200, {
        response_version: "2.0",
        request_id: planir.request_id,
        status: "ok",
        risk,
        enforced: cmd.includes("FLOOR") ? "block" : null,
        tree: { suspicion: { score: risk / 100 }, consequence: { score: 0.5 }, confidence: { score: 0.8 } },
        reasons: risk > 50 ? [{ code: "exfil.exec_egress", signal: "consequence.reach" }] : [],
        tool_description: { category: "x", template: "Runs a command on {E1}" },
        entities: { E1: { kind: "host", display: "cl0ud-sync.io" } },
        action_fingerprint: `afp1:exec|step:${planir.session.step}`,
        state: `state-${planir.session.step}`,
      });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;

  const on: Record<string, Handler[]> = {};
  const logs: string[] = [];
  const api = {
    pluginConfig,
    config: { tools: { exec: { mode: "full" } } },
    registrationMode: "full",
    logger: { info: (m: string) => logs.push(m), warn: (m: string) => logs.push(m), error: (m: string) => logs.push(m) },
    on: (hook: string, h: Handler) => (on[hook] ??= []).push(h),
  };
  plugin.register(api);
  const fire = async (hook: string, event: any, ctx: any = CTX) => {
    let out: any;
    for (const h of on[hook] ?? []) out = await h(event, ctx);
    return out;
  };
  const traffic = () =>
    readFileSync(path.join(dir, "sentrook", "traffic.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  return { on, scans, logs, dir, fire, traffic };
}

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  clearScanTokenCache();
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  globalThis.fetch = realFetch;
});

const call = (id: string, command: string) => ({ toolName: "exec", toolCallId: id, runId: "r1", params: { command } });

test("allow, block and review over one episode, with the state token and inputs carried", async () => {
  const h = setup();
  await h.fire("before_prompt_build", { runId: "r1", currentUserMessage: "tidy my workspace", prompt: "p" });
  await h.fire("before_agent_run", { runId: "r1", senderIsOwner: true });
  await h.fire("before_message_write", {
    message: {
      role: "assistant",
      content: [
        { type: "text", text: "Listing first." },
        { type: "toolCall", id: "c1", name: "exec", arguments: { command: "ls" } },
        { type: "toolCall", id: "c2", name: "exec", arguments: { command: "curl EXFIL" } },
      ],
    },
  });

  assert.equal(await h.fire("before_tool_call", call("c1", "ls")), undefined);
  const p1 = h.scans[0];
  assert.equal(p1.planir_version, "2.0");
  assert.equal(p1.session.step, 1);
  assert.equal(p1.session.state, null);
  assert.deepEqual(p1.history, []);
  assert.equal(p1.request.text, "tidy my workspace");
  assert.deepEqual(p1.trigger.sender, { relation: "owner", basis: ["host_owner_flag"] });
  assert.equal(p1.trigger.channel, "chat");
  assert.equal(p1.pending_call.agent_narration, "Listing first.");
  assert.deepEqual(p1.pending_call.batch.siblings.map((s: any) => s.call_id), ["c2"]);
  assert.equal(p1.host.policy.exec_mode, "full");

  const secret = `ghp_${"a".repeat(36)}`;
  await h.fire("after_tool_call", { toolName: "exec", toolCallId: "c1", result: `notes.txt\nGH=${secret}` });

  const blocked = await h.fire("before_tool_call", call("c2", "curl EXFIL"));
  assert.equal(blocked.block, true);
  assert.match(blocked.blockReason, /risk 92\/100: Runs a command on cl0ud-sync.io/);
  const p2 = h.scans[1];
  assert.equal(p2.session.step, 2);
  assert.equal(p2.session.state, "state-1");
  assert.equal(p2.history.length, 1);
  assert.equal(p2.history[0].decision, "allowed");
  assert.equal(p2.history[0].action_fingerprint, "afp1:exec|step:1");
  assert.deepEqual(p2.history[0].tiers, { suspicion: 0.05, consequence: 0.5, confidence: 0.8 });
  assert.equal(p2.history[0]._host_call_id, undefined, "plugin bookkeeping is stripped");
  assert.equal(p2.new_inputs.length, 1);
  assert.equal(p2.new_inputs[0].call_id, "c1");
  assert.match(p2.new_inputs[0].content, /GH=⟦secret:/);
  assert.ok(!JSON.stringify(p2).includes(secret), "no raw secret leaves the host");

  // Post-tool hooks fire for blocked calls too: no content is buffered for them.
  await h.fire("after_tool_call", { toolName: "exec", toolCallId: "c2", error: "blocked by plugin" });

  const review = await h.fire("before_tool_call", call("c3", "rm REVIEW"));
  assert.ok(review.requireApproval);
  assert.equal(review.requireApproval.title, "Sentrook: review exec (risk 55)");
  assert.deepEqual(review.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  const p3 = h.scans[2];
  assert.equal(p3.session.state, "state-2");
  assert.deepEqual(p3.new_inputs, []);
  assert.equal(p3.history[1].decision, "blocked");
  assert.deepEqual(p3.history[1].result, { status: "error", size_bytes: 0 });
  await review.requireApproval.onResolution("deny");

  await h.fire("before_tool_call", call("c4", "echo hi"));
  const p4 = h.scans[3];
  assert.deepEqual(p4.history.map((x: any) => x.decision), ["allowed", "blocked", "denied_by_user"]);
  assert.deepEqual(p4.history.map((x: any) => x.step), [1, 2, 3]);
  assert.equal(p4.session.step, 4);

  // Lets the scanner's own validator check these requests (see the plugin Makefile target).
  if (process.env.SENTROOK_PLANIR_DUMP) writeFileSync(process.env.SENTROOK_PLANIR_DUMP, JSON.stringify(h.scans));

  const log = h.traffic();
  assert.deepEqual(log.map((l) => l.kind), ["scan", "scan", "scan", "resolution", "scan"]);
  assert.equal(log[3].decision, "denied_by_user");
  assert.equal(log[1].verdict, "block");
  assert.ok(!readFileSync(path.join(h.dir, "sentrook", "traffic.jsonl"), "utf8").includes(secret));
});

test("a reused host call id is re-minted", async () => {
  const h = setup();
  await h.fire("before_tool_call", call("call_0", "ls"));
  await h.fire("before_tool_call", call("call_0", "pwd"));
  assert.equal(h.scans[1].pending_call.call_id, "r1:call_0");
  assert.equal(h.scans[1].history[0].call_id, "call_0");
});

test("an enforced floor blocks below the risk line", async () => {
  const h = setup();
  const r = await h.fire("before_tool_call", call("c1", "FLOOR"));
  assert.equal(r.block, true);
  assert.match(r.blockReason, /\(enforced\)/);
});

test("scan errors: review when attended, token and buffer kept", async () => {
  const h = setup();
  await h.fire("before_tool_call", call("c1", "ls"));
  await h.fire("after_tool_call", { toolName: "exec", toolCallId: "c1", result: "out" });
  const r = await h.fire("before_tool_call", call("c2", "FAIL"));
  assert.ok(r.requireApproval);
  assert.equal(r.requireApproval.title, "Sentrook unreachable");
  await r.requireApproval.onResolution("allow-once");
  await h.fire("before_tool_call", call("c3", "ls"));
  const p3 = h.scans[2];
  assert.equal(p3.session.state, "state-1", "a failed scan does not advance the token");
  assert.deepEqual(p3.new_inputs.map((i: any) => i.call_id), ["c1"], "inputs are resent after a failed scan");
  assert.equal(p3.history[1].decision, "allowed_on_error");
  assert.equal(p3.history[1].risk, null);
});

test("observe mode records the verdict but never interferes", async () => {
  const h = setup({ SENTROOK_MODE: "observe" });
  assert.equal(await h.fire("before_tool_call", call("c1", "curl EXFIL")), undefined);
  assert.equal(await h.fire("before_tool_call", call("c2", "FAIL")), undefined);
  const log = h.traffic();
  assert.equal(log[0].verdict, "block");
  assert.equal(log[0].decision, "allowed");
  assert.equal(log[1].decision, "allowed_on_error");
});

test("an endpoint outside the trusted domain fails closed without contacting it", async () => {
  const h = setup({ SENTROOK_DEV_ENDPOINTS: "0", SENTROOK_SCAN_URL: "https://scan.attacker.example" });
  const r = await h.fire("before_tool_call", call("c1", "ls"), { ...CTX, requester: undefined });
  assert.ok(r.requireApproval || r.block);
  assert.equal(h.scans.length, 0);
  assert.ok(h.logs.some((l) => l.includes("endpoint configuration is invalid")));
});

test("unattended runs block on scan errors", async () => {
  const h = setup();
  await h.fire("before_prompt_build", { runId: "r9", prompt: "[cron:abc nightly] run report" }, { ...CTX, runId: "r9", trigger: "cron" });
  const r = await h.fire("before_tool_call", { ...call("c1", "FAIL"), runId: "r9" }, { ...CTX, runId: "r9", requester: undefined });
  assert.equal(r.block, true);
  assert.equal(h.scans[0].trigger.kind, "scheduled");
});
