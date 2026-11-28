/**
 * "Always allow" on a review of an MCP tool call: later calls of that tool on that server are not asked again.
 *
 * With no suggested grant the card offered only "Allow once", so every call of an MCP write tool (another page, other
 * text) asked again. On the owner's own message, a review of an MCP tool call now offers "Always allow", and the
 * answer is kept as a standing allowance for that tool on that server (its identity), with the Hermes plugin's
 * Session-coverage limits: at most 10 points above the answered risk, below the block line, no new warning, no
 * floor, nothing enforced, a complete scan. The page a call writes is not part of the key; a host it sends to is. It
 * lasts 30 days, is listed with the grants and revoked like one. The key and the match are shared with the Hermes
 * plugin (`integrations/fixtures/always-allow`).
 */

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import * as alwaysAllow from "./alwaysAllow.ts";
import { clearScanTokenCache } from "./auth.ts";
import { ALWAYS_LINE } from "./card.ts";
import plugin from "./index.ts";

const CASES = JSON.parse(
  readFileSync(path.join(import.meta.dirname, "..", "..", "fixtures", "always-allow", "cases.json"), "utf8"),
);
const WIKI = { url: "https://wiki.example-team.test/mcp" };
const OTHER = { url: "https://wiki.example-other.test/mcp" };
const HINT = {
  kind: "provider",
  pattern: "remote:wiki.example-team.test",
  risk: 30.2,
  subject: "E1",
  relieves: ["reputation.unknown_mcp_server_as_tool_provider"],
  scope: "persistent",
  expires_in_days: 30,
};
const DAY = 24 * 3600_000;

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
let stateDir = "";
let scans: any[] = [];
/** What the scanner answers next: `risk`, `page`, `host`, `extra` codes, `floors`, `enforced`, `status`, `hints`. */
let next: Record<string, any> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-always-"));
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
  scans = [];
  next = {};
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
      const prov = planir.pending_call.provider;
      const entities: Record<string, any> = { E1: { kind: "mcp_server", display: String(prov.name) } };
      let template = "Writes a page through {E1}";
      const reasons: any[] = ["jev.irreversibility", "jev.reach", "jev.sensitivity"].map((code) => ({ code, subject: null, text: "it cannot be undone" }));
      if (next.page) {
        entities.E2 = { kind: "path", display: next.page };
        template = "Writes {E2} through {E1}";
        reasons.push({ code: "origin.agent_generated", subject: "E2", text: null });
      }
      if (next.host) {
        entities.E3 = { kind: "host", display: next.host };
        template += " and sends it to {E3}";
        reasons.push({ code: "send.off_host", subject: "E3", text: null });
      }
      for (const code of next.extra ?? []) reasons.push({ code, subject: null, text: null });
      return json(200, {
        response_version: "2.0",
        request_id: planir.request_id,
        status: next.status ?? "ok",
        risk: next.risk ?? 50,
        enforced: next.enforced ?? null,
        floors_applied: next.floors ?? [],
        tree: { suspicion: { score: 0.2 }, consequence: { score: 0.8 } },
        reasons,
        tool_description: { template },
        entities,
        grant_hints: next.hints ?? [],
        approval_fingerprint: `afp1:mcp|prov:${prov.identity}`,
        action_fingerprint: `afp1:mcp|step:${planir.session.step}`,
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

/** The owner, in a direct message to the agent on Telegram (an invented chat). */
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
  const servers: Record<string, any> = { wiki: { ...WIKI }, notes: { ...OTHER } };
  plugin.register({
    pluginConfig: {},
    registrationMode: "full",
    config: { tools: { exec: { mode: "full" } }, mcp: { servers } },
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
    runtime: { channel: { outbound: { loadAdapter: async () => ({ sendText: async () => ({ ok: true }) }) } } },
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
  let turn = 0;
  /** One call of `tool` from the owner's message in session `sid` (`sessionKey` sets the chat). */
  const call = async (id: string, o: { tool?: string; sid?: string; sessionKey?: string } = {}) => {
    const sid = o.sid ?? "S1";
    const runId = `r${++turn}`;
    const ctx = {
      sessionKey: o.sessionKey ?? "agent:main:main",
      sessionId: sid,
      agentId: "main",
      runId,
      requester: { senderIsOwner: true, channel: "telegram" },
      trigger: "user",
    };
    await fire("before_prompt_build", { runId, currentUserMessage: "update the onboarding pages on the wiki", prompt: "p" }, ctx);
    await fire("before_agent_run", { runId, senderIsOwner: true }, ctx);
    return fire(
      "before_tool_call",
      { toolName: o.tool ?? "wiki__update_page", toolCallId: id, runId, params: { title: `Onboarding/${id}`, text: `Revised ${id}.` } },
      ctx,
    );
  };
  const command = async (name: string, args: string) => (await commands[name].handler({ ...DM, args })).text as string;
  return { call, records, command, servers };
}

const kept = (): any[] => alwaysAllow.load(stateDir)?.allows ?? [];
const asked = (out: any) => !!out?.requireApproval;

/** A review answered `choice`, then the next call with `then` as the scanner's answer. */
async function alwaysThen(first: Record<string, any> = {}, then: Record<string, any> = {}, o: { tool?: string; sid?: string } = {}, choice = "allow-always") {
  const r = registered();
  next = first;
  const out = await r.call("c1");
  assert.ok(asked(out));
  await out.requireApproval.onResolution(choice);
  next = then;
  return { r, out: await r.call("c2", o) };
}

// ---- shared cases -------------------------------------------------------------------------------------

for (const c of CASES.keys) {
  test(`shared key: ${c.name}`, () => {
    assert.equal(alwaysAllow.keyOf(c.tool, c.provider, c.response, CASES.secret), c.match);
  });
}

for (const c of CASES.covering) {
  test(`shared covering: ${c.name}`, () => {
    const now = new Date("2026-11-28T12:00:00Z");
    const data = { allows: [{ id: "aa-000001", key: "k", answers: [{ ...c.answer, request_id: "r1", at: "2026-11-28T11:00:00Z" }] }] };
    assert.equal(alwaysAllow.covering(data, "k", c.response, now, CASES.block_at) !== null, c.covered);
  });
}

// ---- must stay silent ---------------------------------------------------------------------------------

test("after allow always, the same tool on the same server with other arguments is not asked", async () => {
  const { r, out } = await alwaysThen({}, { risk: 49 });
  assert.equal(out, undefined);
  const [first, second] = r.records("scan");
  assert.equal(second.verdict, "review");
  assert.equal(second.decision, "allowed");
  const [entry] = kept();
  assert.deepEqual(second.always_allowed, { by: first.request_id, id: entry.id });
  const [res] = r.records("resolution");
  assert.equal(res.always_allow, entry.id);
  assert.equal(entry.tool, "wiki__update_page");
  assert.equal(entry.identity, "remote:wiki.example-team.test");
});

test("the review card offers allow always and says what it covers", async () => {
  const r = registered();
  const out = await r.call("c1");
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "allow-always", "deny"]);
  assert.ok(out.requireApproval.description.split("\n").includes(ALWAYS_LINE), out.requireApproval.description);
});

test("it lasts into another session", async () => {
  const { r } = await alwaysThen();
  assert.equal(await r.call("c9", { sid: "S2" }), undefined);
});

test("a call writing another page is not asked", async () => {
  const { out } = await alwaysThen({ page: "Onboarding/Laptops" }, { page: "Onboarding/Accounts" });
  assert.equal(out, undefined);
});

for (const risk of [55, 60]) {
  test(`a call ${risk - 50} points higher is not asked`, async () => {
    assert.equal((await alwaysThen({}, { risk })).out, undefined);
  });
}

test("a rising consequence trend alone does not ask", async () => {
  assert.equal((await alwaysThen({}, { extra: ["escalation.consequence_rising"] })).out, undefined);
});

// ---- must still fire ----------------------------------------------------------------------------------

test("the same tool on a server with another identity asks", async () => {
  const r = registered();
  next = {};
  const out = await r.call("c1");
  await out.requireApproval.onResolution("allow-always");
  r.servers.wiki = { ...OTHER };
  assert.ok(asked(await r.call("c2")));
});

test("a tool of the same name on another server asks", async () => {
  assert.ok(asked((await alwaysThen({}, {}, { tool: "notes__update_page" })).out));
});

test("another tool on the same server asks", async () => {
  assert.ok(asked((await alwaysThen({}, {}, { tool: "wiki__create_page" })).out));
});

const fires: [string, Record<string, any>][] = [
  ["a call that also sends to a host", { host: "paste.example-drop.test" }],
  ["more than 10 points higher", { risk: 60.5 }],
  ["a new warning", { extra: ["exposure.task_change"] }],
  ["a floor", { floors: [{ floor: "sensitive_data_sent" }] }],
  ["an enforced review", { risk: 30, enforced: "review" }],
  ["a degraded scan", { status: "degraded" }],
];
for (const [name, then] of fires) {
  test(`${name} asks`, async () => {
    assert.ok(asked((await alwaysThen({}, then)).out));
  });
}

test("a block score is blocked", async () => {
  const { out } = await alwaysThen({ risk: 75 }, { risk: 82 });
  assert.equal(out?.block, true);
});

test("after 30 days it asks again", async () => {
  const { r } = await alwaysThen();
  const file = path.join(stateDir, alwaysAllow.FILE);
  const data = JSON.parse(readFileSync(file, "utf8"));
  const old = new Date(Date.now() - 31 * DAY).toISOString();
  for (const e of data.allows) for (const a of e.answers) a.at = old;
  writeFileSync(file, JSON.stringify(data));
  assert.ok(asked(await r.call("c3")));
});

test("listed with the grants, and revoked it asks again", async () => {
  const { r } = await alwaysThen();
  const [entry] = kept();
  const listing = await r.command("sentrook-grants", "");
  assert.ok(listing.includes(entry.id) && listing.includes("wiki__update_page") && listing.includes("remote:wiki.example-team.test"), listing);
  assert.equal(await r.command("sentrook-revoke", entry.id), `Revoked ${entry.id}: Always for wiki__update_page on wiki.`);
  assert.deepEqual(kept(), []);
  assert.ok(asked(await r.call("c3")));
});

// ---- when nothing is kept -----------------------------------------------------------------------------

for (const choice of ["allow-once", "deny", "timeout"]) {
  test(`answering ${choice} keeps nothing`, async () => {
    const { out } = await alwaysThen({}, {}, {}, choice);
    assert.ok(asked(out));
    assert.deepEqual(kept(), []);
  });
}

test("in a group chat allow always is not offered and nothing is kept", async () => {
  const r = registered();
  const out = await r.call("c1", { sessionKey: "agent:main:telegram:group:-1001" });
  assert.ok(scans[0].trigger.sender.basis.includes("group_chat"), JSON.stringify(scans[0].trigger.sender));
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  assert.ok(!out.requireApproval.description.includes(ALWAYS_LINE));
  await out.requireApproval.onResolution("allow-always");
  assert.deepEqual(kept(), []);
});

test("with a suggested grant, allow always sets the grant and keeps no allowance", async () => {
  await alwaysThen({ hints: [HINT] });
  assert.deepEqual(kept(), []);
  const g = JSON.parse(readFileSync(path.join(stateDir, "grants.json"), "utf8")).grants;
  assert.deepEqual(g.map((x: any) => x.pattern), [HINT.pattern]);
});

test("a built-in tool offers no standing allowance", async () => {
  const r = registered();
  const out = await r.call("c1", { tool: "write" });
  if (asked(out)) {
    assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
    await out.requireApproval.onResolution("allow-always");
  }
  assert.deepEqual(kept(), []);
});

test("a server the host config does not describe keeps nothing", async () => {
  const r = registered();
  delete r.servers.wiki;
  next = {};
  const out = await r.call("c1");
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  await out.requireApproval.onResolution("allow-always");
  assert.deepEqual(kept(), []);
});
