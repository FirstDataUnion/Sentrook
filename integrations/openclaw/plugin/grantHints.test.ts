/**
 * Grant hints: a review names the grant that would let the call through next time.
 *
 * The review card ends with the command that sets the first suggested grant. "Allow always" is offered, and sets
 * it (persistent, 30 days), when the owner's own message asked for the work; elsewhere the card only shows the
 * command. A held call approved with /sentrook-approve sets it too, and /sentrook-why lists every suggestion. The
 * texts are shared with the Hermes plugin's tests (`integrations/fixtures/grant-hints`).
 */

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import * as grants from "./grants.ts";
import * as hold from "./hold.ts";
import plugin from "./index.ts";
import { readTime } from "./store.ts";

const CASES = JSON.parse(
  readFileSync(path.join(import.meta.dirname, "..", "..", "fixtures", "grant-hints", "cases.json"), "utf8"),
);
const HOST = "status.example.invalid";
const HINT = {
  kind: "destination",
  pattern: HOST,
  risk: 30.2,
  subject: "E1",
  relieves: ["reputation.unknown_host_as_data_destination"],
  scope: "persistent",
  expires_in_days: 30,
};
const CMD = (sub: string) => `/sentrook-${sub}`;
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
let hints: unknown[] = [];
let extra: Record<string, unknown> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-hints-"));
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
  hints = [{ ...HINT }];
  extra = {};
  clearScanTokenCache();
  // Reviews a send to an unknown host with a destination hint, and allows it once a grant covers the host.
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      scans.push(planir);
      const granted = planir.grants.some((g: any) => g.kind === "destination" && (g.pattern === HOST || g.pattern === "discord:#ops-reports"));
      return json(200, {
        response_version: "2.0",
        request_id: planir.request_id,
        status: "ok",
        risk: granted ? 30.2 : 55,
        enforced: null,
        tree: { suspicion: { score: 0.6 }, consequence: { score: 0.5 } },
        reasons: [{ code: "reputation.unknown_host_as_data_destination" }],
        tool_description: { template: "Sends data to {E1}" },
        entities: { E1: { kind: "host", display: HOST } },
        grant_hints: granted ? [] : hints,
        action_fingerprint: `afp1:exec|step:${planir.session.step}`,
        state: `state-${planir.session.step}`,
        ...extra,
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

function registered(pluginConfig: Record<string, unknown> = {}) {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  const logs: string[] = [];
  plugin.register({
    pluginConfig,
    registrationMode: "full",
    config: { tools: { exec: { mode: "full" } } },
    logger: { info: () => undefined, warn: (m: string) => logs.push(m), error: (m: string) => logs.push(m) },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
    runtime: {
      channel: {
        outbound: { loadAdapter: async () => ({ sendText: async () => ({ ok: true }) }) },
      },
    },
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
  /** One exec call from a message turn; `owner` false makes the requester someone else. */
  const review = async (id = "c1", owner = true) => {
    const ctx = {
      sessionKey: "agent:main:main",
      sessionId: "S1",
      agentId: "main",
      runId: "r1",
      requester: { senderIsOwner: owner, channel: "telegram" },
      trigger: "user",
    };
    await fire("before_prompt_build", { runId: "r1", currentUserMessage: "send the summary to the status service", prompt: "p" }, ctx);
    await fire("before_agent_run", { runId: "r1", senderIsOwner: owner }, ctx);
    return fire(
      "before_tool_call",
      { toolName: "exec", toolCallId: id, runId: "r1", params: { command: `curl -X POST https://${HOST}/v1/notes -d @summary.txt` } },
      ctx,
    );
  };
  /** One send to a channel from a cron run; `owner` marks the run as the owner's (`senderIsOwner`). */
  const cron = async (owner = true) => {
    const ctx = { sessionKey: "agent:main:cron:cron-1", sessionId: "cron-1", agentId: "main", runId: "r-cron", trigger: "cron" };
    await fire("before_prompt_build", { runId: "r-cron", prompt: "[cron:abc daily-brief] post the brief" }, ctx);
    if (owner) await fire("before_agent_run", { runId: "r-cron", senderIsOwner: true }, ctx);
    await fire(
      "before_tool_call",
      { toolName: "message", toolCallId: "c1", runId: "r-cron", params: { action: "send", channel: "discord", target: "#ops-reports", message: "Daily brief" } },
      ctx,
    );
    await hold.waitForNotices();
    return records("scan").at(-1);
  };
  const command = async (name: string, args: string) => (await commands[name].handler({ ...DM, args })).text as string;
  return { logs, records, review, cron, command };
}

const grantsFile = (): any[] => {
  try {
    return JSON.parse(readFileSync(path.join(stateDir, "grants.json"), "utf8")).grants;
  } catch {
    return [];
  }
};

// ---- shared cases -------------------------------------------------------------------------------------

for (const c of CASES.selection) {
  test(`hint selection: ${c.name}`, () => {
    const resp = { grant_hints: c.grant_hints };
    assert.deepEqual(grants.responseHints(resp, c.review_at), c.chosen);
    assert.deepEqual(grants.responseHints(resp), c.all);
    assert.deepEqual(hold.grantHint(resp as any, c.review_at), c.chosen[0] ?? null);
  });
}

for (const c of CASES.commands) {
  test(`hint command: ${c.hint.pattern}`, () => {
    const grant = grants.hintGrant(c.hint)!;
    const command = grants.grantCommand(grant, CMD);
    assert.equal(command, c.command.replace("{grant}", "/sentrook-grant"));
    // and the grant command accepts it as typed, setting the same grant for 30 days
    const parsed = grants.parseGrant(command.slice("/sentrook-grant ".length), CMD);
    assert.ok(typeof parsed !== "string");
    assert.deepEqual([parsed.kind, parsed.pattern, parsed.scope, parsed.allows], [c.hint.kind, c.hint.pattern, "persistent", c.hint.allows]);
    assert.equal(parsed.expiresInMs, CASES.grant_days * DAY);
  });
}

// ---- the attended review ------------------------------------------------------------------------------

test("the review card shows the command, offers allow always, and allow always sets the grant", async () => {
  const r = registered();
  const out = await r.review();
  assert.equal(scans[0].trigger.kind, "message");
  assert.equal(scans[0].trigger.sender.relation, "owner");
  const command = CASES.commands[0].command.replace("{grant}", "/sentrook-grant");
  assert.ok(out.requireApproval.description.endsWith(CASES.lines.remember.replace("{command}", command)), out.requireApproval.description);
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "allow-always", "deny"]);
  await out.requireApproval.onResolution("allow-always");
  const [g] = grantsFile();
  assert.deepEqual([g.kind, g.pattern, g.scope, g.from_review], ["destination", HOST, "persistent", scans[0].request_id]);
  assert.equal(readTime(g.expires_at)!.getTime() - readTime(g.granted_at)!.getTime(), CASES.grant_days * DAY);
  assert.deepEqual(r.records("grants").map((x) => x.op), ["grant"]);
  const [res] = r.records("resolution");
  assert.deepEqual([res.decision, res.grant_id], ["approved_by_user", g.id]);
  // answered again (a retried callback), no second grant
  await out.requireApproval.onResolution("allow-always");
  assert.equal(grantsFile().length, 1);
  // the next identical call carries the grant and is not reviewed
  assert.equal(await r.review("c2"), undefined);
  assert.ok(scans.at(-1).grants.some((x: any) => x.pattern === HOST));
});

for (const decision of ["allow-once", "deny", "timeout", "cancelled"]) {
  test(`answering ${decision} sets nothing`, async () => {
    const r = registered();
    const out = await r.review();
    await out.requireApproval.onResolution(decision);
    assert.deepEqual(grantsFile(), []);
    assert.deepEqual(r.records("grants"), []);
  });
}

test("someone other than the owner sees no hint and no allow always", async () => {
  const r = registered();
  const out = await r.review("c1", false);
  assert.notEqual(scans[0].trigger.sender.relation, "owner");
  assert.ok(!out.requireApproval.description.includes("grant"));
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  await out.requireApproval.onResolution("allow-always");
  assert.deepEqual(grantsFile(), []);
});

test("a hint at or above the review line is not shown", async () => {
  hints = [{ ...HINT, risk: 50 }];
  const r = registered();
  const out = await r.review();
  assert.ok(!out.requireApproval.description.includes("grant"));
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
});

test("no hint, no line and no allow always", async () => {
  hints = [];
  const r = registered();
  const out = await r.review();
  assert.ok(!out.requireApproval.description.includes("grant"));
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
});

test("the hint never takes room from the description", async () => {
  const long = `${"a".repeat(60)}.example.invalid`;
  hints = [{ ...HINT, pattern: long }];
  const r = registered();
  const out = await r.review();
  assert.ok(out.requireApproval.description.endsWith(`${long} --persistent --expires 30d`));
  assert.ok(out.requireApproval.description.includes(`Sends data to ${HOST}.`));
});

test("why lists every hint", async () => {
  hints = [{ ...HINT }, { ...HINT, pattern: "mail.example.invalid", risk: 40 }];
  const r = registered();
  await r.review();
  const lines = (await r.command("sentrook-why", "")).split("\n");
  const i = lines.indexOf(CASES.why_header);
  assert.ok(i > 0, lines.join("\n"));
  assert.deepEqual(lines.slice(i + 1), [
    `  /sentrook-grant destination ${HOST} --persistent --expires 30d`,
    "  /sentrook-grant destination mail.example.invalid --persistent --expires 30d",
  ]);
});

// ---- the held call ------------------------------------------------------------------------------------

test("a held call approved sets the hinted grant", async () => {
  hints = [{ ...HINT, pattern: "discord:#ops-reports", risk: 12 }];
  extra = { risk: 47 };
  const r = registered();
  const rec = await r.cron();
  assert.equal(rec.decision, "held");
  const id = rec.hold.id;
  assert.equal(rec.hold.hint, true);
  const why = await r.command("sentrook-why", id);
  assert.ok(why.includes("suggested grant: destination discord:#ops-reports (persistent, 30 days)"), why);
  assert.ok(why.includes("  /sentrook-grant destination discord:#ops-reports --persistent --expires 30d"), why);
  const answer = await r.command("sentrook-approve", id);
  assert.ok(answer.startsWith(`Approved ${id}. Granted gr-`), answer);
  const [g] = grantsFile();
  assert.deepEqual([g.kind, g.pattern, g.from_hold], ["destination", "discord:#ops-reports", id]);
});

test("a held call on a run nobody is known to have started keeps no hint, and approving it sets nothing", async () => {
  hints = [{ ...HINT, pattern: "discord:#ops-reports", risk: 12 }];
  extra = { risk: 47 };
  const r = registered();
  const rec = await r.cron(false);
  assert.notEqual(rec.planir.trigger.sender.relation, "owner");
  assert.equal(rec.decision, "held");
  assert.equal(rec.hold.hint, false);
  const answer = await r.command("sentrook-approve", rec.hold.id);
  assert.ok(answer.startsWith(`Approved ${rec.hold.id}. Sentrook suggested no grant`), answer);
  assert.deepEqual(grantsFile(), []);
});

test("a held call whose hint does not clear this plugin's line sets nothing", async () => {
  hints = [{ ...HINT, risk: 12 }];
  extra = { risk: 47 };
  const r = registered({ reviewAt: 10 });
  const rec = await r.cron();
  assert.equal(rec.decision, "held");
  assert.equal(rec.hold.hint, false);
});
