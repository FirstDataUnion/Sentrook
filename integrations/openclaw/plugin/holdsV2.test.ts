/**
 * Answers to a held call each do something: `/sentrook-allow` lets the job's next run make the call once,
 * `/sentrook-allow <id> always` lets the job make it for 30 days, `/sentrook-deny` refuses it on the job for 30 days
 * with no more notices.
 *
 * A pass or denial is bound to the cron job OpenClaw names for the run (`ctx.inputProvenance.jobId` or `ctx.jobId`
 * when `ctx.trigger` is `cron`, never the prompt's tag) and to the action, matched on the same terms as the Hermes
 * plugin's Session answer: same tool, same parties, risk no higher, no new warning, not enforced, no floor, and the
 * scan's `owner_pass` at or above the pass's level. The matching table is shared with the Hermes plugin
 * (`integrations/fixtures/hold/cases.json`, `passes`).
 */

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import * as hold from "./hold.ts";
import plugin from "./index.ts";
import * as passes from "./passes.ts";
import { readTime } from "./store.ts";
import { runVerify } from "./verify.ts";

const FIXTURES = JSON.parse(readFileSync(fileURLToPath(new URL("../../fixtures/hold/cases.json", import.meta.url)), "utf8"));
const SEND = FIXTURES.notices[0];
const FP = "afp1:message_send|ch:discord:#ops-reports";
/** A scan the scanner lets the owner pass for good: a send that names its channel. */
const ALWAYS = {
  risk: 47,
  enforced: null,
  owner_pass: "always",
  approval_fingerprint: FP,
  reasons: [{ code: "trigger.scheduled" }, { code: "send.unbound_channel", subject: "E1" }],
};
/** The same send from a scanner that sends no `owner_pass` (it predates it): allow once and deny. */
const { owner_pass: _drop, ...NAMED } = ALWAYS;
const OTHER_CHANNEL = { E1: { kind: "channel", display: "discord:#general" } };
const HELD = { block: true, blockReason: FIXTURES.held_text };
const DECLINED = { block: true, blockReason: FIXTURES.declined_text };
const DAY = 24 * 3600_000;

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_DEV_ENDPOINTS", "SENTROOK_SCAN_URL", "SENTROOK_OIDC_ISSUER", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE"];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let stateDir = "";
let scans: any[] = [];
let reply: Record<string, unknown> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-holds2-"));
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
  reply = { ...NAMED };
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      scans.push(planir);
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
  /**
   * One send in run `n` of cron job `job` (each run its own session); null `job`: a cron-triggered run OpenClaw
   * names no job for. `provenance`: the job id comes in `inputProvenance` (else as the hook's `jobId`).
   */
  const run = async (n: number, job: string | null = "job-j", opts: { id?: string; provenance?: boolean; message?: string } = {}) => {
    const sid = `cron-${job}-${n}`;
    const runId = `r-${sid}-${opts.id ?? "c1"}`;
    const ctx: Record<string, unknown> = { sessionKey: `agent:main:cron:${sid}`, sessionId: sid, agentId: "main", runId, trigger: "cron" };
    if (job) {
      if (opts.provenance === false) ctx.jobId = job;
      else ctx.inputProvenance = { kind: "cron", jobId: job };
    }
    // The prompt's tag names another job: it is never what a pass is bound to.
    await fire("before_prompt_build", { runId, prompt: "[cron:tagged-job daily-brief] post the brief" }, ctx);
    const out = await fire(
      "before_tool_call",
      {
        toolName: "message",
        toolCallId: opts.id ?? "c1",
        runId,
        params: { action: "send", channel: "discord", target: "#ops-reports", message: opts.message ?? `Daily brief ${n}` },
      },
      ctx,
    );
    await hold.waitForNotices();
    return { out, rec: records("scan").at(-1), ctx };
  };
  const command = async (name: string, args: string, ctx: Record<string, unknown> = DM) =>
    (await commands[name].handler({ ...ctx, args })).text as string;
  return { fire, commands, sent, records, run, command };
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

test("allow lets the job's next run make the same send once; the run after is held again", async () => {
  const r = await withNotify();
  let { out, rec } = await r.run(1);
  assert.deepEqual(out, HELD);
  const id = rec.hold.id;
  assert.deepEqual(rec.hold.offers, ["allow", "deny"], "this scanner sends no owner_pass: never always");
  assert.match(rec.hold.notice.status, /queued/);
  const answer = await r.command("sentrook-allow", id);
  assert.ok(answer.startsWith("Job job-j may make this call once: on its next run, or if the held run retries it."), answer);
  const [p] = stored();
  assert.deepEqual([p.kind, p.uses, p.level, p.job_id], ["allow", "once", "once", "job-j"]);
  assert.deepEqual(holds(), []);
  ({ out, rec } = await r.run(2));
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed_by_pass");
  assert.deepEqual([rec.pass.id, rec.pass.kind], [p.id, "allow"]);
  assert.deepEqual(stored(), [], "used up");
  ({ out, rec } = await r.run(3));
  assert.deepEqual(out, HELD);
});

test("the job id may come as the hook's jobId too", async () => {
  const r = registered();
  const { rec } = await r.run(1, "job-j", { provenance: false });
  await r.command("sentrook-allow", rec.hold.id);
  assert.equal((await r.run(2, "job-j", { provenance: false })).out, undefined);
});

test("allow later is the same until the plugin can start the run", async () => {
  const r = registered();
  const { rec } = await r.run(1);
  assert.ok((await r.command("sentrook-allow", `${rec.hold.id} later`)).startsWith("Job job-j may make this call once: on its next run, or if the held run retries it."));
  assert.equal((await r.run(2)).out, undefined);
});

test("allow always lets three later runs through and counts them", async () => {
  reply = { ...ALWAYS };
  const r = registered();
  const { rec } = await r.run(1);
  assert.deepEqual(rec.hold.offers, ["allow", "allow always", "deny"]);
  const answer = await r.command("sentrook-allow", `${rec.hold.id} always`);
  let [p] = stored();
  assert.ok(answer.startsWith("Job job-j may make this call until "), answer);
  assert.ok(answer.includes(`Undo: /sentrook-passes revoke ${p.id}.`), answer);
  assert.equal(readTime(p.expires_at)!.getTime() - readTime(p.set_at)!.getTime(), 30 * DAY);
  for (const n of [2, 3, 4]) {
    const { out, rec } = await r.run(n);
    assert.equal(out, undefined);
    assert.equal(rec.decision, "allowed_by_pass");
  }
  [p] = stored();
  assert.equal(p.use_count, 3);
  assert.match(await r.command("sentrook-passes", ""), /used 3 times/);
  assert.deepEqual(r.records("resolution").map((x) => x.resolution), ["hold_allowed_always"]);
});

test("after allow, a retry in the same session is not a retry after a denial", async () => {
  const r = registered();
  const { rec, ctx } = await r.run(1);
  await r.command("sentrook-allow", rec.hold.id);
  const session = JSON.parse(readFileSync(path.join(stateDir, "sessions", `${ctx.sessionId}.json`), "utf8"));
  assert.equal(session.history.at(-1).decision, "approved_by_user");
  await r.fire("after_tool_call", { toolName: "message", toolCallId: "c1", runId: ctx.runId, error: "held" }, ctx);
  const out = await r.fire(
    "before_tool_call",
    { toolName: "message", toolCallId: "c2", runId: ctx.runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: "Daily brief 1" } },
    ctx,
  );
  assert.equal(out, undefined);
  const sent = scans.at(-1).history.map((e: any) => e.decision);
  assert.ok(sent.includes("approved_by_user") && !sent.includes("review_timed_out"), sent.join(","));
});

// ---- must fire ---------------------------------------------------------------------------------------------

test("after allow, a send to another channel is held", async () => {
  reply = { ...ALWAYS };
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-allow", rec.hold.id);
  reply = { ...ALWAYS, entities: OTHER_CHANNEL };
  assert.deepEqual((await r.run(2)).out, HELD);
  assert.equal(stored().length, 1, "not used");
});

test("the same send from another job is held, and so is a run OpenClaw names no job for", async () => {
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-allow", rec.hold.id);
  assert.deepEqual((await r.run(1, "job-k")).out, HELD);
  // The prompt's tag says "tagged-job": a run with no job in its metadata is no job's run.
  assert.deepEqual((await r.run(1, null)).out, HELD);
  assert.equal(stored().length, 1);
});

const RISKIER: [string, Record<string, unknown>][] = [
  ["higher risk", { risk: 52 }],
  ["new warning", { reasons: [...ALWAYS.reasons, { code: "steer.uses_steering_content" }] }],
  ["enforced", { enforced: "review" }],
  ["floor", { floors_applied: ["send.secret_off_host"] }],
  ["owner_pass once", { owner_pass: "once" }],
  ["owner_pass null", { owner_pass: null }],
];
for (const [name, later] of RISKIER) {
  test(`a standing pass never passes a riskier call: ${name}`, async () => {
    reply = { ...ALWAYS };
    const r = registered();
    const { rec } = await r.run(1);
    await r.command("sentrook-allow", `${rec.hold.id} always`);
    reply = { ...ALWAYS, ...later };
    const { out, rec: again } = await r.run(2);
    assert.deepEqual(out, HELD);
    assert.equal(again.decision, "held");
    assert.equal(stored()[0].use_count, 0);
  });
}

for (const [name, scan, why] of [
  ["once", { ...ALWAYS, owner_pass: "once" }, "for this one it offers it once"],
  ["null", { ...ALWAYS, owner_pass: null }, "Sentrook does not offer to let this call through"],
  ["missing (an older scanner)", { ...NAMED }, "for this one it offers it once"],
] as const) {
  test(`allow always is refused with a reason when owner_pass is ${name}`, async () => {
    reply = { ...scan };
    const r = await withNotify();
    const { rec } = await r.run(1);
    const id = rec.hold.id;
    assert.ok(!rec.hold.offers.includes("allow always"));
    assert.ok(!r.sent.at(-1).text.includes("always"));
    const answer = await r.command("sentrook-allow", `${id} always`);
    assert.ok(answer.startsWith("Not ") && answer.includes(why), answer);
    assert.deepEqual(holds().map((h: any) => h.id), [id]);
    assert.deepEqual(stored(), []);
  });
}

for (const [name, later] of [
  ["enforced", { enforced: "review" }],
  ["floor", { floors_applied: ["send.secret_off_host"] }],
  ["degraded", { status: "degraded" }],
] as const) {
  test(`a hold no pass could let through offers only deny: ${name}`, async () => {
    reply = { ...ALWAYS, ...later };
    const r = await withNotify();
    const { rec } = await r.run(1);
    assert.deepEqual(rec.hold.offers, ["deny"]);
    assert.ok(!r.sent.at(-1).text.includes("allow"));
    assert.match(await r.command("sentrook-allow", rec.hold.id), /does not offer to let this call through/);
  });
}

test("a denied call counts as blocked on the dashboard", async () => {
  const { actionOf } = await import("./history.ts");
  const { bucketOf } = await import("./dashboard.ts");
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-deny", rec.hold.id);
  const { rec: denied } = await r.run(2);
  const action = actionOf(denied, null);
  assert.deepEqual([action, bucketOf(denied, action)], ["declined (denied by owner)", "blocked"]);
});

test("the answer's history update waits for a scan of the same session, across stores", async () => {
  const { Store } = await import("./store.ts");
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-lock-"));
  const order: string[] = [];
  let release!: () => void;
  const scan = new Store(dir).withSession("s1", () => new Promise<void>((r) => (release = () => (order.push("scan"), r()))));
  const update = new Store(dir).withSession("s1", () => void order.push("update"));
  await new Promise((r) => setTimeout(r, 20));
  release();
  await Promise.all([scan, update]);
  assert.deepEqual(order, ["scan", "update"]);
});

test("a call that names nothing is offered allow once, bound to its arguments", async () => {
  reply = { ...ALWAYS, approval_fingerprint: "afp1:message_send" };
  const r = registered();
  const { rec } = await r.run(1);
  assert.deepEqual(rec.hold.offers, ["allow", "deny"]);
  assert.match(await r.command("sentrook-allow", `${rec.hold.id} always`), /names nothing/);
  await r.command("sentrook-allow", rec.hold.id);
  // run 2 sends other words: other arguments, so it is held
  assert.deepEqual((await r.run(2)).out, HELD);
  // the exact same call goes through
  assert.equal((await r.run(3, "job-j", { message: "Daily brief 1" })).out, undefined);
});

test("deny declines the job's call with no notice; another job is still held with a notice", async () => {
  const r = await withNotify();
  const { rec, ctx } = await r.run(1);
  const answer = await r.command("sentrook-deny", rec.hold.id);
  assert.ok(answer.startsWith("Job job-j will not make this call until ") && answer.includes("you won't be told again"), answer);
  const before = r.sent.length;
  const { out, rec: denied } = await r.run(2);
  assert.deepEqual(out, DECLINED);
  assert.equal(denied.decision, "denied_by_owner");
  assert.ok(!("hold" in denied));
  assert.equal(r.sent.length, before);
  assert.deepEqual(holds(), []);
  assert.deepEqual((await r.run(1, "job-k")).out, HELD);
  assert.equal(r.sent.length, before + 1);
  const session = JSON.parse(readFileSync(path.join(stateDir, "sessions", `${ctx.sessionId}.json`), "utf8"));
  assert.equal(session.history.at(-1).decision, "denied_by_user");
});

test("a denied call is sent to the scanner as a denial by the owner", async () => {
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-deny", rec.hold.id);
  const { ctx } = await r.run(2);
  await r.fire("after_tool_call", { toolName: "message", toolCallId: "c1", runId: ctx.runId, error: "declined" }, ctx);
  await r.fire(
    "before_tool_call",
    { toolName: "message", toolCallId: "c2", runId: ctx.runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: "Daily brief 2" } },
    ctx,
  );
  assert.equal(scans.at(-1).history[0].decision, "denied_by_user");
});

for (const name of ["sentrook-allow", "sentrook-deny", "sentrook-approve", "sentrook-passes"]) {
  test(`${name} is refused to a non-owner`, async () => {
    const r = registered();
    const { rec } = await r.run(1);
    assert.deepEqual(r.commands[name].requiredScopes, ["operator.admin"]);
    const args = name === "sentrook-passes" ? "" : rec.hold.id;
    assert.match(await r.command(name, args, { ...DM, senderIsOwner: false }), /^Only the owner can run/);
    assert.equal(holds().length, 1);
    assert.deepEqual(stored(), []);
  });
}

for (const [name, args, want] of [
  ["sentrook-allow", "", "usage: /sentrook-allow <id> [later|always]"],
  ["sentrook-allow", "h-zzzzzz", "usage: /sentrook-allow <id> [later|always]"],
  ["sentrook-allow", "h-1a2b3c sometimes", "usage: /sentrook-allow <id> [later|always]"],
  ["sentrook-deny", "h-1a2b3c always", "usage: /sentrook-deny <id>"],
  ["sentrook-deny", "p-1a2b3c", "usage: /sentrook-deny <id>"],
  ["sentrook-allow", "h-abcdef", "No held call h-abcdef: the id is unknown, already answered or expired."],
  ["sentrook-deny", "h-abcdef", "No held call h-abcdef: the id is unknown, already answered or expired."],
  ["sentrook-passes", "revoke p-abcdef", "No pass or denial p-abcdef: the id is unknown, used up or expired."],
  ["sentrook-passes", "revoke h-abcdef", "usage: passes revoke <id>"],
  ["sentrook-passes", "frobnicate", "usage: /sentrook-passes [revoke <id>]"],
] as const) {
  test(`unknown and malformed ids get clear replies: /${name} ${args}`, async () => {
    const r = registered();
    assert.ok((await r.command(name, args)).startsWith(want));
  });
}

test("an expired hold says so", async () => {
  const r = registered();
  const { rec } = await r.run(1);
  const file = path.join(stateDir, "holds.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.holds[0].expires_at = "2020-01-01T00:00:00Z";
  writeFileSync(file, JSON.stringify(data));
  assert.ok((await r.command("sentrook-deny", rec.hold.id)).startsWith(`Held call ${rec.hold.id} expired: a hold can be answered for 7 days.`));
});

test("deny on a run OpenClaw names no job for is refused", async () => {
  const r = registered();
  const { out, rec } = await r.run(1, null);
  assert.deepEqual(out, HELD);
  assert.deepEqual(rec.hold.offers, ["allow"]);
  assert.match(await r.command("sentrook-deny", rec.hold.id), /not on a cron job/);
});

// ---- holds repeat, passes list -----------------------------------------------------------------------------

test("a repeat of a waiting hold updates it and sends no new notice", async () => {
  const r = await withNotify();
  const { rec: first } = await r.run(1);
  const { rec: second } = await r.run(2);
  assert.equal(second.hold.id, first.hold.id);
  assert.equal(second.hold.repeat, true);
  assert.equal(second.hold.notice.status, "not_sent");
  assert.equal(r.sent.length, 1);
  const [entry] = holds();
  assert.equal(entry.count, 2);
  assert.equal(entry.held.length, 2);
  const { runSentrookCommand } = await import("./commands.ts");
  assert.match(await runSentrookCommand("status", { pluginConfig: {}, env: process.env }), new RegExp(`${entry.id} held 2 times since`));
  await r.command("sentrook-allow", entry.id);
  assert.deepEqual(r.records("resolution").map((x) => x.request_id), [first.request_id, second.request_id]);
});

test("a riskier repeat is a new hold with its own notice", async () => {
  const r = await withNotify();
  const { rec: first } = await r.run(1);
  reply = { ...NAMED, risk: 60 };
  const { rec: second } = await r.run(2);
  assert.notEqual(second.hold.id, first.hold.id);
  assert.equal(r.sent.length, 2);
});

test("passes lists and revokes", async () => {
  reply = { ...ALWAYS };
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-allow", `${rec.hold.id} always`);
  const [p] = stored();
  const listed = await r.command("sentrook-passes", "");
  assert.ok(listed.startsWith(`${p.id}  allowed on job job-j until `) && listed.includes("used 0 times"), listed);
  const { runSentrookCommand } = await import("./commands.ts");
  assert.match(await runSentrookCommand("status", { pluginConfig: {}, env: process.env }), /^passes: 1 standing, 0 once, 0 denials$/m);
  assert.equal(await r.command("sentrook-passes", `revoke ${p.id}`), `Revoked pass ${p.id}.`);
  assert.deepEqual(r.records("passes").map((x) => x.op), ["add", "revoke"]);
  assert.deepEqual((await r.run(2)).out, HELD);
});

test("an unreadable passes file holds as before, and verify fails", async () => {
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-allow", rec.hold.id);
  writeFileSync(path.join(stateDir, "passes.json"), "{not json");
  assert.deepEqual((await r.run(2)).out, HELD);
  const checks = await runVerify({}, { env: process.env });
  const found = checks.find((c: any) => c.name === "held-call passes");
  assert.deepEqual([found?.ok, found?.detail], [false, "passes file unreadable"]);
});

// ---- must stay the same ------------------------------------------------------------------------------------

test("a block is never passed", async () => {
  reply = { ...ALWAYS };
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-allow", `${rec.hold.id} always`);
  reply = { ...ALWAYS, risk: 85 };
  const { out, rec: blocked } = await r.run(2);
  assert.equal(out.block, true);
  assert.match(out.blockReason, /^Sentrook security block:/);
  assert.equal(blocked.decision, "blocked");
});

test("observe mode ignores a denial", async () => {
  const r = registered();
  const { rec } = await r.run(1);
  await r.command("sentrook-deny", rec.hold.id);
  const o = registered({ mode: "observe" });
  const { out, rec: observed } = await o.run(2);
  assert.equal(out, undefined);
  assert.equal(observed.decision, "allowed");
});

test("holds.json is version 2", async () => {
  const r = registered();
  await r.run(1);
  assert.equal(JSON.parse(readFileSync(path.join(stateDir, "holds.json"), "utf8")).version, 2);
});

// ---- the shared matching table -----------------------------------------------------------------------------

test("pass matching: the shared table", () => {
  for (const c of FIXTURES.passes) {
    const held = passes.matchOf(c.tool, c.held, c.args, "salt");
    const later = passes.matchOf(c.later_tool ?? c.tool, c.later, c.later_args, "salt");
    const got = passes.eligible(c.later) && passes.covers(held, later) && passes.levelCovers(passes.levelOf(c.later), c.pass_level);
    assert.equal(got, c.matches, c.name);
  }
});

test("cronJobId reads only the host's run metadata", () => {
  assert.equal(hold.cronJobId({ trigger: "cron", inputProvenance: { jobId: "a" } }, {}), "a");
  assert.equal(hold.cronJobId({ trigger: "cron", jobId: "b" }, {}), "b");
  assert.equal(hold.cronJobId({}, { trigger: "cron", inputProvenance: { jobId: "c" } }), "c");
  assert.equal(hold.cronJobId({ trigger: "heartbeat", jobId: "d" }, {}), null);
  assert.equal(hold.cronJobId({ trigger: "cron" }, { prompt: "[cron:e name] x" }), null);
});

test("passes expire after 30 days", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-passes-"));
  const t0 = new Date("2026-11-24T00:00:00Z");
  const ref = passes.jobRef("j");
  const match: passes.Match = { key: "k", named: true, risk: 1, warnings: [] };
  passes.add(dir, { kind: "deny", uses: "standing", level: null, hold: { id: "h-000000", job_id: "j", job_ref: ref, match }, by: {}, now: t0 });
  assert.ok(passes.check(dir, ref, match, { risk: 1 }, new Date(t0.getTime() + 29 * DAY)));
  assert.equal(passes.check(dir, ref, match, { risk: 1 }, new Date(t0.getTime() + 30 * DAY)), null);
});
