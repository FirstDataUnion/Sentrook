/**
 * Holds: a review on an unattended run waits for the owner, who is told once and may answer it.
 *
 * The agent is told the call is held and must not be retried in this run; the owner gets one notice as a
 * direct message where they ran `/sentrook-notify here`, and answers within 7 days (holdsV2.test.ts covers what
 * each answer sets). A hold from before version 2 is still answered as approve answered it: the suggested grant,
 * persistent for 30 days. Blocks stay blocks, and attended runs still get the host's approval prompt. The texts are
 * shared with the Hermes plugin's tests (`integrations/fixtures/hold`).
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import { ERROR_CAUSES } from "./card.ts";
import * as consent from "./consent.ts";
import { SIGN_IN_FIXES } from "./scanErrorPolicy.ts";
import { formatHistory, recentScans, actionOf, reviewOf } from "./history.ts";
import * as hold from "./hold.ts";
import { roomRefusal } from "./owner.ts";
import * as passes from "./passes.ts";
import * as scanFailure from "./scanFailureNotice.ts";
import plugin from "./index.ts";
import * as grants from "./grants.ts";
import { DatabaseSync } from "node:sqlite";
import { readTime, Store } from "./store.ts";

const FIXTURES = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/hold/cases.json", import.meta.url)), "utf8"),
) as {
  held_text: string;
  notices: {
    name: string;
    response: any;
    tool: string;
    where: {
      run: string;
      session_ref: string;
      job_id: string | null;
      job_name: string | null;
      source?: { kind: passes.SourceKind; value: string } | null;
    };
    where_text: string;
    id: string;
    offers: string[];
    text: string;
  }[];
  block_at: number;
  hints: { hint: unknown; grant: unknown }[];
  scan_failure_quiet_hours: number;
  scan_failure_reasons: { failure: { kind: string; status?: number }; reason: string }[];
  scan_failure_notices: {
    name: string;
    failure: { kind: string; status?: number };
    tool: string;
    where: { run: string; session_ref: string; job_id: string | null; job_name: string | null };
    where_text: string;
    quiet_key: string;
    text: string;
  }[];
  outcomes: { name: string; risk: number; enforced: string | null; ceiling?: string | null; reasons?: string[]; attended: string; unattended: string }[];
  history: { name: string; decision: string; resolution: string | null; action: string; review: string }[];
};
const SEND = FIXTURES.notices[0]!;
const CONSENT = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/consent/cases.json", import.meta.url)), "utf8"),
);
const CONSENT_NOTICE: string = CONSENT.rendered.openclaw.withdrawn_notice;
const HINT = FIXTURES.hints[0]!.hint as Record<string, unknown>;
const HOUR = 3600_000;

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
let reply: Record<string, unknown> = {};
/** The scanner cannot be reached while set. */
let unreachable = false;
/** The scanner refuses the credentials (401) while set. */
let unauthorized = false;
/** The identity service refuses the credentials with `tokenAnswer` (consent withdrawn by default) while set. */
let withdrawn = false;
let tokenAnswer: { status: number; body: unknown } = CONSENT.token_error;
/** Every URL fetched. */
let requests: string[] = [];

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-hold-"));
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
  reply = { risk: 47, enforced: null };
  unreachable = false;
  unauthorized = false;
  withdrawn = false;
  tokenAnswer = CONSENT.token_error;
  requests = [];
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    requests.push(url);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token") && withdrawn) return json(tokenAnswer.status, tokenAnswer.body);
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      scans.push(planir);
      if (unreachable) throw new TypeError("fetch failed");
      if (unauthorized) return json(401, { error: "invalid_token" });
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

function registered(pluginConfig: Record<string, unknown> = {}, outbound: unknown = "default") {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  const sent: any[] = [];
  const logs: string[] = [];
  const adapters =
    outbound === "default"
      ? {
          loadAdapter: async (channel: string) => ({
            sendText: async (req: any) => {
              sent.push({ channel, ...req });
              return { ok: true };
            },
          }),
        }
      : outbound;
  plugin.register({
    pluginConfig,
    registrationMode: "full",
    config: { tools: { exec: { mode: "full" } } },
    logger: { info: () => undefined, warn: (m: string) => logs.push(m), error: (m: string) => logs.push(m) },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
    runtime: { channel: { outbound: adapters } },
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
  /** One send to a channel from a run with `trigger`: the hook's result and the scan's traffic record. */
  const send = async (trigger: string, sid = "cron-1", id = "c1") => {
    const runId = `r-${sid}`;
    const ctx = { sessionKey: `agent:main:cron:${sid}`, sessionId: sid, agentId: "main", runId, trigger };
    await fire("before_prompt_build", { runId, prompt: trigger === "cron" ? "[cron:abc daily-brief] post the brief" : "post the brief" }, ctx);
    const out = await fire(
      "before_tool_call",
      { toolName: "message", toolCallId: id, runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: "Daily brief" } },
      ctx,
    );
    await hold.waitForNotices();
    return { out, rec: records("scan").at(-1), ctx };
  };
  const command = async (name: string, args: string, ctx: Record<string, unknown> = DM) =>
    (await commands[name].handler({ ...ctx, args })).text as string;
  return { on, fire, commands, sent, logs, records, send, command };
}

const holds = () => JSON.parse(readFileSync(path.join(stateDir, "holds.json"), "utf8")).holds;

/** Turns the waiting hold into one an earlier version of the plugin stored: no `v`, 24 hours, with `hint`. */
function asV1(hint: unknown = null) {
  const file = path.join(stateDir, "holds.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  const h = data.holds[0];
  const keep = ["id", "request_id", "session_ref", "tool", "where", "held_at", "notice"];
  data.holds[0] = Object.fromEntries(keep.map((k) => [k, h[k]]));
  data.holds[0].expires_at = `${new Date(readTime(h.held_at)!.getTime() + 24 * HOUR).toISOString().slice(0, 19)}Z`;
  data.holds[0].hint = hint;
  data.version = 1;
  writeFileSync(file, JSON.stringify(data));
}

const noticeCmd = (verb: string) => `{${verb}}`;
const grantsFile = () => JSON.parse(readFileSync(path.join(stateDir, "grants.json"), "utf8")).grants;

// ---- where the notice goes ------------------------------------------------------------------------------

test("/sentrook-notify here from the owner's direct message records that chat", async () => {
  const r = registered();
  assert.match(await r.command("sentrook-notify", "status"), /^Held-call notices are not sent: no notify target is set/);
  assert.equal(await r.command("sentrook-notify", "here"), "Held-call notices now go to you by a direct message on telegram.");
  const saved = JSON.parse(readFileSync(path.join(stateDir, "notify.json"), "utf8")).target;
  assert.deepEqual(
    { channel: saved.channel, to: saved.to, accountId: saved.accountId, basis: saved.set_by.basis },
    { channel: "telegram", to: "100200300", accountId: "default", basis: ["sender_is_owner"] },
  );
  assert.equal(await r.command("sentrook-notify", "status"), "Held-call notices go by a direct message on telegram.");
  const [rec] = r.records("notify");
  assert.equal(rec.op, "notify_here");
  assert.ok(!JSON.stringify(rec).includes("100200300"), "the recipient id is not logged");
  assert.equal(await r.command("sentrook-notify", "off"), "Held-call notices are off; held calls still wait for /sentrook-allow or /sentrook-deny.");
  assert.match(await r.command("sentrook-notify", "status"), /not sent/);
});

test("/sentrook-notify here from the Control UI has no chat to record", async () => {
  const r = registered();
  const ui = { ...DM, senderId: "", channel: "webchat", gatewayClientScopes: ["operator.admin"] };
  assert.match(await r.command("sentrook-notify", "here", ui), /^Run \/sentrook-notify here as a direct message/);
});

test("/sentrook-notify and the answers to a hold are owner commands like the others", async () => {
  const r = registered();
  for (const name of ["sentrook-notify", "sentrook-approve", "sentrook-allow", "sentrook-deny", "sentrook-passes"]) {
    assert.deepEqual(r.commands[name].requiredScopes, ["operator.admin"]);
    assert.match(await r.command(name, "here", { ...DM, senderIsOwner: false }), /^Only the owner can run/);
  }
});

// ---- must hold, not block -----------------------------------------------------------------------------

test("a scheduled send at risk 47 is held, the agent told not to retry, and the owner told once", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  const { out, rec } = await r.send("cron");
  assert.deepEqual(out, { block: true, blockReason: FIXTURES.held_text });
  assert.equal(rec.verdict, "review");
  assert.equal(rec.decision, "held");
  const [entry] = holds();
  // OpenClaw names no cron job for this run (only the prompt's tag does): allow only, bound to the exact call
  assert.deepEqual(rec.hold, { id: entry.id, expires_at: entry.expires_at, hint: false, offers: ["allow"], notice: { status: "queued", target: "telegram" } });
  assert.equal(readTime(entry.expires_at)!.getTime() - readTime(entry.held_at)!.getTime(), 7 * 24 * HOUR);
  assert.equal(entry.request_id, rec.request_id);
  assert.equal(entry.v, 2);
  assert.ok(!JSON.stringify(entry).includes("Daily brief"), "the store keeps no raw arguments");
  // OpenClaw names no job for this run: the prompt's tag alone never names the job a hold's answers are bound to
  const where = `scheduled run, session ${rec.session_ref}`;
  assert.equal(entry.where, where);
  assert.equal(r.sent.length, 1);
  const [notice] = r.sent;
  assert.deepEqual({ channel: notice.channel, to: notice.to, accountId: notice.accountId }, { channel: "telegram", to: "100200300", accountId: "default" });
  const text = hold.noticeText({ ...SEND.response, ...reply }, "message", where, entry.id, ["allow"], (v) => `/sentrook-${v}`, null);
  assert.equal(notice.text, text);
  assert.match(formatHistory(recentScans(path.join(stateDir, "traffic.jsonl"), 1), "w"), / held +no answer$/m);
});

test("the held call did not run and the next scan sends it as an unanswered review", async () => {
  const r = registered();
  const { ctx } = await r.send("cron");
  await r.fire("after_tool_call", { toolName: "message", toolCallId: "c1", runId: ctx.runId, error: "held" }, ctx);
  reply = { risk: 5 };
  await r.send("cron", "cron-1", "c2");
  const [first] = scans.at(-1).history;
  assert.equal(first.decision, "review_timed_out");
  assert.deepEqual(first.result, { status: "error", size_bytes: 0 });
  assert.deepEqual(scans.at(-1).new_inputs, []);
});

test("with no notify target the call is still held and the notice logged as unsent", async () => {
  const r = registered();
  const { out, rec } = await r.send("cron");
  assert.equal(out.blockReason, FIXTURES.held_text);
  assert.equal(rec.decision, "held");
  assert.deepEqual(rec.hold.notice, { status: "unsent", target: null, reason: hold.NOTIFY_UNSET });
  assert.equal(r.sent.length, 0);
  assert.ok(r.logs.some((m) => m.includes("held a call but sent no notice")));
  assert.match(await r.command("sentrook-notify", "status"), /not sent/);
});

test("without outbound adapters the notice is logged as unsent", async () => {
  const r = registered({}, null);
  await r.command("sentrook-notify", "here");
  const { rec } = await r.send("cron");
  assert.equal(rec.decision, "held");
  assert.deepEqual(rec.hold.notice, { status: "unsent", target: null, reason: "this OpenClaw has no outbound adapters for plugins" });
});

test("a notice the channel refuses is logged, and the call stays held", async () => {
  const r = registered({}, { loadAdapter: async () => ({ sendText: async () => Promise.reject(new Error("chat not found")) }) });
  await r.command("sentrook-notify", "here");
  const { rec } = await r.send("cron");
  assert.equal(rec.decision, "held");
  assert.ok(r.logs.some((m) => m.includes("held-call notice not delivered: Error: chat not found")));
});

// ---- approve -------------------------------------------------------------------------------------------

test("a hold from before v2 is approved as before: the suggested grant, persistent for 30 days", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  asV1({ ...HINT });
  // Only allow (or approve) answers it: a standing pass or a denial needs what a v2 hold keeps.
  for (const [name, args] of [["sentrook-deny", id], ["sentrook-allow", `${id} always`]] as const) {
    assert.ok((await r.command(name, args)).startsWith(`Held call ${id} was made by an earlier version`));
  }
  const answer = await r.command("sentrook-approve", id);
  assert.ok(answer.startsWith(`Approved ${id}. Granted gr-`), answer);
  assert.ok(answer.includes("(persistent, expires ") && answer.includes("The held call is not run again"));
  const [g] = grantsFile();
  assert.deepEqual([g.kind, g.pattern, g.scope, g.from_hold], ["destination", "discord:#ops-reports", "persistent", id]);
  assert.equal(readTime(g.expires_at)!.getTime() - readTime(g.granted_at)!.getTime(), 30 * 24 * HOUR);
  assert.deepEqual(g.set_by.basis, ["sender_is_owner"]);
  assert.deepEqual(holds(), []);
  const [res] = r.records("resolution");
  assert.deepEqual(
    [res.request_id, res.resolution, res.decision, res.hold_id, res.grant_id],
    [rec.request_id, "hold_approved", "held", id, g.id],
  );
  assert.deepEqual(r.records("grants").map((x) => x.op), ["grant"]);
  // The next run sends the grant; whether it relieves the call is the scanner's to decide.
  await r.send("cron", "cron-2", "c9");
  const sent = scans.at(-1).grants.filter((x: any) => x.pattern === "discord:#ops-reports");
  assert.deepEqual(sent, [
    { grant_ref: "g_1", kind: "destination", pattern: "discord:#ops-reports", scope: "persistent", granted_at: g.granted_at, expires_at: g.expires_at },
  ]);
  assert.ok((await r.command("sentrook-approve", id)).startsWith(`No held call ${id}`));
});

test("approve is allow: it sets a one-use pass, never the suggested grant", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  const file = path.join(stateDir, "holds.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.holds[0].hint = { ...HINT };
  writeFileSync(file, JSON.stringify(data));
  const answer = await r.command("sentrook-approve", id);
  assert.ok(answer.startsWith("The next identical call from an unattended run may go through once"), answer);
  assert.throws(() => grantsFile());
  const [res] = r.records("resolution");
  assert.deepEqual([res.resolution, res.hold_id, res.grant_id], ["hold_allowed", id, undefined]);
  assert.ok(answer.includes(res.pass_id));
});

test("a malformed or unknown id is refused", async () => {
  const r = registered();
  for (const bad of ["", "h-zzzzzz", "gr-1a2b3c", "h-1a2b3c h-1a2b3c"]) {
    assert.ok((await r.command("sentrook-approve", bad)).startsWith("usage: /sentrook-approve <id>"), bad);
  }
  assert.equal(await r.command("sentrook-approve", "h-abcdef"), "No held call h-abcdef: the id is unknown, already answered or expired.");
});

// ---- expiry --------------------------------------------------------------------------------------------

test("after 7 days the hold expires, an answer is refused and hold_expired is recorded once", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  const file = path.join(stateDir, "holds.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.holds[0].expires_at = `${new Date(Date.now() - 1000).toISOString().slice(0, 19)}Z`;
  writeFileSync(file, JSON.stringify(data));
  assert.equal(
    await r.command("sentrook-allow", id),
    `Held call ${id} expired: a hold can be answered for 7 days. Nothing was set; the next run is scanned as before.`,
  );
  const [res] = r.records("resolution");
  assert.deepEqual([res.request_id, res.resolution, res.decision, res.hold_id], [rec.request_id, "hold_expired", "held", id]);
  assert.deepEqual(holds(), []);
  assert.ok((await r.command("sentrook-approve", id)).startsWith(`No held call ${id}`));
  assert.equal(r.records("resolution").length, 1);
});

test("expiry is exactly 7 days and recorded when the holds next change", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-hold-unit-"));
  const t0 = new Date("2026-11-16T09:00:00Z");
  const log: any[] = [];
  const { id } = hold.create(
    dir,
    { requestId: "r1", sessionRef: "s_0a1b2c3d4e5f", tool: "message", where: "session s_0a1b2c3d4e5f", hint: null, notice: { status: "queued" } },
    t0,
    (x) => log.push(x),
  );
  const DAYS = 7 * 24 * HOUR;
  assert.equal(hold.waiting(dir, new Date(t0.getTime() + DAYS - 1000)), 1);
  assert.equal(hold.waiting(dir, new Date(t0.getTime() + DAYS)), 0);
  assert.equal(log.length, 0);
  hold.sweep(dir, new Date(t0.getTime() + DAYS), (x) => log.push(x));
  assert.deepEqual(log.map((x) => [x.resolution, x.hold_id]), [["hold_expired", id]]);
  const by = { basis: ["sender_is_owner"], channel: "telegram", sender_ref: null };
  const answer = await hold.answer(dir, "allow", id!, by, new Date(t0.getTime() + DAYS + HOUR), (s) => `/sentrook-${s}`, (x) => log.push(x), () => undefined);
  assert.ok(answer.reply.startsWith(`No held call ${id}`));
});

test("status counts waiting holds and says where notices go", async () => {
  const { runSentrookCommand } = await import("./commands.ts");
  const r = registered();
  const status = () => runSentrookCommand("status", { pluginConfig: {}, env: process.env });
  assert.match(await status(), /^held calls: 0 waiting; notices not sent \(no notify target is set/m);
  await r.command("sentrook-notify", "here");
  await r.send("cron");
  assert.match(await status(), /^held calls: 1 waiting; notices by a direct message on telegram$/m);
});

// ---- must still block, and attended runs are unchanged ----------------------------------------------------

for (const c of FIXTURES.outcomes) {
  for (const attended of [true, false]) {
    test(`${c.name}, ${attended ? "attended" : "unattended"}: ${attended ? c.attended : c.unattended}`, async () => {
      const r = registered();
      await r.command("sentrook-notify", "here");
      reply = { risk: c.risk, enforced: c.enforced, ceiling: c.ceiling ?? null, reasons: (c.reasons ?? []).map((code) => ({ code })) };
      const { out, rec } = await r.send(attended ? "user" : "cron");
      const want = attended ? c.attended : c.unattended;
      if (want === "allow") {
        assert.equal(out, undefined);
        assert.equal(rec.decision, "allowed");
      } else if (want === "review") {
        assert.ok(out.requireApproval);
        assert.equal(rec.decision, "review_timed_out");
      } else if (want === "block") {
        assert.equal(out.block, true);
        assert.match(out.blockReason, /^Sentrook security block:/);
        assert.equal(rec.decision, "blocked");
      } else {
        assert.deepEqual(out, { block: true, blockReason: FIXTURES.held_text });
        assert.equal(rec.decision, "held");
      }
      assert.equal(rec.decision === "held", "hold" in rec);
      assert.equal(r.sent.length, want === "held" ? 1 : 0);
    });
  }
}

test("observe mode holds nothing", async () => {
  const r = registered({ mode: "observe" });
  const { out, rec } = await r.send("cron");
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed");
  assert.equal(r.sent.length, 0);
});

// ---- the shared texts -------------------------------------------------------------------------------------

test("notice text: the shared text for each case", () => {
  for (const c of FIXTURES.notices) {
    const jobId = c.where.job_id;
    const src = c.where.source ? passes.sourceOf(c.where.source.kind, c.where.source.value) : null;
    const where = hold.whereText(c.where.run, c.where.session_ref, c.where.job_id, c.where.job_name, src);
    assert.equal(where, c.where_text, c.name);
    const match = passes.matchOf(c.tool, c.response, {}, "salt", jobId === null && src === null);
    const offers = passes.offers(jobId, passes.offeredLevel(c.response), match.named, passes.riskOf(c.response), FIXTURES.block_at, !!(c as { acted?: boolean }).acted, src !== null);
    assert.deepEqual(offers, c.offers, c.name);
    const scope = jobId !== null ? "job" : (src?.kind ?? null);
    assert.equal(hold.noticeText(c.response, c.tool, where, c.id, offers, noticeCmd, scope), c.text, c.name);
  }
});

test("a suggested grant passes the grant command's rules", () => {
  for (const c of FIXTURES.hints) assert.deepEqual(grants.hintGrant(c.hint), c.grant, JSON.stringify(c.hint));
});

test("history columns for held scans", () => {
  for (const c of FIXTURES.history) {
    const scan = { verdict: "review", decision: c.decision, mode: "enforce", response: { risk: 47 } };
    const res = c.resolution ? { resolution: c.resolution } : null;
    const action = actionOf(scan, res);
    assert.deepEqual([action, reviewOf(action, res)], [c.action, c.review], c.name);
  }
});

// ---- two processes at once -------------------------------------------------------------------------------

/** Runs `count` holds in a separate node process, starting at `startAt` (ms since the epoch). */
function holdInChild(dir: string, script: string, label: string, count: number, startAt: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", script, dir, label, String(count), String(startAt)], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let err = "";
    child.stderr.on("data", (d) => (err += String(d)));
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`child ${label} exited ${code}: ${err}`))));
  });
}

test("two processes holding calls at the same time keep every hold", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-hold-race-"));
  const script = path.join(dir, "child.ts");
  writeFileSync(
    script,
    `import * as hold from ${JSON.stringify(pathToFileURL(path.resolve("hold.ts")).href)};
const [dir, label, count, startAt] = process.argv.slice(2);
while (Date.now() < Number(startAt)) {}
for (let i = 0; i < Number(count); i++) {
  hold.create(dir, { requestId: label + "-" + i, sessionRef: "s_" + label, tool: "message", where: label, hint: null, notice: {} }, new Date(), () => {});
}
`,
  );
  const startAt = Date.now() + 800;
  await Promise.all([holdInChild(dir, script, "a", 40, startAt), holdInChild(dir, script, "b", 40, startAt)]);
  const kept = JSON.parse(readFileSync(path.join(dir, "holds.json"), "utf8")).holds.map((h: any) => h.request_id).sort();
  const want = ["a", "b"].flatMap((l) => Array.from({ length: 40 }, (_, i) => `${l}-${i}`)).sort();
  assert.deepEqual(kept, want);
  assert.equal(existsSync(path.join(dir, "holds.json.lock")), false);
});

const WAITER = (store: string) => `import { appendFileSync } from "node:fs";
import { withFileLock } from ${JSON.stringify(store)};
const [file, log, label, startAt, rounds] = process.argv.slice(2);
while (Date.now() < Number(startAt)) {}
for (let i = 0; i < Number(rounds); i++) {
  for (;;) {
    try {
      withFileLock(file, () => {
        appendFileSync(log, "in " + label + "\\n");
        const until = Date.now() + 5;
        while (Date.now() < until) {}
        appendFileSync(log, "out " + label + "\\n");
      });
      break;
    } catch (err) {
      if (!String(err).includes("locked by another process")) throw err;
    }
  }
}
`;

/** A process that takes the lock and then never lets go, until it is killed. */
const CRASHER = (store: string) => `import { withFileLock } from ${JSON.stringify(store)};
withFileLock(process.argv[2], () => {
  process.stdout.write("held\\n");
  const until = Date.now() + 60_000;
  while (Date.now() < until) {}
});
`;

function child(script: string, args: string[], onStdout?: (s: string) => void) {
  const proc = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", script, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  proc.stderr.on("data", (d) => (err += String(d)));
  if (onStdout) proc.stdout.on("data", (d) => onStdout(String(d)));
  const done = new Promise<number | null>((resolve) => proc.on("exit", (code) => resolve(code)));
  return { proc, done, err: () => err };
}

test("three processes after a holder crashed never hold the lock at once, round after round", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-lock-three-"));
  const store = pathToFileURL(path.resolve("store.ts")).href;
  const waiter = path.join(dir, "waiter.ts");
  const crasher = path.join(dir, "crasher.ts");
  writeFileSync(waiter, WAITER(store));
  writeFileSync(crasher, CRASHER(store));
  const file = path.join(dir, "holds.json");
  for (let round = 0; round < 3; round++) {
    // A holder that dies holding the lock: the system releases it with the process.
    let crashed!: ReturnType<typeof child>;
    await new Promise<void>((resolve) => {
      crashed = child(crasher, [file], (out) => out.includes("held") && resolve());
    });
    crashed.proc.kill("SIGKILL");
    await crashed.done;
    const log = path.join(dir, `log-${round}`);
    const startAt = Date.now() + 600;
    const runs = ["a", "b", "c"].map((label) => child(waiter, [file, log, label, String(startAt), "8"]));
    const codes = await Promise.all(runs.map((r) => r.done));
    assert.deepEqual(codes, [0, 0, 0], runs.map((r) => r.err()).join("\n"));
    const lines = readFileSync(log, "utf8").trim().split("\n");
    assert.equal(lines.length, 48);
    for (let i = 0; i < lines.length; i += 2) {
      assert.ok(lines[i]!.startsWith("in ") && lines[i + 1] === `out ${lines[i]!.slice(3)}`, `round ${round}: ${lines.join(" | ")}`);
    }
  }
});

test("a hold whose file is locked still holds, and the notice is logged unsent", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  mkdirSync(stateDir, { recursive: true });
  // Another process holds the holds file's lock for as long as this scan waits.
  const other = new DatabaseSync(path.join(stateDir, "holds.json.lockdb"));
  other.exec("BEGIN EXCLUSIVE");
  let sent;
  try {
    sent = await r.send("cron");
  } finally {
    other.exec("ROLLBACK");
    other.close();
  }
  const { out, rec, ctx } = sent;
  assert.deepEqual(out, { block: true, blockReason: FIXTURES.held_text });
  assert.equal(rec.decision, "held");
  assert.deepEqual(rec.hold, { id: null, expires_at: null, hint: false, offers: [], notice: { status: "unsent", target: null, reason: "holds file locked" } });
  assert.equal(r.sent.length, 0);
  // The session history has the held call too.
  reply = { risk: 5 };
  await r.fire("after_tool_call", { toolName: "message", toolCallId: "c1", runId: ctx.runId, error: "held" }, ctx);
  await r.send("cron", "cron-1", "c2");
  assert.equal(scans.at(-1).history[0].decision, "review_timed_out");
});

test("approving a v1 hold keeps it when the grant cannot be written", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  asV1({ ...HINT });
  writeFileSync(path.join(stateDir, "grants.json"), "{not json");
  const answer = await r.command("sentrook-approve", id);
  assert.ok(answer.startsWith("Not approved: The grants file ") && answer.includes(`${id} is still waiting`), answer);
  assert.deepEqual(holds().map((h: any) => h.id), [id]);
  assert.equal(r.records("resolution").length, 0);
  rmSync(path.join(stateDir, "grants.json"));
  assert.ok((await r.command("sentrook-approve", id)).startsWith(`Approved ${id}. Granted gr-`));
  assert.deepEqual(holds(), []);
});

// ---- what the notice carries ---------------------------------------------------------------------------

const CANARY = "CANARY-not-a-real-secret-4471";
const NOTICE_ABSENT = ["47", "risk", "send.unbound_channel", "exfil", "Scores", "suspicion", "consequence", "~/.config/ops/token", "path", CANARY, "brief, key", "grant"];

// The strings from NOTICE_ABSENT found in a notice, after taking out the hold id and session ref: both are
// random, and either can contain "47" (the risk score the test sets) by chance.
function leaked(text: string, ids: string[]): string[] {
  const rest = ids.reduce((t, id) => t.replaceAll(id, "<id>"), text);
  return NOTICE_ABSENT.filter((s) => rest.includes(s));
}

test("the leak check ignores digits inside the hold id and session ref, and still finds the risk score", () => {
  const text = "To approve: /sentrook-approve h-a47b00\nsession s_1f47c9";
  assert.deepEqual(leaked(text, ["h-a47b00", "s_1f47c9"]), []);
  assert.deepEqual(leaked(`${text}\nrisk 47`, ["h-a47b00", "s_1f47c9"]), ["47", "risk"]);
  assert.deepEqual(leaked(`${text}\nscore 47`, ["h-a47b00", "s_1f47c9"]), ["47"]);
});

test("the notice carries only the minimal fields: no risk, reasons, scores, entities, arguments or secrets", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  reply = {
    risk: 47,
    reasons: [{ code: "send.unbound_channel" }, { code: "exfil.exec_egress" }],
    entities: { E1: { kind: "channel", display: "discord:#ops-reports" }, E2: { kind: "path", display: "~/.config/ops/token" } },
  };
  const runId = "r-cron-9";
  const ctx = { sessionKey: "agent:main:cron:cron-9", sessionId: "cron-9", agentId: "main", runId, trigger: "cron" };
  await r.fire("before_prompt_build", { runId, prompt: "[cron:abc daily-brief] post the brief" }, ctx);
  await r.fire(
    "before_tool_call",
    { toolName: "message", toolCallId: "c1", runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: `brief, key ${CANARY}` } },
    ctx,
  );
  await hold.waitForNotices();
  const rec = r.records("scan").at(-1);
  const id = rec.hold.id;
  assert.equal(
    r.sent[0].text,
    "Sentrook held a tool call on an unattended run; it did not run.\n" +
      `Run: scheduled run, session ${rec.session_ref}\n` +
      "Tool: message: Sends a message to discord:#ops-reports\n" +
      "Held because it sends data to a destination outside this machine.\n" +
      "Reply within 7 days:\n" +
      `- let this exact call through once, within 7 days: /sentrook-allow ${id}\n` +
      `For the reasons: /sentrook-why ${id}`,
  );
  assert.deepEqual(leaked(r.sent[0].text, [id, rec.session_ref]), []);
});

test("/sentrook-why with a hold id gives the owner the reasons", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  const why = await r.command("sentrook-why", id);
  assert.ok(why.startsWith(`scan: ${rec.request_id}`), why);
  assert.ok(why.includes("risk: 47") && why.includes("reasons: trigger.scheduled, send.unbound_channel"), why);
  assert.ok(why.includes("action: held") && why.includes("review: no answer"), why);
  assert.ok(why.includes("hold: waiting, until ") && why.includes("answers: allow"), why);
  assert.ok(!why.includes("suggested grant"), why);
  await r.command("sentrook-allow", id);
  assert.ok((await r.command("sentrook-why", id)).endsWith("hold: answered or expired"));
  assert.equal(await r.command("sentrook-why", "h-abcdef"), "No held call h-abcdef in the recent traffic log.");
  assert.match(await r.command("sentrook-why", id, { ...DM, senderIsOwner: false }), /^Only the owner can run/);
});

// ---- the notify target ---------------------------------------------------------------------------------

test("/sentrook-notify here refuses a group or channel, and a message with no sender", async () => {
  const r = registered();
  // A room, by its session key or reply address: refused like every owner command.
  for (const ctx of [
    { ...DM, sessionKey: "agent:main:telegram:group:-1002003004" },
    { ...DM, channel: "discord", sessionKey: "agent:main:main", to: "channel:1498333845953712258" },
  ]) {
    assert.equal(await r.command("sentrook-notify", "here", ctx), roomRefusal("notify"));
  }
  // A sender that is a channel: notify's own rule, a notice goes to one person.
  assert.match(
    await r.command("sentrook-notify", "here", { ...DM, channel: "discord", senderId: "channel:1498333845953712258", sessionKey: "agent:main:main" }),
    /not in a group or channel/,
  );
  assert.match(await r.command("sentrook-notify", "here", { ...DM, senderId: "", from: "telegram:100200300" }), /did not say who sent this/);
  assert.equal(existsSync(path.join(stateDir, "notify.json")), false);
});

test("/sentrook-notify here on Discord records the user: form", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here", { ...DM, channel: "discord", senderId: "811122233344455566", sessionKey: "agent:main:discord:direct:811122233344455566" });
  const saved = JSON.parse(readFileSync(path.join(stateDir, "notify.json"), "utf8")).target;
  assert.equal(saved.to, "user:811122233344455566");
});

test("a thread is kept only for a direct message on Telegram or Slack", () => {
  const by = {};
  const now = new Date();
  const t = (ctx: hold.NotifyContext) => hold.targetOf(ctx, by, now) as any;
  assert.equal(t({ ...DM, messageThreadId: 7 }).threadId, 7);
  assert.equal(t({ ...DM, channel: "slack", senderId: "U01ABCDEF", sessionKey: "agent:main:slack:direct:u01abcdef", messageThreadId: 1730000000.1 }).threadId, "1730000000.1");
  assert.equal(t({ ...DM, sessionKey: "agent:main:main", messageThreadId: 7 }).threadId, undefined); // cannot tell
  assert.equal(t({ ...DM, channel: "discord", senderId: "811122233344455566", messageThreadId: "9" }).threadId, undefined);
  assert.equal(t({ ...DM, sessionKey: "agent:main:main" }).to, "100200300");
});

// ---- run identity, retried approvals, malformed responses ------------------------------------------------

test("a cron marker in the prompt names a job only on a run the host calls a cron run", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  const scan = async (trigger: string, sid: string) => {
    const runId = `r-${sid}`;
    const ctx = { sessionKey: `agent:main:${sid}`, sessionId: sid, agentId: "main", runId, trigger };
    await r.fire("before_prompt_build", { runId, prompt: "[cron:9f1c2a approve-all] post the brief" }, ctx);
    const out = await r.fire(
      "before_tool_call",
      { toolName: "message", toolCallId: `c-${sid}`, runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: "x" } },
      ctx,
    );
    await hold.waitForNotices();
    return { out, rec: r.records("scan").at(-1) };
  };
  // An attended run whose prompt starts with the marker is asked about, not held or labelled.
  const attended = await scan("user", "chat-1");
  assert.ok(attended.out.requireApproval);
  assert.equal(attended.rec.hold, undefined);
  // An unattended run that is not a cron run keeps its own label.
  const beat = await scan("heartbeat", "beat-1");
  assert.equal(beat.rec.decision, "held");
  assert.equal(holds().at(-1).where, `heartbeat run, agent "main", session ${beat.rec.session_ref}`);
  assert.ok(!r.sent.at(-1).text.includes("9f1c2a"));
});

test("a webhook or event run (trigger event) is unattended: a review is held and labelled", async () => {
  // Must fire: OpenClaw starts webhook, mapped-hook and channel-join runs with trigger "event"; nobody can answer there.
  const r = registered();
  await r.command("sentrook-notify", "here");
  const { out, rec } = await r.send("event", "hook-1");
  assert.equal(scans.at(-1).trigger.kind, "hook");
  assert.deepEqual(out, { block: true, blockReason: FIXTURES.held_text });
  assert.equal(rec.decision, "held");
  assert.equal(holds().at(-1).where, `webhook or event run, session ${rec.session_ref}`);
  assert.equal(r.sent.length, 1);
});

test("only the event trigger becomes a hook run: chat, cron, heartbeat and others keep their kinds", async () => {
  // Must stay silent: a chat still asks; cron and heartbeat are still held; manual, memory and no trigger are unchanged.
  const r = registered();
  await r.command("sentrook-notify", "here");
  const chat = await r.send("user", "chat-1");
  assert.equal(scans.at(-1).trigger.kind, "message");
  assert.ok(chat.out.requireApproval, "a chat run asks");
  const kinds: Record<string, string> = { cron: "scheduled", heartbeat: "heartbeat", manual: "system", memory: "system" };
  for (const [trigger, kind] of Object.entries(kinds)) {
    const { rec } = await r.send(trigger, `run-${trigger}`);
    assert.equal(scans.at(-1).trigger.kind, kind, trigger);
    if (trigger === "cron" || trigger === "heartbeat") assert.equal(rec.decision, "held", trigger);
  }
  await r.send(undefined as unknown as string, "run-none");
  assert.equal(scans.at(-1).trigger.kind, "unknown");
});

test("a retried approve of a v1 hold after the holds file failed to save sets one grant", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  asV1({ ...HINT });
  const real = Store.prototype.saveHolds;
  let calls = 0;
  Store.prototype.saveHolds = function (this: Store, value) {
    calls += 1;
    if (calls === 1) throw new Error("disk full");
    return real.call(this, value);
  };
  let first: string;
  try {
    first = await r.command("sentrook-approve", id);
  } finally {
    Store.prototype.saveHolds = real;
  }
  assert.ok(first.startsWith("Not finished: Granted gr-") && first.includes(`approve ${id} again to finish`), first);
  assert.deepEqual(holds().map((h: any) => h.id), [id]);
  const second = await r.command("sentrook-approve", id);
  assert.ok(second.startsWith(`Approved ${id}. Granted gr-`), second);
  const [g] = grantsFile();
  assert.equal(grantsFile().length, 1);
  assert.equal(g.from_hold, id);
  assert.ok(first.includes(g.id) && second.includes(g.id));
  assert.equal(r.records("grants").length, 1);
  assert.deepEqual(r.records("resolution").map((x) => x.resolution), ["hold_approved"]);
  assert.deepEqual(holds(), []);
});

test("a malformed response still holds, with the traffic record written and the notice unsent", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  reply = { risk: 47, tool_description: { template: 42 } };
  const { out, rec } = await r.send("cron");
  assert.deepEqual(out, { block: true, blockReason: FIXTURES.held_text });
  assert.equal(rec.decision, "held");
  assert.deepEqual(rec.hold.notice, { status: "unsent", target: null, reason: "notice could not be built" });
  assert.equal(r.sent.length, 0);
});

// ---- scan failures on unattended runs -------------------------------------------------------------------

const VERIFY = "openclaw sentrook verify";

test("scan-failure notice text, reason and quiet key match the shared cases", () => {
  assert.equal(scanFailure.QUIET_MS, FIXTURES.scan_failure_quiet_hours * HOUR);
  for (const c of FIXTURES.scan_failure_reasons) {
    assert.equal(scanFailure.reasonOf({ ok: false, detail: "secret detail", ...c.failure } as any), c.reason, JSON.stringify(c.failure));
  }
  for (const c of FIXTURES.scan_failure_notices) {
    const where = hold.whereText(c.where.run, c.where.session_ref, c.where.job_id, c.where.job_name);
    assert.equal(where, c.where_text, c.name);
    assert.equal(scanFailure.quietKey(c.where.job_id, c.where.session_ref), c.quiet_key, c.name);
    const text = scanFailure.noticeText({ ok: false, detail: "secret detail", ...c.failure } as any, c.tool, where, c.where.job_id !== null, VERIFY);
    assert.equal(text, c.text.replace("{verify}", VERIFY), c.name);
    assert.ok(!text.includes("secret detail"), "the failure detail is not sent");
  }
});

/** One send from a cron run of job `job` (or another unattended `trigger`) in session `sid`. */
async function cronSend(r: ReturnType<typeof registered>, sid: string, job: string | null = "abc", trigger = "cron") {
  const runId = `r-${sid}`;
  const ctx = { sessionKey: `agent:main:cron:${sid}`, sessionId: sid, agentId: "main", runId, trigger };
  await r.fire("before_prompt_build", { runId, prompt: job ? `[cron:${job} daily-brief] post the brief` : "post the brief" }, ctx);
  const out = await r.fire(
    "before_tool_call",
    { toolName: "message", toolCallId: `c-${sid}`, runId, params: { action: "send", channel: "discord", target: "#ops-reports", message: "x" } },
    ctx,
  );
  await hold.waitForNotices();
  return { out, rec: r.records("scan").at(-1) };
}

test("a scan failure on an unattended run blocks the call and tells the owner once per job for 6 hours", async () => {
  // Must fire: the first failure in a job is announced; repeats in the same job are blocked quietly; another job is
  // announced; after the quiet period the job is announced again.
  const r = registered();
  await r.command("sentrook-notify", "here");
  unreachable = true;
  const first = await cronSend(r, "cron-1");
  assert.equal(first.out.block, true);
  assert.equal(first.rec.decision, "blocked_on_error");
  assert.deepEqual(first.rec.notice, { status: "queued", target: "telegram" });
  assert.equal(r.sent.length, 1);
  const where = `cron job abc, job name "daily-brief", session ${first.rec.session_ref}`;
  assert.equal(r.sent[0].text, scanFailure.noticeText({ ok: false, kind: "network", detail: "" }, "message", where, true, VERIFY));
  assert.deepEqual({ channel: r.sent[0].channel, to: r.sent[0].to }, { channel: "telegram", to: "100200300" });
  assert.match(r.sent[0].text, /not announced for 6 hours/);
  assert.ok(!/approve/i.test(r.sent[0].text), "nothing to approve: the call was not held");

  const again = await cronSend(r, "cron-2");
  assert.equal(again.out.block, true);
  assert.deepEqual(again.rec.notice, { status: "quiet" });
  assert.equal(r.sent.length, 1, "the same job in its quiet period sends nothing");

  await cronSend(r, "cron-3", "xyz");
  assert.equal(r.sent.length, 2, "another job is announced");

  const file = path.join(stateDir, "scan-failure-notices.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.sent["job:abc"] = new Date(Date.now() - 6 * HOUR - 60_000).toISOString();
  writeFileSync(file, JSON.stringify(data));
  await cronSend(r, "cron-4");
  assert.equal(r.sent.length, 3, "after 6 hours the job is announced again");
  assert.ok(!existsSync(path.join(stateDir, "holds.json")) || holds().length === 0, "a scan failure holds nothing");
});

test("an unattended run with no cron job is quieted by its session", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  unreachable = true;
  await cronSend(r, "beat-1", null, "heartbeat");
  await cronSend(r, "beat-1", null, "heartbeat");
  assert.equal(r.sent.length, 1);
  assert.match(r.sent[0].text, /^Run: heartbeat run, session /m);
  assert.match(r.sent[0].text, /in this session are not announced/);
  await cronSend(r, "beat-2", null, "heartbeat");
  assert.equal(r.sent.length, 2, "another session is announced");
});

test("with no notify target the failure is still blocked, logged unsent, and announced once a target is set", async () => {
  const r = registered();
  unreachable = true;
  const first = await cronSend(r, "cron-1");
  assert.equal(first.out.block, true);
  assert.deepEqual(first.rec.notice, { status: "unsent", target: null, reason: hold.NOTIFY_UNSET });
  await r.command("sentrook-notify", "here");
  await cronSend(r, "cron-2");
  assert.equal(r.sent.length, 1, "an unsent notice does not start the quiet period");
});

test("scan failures send no notice when attended, in observe mode, or when the scan answers", async () => {
  // Must stay silent: an attended failure asks; observe mode lets the call run; a usable answer is unaffected, and an
  // unattended review keeps its own hold notice.
  const r = registered();
  await r.command("sentrook-notify", "here");
  unreachable = true;
  const chat = await r.send("user", "chat-1");
  assert.ok(chat.out.requireApproval);
  assert.equal(chat.rec.notice, undefined);
  assert.equal(r.sent.length, 0);
  unreachable = false;
  reply = { risk: 5, enforced: null };
  const ok = await cronSend(r, "cron-ok");
  assert.equal(ok.out, undefined);
  assert.equal(ok.rec.notice, undefined);
  reply = { risk: 47, enforced: null };
  const held = await cronSend(r, "cron-held");
  assert.equal(held.rec.decision, "held");
  assert.equal(r.sent.length, 1);
  assert.match(r.sent[0].text, /^Sentrook held a tool call/);
});

test("observe mode sends no scan-failure notice", async () => {
  process.env.SENTROOK_MODE = "observe";
  const r = registered();
  await r.command("sentrook-notify", "here");
  unreachable = true;
  const { out, rec } = await cronSend(r, "cron-1");
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed_on_error");
  assert.equal(rec.notice, undefined);
  assert.equal(r.sent.length, 0);
});

test("a notice that cannot be delivered does not quiet the job", async () => {
  let attempts = 0;
  const failing = {
    loadAdapter: async () => ({
      sendText: async () => {
        attempts += 1;
        throw new Error("channel down");
      },
    }),
  };
  const r = registered({}, failing);
  await r.command("sentrook-notify", "here");
  unreachable = true;
  const first = await cronSend(r, "cron-1");
  assert.equal(first.out.block, true);
  await cronSend(r, "cron-2");
  assert.equal(attempts, 2, "the second failure tries again");
  assert.ok(r.logs.some((l) => l.includes("scan-failure notice not delivered")));
});

test("only a block on an unattended run is announced, whatever the scan-error policy", async () => {
  // Must stay silent: deny in a chat blocks without a notice; allow on an unattended run lets the call run; a usable
  // block is a security block, not a scan failure. Must fire: bad credentials still block under allow, and notify.
  const deny = registered({ onScanError: "deny" });
  await deny.command("sentrook-notify", "here");
  unreachable = true;
  const chat = await deny.send("user", "chat-1");
  assert.equal(chat.out.block, true);
  assert.equal(chat.rec.notice, undefined);
  assert.equal(deny.sent.length, 0);
  unreachable = false;
  reply = { risk: 92, enforced: null };
  const blocked = await cronSend(deny, "cron-block");
  assert.equal(blocked.out.block, true);
  assert.equal(blocked.rec.decision, "blocked");
  assert.equal(blocked.rec.notice, undefined);
  assert.equal(deny.sent.length, 0);

  const allow = registered({ onScanError: "allow" });
  await allow.command("sentrook-notify", "here");
  unreachable = true;
  const ran = await cronSend(allow, "cron-allow");
  assert.equal(ran.out, undefined);
  assert.equal(ran.rec.notice, undefined);
  assert.equal(allow.sent.length, 0);
  unreachable = false;
  unauthorized = true;
  const creds = await cronSend(allow, "cron-creds", "def");
  assert.equal(creds.out.block, true);
  assert.deepEqual(creds.rec.notice, { status: "queued", target: "telegram" });
  assert.equal(allow.sent.length, 1);
  assert.match(allow.sent[0].text, /^Reason: Sentrook's endpoint or credentials are not configured correctly\.$/m);
});

// ---- consent withdrawn on the FIDU portal ----------------------------------------------------------------

/** The identity service starts refusing the credentials; a token already issued would last until it expires. */
function withdraw() {
  withdrawn = true;
  clearScanTokenCache();
  scans = [];
}

test("after consent is withdrawn the owner is told once, not again after a restart", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  withdraw();
  const first = await cronSend(r, "cron-1");
  assert.equal(first.out.block, true);
  assert.equal(first.rec.decision, "blocked_on_error");
  assert.deepEqual(first.rec.notice, { status: "queued", target: "telegram" });
  assert.deepEqual(r.sent.map((m) => m.text), [CONSENT_NOTICE]);
  assert.deepEqual(scans, [], "nothing is sent to the scan service without a token");
  const again = await cronSend(r, "cron-2");
  assert.deepEqual(again.rec.notice, { status: "quiet" });
  await cronSend(r, "cron-3", "xyz");
  const restarted = registered();
  await cronSend(restarted, "cron-4");
  assert.equal(r.sent.length + restarted.sent.length, 1);
});

test("after consent is withdrawn enforce mode still asks when attended and blocks when not", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  withdraw();
  const chat = await r.send("user", "chat-1");
  assert.ok(chat.out.requireApproval);
  assert.match(chat.out.requireApproval.description, new RegExp(`^${ERROR_CAUSES.consent_withdrawn}\n`));
  assert.equal(chat.rec.decision, "blocked_on_error");
  assert.deepEqual(chat.rec.notice, { status: "queued", target: "telegram" });
  const cron = await cronSend(r, "cron-1");
  assert.deepEqual(cron.out, { block: true, blockReason: SIGN_IN_FIXES.consent_withdrawn });
  assert.deepEqual(cron.rec.notice, { status: "quiet" }, "no scan-failure notice on top of the consent notice");
  assert.equal(r.sent.length, 1);
});

test("after consent is withdrawn onScanError allow still blocks", async () => {
  const r = registered({ onScanError: "allow" });
  withdraw();
  const chat = await r.send("user", "chat-1");
  assert.equal(chat.out.block, true);
});

test("after consent is withdrawn observe mode does not ask, and the owner is still told once", async () => {
  process.env.SENTROOK_MODE = "observe";
  const r = registered();
  await r.command("sentrook-notify", "here");
  withdraw();
  const chat = await r.send("user", "chat-1");
  assert.equal(chat.out, undefined);
  assert.equal(chat.rec.decision, "allowed_on_error");
  const cron = await cronSend(r, "cron-1");
  assert.equal(cron.out, undefined);
  assert.deepEqual(r.sent.map((m) => m.text), [CONSENT_NOTICE]);
});

test("signing in again or new credentials announce a later withdrawal", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  withdraw();
  await cronSend(r, "cron-1");
  await cronSend(r, "cron-2");
  assert.equal(r.sent.length, 1);
  process.env.SENTROOK_SCAN_CLIENT_ID = "client-2";
  await cronSend(r, "cron-3");
  assert.equal(r.sent.length, 2);
  consent.reset(stateDir); // what `openclaw sentrook login` does
  await cronSend(r, "cron-4");
  assert.equal(r.sent.length, 3);
});

test("a consent notice with nowhere to go is announced once a target is set", async () => {
  const r = registered();
  withdraw();
  const first = await cronSend(r, "cron-1");
  assert.deepEqual(first.rec.notice, { status: "unsent", target: null, reason: hold.NOTIFY_UNSET });
  await r.command("sentrook-notify", "here");
  const next = await cronSend(r, "cron-2");
  assert.deepEqual(next.rec.notice, { status: "queued", target: "telegram" });
});

test("other refused credentials send no consent notice", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  withdraw();
  tokenAnswer = { status: 401, body: { error: "invalid_client" } };
  const chat = await r.send("user", "chat-1");
  assert.match(chat.out.requireApproval.description, new RegExp(`^${ERROR_CAUSES.sign_in_rejected}\n`));
  assert.equal(chat.rec.notice, undefined);
  assert.ok(!existsSync(path.join(stateDir, consent.FILE)));
});

for (const missing of ["SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET"]) {
  test(`no scan request is made without ${missing}`, async () => {
    // Must stay silent: no token is asked for and no scan is sent, not even anonymously.
    process.env[missing] = "  ";
    const r = registered();
    const { out, rec } = await cronSend(r, "cron-1");
    assert.deepEqual(out, { block: true, blockReason: SIGN_IN_FIXES.not_signed_in });
    assert.equal(rec.failure.kind, "config");
    assert.deepEqual(requests, []);
    assert.deepEqual(scans, []);
  });
}
