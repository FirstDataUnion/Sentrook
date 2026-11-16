/**
 * Holds: a review on an unattended run waits for the owner, who is told once and may approve it.
 *
 * The agent is told the call is held and must not be retried in this run; the owner gets one notice as a
 * direct message where they ran `/sentrook-notify here`; `/sentrook-approve <id>` within 24 hours sets the
 * suggested grant (persistent, 30 days). Blocks stay blocks, and attended runs still get the host's approval
 * prompt. The texts are shared with the Hermes plugin's tests (`integrations/fixtures/hold`).
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import { formatHistory, recentScans, actionOf, reviewOf } from "./history.ts";
import * as hold from "./hold.ts";
import plugin from "./index.ts";
import * as grants from "./grants.ts";
import { readTime, withFileLock } from "./store.ts";

const FIXTURES = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/hold/cases.json", import.meta.url)), "utf8"),
) as {
  held_text: string;
  notices: {
    name: string;
    response: any;
    tool: string;
    where: { run: string; session_ref: string; job_id: string | null; job_name: string | null };
    where_text: string;
    id: string;
    text: string;
  }[];
  hints: { hint: unknown; grant: unknown }[];
  outcomes: { name: string; risk: number; enforced: string | null; attended: string; unattended: string }[];
  history: { name: string; decision: string; resolution: string | null; action: string; review: string }[];
};
const SEND = FIXTURES.notices[0]!;
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
  assert.equal(await r.command("sentrook-notify", "off"), "Held-call notices are off; held calls still wait for /sentrook-approve.");
  assert.match(await r.command("sentrook-notify", "status"), /not sent/);
});

test("/sentrook-notify here from the Control UI has no chat to record", async () => {
  const r = registered();
  const ui = { ...DM, senderId: "", channel: "webchat", gatewayClientScopes: ["operator.admin"] };
  assert.match(await r.command("sentrook-notify", "here", ui), /^Run \/sentrook-notify here as a direct message/);
});

test("/sentrook-notify and /sentrook-approve are owner commands like the others", async () => {
  const r = registered();
  for (const name of ["sentrook-notify", "sentrook-approve"]) {
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
  assert.deepEqual(rec.hold, { id: entry.id, expires_at: entry.expires_at, hint: false, notice: { status: "queued", target: "telegram" } });
  assert.equal(readTime(entry.expires_at)!.getTime() - readTime(entry.held_at)!.getTime(), 24 * HOUR);
  assert.equal(entry.request_id, rec.request_id);
  const where = `cron job abc, job name "daily-brief", session ${rec.session_ref}`;
  assert.equal(entry.where, where);
  assert.equal(r.sent.length, 1);
  const [notice] = r.sent;
  assert.deepEqual({ channel: notice.channel, to: notice.to, accountId: notice.accountId }, { channel: "telegram", to: "100200300", accountId: "default" });
  const text = hold.noticeText({ ...SEND.response, ...reply }, "message", where, entry.id, "/sentrook-approve", "/sentrook-why");
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

test("approve from the owner's direct message sets the suggested grant, persistent for 30 days", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  // The scan response suggests no grant yet; a hold that carries one is approved like this.
  const file = path.join(stateDir, "holds.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.holds[0].hint = { ...HINT };
  writeFileSync(file, JSON.stringify(data));
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

test("approve without a suggestion sets nothing and says so", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  assert.equal(
    await r.command("sentrook-approve", id),
    `Approved ${id}. Sentrook suggested no grant for this call, so nothing was set: the next run is scanned as ` +
      "before. To let it pass, add a grant with /sentrook-grant. The held call is not run again.",
  );
  assert.throws(() => grantsFile());
  const [res] = r.records("resolution");
  assert.deepEqual([res.resolution, res.hold_id, res.grant_id], ["hold_approved", id, undefined]);
});

test("a malformed or unknown id is refused", async () => {
  const r = registered();
  for (const bad of ["", "h-zzzzzz", "gr-1a2b3c", "h-1a2b3c h-1a2b3c"]) {
    assert.ok((await r.command("sentrook-approve", bad)).startsWith("usage: /sentrook-approve <id>"), bad);
  }
  assert.equal(await r.command("sentrook-approve", "h-abcdef"), "No held call h-abcdef: the id is unknown, already answered or expired.");
});

// ---- expiry --------------------------------------------------------------------------------------------

test("after 24 hours the hold expires, approve is refused and hold_expired is recorded once", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  const file = path.join(stateDir, "holds.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.holds[0].expires_at = `${new Date(Date.now() - 1000).toISOString().slice(0, 19)}Z`;
  writeFileSync(file, JSON.stringify(data));
  assert.equal(
    await r.command("sentrook-approve", id),
    `Held call ${id} expired: holds last 24 hours. Nothing was approved; the next run is scanned as before.`,
  );
  const [res] = r.records("resolution");
  assert.deepEqual([res.request_id, res.resolution, res.decision, res.hold_id], [rec.request_id, "hold_expired", "held", id]);
  assert.deepEqual(holds(), []);
  assert.ok((await r.command("sentrook-approve", id)).startsWith(`No held call ${id}`));
  assert.equal(r.records("resolution").length, 1);
});

test("expiry is exactly 24 hours and recorded when the holds next change", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-hold-unit-"));
  const t0 = new Date("2026-11-16T09:00:00Z");
  const log: any[] = [];
  const id = hold.create(
    dir,
    { requestId: "r1", sessionRef: "s_0a1b2c3d4e5f", tool: "message", where: "session s_0a1b2c3d4e5f", hint: null, notice: { status: "queued" } },
    t0,
    (x) => log.push(x),
  )!;
  assert.equal(hold.waiting(dir, new Date(t0.getTime() + 24 * HOUR - 1000)), 1);
  assert.equal(hold.waiting(dir, new Date(t0.getTime() + 24 * HOUR)), 0);
  assert.equal(log.length, 0);
  hold.sweep(dir, new Date(t0.getTime() + 24 * HOUR), (x) => log.push(x));
  assert.deepEqual(log.map((x) => [x.resolution, x.hold_id]), [["hold_expired", id]]);
  const by = { basis: ["sender_is_owner"], channel: "telegram", sender_ref: null };
  const answer = hold.approve(dir, id, by, new Date(t0.getTime() + 25 * HOUR), (s) => `/sentrook-${s}`, (x) => log.push(x), () => undefined);
  assert.ok(answer.startsWith(`No held call ${id}`));
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
      reply = { risk: c.risk, enforced: c.enforced };
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
    const where = hold.whereText(c.where.run, c.where.session_ref, c.where.job_id, c.where.job_name);
    assert.equal(where, c.where_text, c.name);
    assert.equal(hold.noticeText(c.response, c.tool, where, c.id, "{approve}", "{why}"), c.text, c.name);
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

test("two waiters racing a lock left over never both enter", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-lock-race-"));
  const lock = path.join(dir, "holds.json.lock");
  writeFileSync(lock, "99999:dead\n");
  const old = new Date(Date.now() - 60_000);
  utimesSync(lock, old, old);
  const log = path.join(dir, "log");
  const script = path.join(dir, "waiter.ts");
  writeFileSync(
    script,
    `import { appendFileSync } from "node:fs";
import { withFileLock } from ${JSON.stringify(pathToFileURL(path.resolve("store.ts")).href)};
const [file, log, label, startAt] = process.argv.slice(2);
while (Date.now() < Number(startAt)) {}
for (let i = 0; i < 5; i++) {
  withFileLock(file, () => {
    appendFileSync(log, "in " + label + "\\n");
    const until = Date.now() + 20;
    while (Date.now() < until) {}
    appendFileSync(log, "out " + label + "\\n");
  });
}
`,
  );
  const startAt = Date.now() + 800;
  const run = (label: string) =>
    new Promise<void>((resolve, reject) => {
      const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", script, path.join(dir, "holds.json"), log, label, String(startAt)], {
        stdio: ["ignore", "ignore", "pipe"],
      });
      let err = "";
      child.stderr.on("data", (d) => (err += String(d)));
      child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`waiter ${label} exited ${code}: ${err}`))));
    });
  await Promise.all([run("a"), run("b")]);
  const lines = readFileSync(log, "utf8").trim().split("\n");
  assert.equal(lines.length, 20);
  for (let i = 0; i < 20; i += 2) {
    assert.ok(lines[i]!.startsWith("in ") && lines[i + 1] === `out ${lines[i]!.slice(3)}`, lines.join(" | "));
  }
  assert.equal(existsSync(lock), false);
});

test("a holder releases only its own lock", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-lock-own-"));
  const lock = path.join(dir, "grants.json.lock");
  withFileLock(path.join(dir, "grants.json"), () => {
    // Taken over while held (as after a 30-second stall): the new holder's lock must survive this release.
    writeFileSync(lock, "4242:someone-else\n");
  });
  assert.equal(readFileSync(lock, "utf8"), "4242:someone-else\n");
});

test("a hold whose file is locked still holds, and the notice is logged unsent", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(path.join(stateDir, "holds.json.lock"), "4242:another-process\n");
  const { out, rec, ctx } = await r.send("cron");
  assert.deepEqual(out, { block: true, blockReason: FIXTURES.held_text });
  assert.equal(rec.decision, "held");
  assert.deepEqual(rec.hold, { id: null, expires_at: null, hint: false, notice: { status: "unsent", target: null, reason: "holds file locked" } });
  assert.equal(r.sent.length, 0);
  // The session history has the held call too.
  reply = { risk: 5 };
  await r.fire("after_tool_call", { toolName: "message", toolCallId: "c1", runId: ctx.runId, error: "held" }, ctx);
  await r.send("cron", "cron-1", "c2");
  assert.equal(scans.at(-1).history[0].decision, "review_timed_out");
});

test("approve keeps the hold when the grant cannot be written", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  const file = path.join(stateDir, "holds.json");
  const data = JSON.parse(readFileSync(file, "utf8"));
  data.holds[0].hint = { ...HINT };
  writeFileSync(file, JSON.stringify(data));
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
      `Run: cron job abc, job name "daily-brief", session ${rec.session_ref}\n` +
      "Tool: message: Sends a message to discord:#ops-reports\n" +
      "Held because it sends data to a destination outside this machine.\n" +
      `To approve within 24 hours: /sentrook-approve ${id}\n` +
      `For the reasons: /sentrook-why ${id}`,
  );
  for (const absent of ["47", "risk", "send.unbound_channel", "exfil", "Scores", "suspicion", "consequence", "~/.config/ops/token", "path", CANARY, "brief, key", "grant"]) {
    assert.ok(!r.sent[0].text.includes(absent), absent);
  }
});

test("/sentrook-why with a hold id gives the owner the reasons", async () => {
  const r = registered();
  const { rec } = await r.send("cron");
  const id = rec.hold.id;
  const why = await r.command("sentrook-why", id);
  assert.ok(why.startsWith(`scan: ${rec.request_id}`), why);
  assert.ok(why.includes("risk: 47") && why.includes("reasons: trigger.scheduled, send.unbound_channel"), why);
  assert.ok(why.includes("action: held") && why.includes("review: no answer"), why);
  assert.ok(why.includes("hold: waiting, until ") && why.includes("suggested grant: none"), why);
  await r.command("sentrook-approve", id);
  assert.ok((await r.command("sentrook-why", id)).endsWith("hold: answered or expired"));
  assert.equal(await r.command("sentrook-why", "h-abcdef"), "No held call h-abcdef in the recent traffic log.");
  assert.match(await r.command("sentrook-why", id, { ...DM, senderIsOwner: false }), /^Only the owner can run/);
});

// ---- the notify target ---------------------------------------------------------------------------------

test("/sentrook-notify here refuses a group or channel, and a message with no sender", async () => {
  const r = registered();
  for (const ctx of [
    { ...DM, sessionKey: "agent:main:telegram:group:-1002003004" },
    { ...DM, channel: "discord", sessionKey: "agent:main:main", to: "channel:1498333845953712258" },
    { ...DM, channel: "discord", senderId: "channel:1498333845953712258", sessionKey: "agent:main:main" },
  ]) {
    assert.match(await r.command("sentrook-notify", "here", ctx), /not in a group or channel/);
  }
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

test("a lock left by a process that died is taken over", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-hold-stale-"));
  const lock = path.join(dir, "holds.json.lock");
  writeFileSync(lock, "99999\n");
  const old = new Date(Date.now() - 60_000);
  utimesSync(lock, old, old);
  const id = hold.create(dir, { requestId: "r1", sessionRef: "s_x", tool: "message", where: "w", hint: null, notice: {} }, new Date(), () => {});
  assert.match(String(id), /^h-[0-9a-f]{6}$/);
  assert.equal(existsSync(lock), false);
});
