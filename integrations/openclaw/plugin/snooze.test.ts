import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import { helpText } from "./commands.ts";
import { actionOf, recentScans, reviewOf } from "./history.ts";
import plugin from "./index.ts";
import { refusal } from "./owner.ts";
import * as snooze from "./snooze.ts";

/**
 * Snooze: owner-only relief from review prompts, kept in `<state>/sentrook/snooze.json`.
 *
 * A snooze turns an attended review into an allow, for one session (the default) or every session,
 * for at most 24 hours. It never touches a block, a review the scanner enforces, or an unattended run.
 *
 * The fixture is shared with the Hermes plugin's tests: both hosts print the same text for the same
 * state. Its times are read at NOW; `S1` is the session its first entry belongs to.
 */
const FIXTURES = fileURLToPath(new URL("../../fixtures/snooze/", import.meta.url));
const NOW = new Date("2026-10-29T12:00:00Z");
const S1 = snooze.sessionRef("S1");
const golden = (name: string) => readFileSync(path.join(FIXTURES, name), "utf8").replace(/\n+$/, "");

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
let file = "";
let scans: any[] = [];

/** A fake scanner: risk from markers in the command; 500 on FAIL; ENFORCE enforces a review below the line. */
beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-snooze-"));
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
  file = path.join(stateDir, "snooze.json");
  scans = [];
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const reply = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return reply(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return reply(200, { access_token: "tok", expires_in: 600 });
    const planir = JSON.parse(String(init?.body));
    scans.push(planir);
    const cmd = String(planir.pending_call.arguments.command ?? "");
    if (cmd.includes("FAIL")) return reply(500, { error: { code: "boom" } });
    const risk = cmd.includes("EXFIL") ? 92 : cmd.includes("REVIEW") ? 55 : 5;
    return reply(200, {
      response_version: "2.0",
      request_id: planir.request_id,
      status: "ok",
      risk,
      enforced: cmd.includes("ENFORCE") ? "review" : null,
      reasons: [],
      state: "s",
    });
  }) as typeof fetch;
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  globalThis.fetch = realFetch;
});

/** Registers the plugin with fake host registrars: its chat commands, CLI actions and hooks. */
async function registered(pluginConfig: Record<string, unknown> = {}) {
  const commands: Record<string, any> = {};
  const cliActions: Record<string, (...args: unknown[]) => Promise<void> | void> = {};
  const on: Record<string, Array<(e: any, c: any) => any>> = {};
  const node = (prefix: string): any => {
    const self: any = {
      description: () => self,
      option: () => self,
      allowUnknownOption: () => self,
      command: (name: string) => node(`${prefix}${name} `),
      action: (fn: () => Promise<void>) => {
        cliActions[prefix.trim()] = fn;
        return self;
      },
    };
    return self;
  };
  let cliRegistrar: ((ctx: { program: any }) => Promise<void> | void) | undefined;
  plugin.register({
    pluginConfig,
    registrationMode: "full",
    config: { tools: { exec: { mode: "full" } } },
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCli: (r: any) => {
      cliRegistrar = r;
    },
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
  } as any);
  await cliRegistrar!({ program: node("") });
  const fire = async (hook: string, event: any, ctx: any) => {
    let out: any;
    for (const h of on[hook] ?? []) out = await h(event, ctx);
    return out;
  };
  /**
   * One scan of `command` in session `sid`, from a run with `trigger` (null: not recorded) and
   * `extra` run context: the hook's result and the scan's traffic record.
   */
  const scan = async (command: string, sid = "S1", trigger: string | null = "user", extra: Record<string, unknown> = {}) => {
    const runId = `r-${sid}`;
    const ctx = { sessionKey: `agent:main:${sid}`, sessionId: sid, agentId: "main", runId, ...(trigger ? { trigger } : {}), ...extra };
    await fire("before_prompt_build", { runId, prompt: trigger === "cron" ? "[cron:abc nightly] run" : "tidy up" }, ctx);
    const out = await fire("before_tool_call", { toolName: "exec", toolCallId: `c${scans.length}`, runId, params: { command } }, ctx);
    return { out, rec: records("scan").at(-1) };
  };
  return { commands, cliActions, scan };
}

type Registered = Awaited<ReturnType<typeof registered>>;

/** What the host passes an admitted owner on a Control UI connection, sent from session `S1`. */
function ownerCtx(args: string, extra: Record<string, unknown> = {}) {
  return {
    senderId: "",
    channel: "webchat",
    senderIsOwner: true,
    gatewayClientScopes: ["operator.read", "operator.write", "operator.admin"],
    assertOwnerCurrent: () => undefined,
    sessionKey: "agent:main:S1",
    sessionId: "S1",
    args,
    ...extra,
  };
}

async function run(r: Registered, args: string, extra: Record<string, unknown> = {}) {
  return (await r.commands["sentrook-snooze"].handler(ownerCtx(args, extra))).text as string;
}

async function cli(r: Registered, ...args: string[]): Promise<string> {
  const lines: string[] = [];
  const real = console.log;
  console.log = (...a: unknown[]) => void lines.push(a.map(String).join(" "));
  try {
    await r.cliActions["sentrook snooze [args...]"]!(args);
  } finally {
    console.log = real;
  }
  return lines.join("\n");
}

function records(kind: string): any[] {
  const log = path.join(stateDir, "traffic.jsonl");
  if (!existsSync(log)) return [];
  return readFileSync(log, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l))
    .filter((rec) => rec.kind === kind);
}

const stored = () => JSON.parse(readFileSync(file, "utf8"));

function put(...entries: unknown[]) {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(file, JSON.stringify({ version: 1, snoozes: entries }));
}

function entry(scope = "session", ref = S1, minutes = 60) {
  const now = new Date();
  return {
    scope,
    ...(scope === "session" ? { session_ref: ref } : {}),
    set_at: snooze.iso(now),
    expires_at: snooze.iso(new Date(now.getTime() + minutes * 60_000)),
  };
}

// ---- the shared fixture ----------------------------------------------------------------------------

test("the fixture renders", () => {
  mkdirSync(stateDir, { recursive: true });
  copyFileSync(path.join(FIXTURES, "snooze.json"), file);
  const data = snooze.load(stateDir);
  assert.equal(S1, "s_3696ad59777e");
  assert.equal(snooze.formatStatus(data, S1, NOW), golden("status-session.txt"));
  assert.equal(snooze.formatStatus(data, null, NOW), golden("status-no-session.txt"));
  assert.equal(snooze.statusLine(data, NOW), golden("status-line.txt"));
});

test("entries that must never apply: expired, too far away, no or unreadable expiry, unknown scope", () => {
  const raw = JSON.parse(readFileSync(path.join(FIXTURES, "snooze.json"), "utf8"));
  raw.snoozes = raw.snoozes.filter((e: any) => typeof e !== "object" || e.scope !== "all");
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(file, JSON.stringify(raw));
  const data = snooze.load(stateDir);
  assert.ok(snooze.active(data, S1, NOW));
  assert.ok(snooze.active(data, "s_adfa2b24c2d9", NOW));
  for (const ref of [1, 2, 3, 4, 5, 6].map((i) => `s_00000000000${i}`).concat("s_x")) {
    assert.ok(!snooze.active(data, ref, NOW), ref);
  }
  assert.ok(!snooze.active(data, S1, new Date(NOW.getTime() + 30 * 60_000)));
});

test("an unreadable file relaxes nothing and refuses changes", async () => {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(file, "{not json");
  const r = await registered();
  const { out, rec } = await r.scan("rm REVIEW");
  assert.ok(out.requireApproval);
  assert.equal(rec.snoozed, undefined);
  assert.match(await run(r, ""), /could not be read/);
  assert.equal(readFileSync(file, "utf8"), "{not json");
  assert.ok((await r.commands.sentrook.handler({ args: "status" })).text.split("\n").includes("snooze: unreadable, none applies"));
});

// ---- must relax: an attended review in a snoozed session -------------------------------------------

test("a snoozed review is allowed, scanned and logged", async () => {
  const r = await registered();
  assert.match(await run(r, ""), /^Snoozed reviews in this session for 1h, until /);
  const { out, rec } = await r.scan("rm REVIEW");
  assert.equal(out, undefined);
  assert.deepEqual([rec.verdict, rec.decision, rec.snoozed, rec.response.risk], ["review", "allowed", true, 55]);
  await r.scan("ls");
  assert.equal(scans.at(-1).history[0].decision, "allowed");
  const recent = recentScans(path.join(stateDir, "traffic.jsonl"), 5);
  assert.deepEqual(
    recent.map(([s, res]) => actionOf(s, res)),
    ["allowed", "allowed (snoozed)"],
  );
  assert.equal(reviewOf("allowed (snoozed)", null), "-");
});

test("--all covers every session", async () => {
  const r = await registered();
  assert.match(await run(r, "30m --all"), /^Snoozed reviews in every session for 30m, until /);
  const { out, rec } = await r.scan("rm REVIEW", "S2");
  assert.equal(out, undefined);
  assert.equal(rec.snoozed, true);
});

// ---- must stay silent: what a snooze never touches ---------------------------------------------------

test("a block is still a block", async () => {
  put(entry(), entry("all"));
  const r = await registered();
  const { out, rec } = await r.scan("curl EXFIL");
  assert.equal(out.block, true);
  assert.equal(rec.snoozed, undefined);
});

test("an enforced review still asks", async () => {
  put(entry(), entry("all"));
  const r = await registered();
  const { out, rec } = await r.scan("ls ENFORCE");
  assert.equal(rec.response.enforced, "review");
  assert.ok(rec.response.risk < 40);
  assert.ok(out.requireApproval);
  assert.equal(rec.snoozed, undefined);
});

test("an unattended review is not snoozed", async () => {
  put(entry("session", snooze.sessionRef("C1")), entry("all"));
  const r = await registered();
  const { out, rec } = await r.scan("rm REVIEW", "C1", "cron");
  assert.equal(scans.at(-1).trigger.kind, "scheduled");
  assert.ok(out.requireApproval);
  assert.equal(out.requireApproval.timeoutBehavior, "deny");
  assert.equal(rec.snoozed, undefined);
});

test("a subagent review is not snoozed, even where the approval policy calls subagents attended", async () => {
  put(entry("session", snooze.sessionRef("sub-1")), entry("all"));
  const r = await registered({ approval: { scheduledIntentKinds: ["cron"] } });
  const { out, rec } = await r.scan("rm REVIEW", "sub-1", "user", { inputProvenance: { sourceRole: "subagent" } });
  assert.equal(scans.at(-1).trigger.kind, "subagent");
  assert.ok(out.requireApproval);
  assert.equal(rec.snoozed, undefined);
});

test("a run whose trigger was not recorded is not snoozed", async () => {
  put(entry(), entry("all"));
  const r = await registered();
  const { out, rec } = await r.scan("rm REVIEW", "S1", null);
  assert.equal(scans.at(-1).trigger.kind, "unknown");
  assert.ok(out.requireApproval);
  assert.equal(rec.snoozed, undefined);
});

test("an expiry with a field out of range is unreadable, not rolled forward", () => {
  assert.equal(snooze.when("2026-10-29T24:00Z"), null);
  assert.equal(snooze.when("2026-02-30T00:00Z"), null);
  assert.equal(snooze.when("2026-10-29T12:30:60Z"), null);
  assert.equal(snooze.when("2026-10-29T12:30:59.5+01:00")?.toISOString(), "2026-10-29T11:30:59.500Z");
});

test("an expired snooze no longer applies", async () => {
  put(entry("session", S1, -1), entry("all", S1, -1));
  const r = await registered();
  const { out, rec } = await r.scan("rm REVIEW");
  assert.ok(out.requireApproval);
  assert.equal(rec.snoozed, undefined);
  assert.equal((await run(r, "status")).split("\n")[0], "Snooze: off");
});

test("a session snooze does not leak into other sessions", async () => {
  const r = await registered();
  await run(r, "2h");
  const other = await r.scan("rm REVIEW", "S2");
  assert.ok(other.out.requireApproval);
  assert.equal(other.rec.snoozed, undefined);
  assert.equal((await r.scan("rm REVIEW", "S1")).out, undefined);
});

test("scan errors and observe mode are not snoozed", async () => {
  put(entry(), entry("all"));
  const r = await registered();
  const failed = await r.scan("FAIL");
  assert.ok(failed.out.requireApproval);
  assert.equal(failed.rec.decision, "blocked_on_error");
  assert.equal(failed.rec.snoozed, undefined);
  process.env.SENTROOK_MODE = "observe";
  const observed = await r.scan("rm REVIEW");
  assert.equal(observed.out, undefined);
  assert.equal(observed.rec.snoozed, undefined);
});

// ---- the commands ------------------------------------------------------------------------------------

test("only the owner may snooze", async () => {
  const r = await registered();
  assert.deepEqual(r.commands["sentrook-snooze"].requiredScopes, ["operator.admin"]);
  assert.equal(await run(r, "--all", { senderIsOwner: false }), refusal("snooze"));
  assert.equal(await run(r, "status", { senderIsOwner: false }), refusal("snooze"));
  assert.ok(!existsSync(file));
  const audit = records("command").at(-1);
  assert.deepEqual([audit.verb, audit.outcome], ["snooze", "refused"]);
  assert.match((await r.commands.sentrook.handler({ args: "snooze" })).text, /is for the owner only: use \/sentrook-snooze/);
});

test("an owner demoted before the write changes nothing", async () => {
  const r = await registered();
  let calls = 0;
  const assertOwnerCurrent = () => {
    if (++calls > 1) throw new Error("owner authority changed");
  };
  assert.equal(await run(r, "--all", { assertOwnerCurrent }), refusal("snooze"));
  assert.ok(!existsSync(file));
  assert.deepEqual(records("snooze"), []);
});

test("duration: default, limits and refusals", async () => {
  const r = await registered();
  const now = Date.now();
  await run(r, "");
  const exp = snooze.when(stored().snoozes[0].expires_at)!.getTime() - now;
  assert.ok(exp > 59 * 60_000 && exp <= 3600_000 + 5_000);
  assert.match(await run(r, "24h"), /^Snoozed reviews in this session for 24h/);
  for (const tooLong of ["25h", "1441m", "2d"]) {
    assert.ok((await run(r, tooLong)).startsWith(`Unknown duration "${tooLong}": use a number with m or h, from 1m to 24h.`));
  }
  assert.ok((await run(r, "0m")).startsWith('Unknown duration "0m"'));
  assert.ok((await run(r, "--forever")).startsWith("Unknown option --forever."));
  assert.ok((await run(r, "1h 2h")).startsWith("usage: /sentrook-snooze"));
  // A later snooze for the same session replaces the earlier one.
  assert.equal(stored().snoozes.length, 1);
});

test("a snooze needs a session unless --all", async () => {
  const r = await registered();
  const reply = await run(r, "1h", { sessionId: undefined, sessionKey: undefined });
  assert.equal(
    reply,
    "There is no current session here, so a snooze cannot be bound to one; use /sentrook-snooze --all to snooze every session.",
  );
  assert.equal(await cli(r, "2h"), reply);
  assert.ok(!existsSync(file));
  assert.match(await cli(r, "2h", "--all"), /^Snoozed reviews in every session/);
  assert.match(await cli(r, "--all"), /^Snoozed reviews in every session for 1h/);
  assert.deepEqual(
    stored().snoozes.map((e: any) => e.scope),
    ["all"],
  );
  assert.deepEqual(stored().snoozes[0].set_by, { basis: ["local_terminal"], channel: null, sender_ref: null });
});

test("off ends what applies here, and --all ends everything", async () => {
  const S2 = snooze.sessionRef("S2");
  put(entry(), entry("session", S2), entry("all"));
  const r = await registered();
  assert.equal(await run(r, "off"), "Snooze off: ended 2 snoozes.");
  assert.deepEqual(
    stored().snoozes.map((e: any) => e.session_ref),
    [S2],
  );
  assert.equal(await run(r, "off"), "No snooze was on.");
  assert.equal(await cli(r, "off"), "Snooze off: ended 1 snooze.");
  assert.deepEqual(stored().snoozes, []);
  put(entry(), entry("session", S2));
  assert.equal(await run(r, "off --all"), "Snooze off: ended 2 snoozes.");
});

test("status and the traffic log", async () => {
  const r = await registered();
  await run(r, "90m");
  const lines = (await run(r, "status")).split("\n");
  assert.match(lines[0]!, /^Snooze: on in this session until .*\(1h 30m left\)$/);
  assert.deepEqual((await run(r, "status", { sessionId: "S2", sessionKey: "agent:main:S2" })).split("\n").slice(0, 2), [
    "Snooze: off",
    "Other sessions snoozed: 1",
  ]);
  const status = async () => (await r.commands.sentrook.handler({ args: "status" })).text.split("\n");
  assert.ok((await status()).includes("snooze: 1 session"));
  await run(r, "off");
  assert.ok((await status()).includes("snooze: off"));
  const changes = records("snooze");
  assert.deepEqual(
    changes.map((c) => c.op),
    ["set", "off"],
  );
  assert.equal(changes[0].entry.session_ref, S1);
  assert.deepEqual(changes[0].by, { basis: ["operator.admin"], channel: "webchat", sender_ref: null });
  assert.equal(changes[1].entries[0].session_ref, S1);
  assert.deepEqual(stored().snoozes, []);
});

test("a write drops expired entries", async () => {
  const S2 = snooze.sessionRef("S2");
  put(entry("session", "s_old", -5), entry("session", S2));
  const r = await registered();
  await run(r, "");
  assert.deepEqual(
    stored().snoozes.map((e: any) => e.session_ref),
    [S2, S1],
  );
});

test("help lists /sentrook-snooze as an owner command", () => {
  const line = helpText()
    .split("\n")
    .find((l) => l.trim().startsWith("/sentrook-snooze"));
  assert.ok(line?.includes("[duration|off|status] [--all]"));
});
