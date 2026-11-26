import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import { helpText, OWNER_SUBCOMMANDS } from "./commands.ts";
import { credentialPatternOk, destinationOk, nothingLiteral, resolveConfig, wildcardDomainOk } from "./config.ts";
import * as grants from "./grants.ts";
import plugin from "./index.ts";
import { refusal } from "./owner.ts";
import { runVerify } from "./verify.ts";
import { bindingProblem, callCwd, callPlatform, providerFor, relevantGrants, sessionRef } from "./planir.ts";

/**
 * Shared with the Hermes plugin's tests: both hosts print the same text for the same state. Times are
 * read at NOW; the listing is seen from session `S1`, which `gr-1a2b3c` is bound to.
 */
const FIXTURES = fileURLToPath(new URL("../../fixtures/grants/", import.meta.url));
const NOW = new Date("2026-10-29T12:00:00Z");
const CMD = (s: string) => `/sentrook-${s}`;
const S1 = sessionRef("S1");
const S2 = sessionRef("S2");
const NOTE = " Cron jobs, subagents and other chats need a --persistent grant (add --expires to end it).";
const golden = (name: string) =>
  readFileSync(path.join(FIXTURES, name), "utf8").replace(/\n+$/, "").replaceAll("{bind}", "/sentrook-bind");

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

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-grants-"));
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
  file = path.join(stateDir, "grants.json");
  scans = [];
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const reply = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return reply({ token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return reply({ access_token: "tok", expires_in: 600 });
    const planir = JSON.parse(String(init?.body));
    scans.push(planir);
    return reply({ response_version: "2.0", request_id: planir.request_id, status: "ok", risk: 5, state: "s" });
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
async function registered(pluginConfig: Record<string, unknown> = {}, hostConfig: Record<string, unknown> = {}) {
  const commands: Record<string, any> = {};
  const cliActions: Record<string, (...args: unknown[]) => Promise<void> | void> = {};
  const on: Record<string, Array<(e: any, c: any) => any>> = {};
  const unknownOptions: string[] = [];
  const warnings: string[] = [];
  const node = (prefix: string): any => {
    const self: any = {
      description: () => self,
      option: () => self,
      allowUnknownOption: () => (unknownOptions.push(prefix.trim()), self),
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
    config: { tools: { exec: { mode: "full" } }, ...hostConfig },
    logger: { info: () => undefined, warn: (m: string) => void warnings.push(m), error: () => undefined },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCli: (r: any) => {
      cliRegistrar = r;
    },
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
  } as any);
  await cliRegistrar!({ program: node("") });
  /** The scan request for one call of `toolName` in session `sid` (keyed as the host keys it). */
  const call = async (toolName: string, params: Record<string, unknown>, sid = "S1", extra: Record<string, unknown> = {}) => {
    const ctx = { sessionKey: `agent:main:${sid}`, sessionId: sid, agentId: "main", runId: "r1", ...extra };
    for (const h of on.before_tool_call ?? []) await h({ toolName, toolCallId: `c${scans.length}`, runId: "r1", params }, ctx);
    return scans.at(-1);
  };
  /** The grants sent with one scan of `command` in session `sid`. */
  const scan = async (command: string, sid = "S1", extra: Record<string, unknown> = {}) =>
    (await call("exec", { command }, sid, extra)).grants;
  return { commands, cliActions, call, scan, on, unknownOptions, warnings };
}

/** What the host passes an admitted owner on a Control UI connection, sent from session `S1`. */
function ownerCtx(args: string, extra: Record<string, unknown> = {}) {
  return {
    senderId: "",
    channel: "webchat",
    sessionKey: "agent:main:S1",
    sessionId: "S1",
    senderIsOwner: true,
    gatewayClientScopes: ["operator.read", "operator.write", "operator.admin"],
    assertOwnerCurrent: () => undefined,
    args,
    ...extra,
  };
}

type Registered = Awaited<ReturnType<typeof registered>>;

async function run(r: Registered, command: string, args: string, extra: Record<string, unknown> = {}) {
  return (await r.commands[command].handler(ownerCtx(args, extra))).text as string;
}

async function cli(r: Registered, action: string, ...args: unknown[]): Promise<string> {
  const lines: string[] = [];
  const real = console.log;
  console.log = (...a: unknown[]) => void lines.push(a.map(String).join(" "));
  try {
    await r.cliActions[action]!(...args);
  } finally {
    console.log = real;
  }
  return lines.join("\n");
}

const stored = () => JSON.parse(readFileSync(file, "utf8"));

function records(kind: string): any[] {
  const log = path.join(stateDir, "traffic.jsonl");
  if (!existsSync(log)) return [];
  return readFileSync(log, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l))
    .filter((r) => r.kind === kind);
}

/** The fixture's config, in OpenClaw's key names. */
function fixtureConfig(): Record<string, unknown> {
  const cfg = JSON.parse(readFileSync(path.join(FIXTURES, "config.json"), "utf8"));
  return { grants: cfg.grants, channelBindings: cfg.channel_bindings };
}

function fixtureFile() {
  mkdirSync(stateDir, { recursive: true });
  copyFileSync(path.join(FIXTURES, "grants.json"), file);
}

test("the fixture renders", () => {
  fixtureFile();
  const cfg = resolveConfig(fixtureConfig(), process.env);
  const data = grants.load(cfg.stateDir);
  assert.equal(grants.formatGrants(cfg, data, NOW, CMD, S1), golden("grants.txt"));
  assert.equal(grants.formatBindings(cfg, data), golden("bindings.txt"));
  assert.deepEqual(grants.effective(cfg, data, NOW, S1), JSON.parse(readFileSync(path.join(FIXTURES, "planir-grants.json"), "utf8")));
  // From the command line, every session grant shows the session it is bound to.
  const listing = grants.formatGrants(cfg, data, NOW, CMD, null);
  assert.ok(listing.includes(`session ${S1}; set 2026-10-29 09:00 UTC (local_terminal)`), listing);
  assert.ok(!listing.includes("this session"));
});

test("a grant round-trips through the file and into scans", async () => {
  const r = await registered();
  const out = await run(r, "sentrook-grant", "destination #ops");
  const [g] = stored().grants;
  assert.equal(out, `Granted ${g.id}: destination #ops (this session only).${NOTE}`);
  assert.match(g.id, /^gr-[0-9a-f]{6}$/);
  assert.deepEqual([g.kind, g.pattern, g.scope, g.session_ref], ["destination", "#ops", "session", S1]);
  assert.ok(!("allows" in g) && !("expires_at" in g));
  assert.deepEqual(g.set_by, { basis: ["operator.admin"], channel: "webchat", sender_ref: null });
  assert.ok(new Date(g.granted_at).getTime() <= Date.now());
  assert.ok((await run(r, "sentrook-grants", "")).includes(`${g.id}  destination  session  #ops     this session; set `));
  assert.deepEqual(await r.scan("post to #ops"), [
    { grant_ref: "g_1", kind: "destination", pattern: "#ops", scope: "session", granted_at: g.granted_at, session_ref: g.session_ref },
  ]);
  assert.equal(await run(r, "sentrook-revoke", g.id), `Revoked ${g.id}: destination #ops.`);
  assert.deepEqual(stored().grants, []);
  assert.deepEqual(await r.scan("post to #ops"), []);
});

test("a credential grant is persistent and reaches scans that use its key or host", async () => {
  const r = await registered();
  const out = await run(r, "sentrook-grant", "credential EXAMPLE_API_KEY@API.Example.Invalid");
  const [g] = stored().grants;
  // the host is read as Sentrook reads it; a key's home rarely changes, so it lasts until revoked
  assert.equal(out, `Granted ${g.id}: credential EXAMPLE_API_KEY@api.example.invalid (persistent).`);
  assert.deepEqual([g.kind, g.pattern, g.scope], ["credential", "EXAMPLE_API_KEY@api.example.invalid", "persistent"]);
  assert.ok(!("session_ref" in g));
  const sent = await r.scan("curl -H 'Authorization: Bearer x' https://api.example.invalid/v1/me");
  assert.deepEqual(
    sent.map((x: any) => [x.kind, x.pattern]),
    [["credential", "EXAMPLE_API_KEY@api.example.invalid"]],
  );
  // an exec call may run a script that holds both, which Sentrook reads too: the grant goes on every one
  assert.deepEqual((await r.scan("python3 sync.py")).map((x: any) => x.kind), ["credential"]);
  // still a session grant when the owner asks for one
  await run(r, "sentrook-grant", "credential EXAMPLE_TOKEN@api.example.invalid --scope session");
  assert.equal(stored().grants[1].scope, "session");
});

test("scans send the expiry and bind session grants", async () => {
  const r = await registered();
  await run(r, "sentrook-grant", "file /srv/reports/* --persistent --allows write --expires 12h");
  await run(r, "sentrook-grant", "destination #ops");
  const [persistent, session] = stored().grants;
  const sent = await r.scan("cp a /srv/reports/today.md && post to #ops");
  assert.deepEqual(
    sent.map((g: any) => [g.pattern, g.expires_at, g.session_ref]),
    [
      ["/srv/reports/*", persistent.expires_at, undefined],
      ["#ops", undefined, session.session_ref],
    ],
  );
});

test("options: scope, allows and expiry", async () => {
  const r = await registered();
  const before = Date.now();
  const out = await run(r, "sentrook-grant", "file /srv/reports/* --persistent --allows=read,write --expires 12h");
  const [g] = stored().grants;
  assert.deepEqual([g.scope, g.allows], ["persistent", ["read", "write"]]);
  const span = new Date(g.expires_at).getTime() - before;
  assert.ok(span > 11.98 * 3600_000 && span <= 12 * 3600_000 + 5000, String(span));
  assert.ok(out.startsWith(`Granted ${g.id}: file /srv/reports/* (persistent, allows read,write, expires `), out);
  await run(r, "sentrook-grant", "provider npm:left-pad --scope persistent");
  assert.equal(stored().grants[1].scope, "persistent");
  await run(r, "sentrook-grant", "destination #ops --scope session");
  assert.equal(stored().grants[2].scope, "session");
  await run(r, "sentrook-grant", "repo github.com/kestrelwade/yard-helper --persistent");
  assert.deepEqual([stored().grants[3].kind, stored().grants[3].pattern], ["repo", "github.com/kestrelwade/yard-helper"]);
});

for (const [args, reply] of [
  ["destination #ops --scope persistant", 'Unknown scope "persistant": use session or persistent.'],
  ["destination #ops --scope=Persistent", 'Unknown scope "Persistent": use session or persistent.'],
  ["destination #ops --persistant", "Unknown option --persistant."],
  ["destinaton #ops", 'Unknown grant kind "destinaton": use destination, file, provider, repo or credential.'],
  ["credential EXAMPLE_API_KEY", '"EXAMPLE_API_KEY" is not a credential pattern: use NAME@host, such as MY_SERVICE_TOKEN@api.myservice.example (NAME may end in * after three or more characters, host may be *.example.com).'],
  ["credential EX*@api.example.invalid", '"EX*@api.example.invalid" is not a credential pattern: use NAME@host, such as MY_SERVICE_TOKEN@api.myservice.example (NAME may end in * after three or more characters, host may be *.example.com).'],
  ["credential EXAMPLE_API_KEY@*.invalid", '"EXAMPLE_API_KEY@*.invalid" is not a credential pattern: use NAME@host, such as MY_SERVICE_TOKEN@api.myservice.example (NAME may end in * after three or more characters, host may be *.example.com).'],
  ["credential EXAMPLE_API_KEY@https://api.example.invalid/", '"EXAMPLE_API_KEY@https://api.example.invalid/" is not a credential pattern: use NAME@host, such as MY_SERVICE_TOKEN@api.myservice.example (NAME may end in * after three or more characters, host may be *.example.com).'],
  ["credential EXAMPLE_API_KEY@api.example.invalid --allows read", "--allows applies to file grants only."],
  ["file /x --allows read,wrte", 'Unknown allows value "wrte": use read, write, edit, delete or exec.'],
  ["destination #ops --allows write", "--allows applies to file grants only."],
  ["destination #ops --expires 2w", 'Unknown expiry "2w": use a number with m, h or d, from 1m to 365d.'],
  ["destination #ops --expires 366d", 'Unknown expiry "366d": use a number with m, h or d, from 1m to 365d.'],
  ["destination #ops --expires", "--expires needs a value."],
  ["destination #ops --session S2", 'Unknown session "S2": use a session ref (s_ and 12 hex digits) from /sentrook-history.'],
  ["destination #ops --persistent --session s_0123456789ab", "--session applies to session grants only."],
  ["destination #ops --session", "--session needs a value."],
  ["destination", ""],
  ["destination #ops extra", ""],
  [`destination ${"x".repeat(257)}`, "The pattern must be at most 256 printable characters."],
] as const) {
  test(`bad input is refused and nothing is written: ${args.slice(0, 40)}`, async () => {
    const r = await registered();
    const usage = grants.grantUsage(CMD);
    assert.equal(await run(r, "sentrook-grant", args), reply ? `${reply}\n${usage}` : usage);
    assert.ok(!existsSync(file));
    assert.deepEqual(records("grants"), []);
  });
}

test("config scope is strict", () => {
  const cfg = resolveConfig(
    {
      grants: ["a", "b", "c", "d", "e", "f"].map((x, i) => ({
        kind: "destination",
        pattern: `${x}.example`,
        ...(i === 0 ? {} : { scope: [undefined, "persistent", "session", "persistant", "Persistent", true][i] }),
      })),
    },
    {},
  );
  assert.deepEqual(
    cfg.grants.map((g) => g.scope),
    ["persistent", "persistent", "session", "session", "session", "session"],
  );
  assert.deepEqual(cfg.unsentGrants, {
    2: "no session",
    3: 'unknown scope "persistant"',
    4: 'unknown scope "Persistent"',
    5: "unknown scope true",
  });
});

for (const [command, args] of [
  ["sentrook-grants", ""],
  ["sentrook-grant", "destination #ops"],
  ["sentrook-revoke", "gr-1a2b3c"],
  ["sentrook-bind", "add #ops"],
  ["sentrook-bind", "remove discord:1234"],
  ["sentrook-bind", "list"],
] as const) {
  test(`a non-owner is refused /${command} ${args} and nothing changes`, async () => {
    fixtureFile();
    const before = readFileSync(file, "utf8");
    const r = await registered();
    const verb = command.slice("sentrook-".length);
    for (const extra of [
      { senderIsOwner: false },
      { senderIsOwner: undefined, assertOwnerCurrent: undefined },
      {
        assertOwnerCurrent: () => {
          throw new Error("owner authority changed");
        },
      },
    ]) {
      assert.equal(await run(r, command, args, extra), refusal(verb));
    }
    assert.equal(readFileSync(file, "utf8"), before);
    assert.deepEqual(
      records("command").map((rec) => [rec.verb, rec.outcome]),
      [
        [verb, "refused"],
        [verb, "refused"],
        [verb, "refused"],
      ],
    );
    assert.deepEqual(records("grants"), []);
  });
}

test("an owner demoted before the write changes nothing", async () => {
  const r = await registered();
  let calls = 0;
  const assertOwnerCurrent = () => {
    if (++calls > 1) throw new Error("owner authority changed");
  };
  assert.equal(await run(r, "sentrook-grant", "destination #ops", { assertOwnerCurrent }), refusal("grant"));
  assert.ok(!existsSync(file));
  assert.deepEqual(records("grants"), []);
  assert.deepEqual(
    records("command").map((rec) => [rec.outcome, rec.reason]),
    [
      ["allowed", undefined],
      ["refused", "stale_owner"],
    ],
  );
});

test("a sender id is stored only as a salted hash", async () => {
  const r = await registered();
  await run(r, "sentrook-grant", "destination #ops", { senderId: "owner-7731", channel: "telegram" });
  const [g] = stored().grants;
  assert.equal(g.set_by.channel, "telegram");
  assert.match(g.set_by.sender_ref, /^u_[0-9a-f]{16}$/);
  assert.ok(!readFileSync(file, "utf8").includes("owner-7731"));
});

test("config entries are read-only", async () => {
  fixtureFile();
  const before = readFileSync(file, "utf8");
  const r = await registered(fixtureConfig());
  assert.equal(await run(r, "sentrook-revoke", "cfg-1"), "cfg-1 is set in the plugin config; remove it there.");
  assert.equal(await run(r, "sentrook-revoke", "gr-zzzzzz"), "No grant gr-zzzzzz; see /sentrook-grants.");
  assert.equal(await run(r, "sentrook-revoke", ""), "usage: /sentrook-revoke <id>, with an id from /sentrook-grants");
  assert.equal(await run(r, "sentrook-bind", "remove #daily-brief"), "#daily-brief is bound in the plugin config; remove it there.");
  assert.equal(await run(r, "sentrook-bind", "add #daily-brief"), "#daily-brief is already bound in the plugin config.");
  assert.equal(await run(r, "sentrook-bind", "add discord:1234"), "discord:1234 is already bound.");
  assert.equal(await run(r, "sentrook-bind", "remove #nowhere"), "#nowhere is not bound.");
  assert.equal(readFileSync(file, "utf8"), before);
  assert.deepEqual(records("grants"), []);
});

test("bindings round-trip", async () => {
  const r = await registered();
  assert.equal(await run(r, "sentrook-bind", "add discord:999"), "Channel binding added: discord:999.");
  const [b] = stored().bindings;
  assert.equal(b.pattern, "discord:999");
  assert.deepEqual(b.set_by.basis, ["operator.admin"]);
  assert.ok((await run(r, "sentrook-bind", "list")).includes("discord:999  set "));
  assert.equal(await run(r, "sentrook-bind", ""), await run(r, "sentrook-bind", "list"));
  const [sent] = await r.scan("send to discord:999");
  assert.deepEqual({ ...sent, granted_at: null }, { grant_ref: "g_1", kind: "destination", pattern: "discord:999", scope: "persistent", granted_at: null });
  assert.equal(await run(r, "sentrook-bind", "remove discord:999"), "Channel binding removed: discord:999.");
  assert.deepEqual(stored().bindings, []);
  assert.equal(await run(r, "sentrook-bind", "frob x"), "usage: /sentrook-bind add|remove <channel>, or /sentrook-bind list");
});

test("every change is audited", async () => {
  const r = await registered();
  await run(r, "sentrook-grant", "destination #ops");
  const id = stored().grants[0].id;
  await run(r, "sentrook-revoke", id);
  await run(r, "sentrook-bind", "add discord:999");
  await run(r, "sentrook-bind", "remove discord:999");
  const changes = records("grants");
  assert.deepEqual(
    changes.map((c) => c.op),
    ["grant", "revoke", "bind_add", "bind_remove"],
  );
  assert.equal(changes[0].entry.id, id);
  assert.equal(changes[1].entry.id, id);
  assert.equal(changes[2].entry.pattern, "discord:999");
  assert.ok(changes.every((c) => c.by.basis[0] === "operator.admin"));
  assert.deepEqual(
    records("command").map((c) => c.verb),
    ["grant", "revoke", "bind", "bind"],
  );
});

test("expired grants are not sent and are dropped on the next change", async () => {
  fixtureFile();
  const r = await registered(fixtureConfig());
  const sent = await r.scan("npm install npm:left-pad then post to #ops");
  assert.deepEqual(
    sent.map((g: any) => g.pattern),
    ["#ops"],
  );
  await run(r, "sentrook-bind", "add discord:999");
  const ids = stored().grants.map((g: any) => g.id);
  assert.ok(!ids.includes("gr-4d5e6f") && ids.includes("gr-1a2b3c"));
});

test("an expired grant can still be revoked", async () => {
  fixtureFile();
  const r = await registered(fixtureConfig());
  assert.equal(await run(r, "sentrook-revoke", "gr-4d5e6f"), "Revoked gr-4d5e6f: provider npm:left-pad.");
  assert.deepEqual(
    records("grants").map((c) => c.op),
    ["revoke"],
  );
});

test("an over-broad pattern of another kind is stored as typed: whether it relieves is the scanner's call", async () => {
  const r = await registered();
  const out = await run(r, "sentrook-grant", "provider *");
  assert.ok(out.startsWith("Granted ") && out.endsWith(`: provider * (this session only).${NOTE}`), out);
  assert.equal(stored().grants[0].pattern, "*");
});

/**
 * Shared with the Hermes plugin's tests and the scanner's: a wildcard over a whole public suffix is refused, and one
 * in the config is never sent.
 */
const DESTINATION_PATTERNS = JSON.parse(readFileSync(path.join(FIXTURES, "destination-patterns.json"), "utf8"));
for (const c of DESTINATION_PATTERNS.cases) {
  test(`destination pattern: ${c.typed}`, () => {
    // A scanner-only case is taken as typed.
    const ok = c.ok || c.scanner_only === true;
    const parsed = grants.parseGrant(`destination ${c.typed} --persistent`, CMD);
    if (ok) assert.deepEqual(parsed, { kind: "destination", pattern: c.typed, scope: "persistent" });
    else assert.equal(parsed, DESTINATION_PATTERNS.refusal.replace("{pattern}", c.typed));
    const cfg = resolveConfig({ grants: [{ kind: "destination", pattern: c.typed }] }, {});
    assert.deepEqual(cfg.unsentGrants, ok ? {} : { 0: "too broad" });
  });
}

/**
 * Long runs of `.` and `[` (100k at full size, 1/`divisor` of it for the growth check), which a pattern check with
 * nested or overlapping repeats would take quadratic time over.
 */
const longRuns = (divisor = 1) => {
  const n = Math.floor(100_000 / divisor);
  return [
    "[".repeat(n),
    `*.${"[".repeat(n)}`,
    `a${"[".repeat(n)}*`,
    `${".".repeat(n)}x`,
    `*.${".".repeat(n)}a`,
    `*.${"a.".repeat(Math.floor(n / 2))}${".".repeat(n)}`,
    `slack:${"[".repeat(n)}*`,
    `*@${".".repeat(n)}*`,
  ];
};

/**
 * How the time grows with the input, as the scanner's tests measure it (`sentrook/tests/linear_time.py`): the work at
 * a quarter and at full size, the fastest of a few runs each; linear work takes about 4 times as long, quadratic about
 * 16. A full-size run under 20 ms is too short to time and passes. Returns [quarter ms, full ms].
 */
function assertLinear(run: (divisor: number) => void, what: string, limit = 10): [number, number] {
  const ms = (divisor: number) => {
    const t0 = performance.now();
    run(divisor);
    return performance.now() - t0;
  };
  let small = ms(4);
  let large = ms(1);
  small = Math.min(small, ms(4));
  for (let attempt = 1; attempt < 5 && large >= 20 && large / Math.max(small, 1e-6) >= 0.8 * limit; attempt++) {
    small = Math.min(small, ms(4));
    large = Math.min(large, ms(1));
  }
  const growth = large / Math.max(small, 1e-6);
  assert.ok(large < 20 || growth < limit, `${what}: ${large.toFixed(1)} ms at full size vs ${small.toFixed(1)} ms at 1/4, ${growth.toFixed(1)}x`);
  return [small, large];
}

test("pattern checks take linear time on long runs of . and [", () => {
  // A generous ceiling guards against a hang.
  const [, full] = assertLinear((divisor) => {
    for (const p of longRuns(divisor)) {
      destinationOk(p);
      nothingLiteral(p);
      bindingProblem(p);
      wildcardDomainOk(p);
      credentialPatternOk(`NAME@${p}`);
      relevantGrants([{ kind: "destination", pattern: p, scope: "persistent" }], p);
    }
  }, "destination pattern checks");
  assert.ok(full < 10_000, `${full} ms`);
});

test("a public-suffix destination grant is refused and nothing is stored", async () => {
  const r = await registered();
  const out = await run(r, "sentrook-grant", "destination *.com --persistent");
  assert.ok(
    out.startsWith('"*.com" is too broad for a destination grant: a wildcard may cover only one registrable domain'),
    out,
  );
  assert.ok(out.endsWith(grants.grantUsage(CMD)), out);
  assert.ok(!existsSync(file) || stored().grants.length === 0);
  assert.deepEqual(records("grants"), []);
});

test("a too-broad config grant is dropped and the others still load", async () => {
  // One bad entry never disables the rest: it keeps its cfg-N, is listed as too broad and never sent.
  const config = {
    grants: [
      { kind: "destination", pattern: "*.mycorp.example" },
      { kind: "destination", pattern: "*.com" },
      { kind: "destination", pattern: "api.example.com" },
    ],
  };
  const r = await registered(config);
  const sent = await r.scan("curl -d x https://a.mycorp.example https://api.example.com https://b.com");
  assert.deepEqual(
    sent.map((g: any) => g.pattern),
    ["*.mycorp.example", "api.example.com"],
  );
  const rows = Object.fromEntries(
    (await run(r, "sentrook-grants", ""))
      .split("\n")
      .slice(2, 5)
      .map((l) => [l.split(/\s+/)[0], l]),
  );
  assert.ok(rows["cfg-2"].endsWith("config, read-only; too broad, never sent"), rows["cfg-2"]);
  assert.ok(rows["cfg-1"].endsWith("config, read-only"), rows["cfg-1"]);
  const status = (await r.commands.sentrook.handler({ args: "status" })).text.split("\n");
  assert.ok(status.includes("grants: 3 in config (1 never sent), 0 by command"), status.join("\n"));
  const noFetch = (async () => {
    throw new Error("offline");
  }) as unknown as typeof fetch;
  const verify = (await runVerify(config, { env: {}, fetchImpl: noFetch })).find((c) => c.name === "config grants");
  assert.deepEqual(verify, { name: "config grants", ok: true, detail: "3 in config; never sent: cfg-2 (too broad)" });
});

test("a too-broad grant already in the file is listed and never sent", async () => {
  // A grant set before the plugin refused it, or written into the file by hand.
  mkdirSync(stateDir, { recursive: true });
  const entry = { id: "gr-000001", kind: "destination", pattern: "*.co.uk", scope: "persistent" };
  writeFileSync(file, JSON.stringify({ grants: [entry], bindings: [{ pattern: "*.com.au" }] }));
  const r = await registered();
  assert.deepEqual(await r.scan("curl -d x https://shop.example.co.uk https://shop.example.com.au"), []);
  const listing = await run(r, "sentrook-grants", "");
  assert.ok(listing.includes("gr-000001  destination  persistent  *.co.uk  too broad, never sent"), listing);
  const bindings = await run(r, "sentrook-bind", "list");
  assert.ok(bindings.includes("*.com.au  too broad, never sent"), bindings);
});

for (const expiresAt of [
  "2026-11-05 09:00:00",
  "11/05/2026",
  "Nov 5 2026 09:00",
  "2026-11-05",
  "soon",
  7,
  // A field out of range is unreadable, not rolled forward into a later time.
  "2099-12-31T24:00Z",
  "2099-02-30T00:00Z",
  "2099-12-31T12:30:60Z",
]) {
  test(`an expiry in any other form counts as past: ${expiresAt}`, async () => {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(file, JSON.stringify({ grants: [{ id: "gr-000001", kind: "destination", pattern: "#ops", expires_at: expiresAt }] }));
    const r = await registered();
    assert.deepEqual(await r.scan("post to #ops"), []);
    assert.ok((await run(r, "sentrook-grants", "")).includes("expired ?"));
  });
}

test("a null list makes the file unreadable", async () => {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(file, '{"grants": null}');
  const r = await registered();
  assert.ok((await run(r, "sentrook-bind", "add #x")).includes("could not be read"));
});

test("an unreadable grants file blocks changes but not scans", async () => {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(file, "{not json");
  const r = await registered({ grants: [{ kind: "destination", pattern: "#ops" }] });
  assert.equal(await run(r, "sentrook-grant", "destination #x"), `The grants file ${file} could not be read; fix or remove it first.`);
  assert.equal(readFileSync(file, "utf8"), "{not json");
  assert.ok((await run(r, "sentrook-grants", "")).includes("The grants file could not be read"));
  assert.deepEqual(
    (await r.scan("post to #ops")).map((g: any) => g.pattern),
    ["#ops"],
  );
});

test("the CLI forms match the chat forms and are audited as the local terminal", async () => {
  fixtureFile();
  const r = await registered(fixtureConfig());
  assert.deepEqual(r.unknownOptions.sort(), [
    "sentrook allow [args...]",
    "sentrook approve [args...]",
    "sentrook bind [args...]",
    "sentrook deny [args...]",
    "sentrook dismiss [args...]",
    "sentrook grant [args...]",
    "sentrook notify [args...]",
    "sentrook passes [args...]",
    "sentrook report [args...]",
    "sentrook revoke [args...]",
    "sentrook setup [args...]",
    "sentrook snooze [args...]",
  ]);
  assert.equal(await cli(r, "sentrook grants"), await run(r, "sentrook-grants", "", { sessionId: undefined, sessionKey: undefined }));
  assert.equal(await cli(r, "sentrook bind [args...]", ["list"]), await run(r, "sentrook-bind", "list"));
  const out = await cli(r, "sentrook grant [args...]", ["file", "/srv/x/*", "--allows", "read", "--persistent"]);
  const id = out.split(" ")[1]!.replace(/:$/, "");
  assert.equal(out, `Granted ${id}: file /srv/x/* (persistent, allows read).`);
  assert.deepEqual(stored().grants.at(-1).set_by, { basis: ["local_terminal"], channel: null, sender_ref: null });
  assert.ok((await cli(r, "sentrook grant [args...]", ["file", "/x", "--scope", "persistant"])).startsWith('Unknown scope "persistant"'));
  const bound = await cli(r, "sentrook grant [args...]", ["destination", "#z", "--session", S2]);
  assert.ok(bound.endsWith(`: destination #z (session ${S2} only).${NOTE}`), bound);
  assert.equal(await cli(r, "sentrook revoke [args...]", [id]), `Revoked ${id}: file /srv/x/*.`);
  assert.equal(await cli(r, "sentrook bind [args...]", ["add", "discord:5"]), "Channel binding added: discord:5.");
  const cliRecords = records("command").filter((c) => c.basis[0] === "local_terminal");
  assert.equal(cliRecords.length, 7);
});

test("status counts grants from both sources", async () => {
  fixtureFile();
  const r = await registered(fixtureConfig());
  const out = (await r.commands.sentrook.handler({ args: "status" })).text.split("\n");
  assert.ok(out.includes("grants: 2 in config (1 never sent), 8 by command"), out.join("\n"));
  assert.ok(out.includes("channel bindings: 1 in config, 1 by command"));
});

test("the grant commands are owner commands and listed in help", async () => {
  const r = await registered();
  for (const name of ["sentrook-grants", "sentrook-grant", "sentrook-revoke", "sentrook-bind"]) {
    assert.deepEqual(r.commands[name].requiredScopes, ["operator.admin"]);
    assert.equal(r.commands[name].acceptsArgs, true);
  }
  const help = helpText();
  for (const o of ["grants", "grant", "revoke", "bind"]) assert.ok(help.includes(`/${OWNER_SUBCOMMANDS[o]!.command}`));
  assert.match(help, /^ {2}\/sentrook-grant <kind> <pattern> \[flags\] /m);
  assert.match(help, /^ {2}\/sentrook-bind add\|remove\|list \[channel\] /m);
});

// ---- session grants: bound to the session they were set in -------------------------------------------

const patterns = (sent: any[]) => sent.map((g) => g.pattern);

test("a session grant relieves only in its own session", async () => {
  // Must relieve in session A; must stay silent in session B, a cron run and a subagent.
  const r = await registered();
  await run(r, "sentrook-grant", "destination #ops");
  assert.deepEqual(patterns(await r.scan("post to #ops")), ["#ops"]);
  assert.deepEqual(await r.scan("post to #ops", "S2"), []);
  assert.deepEqual(await r.scan("post to #ops", "cron-run-1", { sessionKey: "agent:main:cron:daily", trigger: "cron" }), []);
  assert.deepEqual(await r.scan("post to #ops", "sub-1", { sessionKey: "agent:main:subagent:sub-1" }), []);
  assert.deepEqual(patterns(await r.scan("post to #ops")), ["#ops"]);
  assert.equal(stored().grants[0].session_ref, S1);
});

// ---- config grants: a session scope names no session, so they are never sent ---------------------------

/**
 * An entry the parser drops (no pattern), two config grants that never apply (scope session, a scope
 * typo) and two that apply everywhere. The dropped entry takes no cfg-N.
 */
const UNSENT_CONFIG = [
  { kind: "destination", scope: "session" },
  { kind: "destination", pattern: "#ops", scope: "session" },
  { kind: "destination", pattern: "#standup", scope: "persistant" },
  { kind: "destination", pattern: "#daily" },
  { kind: "destination", pattern: "#weekly", scope: "persistent" },
];
const UNSENT_SUMMARY = 'cfg-1 (no session), cfg-2 (unknown scope "persistant")';

test("a config session grant is never sent", async () => {
  // Must stay silent in two sessions, a cron run and a subagent; persistent ones go everywhere.
  const r = await registered({ grants: UNSENT_CONFIG });
  const cmd = "post to #ops #standup #daily #weekly";
  for (const [sid, extra] of [
    ["S1", {}],
    ["S2", {}],
    ["cron-run-1", { sessionKey: "agent:main:cron:daily", trigger: "cron" }],
    ["sub-1", { sessionKey: "agent:main:subagent:sub-1" }],
  ] as const) {
    const sent = await r.scan(cmd, sid, extra);
    assert.deepEqual(
      sent.map((g: any) => [g.pattern, g.scope]),
      [
        ["#daily", "persistent"],
        ["#weekly", "persistent"],
      ],
    );
  }
});

test("listing, status and verify flag config grants never sent", async () => {
  const r = await registered({ grants: UNSENT_CONFIG });
  const rows = Object.fromEntries(
    (await run(r, "sentrook-grants", ""))
      .split("\n")
      .slice(2, 6)
      .map((l) => [l.split(/\s+/)[0], l]),
  );
  assert.ok(rows["cfg-1"].endsWith("config, read-only; no session, never sent"), rows["cfg-1"]);
  assert.ok(rows["cfg-2"].endsWith('config, read-only; unknown scope "persistant", never sent'), rows["cfg-2"]);
  assert.ok(rows["cfg-3"].endsWith("config, read-only"));
  assert.ok(rows["cfg-4"].endsWith("config, read-only"));
  const status = (await r.commands.sentrook.handler({ args: "status" })).text.split("\n");
  assert.ok(status.includes("grants: 4 in config (2 never sent), 0 by command"), status.join("\n"));
  const noFetch = (async () => {
    throw new Error("offline");
  }) as unknown as typeof fetch;
  const verify = async (cfg: Record<string, unknown>) =>
    (await runVerify(cfg, { env: {}, fetchImpl: noFetch })).find((c) => c.name === "config grants");
  // Reported, not failed: a grant that is never sent only makes Sentrook stricter.
  assert.deepEqual(await verify({ grants: UNSENT_CONFIG }), {
    name: "config grants",
    ok: true,
    detail: `4 in config; never sent: ${UNSENT_SUMMARY}`,
  });
  assert.deepEqual(await verify({ grants: UNSENT_CONFIG.slice(3) }), { name: "config grants", ok: true, detail: "2 in config" });
});

test("startup warns about config grants never sent", async () => {
  const warnings = (await registered({ grants: UNSENT_CONFIG })).warnings;
  // The misspelt scope is also a setting not read as written; the entry without a pattern is one too.
  const [settings, warning, ...more] = warnings;
  assert.deepEqual(more, []);
  assert.ok(settings.includes('grants[2].scope: "persistant" is not session or persistent'), settings);
  assert.ok(settings.includes("grants[0]: needs kind and pattern; ignored"), settings);
  assert.ok(warning.includes(UNSENT_SUMMARY) && warning.includes("/sentrook-grants"), warning);
  assert.deepEqual((await registered({ grants: UNSENT_CONFIG.slice(3) })).warnings, []);
});

test("the command and the scan name a session alike", async () => {
  // The session_ref stored at command time is the one a scan of that session sends.
  const r = await registered();
  const sid = "7b0e6c1e-2f4a-4c55-9d1e-0a1b2c3d4e5f";
  await run(r, "sentrook-grant", "destination #ops", { sessionKey: "agent:main:telegram:dm:42", sessionId: sid });
  const [g] = stored().grants;
  await r.scan("post to #ops", sid, { sessionKey: "agent:main:telegram:dm:42" });
  assert.equal(g.session_ref, scans.at(-1).session.session_ref);
  assert.deepEqual(patterns(scans.at(-1).grants), ["#ops"]);
  // A command context with only a session key is keyed on it, as a scan with only a session key is.
  await run(r, "sentrook-grant", "destination #key", { sessionKey: "agent:main:key-only", sessionId: undefined });
  await r.scan("post to #key", "unused", { sessionKey: "agent:main:key-only", sessionId: undefined });
  assert.equal(stored().grants[1].session_ref, scans.at(-1).session.session_ref);
  assert.deepEqual(patterns(scans.at(-1).grants), ["#key"]);
});

test("a session grant needs a session", async () => {
  // The CLI, or a command context with no session, must name one with --session or use --persistent.
  const refusal =
    "There is no current session here, so a session grant cannot be bound to one; give " +
    "--session <ref> (from /sentrook-history) or --persistent (with --expires to end it).";
  const r = await registered();
  assert.equal(await cli(r, "sentrook grant [args...]", ["destination", "#ops"]), refusal);
  assert.equal(await run(r, "sentrook-grant", "destination #ops", { sessionId: undefined, sessionKey: undefined }), refusal);
  assert.equal(await run(r, "sentrook-grant", "destination #ops", { sessionId: "", sessionKey: "" }), refusal);
  assert.ok(!existsSync(file));
  assert.deepEqual(records("grants"), []);
  const out = await cli(r, "sentrook grant [args...]", ["destination", "#ops", "--session", S2]);
  assert.ok(out.endsWith(`: destination #ops (session ${S2} only).${NOTE}`), out);
  assert.deepEqual(patterns(await r.scan("post to #ops", "S2")), ["#ops"]);
  assert.deepEqual(await r.scan("post to #ops"), []);
  const persistent = await cli(r, "sentrook grant [args...]", ["destination", "#all", "--persistent", "--expires", "1h"]);
  assert.ok(persistent.includes(": destination #all (persistent, expires "), persistent);
});

test("a chat command can bind another session", async () => {
  const r = await registered();
  const out = await run(r, "sentrook-grant", `destination #ops --session ${S2}`);
  assert.ok(out.endsWith(`: destination #ops (session ${S2} only).${NOTE}`), out);
  assert.deepEqual(await r.scan("post to #ops"), []);
  assert.deepEqual(patterns(await r.scan("post to #ops", "S2")), ["#ops"]);
  const id = stored().grants[0].id;
  assert.ok((await run(r, "sentrook-grants", "")).includes(`${id}  destination  session  #ops     session ${S2}; set `));
  const fromS2 = await run(r, "sentrook-grants", "", { sessionKey: "agent:main:S2", sessionId: "S2" });
  assert.ok(fromS2.includes(`${id}  destination  session  #ops     this session; set `), fromS2);
});

test("a session grant still expires", async () => {
  mkdirSync(stateDir, { recursive: true });
  const live = { id: "gr-000001", kind: "destination", pattern: "#ops", scope: "session", session_ref: S1, expires_at: "2099-01-01T00:00:00Z" };
  writeFileSync(file, JSON.stringify({ grants: [live] }));
  const r = await registered();
  assert.deepEqual(patterns(await r.scan("post to #ops")), ["#ops"]);
  writeFileSync(file, JSON.stringify({ grants: [{ ...live, expires_at: "2026-01-01T00:00:00Z" }] }));
  assert.deepEqual(await r.scan("post to #ops"), []);
});

test("a session grant stored without a session is never sent", async () => {
  mkdirSync(stateDir, { recursive: true });
  const r = await registered();
  const entry = { id: "gr-000001", kind: "destination", pattern: "#ops", scope: "session" };
  for (const bad of [{}, { session_ref: "" }, { session_ref: null }, { session_ref: 7 }]) {
    writeFileSync(file, JSON.stringify({ grants: [{ ...entry, ...bad }] }));
    assert.deepEqual(await r.scan("post to #ops"), []);
    assert.ok((await run(r, "sentrook-grants", "")).includes("gr-000001  destination  session  #ops     no session, never sent"));
  }
});

test("persistent and config grants are sent in every session", async () => {
  const r = await registered({ grants: [{ kind: "destination", pattern: "#cfg" }] });
  const out = await run(r, "sentrook-grant", "destination #ops --persistent");
  assert.ok(out.endsWith(": destination #ops (persistent)."), out);
  assert.ok(!("session_ref" in stored().grants[0]));
  for (const [sid, extra] of [
    ["S1", {}],
    ["S2", {}],
    ["sub-1", { sessionKey: "agent:main:subagent:sub-1" }],
  ] as const) {
    assert.deepEqual(patterns(await r.scan("post to #ops and #cfg", sid, extra)), ["#cfg", "#ops"]);
  }
});

const RELEVANCE = JSON.parse(readFileSync(path.join(FIXTURES, "relevance.json"), "utf8"));

/** The identity OpenClaw gives a remote MCP server configured at `url`. */
const remoteIdentity = (url: string) => providerFor({ mcp: { servers: { srv: { url } } } }, "srv__tool").identity;

/** Shared with the Hermes plugin's tests: both hosts give a remote MCP server the same identity. */
const REMOTE = JSON.parse(readFileSync(path.join(FIXTURES, "..", "provider", "remote-identity.json"), "utf8"));
for (const c of REMOTE.cases) {
  test(`remote identity: ${c.url}`, () => {
    assert.equal(remoteIdentity(c.url), c.identity);
  });
}

/** Shared with the Hermes plugin's tests: both hosts send the same grants for the same call. */
for (const c of RELEVANCE.cases) {
  test(`relevance: ${c.case}`, () => {
    const sent = relevantGrants([c.grant], JSON.stringify(c.arguments), {
      identity: c.url ? remoteIdentity(c.url) : c.identity,
      home: c.home ?? RELEVANCE.home,
      workspace: c.workspace ?? RELEVANCE.workspace,
      cwd: callCwd(c.arguments),
      platform: callPlatform(c.arguments, c.tool_kind ?? "other"),
      execCall: c.tool_kind === "exec",
    });
    assert.equal(sent.length > 0, c.sent);
  });
}

/** Shared with the Hermes plugin's tests and the scanner's: a credential pattern is read as Sentrook reads it. */
const CREDENTIAL_PATTERNS = JSON.parse(readFileSync(path.join(FIXTURES, "credential-patterns.json"), "utf8"));
for (const c of CREDENTIAL_PATTERNS.cases) {
  test(`credential pattern: ${c.typed}`, () => {
    const parsed = grants.parseGrant(`credential ${c.typed}`, CMD);
    if (c.pattern === null) {
      assert.ok(typeof parsed === "string" && parsed.includes("is not a credential pattern"), String(parsed));
    } else {
      assert.deepEqual(parsed, { kind: "credential", pattern: c.pattern, scope: "persistent" });
    }
  });
}

test("naming a session makes a credential grant a session grant", () => {
  const parsed = grants.parseGrant("credential EXAMPLE_API_KEY@api.example.invalid --session s_0123456789ab", CMD);
  assert.ok(typeof parsed !== "string");
  assert.deepEqual([parsed.scope, parsed.session_ref], ["session", "s_0123456789ab"]);
});

/** Shared with the Hermes plugin's tests: both hosts say the same about a binding that can never apply. */
const BINDING_PROBLEMS = JSON.parse(readFileSync(path.join(FIXTURES, "binding-problems.json"), "utf8"));
for (const c of BINDING_PROBLEMS.cases) {
  test(`binding problem: ${c.pattern}`, () => {
    assert.equal(bindingProblem(c.pattern), c.problem);
  });
}

test("a channel binding reaches the scan of a message send in the form the owner wrote it", async () => {
  const r = await registered({ channelBindings: ["discord:#daily-brief", "#ops-yard"] });
  const send = async (channel: string, target: string) =>
    patterns((await r.call("message", { action: "send", channel, target, message: "Daily brief" }, "cron:daily")).grants);
  assert.deepEqual(await send("discord", "#daily-brief"), ["discord:#daily-brief"]);
  assert.deepEqual(await send("discord", "channel:ops-yard"), ["#ops-yard"]);
  // Must stay silent: the same name on another platform, and a direct message to someone named ops-yard.
  assert.deepEqual(await send("slack", "#daily-brief"), []);
  assert.deepEqual(await send("discord", "user:ops-yard"), []);
});

test("bind list, bind add and verify flag bindings that can never apply", async () => {
  const r = await registered({ channelBindings: ["#daily-brief", "*"] });
  assert.equal(await run(r, "sentrook-bind", "add ab"), "Channel binding added: ab (too short, never sent).");
  const rows = Object.fromEntries(
    (await run(r, "sentrook-bind", "list"))
      .split("\n")
      .slice(2)
      .map((l) => [l.split(/\s+/)[0], l]),
  );
  assert.ok(rows["#daily-brief"].endsWith("config, read-only"), rows["#daily-brief"]);
  assert.ok(rows["*"].endsWith("config, read-only; matches every channel, ignored"), rows["*"]);
  assert.ok(rows["ab"].endsWith("(operator.admin); too short, never sent"), rows["ab"]);
  const noFetch = (async () => {
    throw new Error("offline");
  }) as unknown as typeof fetch;
  const verify = async (cfg: Record<string, unknown>) =>
    (await runVerify(cfg, { env: {}, fetchImpl: noFetch })).find((c) => c.name === "channel bindings");
  // Reported, not failed: a binding that never applies only makes Sentrook stricter.
  assert.deepEqual(await verify({ channelBindings: ["#daily-brief", "*"] }), {
    name: "channel bindings",
    ok: true,
    detail: "2 in config; cannot apply: * (matches every channel, ignored)",
  });
  assert.deepEqual(await verify({ channelBindings: ["discord:#daily-brief"] }), { name: "channel bindings", ok: true, detail: "1 in config" });
});

test("provider and home grants reach the scan", async () => {
  const mcp = { mcp: { servers: { notes: { command: "npx", args: ["-y", "@acme/notes-mcp"] } } } };
  const r = await registered(
    {
      grants: [
        { kind: "provider", pattern: "npm:@acme/notes-mcp" },
        { kind: "file", pattern: "~/notes/*", allows: ["read"] },
      ],
    },
    mcp,
  );
  const scan = await r.call("notes__read", { path: path.join(homedir(), "notes", "a.md") });
  assert.equal(scan.pending_call.provider.identity, "npm:@acme/notes-mcp");
  assert.deepEqual(patterns(scan.grants), ["npm:@acme/notes-mcp", "~/notes/*"]);
});

test("./ paths reach the scan from the call's cwd and the workspace", async () => {
  const r = await registered({
    grants: [
      { kind: "file", pattern: "~/notes/*", allows: ["read"] },
      { kind: "file", pattern: "/srv/ws/src/*", allows: ["read"] },
    ],
  });
  for (const h of r.on.before_agent_run ?? []) h({ runId: "r1" }, { runId: "r1", workspaceDir: "/srv/ws" });
  const fromHome = await r.call("exec", { command: "cat ./notes/a.md", workdir: homedir() });
  assert.deepEqual(patterns(fromHome.grants), ["~/notes/*"]);
  assert.deepEqual(patterns((await r.call("read", { path: "./src/a.py" })).grants), ["/srv/ws/src/*"]);
});
