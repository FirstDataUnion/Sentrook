import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { helpText, OWNER_SUBCOMMANDS, runSentrookCommand } from "./commands.ts";
import { recentScans, recordsBackward } from "./history.ts";
import plugin from "./index.ts";
import { refusal } from "./owner.ts";

/** Shared with the Hermes plugin's tests: both hosts print the same text for the same log. */
const FIXTURES = fileURLToPath(new URL("../../fixtures/traffic-log/", import.meta.url));
/** Strings that appear only in call arguments, reason details and failure details in the fixture. */
const RAW = "RAW-ARG-MARKER";

const golden = (name: string) =>
  readFileSync(path.join(FIXTURES, name), "utf8").replace(/\n+$/, "").replaceAll("{why}", "/sentrook-why");

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE"];
const savedEnv: Record<string, string | undefined> = {};
let logFile = "";
beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OPENCLAW_STATE_DIR = mkdtempSync(path.join(tmpdir(), "sentrook-history-"));
  logFile = path.join(process.env.OPENCLAW_STATE_DIR, "sentrook", "traffic.jsonl");
  mkdirSync(path.dirname(logFile), { recursive: true });
  copyFileSync(path.join(FIXTURES, "traffic.jsonl"), logFile);
  copyFileSync(path.join(FIXTURES, "traffic.jsonl.1"), `${logFile}.1`);
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

/** Drop the fixture's torn last line, so the audit record appended next starts on its own line. */
function untorn() {
  const text = readFileSync(logFile, "utf8");
  writeFileSync(logFile, text.slice(0, text.lastIndexOf("\n") + 1));
}

function commandRecords() {
  return readFileSync(logFile, "utf8")
    .split("\n")
    .flatMap((l) => {
      try {
        return [JSON.parse(l)];
      } catch {
        return [];
      }
    })
    .filter((r) => r.kind === "command");
}

/** Registers the plugin with fake host registrars and returns its chat commands and CLI actions. */
async function registered(pluginConfig: Record<string, unknown> = {}) {
  const commands: Record<string, any> = {};
  const cliActions: Record<string, (...args: unknown[]) => Promise<void> | void> = {};
  const node = (prefix: string): any => {
    const self: any = {
      description: () => self,
      option: () => self,
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
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: () => undefined,
    registerCli: (r: any) => {
      cliRegistrar = r;
    },
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
  } as any);
  await cliRegistrar!({ program: node("") });
  return { commands, cliActions };
}

/** What the host passes an admitted owner on a Control UI connection. */
function ownerCtx(args: string, extra: Record<string, unknown> = {}) {
  return {
    senderId: "",
    channel: "webchat",
    senderIsOwner: true,
    gatewayClientScopes: ["operator.read", "operator.write", "operator.admin"],
    assertOwnerCurrent: () => undefined,
    args,
    ...extra,
  };
}

async function run(command: string, args: string, extra: Record<string, unknown> = {}, pluginConfig = {}) {
  const { commands } = await registered(pluginConfig);
  return (await commands[command].handler(ownerCtx(args, extra))).text as string;
}

async function captureLog(fn: () => Promise<void> | void): Promise<string> {
  const lines: string[] = [];
  const real = console.log;
  console.log = (...args: unknown[]) => void lines.push(args.map(String).join(" "));
  try {
    await fn();
  } finally {
    console.log = real;
  }
  return lines.join("\n");
}

test("the fixture log renders", async () => {
  assert.equal(await run("sentrook-history", ""), golden("history.txt"));
  assert.equal(await run("sentrook-why", ""), golden("why-last.txt"));
  assert.equal(await run("sentrook-why", "last"), golden("why-last.txt"));
  assert.equal(await run("sentrook-why", "4444a1b2"), golden("why-4444a1b2.txt"));
  assert.equal(await run("sentrook-why", "5555a1b2-0000-4000-8000-000000000005"), golden("why-5555a1b2.txt"));
});

test("a resolution joins its scan across the rotation", async () => {
  const row = (await run("sentrook-history", "")).split("\n").find((l) => l.startsWith("3333a1b2"))!;
  assert.equal(row.split(/\s+/).at(-1), "approved");
});

test("a torn last line and a garbled line are skipped", async () => {
  const out = await run("sentrook-history", "50");
  assert.ok(!out.includes("9999a1b2"));
  assert.ok(out.startsWith("Last 8 scans"));
  assert.ok((await run("sentrook-history", "1")).split("\n")[2]!.startsWith("8888a1b2"));
});

test("only the rotated file", async () => {
  rmSync(logFile);
  const out = await run("sentrook-history", "");
  assert.ok(out.startsWith("Last 3 scans"), out);
  assert.ok(out.includes("3333a1b2") && out.includes("no answer"));
});

test("history takes a count up to 50", async () => {
  const two = (await run("sentrook-history", "2")).split("\n");
  assert.deepEqual(
    two.slice(2, -1).map((r) => r.slice(0, 8)),
    ["8888a1b2", "7777a1b2"],
  );
  for (const bad of ["0", "-1", "two", "3 4"]) {
    assert.ok((await run("sentrook-history", bad)).startsWith("usage: /sentrook-history [n]"), bad);
  }
  const lines = Array.from({ length: 70 }, (_, i) =>
    JSON.stringify({
      ts: `2026-10-30T10:${String(Math.floor(i / 60)).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}.000Z`,
      kind: "scan",
      request_id: `${i.toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`,
      tool: "terminal",
      mode: "enforce",
      verdict: "allow",
      decision: "allowed",
      response: { risk: 1 },
    }),
  );
  writeFileSync(logFile, `${lines.join("\n")}\n`);
  assert.ok((await run("sentrook-history", "999")).startsWith("Last 50 scans"));
  assert.ok((await run("sentrook-history", "")).startsWith("Last 10 scans"));
});

test("no raw arguments are ever shown", async () => {
  const outputs = [await run("sentrook-history", "50"), await run("sentrook-why", "")];
  for (let n = 1; n <= 8; n++) outputs.push(await run("sentrook-why", `${String(n).repeat(4)}a1b2`));
  for (const out of outputs.slice(1)) assert.ok(out.includes("scan:"), out);
  for (const out of outputs) {
    assert.ok(!out.includes(RAW), out);
    assert.ok(!out.includes("curl"), out);
  }
});

test("why for an unknown or malformed id", async () => {
  assert.equal(await run("sentrook-why", "abcdef12"), "No scan abcdef12 in the recent traffic log.");
  assert.ok((await run("sentrook-why", "../../etc")).startsWith("usage: /sentrook-why [request_id|last]"));
});

test("a missing or disabled log", async () => {
  rmSync(logFile);
  rmSync(`${logFile}.1`);
  assert.equal(await run("sentrook-history", ""), "No scans in the traffic log yet.");
  assert.equal(await run("sentrook-why", ""), "No scans in the traffic log yet.");
  assert.equal(
    await run("sentrook-history", "", {}, { trafficLog: { enabled: false } }),
    "The traffic log is off, so there is no scan history.",
  );
});

test("history and why are owner commands that require the admin scope", async () => {
  const { commands } = await registered();
  assert.deepEqual(Object.keys(commands).sort(), [
    "sentrook",
    "sentrook-bind",
    "sentrook-grant",
    "sentrook-grants",
    "sentrook-history",
    "sentrook-revoke",
    "sentrook-snooze",
    "sentrook-why",
  ]);
  for (const name of ["sentrook-history", "sentrook-why"]) {
    assert.deepEqual(commands[name].requiredScopes, ["operator.admin"]);
    assert.equal(commands[name].acceptsArgs, true);
    assert.equal(commands[name].agentPromptGuidance, undefined);
  }
  assert.equal(commands.sentrook.requiredScopes, undefined, "/sentrook status stays open");
});

for (const [verb, sub] of Object.entries(OWNER_SUBCOMMANDS)) {
  test(`a non-owner is refused /${sub.command} and the refusal is audited`, async () => {
    untorn();
    for (const extra of [
      { senderIsOwner: false },
      { senderIsOwner: undefined, assertOwnerCurrent: undefined },
      {
        assertOwnerCurrent: () => {
          throw new Error("owner authority changed");
        },
      },
    ]) {
      const out = await run(sub.command, "5", extra);
      assert.equal(out, refusal(verb));
    }
    const recs = commandRecords();
    assert.deepEqual(
      recs.map((r) => [r.verb, r.outcome]),
      [
        [verb, "refused"],
        [verb, "refused"],
        [verb, "refused"],
      ],
    );
  });
}

test("the owner is audited", async () => {
  untorn();
  assert.ok((await run("sentrook-history", "")).startsWith("Last "));
  const [rec] = commandRecords();
  assert.deepEqual([rec.verb, rec.outcome, rec.basis], ["history", "allowed", ["operator.admin"]]);
});

test("/sentrook history and why point to the owner commands and show nothing", async () => {
  const ctx = { pluginConfig: {}, env: { OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR } };
  assert.equal(await runSentrookCommand("history 5", ctx), "/sentrook history is for the owner only: use /sentrook-history [n].");
  assert.equal(
    await runSentrookCommand("WHY", ctx),
    "/sentrook why is for the owner only: use /sentrook-why [request_id|last].",
  );
  const help = helpText();
  assert.match(help, /^ {2}\/sentrook-history \[n\] /m);
  assert.match(help, /^ {2}\/sentrook-why \[request_id\|last\] /m);
  assert.match(help, /^Owner only \(gateway scope operator\.admin\):$/m);
});

test("the CLI forms match the chat forms and are audited as the local terminal", async () => {
  untorn();
  const { commands, cliActions } = await registered();
  const chat = async (name: string, args: string) => (await commands[name].handler(ownerCtx(args))).text;
  assert.equal(await captureLog(() => cliActions["sentrook history [n]"]!()), await chat("sentrook-history", ""));
  assert.equal(await captureLog(() => cliActions["sentrook history [n]"]!("2")), await chat("sentrook-history", "2"));
  assert.equal(await captureLog(() => cliActions["sentrook why [request_id]"]!()), await chat("sentrook-why", ""));
  assert.equal(await captureLog(() => cliActions["sentrook why [request_id]"]!("4444a1b2")), golden("why-4444a1b2.txt"));
  assert.deepEqual(
    commandRecords().map((r) => r.basis[0]),
    ["local_terminal", "operator.admin", "local_terminal", "operator.admin", "local_terminal", "operator.admin", "local_terminal"],
  );
});

test("only the tail is read", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-tail-"));
  const file = path.join(dir, "traffic.jsonl");
  writeFileSync(
    file,
    Array.from({ length: 200 }, (_, i) => `${JSON.stringify({ kind: "scan", request_id: `r${i}`, pad: "x".repeat(1000) })}\n`).join(""),
  );
  const ids = [...recordsBackward(file, 10_000)].map((r) => r.request_id);
  assert.equal(ids[0], "r199");
  assert.ok(ids.length >= 5 && ids.length <= 10, String(ids.length));
  assert.deepEqual(
    recentScans(file, 3).map(([s]) => s.request_id),
    ["r199", "r198", "r197"],
  );
});

test("halves and wide characters print as on Hermes", async () => {
  copyFileSync(path.join(FIXTURES, "edge", "traffic.jsonl"), logFile);
  rmSync(`${logFile}.1`);
  assert.equal(await run("sentrook-history", ""), golden("edge/history.txt"));
  assert.equal(await run("sentrook-why", ""), golden("edge/why-last.txt"));
});

test("lines cross read chunks intact", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-chunks-"));
  const file = path.join(dir, "traffic.jsonl");
  writeFileSync(
    file,
    Array.from({ length: 300 }, (_, i) => `${JSON.stringify({ kind: "scan", request_id: `r${i}`, pad: "é🙂".repeat(50 + i * 3) })}\n`).join(""),
  );
  assert.ok(statSync(file).size > 10 * 64 * 1024);
  assert.deepEqual(
    [...recordsBackward(file)].map((r) => r.request_id),
    Array.from({ length: 300 }, (_, i) => `r${299 - i}`),
  );
});

test("a count in other digits is a usage error", async () => {
  for (const bad of ["²", "١٢", "1234567"]) {
    assert.ok((await run("sentrook-history", bad)).startsWith("usage: /sentrook-history [n]"), bad);
  }
});
