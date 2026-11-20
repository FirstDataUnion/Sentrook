import assert from "node:assert/strict";
import { closeSync, copyFileSync, fstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, test } from "node:test";

import { REPORT_USAGE } from "./commands.ts";
import { SUPPORT_EMAIL, WRONG_SCAN_ISSUE_URL } from "./config.ts";
import { formatWhy, LOG_OFF, NO_SCANS, parseRef } from "./history.ts";
import plugin from "./index.ts";
import * as report from "./report.ts";

/** Shared with the Hermes plugin's tests: both hosts build the same report for the same log. */
const FIXTURES = fileURLToPath(new URL("../../fixtures/traffic-log/report/", import.meta.url));
const ISSUE_FORM = fileURLToPath(new URL("../../../.github/ISSUE_TEMPLATE/wrong_scan.yml", import.meta.url));
/** Strings that appear only in the PlanIR body, reason details and failure details in the fixture. */
const PRIVATE = ["PLANIR-BODY-MARKER", "PRIVATE-PATH-MARKER"];
const IDS = ["aaaa1b2c", "bbbb1b2c", "cccc1b2c"];
const LONG_IDS = ["dddd1b2c", "eeee1b2c"];
const CASES: Array<[string, string]> = [
  ...IDS.map((i): [string, string] => ["traffic.jsonl", i]),
  ...LONG_IDS.map((i): [string, string] => ["long.jsonl", i]),
  ["odd.jsonl", "odd"],
];

const golden = (name: string) => readFileSync(path.join(FIXTURES, name), "utf8").replace(/\n+$/, "");
const found = (logName: string, ref: string) => report.find(path.join(FIXTURES, logName), parseRef(ref === "odd" ? "last" : ref)!)!;
const hasPrivate = (s: string) => PRIVATE.some((m) => s.includes(m));

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE"];
const savedEnv: Record<string, string | undefined> = {};
let logFile = "";
beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OPENCLAW_STATE_DIR = mkdtempSync(path.join(tmpdir(), "sentrook-report-"));
  logFile = path.join(process.env.OPENCLAW_STATE_DIR, "sentrook", "traffic.jsonl");
  mkdirSync(path.dirname(logFile), { recursive: true });
  copyFileSync(path.join(FIXTURES, "traffic.jsonl"), logFile);
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

/** Registers the plugin with fake host registrars and returns its chat commands and CLI actions. */
async function registered(pluginConfig: Record<string, unknown> = {}) {
  const commands: Record<string, any> = {};
  const cliActions: Record<string, (...args: unknown[]) => Promise<void> | void> = {};
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

async function run(args: string, pluginConfig: Record<string, unknown> = {}) {
  const { commands } = await registered(pluginConfig);
  const ctx = {
    senderId: "",
    channel: "webchat",
    senderIsOwner: true,
    gatewayClientScopes: ["operator.read", "operator.write", "operator.admin"],
    assertOwnerCurrent: () => undefined,
    args,
  };
  return (await commands["sentrook-report"].handler(ctx)).text as string;
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

/** The issue form's field ids, read from its YAML without a YAML parser. */
function formFieldIds(): Set<string> {
  return new Set([...readFileSync(ISSUE_FORM, "utf8").matchAll(/^ {4}id: (\S+)$/gm)].map((m) => m[1]!));
}

for (const [logName, ref] of CASES) {
  test(`${ref}: the report matches the shared goldens`, () => {
    const f = found(logName, ref);
    assert.equal(report.summary(f.scan, f.resolution), golden(`summary-${ref}.txt`));
    assert.equal(report.fullRecord(f), golden(`full-${ref}.txt`));
    const [url, fitted] = report.githubLink(f.scan, f.resolution);
    assert.equal(`${fitted || "whole"}\n${url}`, golden(`github-${ref}.txt`));
    assert.equal(report.mailto(f.scan), golden(`mailto-${ref}.txt`));
  });
}

test("the full record is the log lines byte for byte", () => {
  const lines = readFileSync(path.join(FIXTURES, "traffic.jsonl"), "utf8").split("\n");
  assert.deepEqual(report.fullRecord(found("traffic.jsonl", "aaaa1b2c")).split("\n"), [report.FULL_BEGIN, lines[0], lines[1], report.FULL_END]);
});

test("summaries and links hold no private content", () => {
  for (const [logName, ref] of CASES) {
    const f = found(logName, ref);
    const [url] = report.githubLink(f.scan, f.resolution);
    for (const out of [report.summary(f.scan, f.resolution), url, report.mailto(f.scan)]) assert.ok(!hasPrivate(out), ref);
  }
  assert.ok(hasPrivate(report.fullRecord(found("traffic.jsonl", "aaaa1b2c"))));
});

test("grant suggestions stay out of the summary", () => {
  const f = found("traffic.jsonl", "aaaa1b2c");
  assert.ok(formatWhy(f.scan, f.resolution).includes("grants that would allow"));
  assert.ok(!report.summary(f.scan, f.resolution).includes("grant"));
});

test("links fit and name the form's fields", () => {
  const fields = formFieldIds();
  for (const [logName, ref] of CASES) {
    const f = found(logName, ref);
    const [url, fitted] = report.githubLink(f.scan, f.resolution);
    assert.ok(url.length <= report.URL_MAX);
    assert.ok(url.startsWith(WRONG_SCAN_ISSUE_URL));
    const params = new URL(url).searchParams;
    for (const key of params.keys()) assert.ok(key === "template" || key === "title" || fields.has(key), key);
    assert.equal(params.get("template"), "wrong_scan.yml");
    assert.equal(params.has("report"), fitted !== "blank");
    const mail = report.mailto(f.scan);
    assert.ok(mail.startsWith(`mailto:${SUPPORT_EMAIL}?`) && mail.length < 500);
    assert.ok(new URLSearchParams(mail.split("?")[1]).get("subject")!.includes(f.scan.request_id.slice(0, 8)));
  }
  const trimmed = new URL(golden("github-dddd1b2c.txt").split("\n")[1]!).searchParams.get("report")!;
  assert.ok(trimmed.includes("  (trimmed, 28 more)") && trimmed.endsWith(report.END));
});

test("report replies", async () => {
  const out = await run("aaaa1b2c");
  assert.ok(out.startsWith(`${golden("summary-aaaa1b2c.txt")}\n\n`));
  assert.ok(out.includes("/sentrook-report aaaa1b2c --github") && out.includes(SUPPORT_EMAIL));
  assert.ok((await run("")).startsWith(golden("summary-cccc1b2c.txt")));
  assert.equal(await run("last"), await run(""));
  assert.equal(await run("aaaa1b2c --full"), [golden("summary-aaaa1b2c.txt"), report.FULL_WARNING, golden("full-aaaa1b2c.txt")].join("\n\n"));
  const gh = await run("bbbb --github");
  assert.ok(gh.split("\n").includes(golden("github-bbbb1b2c.txt").split("\n")[1]!) && gh.includes("The issue is public"));
  assert.ok(gh.includes("/sentrook-report bbbb1b2c --save"));
  for (const o of [out, await run("aaaa1b2c --github")]) assert.ok(!hasPrivate(o));
});

test("--save writes a file only the owner can read", async () => {
  const out = await run("aaaa1b2c --save");
  const file = out.split(" to ")[1]!.split(" (readable")[0]!;
  assert.equal(path.dirname(file), path.join(path.dirname(logFile), "reports"));
  // One handle for the mode and the content, so both describe the same file.
  const fd = openSync(file, "r");
  try {
    assert.equal(fstatSync(fd).mode & 0o777, 0o600);
    assert.equal(readFileSync(fd, "utf8"), `${[golden("summary-aaaa1b2c.txt"), report.FULL_WARNING, golden("full-aaaa1b2c.txt")].join("\n\n")}\n`);
  } finally {
    closeSync(fd);
  }
  assert.ok(out.includes(SUPPORT_EMAIL) && out.includes('"Sentrook wrong scan aaaa1b2c"'));
  assert.ok(!hasPrivate(out));
});

test("bad arguments, unknown ids and a missing or disabled log", async () => {
  for (const bad of ["aaaa --bogus", "aaaa --full --github", "aaaa bbbb", "../../etc", "--full --save"]) {
    assert.equal(await run(bad), REPORT_USAGE, bad);
  }
  assert.equal(await run("abcdef12"), "No scan abcdef12 in the recent traffic log.");
  assert.ok((await run("--full")).startsWith(golden("summary-cccc1b2c.txt")));
  unlinkSync(logFile);
  assert.equal(await run(""), NO_SCANS);
  assert.equal(await run("", { trafficLog: { enabled: false } }), LOG_OFF);
});

test("the CLI form matches the chat form", async () => {
  const { cliActions } = await registered();
  const action = cliActions["sentrook report [args...]"]!;
  assert.equal(await captureLog(() => action(["aaaa1b2c", "--full"])), await run("aaaa1b2c --full"));
  assert.equal(await captureLog(() => action([])), await run(""));
});

test("a malformed record still reports, and --save stays inside the reports folder", async () => {
  copyFileSync(path.join(FIXTURES, "odd.jsonl"), logFile);
  assert.ok((await run("")).startsWith(golden("summary-odd.txt")));
  assert.ok((await run("--github")).includes(golden("github-odd.txt").split("\n")[1]!));
  const out = await run("--save");
  const file = out.split(" to ")[1]!.split(" (readable")[0]!;
  assert.equal(path.dirname(file), path.join(path.dirname(logFile), "reports"));
  assert.ok(path.basename(file).startsWith("sentrook-report-_______x-"));
});

test("the CLI takes a flag without an id", async () => {
  const { cliActions } = await registered();
  const action = cliActions["sentrook report [args...]"]!;
  assert.equal(await captureLog(() => action(["--full"])), await run("--full"));
  assert.equal(await captureLog(() => action(["--full", "aaaa1b2c"])), await run("aaaa1b2c --full"));
});
