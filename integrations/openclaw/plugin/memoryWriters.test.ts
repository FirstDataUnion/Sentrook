import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { dreamingState, memoryWriterChecks, sessionMemoryHookState } from "./memoryWriters.ts";
import { runVerify } from "./verify.ts";

const DREAMING_OFF = { plugins: { entries: { "memory-core": { config: { dreaming: { enabled: false } } } } } };
const HOOK_ON = { hooks: { internal: { entries: { "session-memory": { enabled: true } } } } };
const BOTH_ON = { ...HOOK_ON };
const BOTH_OFF = { ...DREAMING_OFF, hooks: { internal: { entries: { "session-memory": { enabled: false } } } } };
const HOOK_ONLY = { ...DREAMING_OFF, ...HOOK_ON };

const DREAMING_LINE = /^ok   dreaming: .*MEMORY\.md.*openclaw config set plugins\.entries\.memory-core\.config\.dreaming\.enabled false/m;
const HOOK_LINE = /^ok   session-memory hook: .*openclaw hooks disable session-memory/m;

const noFetch = (async () => {
  throw new Error("no network in tests");
}) as unknown as typeof fetch;
const OFFLINE = { scanUrl: "http://scan.invalid" };

async function report(hostConfig: unknown) {
  const { formatVerifyReport } = await import("./verify.ts");
  const checks = await runVerify(OFFLINE, { env: {}, fetchImpl: noFetch, hostConfig });
  return { checks, text: formatVerifyReport(checks) };
}

test("dreaming is on unless its setting is false, as OpenClaw reads it", () => {
  assert.equal(dreamingState({}), "on", "a bare config runs dreaming");
  assert.equal(dreamingState(DREAMING_OFF), "off");
  assert.equal(dreamingState({ plugins: { entries: { "memory-core": { config: { dreaming: { enabled: "false" } } } } } }), "off");
  assert.equal(dreamingState({ plugins: { entries: { "memory-core": { config: { dreaming: { enabled: true } } } } } }), "on");
  assert.equal(dreamingState({ plugins: { entries: { "memory-core": { config: { dreaming: { enabled: "TRUE" } } } } } }), "on");
});

test("dreaming is off when memory-core cannot run, and unknown when it may not", () => {
  assert.equal(dreamingState({ plugins: { enabled: false } }), "off");
  assert.equal(dreamingState({ plugins: { entries: { "memory-core": { enabled: false } } } }), "off");
  assert.equal(dreamingState({ plugins: { deny: ["memory-core"] } }), "off");
  assert.equal(dreamingState({ plugins: { slots: { memory: "none" } } }), "off");
  assert.equal(dreamingState({ plugins: { slots: { memory: "memory-lancedb" } } }), null);
  assert.equal(dreamingState({ plugins: { slots: { memory: "memory-core" } } }), "on");
  assert.equal(dreamingState({ plugins: { allow: ["sentrook"] } }), null);
  assert.equal(dreamingState({ plugins: { allow: ["sentrook", "memory-core"] } }), "on");
  assert.equal(dreamingState({ cron: { enabled: false } }), null);
});

test("the session-memory hook is on only when OpenClaw would select it", () => {
  assert.equal(sessionMemoryHookState({}), "off", "a bare config loads no internal hooks");
  assert.equal(sessionMemoryHookState(HOOK_ON), "on");
  assert.equal(sessionMemoryHookState({ hooks: { internal: { entries: { "session-memory": {} } } } }), "on");
  assert.equal(sessionMemoryHookState(BOTH_OFF), "off");
  assert.equal(sessionMemoryHookState({ hooks: { internal: { enabled: true } } }), "on", "open discovery");
  assert.equal(sessionMemoryHookState({ hooks: { internal: { load: { extraDirs: ["/x"] } } } }), "on");
  assert.equal(sessionMemoryHookState({ hooks: { internal: { enabled: true, load: { extraDirs: ["  "] } } } }), "on");
  assert.equal(
    sessionMemoryHookState({ hooks: { internal: { enabled: true, entries: { "command-logger": { enabled: true } } } } }),
    "off",
    "named entries form an allowlist",
  );
  assert.equal(
    sessionMemoryHookState({ hooks: { internal: { enabled: true, load: { extraDirs: ["/x"] }, entries: { "session-memory": { enabled: false } } } } }),
    "off",
  );
});

test("the master switch off silences the hook whatever the entry says", () => {
  const cfg = { hooks: { internal: { enabled: false, entries: { "session-memory": { enabled: true } } } } };
  assert.equal(sessionMemoryHookState(cfg), "off");
  assert.deepEqual(memoryWriterChecks({ ...DREAMING_OFF, ...cfg }), []);
});

test("settings that cannot be read give no line", () => {
  for (const cfg of [undefined, null, "x", 3, []]) {
    assert.equal(dreamingState(cfg), null);
    assert.equal(sessionMemoryHookState(cfg), null);
    assert.deepEqual(memoryWriterChecks(cfg), []);
  }
  const odd = { plugins: "x", hooks: { internal: "x" } };
  assert.equal(dreamingState(odd), null);
  assert.equal(sessionMemoryHookState(odd), null);
});

test("verify prints the dreaming line, the hook line, or both", async () => {
  let { text } = await report({});
  assert.match(text, DREAMING_LINE, "bare config: dreaming");
  assert.doesNotMatch(text, /session-memory hook:/, "bare config: no hook line");

  ({ text } = await report(HOOK_ONLY));
  assert.match(text, HOOK_LINE);
  assert.doesNotMatch(text, /dreaming:/);

  ({ text } = await report(BOTH_ON));
  assert.match(text, DREAMING_LINE);
  assert.match(text, HOOK_LINE);
  assert.ok(text.indexOf("dreaming:") < text.indexOf("session-memory hook:"), "dreaming leads");
});

test("verify prints nothing about memory writers when both are off or the config cannot be read", async () => {
  for (const cfg of [BOTH_OFF, undefined]) {
    const { text } = await report(cfg);
    assert.doesNotMatch(text, /dreaming:|session-memory hook:/);
  }
});

test("the memory writer lines never fail verify", async () => {
  const failing = (checks: { ok: boolean; name: string }[]) => checks.filter((c) => !c.ok).map((c) => c.name);
  const base = failing((await report(BOTH_OFF)).checks);
  for (const cfg of [{}, HOOK_ONLY, BOTH_ON]) {
    const { checks } = await report(cfg);
    assert.deepEqual(failing(checks), base);
    for (const c of checks.filter((c) => c.name === "dreaming" || c.name === "session-memory hook")) assert.equal(c.ok, true);
  }
});

test("the README gives the same commands verify prints", () => {
  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
  const checks = memoryWriterChecks(HOOK_ON);
  assert.equal(checks.length, 2);
  for (const c of checks) {
    const command = c.detail.slice(c.detail.lastIndexOf("openclaw "));
    assert.ok(readme.includes("```bash\n" + command + "\n```"), `README has a block with: ${command}`);
  }
});
