import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { resolveApprovalPolicyConfig, TIMEOUT_BEHAVIOR_IGNORED_THROUGH, timeoutBehaviorNote } from "./approvalPolicy.ts";
import { openclawVersionFrom } from "./cli.ts";

const allow = resolveApprovalPolicyConfig({ pluginApproval: { scheduledTimeoutBehavior: "allow" } });
const deny = resolveApprovalPolicyConfig({ pluginApproval: { scheduledTimeoutBehavior: "deny" } });
const unset = resolveApprovalPolicyConfig({});

test("allow on a host that ignores timeoutBehavior gets one line naming the version and what happens", () => {
  for (const v of ["2026.10.3", "2026.9.5", "2026.5.27", TIMEOUT_BEHAVIOR_IGNORED_THROUGH, "2026.11.2-beta.1"]) {
    const note = timeoutBehaviorNote(allow, v);
    assert.ok(note, v);
    assert.ok(note.includes(`OpenClaw ${v}`), note);
    assert.match(note, /not honoured/);
    assert.match(note, /denied/);
    assert.ok(!note.includes("\n"));
  }
});

test("allow set through the env var counts too", () => {
  const fromEnv = resolveApprovalPolicyConfig({ env: { SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_BEHAVIOR: "allow" } });
  assert.ok(timeoutBehaviorNote(fromEnv, "2026.10.3"));
});

test("no line with deny, the default, an unknown host version or a newer host", () => {
  assert.equal(timeoutBehaviorNote(deny, "2026.10.3"), null);
  assert.equal(timeoutBehaviorNote(unset, "2026.10.3"), null);
  for (const v of [undefined, "", "unknown", "dev", "2026.11.3", "2026.12.1", "2027.1.1", "2026.11.5-beta.1"]) {
    assert.equal(timeoutBehaviorNote(allow, v), null, String(v));
  }
});

test("the CLI reads the host version from OPENCLAW_VERSION, else from the openclaw package above its entry", () => {
  const root = mkdtempSync(path.join(tmpdir(), "sentrook-ocver-"));
  writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "openclaw", version: "2026.10.3" }));
  mkdirSync(path.join(root, "dist", "cli"), { recursive: true });
  // A package.json of another name nearer the entry is skipped.
  writeFileSync(path.join(root, "dist", "package.json"), JSON.stringify({ type: "module" }));
  const entry = path.join(root, "dist", "cli", "run.mjs");
  writeFileSync(entry, "");

  assert.equal(openclawVersionFrom(entry, {}), "2026.10.3");
  assert.equal(openclawVersionFrom(entry, { OPENCLAW_VERSION: " 2026.11.2 " }), "2026.11.2");
  assert.equal(openclawVersionFrom(undefined, {}), undefined);
  assert.equal(openclawVersionFrom(path.join(tmpdir(), "no-such-dir", "x.mjs"), {}), undefined);

  const other = mkdtempSync(path.join(tmpdir(), "sentrook-ocver-"));
  writeFileSync(path.join(other, "package.json"), JSON.stringify({ name: "node", version: "22.0.0" }));
  writeFileSync(path.join(other, "node"), "");
  assert.equal(openclawVersionFrom(path.join(other, "node"), {}), undefined);
});
