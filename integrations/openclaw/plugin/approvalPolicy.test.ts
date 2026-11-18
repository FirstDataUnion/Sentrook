import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS,
  resolveApprovalPolicyConfig,
  resolveApprovalTiming,
} from "./approvalPolicy.ts";

const manifest = JSON.parse(readFileSync(new URL("./openclaw.plugin.json", import.meta.url), "utf8"));
const approvalSchema = manifest.configSchema.properties.approval;

test("the manifest's approval settings are the interactive timeout and the unattended run kinds, nothing else", () => {
  assert.deepEqual(Object.keys(approvalSchema.properties).sort(), ["interactiveTimeoutMs", "scheduledIntentKinds"]);
  assert.equal(approvalSchema.additionalProperties, false);
});

test("a review in a chat waits the interactive timeout, 5 minutes unless set", () => {
  const unset = resolveApprovalPolicyConfig({});
  assert.deepEqual(resolveApprovalTiming(unset, "user", undefined), {
    timeoutMs: DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS,
    unattended: false,
  });
  assert.equal(DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS, 300_000);

  const fromConfig = resolveApprovalPolicyConfig({ pluginApproval: { interactiveTimeoutMs: 60_000 } });
  assert.equal(resolveApprovalTiming(fromConfig, "user", undefined).timeoutMs, 60_000);
  const fromEnv = resolveApprovalPolicyConfig({ env: { SENTROOK_APPROVAL_TIMEOUT_MS: "90000" } });
  assert.equal(resolveApprovalTiming(fromEnv, "user", undefined).timeoutMs, 90_000);
});

test("cron and subagent runs are unattended by default; scheduledIntentKinds changes which", () => {
  const unset = resolveApprovalPolicyConfig({});
  for (const kind of ["cron", "subagent"] as const) {
    assert.equal(resolveApprovalTiming(unset, kind, undefined).unattended, true, kind);
  }
  for (const kind of ["user", "system", undefined] as const) {
    assert.equal(resolveApprovalTiming(unset, kind, undefined).unattended, false, String(kind));
  }
  const cronOnly = resolveApprovalPolicyConfig({ pluginApproval: { scheduledIntentKinds: ["cron"] } });
  assert.equal(resolveApprovalTiming(cronOnly, "subagent", undefined).unattended, false);
});

test("the policy carries no unattended timeout or timeout behaviour", () => {
  const policy = resolveApprovalPolicyConfig({});
  assert.deepEqual(Object.keys(policy).sort(), ["interactiveTimeoutMs", "scheduledIntentKinds"]);
});
