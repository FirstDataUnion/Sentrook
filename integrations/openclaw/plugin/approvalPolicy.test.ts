import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS,
  DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS,
  resolveApprovalPolicyConfig,
  resolveApprovalTiming,
  resolveIntentKind,
} from "./approvalPolicy.ts";

describe("resolveIntentKind", () => {
  it("prefers explicit intent_kind", () => {
    assert.equal(resolveIntentKind("user", "[cron:abc] daily"), "user");
  });

  it("classifies cron prefix from intent text", () => {
    assert.equal(
      resolveIntentKind(undefined, "[cron:abc] Daily Brief"),
      "cron",
    );
  });

  it("classifies subagent markers", () => {
    assert.equal(
      resolveIntentKind(undefined, "[Subagent Task]\nCollect calendar events"),
      "subagent",
    );
  });
});

describe("resolveApprovalTiming", () => {
  const policy = resolveApprovalPolicyConfig({});

  it("uses interactive deny for user intents", () => {
    const timing = resolveApprovalTiming(policy, "user", "check my email");
    assert.equal(timing.timeoutMs, DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS);
    assert.equal(timing.timeoutBehavior, "deny");
    assert.equal(timing.unattended, false);
  });

  it("uses scheduled deny for cron intents", () => {
    const timing = resolveApprovalTiming(
      policy,
      "cron",
      "[cron:abc] Daily Brief",
    );
    assert.equal(timing.timeoutMs, DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS);
    assert.equal(timing.timeoutBehavior, "deny");
    assert.equal(timing.unattended, true);
  });

  it("uses scheduled deny for subagent intents", () => {
    const timing = resolveApprovalTiming(
      policy,
      "subagent",
      "[Subagent Task] run calendar sync",
    );
    assert.equal(timing.unattended, true);
    assert.equal(timing.timeoutBehavior, "deny");
  });

  it("honours scheduledTimeoutBehavior allow override", () => {
    const open = resolveApprovalPolicyConfig({
      pluginApproval: { scheduledTimeoutBehavior: "allow" },
    });
    const timing = resolveApprovalTiming(
      open,
      "cron",
      "[cron:abc] Daily Brief",
    );
    assert.equal(timing.timeoutBehavior, "allow");
    assert.equal(timing.unattended, true);
  });

  it("uses interactive policy when kind is outside scheduledIntentKinds", () => {
    const narrowed = resolveApprovalPolicyConfig({
      pluginApproval: { scheduledIntentKinds: ["subagent"] },
    });
    const timing = resolveApprovalTiming(
      narrowed,
      "cron",
      "[cron:abc] Daily Brief",
    );
    assert.equal(timing.timeoutBehavior, "deny");
    assert.equal(timing.timeoutMs, DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS);
    assert.equal(timing.unattended, false);
  });
});

describe("resolveApprovalPolicyConfig", () => {
  it("reads env overrides", () => {
    const policy = resolveApprovalPolicyConfig({
      env: {
        SENTROOK_APPROVAL_TIMEOUT_MS: "60000",
        SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_MS: "300000",
        SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_BEHAVIOR: "allow",
      },
    });
    assert.equal(policy.interactiveTimeoutMs, 60_000);
    assert.equal(policy.scheduledTimeoutMs, 300_000);
    assert.equal(policy.scheduledTimeoutBehavior, "allow");
  });

  it("defaults scheduledTimeoutBehavior to deny", () => {
    const policy = resolveApprovalPolicyConfig({});
    assert.equal(policy.scheduledTimeoutBehavior, "deny");
  });
});
