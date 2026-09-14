import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS,
  DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS,
  MAX_APPROVAL_TIMEOUT_MS,
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
    const timing = resolveApprovalTiming(policy, { intentText: "check my email" });
    assert.equal(timing.timeoutMs, DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS);
    assert.equal(timing.timeoutBehavior, "deny");
    assert.equal(timing.unattended, false);
  });

  it("uses scheduled deny for cron intents", () => {
    const timing = resolveApprovalTiming(policy, {
      trigger: "cron",
      intentText: "[cron:abc] Daily Brief",
    });
    assert.equal(timing.timeoutMs, DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS);
    assert.equal(timing.timeoutBehavior, "deny");
    assert.equal(timing.unattended, true);
  });

  it("uses scheduled deny for heartbeat intents", () => {
    const timing = resolveApprovalTiming(policy, { trigger: "heartbeat" });
    assert.equal(timing.unattended, true);
    assert.equal(timing.timeoutBehavior, "deny");
  });

  it("uses interactive policy for a subagent of a user session", () => {
    const timing = resolveApprovalTiming(policy, {
      sessionKey: "agent:main:subagent:search",
      parentSessionKey: "agent:main:main",
      intentText: "[Subagent Task] run calendar sync",
    });
    assert.equal(timing.unattended, false);
    assert.equal(timing.timeoutMs, DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS);
  });

  it("uses scheduled deny for a subagent of a cron session", () => {
    const timing = resolveApprovalTiming(policy, {
      sessionKey: "agent:main:subagent:nightly",
      parentSessionKey: "agent:main:cron:abc:run:1",
    });
    assert.equal(timing.unattended, true);
    assert.equal(timing.timeoutBehavior, "deny");
  });

  it("ignores scheduledTimeoutBehavior allow (OpenClaw 2.0 always deny)", () => {
    const open = resolveApprovalPolicyConfig({
      pluginApproval: { scheduledTimeoutBehavior: "allow" },
    });
    assert.equal(open.scheduledTimeoutBehavior, "allow");
    const timing = resolveApprovalTiming(open, {
      trigger: "cron",
      intentText: "[cron:abc] Daily Brief",
    });
    assert.equal(timing.timeoutBehavior, "deny");
    assert.equal(timing.unattended, true);
  });

  it("uses interactive policy when kind is outside scheduledIntentKinds", () => {
    const narrowed = resolveApprovalPolicyConfig({
      pluginApproval: { scheduledIntentKinds: ["subagent"] },
    });
    const timing = resolveApprovalTiming(narrowed, {
      trigger: "cron",
      intentText: "[cron:abc] Daily Brief",
    });
    assert.equal(timing.timeoutBehavior, "deny");
    assert.equal(timing.timeoutMs, DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS);
    assert.equal(timing.unattended, false);
  });

  it("treats an explicit unattended boolean as authoritative", () => {
    const timing = resolveApprovalTiming(policy, true);
    assert.equal(timing.unattended, true);
    assert.equal(timing.timeoutMs, DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS);
  });
});

describe("resolveApprovalPolicyConfig", () => {
  it("defaults both review windows to the 10 minute cap", () => {
    const policy = resolveApprovalPolicyConfig({});
    assert.equal(policy.interactiveTimeoutMs, MAX_APPROVAL_TIMEOUT_MS);
    assert.equal(policy.scheduledTimeoutMs, MAX_APPROVAL_TIMEOUT_MS);
    assert.equal(policy.scheduledTimeoutBehavior, "deny");
    assert.deepEqual(policy.scheduledIntentKinds, ["cron", "heartbeat"]);
  });

  it("reads env overrides and still parses deprecated allow", () => {
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

  it("caps review timeouts at 10 minutes without erroring", () => {
    const policy = resolveApprovalPolicyConfig({
      pluginApproval: {
        interactiveTimeoutMs: 1_800_000,
        scheduledTimeoutMs: 9_999_999,
        scheduledTimeoutBehavior: "allow",
      },
    });
    assert.equal(policy.interactiveTimeoutMs, MAX_APPROVAL_TIMEOUT_MS);
    assert.equal(policy.scheduledTimeoutMs, MAX_APPROVAL_TIMEOUT_MS);
    assert.equal(policy.scheduledTimeoutBehavior, "allow");
  });
});
