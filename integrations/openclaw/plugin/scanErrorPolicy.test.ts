import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parseOnScanError,
  parseRetryAfterSeconds,
  resolveOnScanError,
  scanErrorToHookResult,
  type ScanFailure,
} from "./scanErrorPolicy.ts";

const timeoutFailure: ScanFailure = {
  ok: false,
  kind: "timeout",
  detail: "aborted",
};

const rateLimited: ScanFailure = {
  ok: false,
  kind: "rate_limited",
  status: 429,
  retryAfterSec: 1,
  detail: "rate limited",
};

const unauthorized: ScanFailure = {
  ok: false,
  kind: "http",
  status: 401,
  detail: "unauthorized",
};

describe("parseOnScanError", () => {
  it("defaults to allow", () => {
    assert.equal(parseOnScanError(undefined), "allow");
    assert.equal(resolveOnScanError({}), "allow");
  });

  it("reads plugin config then env", () => {
    assert.equal(resolveOnScanError({ pluginConfig: "review" }), "review");
    assert.equal(
      resolveOnScanError({ env: { SENTROOK_ON_SCAN_ERROR: "deny" } }),
      "deny",
    );
  });
});

describe("scanErrorToHookResult", () => {
  const interactive = {
    unattended: false,
    scheduledTimeoutBehavior: "deny" as const,
    interactiveTimeoutMs: 300_000,
  };

  it("allow: timeout and 429 return undefined (fail open)", () => {
    assert.equal(
      scanErrorToHookResult(timeoutFailure, { onScanError: "allow", ...interactive }),
      undefined,
    );
    assert.equal(
      scanErrorToHookResult(rateLimited, { onScanError: "allow", ...interactive }),
      undefined,
    );
  });

  it("deny: timeout and 429 block", () => {
    const blocked = scanErrorToHookResult(timeoutFailure, {
      onScanError: "deny",
      ...interactive,
    });
    assert.equal(blocked?.block, true);
    assert.match(blocked?.blockReason || "", /did not scan/);
    const limited = scanErrorToHookResult(rateLimited, {
      onScanError: "deny",
      ...interactive,
    });
    assert.equal(limited?.block, true);
    assert.match(limited?.blockReason || "", /rate-limited/);
  });

  it("review interactive: requireApproval allow-once/deny only", () => {
    const result = scanErrorToHookResult(timeoutFailure, {
      onScanError: "review",
      ...interactive,
    });
    const approval = result?.requireApproval;
    assert.ok(approval);
    assert.equal(approval.title, "Sentrook unreachable");
    assert.match(approval.description, /continue anyway without scanning/);
    assert.deepEqual(approval.allowedDecisions, ["allow-once", "deny"]);
    assert.equal(approval.timeoutBehavior, "deny");
  });

  it("review interactive 429 uses rate-limit copy", () => {
    const result = scanErrorToHookResult(rateLimited, {
      onScanError: "review",
      ...interactive,
    });
    assert.equal(result?.requireApproval?.title, "Sentrook rate limited");
  });

  it("review unattended follows scheduledTimeoutBehavior immediately", () => {
    const denied = scanErrorToHookResult(timeoutFailure, {
      onScanError: "review",
      unattended: true,
      scheduledTimeoutBehavior: "deny",
      interactiveTimeoutMs: 300_000,
    });
    assert.equal(denied?.block, true);
    assert.equal(denied?.requireApproval, undefined);

    const allowed = scanErrorToHookResult(timeoutFailure, {
      onScanError: "review",
      unattended: true,
      scheduledTimeoutBehavior: "allow",
      interactiveTimeoutMs: 300_000,
    });
    assert.equal(allowed, undefined);
  });

  it("401 always denies and never uses the unreachable card", () => {
    const result = scanErrorToHookResult(unauthorized, {
      onScanError: "allow",
      ...interactive,
    });
    assert.equal(result?.block, true);
    assert.match(result?.blockReason || "", /credentials/);
    assert.equal(result?.requireApproval, undefined);
  });
});

describe("parseRetryAfterSeconds", () => {
  it("parses integer seconds", () => {
    assert.equal(parseRetryAfterSeconds("2"), 2);
  });
});
