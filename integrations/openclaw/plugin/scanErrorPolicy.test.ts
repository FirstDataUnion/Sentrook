import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parseOnScanError,
  parseRetryAfterSeconds,
  resolveOnScanError,
  scanAuthErrorToFailure,
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
  detail: 'client_credentials token mint failed: HTTP 401: {"error":"invalid_client"}',
};

describe("parseOnScanError", () => {
  it("defaults to review", () => {
    assert.equal(parseOnScanError(undefined), "review");
    assert.equal(resolveOnScanError({}), "review");
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
    assert.match(blocked?.blockReason || "", /not a security policy deny/i);
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

  it("review unattended always blocks (ignores scheduledTimeoutBehavior)", () => {
    const denied = scanErrorToHookResult(timeoutFailure, {
      onScanError: "review",
      unattended: true,
      interactiveTimeoutMs: 300_000,
    });
    assert.equal(denied?.block, true);
    assert.equal(denied?.requireApproval, undefined);
  });

  it("401 never fail-opens on allow", () => {
    const result = scanErrorToHookResult(unauthorized, {
      onScanError: "allow",
      ...interactive,
    });
    assert.equal(result?.block, true);
    assert.match(result?.blockReason || "", /configuration error/i);
    assert.match(result?.blockReason || "", /not a security policy deny/i);
    assert.match(result?.blockReason || "", /invalid_client/);
    assert.equal(result?.requireApproval, undefined);
  });

  it("401 review interactive escalates with config-error card", () => {
    const result = scanErrorToHookResult(unauthorized, {
      onScanError: "review",
      ...interactive,
    });
    assert.equal(result?.block, undefined);
    assert.equal(result?.requireApproval?.title, "Sentrook authentication failed");
    assert.match(result?.requireApproval?.description || "", /configuration error/i);
    assert.match(result?.requireApproval?.description || "", /Continue this tool without scanning/);
  });

  it("401 review unattended blocks even when scheduledTimeoutBehavior is allow", () => {
    const result = scanErrorToHookResult(unauthorized, {
      onScanError: "review",
      unattended: true,
      interactiveTimeoutMs: 300_000,
    });
    assert.equal(result?.block, true);
    assert.equal(result?.requireApproval, undefined);
    assert.match(result?.blockReason || "", /configuration error/i);
  });
});

describe("scanAuthErrorToFailure", () => {
  it("maps HTTP 401 mint errors to auth failures", () => {
    const failure = scanAuthErrorToFailure(
      new Error('client_credentials token mint failed: HTTP 401: {"error":"invalid_client"}'),
    );
    assert.equal(failure.kind, "http");
    assert.equal(failure.status, 401);
    assert.match(failure.detail, /invalid_client/);
  });

  it("maps hung mint to timeout", () => {
    const failure = scanAuthErrorToFailure(new Error("OIDC request timed out after 30000ms"));
    assert.equal(failure.kind, "timeout");
  });

  it("maps other mint errors to network", () => {
    const failure = scanAuthErrorToFailure(new Error("ECONNREFUSED"));
    assert.equal(failure.kind, "network");
  });
});

describe("parseRetryAfterSeconds", () => {
  it("parses integer seconds", () => {
    assert.equal(parseRetryAfterSeconds("2"), 2);
  });
});
