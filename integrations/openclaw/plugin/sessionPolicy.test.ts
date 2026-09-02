import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  formatDuration,
  parseOnOff,
  parseQuietDuration,
  parseSensitivity,
  QUIET_CAP_MS,
  resolveReviewSkip,
  skipResolutionDecision,
} from "./sessionPolicy.ts";

describe("parseQuietDuration", () => {
  const now = Date.parse("2026-09-02T12:00:00.000Z");

  it("turns off", () => {
    assert.deepEqual(parseQuietDuration("off", now), { untilMs: null });
    assert.deepEqual(parseQuietDuration("0", now), { untilMs: null });
  });

  it("accepts minutes and hours and caps at 8h", () => {
    const thirty = parseQuietDuration("30m", now);
    assert.ok(!("error" in thirty));
    assert.equal(thirty.untilMs, now + 30 * 60 * 1000);
    const eight = parseQuietDuration("8h", now);
    assert.ok(!("error" in eight));
    assert.equal(eight.untilMs, now + QUIET_CAP_MS);
    const over = parseQuietDuration("9h", now);
    assert.ok("error" in over);
    assert.match(over.error, /8 hours/);
  });
});

describe("parseOnOff / sensitivity", () => {
  it("defaults allow-all with no arg to on", () => {
    assert.equal(parseOnOff(undefined, true), true);
    assert.equal(parseOnOff("off", true), false);
    assert.ok(typeof parseOnOff("maybe", true) === "object");
  });

  it("parses sensitivity", () => {
    assert.equal(parseSensitivity("lenient"), "lenient");
    assert.equal(parseSensitivity("nope"), "strict");
  });

  it("formats remaining time", () => {
    assert.equal(formatDuration(45_000), "45s");
    assert.equal(formatDuration(5 * 60_000), "5m");
    assert.equal(formatDuration(2 * 3600_000), "2h");
  });
});

describe("resolveReviewSkip", () => {
  const base = {
    hostedDecision: "review" as const,
    unattended: false,
    allowAll: false,
    quietUntilMs: null as number | null,
    sensitivity: "strict" as const,
    reviewSeverity: "warning",
    allowlistHit: false,
    nowMs: 1_000,
  };

  it("does not skip allow or block", () => {
    assert.equal(resolveReviewSkip({ ...base, hostedDecision: "allow" }), undefined);
    assert.equal(resolveReviewSkip({ ...base, hostedDecision: "block" }), undefined);
  });

  it("prefers allowlist, then allow-all, then quiet, then lenient info", () => {
    assert.equal(resolveReviewSkip({ ...base, allowlistHit: true, allowAll: true }), "allowlist");
    assert.equal(resolveReviewSkip({ ...base, allowAll: true }), "allow-all");
    assert.equal(resolveReviewSkip({ ...base, quietUntilMs: 2_000 }), "quiet");
    assert.equal(resolveReviewSkip({ ...base, quietUntilMs: 500 }), undefined);
    assert.equal(
      resolveReviewSkip({
        ...base,
        sensitivity: "lenient",
        reviewSeverity: "info",
      }),
      "lenient",
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        sensitivity: "lenient",
        reviewSeverity: "warning",
      }),
      undefined,
    );
  });

  it("never applies session skips when unattended (allowlist still can)", () => {
    assert.equal(
      resolveReviewSkip({ ...base, unattended: true, allowAll: true, quietUntilMs: 9_000 }),
      undefined,
    );
    assert.equal(
      resolveReviewSkip({ ...base, unattended: true, allowlistHit: true }),
      "allowlist",
    );
  });

  it("maps skip reasons onto resolution decisions", () => {
    assert.equal(skipResolutionDecision("allow-all"), "allow-all-skip");
    assert.equal(skipResolutionDecision("quiet"), "quiet-skip");
    assert.equal(skipResolutionDecision("lenient"), "lenient-skip");
    assert.equal(skipResolutionDecision("allowlist"), "allowlist-hit");
  });
});
