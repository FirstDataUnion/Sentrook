import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  combinedAllowAll,
  formatDuration,
  laterQuietUntil,
  parseOnOff,
  parseQuietDuration,
  parseSensitivity,
  parseSensitivityToken,
  parseSessionSensitivityToken,
  QUIET_CAP_MS,
  resolveReviewSkip,
  reviewSeverityOf,
  sensitivityCoversReview,
  sensitivityFloorHighlight,
  sessionFloorLabel,
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
    assert.equal(parseSensitivity("lenient"), "info");
    assert.equal(parseSensitivityToken("lenient"), "info");
    assert.equal(parseSensitivityToken("info"), "info");
    assert.equal(parseSensitivityToken("warning"), "warning");
    assert.equal(parseSensitivityToken("warn"), "warning");
    assert.equal(parseSensitivityToken("critical"), "critical");
    assert.equal(parseSensitivityToken("nope"), undefined);
    assert.equal(parseSensitivity("nope"), "strict");
  });

  it("parses session floor tokens including default", () => {
    assert.equal(parseSessionSensitivityToken("default"), null);
    assert.equal(parseSessionSensitivityToken("off"), null);
    assert.equal(parseSessionSensitivityToken("inherit"), null);
    assert.equal(parseSessionSensitivityToken("warning"), "warning");
    assert.equal(parseSessionSensitivityToken("lenient"), "info");
    assert.equal(parseSessionSensitivityToken("nope"), undefined);
    assert.equal(sessionFloorLabel(null), "default");
    assert.equal(sessionFloorLabel("warning"), "warning");
  });

  it("treats missing review_severity as warning", () => {
    assert.equal(reviewSeverityOf(undefined), "warning");
    assert.equal(reviewSeverityOf("INFO"), "info");
    assert.equal(sensitivityCoversReview("info", undefined), false);
    assert.equal(sensitivityCoversReview("warning", undefined), true);
    assert.equal(sensitivityCoversReview("critical", "critical"), true);
    assert.equal(sensitivityCoversReview("strict", "info"), false);
  });

  it("highlights the selected floor and every lower auto-accept level", () => {
    assert.equal(sensitivityFloorHighlight("strict", "strict"), "on");
    assert.equal(sensitivityFloorHighlight("strict", "info"), "off");
    assert.equal(sensitivityFloorHighlight("info", "strict"), "off");
    assert.equal(sensitivityFloorHighlight("info", "info"), "on");
    assert.equal(sensitivityFloorHighlight("warning", "info"), "covered");
    assert.equal(sensitivityFloorHighlight("warning", "warning"), "on");
    assert.equal(sensitivityFloorHighlight("warning", "critical"), "off");
    assert.equal(sensitivityFloorHighlight("critical", "info"), "covered");
    assert.equal(sensitivityFloorHighlight("critical", "warning"), "covered");
    assert.equal(sensitivityFloorHighlight("critical", "critical"), "on");
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
    unattendedSensitivity: "strict" as const,
    reviewSeverity: "warning",
    allowlistHit: false,
    nowMs: 1_000,
  };

  it("does not skip allow or block", () => {
    assert.equal(resolveReviewSkip({ ...base, hostedDecision: "allow" }), undefined);
    assert.equal(resolveReviewSkip({ ...base, hostedDecision: "block" }), undefined);
  });

  it("prefers allowlist, then allow-all, then quiet, then the severity floor", () => {
    assert.equal(resolveReviewSkip({ ...base, allowlistHit: true, allowAll: true }), "allowlist");
    assert.equal(resolveReviewSkip({ ...base, allowAll: true }), "allow-all");
    assert.equal(resolveReviewSkip({ ...base, quietUntilMs: 2_000 }), "quiet");
    assert.equal(resolveReviewSkip({ ...base, quietUntilMs: 500 }), undefined);
    assert.equal(
      resolveReviewSkip({
        ...base,
        sensitivity: "info",
        reviewSeverity: "info",
      }),
      "lenient",
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        sensitivity: "info",
        reviewSeverity: "warning",
      }),
      undefined,
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        sensitivity: "warning",
        reviewSeverity: "warning",
      }),
      "lenient",
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        sensitivity: "warning",
        reviewSeverity: "critical",
      }),
      undefined,
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        sensitivity: "critical",
        reviewSeverity: "critical",
      }),
      "lenient",
    );
  });

  it("allow-all skips critical reviews (no authority carve-out)", () => {
    assert.equal(
      resolveReviewSkip({
        ...base,
        allowAll: true,
        reviewSeverity: "critical",
      }),
      "allow-all",
    );
  });

  it("never applies allow-all or quiet when unattended (allowlist still can)", () => {
    assert.equal(
      resolveReviewSkip({ ...base, unattended: true, allowAll: true, quietUntilMs: 9_000 }),
      undefined,
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        unattended: true,
        sensitivity: "critical",
        reviewSeverity: "critical",
      }),
      undefined,
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        unattended: true,
        unattendedSensitivity: "warning",
        reviewSeverity: "warning",
      }),
      "lenient",
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        unattended: true,
        unattendedSensitivity: "info",
        reviewSeverity: "warning",
      }),
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
    assert.equal(skipResolutionDecision("session"), "session-skip");
  });

  it("session unattended floor covers warning and ignores allow-all", () => {
    assert.equal(
      resolveReviewSkip({
        ...base,
        unattended: true,
        allowAll: true,
        sessionUnattended: "warning",
        unattendedSensitivity: "strict",
        reviewSeverity: "warning",
      }),
      "session",
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        unattended: true,
        sessionUnattended: "info",
        unattendedSensitivity: "critical",
        reviewSeverity: "warning",
      }),
      undefined,
    );
  });

  it("session attended floor ignores allow-all, quiet, and the global attended floor", () => {
    assert.equal(
      resolveReviewSkip({
        ...base,
        allowAll: true,
        quietUntilMs: 9_000,
        sensitivity: "critical",
        sessionAttended: "info",
        reviewSeverity: "warning",
      }),
      undefined,
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        allowAll: true,
        sensitivity: "strict",
        sessionAttended: "warning",
        reviewSeverity: "warning",
      }),
      "session",
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        allowAll: true,
        sessionAttended: "strict",
        reviewSeverity: "info",
      }),
      undefined,
    );
  });

  it("Default session attended still uses allow-all then quiet then global", () => {
    assert.equal(
      resolveReviewSkip({
        ...base,
        allowAll: true,
        sessionAttended: null,
        reviewSeverity: "critical",
      }),
      "allow-all",
    );
    assert.equal(
      resolveReviewSkip({
        ...base,
        quietUntilMs: 2_000,
        sessionAttended: null,
      }),
      "quiet",
    );
  });

  it("unattended never uses the session attended floor", () => {
    assert.equal(
      resolveReviewSkip({
        ...base,
        unattended: true,
        sessionAttended: "critical",
        unattendedSensitivity: "strict",
        reviewSeverity: "info",
      }),
      undefined,
    );
  });
});

describe("combinedAllowAll / laterQuietUntil", () => {
  it("ORs allow-all flags and takes the later quiet deadline", () => {
    assert.equal(combinedAllowAll(true, false), true);
    assert.equal(combinedAllowAll(false, true), true);
    assert.equal(combinedAllowAll(false, false), false);
    assert.equal(laterQuietUntil(null, 10), 10);
    assert.equal(laterQuietUntil(20, null), 20);
    assert.equal(laterQuietUntil(20, 40), 40);
    assert.equal(laterQuietUntil(null, null), null);
  });
});
