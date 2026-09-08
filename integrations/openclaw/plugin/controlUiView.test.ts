import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { renderNativePage } from "./controlUiView.ts";
import type { SentrookState } from "./featureContract.ts";

const state: SentrookState = {
  pending: [
    {
      eventId: "e1",
      toolCallId: "call-1",
      approvalId: "plugin:1",
      tool: "exec",
      command: "rm -rf /tmp/x",
      args: { command: "rm -rf /tmp/x" },
      scan: { decision: "review", review_severity: "critical", summary: "destructive" },
      timeoutMs: 600_000,
      createdAtMs: Date.now() - 5000,
      intent: "cleanup",
      intentKind: "user",
      priorSteps: [],
      priorOmitted: 0,
    },
  ],
  history: [],
  audit: { scanned: 1, allow: 0, review: 1, block: 0, error: 0 },
  sessions: [],
  sensitivity: "strict",
  unattendedSensitivity: "strict",
  allowAll: false,
  quietUntilMs: null,
  feedbackMode: "submit",
  onScanError: "review",
  log: { enabled: true, path: "/tmp/log", bytes: 10, lines: 1, maxAgeDays: 14, maxBytes: 1000 },
  allowlist: [],
  resolveAvailable: true,
  setupNeeded: false,
};

describe("renderNativePage", () => {
  it("renders pending reviews and write controls when the connection can write", () => {
    const html = renderNativePage(state, {
      tab: "reviews",
      canWrite: true,
      connected: true,
      now: Date.now(),
    });
    assert.match(html, /Pending reviews/);
    assert.match(html, /data-resolve="deny"/);
    assert.match(html, /call-1/);
    assert.doesNotMatch(html, / disabled>/);
  });

  it("disables mutations when the connection cannot write", () => {
    const html = renderNativePage(state, {
      tab: "reviews",
      canWrite: false,
      connected: true,
      now: Date.now(),
    });
    assert.match(html, /read-only/);
    assert.match(html, /data-resolve="allow-once"[^>]*disabled/);
  });

  it("shows first-run setup instead of the empty queue", () => {
    const html = renderNativePage(
      { ...state, pending: [], setupNeeded: true },
      { tab: "reviews", canWrite: true, connected: true, now: Date.now() },
    );
    assert.match(html, /Connect hosted Sentrook/);
    assert.match(html, /data-setup-save/);
  });
});
