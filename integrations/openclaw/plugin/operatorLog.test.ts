import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  DEFAULT_OPERATOR_LOG_NAME,
  OPERATOR_LOG_SCHEMA,
  appendOperatorLog,
  operatorLogStats,
  purgeOperatorLog,
  queryOperatorLog,
  resolveOperatorLogConfig,
  scrubOperatorArgs,
  type OperatorLogConfig,
} from "./operatorLog.ts";

const ENV_KEYS = [
  "SENTROOK_OPERATOR_LOG",
  "SENTROOK_OPERATOR_LOG_PATH",
  "SENTROOK_OPERATOR_LOG_MAX_DAYS",
  "SENTROOK_OPERATOR_LOG_MAX_BYTES",
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

function baseEvent(overrides: Record<string, unknown> = {}) {
  return {
    event: "scan" as const,
    run_id: "uuid-1:r1",
    metadata: {
      adapter: "openclaw",
      hook: "before_tool_call",
      session_id: "uuid-1",
      session_key: "main",
      tool_call_id: "t1",
      step_seq: 1,
    },
    pending: {
      id: "s1",
      tool: "exec",
      status: "pending",
      args: { command: "ls" },
    },
    scan: { decision: "allow" },
    hook: { action: "continue" },
    ...overrides,
  };
}

describe("resolveOperatorLogConfig", () => {
  it("is on by default under the OpenClaw state dir", () => {
    const saved = saveEnv();
    try {
      for (const key of ENV_KEYS) delete process.env[key];
      process.env.OPENCLAW_STATE_DIR = "/tmp/oc-state";
      const cfg = resolveOperatorLogConfig(process.env);
      assert.equal(cfg.enabled, true);
      assert.equal(cfg.path, path.resolve("/tmp/oc-state", DEFAULT_OPERATOR_LOG_NAME));
      assert.equal(cfg.maxAgeDays, 14);
    } finally {
      restoreEnv(saved);
    }
  });

  it("can be disabled with SENTROOK_OPERATOR_LOG=0", () => {
    const saved = saveEnv();
    try {
      process.env.SENTROOK_OPERATOR_LOG = "0";
      assert.equal(resolveOperatorLogConfig(process.env).enabled, false);
    } finally {
      restoreEnv(saved);
    }
  });
});

describe("appendOperatorLog", () => {
  it("writes JSONL with schema_version and chmod-safe create", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-"));
    const cfg: OperatorLogConfig = {
      enabled: true,
      path: path.join(dir, "sentrook-operator.jsonl"),
      maxAgeDays: 14,
      maxBytes: 32 * 1024 * 1024,
    };
    try {
      appendOperatorLog(cfg, baseEvent({ id: "sr_test1" }));
      const line = readFileSync(cfg.path, "utf8").trim();
      const parsed = JSON.parse(line) as { schema_version?: string; id?: string };
      assert.equal(parsed.schema_version, OPERATOR_LOG_SCHEMA);
      assert.equal(parsed.id, "sr_test1");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not truncate a command longer than the hosted 500-char pack", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-"));
    const cfg: OperatorLogConfig = {
      enabled: true,
      path: path.join(dir, "sentrook-operator.jsonl"),
      maxAgeDays: 14,
      maxBytes: 32 * 1024 * 1024,
    };
    const command = `${"echo padding; ".repeat(80)}curl https://example/collect`;
    try {
      const args = scrubOperatorArgs({ command });
      appendOperatorLog(
        cfg,
        baseEvent({
          id: "sr_long",
          pending: { id: "s1", tool: "exec", status: "pending", args },
        }),
      );
      const parsed = JSON.parse(readFileSync(cfg.path, "utf8").trim()) as {
        pending?: { args?: { command?: string } };
      };
      const stored = parsed.pending?.args?.command ?? "";
      assert.ok(stored.length > 500);
      assert.ok(stored.includes("https://example/collect"));
      assert.ok(!stored.includes("[TRUNCATED]"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rotates the live file when over maxBytes but still writes an oversized line", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-"));
    const cfg: OperatorLogConfig = {
      enabled: true,
      path: path.join(dir, "sentrook-operator.jsonl"),
      maxAgeDays: 14,
      maxBytes: 200,
    };
    try {
      appendOperatorLog(cfg, baseEvent({ id: "sr_a", pending: { id: "s1", tool: "exec", status: "pending", args: { command: "a".repeat(80) } } }));
      appendOperatorLog(cfg, baseEvent({ id: "sr_b", pending: { id: "s1", tool: "exec", status: "pending", args: { command: "b".repeat(80) } } }));
      const live = readFileSync(cfg.path, "utf8");
      assert.ok(live.includes("sr_b"));
      const bak = readFileSync(`${cfg.path}.1`, "utf8");
      assert.ok(bak.includes("sr_a"));
      const huge = "c".repeat(500);
      appendOperatorLog(cfg, baseEvent({ id: "sr_huge", pending: { id: "s1", tool: "exec", status: "pending", args: { command: huge } } }));
      const afterHuge = readFileSync(cfg.path, "utf8");
      assert.ok(afterHuge.includes(huge));
      assert.ok(!afterHuge.includes("[TRUNCATED]"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("is a no-op when disabled", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-"));
    const cfg: OperatorLogConfig = {
      enabled: false,
      path: path.join(dir, "sentrook-operator.jsonl"),
      maxAgeDays: 14,
      maxBytes: 32 * 1024 * 1024,
    };
    try {
      appendOperatorLog(cfg, baseEvent());
      assert.throws(() => readFileSync(cfg.path));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("queryOperatorLog + purge", () => {
  it("returns newest first and filters session / decision / command", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-"));
    const cfg: OperatorLogConfig = {
      enabled: true,
      path: path.join(dir, "sentrook-operator.jsonl"),
      maxAgeDays: 14,
      maxBytes: 32 * 1024 * 1024,
    };
    try {
      appendOperatorLog(
        cfg,
        baseEvent({
          id: "sr_old",
          ts: "2026-09-01T00:00:00.000Z",
          scan: { decision: "allow" },
        }),
      );
      appendOperatorLog(
        cfg,
        baseEvent({
          id: "sr_new",
          ts: "2026-09-02T00:00:00.000Z",
          metadata: {
            adapter: "openclaw",
            hook: "before_tool_call",
            session_id: "uuid-1",
            session_key: "main",
            tool_call_id: "t2",
            step_seq: 2,
          },
          pending: {
            id: "s2",
            tool: "exec",
            status: "pending",
            args: { command: "curl https://example" },
          },
          scan: { decision: "review" },
        }),
      );
      const newest = queryOperatorLog(cfg, { sessionId: "uuid-1" });
      assert.equal(newest[0]?.id, "sr_new");
      const reviews = queryOperatorLog(cfg, { decision: "review" });
      assert.equal(reviews.length, 1);
      const curls = queryOperatorLog(cfg, { commandSubstring: "curl" });
      assert.equal(curls.length, 1);
      assert.equal(curls[0]?.id, "sr_new");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("drops lines older than maxAgeDays", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-"));
    const cfg: OperatorLogConfig = {
      enabled: true,
      path: path.join(dir, "sentrook-operator.jsonl"),
      maxAgeDays: 1,
      maxBytes: 32 * 1024 * 1024,
    };
    try {
      const old = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
      const recent = new Date().toISOString();
      appendOperatorLog(cfg, baseEvent({ id: "sr_aged", ts: old }));
      appendOperatorLog(cfg, baseEvent({ id: "sr_fresh", ts: recent, metadata: { adapter: "openclaw", hook: "before_tool_call", session_id: "uuid-1", session_key: "main", tool_call_id: "t2", step_seq: 2 } }));
      const dropped = purgeOperatorLog(cfg);
      assert.equal(dropped, 1);
      const left = queryOperatorLog(cfg);
      assert.equal(left.length, 1);
      assert.equal(left[0]?.id, "sr_fresh");
      const stats = operatorLogStats(cfg);
      assert.equal(stats.lines, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("golden fixture parity", () => {
  it("OpenClaw can parse the core golden JSONL", () => {
    const golden = path.join(
      import.meta.dirname,
      "..",
      "..",
      "..",
      "sentrook",
      "sentrook",
      "operator_log",
      "fixtures",
      "golden.jsonl",
    );
    const lines = readFileSync(golden, "utf8")
      .split("\n")
      .filter((line) => line.trim());
    const events = lines.map((line) => JSON.parse(line) as { event?: string; schema_version?: string });
    assert.deepEqual(
      events.map((e) => e.event),
      ["scan", "resolution", "result", "scan_error"],
    );
    assert.ok(events.every((e) => e.schema_version === OPERATOR_LOG_SCHEMA));
  });
});

describe("scrubOperatorArgs", () => {
  it("redacts secrets without clipping a long command", () => {
    const token = "ghp_1234567890abcdefghij";
    const command = `${"echo padding; ".repeat(80)}curl -H 'Authorization: token ${token}' https://x`;
    const cleaned = scrubOperatorArgs({ command, api_key: "secret" });
    assert.equal(cleaned.api_key, "[REDACTED]");
    assert.equal(typeof cleaned.command, "string");
    assert.ok(!String(cleaned.command).includes(token));
    assert.ok(String(cleaned.command).length > 500);
  });
});
