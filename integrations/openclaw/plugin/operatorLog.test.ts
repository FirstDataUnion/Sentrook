import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, renameSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  DEFAULT_OPERATOR_LOG_NAME,
  DEFAULT_TIMELINE_SCAN_LIMIT,
  OPERATOR_LOG_SCHEMA,
  appendOperatorLog,
  operatorLogStats,
  purgeOperatorLog,
  queryOperatorLog,
  resolveOperatorLogConfig,
  scrubOperatorArgs,
  tailOperatorLog,
  wipeOperatorLog,
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
      assert.equal(statSync(cfg.path).mode & 0o777, 0o600);
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
          metadata: {
            adapter: "openclaw",
            hook: "before_tool_call",
            session_id: "uuid-other",
            session_key: "other",
            tool_call_id: "t0",
            step_seq: 0,
          },
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
      const viaKey = queryOperatorLog(cfg, { sessionKey: "main" });
      assert.equal(viaKey.length, 1);
      assert.equal(viaKey[0]?.id, "sr_new");
      const windowed = queryOperatorLog(cfg, {
        since: new Date("2026-09-01T12:00:00.000Z"),
        until: new Date("2026-09-03T00:00:00.000Z"),
      });
      assert.equal(windowed.length, 1);
      assert.equal(windowed[0]?.id, "sr_new");
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

  it("wipeOperatorLog deletes the live file and rotation", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-wipe-"));
    const cfg: OperatorLogConfig = {
      enabled: true,
      path: path.join(dir, "sentrook-operator.jsonl"),
      maxAgeDays: 14,
      maxBytes: 32 * 1024 * 1024,
    };
    try {
      appendOperatorLog(cfg, baseEvent({ id: "sr_wipe" }));
      const dropped = wipeOperatorLog(cfg);
      assert.equal(dropped, 1);
      assert.equal(queryOperatorLog(cfg).length, 0);
      assert.equal(operatorLogStats(cfg).lines, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("tailOperatorLog", () => {
  function tmpLog(): { dir: string; cfg: OperatorLogConfig } {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-oplog-"));
    return {
      dir,
      cfg: {
        enabled: true,
        path: path.join(dir, "sentrook-operator.jsonl"),
        maxAgeDays: 14,
        maxBytes: 32 * 1024 * 1024,
      },
    };
  }

  function scanEvent(id: string, extra: Record<string, unknown> = {}) {
    return baseEvent({
      id,
      run_id: `uuid-1:${id}`,
      metadata: {
        adapter: "openclaw",
        hook: "before_tool_call",
        session_id: "uuid-1",
        session_key: "main",
        tool_call_id: id,
        step_seq: 1,
      },
      ...extra,
    });
  }

  it("returns newest scans first and caps at scanLimit", () => {
    const { dir, cfg } = tmpLog();
    try {
      for (let i = 0; i < 5; i++) {
        appendOperatorLog(cfg, scanEvent(`sr_${i}`));
      }
      const events = tailOperatorLog(cfg, { scanLimit: 3, chunkBytes: 32 });
      const scans = events.filter((e) => e.event === "scan");
      assert.deepEqual(
        scans.map((e) => e.id),
        ["sr_4", "sr_3", "sr_2"],
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("includes a result written after the scan when walking backward", () => {
    const { dir, cfg } = tmpLog();
    try {
      appendOperatorLog(cfg, scanEvent("sr_s"));
      appendOperatorLog(cfg, {
        event: "result",
        id: "sr_r",
        run_id: "uuid-1:sr_s",
        metadata: {
          adapter: "openclaw",
          hook: "after_tool_call",
          session_id: "uuid-1",
          session_key: "main",
          tool_call_id: "sr_s",
        },
        result: { excerpt: "ok", ok: true, byte_size: 2 },
      });
      const events = tailOperatorLog(cfg, { scanLimit: 1, chunkBytes: 32 });
      assert.deepEqual(
        events.map((e) => e.event),
        ["result", "scan"],
      );
      assert.equal(events[0]!.id, "sr_r");
      assert.equal(events[1]!.id, "sr_s");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("walks the live file then .1", () => {
    const { dir, cfg } = tmpLog();
    try {
      for (const id of ["sr_1", "sr_2", "sr_3"]) {
        appendOperatorLog(cfg, scanEvent(id));
      }
      renameSync(cfg.path, `${cfg.path}.1`);
      for (const id of ["sr_4", "sr_5"]) {
        appendOperatorLog(cfg, scanEvent(id));
      }
      const scans = tailOperatorLog(cfg, { scanLimit: 4, chunkBytes: 32 }).filter(
        (e) => e.event === "scan",
      );
      assert.deepEqual(
        scans.map((e) => e.id),
        ["sr_5", "sr_4", "sr_3", "sr_2"],
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("stops after 100 scans when more exist", () => {
    const { dir, cfg } = tmpLog();
    try {
      for (let i = 0; i < 120; i++) {
        appendOperatorLog(cfg, scanEvent(`sr_${String(i).padStart(3, "0")}`));
      }
      const scans = tailOperatorLog(cfg, { chunkBytes: 32 }).filter(
        (e) => e.event === "scan" || e.event === "scan_error",
      );
      assert.equal(scans.length, DEFAULT_TIMELINE_SCAN_LIMIT);
      assert.equal(scans[0]!.id, "sr_119");
      assert.equal(scans[99]!.id, "sr_020");
      assert.ok(!scans.some((e) => e.id === "sr_019"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("stats use first/last line and newline counts, not a full JSON parse", () => {
    const { dir, cfg } = tmpLog();
    try {
      appendOperatorLog(cfg, scanEvent("sr_old", { ts: "2026-09-01T00:00:00.000Z" }));
      appendOperatorLog(cfg, scanEvent("sr_new", { ts: "2026-09-07T12:00:00.000Z" }));
      const stats = operatorLogStats(cfg);
      assert.equal(stats.lines, 2);
      assert.ok(stats.bytes > 0);
      assert.equal(stats.oldestTs, "2026-09-01T00:00:00.000Z");
      assert.equal(stats.newestTs, "2026-09-07T12:00:00.000Z");
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
