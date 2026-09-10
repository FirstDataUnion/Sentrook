import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import { PLUGIN_ID } from "./configure.ts";
import { ensureConversationAccess, patchSentrookPluginConfig } from "./pluginConfigPatch.ts";

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "OPENCLAW_HOME"] as const;
type Saved = Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>;
const tempDirs: string[] = [];

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

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("patchSentrookPluginConfig", () => {
  it("merges sensitivity into the plugin entry", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-patch-"));
    tempDirs.push(dir);
    writeFileSync(
      join(dir, "openclaw.json"),
      JSON.stringify({
        plugins: {
          entries: {
            [PLUGIN_ID]: { enabled: true, config: { timeoutMs: 14000 } },
          },
        },
      }),
      "utf8",
    );
    const saved = saveEnv();
    try {
      process.env.OPENCLAW_STATE_DIR = dir;
      const result = patchSentrookPluginConfig({ sensitivity: "warning" });
      assert.equal(result.ok, true);
      const cfg = JSON.parse(readFileSync(join(dir, "openclaw.json"), "utf8")) as {
        plugins: { entries: Record<string, { config: Record<string, unknown> }> };
      };
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.sensitivity, "warning");
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.timeoutMs, 14000);
    } finally {
      restoreEnv(saved);
    }
  });

  it("reports when openclaw.json is missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-patch-missing-"));
    tempDirs.push(dir);
    const saved = saveEnv();
    try {
      process.env.OPENCLAW_STATE_DIR = dir;
      const result = patchSentrookPluginConfig({ sensitivity: "warning" });
      assert.equal(result.ok, false);
      if (result.ok) return;
      assert.match(result.error, /openclaw\.json was not found/);
      assert.match(result.error, /until gateway restart/);
    } finally {
      restoreEnv(saved);
    }
  });

  it("reports when openclaw.json is not strict JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-patch-json5-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, "openclaw.json"), "{ plugins: {} }\n", "utf8");
    const saved = saveEnv();
    try {
      process.env.OPENCLAW_STATE_DIR = dir;
      const result = patchSentrookPluginConfig({ sensitivity: "warning" });
      assert.equal(result.ok, false);
      if (result.ok) return;
      assert.match(result.error, /not strict JSON/);
    } finally {
      restoreEnv(saved);
    }
  });
});

describe("ensureConversationAccess", () => {
  it("writes hooks.allowConversationAccess when the plugin entry exists", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-access-"));
    tempDirs.push(dir);
    writeFileSync(
      join(dir, "openclaw.json"),
      JSON.stringify({
        plugins: {
          entries: {
            [PLUGIN_ID]: { enabled: true, config: { timeoutMs: 14000 } },
          },
        },
      }),
      "utf8",
    );
    const saved = saveEnv();
    try {
      process.env.OPENCLAW_STATE_DIR = dir;
      const first = ensureConversationAccess();
      assert.equal(first.ok, true);
      if (!first.ok) return;
      assert.equal(first.wrote, true);
      const cfg = JSON.parse(readFileSync(join(dir, "openclaw.json"), "utf8")) as {
        plugins: {
          entries: Record<string, { hooks?: { allowConversationAccess?: boolean }; config?: { timeoutMs?: number } }>;
        };
      };
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.hooks?.allowConversationAccess, true);
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config?.timeoutMs, 14000);
      const second = ensureConversationAccess();
      assert.equal(second.ok, true);
      if (!second.ok) return;
      assert.equal(second.wrote, false);
    } finally {
      restoreEnv(saved);
    }
  });

  it("does not throw when the plugin entry is missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-access-missing-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, "openclaw.json"), JSON.stringify({ plugins: { entries: {} } }), "utf8");
    const saved = saveEnv();
    try {
      process.env.OPENCLAW_STATE_DIR = dir;
      const result = ensureConversationAccess();
      assert.equal(result.ok, false);
    } finally {
      restoreEnv(saved);
    }
  });
});
