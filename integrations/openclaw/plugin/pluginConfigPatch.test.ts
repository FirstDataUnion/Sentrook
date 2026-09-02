import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import { PLUGIN_ID } from "./configure.ts";
import { patchSentrookPluginConfig } from "./pluginConfigPatch.ts";

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
      const result = patchSentrookPluginConfig({ sensitivity: "lenient" });
      assert.equal(result.ok, true);
      const cfg = JSON.parse(readFileSync(join(dir, "openclaw.json"), "utf8")) as {
        plugins: { entries: Record<string, { config: Record<string, unknown> }> };
      };
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.sensitivity, "lenient");
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.timeoutMs, 14000);
    } finally {
      restoreEnv(saved);
    }
  });
});
