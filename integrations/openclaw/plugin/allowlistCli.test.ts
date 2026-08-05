import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import {
  clearAllowlistFile,
  formatAllowlistList,
  resolveAllowlistCliPath,
  runAllowlistClear,
  runAllowlistList,
  runAllowlistPath,
} from "./allowlistCli.ts";
import { saveAllowlist } from "./localAllowlist.ts";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "sentrook-allow-cli-"));
  tempDirs.push(dir);
  return dir;
}

describe("allowlist CLI helpers", () => {
  it("resolves path under state dir by default", () => {
    const dir = tempDir();
    const path = resolveAllowlistCliPath({ stateDir: dir });
    assert.equal(path, join(dir, "sentrook-allowlist.json"));
  });

  it("honours explicit --path override", () => {
    const dir = tempDir();
    const custom = join(dir, "custom.json");
    assert.equal(runAllowlistPath({ path: custom }), custom);
  });

  it("reads allowlist.path from openclaw.json plugin config", () => {
    const dir = tempDir();
    const custom = join(dir, "from-config.json");
    writeFileSync(
      join(dir, "openclaw.json"),
      JSON.stringify({
        plugins: {
          entries: {
            "sentrook-openclaw": {
              enabled: true,
              config: { allowlist: { path: custom } },
            },
          },
        },
      }),
      "utf8",
    );
    assert.equal(resolveAllowlistCliPath({ stateDir: dir }), custom);
  });

  it("lists empty allowlist message", () => {
    const dir = tempDir();
    const path = join(dir, "sentrook-allowlist.json");
    const out = formatAllowlistList(path);
    assert.match(out, /empty/);
    assert.match(out, /Allowlist:/);
  });

  it("lists skeleton and script_bind entries", () => {
    const dir = tempDir();
    const path = join(dir, "sentrook-allowlist.json");
    saveAllowlist(path, {
      version: 1,
      entries: [
        {
          kind: "skeleton",
          tool: "exec",
          matched_rule_ids: ["AIRA-010"],
          skeleton: "rg -n TODO src/",
          created_at: "2026-07-20T00:00:00.000Z",
          source: "allow-always",
        },
        {
          kind: "script_bind",
          tool: "exec",
          interpreter: "python",
          script_path: "/tmp/helper.py",
          content_sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          args_skeleton: "--date <date>",
          matched_rule_ids: ["AIRA-010"],
          created_at: "2026-07-20T00:00:00.000Z",
          source: "allow-always",
        },
      ],
    });
    const out = runAllowlistList({ path });
    assert.match(out, /2 entries/);
    assert.match(out, /skeleton: rg -n TODO src\//);
    assert.match(out, /script: \/tmp\/helper\.py/);
    assert.match(out, /sha256: abcdef012345…/);
  });

  it("clear requires --yes", () => {
    assert.throws(() => runAllowlistClear({ path: "/tmp/x" }), /--yes/);
  });

  it("clear empties an existing allowlist file", () => {
    const dir = tempDir();
    const path = join(dir, "sentrook-allowlist.json");
    saveAllowlist(path, {
      version: 1,
      entries: [
        {
          kind: "skeleton",
          tool: "exec",
          matched_rule_ids: ["AIRA-010"],
          skeleton: "git status",
          created_at: "2026-07-20T00:00:00.000Z",
          source: "allow-always",
        },
      ],
    });
    const msg = runAllowlistClear({ path, yes: true });
    assert.match(msg, /Cleared 1 entry/);
    assert.equal(clearAllowlistFile(path).cleared, 0);
    assert.match(runAllowlistList({ path }), /empty/);
  });

  it("clear on missing file reports already empty", () => {
    const dir = tempDir();
    const path = join(dir, "missing.json");
    const msg = runAllowlistClear({ path, yes: true });
    assert.match(msg, /already empty/);
  });
});
