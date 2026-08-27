import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  CLIENT_ID_VAR,
  CLIENT_SECRET_VAR,
  DEFAULT_TIMEOUT_MS,
  PLUGIN_ID,
  applyConfigPatch,
  buildConfigPatchDocument,
  buildPluginEntryConfig,
  collectAnswersNonInteractive,
  dotenvPath,
  openclawConfigPath,
  resolveStateDir,
  restartHint,
  sanitizeSecretInput,
  stripStalePluginConfigKeys,
  upsertDotenvVar,
  withSpinner,
  writeScanCredentials,
} from "./configure.ts";

describe("sanitizeSecretInput", () => {
  it("strips terminal focus-in/out CSI sequences (ESC[I / ESC[O)", () => {
    const poisoned = `\u001b[O\u001b[I549015b282bca5f2deadbeef`;
    assert.equal(sanitizeSecretInput(poisoned), "549015b282bca5f2deadbeef");
  });

  it("strips bracketed-paste markers and other C0 controls", () => {
    const poisoned = `\u001b[200~abc-secret\u001b[201~\u0000\u0007`;
    assert.equal(sanitizeSecretInput(poisoned), "abc-secret");
  });

  it("trims surrounding whitespace without altering a clean secret", () => {
    assert.equal(sanitizeSecretInput("  plain-secret  "), "plain-secret");
  });
});

describe("buildPluginEntryConfig", () => {
  it("omits credentials from openclaw.json (env-only auth)", () => {
    const cfg = buildPluginEntryConfig({
      timeoutMs: 3000,
      contributeCorpus: true,
      clientId: "cid",
      clientSecret: "csec",
    });
    assert.equal(cfg.clientId, undefined);
    assert.equal(cfg.clientSecret, undefined);
    assert.equal(cfg.apiKey, undefined);
    assert.equal("url" in cfg, false);
    assert.equal("mode" in cfg, false);
    assert.equal("sanitization" in cfg, false);
    assert.deepEqual(cfg.feedback, { mode: "submit" });
    assert.equal(cfg.onScanError, "review");
  });

  it("sets feedback off when user opts out of corpus contribution", () => {
    const cfg = buildPluginEntryConfig({
      timeoutMs: 3000,
      contributeCorpus: false,
    });
    assert.deepEqual(cfg.feedback, { mode: "off" });
  });

  it("also omits apiKey from config", () => {
    const cfg = buildPluginEntryConfig({
      timeoutMs: 1500,
      contributeCorpus: true,
      apiKey: "k",
    });
    assert.equal(cfg.apiKey, undefined);
    assert.equal("mode" in cfg, false);
    assert.equal("sanitization" in cfg, false);
  });
});

describe("buildConfigPatchDocument", () => {
  it("does not declare SecretRefs or secrets.providers", () => {
    const doc = buildConfigPatchDocument({
      timeoutMs: DEFAULT_TIMEOUT_MS,
      contributeCorpus: true,
      clientId: "cid",
      clientSecret: "sec",
    });
    assert.doesNotMatch(doc, /secrets:\s*\{/);
    assert.doesNotMatch(doc, /clientSecret/);
    assert.doesNotMatch(doc, /\$\{SENTROOK_SCAN_/);
    assert.match(doc, new RegExp(`"${PLUGIN_ID}"`));
  });
});

describe("dotenv helpers", () => {
  it("strips focus CSI junk when writing client_secret", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-cfg-"));
    try {
      writeScanCredentials(dir, {
        timeoutMs: DEFAULT_TIMEOUT_MS,
        contributeCorpus: true,
        clientId: "cid",
        clientSecret: "\u001b[O\u001b[I549015b282bca5f2",
      });
      const text = readFileSync(dotenvPath(dir), "utf8");
      assert.match(text, new RegExp(`^${CLIENT_SECRET_VAR}=549015b282bca5f2$`, "m"));
      assert.doesNotMatch(text, /\u001b/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("upserts credentials without clobbering other keys", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-cfg-"));
    try {
      const dotenv = dotenvPath(dir);
      upsertDotenvVar(dotenv, "OTHER", "keep");
      writeScanCredentials(dir, {
        timeoutMs: 3000,
        contributeCorpus: true,
        clientId: "id1",
        clientSecret: "sec1",
      });
      const text = readFileSync(dotenv, "utf8");
      assert.match(text, /^OTHER=keep$/m);
      assert.match(text, new RegExp(`^${CLIENT_ID_VAR}=id1$`, "m"));
      assert.match(text, new RegExp(`^${CLIENT_SECRET_VAR}=sec1$`, "m"));
      assert.match(text, /^SENTROOK_OIDC_ISSUER=https:\/\/identity\.firstdataunion\.org$/m);
      writeScanCredentials(dir, {
        timeoutMs: 3000,
        contributeCorpus: true,
        clientId: "id2",
        clientSecret: "sec2",
      });
      const text2 = readFileSync(dotenv, "utf8");
      assert.match(text2, new RegExp(`^${CLIENT_ID_VAR}=id2$`, "m"));
      assert.doesNotMatch(text2, /id1/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects empty client secret", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-cfg-"));
    try {
      assert.throws(
        () =>
          writeScanCredentials(dir, {
            timeoutMs: 3000,
            contributeCorpus: true,
            clientId: "id",
            clientSecret: "   ",
          }),
        /required/,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("dual-writes when SENTROOK_DOTENV is set", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-cfg-"));
    const composeEnv = path.join(dir, "compose.env");
    const prev = process.env.SENTROOK_DOTENV;
    try {
      process.env.SENTROOK_DOTENV = composeEnv;
      writeScanCredentials(path.join(dir, "state"), {
        timeoutMs: 3000,
        contributeCorpus: true,
        clientId: "id1",
        clientSecret: "sec1",
      });
      assert.match(readFileSync(composeEnv, "utf8"), new RegExp(`^${CLIENT_SECRET_VAR}=sec1$`, "m"));
    } finally {
      if (prev === undefined) delete process.env.SENTROOK_DOTENV;
      else process.env.SENTROOK_DOTENV = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("resolveStateDir", () => {
  it("prefers OPENCLAW_STATE_DIR over OPENCLAW_HOME", () => {
    assert.equal(
      resolveStateDir({
        OPENCLAW_HOME: "/home/node",
        OPENCLAW_STATE_DIR: "/home/node/.openclaw",
        HOME: "/home/node",
      }),
      "/home/node/.openclaw",
    );
  });

  it("treats OPENCLAW_HOME as home root, not state dir (Docker)", () => {
    // Official compose sets OPENCLAW_HOME=/home/node and STATE_DIR separately.
    // If STATE_DIR is missing, still must not write to /home/node/.env.
    assert.equal(
      resolveStateDir({
        OPENCLAW_HOME: "/home/node",
        HOME: "/home/node",
      }),
      path.join("/home/node", ".openclaw"),
    );
  });

  it("falls back to $HOME/.openclaw", () => {
    assert.equal(resolveStateDir({ HOME: "/Users/oli" }), path.join("/Users/oli", ".openclaw"));
  });
});

describe("restartHint", () => {
  it("prefers restart over force-recreate for state-dir .env", () => {
    const hint = restartHint("/home/node/.openclaw/.env");
    assert.match(hint, /docker compose restart/);
    assert.match(hint, /\/home\/node\/\.openclaw\/\.env/);
    assert.match(hint, /force-recreate/);
    assert.match(hint, /do NOT need/i);
    assert.match(hint, /default Compose service name/);
    assert.match(hint, /docker compose ps/);
  });
});

describe("collectAnswersNonInteractive", () => {
  it("requires OIDC client credentials", () => {
    assert.throws(() => collectAnswersNonInteractive({}), /client-id/);
  });

  it("accepts OIDC seed", () => {
    const a = collectAnswersNonInteractive({
      clientId: "c",
      clientSecret: "s",
    });
    assert.equal("url" in a, false);
    assert.equal(a.clientId, "c");
    assert.equal(a.contributeCorpus, true);
    assert.equal(a.onScanError, "review");
    assert.equal(a.timeoutMs, DEFAULT_TIMEOUT_MS);
  });

  it("honours contributeCorpus opt-out", () => {
    const a = collectAnswersNonInteractive({
      clientId: "c",
      clientSecret: "s",
      contributeCorpus: false,
    });
    assert.equal(a.contributeCorpus, false);
  });

  it("plugin entry config never includes mode or sanitization", () => {
    const cfg = buildPluginEntryConfig({
      timeoutMs: DEFAULT_TIMEOUT_MS,
      contributeCorpus: true,
      clientId: "c",
      clientSecret: "s",
    });
    assert.equal("mode" in cfg, false);
    assert.equal("sanitization" in cfg, false);
  });
});

describe("applyConfigPatch json fallback", () => {
  it("merges plugin entry when openclaw CLI is missing", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-cfg-"));
    try {
      writeFileSync(
        openclawConfigPath(dir),
        JSON.stringify({
          plugins: {
            entries: {
              [PLUGIN_ID]: {
                enabled: true,
                config: {
                  url: "https://old.example",
                  clientSecret: `\${${CLIENT_SECRET_VAR}}`,
                },
              },
            },
          },
        }) + "\n",
      );
      const result = await applyConfigPatch(
        dir,
        {
          timeoutMs: 3000,
          contributeCorpus: true,
          clientId: "cid",
          clientSecret: "sec",
        },
        { openclawBin: "sentrook-openclaw-definitely-missing", allowJsonFallback: true },
      );
      assert.equal(result.method, "json-fallback");
      const cfg = JSON.parse(readFileSync(openclawConfigPath(dir), "utf8")) as {
        plugins: {
          entries: Record<string, { enabled: boolean; config: Record<string, unknown> }>;
        };
      };
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.enabled, true);
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.url, undefined);
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.clientSecret, undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("withSpinner", () => {
  it("runs work and writes a plain progress line when spinner disabled", async () => {
    const chunks: string[] = [];
    const stream = {
      isTTY: false,
      write: (s: string) => {
        chunks.push(s);
        return true;
      },
    } as unknown as NodeJS.WriteStream;
    const value = await withSpinner("doing thing", async () => 42, {
      enabled: false,
      stream,
    });
    assert.equal(value, 42);
    assert.match(chunks.join(""), /doing thing/);
  });
});

describe("stripStalePluginConfigKeys", () => {
  it("removes stale SecretRef credential keys", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-strip-"));
    try {
      writeFileSync(
        openclawConfigPath(dir),
        JSON.stringify({
          plugins: {
            entries: {
              [PLUGIN_ID]: {
                enabled: true,
                config: {
                  url: "https://old.example",
                  mode: "observe",
                  sanitization: { enabled: false },
                  clientId: `\${${CLIENT_ID_VAR}}`,
                  clientSecret: `\${${CLIENT_SECRET_VAR}}`,
                },
              },
            },
          },
        }) + "\n",
      );
      assert.equal(stripStalePluginConfigKeys(dir), true);
      const cfg = JSON.parse(readFileSync(openclawConfigPath(dir), "utf8")) as {
        plugins: { entries: Record<string, { config: Record<string, unknown> }> };
      };
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.url, undefined);
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.clientId, undefined);
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.clientSecret, undefined);
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.mode, undefined);
      assert.equal(cfg.plugins.entries[PLUGIN_ID]?.config.sanitization, undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns false when openclaw.json is missing", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-strip-missing-"));
    try {
      assert.equal(stripStalePluginConfigKeys(dir), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
