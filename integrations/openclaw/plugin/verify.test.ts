import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { CLIENT_ID_VAR, CLIENT_SECRET_VAR, PLUGIN_ID } from "./configure.ts";
import { formatVerifyReport, runVerify } from "./verify.ts";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function writePluginConfig(dir: string, url = "https://example.invalid"): void {
  writeFileSync(
    path.join(dir, "openclaw.json"),
    JSON.stringify({
      plugins: {
        entries: {
          [PLUGIN_ID]: {
            enabled: true,
            config: { url },
          },
        },
      },
    }) + "\n",
  );
}

function writeOidcDotenv(
  dir: string,
  extra: Record<string, string> = {},
): void {
  const lines = [
    `${CLIENT_ID_VAR}=cid`,
    `${CLIENT_SECRET_VAR}=csec`,
    ...Object.entries(extra).map(([k, v]) => `${k}=${v}`),
  ];
  writeFileSync(path.join(dir, ".env"), lines.join("\n") + "\n", { mode: 0o600 });
}

function mockHealth(body: Record<string, unknown>, status = 200): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    assert.match(url, /\/health$/);
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

describe("runVerify", () => {
  it("fails when plugin entry and credentials are missing", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    try {
      writeFileSync(path.join(dir, "openclaw.json"), "{}\n");
      const result = await runVerify({
        stateDir: dir,
        url: "https://example.invalid",
        timeoutMs: 500,
      });
      assert.equal(result.ok, false);
      assert.ok(result.checks.some((c) => c.name === "plugin config" && !c.ok));
      assert.ok(result.checks.some((c) => c.name === "scan credentials" && !c.ok));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("passes credential checks from .env alone (no process.env required)", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    const prevId = process.env[CLIENT_ID_VAR];
    const prevSecret = process.env[CLIENT_SECRET_VAR];
    try {
      delete process.env[CLIENT_ID_VAR];
      delete process.env[CLIENT_SECRET_VAR];
      writePluginConfig(dir);
      writeOidcDotenv(dir);
      const result = await runVerify({
        stateDir: dir,
        url: "https://example.invalid",
        timeoutMs: 500,
      });
      const byName = Object.fromEntries(result.checks.map((c) => [c.name, c]));
      assert.equal(byName["plugin config"]?.ok, true);
      assert.equal(byName["scan credentials"]?.ok, true);
      assert.equal(byName["credentials load path"]?.ok, true);
      assert.match(byName["credentials load path"]?.detail || "", /\.env file/);
      assert.equal(byName["scan service health"]?.ok, false);
      assert.match(formatVerifyReport(result), /FAILED/);
    } finally {
      if (prevId === undefined) delete process.env[CLIENT_ID_VAR];
      else process.env[CLIENT_ID_VAR] = prevId;
      if (prevSecret === undefined) delete process.env[CLIENT_SECRET_VAR];
      else process.env[CLIENT_SECRET_VAR] = prevSecret;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports process.env visibility when SENTROOK_SCAN_* are set in CLI process", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    const prevId = process.env[CLIENT_ID_VAR];
    const prevSecret = process.env[CLIENT_SECRET_VAR];
    try {
      writePluginConfig(dir);
      writeOidcDotenv(dir);
      process.env[CLIENT_ID_VAR] = "cid";
      process.env[CLIENT_SECRET_VAR] = "csec";
      const result = await runVerify({
        stateDir: dir,
        url: "https://example.invalid",
        timeoutMs: 500,
      });
      const loadPath = result.checks.find((c) => c.name === "credentials load path");
      assert.ok(loadPath?.ok);
      assert.match(loadPath?.detail || "", /process\.env/);
    } finally {
      if (prevId === undefined) delete process.env[CLIENT_ID_VAR];
      else process.env[CLIENT_ID_VAR] = prevId;
      if (prevSecret === undefined) delete process.env[CLIENT_SECRET_VAR];
      else process.env[CLIENT_SECRET_VAR] = prevSecret;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("accepts legacy SENTROOK_SCAN_API_KEY from dotenv alone for HTTPS", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    const prevKey = process.env.SENTROOK_SCAN_API_KEY;
    try {
      delete process.env.SENTROOK_SCAN_API_KEY;
      writePluginConfig(dir);
      writeFileSync(path.join(dir, ".env"), "SENTROOK_SCAN_API_KEY=legacy-key\n", {
        mode: 0o600,
      });
      const result = await runVerify({
        stateDir: dir,
        url: "https://example.invalid",
        timeoutMs: 500,
      });
      const creds = result.checks.find((c) => c.name === "scan credentials");
      assert.equal(creds?.ok, true);
      assert.match(creds?.detail || "", /legacy/i);
    } finally {
      if (prevKey === undefined) delete process.env.SENTROOK_SCAN_API_KEY;
      else process.env.SENTROOK_SCAN_API_KEY = prevKey;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("runVerify — OIDC issuer alignment", () => {
  it("passes when plugin issuer matches /health oidc_issuer (trailing slash normalized)", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    const prevIssuer = process.env.SENTROOK_OIDC_ISSUER;
    try {
      delete process.env.SENTROOK_OIDC_ISSUER;
      writePluginConfig(dir);
      writeOidcDotenv(dir, {
        SENTROOK_OIDC_ISSUER: "https://dev.identity.example/",
      });
      mockHealth({
        status: "ok",
        rules_loaded: 22,
        oidc_issuer: "https://dev.identity.example",
        oidc_audience: "sentrook",
      });
      const result = await runVerify({
        stateDir: dir,
        url: "https://scan.test",
        timeoutMs: 2000,
      });
      const byName = Object.fromEntries(result.checks.map((c) => [c.name, c]));
      assert.equal(byName["scan service health"]?.ok, true);
      assert.equal(byName["OIDC issuer alignment"]?.ok, true);
      assert.match(
        byName["OIDC issuer alignment"]?.detail || "",
        /https:\/\/dev\.identity\.example/,
      );
      assert.equal(result.ok, true);
      assert.match(formatVerifyReport(result), /OK —/);
    } finally {
      if (prevIssuer === undefined) delete process.env.SENTROOK_OIDC_ISSUER;
      else process.env.SENTROOK_OIDC_ISSUER = prevIssuer;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails when plugin issuer is dig and scan /health reports prod", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    const prevIssuer = process.env.SENTROOK_OIDC_ISSUER;
    try {
      delete process.env.SENTROOK_OIDC_ISSUER;
      writePluginConfig(dir);
      writeOidcDotenv(dir, {
        SENTROOK_OIDC_ISSUER: "https://dev.identity.firstdataunion.org",
      });
      mockHealth({
        status: "ok",
        oidc_issuer: "https://identity.firstdataunion.org",
      });
      const result = await runVerify({
        stateDir: dir,
        url: "https://scan.test",
        timeoutMs: 2000,
      });
      const align = result.checks.find((c) => c.name === "OIDC issuer alignment");
      assert.equal(align?.ok, false);
      assert.match(align?.detail || "", /mismatch: plugin=/);
      assert.equal(result.ok, false);
    } finally {
      if (prevIssuer === undefined) delete process.env.SENTROOK_OIDC_ISSUER;
      else process.env.SENTROOK_OIDC_ISSUER = prevIssuer;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("passes informatively when /health omits oidc_issuer (legacy deploy)", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    try {
      writePluginConfig(dir);
      writeOidcDotenv(dir);
      mockHealth({ status: "ok", rules_loaded: 10 });
      const result = await runVerify({
        stateDir: dir,
        url: "https://scan.test",
        timeoutMs: 2000,
      });
      const align = result.checks.find((c) => c.name === "OIDC issuer alignment");
      assert.equal(align?.ok, true);
      assert.match(align?.detail || "", /no oidc_issuer yet/);
      assert.equal(result.ok, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails when /health returns non-ok status", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    try {
      writePluginConfig(dir);
      writeOidcDotenv(dir);
      mockHealth({ status: "degraded" }, 503);
      const result = await runVerify({
        stateDir: dir,
        url: "https://scan.test",
        timeoutMs: 2000,
      });
      const health = result.checks.find((c) => c.name === "scan service health");
      assert.equal(health?.ok, false);
      assert.match(health?.detail || "", /HTTP 503/);
      assert.ok(!result.checks.some((c) => c.name === "OIDC issuer alignment"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
