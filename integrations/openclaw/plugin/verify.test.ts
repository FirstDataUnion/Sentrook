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

function mintJwt(expiresInSec = 3600): string {
  const exp = Math.floor(Date.now() / 1000) + expiresInSec;
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url");
  return `aaa.${payload}.bbb`;
}

/** Route-aware fetch mock: /health, OIDC discovery, token mint. */
function mockVerifyNetwork(opts: {
  health?: { body: Record<string, unknown>; status?: number };
  tokenStatus?: number;
  tokenBody?: string;
}): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/health")) {
      const health = opts.health ?? { body: { status: "ok" }, status: 200 };
      return new Response(JSON.stringify(health.body), {
        status: health.status ?? 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url.includes("openid-configuration")) {
      return new Response(
        JSON.stringify({ token_endpoint: "https://identity.test/oauth/token" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.includes("/oauth/token")) {
      const status = opts.tokenStatus ?? 200;
      const body =
        opts.tokenBody ??
        JSON.stringify({ access_token: mintJwt(), expires_in: 3600 });
      return new Response(body, {
        status,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
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
      mockVerifyNetwork({
        health: { body: { status: "error" }, status: 503 },
        tokenStatus: 200,
      });
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
      assert.equal(byName["OIDC token mint"]?.ok, true);
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
      mockVerifyNetwork({
        health: { body: { status: "error" }, status: 503 },
      });
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

  it("accepts SENTROOK_SCAN_API_KEY from dotenv alone for HTTPS", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    const prevKey = process.env.SENTROOK_SCAN_API_KEY;
    try {
      delete process.env.SENTROOK_SCAN_API_KEY;
      writePluginConfig(dir);
      writeFileSync(path.join(dir, ".env"), "SENTROOK_SCAN_API_KEY=shared-key\n", {
        mode: 0o600,
      });
      mockVerifyNetwork({
        health: { body: { status: "error" }, status: 503 },
      });
      const result = await runVerify({
        stateDir: dir,
        url: "https://example.invalid",
        timeoutMs: 500,
      });
      const creds = result.checks.find((c) => c.name === "scan credentials");
      assert.equal(creds?.ok, true);
      assert.match(creds?.detail || "", /shared API key/i);
      assert.ok(!result.checks.some((c) => c.name === "OIDC token mint"));
    } finally {
      if (prevKey === undefined) delete process.env.SENTROOK_SCAN_API_KEY;
      else process.env.SENTROOK_SCAN_API_KEY = prevKey;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fails when Identity rejects client_credentials (HTTP 401)", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    try {
      writePluginConfig(dir);
      writeOidcDotenv(dir);
      mockVerifyNetwork({
        health: {
          body: {
            status: "ok",
            oidc_issuer: "https://identity.firstdataunion.org",
          },
        },
        tokenStatus: 401,
        tokenBody: '{"error":"invalid_client"}',
      });
      const result = await runVerify({
        stateDir: dir,
        url: "https://scan.test",
        timeoutMs: 2000,
      });
      const mint = result.checks.find((c) => c.name === "OIDC token mint");
      assert.equal(mint?.ok, false);
      assert.match(mint?.detail || "", /HTTP 401/);
      assert.match(mint?.detail || "", /invalid_client|client_id\/secret/i);
      assert.equal(result.ok, false);
    } finally {
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
      mockVerifyNetwork({
        health: {
          body: {
            status: "ok",
            rules_loaded: 22,
            oidc_issuer: "https://dev.identity.example",
            oidc_audience: "sentrook",
          },
        },
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
      assert.equal(byName["OIDC token mint"]?.ok, true);
      assert.equal(result.ok, true);
      assert.match(formatVerifyReport(result), /OK —/);
      assert.match(formatVerifyReport(result), /gateway logs/);
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
      mockVerifyNetwork({
        health: {
          body: {
            status: "ok",
            oidc_issuer: "https://identity.firstdataunion.org",
          },
        },
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

  it("passes informatively when /health omits oidc_issuer (older deploy)", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-verify-"));
    try {
      writePluginConfig(dir);
      writeOidcDotenv(dir);
      mockVerifyNetwork({
        health: { body: { status: "ok", rules_loaded: 10 } },
      });
      const result = await runVerify({
        stateDir: dir,
        url: "https://scan.test",
        timeoutMs: 2000,
      });
      const align = result.checks.find((c) => c.name === "OIDC issuer alignment");
      assert.equal(align?.ok, true);
      assert.match(align?.detail || "", /no oidc_issuer yet/);
      assert.equal(result.checks.find((c) => c.name === "OIDC token mint")?.ok, true);
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
      mockVerifyNetwork({
        health: { body: { status: "degraded" }, status: 503 },
      });
      const result = await runVerify({
        stateDir: dir,
        url: "https://scan.test",
        timeoutMs: 2000,
      });
      const health = result.checks.find((c) => c.name === "scan service health");
      assert.equal(health?.ok, false);
      assert.match(health?.detail || "", /HTTP 503/);
      assert.ok(!result.checks.some((c) => c.name === "OIDC issuer alignment"));
      // Mint still runs when OIDC vars are present (Identity ≠ scan health).
      assert.equal(result.checks.find((c) => c.name === "OIDC token mint")?.ok, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
