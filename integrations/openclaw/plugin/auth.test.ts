import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";

import {
  buildScanAuthHeaders,
  buildScanAuthHeadersAsync,
  clearScanTokenCache,
  envWithOpenclawDotenv,
  getScanAccessToken,
  resolveApiKey,
  resolveScanAuthConfig,
  urlRequiresScanApiKey,
} from "./auth.ts";

afterEach(() => {
  clearScanTokenCache();
});

describe("resolveApiKey", () => {
  it("returns a trimmed plaintext config value", () => {
    assert.equal(resolveApiKey("  secret-key  ", {}), "secret-key");
  });

  it("resolves env-backed SecretRef objects via process env", () => {
    const ref = { source: "env", provider: "default", id: "SENTROOK_SCAN_API_KEY" };
    assert.equal(
      resolveApiKey(ref, { SENTROOK_SCAN_API_KEY: "from-env" }),
      "from-env",
    );
  });

  it("falls back to SENTROOK_SCAN_API_KEY when config is empty", () => {
    assert.equal(resolveApiKey(undefined, { SENTROOK_SCAN_API_KEY: "fallback" }), "fallback");
  });
});

describe("urlRequiresScanApiKey", () => {
  it("requires auth for https URLs only", () => {
    assert.equal(urlRequiresScanApiKey("https://sentrook.example/scan"), true);
    assert.equal(urlRequiresScanApiKey("http://sentrook-scan:9099"), false);
  });
});

describe("buildScanAuthHeaders", () => {
  it("adds bearer auth when a key is present", () => {
    const headers = buildScanAuthHeaders("abc123");
    assert.equal(headers.authorization, "Bearer abc123");
    assert.equal(headers["content-type"], "application/json");
  });

  it("omits authorization for local unauthenticated scans", () => {
    const headers = buildScanAuthHeaders(null);
    assert.equal(headers.authorization, undefined);
  });
});

describe("resolveScanAuthConfig", () => {
  it("prefers OIDC when client id and secret are present", () => {
    const auth = resolveScanAuthConfig(
      {},
      {
        SENTROOK_SCAN_CLIENT_ID: "client-1",
        SENTROOK_SCAN_CLIENT_SECRET: "secret-1",
        SENTROOK_SCAN_API_KEY: "test-key",
      },
    );
    assert.equal(auth.apiKey, "test-key");
    assert.ok(auth.oidc);
    assert.equal(auth.oidc?.clientId, "client-1");
    assert.equal(auth.oidc?.scope, "sentrook.scan");
    assert.equal(auth.oidc?.audience, "sentrook");
  });

  it("loads OIDC + issuer from OpenClaw dotenv when process env is empty", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-auth-dotenv-"));
    try {
      writeFileSync(
        path.join(dir, ".env"),
        [
          "SENTROOK_SCAN_CLIENT_ID=file-client",
          "SENTROOK_SCAN_CLIENT_SECRET=file-secret",
          "SENTROOK_OIDC_ISSUER=https://dev.identity.example/",
        ].join("\n") + "\n",
      );
      const auth = resolveScanAuthConfig(
        {},
        envWithOpenclawDotenv({}, { stateDir: dir }),
      );
      assert.ok(auth.oidc);
      assert.equal(auth.oidc?.clientId, "file-client");
      assert.equal(auth.oidc?.clientSecret, "file-secret");
      assert.equal(auth.oidc?.issuer, "https://dev.identity.example");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("still prefers non-empty process env over dotenv file values", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-auth-dotenv-"));
    try {
      writeFileSync(
        path.join(dir, ".env"),
        "SENTROOK_SCAN_CLIENT_ID=file-client\nSENTROOK_SCAN_CLIENT_SECRET=file-secret\n",
      );
      const auth = resolveScanAuthConfig(
        {},
        envWithOpenclawDotenv(
          {
            SENTROOK_SCAN_CLIENT_ID: "env-client",
            SENTROOK_SCAN_CLIENT_SECRET: "env-secret",
          },
          { stateDir: dir },
        ),
      );
      assert.equal(auth.oidc?.clientId, "env-client");
      assert.equal(auth.oidc?.clientSecret, "env-secret");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("envWithOpenclawDotenv", () => {
  it("fills missing keys from a dotenv file without overriding env", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-dotenv-"));
    try {
      writeFileSync(
        path.join(dir, ".env"),
        "SENTROOK_SCAN_CLIENT_ID=from-file\nSENTROOK_SCAN_CLIENT_SECRET=sec-file\nKEEP=file\n",
      );
      const merged = envWithOpenclawDotenv(
        { SENTROOK_SCAN_CLIENT_ID: "from-env", KEEP: "" },
        { stateDir: dir },
      );
      assert.equal(merged.SENTROOK_SCAN_CLIENT_ID, "from-env");
      assert.equal(merged.SENTROOK_SCAN_CLIENT_SECRET, "sec-file");
      assert.equal(merged.KEEP, "file");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("getScanAccessToken", () => {
  it("mints and caches a client_credentials access token", async () => {
    let tokenPosts = 0;
    const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("openid-configuration")) {
        return new Response(
          JSON.stringify({ token_endpoint: "https://identity.test/oauth/token" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes("/oauth/token")) {
        tokenPosts += 1;
        assert.equal(init?.method, "POST");
        const body = String(init?.body ?? "");
        assert.match(body, /grant_type=client_credentials/);
        assert.match(body, /client_id=client-1/);
        // Minimal JWT with exp far in the future
        const exp = Math.floor(Date.now() / 1000) + 3600;
        const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url");
        const access = `aaa.${payload}.bbb`;
        return new Response(JSON.stringify({ access_token: access, expires_in: 3600 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;

    const oidc = {
      clientId: "client-1",
      clientSecret: "secret-1",
      issuer: "https://identity.test",
      audience: "sentrook",
      scope: "sentrook.scan",
    };
    const first = await getScanAccessToken(oidc, fetchImpl);
    const second = await getScanAccessToken(oidc, fetchImpl);
    assert.equal(first, second);
    assert.equal(tokenPosts, 1);

    const headers = await buildScanAuthHeadersAsync(
      { apiKey: null, oidc },
      {},
      fetchImpl,
    );
    assert.equal(headers.authorization, `Bearer ${first}`);
    assert.equal(tokenPosts, 1);
  });
});
