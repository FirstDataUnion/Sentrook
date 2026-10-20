import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";

import { clearScanTokenCache, type OidcCredentials } from "./auth.ts";
import { parseScanResponse, postScan } from "./scanClient.ts";

const oidc: OidcCredentials = {
  clientId: "c",
  clientSecret: "s",
  issuer: "http://idp.test",
  audience: "sentrook",
  scope: "sentrook.scan",
};

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

function fakeFetch(scan: (n: number) => Response, opts: { tokenEndpoint?: string } = {}) {
  const calls: string[] = [];
  let scans = 0;
  const impl = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    calls.push(`${init?.method ?? "GET"} ${url}`);
    if (url.endsWith("/.well-known/openid-configuration")) {
      return json(200, { token_endpoint: opts.tokenEndpoint ?? "http://idp.test/oauth/token" });
    }
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url.endsWith("/scan")) {
      assert.equal((init?.headers as Record<string, string>).authorization, "Bearer tok");
      scans += 1;
      return scan(scans);
    }
    throw new Error(`unexpected ${url}`);
  }) as typeof fetch;
  return { impl, calls };
}

const ok = { response_version: "2.0", status: "ok", risk: 12.5, enforced: null, state: "tok2" };

beforeEach(() => clearScanTokenCache());

test("a usable response", async () => {
  const f = fakeFetch(() => json(200, ok));
  const r = await postScan({ scanUrl: "http://scan.test", oidc, body: "{}", timeoutMs: 2000, fetchImpl: f.impl });
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.response.risk, 12.5);
  assert.deepEqual(f.calls, [
    "GET http://idp.test/.well-known/openid-configuration",
    "POST http://idp.test/oauth/token",
    "POST http://scan.test/scan",
  ]);
});

test("degraded still counts; error and missing risk do not", () => {
  assert.equal((parseScanResponse({ ...ok, status: "degraded" }, 200) as any).risk, 12.5);
  assert.equal((parseScanResponse({ ...ok, status: "error", risk: null, error: { code: "invalid_planir" } }, 422) as any).kind, "scan_error");
  assert.equal((parseScanResponse({ ...ok, risk: null }, 200) as any).kind, "scan_error");
  assert.equal((parseScanResponse({ ...ok, response_version: "1.0" }, 200) as any).kind, "http");
  assert.equal((parseScanResponse({ ...ok, enforced: "maybe" }, 200) as any).kind, "http");
});

test("422 carries the error shape", async () => {
  const f = fakeFetch(() => json(422, { response_version: "2.0", status: "error", risk: null, error: { code: "invalid_planir", message: "bad" } }));
  const r = await postScan({ scanUrl: "http://scan.test", oidc, body: "{}", timeoutMs: 2000, fetchImpl: f.impl });
  assert.equal(r.ok, false);
  assert.equal(!r.ok && r.kind, "scan_error");
});

test("one 429 is retried within the deadline", async () => {
  const f = fakeFetch((n) => (n === 1 ? json(429, {}, { "retry-after": "0" }) : json(200, ok)));
  const r = await postScan({ scanUrl: "http://scan.test", oidc, body: "{}", timeoutMs: 2000, fetchImpl: f.impl });
  assert.equal(r.ok, true);
});

test("401 is an auth failure; missing credentials a config failure", async () => {
  const f = fakeFetch(() => json(401, { error: { code: "unauthorized" } }));
  const r = await postScan({ scanUrl: "http://scan.test", oidc, body: "{}", timeoutMs: 2000, fetchImpl: f.impl });
  assert.equal(!r.ok && r.status, 401);
  const c = await postScan({ scanUrl: "http://scan.test", oidc: null, body: "{}", timeoutMs: 2000, fetchImpl: f.impl });
  assert.equal(!c.ok && c.kind, "config");
});

test("a token endpoint off the issuer's origin is refused", async () => {
  const f = fakeFetch(() => json(200, ok), { tokenEndpoint: "http://elsewhere.test/oauth/token" });
  const r = await postScan({ scanUrl: "http://scan.test", oidc, body: "{}", timeoutMs: 2000, fetchImpl: f.impl });
  assert.equal(r.ok, false);
  assert.ok(!f.calls.some((c) => c.includes("elsewhere.test")));
});
