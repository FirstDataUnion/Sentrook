import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import {
  DASHBOARD_ACCESS_FILE,
  accessCookieFromHeader,
  accessFromRequest,
  accessTokensEqual,
  createDashboardAccessToken,
  dashboardCorsAllowOrigin,
  dashboardRestFromPathname,
  dashboardTabPath,
  resolveDashboardAccessToken,
  tabAccessFromPathname,
} from "./dashboardAuth.ts";

describe("dashboard access token", () => {
  it("puts the token on the Control UI tab path", () => {
    const token = createDashboardAccessToken();
    assert.equal(dashboardTabPath(token), `/sentrook/tab/${token}`);
    assert.equal(tabAccessFromPathname(`/sentrook/tab/${token}`), token);
    assert.equal(tabAccessFromPathname(`/tab/${token}`), token);
    assert.equal(tabAccessFromPathname(`/sentrook/tab/${token}/api/policy`), token);
    assert.equal(tabAccessFromPathname("/sentrook/tab/api/policy"), undefined);
    assert.deepEqual(dashboardRestFromPathname(`/sentrook/tab/${token}`), { rest: "", handled: true });
    assert.deepEqual(dashboardRestFromPathname(`/sentrook/tab/${token}/api/policy`), {
      rest: "/api/policy",
      handled: true,
    });
    assert.deepEqual(dashboardRestFromPathname(`/tab/${token}/api/state`), { rest: "/api/state", handled: true });
    assert.equal(dashboardRestFromPathname("/sentrook/tab/api/policy"), undefined);
  });

  it("reads the query or header and compares in constant time", () => {
    const token = "abc_token";
    assert.equal(
      accessFromRequest({ url: "/sentrook?access=abc_token", headers: {} } as never),
      "abc_token",
    );
    assert.equal(
      accessFromRequest({ url: "/sentrook", headers: { "x-sentrook-access": " abc_token " } } as never),
      "abc_token",
    );
    assert.equal(
      accessFromRequest({ url: "/sentrook/tab/wrong_tok?access=abc_token", headers: {} } as never),
      "abc_token",
    );
    assert.equal(
      accessFromRequest({ url: "/sentrook/tab/abc_token/api/policy", headers: {} } as never),
      "abc_token",
    );
    assert.equal(
      accessFromRequest({ url: "/tab/abc_token", headers: {} } as never),
      "abc_token",
    );
    assert.equal(
      accessFromRequest(
        { url: "/sentrook", headers: { cookie: "sentrook_access=cookie_tok" } } as never,
        { allowCookie: true },
      ),
      "cookie_tok",
    );
    assert.equal(
      accessFromRequest({ url: "/sentrook", headers: { cookie: "sentrook_access=cookie_tok" } } as never),
      undefined,
    );
    assert.equal(accessCookieFromHeader("foo=1; sentrook_access=cookie_tok"), "cookie_tok");
    assert.equal(accessTokensEqual(token, token), true);
    assert.equal(accessTokensEqual(token, "nope"), false);
    assert.equal(accessTokensEqual(token, undefined), false);
  });

  it("allows the sandboxed Control UI origin and same-host, not other sites", () => {
    assert.equal(dashboardCorsAllowOrigin("null", "127.0.0.1:18789"), "null");
    assert.equal(
      dashboardCorsAllowOrigin("http://127.0.0.1:18789", "127.0.0.1:18789"),
      "http://127.0.0.1:18789",
    );
    assert.equal(dashboardCorsAllowOrigin("https://evil.example", "127.0.0.1:18789"), undefined);
    assert.equal(dashboardCorsAllowOrigin("http://localhost:18789", "127.0.0.1:18789"), undefined);
    assert.equal(dashboardCorsAllowOrigin(undefined, "127.0.0.1:18789"), undefined);
  });
});

describe("resolveDashboardAccessToken", () => {
  it("reuses the token stored in the state dir", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-access-"));
    try {
      const first = resolveDashboardAccessToken(dir);
      const second = resolveDashboardAccessToken(dir);
      assert.equal(first, second);
      assert.match(first, /^[A-Za-z0-9_-]{32,64}$/);
      assert.equal(readFileSync(path.join(dir, DASHBOARD_ACCESS_FILE), "utf8").trim(), first);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("mints a new token when the file is garbage and does not create a missing dir", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-access-"));
    try {
      writeFileSync(path.join(dir, DASHBOARD_ACCESS_FILE), "nope\n");
      const token = resolveDashboardAccessToken(dir);
      assert.match(token, /^[A-Za-z0-9_-]{32,64}$/);
      assert.notEqual(token, "nope");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    assert.match(resolveDashboardAccessToken(path.join(tmpdir(), "sentrook-missing-access")), /^[A-Za-z0-9_-]{32,64}$/);
  });
});
