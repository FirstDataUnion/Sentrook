import assert from "node:assert/strict";
import { test } from "node:test";

import { DEFAULT_SCAN_URL, parseEndpoint, resolveConfig } from "./config.ts";

test("endpoints default to the hosted service", () => {
  const cfg = resolveConfig({}, { HOME: "/home/u" });
  assert.deepEqual(cfg.endpoints.scan, { ok: true, url: DEFAULT_SCAN_URL });
  assert.equal(cfg.endpoints.dev, false);
  assert.equal(cfg.stateDir, "/home/u/.openclaw/sentrook");
  assert.equal(cfg.trafficLog.path, "/home/u/.openclaw/sentrook/traffic.jsonl");
});

test("a firstdataunion.org dev instance is accepted without the dev switch", () => {
  const cfg = resolveConfig(
    {},
    {
      SENTROOK_SCAN_URL: "https://dev.sentrook.firstdataunion.org/",
      SENTROOK_OIDC_ISSUER: "https://dev.identity.firstdataunion.org",
      SENTROOK_ROOKERY_URL: "https://dev.rookery.firstdataunion.org",
    },
  );
  assert.deepEqual(cfg.endpoints.scan, { ok: true, url: "https://dev.sentrook.firstdataunion.org" });
  assert.equal(cfg.endpoints.issuer.ok, true);
  assert.equal(cfg.endpoints.rookery.ok, true);
});

test("other hosts, http and explicit ports need the dev switch", () => {
  for (const url of [
    "https://sentrook.example.com",
    "https://evilfirstdataunion.org",
    "https://firstdataunion.org.evil.example",
    "http://sentrook.firstdataunion.org",
    "https://sentrook.firstdataunion.org:8443",
    "http://sentrook:8080",
  ]) {
    assert.equal(parseEndpoint(url, false).ok, false, url);
  }
  assert.deepEqual(parseEndpoint("http://sentrook:8080/", true), { ok: true, url: "http://sentrook:8080" });
});

test("credentials and metadata addresses are refused even in dev mode", () => {
  assert.equal(parseEndpoint("https://user:pw@sentrook.firstdataunion.org", true).ok, false);
  assert.equal(parseEndpoint("http://169.254.169.254/", true).ok, false);
  assert.equal(parseEndpoint("file:///etc/passwd", true).ok, false);
});

test("the dev switch is read from env, never plugin config", () => {
  const cfg = resolveConfig({ scanUrl: "http://sentrook:8080", devEndpoints: true }, {});
  assert.equal(cfg.endpoints.scan.ok, false);
  const dev = resolveConfig({ scanUrl: "http://sentrook:8080" }, { SENTROOK_DEV_ENDPOINTS: "1" });
  assert.equal(dev.endpoints.scan.ok, true);
});

test("decision policy defaults and overrides", () => {
  const d = resolveConfig({}, {});
  assert.equal(d.mode, "enforce");
  assert.equal(d.reviewAt, 45);
  assert.equal(d.blockAt, 80);
  assert.equal(d.onScanError, "review");
  const o = resolveConfig({ reviewAt: 50 }, { SENTROOK_MODE: "observe", SENTROOK_BLOCK_AT: "30" });
  assert.equal(o.mode, "observe");
  assert.equal(o.reviewAt, 50);
  assert.equal(o.blockAt, 50, "block line never sits below the review line");
});

test("grants and channel bindings", () => {
  const cfg = resolveConfig(
    {
      grants: [{ kind: "destination", pattern: "*.mycorp.example" }, { kind: "file" }],
      channelBindings: ["#ops-alerts"],
    },
    {},
  );
  assert.deepEqual(cfg.grants, [
    { kind: "destination", pattern: "*.mycorp.example", scope: "persistent" },
    { kind: "destination", pattern: "#ops-alerts", scope: "persistent" },
  ]);
});
