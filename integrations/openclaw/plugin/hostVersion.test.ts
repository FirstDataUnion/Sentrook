import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  NATIVE_UI_MIN_VERSION,
  compareVersions,
  hostUiSupport,
  readOnlyTabMessage,
  resolveHostVersion,
} from "./hostVersion.ts";

const noPackage = () => undefined;

describe("resolveHostVersion", () => {
  it("mirrors the host's own precedence", () => {
    assert.equal(
      resolveHostVersion(
        {
          OPENCLAW_VERSION: "2026.9.2",
          OPENCLAW_SERVICE_VERSION: "2026.1.1",
          npm_package_version: "0.1.0",
        } as NodeJS.ProcessEnv,
        () => "2026.8.1",
      ),
      "2026.9.2",
    );
    // The resolved package outranks the service/npm fallbacks.
    assert.equal(
      resolveHostVersion(
        { OPENCLAW_SERVICE_VERSION: "2026.1.1" } as NodeJS.ProcessEnv,
        () => "2026.9.2",
      ),
      "2026.9.2",
    );
    assert.equal(
      resolveHostVersion({ npm_package_version: "2026.8.1" } as NodeJS.ProcessEnv, noPackage),
      "2026.8.1",
    );
  });

  it("ignores blank and placeholder values", () => {
    assert.equal(resolveHostVersion({} as NodeJS.ProcessEnv, noPackage), undefined);
    assert.equal(
      resolveHostVersion({ OPENCLAW_VERSION: "  " } as NodeJS.ProcessEnv, noPackage),
      undefined,
    );
    assert.equal(
      resolveHostVersion({ OPENCLAW_VERSION: "undefined" } as NodeJS.ProcessEnv, noPackage),
      undefined,
    );
    // 0.0.0 is the host's own "no usable version" sentinel.
    assert.equal(
      resolveHostVersion(
        { OPENCLAW_VERSION: "0.0.0", npm_package_version: "2026.9.2" } as NodeJS.ProcessEnv,
        noPackage,
      ),
      "2026.9.2",
    );
  });
});

describe("compareVersions", () => {
  it("orders calver releases numerically, not lexically", () => {
    assert.equal(compareVersions("2026.9.2", "2026.9.2"), 0);
    assert.equal(compareVersions("2026.9.1", "2026.9.2"), -1);
    assert.equal(compareVersions("2026.10.0", "2026.9.2"), 1);
    // 2026.6.34 must not sort above 2026.9.2 the way string compare would.
    assert.equal(compareVersions("2026.6.34", "2026.9.2"), -1);
    assert.equal(compareVersions("2027.1.0", "2026.9.2"), 1);
  });

  it("treats a pre-release of a version as that version", () => {
    assert.equal(compareVersions("2026.9.2-beta.1", "2026.9.2"), 0);
    assert.equal(compareVersions("2026.9.1-beta", "2026.9.2"), -1);
  });

  it("reports NaN for unparseable input so callers can fall back", () => {
    assert.ok(Number.isNaN(compareVersions("nightly", "2026.9.2")));
    assert.ok(Number.isNaN(compareVersions("2026.9.2", "unknown")));
  });
});

describe("hostUiSupport", () => {
  it("splits on the release that added native plugin pages", () => {
    assert.equal(NATIVE_UI_MIN_VERSION, "2026.9.2");
    assert.equal(hostUiSupport("2026.9.2"), "native");
    assert.equal(hostUiSupport("2026.9.3"), "native");
    assert.equal(hostUiSupport("2026.10.0"), "native");
    // 2026.9.1 is the beta tag and predates the feature-plugin SDK.
    assert.equal(hostUiSupport("2026.9.1"), "legacy");
    assert.equal(hostUiSupport("2026.8.1"), "legacy");
    assert.equal(hostUiSupport("2026.6.5"), "legacy");
  });

  it("falls back to unknown rather than guessing", () => {
    assert.equal(hostUiSupport(undefined), "unknown");
    assert.equal(hostUiSupport("nightly"), "unknown");
  });
});

describe("readOnlyTabMessage", () => {
  it("tells a capable host to enable the lab", () => {
    const msg = readOnlyTabMessage("native", "2026.9.2");
    assert.match(msg, /Custom plugin UI/);
    assert.match(msg, /2026\.9\.2/);
    assert.doesNotMatch(msg, /needs OpenClaw/);
  });

  it("tells an older host to upgrade, naming its version", () => {
    const msg = readOnlyTabMessage("legacy", "2026.8.1");
    assert.match(msg, /runs OpenClaw 2026\.8\.1/);
    assert.match(msg, /2026\.9\.2 or later/);
  });

  it("names both conditions when the version is unknown", () => {
    const msg = readOnlyTabMessage("unknown");
    assert.match(msg, /2026\.9\.2 or later/);
    assert.match(msg, /Custom plugin UI/);
  });

  it("always points at the surfaces that can still write", () => {
    for (const support of ["native", "legacy", "unknown"] as const) {
      assert.match(readOnlyTabMessage(support, "2026.9.2"), /\/sentrook in chat or the sentrook CLI/);
    }
  });
});
