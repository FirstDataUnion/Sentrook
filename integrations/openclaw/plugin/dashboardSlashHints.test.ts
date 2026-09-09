import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ALLOW_ALL_OFF,
  ALLOW_ALL_ON,
  CONFIGURE_CLI,
  LOG_PURGE,
  LOG_WIPE,
  VERIFY_CLI,
  allowAllSession,
  allowlistRm,
  approveAlways,
  approveDeny,
  approveOnce,
  pendingInspect,
  resolveChatCommands,
  feedbackCmd,
  logRetentionDays,
  logRetentionMib,
  quietAll,
  quietSession,
  scanErrorCmd,
  sensitivityCmd,
  sensitivitySession,
  sessionToken,
} from "./dashboardSlashHints.ts";

describe("dashboardSlashHints", () => {
  it("uses complete /approve commands and inspect-when-missing, never plugin:…", () => {
    assert.equal(approveOnce("plugin:abc"), "/approve plugin:abc allow-once");
    assert.equal(approveAlways("plugin:abc"), "/approve plugin:abc allow-always");
    assert.equal(approveDeny("plugin:abc"), "/approve plugin:abc deny");
    assert.equal(approveOnce(undefined), "");
    assert.equal(approveAlways("  "), "");
    assert.deepEqual(resolveChatCommands("plugin:abc"), [
      { label: "Allow once", cmd: "/approve plugin:abc allow-once" },
      { label: "Allow always", cmd: "/approve plugin:abc allow-always" },
      { label: "Deny", cmd: "/approve plugin:abc deny" },
    ]);
    assert.deepEqual(resolveChatCommands(undefined, "e1"), [
      { label: "Inspect in chat", cmd: "/sentrook pending e1" },
    ]);
    assert.equal(pendingInspect("e1"), "/sentrook pending e1");
  });

  it("matches /sentrook usage for policy, log, and CLI", () => {
    assert.equal(ALLOW_ALL_OFF, "/sentrook allow-all all off");
    assert.equal(ALLOW_ALL_ON, "/sentrook allow-all all on");
    assert.equal(quietAll("8h"), "/sentrook quiet all 8h");
    assert.equal(allowAllSession("agent:main:main", true), "/sentrook allow-all session agent:main:main on");
    assert.equal(quietSession("sk", "off"), "/sentrook quiet session sk off");
    assert.equal(sensitivityCmd("attended", "warning"), "/sentrook sensitivity attended warning");
    assert.equal(sensitivityCmd("unattended", "critical"), "/sentrook sensitivity unattended critical confirm");
    assert.equal(
      sensitivitySession("cron:nightly", "attended", "warning"),
      "/sentrook sensitivity session cron:nightly attended warning",
    );
    assert.equal(
      sensitivitySession("cron:nightly", "unattended", "critical"),
      "/sentrook sensitivity session cron:nightly unattended critical confirm",
    );
    assert.equal(feedbackCmd("off"), "/sentrook feedback off");
    assert.equal(scanErrorCmd("allow"), "/sentrook scan-error allow confirm");
    assert.equal(scanErrorCmd("deny"), "/sentrook scan-error deny");
    assert.equal(allowlistRm(3), "/sentrook allowlist rm 3");
    assert.equal(logRetentionDays(7), "/sentrook log retention 7d");
    assert.equal(logRetentionMib(32), "/sentrook log retention 32MiB");
    assert.equal(LOG_PURGE, "/sentrook log purge confirm");
    assert.equal(LOG_WIPE, "/sentrook log purge all confirm");
    assert.equal(VERIFY_CLI, "openclaw sentrook verify");
    assert.equal(CONFIGURE_CLI, "openclaw sentrook configure");
  });

  it("prefers sessionKey over sessionId for the session token", () => {
    assert.equal(sessionToken("key", "id"), "key");
    assert.equal(sessionToken(undefined, "id"), "id");
    assert.equal(sessionToken(), "<key>");
  });
});
