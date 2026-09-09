import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  classifyAttendance,
  extractIntentText,
  firstNonemptyIntent,
  isCronSessionKey,
  isHeartbeatSessionKey,
  isSubagentSessionKey,
} from "./attendance.ts";

describe("session key classifiers", () => {
  it("detects cron base and per-run keys", () => {
    assert.equal(
      isCronSessionKey("agent:main:cron:c6bc5d5c-1a3d-4a32-81e6-ad73f1e9ef2a"),
      true,
    );
    assert.equal(
      isCronSessionKey(
        "agent:main:cron:c6bc5d5c-1a3d-4a32-81e6-ad73f1e9ef2a:run:0654ed91-676b-4b86-bfed-7a1dacefbb47",
      ),
      true,
    );
    assert.equal(isCronSessionKey("agent:main:main"), false);
    assert.equal(isCronSessionKey("main"), false);
  });

  it("detects isolated heartbeat suffixes without treating cron as heartbeat", () => {
    assert.equal(isHeartbeatSessionKey("agent:main:main:heartbeat"), true);
    assert.equal(isHeartbeatSessionKey("agent:main:heartbeat"), true);
    assert.equal(isHeartbeatSessionKey("agent:main:main"), false);
    assert.equal(
      isHeartbeatSessionKey("agent:main:cron:job:run:abc"),
      false,
    );
  });

  it("detects scoped and unscoped subagent keys", () => {
    assert.equal(isSubagentSessionKey("agent:main:subagent:search-helper"), true);
    assert.equal(isSubagentSessionKey("subagent:review-pr-1842"), true);
    assert.equal(isSubagentSessionKey("agent:main:main"), false);
  });
});

describe("classifyAttendance", () => {
  it("prefers host trigger over an empty prompt", () => {
    assert.deepEqual(
      classifyAttendance({ trigger: "cron", intentText: "" }),
      { kind: "cron", unattended: true },
    );
    assert.deepEqual(
      classifyAttendance({ trigger: "heartbeat" }),
      { kind: "heartbeat", unattended: true },
    );
    assert.deepEqual(
      classifyAttendance({ trigger: "user" }),
      { kind: "user", unattended: false },
    );
  });

  it("treats jobId as cron when trigger is missing", () => {
    assert.deepEqual(
      classifyAttendance({ jobId: "c6bc5d5c-1a3d-4a32-81e6-ad73f1e9ef2a" }),
      { kind: "cron", unattended: true },
    );
  });

  it("classifies a cron session key with no prompt (the 2026-09-09 bug)", () => {
    assert.deepEqual(
      classifyAttendance({
        sessionKey:
          "agent:main:cron:c6bc5d5c-1a3d-4a32-81e6-ad73f1e9ef2a:run:0654ed91-676b-4b86-bfed-7a1dacefbb47",
        intentText: "",
      }),
      { kind: "cron", unattended: true },
    );
  });

  it("does not treat a subagent of a user session as unattended", () => {
    assert.deepEqual(
      classifyAttendance({
        sessionKey: "agent:main:subagent:search-helper",
        parentSessionKey: "agent:main:main",
      }),
      { kind: "subagent", unattended: false },
    );
  });

  it("inherits unattended from a cron parent", () => {
    assert.deepEqual(
      classifyAttendance({
        sessionKey: "agent:main:subagent:nightly-mail",
        parentSessionKey:
          "agent:main:cron:c6bc5d5c-1a3d-4a32-81e6-ad73f1e9ef2a:run:0654ed91-676b-4b86-bfed-7a1dacefbb47",
      }),
      { kind: "subagent", unattended: true },
    );
  });

  it("inherits unattended from a heartbeat parent", () => {
    assert.deepEqual(
      classifyAttendance({
        sessionKey: "agent:main:subagent:pulse",
        parentSessionKey: "agent:main:main:heartbeat",
      }),
      { kind: "subagent", unattended: true },
    );
  });

  it("treats a subagent with trigger cron as unattended", () => {
    assert.deepEqual(
      classifyAttendance({
        trigger: "cron",
        sessionKey: "agent:main:subagent:from-cron",
      }),
      { kind: "subagent", unattended: true },
    );
  });

  it("falls back to prompt [cron:] markers for older hosts", () => {
    assert.deepEqual(
      classifyAttendance({ intentText: "[cron: nightly] check mail" }),
      { kind: "cron", unattended: true },
    );
  });

  it("keeps unknown subagents attended unless scheduledIntentKinds includes subagent", () => {
    assert.deepEqual(
      classifyAttendance({ sessionKey: "agent:main:subagent:orphan" }),
      { kind: "subagent", unattended: false },
    );
    assert.deepEqual(
      classifyAttendance(
        { sessionKey: "agent:main:subagent:orphan" },
        ["subagent"],
      ),
      { kind: "subagent", unattended: true },
    );
  });
});

describe("extractIntentText", () => {
  it("reads prompt and inbound content keys", () => {
    assert.equal(extractIntentText({ prompt: "  check my mail  " }), "check my mail");
    assert.equal(extractIntentText({ content: "discord inbound" }), "discord inbound");
    assert.equal(extractIntentText("plain"), "plain");
    assert.equal(extractIntentText({ prompt: "   " }), undefined);
  });

  it("falls back to the last user message when prompt is empty", () => {
    assert.equal(
      extractIntentText({
        prompt: "  ",
        messages: [
          { role: "system", content: "ignore" },
          { role: "user", content: "ship the gateway config" },
          { role: "assistant", content: "ok" },
        ],
      }),
      "ship the gateway config",
    );
    assert.equal(
      extractIntentText({
        messages: [{ role: "user", content: [{ type: "text", text: "from parts" }] }],
      }),
      "from parts",
    );
  });
});

describe("firstNonemptyIntent", () => {
  it("skips empty candidates", () => {
    assert.equal(firstNonemptyIntent("", "  ", null, "kept"), "kept");
    assert.equal(firstNonemptyIntent(undefined, ""), "");
  });
});
