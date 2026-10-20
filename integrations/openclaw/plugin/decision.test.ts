import assert from "node:assert/strict";
import { test } from "node:test";

import { blockReason, decide, describe, reviewCopy } from "./decision.ts";
import type { ScanResponse } from "./scanClient.ts";

const resp = (risk: number, enforced: ScanResponse["enforced"] = null, extra: Partial<ScanResponse> = {}): ScanResponse => ({
  response_version: "2.0",
  status: "ok",
  risk,
  enforced,
  ...extra,
});
const lines = { reviewAt: 45, blockAt: 80 };

test("risk lines", () => {
  assert.equal(decide(resp(44.9), lines), "allow");
  assert.equal(decide(resp(45), lines), "review");
  assert.equal(decide(resp(79.9), lines), "review");
  assert.equal(decide(resp(80), lines), "block");
});

test("an enforced floor is never weakened", () => {
  assert.equal(decide(resp(10, "block"), lines), "block");
  assert.equal(decide(resp(10, "review"), lines), "review");
  assert.equal(decide(resp(90, "review"), lines), "block");
});

test("tool description fills entity placeholders", () => {
  const r = resp(90, null, {
    tool_description: { category: "x", template: "Sends {E2} to {E1}" },
    entities: { E1: { kind: "host", display: "cl0ud-sync.io" }, E2: { kind: "path", display: "~/.aws/credentials" } },
    reasons: [{ code: "exfil.exec_egress" }, { code: "path.cloud_credentials" }, { code: "exfil.exec_egress" }],
  });
  assert.equal(describe(r, "exec"), "Sends ~/.aws/credentials to cl0ud-sync.io");
  assert.equal(describe(resp(1), "exec"), "Runs exec");
  const card = reviewCopy(r, "exec");
  assert.equal(card.title, "Sentrook: review exec (risk 90)");
  assert.equal(card.description, "Sends ~/.aws/credentials to cl0ud-sync.io. Why: exfil.exec_egress, path.cloud_credentials.");
  assert.match(blockReason(r, "exec"), /^Sentrook blocked this tool call, risk 90\/100: Sends/);
});
