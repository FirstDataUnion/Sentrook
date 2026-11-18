import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { blockCategory, blockReason, decide, describe, severity } from "./decision.ts";
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

const CEILING = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/ceiling/cases.json", import.meta.url)), "utf8"),
) as { cases: { name: string; lines: { review_at: number; block_at: number }; response: ScanResponse; verdict: string }[] };

test("verdict ceiling: lowered to review, never raised, enforced still wins", () => {
  assert.ok(CEILING.cases.length >= 5);
  for (const c of CEILING.cases) {
    assert.equal(decide(c.response, { reviewAt: c.lines.review_at, blockAt: c.lines.block_at }), c.verdict, c.name);
  }
});

test("severity: critical for a floor's review and for a block the ceiling lowered", () => {
  assert.equal(severity(resp(55), lines), "warning");
  assert.equal(severity(resp(55, null, { ceiling: "review" }), lines), "warning");
  assert.equal(severity(resp(95, null, { ceiling: "review" }), lines), "critical");
  assert.equal(severity(resp(10, "review"), lines), "critical");
  // a block a snooze turned into a review
  assert.equal(severity(resp(92), lines, true), "critical");
  // custom lines: the block line is the owner's
  assert.equal(severity(resp(90, null, { ceiling: "review" }), { blockAt: 95 }), "warning");
});

test("tool description fills entity placeholders", () => {
  const r = resp(90, null, {
    tool_description: { category: "x", template: "Sends {E2} to {E1}" },
    entities: { E1: { kind: "host", display: "cl0ud-sync.io" }, E2: { kind: "path", display: "~/.aws/credentials" } },
    reasons: [{ code: "exfil.exec_egress" }, { code: "path.cloud_credentials" }, { code: "exfil.exec_egress" }],
  });
  assert.equal(describe(r, "exec"), "Sends ~/.aws/credentials to cl0ud-sync.io");
  assert.equal(describe(resp(1), "exec"), "Runs exec");
  assert.match(blockReason(r), /^Sentrook security block: this tool call did not run because it reads or sends/);
});

const BLOCK_TEXT = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/block-text/cases.json", import.meta.url)), "utf8"),
) as { cases: { name: string; response: ScanResponse; category: string; text: string }[] };

test("block text: the agreed agent text and coarse category for each case", () => {
  for (const c of BLOCK_TEXT.cases) {
    assert.equal(blockCategory(c.response), c.category, c.name);
    assert.equal(blockReason(c.response), c.text, c.name);
  }
});

test("block text never names a reason code, the risk, an entity or the tool description", () => {
  for (const c of BLOCK_TEXT.cases) {
    const text = blockReason(c.response);
    for (const r of c.response.reasons ?? []) {
      const code = (r as { code?: unknown } | null)?.code;
      if (typeof code === "string" && code) assert.ok(!text.includes(code), `${c.name}: ${code}`);
    }
    for (const e of Object.values(c.response.entities ?? {})) if (e.display) assert.ok(!text.includes(e.display), c.name);
    assert.ok(!/\d/.test(text), `${c.name}: no risk or score`);
    assert.ok(!text.includes(describe(c.response, "exec")), c.name);
    assert.ok(!text.includes("enforced"), c.name);
  }
});

