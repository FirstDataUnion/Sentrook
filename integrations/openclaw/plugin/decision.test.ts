import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { blockCategory, blockReason, decide, describe, reviewCopy } from "./decision.ts";
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

test("the review card still shows the reasons the block text leaves out", () => {
  const blocked = BLOCK_TEXT.cases[1].response;
  assert.equal(
    reviewCopy(blocked, "exec").description,
    "Sends ~/.aws/credentials to cl0ud-sync.io. Why: exfil.exec_egress, path.credential_store.",
  );
});

const scored = (extra: Partial<ScanResponse> = {}): ScanResponse =>
  resp(90, null, {
    tree: { suspicion: { score: 0.92 }, consequence: { score: 0.5 }, confidence: { score: 0.8 } },
    tool_description: { category: "x", template: "Sends {E2} to {E1}" },
    entities: { E1: { kind: "host", display: "cl0ud-sync.io" }, E2: { kind: "path", display: "~/.aws/credentials" } },
    reasons: [{ code: "exfil.exec_egress" }, { code: "path.cloud_credentials" }],
    ...extra,
  });
const SCORES = " Scores: suspicion 92, consequence 50, confidence 80.";
const many = Array.from({ length: 20 }, (_, i) => ({ code: `domain.reason_${String(i).padStart(2, "0")}_${"x".repeat(60)}` }));

test("the review card shows the tree scores", () => {
  assert.equal(
    reviewCopy(scored(), "exec").description,
    `Sends ~/.aws/credentials to cl0ud-sync.io. Why: exfil.exec_egress, path.cloud_credentials.${SCORES}`,
  );
  const partial = reviewCopy(scored({ tree: { suspicion: { score: 0.92 }, consequence: { score: null } } }), "exec");
  assert.ok(partial.description.endsWith(" Scores: suspicion 92."));
  const odd = { suspicion: { score: Infinity }, consequence: { score: 1e300 }, confidence: { score: -0.5 } };
  assert.ok(reviewCopy(scored({ tree: odd }), "exec").description.endsWith(" Scores: consequence 100, confidence 0."));
});

test("without a tree the review card has no scores", () => {
  for (const tree of [undefined, {}, { suspicion: {}, consequence: { score: null } }]) {
    const card = reviewCopy(scored({ tree }), "exec");
    assert.equal(card.description, "Sends ~/.aws/credentials to cl0ud-sync.io. Why: exfil.exec_egress, path.cloud_credentials.");
  }
});

test("the review card keeps the risk and scores within the host limits", () => {
  const long = "t".repeat(2000);
  for (const [r, tool] of [
    [scored({ tool_description: null }), long],
    [scored({ reasons: many }), "exec"],
    [scored({ tool_description: null, reasons: many }), long],
    [scored({ entities: { E1: { display: "h".repeat(400) }, E2: { display: "p" } }, reasons: many }), "exec"],
  ] as const) {
    const card = reviewCopy(r, tool);
    assert.ok(card.title.length <= 80 && card.title.endsWith(" (risk 90)"), card.title);
    assert.ok(card.description.length <= 256 && card.description.endsWith(SCORES), card.description);
  }

  // Reason codes go first, one at a time, before the description is shortened.
  const entities = { E1: { display: "h".repeat(60) }, E2: { display: "~/.aws/credentials" } };
  let card = reviewCopy(scored({ entities, reasons: many.slice(0, 3) }), "exec");
  assert.ok(card.description.includes(`Sends ~/.aws/credentials to ${"h".repeat(60)}.`));
  assert.ok(card.description.includes("reason_00") && !card.description.includes("reason_02"));
  assert.ok(card.description.length <= 256);

  entities.E1.display = "h".repeat(240);
  card = reviewCopy(scored({ entities, reasons: many.slice(0, 3) }), "exec");
  assert.ok(!card.description.includes("Why:") && card.description.includes("…."));
  assert.equal(card.description.length, 256);
});

test("the review card carries no redacted data", () => {
  const secret = `ghp_${"A".repeat(36)}`;
  const r = scored({
    reasons: [{ code: "exfil.exec_egress", subject: secret, detail: { value: secret }, signal: secret }],
    entities: { E1: { kind: "host", display: "cl0ud-sync.io" }, E2: { kind: "path", display: "~/x" }, E3: { display: secret } },
  });
  Object.assign(r.tree!.suspicion!, { note: secret });
  Object.assign(r.tree!.consequence!, { sensitivity: secret });
  Object.assign(r.tree!, { extra: { score: secret } });
  const card = reviewCopy(r, "exec");
  assert.ok(!JSON.stringify(card).includes(secret));
  assert.ok(card.description.endsWith(SCORES));
});
