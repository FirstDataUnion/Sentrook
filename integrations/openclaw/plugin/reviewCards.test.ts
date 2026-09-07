import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

import { ReviewCardStore, snapshotReviewPrior } from "./reviewCards.ts";

const stores: ReviewCardStore[] = [];

function sample(overrides: Partial<Parameters<ReviewCardStore["put"]>[0]> = {}) {
  return {
    eventId: "evt-1",
    toolCallId: "t1",
    tool: "exec",
    args: { command: "curl https://x" },
    scan: { decision: "review" },
    timeoutMs: 60_000,
    ...overrides,
  };
}

afterEach(() => {
  while (stores.length) stores.pop()?.shutdown();
});

describe("ReviewCardStore", () => {
  it("put/get/take by toolCallId and eventId", () => {
    const store = new ReviewCardStore();
    stores.push(store);
    store.put(sample());
    assert.equal(store.size(), 1);
    assert.equal(store.get("t1")?.eventId, "evt-1");
    assert.equal(store.get("evt-1")?.toolCallId, "t1");
    assert.equal(store.take("t1")?.eventId, "evt-1");
    assert.equal(store.size(), 0);
    assert.equal(store.get("t1"), undefined);
    assert.equal(store.get("evt-1"), undefined);
  });

  it("replacing the same toolCallId drops the previous card", () => {
    const store = new ReviewCardStore();
    stores.push(store);
    store.put(sample({ eventId: "old" }));
    store.put(sample({ eventId: "new" }));
    assert.equal(store.size(), 1);
    assert.equal(store.get("t1")?.eventId, "new");
    assert.equal(store.get("old"), undefined);
  });

  it("evicts after timeoutMs", async () => {
    const store = new ReviewCardStore();
    stores.push(store);
    store.put(sample({ timeoutMs: 20 }));
    assert.equal(store.size(), 1);
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(store.size(), 0);
  });
});

describe("snapshotReviewPrior", () => {
  it("numbers from 1 and keeps command plus excerpt", () => {
    const snap = snapshotReviewPrior([
      { tool: "read", args: { path: "/tmp/a" }, resultText: "hello", resultOk: true },
      { tool: "exec", args: { command: "ls" }, resultText: "notes.md", resultOk: false },
    ]);
    assert.equal(snap.priorOmitted, 0);
    assert.equal(snap.priorSteps.length, 2);
    assert.deepEqual(snap.priorSteps[0], {
      seq: 1,
      tool: "read",
      command: '{"path":"/tmp/a"}',
      ok: true,
      excerpt: "hello",
    });
    assert.equal(snap.priorSteps[1]?.seq, 2);
    assert.equal(snap.priorSteps[1]?.ok, false);
    assert.equal(snap.priorSteps[1]?.command, "ls");
  });

  it("keeps the last 40 and continues seq after omitted", () => {
    const executed = Array.from({ length: 42 }, (_, i) => ({
      tool: "exec",
      args: { command: `step-${i + 1}` },
    }));
    const snap = snapshotReviewPrior(executed);
    assert.equal(snap.priorOmitted, 2);
    assert.equal(snap.priorSteps.length, 40);
    assert.equal(snap.priorSteps[0]?.seq, 3);
    assert.equal(snap.priorSteps[0]?.command, "step-3");
    assert.equal(snap.priorSteps.at(-1)?.seq, 42);
    assert.equal(snap.priorSteps.at(-1)?.command, "step-42");
  });
});
