import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  buildPlanirSnapshot,
  canonicalPlanirJson,
  type PlanIR,
} from "./planir.ts";

describe("buildPlanirSnapshot", () => {
  it("emits version 1.0 with sequential sN step ids", () => {
    const plan = buildPlanirSnapshot({
      executed: [
        { tool: "read", args: { path: "/a" } },
        { tool: "read", args: { path: "/b" }, resultText: "ok" },
      ],
      coPending: [{ tool: "write", args: { path: "/c", content: "x" } }],
      pending: { tool: "exec", args: { command: "ls" } },
      runId: "sess:run_1",
    });
    assert.equal(plan.version, "1.0");
    assert.deepEqual(
      plan.steps.map((s) => s.id),
      ["s1", "s2", "s3", "s4"],
    );
    assert.equal(plan.steps[0].status, "executed");
    assert.equal(plan.steps[1].status, "executed");
    assert.equal(plan.steps[2].status, "pending");
    assert.equal(plan.steps[3].status, "pending");
  });

  it("matches Python golden: executed read + pending exec ls", () => {
    const plan = buildPlanirSnapshot({
      executed: [{ tool: "read", args: { path: "/tmp/a.txt" } }],
      pending: { tool: "exec", args: { command: "ls" } },
      runId: "golden:1",
      intent: "list files",
      adapter: "fixture",
    });
    assert.equal(plan.version, "1.0");
    assert.deepEqual(
      plan.steps.map((s) => s.id),
      ["s1", "s2"],
    );
    assert.equal(plan.steps[0].tool, "read");
    assert.equal(plan.steps[0].status, "executed");
    assert.deepEqual(plan.steps[0].args, { path: "/tmp/a.txt" });
    assert.equal(plan.steps[1].tool, "exec");
    assert.equal(plan.steps[1].status, "pending");
    assert.deepEqual(plan.steps[1].args, { command: "ls" });
    assert.equal(plan.run_id, "golden:1");
    assert.equal(plan.intent, "list files");
    assert.equal(plan.metadata.adapter, "fixture");

    const roundTrip = JSON.parse(canonicalPlanirJson(plan)) as PlanIR;
    assert.equal(roundTrip.version, "1.0");
    assert.deepEqual(
      roundTrip.steps.map((s) => s.id),
      ["s1", "s2"],
    );
  });
});
