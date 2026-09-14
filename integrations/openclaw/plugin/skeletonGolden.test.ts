import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import {
  allowlistCommandSkeleton,
  isHighRiskCommand,
  parseBindableScript,
  skeletonizeCommand,
  tokenizeArgv,
} from "./localAllowlist.ts";

/**
 * Parity fixture shared with sentrook/tests/test_skeleton.py.
 *
 * The Python twin (sentrook/serve/skeleton.py) exists so the fatigue report can
 * answer "would a host allowlist entry have skipped this review?" offline, and
 * so Phase 3b's allow families cannot drift from what this module considers the
 * same command. Both suites load this file; a divergence means the two lanes
 * disagree about command identity. Add a fixture row before changing either side.
 */
const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLDEN = path.resolve(HERE, "../../../fixtures/skeleton_golden.jsonl");

type GoldenRow = {
  name: string;
  command: string;
  tokens: string[];
  high_risk: boolean;
  skeleton: string | null;
  allowlist_skeleton: string | null;
  bindable_script: { interpreter: string; script_path: string; trailing_args: string[] } | null;
};

const rows: GoldenRow[] = readFileSync(GOLDEN, "utf8")
  .split("\n")
  .filter((line) => line.trim().length > 0)
  .map((line) => JSON.parse(line) as GoldenRow);

describe("skeleton golden fixture (shared with Python twin)", () => {
  it("is present and populated", () => {
    assert.ok(rows.length >= 50, "golden fixture lost cases; regenerate it");
    assert.equal(new Set(rows.map((r) => r.name)).size, rows.length, "duplicate case names");
  });

  for (const row of rows) {
    it(`matches: ${row.name}`, () => {
      assert.deepEqual(tokenizeArgv(row.command.trim()), row.tokens);
      assert.equal(isHighRiskCommand(row.command), row.high_risk);
      assert.equal(skeletonizeCommand(row.command), row.skeleton);
      assert.equal(allowlistCommandSkeleton(row.command), row.allowlist_skeleton);

      const bindable = parseBindableScript(row.command);
      if (row.bindable_script === null) {
        assert.equal(bindable, null);
      } else {
        assert.ok(bindable, "expected a bindable script");
        assert.equal(bindable.interpreter, row.bindable_script.interpreter);
        assert.equal(bindable.scriptPath, row.bindable_script.script_path);
        assert.deepEqual(bindable.trailingArgs, row.bindable_script.trailing_args);
      }
    });
  }
});
