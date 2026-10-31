import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { TrafficLog } from "./traffic.ts";

/** The start of a scan record whose write was cut off (a crash or a full disk): no closing brace, no newline. */
const TORN = '{"kind": "scan", "request_id": "9999';
const SCAN = '{"kind": "scan", "request_id": "1111"}\n';

const tmp = () => mkdtempSync(path.join(tmpdir(), "sentrook-traffic-"));

function records(file: string) {
  return readFileSync(file, "utf8")
    .split("\n")
    .flatMap((l) => {
      try {
        return [JSON.parse(l)];
      } catch {
        return [];
      }
    });
}

test("a record after a torn last line starts its own line", () => {
  const file = path.join(tmp(), "traffic.jsonl");
  writeFileSync(file, SCAN + TORN);
  new TrafficLog(file, 1_000_000, true).write({ kind: "command", verb: "history" });
  const lines = readFileSync(file, "utf8").split("\n");
  assert.deepEqual(lines.slice(0, 2), [SCAN.trimEnd(), TORN]);
  assert.equal(JSON.parse(lines[2]).kind, "command");
  assert.deepEqual(lines.slice(3), [""]);
  assert.deepEqual(
    records(file).map((r) => r.kind),
    ["scan", "command"],
  );
});

test("a log ending with a newline gets no blank line", () => {
  const file = path.join(tmp(), "traffic.jsonl");
  writeFileSync(file, SCAN);
  const log = new TrafficLog(file, 1_000_000, true);
  log.write({ kind: "command", verb: "history" });
  log.write({ kind: "command", verb: "why" });
  const text = readFileSync(file, "utf8");
  assert.ok(!text.includes("\n\n"));
  assert.ok(text.startsWith(SCAN));
  assert.deepEqual(
    records(file).map((r) => r.verb),
    [undefined, "history", "why"],
  );
});

test("a new or empty file starts with the record", () => {
  const dir = tmp();
  const empty = path.join(dir, "empty.jsonl");
  writeFileSync(empty, "");
  for (const file of [path.join(dir, "new", "traffic.jsonl"), empty]) {
    new TrafficLog(file, 1_000_000, true).write({ kind: "command" });
    const text = readFileSync(file, "utf8");
    assert.ok(text.startsWith('{"ts":') && text.endsWith("}\n"), text);
    assert.equal(text.split("\n").length, 2);
  }
});

test("a freshly rotated file starts with the record", () => {
  const dir = tmp();
  const file = path.join(dir, "traffic.jsonl");
  writeFileSync(file, SCAN + TORN);
  new TrafficLog(file, 10, true).write({ kind: "command" });
  assert.equal(readFileSync(`${file}.1`, "utf8"), SCAN + TORN);
  const text = readFileSync(file, "utf8");
  assert.ok(text.startsWith('{"ts":'), text);
  assert.equal(text.split("\n").length, 2);
  assert.equal(records(file)[0].kind, "command");
});
