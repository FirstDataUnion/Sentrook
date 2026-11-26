import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

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

// Retention: records older than 30 days are dropped on a write, from the log and its rotated file.

type RetentionCase = { name: string; before: Record<string, string>; after: Record<string, string> };
const RETENTION = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/traffic-log/retention/cases.json", import.meta.url)), "utf8"),
) as { now: string; cases: RetentionCase[] };
const NOW = new Date(RETENTION.now);
const at = (when: Date) => () => when;
const noErr = () => undefined;
const scan = (ts: string, rid: string) => `${JSON.stringify({ ts, kind: "scan", request_id: rid })}\n`;

for (const c of RETENTION.cases) {
  test(`retention golden: ${c.name}`, () => {
    const dir = tmp();
    for (const [name, text] of Object.entries(c.before)) writeFileSync(path.join(dir, name), text);
    new TrafficLog(path.join(dir, "traffic.jsonl"), 1_000_000, true, noErr, at(NOW)).write({
      kind: "command",
      verb: "history",
    });
    const names = new Set(readdirSync(dir));
    assert.ok(![...names].some((n) => n.endsWith(".tmp")));
    assert.deepEqual(
      ["traffic.jsonl", "traffic.jsonl.1"].filter((n) => names.has(n)),
      ["traffic.jsonl", "traffic.jsonl.1"].filter((n) => n === "traffic.jsonl" || n in c.after),
    );
    for (const name of Object.keys(c.after).filter((n) => n !== "traffic.jsonl")) {
      assert.equal(readFileSync(path.join(dir, name), "utf8"), c.after[name]);
    }
    const text = readFileSync(path.join(dir, "traffic.jsonl"), "utf8");
    const expected = c.after["traffic.jsonl"];
    assert.ok(text.startsWith(expected), text);
    let rest = text.slice(expected.length);
    if (expected && !expected.endsWith("\n")) {
      assert.ok(rest.startsWith("\n"));
      rest = rest.slice(1);
    }
    assert.ok(rest.endsWith("\n") && rest.split("\n").length === 2, rest);
    assert.equal(JSON.parse(rest).verb, "history");
  });
}

test("a 31-day-old record is gone after the next write and a 29-day-old one stays", () => {
  const file = path.join(tmp(), "traffic.jsonl");
  writeFileSync(file, scan("2026-10-26T11:00:00.000Z", "old") + scan("2026-10-28T13:00:00.000Z", "new"), {
    mode: 0o644,
  });
  new TrafficLog(file, 1_000_000, true, noErr, at(NOW)).write({ kind: "command" });
  assert.deepEqual(
    records(file).map((r) => r.request_id),
    ["new", undefined],
  );
  assert.equal(statSync(file).mode & 0o777, 0o600); // the rewrite is readable only by the user
});

test("pruning runs at most once an hour per log", () => {
  const dir = tmp();
  const file = path.join(dir, "traffic.jsonl");
  writeFileSync(file, scan("2026-10-27T12:30:00.000Z", "edge"));
  new TrafficLog(file, 1_000_000, true, noErr, at(NOW)).write({ kind: "command" });
  // Forty minutes later "edge" is over 30 days old, but this process pruned this log less than an hour ago.
  new TrafficLog(file, 1_000_000, true, noErr, at(new Date(NOW.getTime() + 40 * 60_000))).write({ kind: "command" });
  assert.equal(records(file)[0].request_id, "edge");
  const rotated = `${file}.1`;
  writeFileSync(rotated, scan("2026-10-26T11:00:00.000Z", "old"));
  new TrafficLog(file, 1_000_000, true, noErr, at(new Date(NOW.getTime() + 3600_000))).write({ kind: "command" });
  assert.equal(records(file)[0].kind, "command");
  assert.ok(!existsSync(rotated));
});

test("a rotation with a stale rotated file keeps only recent records", () => {
  const dir = tmp();
  const file = path.join(dir, "traffic.jsonl");
  writeFileSync(file, scan("2026-10-20T00:00:00.000Z", "old") + scan("2026-11-20T00:00:00.000Z", "new"));
  writeFileSync(`${file}.1`, scan("2026-10-01T00:00:00.000Z", "older"));
  new TrafficLog(file, 10, true, noErr, at(NOW)).write({ kind: "command" });
  assert.deepEqual(
    records(`${file}.1`).map((r) => r.request_id),
    ["new"],
  );
  assert.deepEqual(
    records(file).map((r) => r.kind),
    ["command"],
  );
});

test("a large log inside the window is not rewritten", () => {
  const file = path.join(tmp(), "traffic.jsonl");
  writeFileSync(file, scan("2026-11-01T00:00:00.000Z", "a").repeat(5000) + scan("2026-10-01T00:00:00.000Z", "z"));
  const inode = statSync(file).ino;
  new TrafficLog(file, 10_000_000, true, noErr, at(NOW)).write({ kind: "command" });
  assert.equal(statSync(file).ino, inode);
});
