import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Store } from "./store.ts";

const STORE_URL = new URL("./store.ts", import.meta.url).href;
const run = promisify(execFile);

const stateDir = () => path.join(mkdtempSync(path.join(tmpdir(), "sentrook-store-")), "sentrook");

/** One process that waits until `at` (epoch ms) and then makes its first `salt()` call on `dir`. */
function saltInChild(dir: string, at: number) {
  const script = `
    import { Store } from ${JSON.stringify(STORE_URL)};
    while (Date.now() < ${at}) {}
    process.stdout.write(new Store(${JSON.stringify(dir)}).salt());
  `;
  return run(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script], {
    cwd: path.dirname(fileURLToPath(STORE_URL)),
  }).then((r) => r.stdout);
}

/** Six processes make their first `salt()` call on `dir` at the same moment; all must agree. */
async function raceSalt(dir: string) {
  // Far enough ahead that every child has started (and is spinning) before it.
  const at = Date.now() + 3_000;
  const salts = await Promise.all(Array.from({ length: 6 }, () => saltInChild(dir, at)));
  assert.match(salts[0]!, /^[0-9a-f]{64}$/);
  assert.deepEqual(new Set(salts), new Set([salts[0]]));
  assert.equal(readFileSync(path.join(dir, "salt"), "utf8"), salts[0]);
  assert.equal(statSync(path.join(dir, "salt")).mode & 0o777, 0o600);
  assert.deepEqual(
    readdirSync(dir).filter((f) => f.endsWith(".tmp")),
    [],
  );
}

test("concurrent first salt() calls from separate processes all get the same salt, stored 0o600", async () => {
  for (let round = 0; round < 3; round++) {
    const dir = stateDir();
    await raceSalt(dir);
    assert.deepEqual(readdirSync(dir), ["salt"]);
  }
});

test("concurrent first salt() calls over an empty salt file all get the same new salt", async () => {
  for (let round = 0; round < 3; round++) {
    const dir = stateDir();
    new Store(dir).salt();
    writeFileSync(path.join(dir, "salt"), "");
    await raceSalt(dir);
  }
});

test("two stores on one dir in one process get the same salt", () => {
  const dir = stateDir();
  const a = new Store(dir).salt();
  const b = new Store(dir).salt();
  assert.equal(a, b);
  assert.equal(statSync(path.join(dir, "salt")).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
});

test("an existing salt is kept, and an empty salt file is replaced", () => {
  const dir = stateDir();
  new Store(dir).salt();
  writeFileSync(path.join(dir, "salt"), "kept-salt\n");
  assert.equal(new Store(dir).salt(), "kept-salt");

  writeFileSync(path.join(dir, "salt"), "");
  const fresh = new Store(dir).salt();
  assert.match(fresh, /^[0-9a-f]{64}$/);
  assert.equal(readFileSync(path.join(dir, "salt"), "utf8"), fresh);
  assert.deepEqual(
    readdirSync(dir).filter((f) => f.endsWith(".tmp")),
    [],
  );
});
