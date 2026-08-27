/**
 * Publish-surface check for the npm tarball OpenClaw actually installs.
 * Run after `npm run build` (see package.json pack:check).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));

type PackFile = { path: string; size?: number };
type PackListing = { files?: PackFile[]; filename?: string; name?: string; version?: string };

function parsePackJson(stdout: string): PackListing {
  const start = stdout.indexOf("[");
  if (start < 0) {
    throw new Error(`npm pack --json produced no array:\n${stdout.slice(0, 400)}`);
  }
  const parsed = JSON.parse(stdout.slice(start)) as unknown;
  if (!Array.isArray(parsed) || parsed.length < 1 || typeof parsed[0] !== "object") {
    throw new Error("npm pack --json: expected a non-empty array of pack listings");
  }
  return parsed[0] as PackListing;
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  name: string;
  version: string;
  main: string;
  files: string[];
  openclaw?: { runtimeExtensions?: string[] };
};

assert.equal(pkg.name, "@firstdataunion/sentrook-openclaw");
assert.equal(pkg.main, "./dist/index.js");
assert.ok(
  pkg.openclaw?.runtimeExtensions?.includes("./dist/index.js"),
  "package.json openclaw.runtimeExtensions must include ./dist/index.js",
);
assert.ok(pkg.files.includes("dist/"), "package.json files must include dist/");
assert.ok(
  pkg.files.includes("openclaw.plugin.json"),
  "package.json files must include openclaw.plugin.json",
);

const manifestRaw = readFileSync(join(root, "openclaw.plugin.json"), "utf8");
const manifest = JSON.parse(manifestRaw) as {
  id?: string;
  name?: string;
  activation?: { onCapabilities?: string[] };
};
assert.equal(manifest.id, "sentrook-openclaw");
assert.equal(typeof manifest.name, "string");
assert.ok(
  manifest.activation?.onCapabilities?.includes("hook"),
  "openclaw.plugin.json must activate on the hook capability",
);

const distJs = join(root, "dist/index.js");
assert.ok(existsSync(distJs), "build did not produce dist/index.js");
assert.ok(statSync(distJs).size > 1024, "dist/index.js is empty or implausibly small");
const distText = readFileSync(distJs, "utf8");
assert.ok(
  distText.includes("before_tool_call"),
  "dist/index.js must register before_tool_call (bundle looks incomplete)",
);

const packed = spawnSync("npm", ["pack", "--dry-run", "--json"], {
  cwd: root,
  encoding: "utf8",
});
if (packed.status !== 0) {
  throw new Error(
    `npm pack --dry-run --json failed:\n${packed.stderr || packed.stdout}`,
  );
}
const listing = parsePackJson(packed.stdout);
const packedPaths = new Set((listing.files ?? []).map((f) => f.path));

const required = [
  "dist/index.js",
  "openclaw.plugin.json",
  "package.json",
  "index.ts",
] as const;
for (const path of required) {
  assert.ok(packedPaths.has(path), `npm pack is missing ${path}`);
}

const distEntry = (listing.files ?? []).find((f) => f.path === "dist/index.js");
assert.ok(distEntry && (distEntry.size ?? 0) > 1024, "packed dist/index.js is missing or empty");

const mustNotPack = [...packedPaths].filter(
  (p) => p.endsWith(".test.ts") || p === "packCheck.ts" || p.startsWith("fixtures/"),
);
assert.deepEqual(mustNotPack, [], `tarball must not include tests/fixtures: ${mustNotPack.join(", ")}`);

console.log(
  `pack:check ok — ${listing.filename ?? `${pkg.name}@${pkg.version}`} includes dist/index.js + openclaw.plugin.json (${packedPaths.size} files)`,
);
