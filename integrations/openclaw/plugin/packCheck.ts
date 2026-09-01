/**
 * Publish-surface check for the npm tarball OpenClaw actually installs.
 * Run after `npm run build` (see package.json pack:check).
 *
 * `npm pack --json` is an array on npm < 12 and a name-keyed object on npm 12+.
 * The release workflow installs npm@latest (Trusted Publishing), so this parser
 * must accept both shapes and ignore notices before/after the JSON.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type PackFile = { path: string; size?: number };
export type PackListing = { files?: PackFile[]; filename?: string; name?: string; version?: string };

function jsonStart(text: string): number {
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "{" || c === "[") return i;
  }
  return -1;
}

/** End index (exclusive) of the first complete JSON object/array, string-aware. */
function jsonEnd(text: string, start: number): number {
  const open = text[start];
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escape) {
        escape = false;
        continue;
      }
      if (c === "\\") {
        escape = true;
        continue;
      }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0) {
        if (c !== close) {
          throw new Error("npm pack --json: malformed JSON");
        }
        return i + 1;
      }
    }
  }
  throw new Error(`npm pack --json: unterminated JSON:\n${text.slice(start, start + 400)}`);
}

function parseFirstJsonValue(text: string): unknown {
  const start = jsonStart(text);
  if (start < 0) {
    throw new Error(`npm pack --json produced no JSON:\n${text.slice(0, 400)}`);
  }
  return JSON.parse(text.slice(start, jsonEnd(text, start))) as unknown;
}

function asListing(value: unknown): PackListing | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as PackListing;
}

function looksLikeListing(value: PackListing): boolean {
  return Array.isArray(value.files) || typeof value.filename === "string" || typeof value.name === "string";
}

/**
 * Normalize `npm pack --json` stdout to a single pack listing.
 * npm < 12: `[ { files, filename, ... } ]`
 * npm >= 12: `{ "<name>": { files, filename, ... } }`
 */
export function parsePackJson(stdout: string, packageName?: string): PackListing {
  const parsed = parseFirstJsonValue(stdout);
  if (Array.isArray(parsed)) {
    if (parsed.length < 1) {
      throw new Error("npm pack --json: expected a non-empty array of pack listings");
    }
    const listing = asListing(parsed[0]);
    if (!listing) {
      throw new Error("npm pack --json: expected a non-empty array of pack listings");
    }
    return listing;
  }
  const obj = asListing(parsed);
  if (!obj) {
    throw new Error("npm pack --json: expected an array or object of pack listings");
  }
  const err = (obj as { error?: { summary?: string } }).error;
  if (err) {
    throw new Error(`npm pack --json reported an error: ${err.summary ?? JSON.stringify(err)}`);
  }
  if (looksLikeListing(obj) && Array.isArray(obj.files)) {
    return obj;
  }
  const keyed = obj as Record<string, unknown>;
  if (packageName) {
    const named = asListing(keyed[packageName]);
    if (named) return named;
  }
  const nested = Object.values(keyed)
    .map(asListing)
    .find((v) => v !== null && looksLikeListing(v));
  if (nested) return nested;
  throw new Error("npm pack --json: expected a pack listing (array or name-keyed object)");
}

function invokedDirectly(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  return resolve(entry) === fileURLToPath(import.meta.url);
}

export function runPackCheck(): void {
  const root = dirname(fileURLToPath(import.meta.url));

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
    activation?: { onStartup?: boolean; onCapabilities?: string[] };
  };
  assert.equal(manifest.id, "sentrook-openclaw");
  assert.equal(typeof manifest.name, "string");
  assert.equal(
    manifest.activation?.onStartup,
    true,
    "openclaw.plugin.json must set activation.onStartup (OpenClaw 2.0 no longer implied-loads hooks)",
  );
  assert.ok(
    manifest.activation?.onCapabilities?.includes("hook"),
    "openclaw.plugin.json must activate on the hook capability",
  );

  const distJs = join(root, "dist/index.js");
  let distBuf: Buffer;
  try {
    distBuf = readFileSync(distJs);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new Error("build did not produce dist/index.js");
    }
    throw err;
  }
  assert.ok(distBuf.length > 1024, "dist/index.js is empty or implausibly small");
  const distText = distBuf.toString("utf8");
  assert.ok(
    distText.includes("before_tool_call"),
    "dist/index.js must register before_tool_call (bundle looks incomplete)",
  );

  const packed = spawnSync("npm", ["pack", "--dry-run", "--json", "--loglevel=error"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, npm_config_update_notifier: "false" },
  });
  if (packed.status !== 0) {
    throw new Error(
      `npm pack --dry-run --json failed:\n${packed.stderr || packed.stdout}`,
    );
  }
  const listing = parsePackJson(packed.stdout, pkg.name);
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
}

if (invokedDirectly()) {
  runPackCheck();
}
