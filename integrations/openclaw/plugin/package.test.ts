/**
 * Store metadata ClawHub validates, kept in step with the guide and the plugin's own version constant.
 * The tarball side (every declared entry is packed) is in packCheck.ts.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PLUGIN_VERSION } from "./planir.ts";

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");
const pkg = JSON.parse(read("./package.json"));
const manifest = JSON.parse(read("./openclaw.plugin.json"));
const guide = read("../README.md");
const packageReadme = read("./README.md");

/** The oldest OpenClaw the plugin is tested on: `openclaw.build.openclawVersion`. */
const floor: string = pkg.openclaw?.build?.openclawVersion;

test("package.json declares the plugin API floor and the OpenClaw version it was built and tested against", () => {
  assert.match(floor, /^\d{4}\.\d{1,2}\.\d+$/, "openclaw.build.openclawVersion is an exact OpenClaw release");
  assert.equal(pkg.openclaw?.compat?.pluginApi, `>=${floor}`, "openclaw.compat.pluginApi is a floor at the tested version");
});

test("the guide and the package README name the same floor", () => {
  assert.ok(guide.includes(`OpenClaw **${floor} or newer**`), `guide requirements say OpenClaw ${floor} or newer`);
  assert.ok(packageReadme.includes(`OpenClaw ${floor} or newer`), `package README says OpenClaw ${floor} or newer`);
});

test("one version: package.json and the version the plugin reports", () => {
  assert.equal(PLUGIN_VERSION, pkg.version);
});

test("every declared entry is shipped by the files allowlist", () => {
  const entries: string[] = [...(pkg.openclaw?.extensions ?? []), ...(pkg.openclaw?.runtimeExtensions ?? [])];
  assert.ok(entries.length >= 2, "both a source and a runtime entry are declared");
  for (const entry of entries) {
    const rel = entry.replace(/^\.\//, "");
    const shipped = (pkg.files as string[]).some((f) => (f.endsWith("/") ? rel.startsWith(f) : rel === f));
    assert.ok(shipped, `files ships ${entry}`);
  }
});

test("the manifest names one ClawHub category and keeps its id", () => {
  assert.equal(manifest.id, "sentrook");
  assert.deepEqual(manifest.categories, ["security"]);
  assert.equal(manifest.version, undefined, "package.json is the only version (ClawHub flags drift)");
});

test("the package README discloses what leaves the machine, what the plugin can do, and how to turn it off", () => {
  for (const needle of [
    "sentrook.firstdataunion.org",
    "identity.firstdataunion.org",
    "SENTROOK_SCAN_CLIENT_ID",
    "~/.openclaw/.env",
    "redacted",
    "observe",
    "openclaw plugins disable sentrook",
    "No telemetry",
    "https://github.com/FirstDataUnion/Sentrook/tree/main/integrations/openclaw",
  ]) {
    assert.ok(packageReadme.includes(needle), `package README mentions ${needle}`);
  }
});
