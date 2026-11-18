/**
 * Copy package.json's version into PLUGIN_VERSION (planir.ts), so a Changesets version bump also changes the version
 * the plugin reports. Run by the root `version` script after `changeset version`.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const at = (rel: string) => fileURLToPath(new URL(rel, import.meta.url));
const { version } = JSON.parse(readFileSync(at("./package.json"), "utf8")) as { version: string };
const path = at("./planir.ts");
const source = readFileSync(path, "utf8");
const line = /^export const PLUGIN_VERSION = "[^"]*";$/m;
if (!line.test(source)) throw new Error("planir.ts has no PLUGIN_VERSION line to update");
writeFileSync(path, source.replace(line, `export const PLUGIN_VERSION = ${JSON.stringify(version)};`));
console.log(`PLUGIN_VERSION = ${version}`);
