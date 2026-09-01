import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parsePackJson } from "./packCheck.ts";

const files = [
  { path: "package.json", size: 80 },
  { path: "dist/index.js", size: 121200 },
  { path: "openclaw.plugin.json", size: 400 },
  { path: "index.ts", size: 200 },
];

const listing = {
  id: "@firstdataunion/sentrook-openclaw@1.0.6-rc.1",
  name: "@firstdataunion/sentrook-openclaw",
  version: "1.0.6-rc.1",
  filename: "firstdataunion-sentrook-openclaw-1.0.6-rc.1.tgz",
  files,
  entryCount: files.length,
  bundled: [] as string[],
};

describe("parsePackJson", () => {
  it("reads npm < 12 array output", () => {
    const parsed = parsePackJson(JSON.stringify([listing]));
    assert.equal(parsed.filename, listing.filename);
    assert.deepEqual(
      parsed.files?.map((f) => f.path),
      files.map((f) => f.path),
    );
  });

  it("reads npm 12 name-keyed object output", () => {
    const stdout = JSON.stringify({ [listing.name]: listing });
    const parsed = parsePackJson(stdout, listing.name);
    assert.equal(parsed.filename, listing.filename);
    assert.equal(parsed.files?.length, files.length);
  });

  it("does not treat the inner files array as the whole document", () => {
    // Reproduces CI: indexOf('[') + JSON.parse(slice) hits `],` after `files`.
    const stdout = JSON.stringify({ [listing.name]: listing }, null, 2);
    assert.match(stdout, /\],/);
    const parsed = parsePackJson(stdout, listing.name);
    assert.ok(parsed.files?.some((f) => f.path === "dist/index.js"));
    assert.equal(parsed.name, listing.name);
  });

  it("ignores notices before and after the JSON", () => {
    const stdout = `npm notice\n${JSON.stringify({ [listing.name]: listing })}\nnpm notice extra\n`;
    const parsed = parsePackJson(stdout, listing.name);
    assert.equal(parsed.filename, listing.filename);
  });

  it("surfaces npm pack error objects", () => {
    assert.throws(
      () => parsePackJson(JSON.stringify({ error: { summary: "Invalid package" } })),
      /Invalid package/,
    );
  });
});
