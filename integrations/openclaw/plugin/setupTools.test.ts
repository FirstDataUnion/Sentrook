/**
 * The agent's setup tools under OpenClaw's tool policy: the manifest lists them for every tool profile, and
 * `openclaw sentrook verify` warns when an allow or deny list in OpenClaw's config would still hide them.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import * as proposals from "./proposals.ts";
import * as report from "./setupReport.ts";
import { hiddenSetupTools, setupToolsCheck } from "./setupTools.ts";
import { formatVerifyReport, runVerify } from "./verify.ts";

const TOOLS = [report.TOOL, proposals.TOOL];
const manifest = JSON.parse(readFileSync(path.join(import.meta.dirname, "openclaw.plugin.json"), "utf8"));

/** OpenClaw's own rule (resolveManifestToolProfileNames): a plugin tool joins a profile's allow list only when the
 * manifest declares it under contracts.tools and lists the profile in toolMetadata.<tool>.profiles. */
function offeredUnder(profile: string): string[] {
  return (manifest.contracts?.tools ?? []).filter((t: string) => manifest.toolMetadata?.[t]?.profiles?.includes(profile));
}

test("the manifest lists both setup tools for every OpenClaw tool profile", () => {
  for (const profile of ["minimal", "coding", "messaging", "full"]) {
    assert.deepEqual(offeredUnder(profile), TOOLS, profile);
  }
  assert.deepEqual(Object.keys(manifest.toolMetadata).sort(), [...TOOLS].sort());
});

test("must stay silent: no tool policy, a profile alone, or lists that let the tools through", () => {
  for (const host of [
    undefined,
    {},
    { tools: { profile: "coding" } },
    { tools: { profile: "messaging", deny: ["exec", "browser"] } },
    { tools: { allow: ["read", "sentrook"] } },
    { tools: { allow: ["group:plugins"] } },
    { tools: { allow: ["sentrook_*"] } },
    { tools: { allow: ["read"], alsoAllow: [report.TOOL, proposals.TOOL] } },
    { agents: { list: [{ id: "main", tools: { profile: "coding", allow: ["*"] } }] } },
  ]) {
    assert.deepEqual(hiddenSetupTools(host), [], JSON.stringify(host));
    assert.equal(setupToolsCheck(host), null, JSON.stringify(host));
  }
});

test("must fire: a deny list naming the tools, the plugin or all plugin tools", () => {
  assert.deepEqual(hiddenSetupTools({ tools: { deny: [proposals.TOOL] } }), [{ tool: proposals.TOOL, where: "tools.deny" }]);
  for (const entry of ["sentrook", "group:plugins", "sentrook_*", "*"]) {
    assert.deepEqual(
      hiddenSetupTools({ tools: { profile: "coding", deny: [entry] } }).map((h) => h.tool),
      TOOLS,
      entry,
    );
  }
  const check = setupToolsCheck({ tools: { deny: ["group:plugins"] } });
  assert.ok(check);
  assert.equal(check.ok, true, "reported, not failed");
  assert.match(check.detail, /^warning: /);
  assert.ok(check.detail.includes("tools.deny"));
  assert.ok(check.detail.includes(proposals.TOOL));
});

test("must fire: an allow list that names neither the tools nor the plugin", () => {
  assert.deepEqual(
    hiddenSetupTools({ tools: { allow: ["read", "exec"] } }).map((h) => h.where),
    ["tools.allow", "tools.allow"],
  );
  assert.deepEqual(
    hiddenSetupTools({ agents: { list: [{ id: "main", tools: { allow: ["read", report.TOOL] } }] } }),
    [{ tool: proposals.TOOL, where: "agents.list[main].tools.allow" }],
  );
  assert.deepEqual(
    hiddenSetupTools({ agents: { list: [{ id: "ops", tools: { deny: [report.TOOL] } }] } }),
    [{ tool: report.TOOL, where: "agents.list[ops].tools.deny" }],
  );
  assert.deepEqual(
    hiddenSetupTools({ tools: { byProvider: { openai: { deny: ["sentrook"] } } } }).map((h) => h.where),
    ["tools.byProvider.openai.deny", "tools.byProvider.openai.deny"],
  );
});

test("verify reports the hidden setup tools", async () => {
  const noFetch = (async () => {
    throw new Error("no network in tests");
  }) as unknown as typeof fetch;
  const run = async (hostConfig: unknown) =>
    formatVerifyReport(await runVerify({ scanUrl: "http://scan.invalid" }, { env: {}, fetchImpl: noFetch, hostConfig }));
  assert.match(await run({ tools: { profile: "coding", deny: ["sentrook"] } }), /^ok   setup tools: warning: .*tools\.deny/m);
  assert.doesNotMatch(await run({ tools: { profile: "coding" } }), /setup tools:/);
});
