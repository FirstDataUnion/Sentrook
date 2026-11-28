/** Whether approval cards reach the owner in each chat app OpenClaw has on (`approvalRoutes.ts`). */
import assert from "node:assert/strict";
import test from "node:test";

import { approvalRoutes } from "./approvalRoutes.ts";

const OWNER = { commands: { ownerAllowFrom: ["discord:251"] } };
const route = (cfg: unknown, app: string) => approvalRoutes(cfg)?.find((r) => r.app === app);

test("unreadable config: not read; no channels: an empty list", () => {
  assert.equal(approvalRoutes(undefined), null);
  assert.deepEqual(approvalRoutes({}), []);
});

test("Discord: cards reach the owner once enabled (true or auto) with an approver", () => {
  for (const enabled of [true, "auto"]) {
    assert.equal(route({ ...OWNER, channels: { discord: { execApprovals: { enabled } } } }, "discord")?.ok, true);
  }
  // an account's own block counts, and its approvers do too
  const viaAccount = { channels: { discord: { accounts: { default: { execApprovals: { enabled: "auto", approvers: ["251"] } } } } } };
  assert.equal(route(viaAccount, "discord")?.ok, true);
});

test("Discord: off until enabled; no approver is refused; each says what the owner runs", () => {
  const off = route({ ...OWNER, channels: { discord: {} } }, "discord")!;
  assert.equal(off.ok, false);
  assert.ok(off.text.includes("openclaw config set channels.discord.execApprovals.enabled true"));
  const noApprover = route({ channels: { discord: { execApprovals: { enabled: true } } } }, "discord")!;
  assert.equal(noApprover.ok, false);
  assert.ok(noApprover.text.includes("channels.discord.execApprovals.approvers"));
  // another app's owner entry is not an approver here
  assert.equal(route({ commands: { ownerAllowFrom: ["telegram:9"] }, channels: { discord: { execApprovals: { enabled: true } } } }, "discord")?.ok, false);
});

test("Telegram: on by default, needs an approver; enabled false is off", () => {
  assert.equal(route({ commands: { ownerAllowFrom: ["telegram:9"] }, channels: { telegram: {} } }, "telegram")?.ok, true);
  assert.equal(route({ channels: { telegram: {} } }, "telegram")?.ok, false);
  assert.equal(route({ commands: { ownerAllowFrom: ["telegram:9"] }, channels: { telegram: { execApprovals: { enabled: false } } } }, "telegram")?.ok, false);
});

test("WhatsApp and Signal need approvals.plugin; Slack needs nothing; others are unknown; off channels are skipped", () => {
  const cfg = { channels: { whatsapp: {}, signal: {}, slack: {}, matrix: {}, telegram: { enabled: false } } };
  const routes = approvalRoutes(cfg)!;
  assert.deepEqual(routes.map((r) => [r.app, r.ok]), [["matrix", null], ["signal", false], ["slack", true], ["whatsapp", false]]);
  assert.ok(routes.find((r) => r.app === "whatsapp")!.text.includes("openclaw config set approvals.plugin.enabled true"));
  assert.ok(routes.find((r) => r.app === "signal")!.text.includes("channels.signal.allowFrom"));
  const forwarded = approvalRoutes({ ...cfg, approvals: { plugin: { enabled: true, mode: "session" } } })!;
  assert.equal(forwarded.find((r) => r.app === "whatsapp")!.ok, true);
});
