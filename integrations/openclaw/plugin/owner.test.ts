import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { OWNER_SCOPES, type OwnerContext, ownerCommand, ownerGate } from "./owner.ts";
import { TrafficLog } from "./traffic.ts";

const SALT = "test-salt";

function harness() {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-owner-"));
  const file = path.join(dir, "traffic.jsonl");
  const traffic = new TrafficLog(file, 1_000_000, true);
  const records = () =>
    readFileSync(file, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l))
      .filter((r) => r.kind === "command");
  return { traffic, records, salt: () => SALT };
}

/** What the host passes an admitted owner on a Control UI connection. */
function adminCtx(extra: Record<string, unknown> = {}) {
  let current = true;
  return {
    ctx: {
      senderId: "",
      channel: "webchat",
      senderIsOwner: true,
      gatewayClientScopes: ["operator.read", "operator.write", "operator.admin"],
      assertOwnerCurrent: () => {
        if (!current) throw new Error("owner authority changed");
      },
      args: "exec 24h",
      ...extra,
    },
    demote: () => {
      current = false;
    },
  };
}

test("mutating commands require the admin gateway scope", () => {
  const h = harness();
  const def = ownerCommand({ name: "grant", description: "Grant", handler: () => ({ text: "ok" }) }, h);
  assert.deepEqual(OWNER_SCOPES, ["operator.admin"]);
  assert.deepEqual(def.requiredScopes, ["operator.admin"]);
  assert.equal(def.name, "grant");
});

test("the owner runs the command and it is audited", async () => {
  const h = harness();
  const seen: unknown[] = [];
  const def = ownerCommand<OwnerContext & { args?: string }>(
    {
      name: "grant",
      description: "Grant",
      handler: (ctx, gate) => {
        gate.beforeWrite();
        seen.push(ctx.args);
        return { text: "granted" };
      },
    },
    h,
  );
  assert.deepEqual(await def.handler(adminCtx().ctx), { text: "granted" });
  assert.deepEqual(seen, ["exec 24h"]);
  const [rec] = h.records();
  assert.equal(rec.verb, "grant");
  assert.equal(rec.outcome, "allowed");
  assert.deepEqual(rec.basis, ["operator.admin"]);
  assert.equal(rec.sender_ref, null);
  assert.equal(rec.channel, "webchat");
  assert.ok(rec.ts);
});

test("an owner from a chat channel is audited by a salted hash of the sender", async () => {
  const h = harness();
  const def = ownerCommand({ name: "snooze", description: "Snooze", handler: () => ({ text: "ok" }) }, h);
  const { ctx } = adminCtx({ senderId: "telegram:42", gatewayClientScopes: undefined, channel: "telegram" });
  assert.deepEqual(await def.handler(ctx), { text: "ok" });
  const [rec] = h.records();
  assert.equal(rec.outcome, "allowed");
  assert.deepEqual(rec.basis, ["sender_is_owner"]);
  assert.equal(rec.sender_ref, `u_${createHmac("sha256", SALT).update("telegram:42").digest("hex").slice(0, 16)}`);
  assert.ok(!JSON.stringify(rec).includes("telegram:42"));
});

for (const [name, extra] of [
  ["senderIsOwner false", { senderIsOwner: false, assertOwnerCurrent: undefined }],
  ["senderIsOwner missing (no requiredScopes)", { senderIsOwner: undefined, assertOwnerCurrent: undefined }],
  ["senderIsOwner truthy but not true", { senderIsOwner: "yes" }],
  ["no assertOwnerCurrent", { assertOwnerCurrent: undefined }],
] as const) {
  test(`a non-owner is refused and audited: ${name}`, async () => {
    const h = harness();
    let ran = false;
    const def = ownerCommand(
      {
        name: "grant",
        description: "Grant",
        handler: () => {
          ran = true;
          return { text: "granted" };
        },
      },
      h,
    );
    const reply = await def.handler(adminCtx(extra as Record<string, unknown>).ctx);
    assert.match(String(reply.text), /^Only the owner can run \/sentrook grant/);
    assert.equal(ran, false);
    const [rec] = h.records();
    assert.equal(rec.outcome, "refused");
    assert.equal(rec.verb, "grant");
  });
}

test("an owner demoted before the command starts is refused", async () => {
  const h = harness();
  let ran = false;
  const def = ownerCommand(
    {
      name: "grant",
      description: "Grant",
      handler: () => {
        ran = true;
        return { text: "granted" };
      },
    },
    h,
  );
  const { ctx, demote } = adminCtx();
  demote();
  assert.match(String((await def.handler(ctx)).text), /^Only the owner/);
  assert.equal(ran, false);
  const [rec] = h.records();
  assert.equal(rec.outcome, "refused");
  assert.equal(rec.reason, "stale_owner");
});

test("an owner demoted mid-command is refused before the write", async () => {
  const h = harness();
  const writes: string[] = [];
  const { ctx, demote } = adminCtx();
  const def = ownerCommand(
    {
      name: "grant",
      description: "Grant",
      handler: async (_ctx, gate) => {
        gate.beforeWrite();
        writes.push("first");
        demote();
        await Promise.resolve();
        gate.beforeWrite();
        writes.push("second");
        return { text: "granted" };
      },
    },
    h,
  );
  assert.match(String((await def.handler(ctx)).text), /^Only the owner/);
  assert.deepEqual(writes, ["first"]);
  const recs = h.records();
  assert.deepEqual(
    recs.map((r) => [r.outcome, r.reason ?? null]),
    [
      ["allowed", null],
      ["refused", "stale_owner"],
    ],
  );
});

test("other handler errors propagate unchanged", async () => {
  const h = harness();
  const def = ownerCommand(
    {
      name: "grant",
      description: "Grant",
      handler: () => {
        throw new Error("disk full");
      },
    },
    h,
  );
  await assert.rejects(Promise.resolve(def.handler(adminCtx().ctx)), /disk full/);
});

test("ownerGate on its own reports the basis without running anything", () => {
  const h = harness();
  const audited: any[] = [];
  const gate = ownerGate(adminCtx().ctx, "grant", { ...h, traffic: { write: (r: any) => audited.push(r) } });
  assert.equal(gate.owner, true);
  assert.deepEqual(gate.basis, ["operator.admin"]);
  assert.equal(audited[0].outcome, "allowed");
});
