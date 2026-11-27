/**
 * Who sent a chat message: the same group facts give the same sender in both plugins. The owner in a group stays
 * the owner, with basis `group_chat`; anyone else there is `other`. The cases are shared with the Hermes plugin's
 * tests (`integrations/fixtures/sender`).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { senderOf } from "./planir.ts";

const FIXTURE = JSON.parse(
  readFileSync(path.join(import.meta.dirname, "..", "..", "fixtures", "sender", "cases.json"), "utf8"),
);
const CFG = { trustedSenders: [], trustedRoles: [] };

for (const c of FIXTURE.cases) {
  test(`sender parity: ${c.name}`, () => {
    const requester = { senderIsOwner: c.owner, senderId: c.owner ? "u-owner" : "u-member" };
    const sent = senderOf(requester, { trigger: "user" }, CFG, c.chat, "message");
    assert.equal(sent.relation, c.relation);
    assert.equal(sent.basis.includes("group_chat"), c.group_chat);
  });
}
