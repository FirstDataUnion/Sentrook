/**
 * Who sent a chat message: the same group facts give the same sender in both plugins. The owner in a group stays
 * the owner, with basis `group_chat`; anyone else there is `other`, unless the owner trusts them or the chat
 * (`trusted`, with the allowlist basis the case names). The cases are shared with the Hermes plugin's
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
    const requester = { senderIsOwner: c.owner, senderId: c.owner ? "u-owner" : "u-member", channel: "discord" };
    // the case's chat: a server channel, or the member's direct chat (never a trusted chat, whatever the list says)
    const chatId = c.chat_id ?? (c.chat === "group" ? "c-ops" : "d-member");
    const chats = [
      ...(c.trusted_chat ? [`discord:${chatId}`] : []),
      ...(c.trusted_chat_id ? [`discord:${c.trusted_chat_id}`] : []),
      ...(c.trusted_server ? [`discord:server:${c.trusted_server}`] : []),
    ];
    const cfg = {
      ...CFG,
      trustedSenders: c.trusted_user ? [`discord:${requester.senderId}`] : [],
      trustedChats: chats.map((chat) => ({ chat, ownerOnly: false })),
    };
    const sent = senderOf(requester, { trigger: "user" }, cfg, c.chat, "message", {
      platform: "discord",
      chat: { platform: "discord", id: chatId },
      server: c.server ?? null,
    });
    assert.equal(sent.relation, c.relation);
    assert.equal(sent.basis.includes("group_chat"), c.group_chat);
    if (c.allowlist) assert.equal(sent.basis[0], c.allowlist);
    else assert.ok(!sent.basis.some((b: string) => b.startsWith("plugin_allowlist:")), sent.basis.join(","));
  });
}
