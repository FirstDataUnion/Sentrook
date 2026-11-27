/**
 * Owner commands answer only where the owner alone reads the reply: OpenClaw marks the owner as the owner in a group or
 * channel room too, and writes a command and its reply into that room's transcript, so every owner command refuses
 * there (and in a chat it cannot tell from a room).
 */

import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { OWNER_SUBCOMMANDS } from "./commands.ts";
import { refusal, roomRefusal } from "./owner.ts";

const VERBS = Object.keys(OWNER_SUBCOMMANDS);

/** Registers the plugin against `config` and returns its chat commands and its traffic log. */
async function registered(config: unknown) {
  const { default: plugin } = await import("./index.ts");
  const oc = mkdtempSync(path.join(tmpdir(), "sentrook-owner-room-"));
  mkdirSync(path.join(oc, "sentrook"), { recursive: true });
  const saved = process.env.OPENCLAW_STATE_DIR;
  process.env.OPENCLAW_STATE_DIR = oc;
  const commands: Record<string, any> = {};
  plugin.register({
    pluginConfig: {},
    config,
    registrationMode: "full",
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: () => undefined,
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
  } as any);
  const restore = () => {
    if (saved === undefined) delete process.env.OPENCLAW_STATE_DIR;
    else process.env.OPENCLAW_STATE_DIR = saved;
  };
  const log = () => {
    try {
      return readFileSync(path.join(oc, "sentrook", "traffic.jsonl"), "utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l))
        .filter((r) => r.kind === "command");
    } catch {
      return [];
    }
  };
  return { commands, log, restore };
}

/** The owner on a chat channel: no gateway scopes, marked by the host with senderIsOwner. */
const owner = (extra: Record<string, unknown>) => ({
  senderId: "123",
  channel: "discord",
  senderIsOwner: true,
  assertOwnerCurrent: () => undefined,
  args: "",
  ...extra,
});

const ADMIN = ["operator.read", "operator.write", "operator.admin"];

test("every owner command is registered with the owner check", async () => {
  const h = await registered({});
  try {
    for (const verb of VERBS) {
      const def = h.commands[OWNER_SUBCOMMANDS[verb]!.command];
      assert.ok(def, verb);
      assert.deepEqual(def.requiredScopes, ["operator.admin"], verb);
    }
  } finally {
    h.restore();
  }
});

test("every owner command refuses the owner in a group or channel room and audits it", async () => {
  const h = await registered({});
  try {
    const rooms = [
      { sessionKey: "agent:main:discord:channel:123456" },
      { channel: "telegram", sessionKey: "agent:main:telegram:group:-1001234567890" },
      // A thread or topic in a room is the room.
      { channel: "slack", sessionKey: "agent:main:slack:channel:c123:thread:1700000000.1" },
      { channel: "telegram", sessionKey: "agent:main:telegram:group:-1001234:topic:9" },
      { channel: "discord", sessionKey: "agent:main:discord:channel:1498333845953712258:thread:77", gatewayClientScopes: ADMIN },
      // The room named only by the reply address.
      { channel: "slack", senderId: "U1", sessionKey: "agent:main:main", to: "channel:C123" },
      // A gateway client with the admin scope, in a room's session: the reply still lands in the room's transcript.
      { channel: "webchat", senderId: "", sessionKey: "agent:main:discord:channel:123456", gatewayClientScopes: ADMIN },
    ];
    for (const verb of VERBS) {
      const def = h.commands[OWNER_SUBCOMMANDS[verb]!.command];
      for (const room of rooms) {
        for (const args of ["", "last", "here", "apply 1234 1"]) {
          const reply = String((await def.handler(owner({ ...room, args }))).text);
          assert.equal(reply, roomRefusal(verb), `${verb} ${args} ${JSON.stringify(room)}`);
        }
      }
    }
    const refused = h.log().filter((r) => r.outcome === "refused" && r.reason === "group_chat");
    assert.equal(refused.length, VERBS.length * rooms.length * 4);
    assert.deepEqual(new Set(refused.map((r) => r.verb)), new Set(VERBS));
    assert.equal(h.log().filter((r) => r.outcome === "allowed").length, 0);
    // Nothing was written: no grants, bindings, snooze, notice target or passes.
    const state = path.join(process.env.OPENCLAW_STATE_DIR!, "sentrook");
    for (const f of ["grants.json", "snooze.json", "notify.json", "passes.json", "setup.json"]) {
      assert.equal(existsSync(path.join(state, f)), false, f);
    }
  } finally {
    h.restore();
  }
});

test("with rooms routed into the main session, every owner command refuses the main key and a chat that says nothing", async () => {
  const h = await registered({ session: { groupScope: "main" } });
  try {
    const chats = [
      { channel: "telegram", sessionKey: "agent:main:main" },
      { channel: "telegram" },
      { channel: "slack", senderId: "U1", to: "slack:C123" },
    ];
    for (const verb of VERBS) {
      const def = h.commands[OWNER_SUBCOMMANDS[verb]!.command];
      for (const chat of chats) {
        assert.equal(String((await def.handler(owner(chat))).text), roomRefusal(verb), `${verb} ${JSON.stringify(chat)}`);
      }
    }
    assert.equal(h.log().filter((r) => r.outcome === "refused" && r.reason === "unknown_chat").length, VERBS.length * chats.length);
  } finally {
    h.restore();
  }
});

test("a route binding that sends rooms into the main session refuses the main key too", async () => {
  const h = await registered({ bindings: [{ match: { channel: "discord" }, session: { groupScope: "main" } }] });
  try {
    const def = h.commands["sentrook-history"];
    assert.equal(String((await def.handler(owner({ sessionKey: "agent:main:main" }))).text), roomRefusal("history"));
  } finally {
    h.restore();
  }
});

test("a non-owner in a room gets the owner refusal, not the room one", async () => {
  const h = await registered({});
  try {
    const def = h.commands["sentrook-grants"];
    const reply = String(
      (await def.handler(owner({ sessionKey: "agent:main:discord:channel:1", senderIsOwner: false, assertOwnerCurrent: undefined }))).text,
    );
    assert.equal(reply, refusal("grants"));
    assert.equal(h.log()[0].reason, "not_owner");
  } finally {
    h.restore();
  }
});

test("owner commands still run from the owner's DM, the Control UI and an admin gateway client", async () => {
  const h = await registered({});
  try {
    const places = [
      // The owner's DM by its own key, and under the default dmScope in the agent's main session.
      { channel: "telegram", sessionKey: "agent:main:telegram:direct:123" },
      { channel: "telegram", sessionKey: "agent:main:main" },
      { channel: "discord", sessionKey: "agent:main:main", to: "user:123" },
      // A thread or topic in the owner's DM is the DM, by its own key or in the main session.
      { channel: "telegram", sessionKey: "agent:main:telegram:direct:5150:topic:7" },
      { channel: "slack", sessionKey: "agent:main:slack:direct:u0abc:thread:1731.22" },
      { channel: "slack", sessionKey: "agent:main:main:thread:42" },
      { channel: "telegram", sessionKey: "agent:main:telegram:direct:5150:topic:7", gatewayClientScopes: ADMIN },
      { channel: "slack", sessionKey: "agent:main:slack:direct:u0abc:thread:1731.22", gatewayClientScopes: ADMIN },
      { channel: "webchat", senderId: "", sessionKey: "agent:main:main:thread:42", gatewayClientScopes: ADMIN },
      // The DM of an agent whose id is a room word.
      { channel: "discord", sessionKey: "agent:group:discord:direct:381022" },
      { channel: "telegram", sessionKey: "agent:channel:main" },
      // The Control UI: no sender, the admin scope, the main session or none.
      { channel: "webchat", senderId: "", sessionKey: "agent:main:main", gatewayClientScopes: ADMIN },
      { channel: "webchat", senderId: "", gatewayClientScopes: ADMIN },
      // A gateway client with the admin scope and no channel or session.
      { channel: undefined, senderId: undefined, gatewayClientScopes: ADMIN },
    ];
    for (const verb of VERBS) {
      const def = h.commands[OWNER_SUBCOMMANDS[verb]!.command];
      for (const place of places) {
        const reply = String((await def.handler(owner(place))).text);
        assert.notEqual(reply, roomRefusal(verb), `${verb} ${JSON.stringify(place)}`);
        assert.ok(!reply.startsWith("Only the owner"), `${verb} ${JSON.stringify(place)}: ${reply}`);
      }
    }
    assert.equal(h.log().filter((r) => r.outcome === "refused").length, 0);
    assert.equal(h.log().filter((r) => r.outcome === "allowed").length, VERBS.length * places.length);
  } finally {
    h.restore();
  }
});

test("with rooms routed into the main session, the Control UI on the main key is refused too; its own DM key works", async () => {
  for (const config of [{ session: { groupScope: "main" } }, { bindings: [{ match: { channel: "discord" }, session: { groupScope: "main" } }] }]) {
    const h = await registered(config);
    try {
      const shared = [
        { channel: "webchat", senderId: "", sessionKey: "agent:main:main", gatewayClientScopes: ADMIN },
        // webchat is the operator's own surface, even without the scope list; its transcript is still the rooms'.
        { channel: "webchat", senderId: "", sessionKey: "agent:main:main" },
        { channel: undefined, senderId: undefined, sessionKey: "agent:main:main:thread:42", gatewayClientScopes: ADMIN },
      ];
      const own = [
        { channel: "telegram", sessionKey: "agent:main:telegram:direct:123" },
        { channel: "webchat", senderId: "", sessionKey: "agent:main:dashboard:abc", gatewayClientScopes: ADMIN },
        { channel: "webchat", senderId: "", gatewayClientScopes: ADMIN },
      ];
      for (const verb of VERBS) {
        const def = h.commands[OWNER_SUBCOMMANDS[verb]!.command];
        for (const place of shared) {
          assert.equal(String((await def.handler(owner(place))).text), roomRefusal(verb), `${verb} ${JSON.stringify(place)}`);
        }
        for (const place of own) {
          const reply = String((await def.handler(owner(place))).text);
          assert.notEqual(reply, roomRefusal(verb), `${verb} ${JSON.stringify(place)}`);
          assert.ok(!reply.startsWith("Only the owner"), `${verb} ${JSON.stringify(place)}: ${reply}`);
        }
      }
      const refused = h.log().filter((r) => r.outcome === "refused");
      assert.equal(refused.length, VERBS.length * shared.length);
      assert.ok(refused.every((r) => r.reason === "unknown_chat"));
    } finally {
      h.restore();
    }
  }
});

test("the command line has no chat and runs every owner command", async () => {
  const oc = mkdtempSync(path.join(tmpdir(), "sentrook-owner-room-cli-"));
  for (const verb of VERBS) {
    const reply = await OWNER_SUBCOMMANDS[verb]!.run(
      {
        pluginConfig: {},
        env: { OPENCLAW_STATE_DIR: oc, HOME: oc },
        hostConfig: { session: { groupScope: "main" } },
        openclawDir: oc,
        owner: { by: { basis: ["local_terminal"], channel: null, sender_ref: null }, beforeWrite: () => undefined, record: () => undefined },
      },
      "",
    );
    assert.notEqual(reply, roomRefusal(verb), verb);
    assert.ok(!reply.startsWith("Only the owner"), `${verb}: ${reply}`);
  }
});

test("the room refusal names the owner's DM, the Control UI and the command line", () => {
  const text = roomRefusal("history");
  assert.match(text, /^\/sentrook-history only runs in your own direct message with the agent, in the Control UI \(in a session no group or channel shares\)/);
  assert.match(text, /openclaw sentrook history on the machine/);
  assert.match(text, /a private channel counts too/);
  assert.match(text, /Open a direct message with the agent and send \/sentrook-history there/);
  assert.match(text, /Nothing was shown or changed\.$/);
});
