/**
 * Trusted users and trusted chats (trust.ts).
 *
 * A member of a chat the owner trusts, or a person the owner trusts, is sent as `trusted`, not as a stranger
 * (`other`), and never as the owner. Trust is set only by the owner, where the other owner commands run (never in a
 * group or channel room). Reviews in a trusted chat are answered as OpenClaw allows there; a chat trusted with
 * `--owner-only` holds them for the owner instead. A trusted turn never sets a grant when its review is approved.
 */

import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import { resolveConfig } from "./config.ts";
import * as hold from "./hold.ts";
import { roomRefusal } from "./owner.ts";
import plugin from "./index.ts";
import { senderOf } from "./planir.ts";
import * as setup from "./setup.ts";
import { fromConfig, parseRef } from "./trust.ts";

const CHAT = "4242424242";
const ROOM = `agent:main:discord:channel:${CHAT}`;
const TRUSTED_MEMBER = { relation: "trusted", basis: ["plugin_allowlist:chat", "group_chat"] };
const OTHER_IN_GROUP = { relation: "other", basis: ["group_chat"] };
const OWNER_IN_GROUP = { relation: "owner", basis: ["group_chat"] };
const HINT = { kind: "destination", pattern: "api.example-notes.test", risk: 10, relieves: [] };

// ---- who sent the turn --------------------------------------------------------------------------------------------

const member = { senderIsOwner: false, senderId: "u-member", channel: "discord" };
const place = (id = CHAT, platform = "discord") => ({ platform, chat: { platform, id } });
const cfgWith = (chats: string[], senders: string[] = []) => ({
  trustedSenders: senders,
  trustedRoles: [],
  trustedChats: chats.map((chat) => ({ chat, ownerOnly: false })),
});

test("a member of a trusted chat is trusted, not other", () => {
  const cfg = cfgWith([`discord:${CHAT}`]);
  assert.deepEqual(senderOf(member, {}, cfg, "group", "message", place()), TRUSTED_MEMBER);
  // without trust, or in another chat, the same member stays a stranger
  assert.deepEqual(senderOf(member, {}, cfgWith([]), "group", "message", place()), OTHER_IN_GROUP);
  assert.deepEqual(senderOf(member, {}, cfg, "group", "message", place("777")), OTHER_IN_GROUP);
  // the same id on another platform is another chat
  assert.deepEqual(senderOf({ ...member, channel: "slack" }, {}, cfg, "group", "message", place(CHAT, "slack")), OTHER_IN_GROUP);
});

test("a thread or topic in a trusted chat is covered by its chat", async () => {
  const { groupChatOfKey } = await import("./planir.ts");
  assert.deepEqual(groupChatOfKey(`${ROOM}:thread:77`, {}), { platform: "discord", id: CHAT });
  assert.deepEqual(groupChatOfKey("agent:main:telegram:group:-1001234:topic:9", {}), { platform: "telegram", id: "-1001234" });
  assert.deepEqual(groupChatOfKey("agent:main:slack:work:channel:c0general", {}), { platform: "slack", id: "c0general" });
  // a direct chat and the main session name no room, so neither can ever match a trusted chat
  for (const key of [
    "agent:main:discord:direct:8111222333",
    "agent:main:telegram:dm:42",
    "agent:main:slack:direct:u0abc:thread:1731.22",
    "agent:main:main",
    "agent:main:main:thread:42",
  ]) {
    assert.equal(groupChatOfKey(key, {}), null, key);
    assert.equal(groupChatOfKey(key, { session: { groupScope: "main" } }), null, key);
  }
});

test("the owner in a trusted chat stays the owner", () => {
  const owner = { senderIsOwner: true, senderId: "u-owner", channel: "discord" };
  assert.deepEqual(senderOf(owner, {}, cfgWith([`discord:${CHAT}`]), "group", "message", place()), OWNER_IN_GROUP);
});

test("a trusted user is trusted in any chat, by platform and id or a bare id, but never the owner", () => {
  for (const senders of [["discord:u-member"], ["u-member"], ["DISCORD:U-MEMBER"]]) {
    const cfg = cfgWith([], senders);
    assert.deepEqual(senderOf(member, {}, cfg, "group", "message", place()), {
      relation: "trusted",
      basis: ["plugin_allowlist:sender", "group_chat"],
    }, senders[0]);
    assert.deepEqual(senderOf(member, {}, cfg, "direct", "message", { platform: "discord" }), {
      relation: "trusted",
      basis: ["plugin_allowlist:sender"],
    });
  }
  // the same id on another platform is someone else
  assert.equal(senderOf({ ...member, channel: "slack" }, {}, cfgWith([], ["discord:u-member"]), "group", "message", place(CHAT, "slack")).relation, "other");
});

test("a direct chat is never a trusted chat", () => {
  const cfg = cfgWith(["discord:d-1"]);
  assert.deepEqual(senderOf(member, {}, cfg, "direct", "message", place("d-1")), { relation: "other", basis: ["none"] });
});

test("a ref names a chat platform and an id", () => {
  for (const raw of ["discord", "discord:", "cron:123", "nope:1", "webchat:1", "discord:has space", "discord:a\x07b", 7, null]) {
    assert.equal(parseRef(raw), null, String(raw));
  }
  assert.deepEqual(parseRef("Discord:123"), ["discord", "123"]);
  // Matrix room ids keep their colons
  assert.deepEqual(parseRef("matrix:!room:example.test"), ["matrix", "!room:example.test"]);
});

test("trustedChats reads text, a list and { chat, owner_only }, and names what it cannot read", () => {
  const env = { OPENCLAW_STATE_DIR: "/nowhere" };
  const cfg = resolveConfig({ trustedChats: ["discord:1", { chat: "slack:C2", owner_only: true }, "cron:3", { chat: "discord:1", owner_only: true }] }, env);
  assert.deepEqual(cfg.trustedChats, [
    { chat: "discord:1", ownerOnly: true },
    { chat: "slack:C2", ownerOnly: true },
  ]);
  assert.deepEqual(cfg.configProblems, ["trustedChats[2]: not <platform>:<chat id> on a chat platform; ignored"]);
  assert.deepEqual(resolveConfig({}, { ...env, SENTROOK_TRUSTED_CHATS: "discord:1,telegram:-100" }).trustedChats, [
    { chat: "discord:1", ownerOnly: false },
    { chat: "telegram:-100", ownerOnly: false },
  ]);
  assert.deepEqual(resolveConfig({ trustedChats: [{ chat: "discord:1", ownerOnly: true }] }, env).configProblems, [
    "trustedChats[0]: has a field other than chat and owner_only; ignored",
  ]);
  assert.deepEqual([...fromConfig(cfg).chats], [["discord:1", true], ["slack:c2", true]]);
});

// ---- a turn in a group chat, end to end ---------------------------------------------------------------------------

const ENV_KEYS = [
  "OPENCLAW_STATE_DIR",
  "SENTROOK_DEV_ENDPOINTS",
  "SENTROOK_SCAN_URL",
  "SENTROOK_OIDC_ISSUER",
  "SENTROOK_SCAN_CLIENT_ID",
  "SENTROOK_SCAN_CLIENT_SECRET",
  "SENTROOK_MODE",
];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let stateDir = "";
let scans: any[] = [];
let reply: Record<string, unknown> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-trust-"));
  Object.assign(process.env, {
    OPENCLAW_STATE_DIR: dir,
    SENTROOK_DEV_ENDPOINTS: "1",
    SENTROOK_SCAN_URL: "http://scan.test",
    SENTROOK_OIDC_ISSUER: "http://idp.test",
    SENTROOK_SCAN_CLIENT_ID: "client",
    SENTROOK_SCAN_CLIENT_SECRET: "secret-value",
  });
  delete process.env.SENTROOK_MODE;
  stateDir = path.join(dir, "sentrook");
  scans = [];
  // a review-band call the scanner lets the owner pass once
  reply = { risk: 55, owner_pass: "once" };
  clearScanTokenCache();
  globalThis.fetch = (async (input: any, init?: RequestInit) => {
    const url = String(input);
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith("/.well-known/openid-configuration")) return json(200, { token_endpoint: "http://idp.test/oauth/token" });
    if (url.endsWith("/oauth/token")) return json(200, { access_token: "tok", expires_in: 600 });
    if (url === "http://scan.test/scan") {
      const planir = JSON.parse(String(init?.body));
      scans.push(planir);
      return json(200, {
        response_version: "2.0",
        request_id: planir.request_id,
        status: "ok",
        enforced: null,
        tree: { suspicion: { score: 0.5 }, consequence: { score: 0.5 }, confidence: { score: 0.8 } },
        reasons: [{ code: "exfil.network_send", signal: "consequence.reach" }],
        tool_description: { category: "network", template: "Sends data to {E1}" },
        entities: { E1: { kind: "host", display: "api.example-notes.test" } },
        action_fingerprint: "afp1:send|api.example-notes.test",
        approval_fingerprint: "afp1:send|api.example-notes.test",
        grant_hints: [],
        ...reply,
        state: `state-${planir.session.step}`,
      });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  globalThis.fetch = realFetch;
});

/** The owner, in a direct message to the agent on Discord. */
const DM = {
  senderId: "u-owner",
  channel: "discord",
  senderIsOwner: true,
  assertOwnerCurrent: () => undefined,
  sessionKey: "agent:main:discord:direct:u-owner",
  sessionId: "D1",
};

function registered(pluginConfig: Record<string, unknown> = {}, hostConfig: Record<string, unknown> = {}) {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  const sent: any[] = [];
  plugin.register({
    pluginConfig,
    registrationMode: "full",
    config: { tools: { exec: { mode: "full" } }, ...hostConfig },
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
    runtime: {
      channel: {
        outbound: {
          loadAdapter: async (channel: string) => ({
            sendText: async (req: any) => {
              sent.push({ channel, ...req });
              return { ok: true };
            },
          }),
        },
      },
    },
  } as any);
  const fire = async (hook: string, event: any, ctx: any) => {
    let out: any;
    for (const h of on[hook] ?? []) out = await h(event, ctx);
    return out;
  };
  const records = (kind: string) =>
    existsSync(path.join(stateDir, "traffic.jsonl"))
      ? readFileSync(path.join(stateDir, "traffic.jsonl"), "utf8")
          .trim()
          .split("\n")
          .map((l) => JSON.parse(l))
          .filter((r) => r.kind === kind)
      : [];
  /** One call in the room from `who` (the owner or a member), in run `run`. */
  const call = async (id: string, who: "owner" | "member" = "member", run = `r-${who}`, key = ROOM) => {
    const requester = { senderIsOwner: who === "owner", senderId: who === "owner" ? "u-owner" : "u-member", channel: "discord" };
    const ctx = { sessionKey: key, sessionId: "G1", agentId: "main", runId: run, requester };
    await fire("before_prompt_build", { runId: run, prompt: "add the meeting notes to the wiki" }, { ...ctx, trigger: "user", messageProvider: "discord" });
    const out = await fire(
      "before_tool_call",
      { toolName: "exec", toolCallId: id, runId: run, params: { command: "curl -s -X POST https://api.example-notes.test/v1/pages" } },
      ctx,
    );
    await hold.waitForNotices();
    return { out, rec: records("scan").at(-1) };
  };
  const command = async (name: string, args: string, ctx: Record<string, unknown> = DM) =>
    (await commands[name].handler({ ...ctx, args })).text as string;
  return { commands, sent, records, call, command };
}

const stored = () => {
  const file = path.join(stateDir, "trust.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {};
};

test("a call from a trusted chat member is sent as trusted; the same call from an untrusted group stays other", async () => {
  const r = registered({ trustedChats: [`discord:${CHAT}`] });
  await r.call("c1");
  assert.deepEqual(scans.at(-1).trigger.sender, TRUSTED_MEMBER);
  await r.call("c2", "member", "r-2", "agent:main:discord:channel:777");
  assert.deepEqual(scans.at(-1).trigger.sender, OTHER_IN_GROUP);
});

test("a thread in a trusted chat is sent as the chat's", async () => {
  const r = registered({ trustedChats: [`discord:${CHAT}`] });
  await r.call("c1", "member", "r-1", `${ROOM}:thread:77`);
  assert.deepEqual(scans.at(-1).trigger.sender, TRUSTED_MEMBER);
});

test("a chat trusted by command counts too", async () => {
  const r = registered();
  await r.command("sentrook-trust-chat", `add discord:${CHAT} --confirm`);
  await r.call("c1");
  assert.deepEqual(scans.at(-1).trigger.sender, TRUSTED_MEMBER);
});

test("a scan record in a group names the chat and a keyed sender, never the sender's id", async () => {
  const r = registered();
  const { rec } = await r.call("c1");
  assert.equal(rec.group.chat, `discord:${CHAT}`);
  assert.match(rec.group.sender, /^[0-9a-f]{16}$/);
  assert.ok(!JSON.stringify(rec.group).includes("u-member"));
  const { rec: again } = await r.call("c2", "member", "r-2");
  assert.equal(again.group.sender, rec.group.sender);
  const { rec: owner } = await r.call("c3", "owner");
  assert.notEqual(owner.group.sender, rec.group.sender);
});

test("members answer reviews in a trusted chat, and approving one never sets a grant", async () => {
  const r = registered({ trustedChats: [`discord:${CHAT}`] });
  reply = { risk: 55, grant_hints: [HINT] };
  const { out, rec } = await r.call("c1");
  assert.ok(out.requireApproval, JSON.stringify(out));
  // no allow-always: whoever answers is not known to be the owner
  assert.deepEqual(out.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  assert.equal(rec.decision, "review_timed_out");
});

test("an owner-only trusted chat holds a member's review for the owner, who allows it once", async () => {
  const r = registered({ trustedChats: [{ chat: `discord:${CHAT}`, owner_only: true }] });
  await r.command("sentrook-notify", "here");
  const { out, rec } = await r.call("c1");
  assert.deepEqual(out, { block: true, blockReason: hold.HELD_CHAT_TEXT });
  assert.equal(rec.decision, "held");
  assert.deepEqual(scans.at(-1).trigger.sender, TRUSTED_MEMBER);
  const [entry] = JSON.parse(readFileSync(path.join(stateDir, "holds.json"), "utf8")).holds;
  assert.equal(entry.where, `trusted discord chat, session ${rec.session_ref}`);
  assert.ok(!entry.where.includes(CHAT));
  // the notice goes to the owner's direct message, not the room
  assert.equal(r.sent.length, 1);
  assert.equal(r.sent[0].to, "user:u-owner");
  // the owner allows it from their direct message; the same call then runs once
  const answer = await r.command("sentrook-allow", rec.hold.id);
  assert.ok(!/only runs in|Only the owner/.test(answer), answer);
  const { out: next, rec: after } = await r.call("c1", "member", "r-2");
  assert.equal(next, undefined);
  assert.equal(after.decision, "allowed_by_pass");
  const { out: third } = await r.call("c1", "member", "r-3");
  assert.equal(third.blockReason, hold.HELD_CHAT_TEXT);
});

test("a trusted chat cannot lower a floor: the scanner's block stays a block", async () => {
  for (const chat of [`discord:${CHAT}`, { chat: `discord:${CHAT}`, owner_only: true }]) {
    const r = registered({ trustedChats: [chat] });
    reply = {
      risk: 90,
      enforced: "block",
      floors_applied: [{ floor: "send.secret_off_host", min_risk: 0.9, subject: "E1" }],
    };
    const { out, rec } = await r.call("c1");
    assert.deepEqual(scans.at(-1).trigger.sender, TRUSTED_MEMBER);
    assert.equal(out?.block, true, JSON.stringify(out));
    assert.notEqual(out.blockReason, hold.HELD_CHAT_TEXT);
    assert.equal(rec.decision, "blocked");
  }
});

test("the owner's own turn in an owner-only chat still asks", async () => {
  const r = registered({ trustedChats: [{ chat: `discord:${CHAT}`, owner_only: true }] });
  const { out } = await r.call("c1", "owner");
  assert.ok(out.requireApproval, JSON.stringify(out));
});

// ---- only the owner sets trust, from their own chat -----------------------------------------------------------------

test("adding a chat warns first and needs --confirm; it is logged by platform only", async () => {
  const r = registered();
  const warn = await r.command("sentrook-trust-chat", `add discord:${CHAT}`);
  assert.ok(warn.startsWith("Warning: Everyone who can post there"), warn);
  assert.match(warn, /channels\.discord\.execApprovals\.approvers or commands\.ownerAllowFrom/);
  assert.ok(warn.endsWith(`/sentrook-trust-chat add discord:${CHAT} --confirm`), warn);
  assert.equal(stored().trusted_chats, undefined);
  const done = await r.command("sentrook-trust-chat", `add discord:${CHAT} --confirm`);
  assert.ok(done.startsWith(`Trusted discord:${CHAT}`), done);
  assert.ok(done.endsWith(`To undo: /sentrook-trust-chat remove discord:${CHAT}.`), done);
  const [entry] = stored().trusted_chats;
  assert.equal(entry.chat, `discord:${CHAT}`);
  assert.equal(entry.owner_only, false);
  assert.deepEqual(entry.set_by.basis, ["sender_is_owner"]);
  const [rec] = r.records("settings");
  assert.equal(rec.op, "trust_chat_add");
  assert.equal(rec.platform, "discord");
  assert.ok(!JSON.stringify(rec).includes(CHAT));
  assert.ok((await r.command("sentrook-trust-chat", "list")).includes(`- discord:${CHAT}`));
  assert.match(await r.command("sentrook-trust-chat", `add discord:${CHAT} --confirm`), /already trusted/);
});

test("an owner-only chat says its reviews are held", async () => {
  const r = registered();
  assert.match(await r.command("sentrook-trust-chat", `add discord:${CHAT} --owner-only`), /hold its reviews for you/);
  await r.command("sentrook-trust-chat", `add discord:${CHAT} --owner-only --confirm`);
  assert.equal(stored().trusted_chats[0].owner_only, true);
  assert.match(await r.command("sentrook-trust-chat", "list"), /\(reviews held for you\)/);
});

test("a platform open to any group gets a louder warning", async () => {
  const r = registered({}, { channels: { discord: { groupPolicy: "open" } } });
  assert.match(await r.command("sentrook-trust-chat", `add discord:${CHAT}`), /OpenClaw answers any group on discord/);
});

test("removing a chat, and one set in config", async () => {
  const r = registered({ trustedChats: ["discord:c-config"] });
  await r.command("sentrook-trust-chat", `add discord:${CHAT} --confirm`);
  assert.ok((await r.command("sentrook-trust-chat", `remove discord:${CHAT}`)).startsWith(`Removed discord:${CHAT}`));
  assert.deepEqual(stored().trusted_chats, []);
  assert.match(await r.command("sentrook-trust-chat", "remove discord:c-config"), /remove it there/);
  assert.match(await r.command("sentrook-trust-chat", `remove discord:${CHAT}`), /was not trusted by command/);
});

test("a trusted user is added the same way", async () => {
  const r = registered();
  assert.ok((await r.command("sentrook-trust-user", "add discord:u-friend")).startsWith("Warning: messages from discord:u-friend"));
  await r.command("sentrook-trust-user", "add discord:u-friend --confirm");
  assert.equal(stored().trusted_senders[0].user, "discord:u-friend");
  assert.match(await r.command("sentrook-trust-user", "add discord:u-friend --owner-only"), /Unknown option --owner-only/);
  assert.match(await r.command("sentrook-trust-user", "list"), /- discord:u-friend/);
});

test("a bad ref changes nothing", async () => {
  const r = registered();
  for (const args of ["add discord", "add cron:1 --confirm", "add", "frob discord:1"]) {
    const out = await r.command("sentrook-trust-chat", args);
    assert.ok(out.includes("usage") || out.includes("is not a chat"), out);
  }
  assert.equal(stored().trusted_chats, undefined);
});

test("a direct chat listed as trusted never makes its sender trusted", async () => {
  const r = registered({ trustedChats: ["discord:u-member", "discord:8111222333"] });
  await r.call("c1", "member", "r-1", "agent:main:discord:direct:8111222333");
  assert.equal(scans.at(-1).trigger.sender.relation, "other");
  assert.ok(!scans.at(-1).trigger.sender.basis.includes("plugin_allowlist:chat"));
  const { rec } = await r.call("c2", "member", "r-2", "agent:main:discord:direct:8111222333");
  assert.equal(rec.group, undefined);
});

test("the owner's own direct chat cannot be trusted as a chat", async () => {
  const r = registered();
  const out = await r.command("sentrook-trust-chat", "add discord:u-owner --confirm");
  assert.ok(out.startsWith("This is your direct chat with the agent"), out);
  assert.equal(stored().trusted_chats, undefined);
});

test("trust cannot be set from a group, by a member or by the owner there", async () => {
  // a group member asks the agent (or runs the command) to trust them or the chat
  const r = registered();
  for (const [name, ref] of [
    ["sentrook-trust-chat", `discord:${CHAT}`],
    ["sentrook-trust-user", "discord:u-member"],
  ] as const) {
    const inRoom = { ...DM, sessionKey: ROOM };
    assert.equal(await r.command(name, `add ${ref} --confirm`, inRoom), roomRefusal(name.replace("sentrook-", "")));
    const byMember = { ...inRoom, senderId: "u-member", senderIsOwner: false };
    assert.match(await r.command(name, `add ${ref} --confirm`, byMember), /^Only the owner can run/);
  }
  assert.deepEqual(stored(), {});
});

// ---- the setup screen --------------------------------------------------------------------------------------------

test("a trusted chat the agent proposed is shown with its warning and set from the screen", () => {
  const oc = mkdtempSync(path.join(tmpdir(), "sentrook-trust-setup-"));
  const state = path.join(oc, "sentrook");
  mkdirSync(state, { recursive: true });
  const now = new Date("2026-11-24T12:00:00Z");
  writeFileSync(
    path.join(state, "proposals.json"),
    JSON.stringify({
      version: 1,
      proposals: [
        {
          id: "p-aaaaaa",
          session_ref: "s_000000000001",
          created_at: "2026-11-24T11:00:00Z",
          expires_at: "2026-11-25T11:00:00Z",
          items: [{ trusted_chat: `discord:${CHAT}`, owner_only: true, reason: "The team server" }],
        },
      ],
    }),
  );
  writeFileSync(path.join(state, "traffic.jsonl"), "");
  const cfg = resolveConfig({ trafficLog: { enabled: true } }, { OPENCLAW_STATE_DIR: oc, HOME: oc });
  const records: any[] = [];
  const by = { basis: ["local_terminal"], channel: null, sender_ref: null };
  const run = (args: string) =>
    setup.run(cfg, args, by, now, (s) => `/sentrook-${s}`, (rec) => records.push(rec), () => undefined, {
      openclawDir: oc,
      hostConfig: {},
      code: () => "4821",
    });
  const screen = run("");
  assert.ok(screen.includes(`Trust the chat \`discord:${CHAT}\``), screen);
  assert.ok(screen.includes("its reviews are held for you"), screen);
  assert.ok(screen.includes("Sentrook has not seen the agent used in this chat lately."), screen);
  assert.ok(screen.includes("Warning: everyone who can post in this chat"), screen);
  const out = run("apply 4821");
  assert.ok(out.includes(`Trusted discord:${CHAT}`), out);
  const [entry] = JSON.parse(readFileSync(path.join(state, "trust.json"), "utf8")).trusted_chats;
  assert.deepEqual([entry.chat, entry.owner_only], [`discord:${CHAT}`, true]);
  const rec = records.find((x) => x.kind === "settings");
  assert.equal(rec.op, "trust_chat_add");
  assert.deepEqual(rec.source, ["p-aaaaaa"]);
  // once trusted, the screen no longer lists it
  assert.ok(!run("").includes(`Trust the chat \`discord:${CHAT}\``));
});
