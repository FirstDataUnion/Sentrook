/**
 * The owner's setup screen (`/sentrook-setup`): items from config, reviews the owner approved and the agent's
 * proposals, described in the plugin's words; `apply` sets them only with the screen's code.
 *
 * The rules, the screen and what applying does are shared with the Hermes plugin's tests (`integrations/fixtures/setup`).
 */

import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { OWNER_SUBCOMMANDS, runSentrookCommand } from "./commands.ts";
import { roomRefusal } from "./owner.ts";
import { resolveConfig } from "./config.ts";
import { deliveryPattern } from "./cronDelivery.ts";
import * as grants from "./grants.ts";
import * as setup from "./setup.ts";
import { readTime, Store } from "./store.ts";

const FIXTURES = path.join(import.meta.dirname, "..", "..", "fixtures", "setup");
const RULES = JSON.parse(readFileSync(path.join(FIXTURES, "rules.json"), "utf8"));
const SCENARIO = path.join(FIXTURES, "scenario");
const META = JSON.parse(readFileSync(path.join(SCENARIO, "scenario.json"), "utf8"));
const APPLY = JSON.parse(readFileSync(path.join(SCENARIO, "apply.json"), "utf8"));
const NOW = new Date(META.now);
const CMD = (sub: string) => `/sentrook-${sub}`;
const BY = { basis: ["local_terminal"], channel: null, sender_ref: null };
const HOST: Record<string, string> = {
  "{setup}": "/sentrook-setup",
  "{revoke}": "/sentrook-revoke",
  "{bind}": "/sentrook-bind",
  "{grants}": "/sentrook-grants",
};
const hostText = (text: string) => Object.entries(HOST).reduce((t, [k, v]) => t.replaceAll(k, v), text);
const noIds = (text: string) => text.replace(/gr-[0-9a-f]{6}/g, "gr-??????");
const read = (file: string) => readFileSync(path.join(SCENARIO, file), "utf8");

// ---- the rules ----------------------------------------------------------------------------------------------------

test("a cron job's delivery to a room is a channel binding", () => {
  for (const [platform, to, pattern] of RULES.delivery) {
    assert.equal(deliveryPattern({ mode: "announce", channel: platform, to }), pattern, `${platform} ${to}`);
    const dir = mkdtempSync(path.join(tmpdir(), "sentrook-setup-"));
    mkdirSync(path.join(dir, "cron"));
    writeFileSync(path.join(dir, "cron", "jobs.json"), JSON.stringify({ jobs: [{ id: "j1", delivery: { mode: "announce", channel: platform, to } }] }));
    assert.deepEqual(setup.cronTargets(dir), pattern ? [["j1", pattern]] : []);
  }
});

test("an OpenClaw job gives no binding for a webhook, the host's own choice, a switched-off job or no store", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-setup-"));
  mkdirSync(path.join(dir, "cron"));
  const jobs = [
    { id: "a", delivery: { mode: "announce", channel: "discord", to: "#one" } },
    { id: "b", delivery: { mode: "webhook", to: "https://hooks.example.com/x" } },
    { id: "c", delivery: { mode: "announce", channel: "last" } },
    { id: "d", enabled: false, delivery: { mode: "announce", channel: "discord", to: "#off" } },
    { id: "", delivery: { mode: "announce", channel: "discord", to: "#no-id" } },
  ];
  writeFileSync(path.join(dir, "cron", "jobs.json"), JSON.stringify({ jobs }));
  assert.deepEqual(setup.cronTargets(dir), [["a", "discord:#one"]]);
  writeFileSync(path.join(dir, "cron", "jobs.json"), "not json");
  assert.deepEqual(setup.cronTargets(dir), []);
  assert.deepEqual(setup.cronTargets(path.join(dir, "missing")), []);
});

test("a grant in force covers an item", () => {
  for (const c of RULES.covers) assert.equal(setup.covers(c.existing, c.candidate), c.covers, `${c.existing.pattern} > ${c.candidate.pattern}`);
});

test("an item warns from its own kind, pattern and allows", () => {
  for (const c of RULES.warnings) {
    assert.deepEqual(setup.itemWarnings({ ...c.item, binding: c.binding ?? false }), c.warnings, c.item.pattern);
  }
});

test("the registrable domain is shown in ASCII", () => {
  for (const [host, domain] of RULES.registrable) assert.equal(setup.registrable(host), domain, host);
});

test("each item is described in the plugin's words", () => {
  for (const c of RULES.describe) assert.equal(setup.describe({ ...c.item, binding: c.binding ?? false }, c.minutes), c.text);
});

test("the last approved review is counted in days", () => {
  for (const [now, last, text] of RULES.last) assert.equal(setup.lastText(new Date(now), new Date(last)), text);
});

test("the agent's note turns no link, mention or emphasis on", () => {
  for (const [reason, line] of RULES.notes) assert.equal(setup.noteLine(reason), line, reason);
});

test("MCP servers are listed by name in code point order", () => {
  assert.deepEqual(
    setup.mcpProviders(RULES.mcp_order.servers).map(([name]) => name),
    RULES.mcp_order.names,
  );
});

test("a covering grant is named safely", () => {
  for (const [gid, label] of RULES.grant_labels) assert.equal(setup.grantLabel(gid), label, JSON.stringify(gid));
});

test("text from config can never end its code span or add lines", () => {
  // An MCP server entry the agent wrote with a newline, a backtick or a space is left out and counted.
  const screen = scene().run("");
  assert.ok(!screen.includes("99.") && !screen.includes("apply 0000") && !screen.includes("ex ample"), screen);
  assert.ok(screen.includes("From your config: 3 items could not be read and are left out."));
  for (const line of screen.split("\n")) assert.equal((line.match(/`/g) ?? []).length % 2, 0, line);
});

test("a covering grant's id is neutralised", () => {
  const s = scene();
  const raw = JSON.parse(readFileSync(path.join(s.state, "grants.json"), "utf8"));
  raw.grants[0].id = "[gr](https://evil.example) @here";
  writeFileSync(path.join(s.state, "grants.json"), JSON.stringify(raw));
  assert.ok(s.run("").includes("Warning: a grant in force already covers this (`grhttps://evil.examp`)."));
});

test("a proposal dated in the future is not live", () => {
  const s = scene();
  assert.ok(!setup.loadProposals(s.state, NOW)!.some((p) => p.id === "p-f00000"));
  // No item of the screen is that proposal's: matched as a whole item line, not as a substring.
  assert.doesNotMatch(s.run(""), /^\d+\. Send data to `future\.example\.com`, /m);
});

test("exposure flagged by the scanner", () => {
  for (const c of RULES.exposure) assert.equal(setup.exposureFlagged(c.response), c.flagged, JSON.stringify(c.response));
});

// ---- the scenario -------------------------------------------------------------------------------------------------

function scene() {
  const oc = mkdtempSync(path.join(tmpdir(), "sentrook-setup-"));
  const state = path.join(oc, "sentrook");
  mkdirSync(state, { recursive: true });
  mkdirSync(path.join(oc, "cron"));
  copyFileSync(path.join(SCENARIO, "openclaw-jobs.json"), path.join(oc, "cron", "jobs.json"));
  for (const f of ["grants.json", "proposals.json", "traffic.jsonl"]) copyFileSync(path.join(SCENARIO, f), path.join(state, f));
  const hostConfig = { mcp: { servers: JSON.parse(read("mcp-servers.json")) } };
  const records: Array<Record<string, unknown>> = [];
  const cfg = (log = true) =>
    resolveConfig({ reviewAt: META.review_at, trafficLog: { enabled: log } }, { OPENCLAW_STATE_DIR: oc, HOME: oc });
  const run = (args: string, minutes = 0, log = true) =>
    setup.run(cfg(log), args, BY, new Date(NOW.getTime() + minutes * 60_000), CMD, (r) => records.push(r), () => undefined, {
      openclawDir: oc,
      hostConfig,
      code: () => META.code,
    });
  return { oc, state, records, run, cfg };
}

test("the screen lists config, approved reviews and proposals", () => {
  assert.equal(scene().run(""), hostText(read("screen.txt").replace(/\n$/, "")));
});

test("with the log off there is no evidence", () => {
  assert.equal(scene().run("", 0, false), hostText(read("screen-log-off.txt").replace(/\n$/, "")));
});

const projection = (e: Record<string, any>) =>
  Object.fromEntries(["kind", "pattern", "allows", "scope", "expires_at", "source"].filter((k) => k in e).map((k) => [k, e[k]]));

for (const c of APPLY.cases) {
  test(`apply and discard: ${c.name}`, () => {
    const s = scene();
    const before = JSON.parse(read("grants.json"));
    s.run("");
    for (const step of c.steps) {
      const reply = s.run(step.args, step.minutes_later ?? 0);
      if ("items" in step) assert.ok(reply.startsWith(`Sentrook setup: ${step.items} item${step.items === 1 ? "" : "s"}.`), reply);
      else assert.equal(noIds(reply), hostText(step.reply));
    }
    const after = JSON.parse(readFileSync(path.join(s.state, "grants.json"), "utf8"));
    const oldIds = new Set(before.grants.map((g: any) => g.id));
    const added = after.grants.filter((g: any) => !oldIds.has(g.id));
    assert.deepEqual(added.map(projection), c.grants_added);
    for (const g of added) {
      assert.deepEqual(g.set_by, BY);
      const at = readTime(g.granted_at)!.getTime();
      assert.ok(at >= NOW.getTime() && at <= NOW.getTime() + 15 * 60_000);
      assert.match(g.id, /^gr-[0-9a-f]{6}$/);
    }
    const newBindings = after.bindings.slice(before.bindings.length);
    assert.deepEqual(
      newBindings.map((b: any) => ({ pattern: b.pattern, source: b.source })),
      c.bindings_added,
    );
    for (const b of newBindings) assert.deepEqual(b.set_by, BY);
    const live = (setup.loadProposals(s.state, NOW) ?? []).map((p) => p.id);
    const raw = new Store(s.state).loadProposals()!;
    const left = Object.fromEntries(
      raw.proposals.filter((p: any) => live.includes(p.id)).map((p: any) => [p.id, p.items.length]),
    );
    assert.deepEqual(left, c.proposals_left);
  });
}

test("applied grants are persistent and listed by grants", () => {
  const s = scene();
  s.run("");
  s.run("apply 4821 3,4");
  const cfg = s.cfg();
  const listing = grants.formatGrants(cfg, grants.load(cfg.stateDir), NOW, CMD, null);
  assert.match(listing, /^gr-[0-9a-f]{6}\s+destination\s+persistent\s+api\.example\.com\s/m);
  assert.match(listing, /^gr-[0-9a-f]{6}\s+destination\s+persistent\s+files\.example\.org\s/m);
});

test("applying the same item twice changes nothing", () => {
  const s = scene();
  s.run("");
  s.run("apply 4821 1,3");
  const first = readFileSync(path.join(s.state, "grants.json"), "utf8");
  const screen = s.run("");
  assert.doesNotMatch(screen, /^\d+\. Send messages to the channel `discord:#daily-brief`, /m);
  assert.doesNotMatch(screen, /^\d+\. Send data to `api\.example\.com`, /m);
  const store = new Store(s.state);
  const kept = store.loadSetup();
  kept.items = [
    { binding: true, kind: "destination", pattern: "discord:#daily-brief", allows: null, minutes: null, tags: ["config"], proposals: [] },
    { binding: false, kind: "destination", pattern: "api.example.com", allows: null, minutes: null, tags: ["reviews"], proposals: [] },
  ];
  store.saveSetup(kept);
  const reply = s.run("apply 4821");
  assert.ok(reply.includes("1. Already set: channel `discord:#daily-brief`."), reply);
  assert.match(reply, /2\. Already set: destination `api\.example\.com` \(gr-[0-9a-f]{6}\)\./);
  assert.equal(readFileSync(path.join(s.state, "grants.json"), "utf8"), first);
});

test("apply writes each change and the apply to the traffic log", () => {
  const s = scene();
  s.run("");
  s.run("apply 4821 1,3");
  assert.deepEqual(
    s.records.map((r) => [r.kind, r.op]),
    [
      ["grants", "bind_add"],
      ["grants", "grant"],
      ["setup", "apply"],
    ],
  );
  for (const r of s.records) assert.deepEqual(r.by, BY);
  assert.deepEqual(s.records.at(-1)!.items, [1, 3]);
});

test("nine unapproved reviews give no evidence", () => {
  const s = scene();
  const cfg = s.cfg();
  const ev = setup.readEvidence(cfg.trafficLog.path, cfg.reviewAt, NOW);
  const counted = Object.fromEntries([...ev.approved.values()].map((e) => [e.grant.pattern, e.count]));
  assert.deepEqual(counted, { "api.example.com": 3, "files.example.org": 2 });
  assert.deepEqual([...ev.exposed], ["s_0000000000a4"]);
  assert.deepEqual(
    setup.approvedSuggestions(ev).map((e) => e.grant.pattern),
    ["api.example.com", "files.example.org"],
  );
});

test("a broader pattern never inherits the count", () => {
  const cfg = scene().cfg();
  const ev = setup.readEvidence(cfg.trafficLog.path, cfg.reviewAt, NOW);
  assert.equal(ev.backing({ kind: "destination", pattern: "files.example.org" })?.count, 2);
  assert.equal(ev.backing({ kind: "destination", pattern: "*.example.org" }), null);
  assert.equal(ev.backing({ kind: "destination", pattern: "*.example.com" }), null);
});

test("no attended item ever appears", () => {
  const screen = scene().run("").toLowerCase();
  assert.ok(!screen.includes("attended") && !screen.includes("telegram"));
});

test("nothing to set up", () => {
  const oc = mkdtempSync(path.join(tmpdir(), "sentrook-setup-"));
  const cfg = resolveConfig({}, { OPENCLAW_STATE_DIR: oc });
  const src = { openclawDir: oc, hostConfig: {} };
  assert.equal(setup.run(cfg, "", BY, NOW, CMD, () => undefined, () => undefined, src), "Sentrook setup: nothing to set up right now.");
  assert.equal(new Store(cfg.stateDir).loadSetup().code, null);
  assert.ok(setup.run(cfg, "apply 0000", BY, NOW, CMD, () => undefined, () => undefined, src).startsWith("That is not the code on the setup screen"));
});

test("each screen has a new code", () => {
  const s = scene();
  const cfg = s.cfg();
  const codes = new Set<string>();
  for (let i = 0; i < 5; i++) {
    const reply = setup.run(cfg, "", BY, NOW, CMD, () => undefined, () => undefined, { openclawDir: s.oc, hostConfig: {} });
    codes.add(/apply ([0-9]{4})\n/.exec(reply)![1]!);
    assert.ok(codes.has(new Store(cfg.stateDir).loadSetup().code));
  }
  assert.ok(codes.size > 1);
});

test("an unreadable proposals file is said", () => {
  const s = scene();
  writeFileSync(path.join(s.state, "proposals.json"), "[1, 2");
  const screen = s.run("");
  assert.ok(screen.includes("The agent's proposals could not be read, so none are shown."));
  assert.ok(!screen.includes("p-a1b2c3"));
});

test("a proposal lasts a day at most", () => {
  const s = scene();
  const raw = JSON.parse(readFileSync(path.join(s.state, "proposals.json"), "utf8"));
  for (const p of raw.proposals) p.expires_at = "2027-01-01T00:00:00Z";
  writeFileSync(path.join(s.state, "proposals.json"), JSON.stringify(raw));
  const later = new Date(NOW.getTime() + (22 * 60 + 30) * 60_000);
  assert.deepEqual(
    setup.loadProposals(s.state, later)!.map((p) => p.id),
    ["p-d4e5f6", "p-b0b0b0"],
  );
});

test("a write after the owner lost authority stops before anything changes", () => {
  const s = scene();
  s.run("");
  const before = readFileSync(path.join(s.state, "grants.json"), "utf8");
  assert.throws(
    () =>
      setup.run(s.cfg(), "apply 4821", BY, NOW, CMD, () => undefined, () => {
        throw new Error("stale_owner");
      }, { openclawDir: s.oc, hostConfig: {} }),
    /stale_owner/,
  );
  assert.equal(readFileSync(path.join(s.state, "grants.json"), "utf8"), before);
  assert.equal(new Store(s.state).loadSetup().code, META.code);
});

// ---- the command --------------------------------------------------------------------------------------------------

test("setup is an owner command, refused without the owner, on chat and the command line", async () => {
  const o = OWNER_SUBCOMMANDS.setup!;
  assert.equal(o.command, "sentrook-setup");
  assert.equal(o.cliRest, true);
  assert.match(await o.run({ pluginConfig: {}, env: {} }, ""), /^Only the owner can run \/sentrook setup/);
  assert.match(await o.run({ pluginConfig: {}, env: {} }, "apply 4821"), /^Only the owner can run \/sentrook setup/);
  assert.match(await runSentrookCommand("setup", { pluginConfig: {}, env: {} }), /owner only: use \/sentrook-setup/);
  const s = scene();
  const records: unknown[] = [];
  const ctx = {
    pluginConfig: { reviewAt: 45 },
    env: { OPENCLAW_STATE_DIR: s.oc, HOME: s.oc },
    owner: { by: BY, beforeWrite: () => undefined, record: (r: unknown) => records.push(r) },
    hostConfig: {},
    openclawDir: s.oc,
  };
  const reply = await o.run(ctx, "");
  assert.ok(reply.startsWith("Sentrook setup: "), reply);
  const code = /\/sentrook-setup apply ([0-9]{4})\n/.exec(reply)![1];
  const applied = await o.run(ctx, `apply ${code} 1`);
  assert.equal(applied.split("\n")[1], "1. Channel binding added: `discord:#daily-brief` (until you remove it).");
});

test("the registered /sentrook-setup reads OpenClaw's MCP servers and job store, and runs from the owner's own DM", async () => {
  const { default: plugin } = await import("./index.ts");
  const s = scene();
  const saved = { OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR, HOME: process.env.HOME };
  process.env.OPENCLAW_STATE_DIR = s.oc;
  try {
    const commands: Record<string, any> = {};
    plugin.register({
      pluginConfig: { reviewAt: 45 },
      config: { mcp: { servers: JSON.parse(read("mcp-servers.json")) } },
      registrationMode: "full",
      logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
      on: () => undefined,
      registerCommand: (def: any) => {
        commands[def.name] = def;
      },
    } as any);
    const def = commands["sentrook-setup"];
    assert.deepEqual(def.requiredScopes, ["operator.admin"]);
    // A chat sender holds no gateway scopes; the host marks the owner's own DM with senderIsOwner.
    // Under OpenClaw's default `session.dmScope: "main"`, the owner's DM runs in the agent's main session.
    const dm = (args: string) => ({
      senderId: "123",
      channel: "telegram",
      sessionKey: "agent:main:main",
      senderIsOwner: true,
      assertOwnerCurrent: () => undefined,
      args,
    });
    const screen = String((await def.handler(dm(""))).text);
    assert.ok(screen.includes("1. Send messages to the channel `discord:#daily-brief`"), screen);
    assert.ok(screen.includes("From your config: MCP server `notes`."), screen);
    const code = /\/sentrook-setup apply ([0-9]{4})\n/.exec(screen)![1];
    const reply = String((await def.handler(dm(`apply ${code} 2`))).text);
    assert.match(reply, /^2\. Granted gr-[0-9a-f]{6}: provider `npm:@example\/notes-mcp` \(persistent, expires /m);
    const added = JSON.parse(readFileSync(path.join(s.state, "grants.json"), "utf8")).grants.at(-1);
    assert.deepEqual(added.set_by.basis, ["sender_is_owner"]);
    assert.equal(added.set_by.channel, "telegram");
    const refused = String((await def.handler({ ...dm(`apply ${code} 1`), senderIsOwner: false })).text);
    assert.match(refused, /^Only the owner can run \/sentrook setup/);
    // OpenClaw marks the owner as the owner in a group room too: the list, and applying it, stay out of the room.
    const before = readFileSync(path.join(s.state, "grants.json"), "utf8");
    for (const sessionKey of ["agent:main:telegram:group:-1001234567890", "agent:main:discord:channel:123456"]) {
      for (const args of ["", `apply ${code} 1`]) {
        const reply = String((await def.handler({ ...dm(args), sessionKey })).text);
        assert.equal(reply, roomRefusal("setup"));
      }
    }
    assert.equal(readFileSync(path.join(s.state, "grants.json"), "utf8"), before);
    const log = readFileSync(path.join(s.state, "traffic.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(log.filter((r) => r.kind === "command" && r.verb === "setup" && r.reason === "group_chat").length, 4);
    // The owner's own DM names itself as one.
    assert.ok(String((await def.handler({ ...dm(""), sessionKey: "agent:main:telegram:direct:123" })).text).startsWith("Sentrook setup: "));
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test("/sentrook-setup refuses a chat it cannot tell from a room; the Control UI and the command line still work", async () => {
  const { default: plugin } = await import("./index.ts");
  const s = scene();
  const saved = { OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR };
  process.env.OPENCLAW_STATE_DIR = s.oc;
  try {
    const commands: Record<string, any> = {};
    // Rooms routed into the agent's main session: the main key no longer says a DM.
    plugin.register({
      pluginConfig: { reviewAt: 45 },
      config: { session: { groupScope: "main" } },
      registrationMode: "full",
      logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
      on: () => undefined,
      registerCommand: (def: any) => {
        commands[def.name] = def;
      },
    } as any);
    const def = commands["sentrook-setup"];
    const owner = { senderIsOwner: true, assertOwnerCurrent: () => undefined, args: "" };
    const text = async (ctx: Record<string, unknown>) => String((await def.handler({ ...owner, ...ctx })).text);
    // A group message on the main key, a chat channel with no session key, a reply address that names no person.
    for (const ctx of [
      { senderId: "123", channel: "telegram", sessionKey: "agent:main:main" },
      { senderId: "123", channel: "telegram" },
      { senderId: "U1", channel: "slack", to: "slack:C123" },
    ]) {
      assert.equal(await text(ctx), roomRefusal("setup"), JSON.stringify(ctx));
    }
    // The owner's own DM, by its own key; the Control UI on the main key (no sender, the admin scope).
    assert.ok((await text({ senderId: "123", channel: "telegram", sessionKey: "agent:main:telegram:direct:123" })).startsWith("Sentrook setup: "));
    const ui = { senderId: "", channel: "webchat", sessionKey: "agent:main:main", gatewayClientScopes: ["operator.read", "operator.write", "operator.admin"] };
    assert.ok((await text(ui)).startsWith("Sentrook setup: "));
    assert.ok((await text({ ...ui, gatewayClientScopes: undefined })).startsWith("Sentrook setup: "), "webchat is the operator's own surface");
    const log = readFileSync(path.join(s.state, "traffic.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(log.filter((r) => r.kind === "command" && r.verb === "setup" && r.reason === "unknown_chat").length, 3);
    // The command line has no chat: it is the machine's owner.
    const o = OWNER_SUBCOMMANDS.setup!;
    const cli = await o.run(
      {
        pluginConfig: { reviewAt: 45 },
        env: { OPENCLAW_STATE_DIR: s.oc },
        owner: { by: BY, beforeWrite: () => undefined, record: () => undefined },
        hostConfig: { session: { groupScope: "main" } },
        openclawDir: s.oc,
      },
      "",
    );
    assert.ok(cli.startsWith("Sentrook setup: "), cli);
  } finally {
    if (saved.OPENCLAW_STATE_DIR === undefined) delete process.env.OPENCLAW_STATE_DIR;
    else process.env.OPENCLAW_STATE_DIR = saved.OPENCLAW_STATE_DIR;
  }
});
