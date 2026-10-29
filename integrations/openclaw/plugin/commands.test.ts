import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { helpText, runSentrookCommand, SUBCOMMANDS } from "./commands.ts";
import plugin from "./index.ts";
import { PLUGIN_VERSION } from "./planir.ts";

const ID = "client-id-value-7f3a";
const SECRET = "client-secret-value-9c1e";

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_SCAN_CLIENT_ID", "SENTROOK_SCAN_CLIENT_SECRET", "SENTROOK_MODE"];
const savedEnv: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OPENCLAW_STATE_DIR = mkdtempSync(path.join(tmpdir(), "sentrook-cmd-"));
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

const stateDir = () => process.env.OPENCLAW_STATE_DIR!;

test("status shows the config-derived facts", async () => {
  const text = await runSentrookCommand("status", {
    pluginConfig: {
      mode: "observe",
      reviewAt: 50,
      blockAt: 90,
      onScanError: "review",
      trafficLog: { enabled: false },
      grants: [{ kind: "destination", pattern: "a.example" }, { kind: "file", pattern: "/tmp/*" }],
      channelBindings: ["chat:ops"],
    },
    env: { OPENCLAW_STATE_DIR: stateDir() },
  });
  assert.match(text, new RegExp(`plugin: ${PLUGIN_VERSION.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`));
  assert.match(text, /^mode: observe$/m);
  assert.match(text, /^review at: 50, block at: 90$/m);
  assert.match(text, /^on scan error: review$/m);
  assert.match(text, /^scan host: sentrook\.firstdataunion\.org$/m);
  assert.match(text, /^credentials: no\b/m);
  assert.match(text, new RegExp(`^traffic log: disabled, ${path.join(stateDir(), "sentrook", "traffic.jsonl")}$`, "m"));
  assert.match(text, /^grants: 2 in config, 0 by command$/m);
  assert.match(text, /^channel bindings: 1 in config, 0 by command$/m);
});

test("status says credentials are present without printing them, from env, the state-dir .env or plugin config", async () => {
  const fromEnv = await runSentrookCommand("status", {
    pluginConfig: {},
    env: { OPENCLAW_STATE_DIR: stateDir(), SENTROOK_SCAN_CLIENT_ID: ID, SENTROOK_SCAN_CLIENT_SECRET: SECRET },
  });
  writeFileSync(path.join(stateDir(), ".env"), `SENTROOK_SCAN_CLIENT_ID=${ID}\nSENTROOK_SCAN_CLIENT_SECRET=${SECRET}\n`);
  const fromDotenv = await runSentrookCommand("status", { pluginConfig: {}, env: { OPENCLAW_STATE_DIR: stateDir() } });
  const fromConfig = await runSentrookCommand("status", {
    pluginConfig: { clientId: ID, clientSecret: SECRET },
    env: { OPENCLAW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "sentrook-cmd-")) },
  });
  for (const text of [fromEnv, fromDotenv, fromConfig]) {
    assert.match(text, /^credentials: yes$/m);
    assert.ok(!text.includes(ID), "client id must not be shown");
    assert.ok(!text.includes(SECRET), "client secret must not be shown");
  }
});

test("status names a missing credential by variable, never by value", async () => {
  const text = await runSentrookCommand("status", {
    pluginConfig: {},
    env: { OPENCLAW_STATE_DIR: stateDir(), SENTROOK_SCAN_CLIENT_ID: ID },
  });
  assert.match(text, /^credentials: no \(SENTROOK_SCAN_CLIENT_SECRET not set\)$/m);
  assert.ok(!text.includes(ID));
});

test("status shows an invalid scan endpoint as invalid", async () => {
  const text = await runSentrookCommand("status", {
    pluginConfig: { scanUrl: "https://scan.elsewhere.example" },
    env: { OPENCLAW_STATE_DIR: stateDir() },
  });
  assert.match(text, /^scan host: invalid \(URL host scan\.elsewhere\.example is not a firstdataunion\.org host/m);
});

test("status does not quote an unparseable scan URL, which may hold a secret", async () => {
  const text = await runSentrookCommand("status", {
    pluginConfig: { scanUrl: "https://u:pw-91c7e2@scan.test:99999" },
    env: { OPENCLAW_STATE_DIR: stateDir() },
  });
  assert.match(text, /^scan host: invalid \(invalid URL \(could not be parsed\)\)$/m);
  assert.ok(!text.includes("pw-91c7e2"));
});

test("a subcommand gets the rest of the input", async () => {
  const seen: string[] = [];
  SUBCOMMANDS.probe = { description: "test only", run: (_ctx, rest) => (seen.push(rest), "") };
  try {
    await runSentrookCommand("  probe  a   b ", { pluginConfig: {}, env: {} });
    await runSentrookCommand("probe", { pluginConfig: {}, env: {} });
  } finally {
    delete SUBCOMMANDS.probe;
  }
  assert.deepEqual(seen, ["a b", ""]);
});

test("help, no input and unknown input all return the help text", async () => {
  const ctx = { pluginConfig: {}, env: { OPENCLAW_STATE_DIR: stateDir() } };
  const help = helpText();
  for (const name of Object.keys(SUBCOMMANDS)) assert.match(help, new RegExp(`/sentrook ${name}\\b`));
  for (const input of [undefined, "", "   ", "help", "HELP", "nonsense", "constructor", "__proto__", "status-ish"]) {
    assert.equal(await runSentrookCommand(input, ctx), help, `input ${JSON.stringify(input)}`);
  }
  assert.notEqual(await runSentrookCommand("  Status  extra", ctx), help);
});

/** Registers the plugin with fake host registrars and returns the slash handler and CLI actions. */
async function registered(pluginConfig: Record<string, unknown>, registrationMode = "full") {
  const commands: any[] = [];
  const cliActions: Record<string, () => Promise<void> | void> = {};
  const node = (prefix: string): any => {
    const self: any = {
      description: () => self,
      option: () => self,
      command: (name: string) => node(`${prefix}${name} `),
      action: (fn: () => Promise<void>) => {
        cliActions[prefix.trim()] = fn;
        return self;
      },
    };
    return self;
  };
  let cliRegistrar: ((ctx: { program: any }) => Promise<void> | void) | undefined;
  plugin.register({
    pluginConfig,
    registrationMode,
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: () => undefined,
    registerCli: (r: any) => {
      cliRegistrar = r;
    },
    registerCommand: (def: any) => commands.push(def),
  } as any);
  await cliRegistrar!({ program: node("") });
  return { commands, cliActions };
}

async function captureLog(fn: () => Promise<void> | void): Promise<string> {
  const lines: string[] = [];
  const real = console.log;
  console.log = (...args: unknown[]) => void lines.push(args.map(String).join(" "));
  try {
    await fn();
  } finally {
    console.log = real;
  }
  return lines.join("\n");
}

test("the plugin registers /sentrook as an argument-taking command with no scopes or prompt guidance", async () => {
  const { commands } = await registered({});
  // The others are the owner-only history and grants commands.
  assert.deepEqual(
    commands.map((c) => c.name),
    ["sentrook", "sentrook-history", "sentrook-why", "sentrook-grants", "sentrook-grant", "sentrook-revoke", "sentrook-bind"],
  );
  const def = commands[0];
  assert.equal(def.acceptsArgs, true);
  assert.equal(typeof def.description, "string");
  assert.equal(def.requiredScopes, undefined);
  assert.equal(def.agentPromptGuidance, undefined);
  assert.deepEqual(await def.handler({ args: "nonsense" }), { text: helpText() });
  assert.deepEqual(await def.handler({}), { text: helpText() });
});

test("CLI metadata loading registers the CLI but not the chat command", async () => {
  const { commands, cliActions } = await registered({}, "cli-metadata");
  assert.equal(commands.length, 0);
  assert.ok(cliActions["sentrook status"]);
});

test("openclaw sentrook status prints exactly what /sentrook status returns", async () => {
  process.env.SENTROOK_SCAN_CLIENT_ID = ID;
  process.env.SENTROOK_SCAN_CLIENT_SECRET = SECRET;
  const { commands, cliActions } = await registered({ mode: "observe", grants: [{ kind: "file", pattern: "/x" }] });
  assert.ok(cliActions["sentrook verify"], "verify stays registered");
  const slash = (await commands[0].handler({ args: "status" })).text;
  const cli = await captureLog(() => cliActions["sentrook status"]!());
  assert.equal(cli, slash);
  assert.match(cli, /^mode: observe$/m);
  assert.match(cli, /^credentials: yes$/m);
  assert.ok(!cli.includes(SECRET) && !cli.includes(ID));
});
