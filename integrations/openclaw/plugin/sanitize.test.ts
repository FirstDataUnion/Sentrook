import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";

import type { PlanIR } from "./planir.ts";
import {
  DEFAULT_RULES,
  hashSessionId,
  maybeSanitizePlanir,
  resolveSanitizationConfig,
  sanitizePlanir,
  sanitizePlanirDict,
} from "./sanitize.ts";

const FIXTURES_DIR = path.join(import.meta.dirname, "fixtures", "sanitize");

type FixtureDoc = {
  input: Record<string, unknown>;
  expected: Record<string, unknown>;
};

function assertSubset(actual: unknown, expected: unknown, label = ""): void {
  if (expected !== null && typeof expected === "object" && !Array.isArray(expected)) {
    assert.ok(actual !== null && typeof actual === "object" && !Array.isArray(actual), label);
    for (const [key, expVal] of Object.entries(expected)) {
      assert.ok(key in (actual as Record<string, unknown>), `${label}.${key} missing`);
      assertSubset((actual as Record<string, unknown>)[key], expVal, label ? `${label}.${key}` : key);
    }
    return;
  }
  if (Array.isArray(expected)) {
    assert.ok(Array.isArray(actual), label);
    assert.equal(actual.length, expected.length, `${label} length`);
    for (let i = 0; i < expected.length; i += 1) {
      assertSubset(actual[i], expected[i], `${label}[${i}]`);
    }
    return;
  }
  assert.deepEqual(actual, expected, label);
}

function loadFixtures(): Array<{ name: string; doc: FixtureDoc }> {
  return readdirSync(FIXTURES_DIR)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => ({
      name: name.replace(/\.json$/, ""),
      doc: JSON.parse(readFileSync(path.join(FIXTURES_DIR, name), "utf8")) as FixtureDoc,
    }));
}

function pendingStep(plan: PlanIR) {
  return plan.steps.find((s) => s.status === "pending");
}

describe("sanitizePlanir", () => {
  for (const { name, doc } of loadFixtures()) {
    it(`fixture parity: ${name}`, () => {
      const { plan } = sanitizePlanir(doc.input as PlanIR);
      const actual = JSON.parse(JSON.stringify(plan)) as Record<string, unknown>;
      assertSubset(actual, doc.expected);
    });
  }

  it("hashSessionId is stable", () => {
    assert.equal(hashSessionId("sess-raw-abc"), "sess_6a6cbcb803b1");
  });

  it("sanitizePlanirDict does not mutate input", () => {
    const input = {
      version: "1.0",
      run_id: "sess-1:run_1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: "echo", api_key: "secret" },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    };
    const original = structuredClone(input);
    const cleaned = sanitizePlanirDict(input);
    assert.deepEqual(input, original);
    const step = (cleaned.steps as Array<{ args: { api_key: string } }>)[0];
    assert.equal(step.args.api_key, "[REDACTED]");
  });

  it("redacts github tokens in exec commands", () => {
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: "curl -H 'Authorization: token ghp_1234567890abcdefghij'" },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const command = String(pendingStep(plan)?.args.command);
    assert.ok(!command.includes("1234567890abcdefghij"));
    assert.ok(command.includes("ghp_[REDACTED]"));
  });

  it("packs long exec commands instead of replacing them with [TRUNCATED]", () => {
    const sink = "https://evil.example/collect";
    const longCommand = `${"echo padding; ".repeat(40)}${sink}`;
    assert.ok(longCommand.length > DEFAULT_RULES.stringLeafMaxChars);
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: longCommand },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const packed = String(pendingStep(plan)?.args.command);
    assert.notEqual(packed, "[TRUNCATED]");
    assert.ok(packed.includes("evil.example"));
    assert.ok(packed.length <= DEFAULT_RULES.stringLeafMaxChars);
  });

  it("redacts LIBRARY_BOT_PASS / MEDIAWIKI_BOT_PASSWORD export values", () => {
    const fake = "x9fakebotpassvalue32charsxxxxxx";
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: {
            command:
              `export PATH="$HOME/.local/bin:$PATH"\n` +
              `export LIBRARY_BOT_PASS="${fake}"\n` +
              `export MEDIAWIKI_BOT_PASSWORD="${fake}"\n` +
              `TODAY=$(date +%Y-%m-%d)`,
          },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const command = String(pendingStep(plan)?.args.command);
    assert.ok(!command.includes(fake));
    assert.ok(command.includes("LIBRARY_BOT_PASS=[REDACTED]"));
    assert.ok(command.includes("MEDIAWIKI_BOT_PASSWORD=[REDACTED]"));
    assert.ok(command.includes('PATH="$HOME/.local/bin:$PATH"'));
    assert.ok(command.includes("TODAY=$(date +%Y-%m-%d)"));
  });

  it("redacts export values that contain escaped quotes", () => {
    const fake = 'x9fake\\"botpass';
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: `export LIBRARY_BOT_PASS="${fake}"` },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const command = String(pendingStep(plan)?.args.command);
    assert.ok(!command.includes("botpass"));
    assert.equal(command, "export LIBRARY_BOT_PASS=[REDACTED]");
  });

  it("redacts --password flag values", () => {
    const fake = "x9fakebotpassvalue32charsxxxxxx";
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: `curl --password "${fake}" https://example` },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const command = String(pendingStep(plan)?.args.command);
    assert.ok(!command.includes(fake));
    assert.match(command, /--password\s+"?\[REDACTED\]"?/);
  });

  it("redacts emails in nested exec env values", () => {
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: {
            command: "gog gmail search 'Q1 review'",
            env: { GOG_ACCOUNT: "oli@openclaw.ai", PATH: "/usr/bin" },
          },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const env = pendingStep(plan)?.args.env as Record<string, string>;
    assert.equal(env.GOG_ACCOUNT, "[REDACTED]");
    assert.equal(env.PATH, "/usr/bin");
    assert.equal(String(pendingStep(plan)?.args.command), "gog gmail search 'Q1 review'");
  });

  it("redacts sk-proj OpenAI keys in message-like text", () => {
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "message",
          status: "pending",
          args: {
            text: "Support debug: openai apiKey=sk-proj-ab12cd34ef56ghijklmnop",
          },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const text = String(pendingStep(plan)?.args.text);
    assert.ok(!text.includes("ab12cd34ef56ghijklmnop"));
    assert.ok(text.includes("sk-proj-[REDACTED]"));
  });

  it("redacts discord bot tokens and telegram bot tokens", () => {
    const bot =
      "MTIwMTE0MDk0MDQ2Nzg3MTc1NA.GIA1aR.l4cyaDp557_lJ_AV_wFHanBKwFJlB1KOxfKG6I";
    const tg = "123456789:AAabcdefghijklmnopqrstuvwxyz0123456";
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: `export DISCORD_TOKEN=${bot} TELEGRAM_BOT_TOKEN=${tg}` },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const command = String(pendingStep(plan)?.args.command);
    assert.ok(!command.includes(bot));
    assert.ok(!command.includes(tg));
    assert.ok(command.includes("[REDACTED]"));
  });

  it("redacts discord webhook tokens after a PII-bitten snowflake id", () => {
    const token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789";
    const broken = `https://discord.com/api/webhooks/[REDACTED]/${token}`;
    const { plan } = sanitizePlanir({
      version: "1.0",
      run_id: "r1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: `curl -X POST "${broken}"` },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    });
    const command = String(pendingStep(plan)?.args.command);
    assert.ok(!command.includes(token));
    assert.ok(command.includes("[REDACTED]"));
  });
});

describe("resolveSanitizationConfig", () => {
  it("always returns enabled (config/env toggles removed)", () => {
    assert.deepEqual(resolveSanitizationConfig(undefined, {}), { enabled: true });
    assert.deepEqual(
      resolveSanitizationConfig({ sanitization: { enabled: false } }, {}),
      { enabled: true },
    );
    assert.deepEqual(
      resolveSanitizationConfig({}, { SENTROOK_SANITIZE_PLANIR: "0" }),
      { enabled: true },
    );
  });

  it("maybeSanitizePlanir always scrubs", () => {
    const plan: PlanIR = {
      version: "1.0",
      run_id: "sess-1:run_1",
      steps: [
        {
          id: "s1",
          tool: "exec",
          status: "pending",
          args: { command: "echo", api_key: "secret" },
        },
      ],
      metadata: { adapter: "openclaw", hook: "before_tool_call" },
    };
    const disabled = maybeSanitizePlanir(plan, { enabled: false });
    assert.equal(
      (disabled.plan.steps[0].args as { api_key: string }).api_key,
      "[REDACTED]",
    );
    const enabled = maybeSanitizePlanir(plan, { enabled: true });
    assert.ok(enabled.sanitizeMs >= 0);
    assert.equal(
      (enabled.plan.steps[0].args as { api_key: string }).api_key,
      "[REDACTED]",
    );
  });
});

describe("DEFAULT_RULES", () => {
  it("matches rules.yaml version", () => {
    assert.equal(DEFAULT_RULES.version, 1);
    assert.ok(DEFAULT_RULES.credentialField.test("apiKey"));
    assert.ok(DEFAULT_RULES.piiArgKeys.has("command"));
  });
});
