/**
 * Background saves: OpenClaw's own skill and memory saves are never asked about, because nobody can answer a prompt
 * in those runs. Allowed saves run; blocked ones are blocked and announced; reviewed ones are let through when the
 * scanner says they are lenient, saved as Skill Workshop drafts where OpenClaw can, or held; a scan failure follows
 * the policy for unattended runs. Every outcome but a plain allow sends the owner a notice where held-call notices go.
 */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import * as bg from "./backgroundSave.ts";
import { runSentrookCommand } from "./commands.ts";
import { actionOf, formatHistory, NOTICE_CALL_HEADER, recentScans } from "./history.ts";
import * as hold from "./hold.ts";
import plugin from "./index.ts";
import * as scanFailure from "./scanFailureNotice.ts";
import { runVerify } from "./verify.ts";

/** A notice's text with the call block (header and fenced lines) taken out, for checks of the rest of its words. */
function withoutCall(text: string): string {
  const lines = text.split("\n");
  const start = lines.indexOf(NOTICE_CALL_HEADER);
  if (start < 0) return text;
  const end = lines.indexOf("```", start + 2);
  return [...lines.slice(0, start), ...lines.slice(end + 1)].join("\n");
}

const ENV_KEYS = [
  "OPENCLAW_STATE_DIR",
  "OPENCLAW_VERSION",
  "SENTROOK_DEV_ENDPOINTS",
  "SENTROOK_SCAN_URL",
  "SENTROOK_OIDC_ISSUER",
  "SENTROOK_SCAN_CLIENT_ID",
  "SENTROOK_SCAN_CLIENT_SECRET",
  "SENTROOK_MODE",
  "SENTROOK_ON_SCAN_ERROR",
];
const savedEnv: Record<string, string | undefined> = {};
const realFetch = globalThis.fetch;
let stateDir = "";
let scans: any[] = [];
/** What the fake scanner answers, over `BASE`. */
let reply: Record<string, unknown> = {};
/** The scanner cannot be reached while set. */
let unreachable = false;

const BASE = {
  response_version: "2.0",
  status: "ok",
  enforced: null,
  tree: { suspicion: { score: 0.5 }, consequence: { score: 1 }, confidence: { score: 0.7 } },
  tool_description: { category: "self_modification", template: "Saves the skill {E1}" },
  entities: { E1: { kind: "skill", display: "deploy-staging" } },
};

const VERDICTS = {
  allow: { risk: 10, reasons: [], self_edit: { adds: [], lenient: false } },
  lenient: { risk: 55, reasons: [{ code: "selfedit.not_grounded" }], self_edit: { adds: [], lenient: true } },
  strict: { risk: 55, reasons: [{ code: "selfedit.not_grounded" }], self_edit: { adds: ["command"], lenient: false } },
  block: { risk: 92, reasons: [{ code: "selfmod.plugin" }], self_edit: { adds: ["command", "secret"], lenient: false } },
} as const;

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-bg-"));
  Object.assign(process.env, {
    OPENCLAW_STATE_DIR: dir,
    SENTROOK_DEV_ENDPOINTS: "1",
    SENTROOK_SCAN_URL: "http://scan.test",
    SENTROOK_OIDC_ISSUER: "http://idp.test",
    SENTROOK_SCAN_CLIENT_ID: "client",
    SENTROOK_SCAN_CLIENT_SECRET: "secret-value",
  });
  for (const k of ["OPENCLAW_VERSION", "SENTROOK_MODE", "SENTROOK_ON_SCAN_ERROR"]) delete process.env[k];
  stateDir = path.join(dir, "sentrook");
  scans = [];
  reply = { ...VERDICTS.allow };
  unreachable = false;
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
      if (unreachable) throw new TypeError("fetch failed");
      return json(200, { ...BASE, ...reply, request_id: planir.request_id, state: `state-${planir.session.step}` });
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

/** The owner, in a direct message to the agent on Telegram (an invented chat). */
const DM = {
  senderId: "100200300",
  channel: "telegram",
  accountId: "default",
  senderIsOwner: true,
  assertOwnerCurrent: () => undefined,
  sessionKey: "agent:main:telegram:direct:100200300",
  sessionId: "D1",
};

// ---- the three background runs, as OpenClaw starts them --------------------------------------------------------

const WORKSHOP = "/home/node/.openclaw/agents/main/agent/workshop-skills";
const TRANSCRIPT = [
  { role: "user", content: "Deploy the app to staging; I like short answers.", __openclaw: { senderIsOwner: true } },
  { role: "assistant", content: [{ type: "text", text: "Done." }] },
];
/** A body only the saving model wrote: it must never reach a notice. */
const BODY_MARKER = "Q7-BODY-MARKER-ONLY-IN-THE-SAVE";
const SKILL = `---\nname: deploy-staging\ndescription: Deploy to staging\n---\n1. make deploy-staging ${BODY_MARKER}\n`;
const TODAY_NOTE = `memory/${new Date().toISOString().slice(0, 10)}.md`;

interface Run {
  ctx: Record<string, unknown>;
  prompt: string;
}

const RUNS: Record<"review" | "flush" | "curator", Run> = {
  // 2026.11.5: no trigger on the review's context.
  review: {
    ctx: {
      sessionKey: "agent:main:internal-session-effects:skill-workshop-review_b2209184-4d54-4c07-8d90-32-dbba75ce3cb4c383",
      sessionId: "internal-session-effects-skill-workshop-review_b2209184",
      agentId: "main",
      runId: "skill-workshop-review:b2209184-4d54-4c07-8d90-32009bbd5c9d",
      workspaceDir: WORKSHOP,
      requester: { senderIsOwner: true },
    },
    prompt: "Background skill review. Distill new durable learning.",
  },
  flush: {
    ctx: {
      sessionKey: "agent:main:internal-session-effects:0f4c5a85-58a1-4bb3-9a43-7d0c1e2f3a4b-3f9c2d1e0a7b6c5d",
      sessionId: "F1",
      agentId: "main",
      runId: "0f4c5a85-58a1-4bb3-9a43-7d0c1e2f3a4b",
      trigger: "memory",
      workspaceDir: "/home/node/.openclaw/workspace",
      requester: { senderIsOwner: false },
    },
    prompt: "Pre-compaction memory flush.",
  },
  curator: {
    ctx: {
      sessionKey: "agent:main:cron:6f1205d4-ee20-48f0-8159-79550aef2f58:run:81986d2e",
      sessionId: "C1",
      agentId: "main",
      runId: "f965ecc0-curator",
      trigger: "cron",
      workspaceDir: WORKSHOP,
    },
    prompt: "[cron:6f1205d4 skill-collection-review-main] Review this agent's Skill Workshop as a collection.",
  },
};

/** The save each run makes in the matrix: a new skill for the review, the day's note, a skill file for the curator. */
const SAVES: Record<keyof typeof RUNS, { toolName: string; params: Record<string, unknown> }> = {
  review: { toolName: "skill_workshop", params: { action: "create", name: "deploy-staging", content: SKILL, reason: "learned" } },
  flush: { toolName: "write", params: { path: TODAY_NOTE, content: `- Prefers short answers. ${BODY_MARKER}` } },
  curator: { toolName: "write", params: { path: "deploy-staging/SKILL.md", content: SKILL } },
};

interface Opts {
  version?: string | null;
  pluginConfig?: Record<string, unknown>;
  /** `runtime.agent` as the host offers it (2026.11.5 has `resolveAgentDir`); none by default. */
  agent?: Record<string, unknown>;
}

/** OpenClaw's live config (`runtime.config.current()`); `api.config` is a different, load-time object. */
const HOST_CONFIG = { tools: { exec: { mode: "full" } } };

function registered(opts: Opts = {}) {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  const sent: any[] = [];
  const logs: string[] = [];
  const version = opts.version === undefined ? "2026.11.5" : opts.version;
  plugin.register({
    pluginConfig: opts.pluginConfig ?? {},
    registrationMode: "full",
    config: { tools: { exec: { mode: "load-time snapshot" } } },
    logger: { info: () => undefined, warn: (m: string) => logs.push(m), error: (m: string) => logs.push(m) },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
    runtime: {
      ...(version === null ? {} : { version }),
      ...(opts.agent ? { agent: opts.agent } : {}),
      config: { current: () => HOST_CONFIG },
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
  const command = async (name: string, args: string, ctx: Record<string, unknown> = DM) =>
    (await commands[name].handler({ ...ctx, args })).text as string;
  let n = 0;
  /** Starts `run` and makes one call in it: the hook's result, the scan's traffic record and the PlanIR sent. */
  /**
   * Starts `run` and makes one call in it: the hook's result, the scan's traffic record and the PlanIR sent. A call
   * turned into a draft then runs as OpenClaw runs it: `draft` is its after_tool_call (default: the draft is kept).
   */
  const save = async (
    run: keyof typeof RUNS,
    call: { toolName: string; params: Record<string, unknown> } = SAVES[run],
    draft: Record<string, unknown> | null = DRAFT_KEPT,
  ) => {
    const { ctx, prompt } = RUNS[run];
    const toolCallId = `t${++n}`;
    await fire("before_prompt_build", { runId: ctx.runId, prompt, messages: TRANSCRIPT }, ctx);
    const out = await fire("before_tool_call", { ...call, toolCallId, runId: ctx.runId }, ctx);
    const rec = records("scan").at(-1);
    if (out?.params && draft) {
      await fire("after_tool_call", { toolName: call.toolName, toolCallId, runId: ctx.runId, params: { ...call.params, ...out.params }, ...draft }, ctx);
    }
    await hold.waitForNotices();
    return { out, rec, planir: scans.at(-1) };
  };
  const holds = () => (existsSync(path.join(stateDir, "holds.json")) ? JSON.parse(readFileSync(path.join(stateDir, "holds.json"), "utf8")).holds : []);
  return { fire, commands, sent, logs, records, command, save, holds };
}

/** What OpenClaw 2026.11.5 reports for a kept draft, and for one it refuses. */
const DRAFT_KEPT = {
  result: {
    content: [{ type: "text", text: 'Saved draft deploy-staging-6df801f9 for "deploy-staging". Skills are unchanged; the user reviews drafts with /learn drafts.' }],
    details: { status: "ok" },
  },
};
const DRAFT_REFUSED = { error: "Too many drafts are waiting for review.", result: { details: { status: "error" } } };

const history = () => formatHistory(recentScans(path.join(stateDir, "traffic.jsonl"), 50), "/sentrook-why");

const WHERE = {
  review: /^Run: Skill Workshop background review, session s_[0-9a-f]+$/m,
  flush: /^Run: memory flush before compaction, session s_[0-9a-f]+$/m,
  curator: /^Run: cron job 6f1205d4, job name "skill-collection-review-main", session s_[0-9a-f]+$/m,
};

// ---- the outcome matrix ------------------------------------------------------------------------------------------

type Cell = "allow" | "lenient" | "strict" | "block" | "error";

/** What each run does with each verdict on OpenClaw 2026.11.5 (the review's save is a new skill, so it drafts). */
const EXPECTED: Record<keyof typeof RUNS, Record<Cell, { decision: string; action: string; notice: RegExp | null }>> = {
  review: {
    allow: { decision: "allowed", action: "allowed (self-edit)", notice: null },
    lenient: { decision: "allowed", action: "allowed (let through, self-edit)", notice: /^Sentrook let one of OpenClaw's background saves through/ },
    strict: { decision: "drafted", action: "drafted (self-edit)", notice: /^Sentrook saved a new skill .* as a Skill Workshop draft/ },
    block: { decision: "blocked", action: "blocked (self-edit)", notice: /^Sentrook blocked one of OpenClaw's background saves/ },
    error: { decision: "blocked_on_error", action: "blocked (scan error)", notice: /^Sentrook could not scan a tool call on an unattended run/ },
  },
  flush: {
    allow: { decision: "allowed", action: "allowed (self-edit)", notice: null },
    lenient: { decision: "allowed", action: "allowed (let through, self-edit)", notice: /^Sentrook let one of OpenClaw's background saves through/ },
    strict: { decision: "held", action: "held (self-edit)", notice: /^Sentrook held one of OpenClaw's background saves: it was not made/ },
    block: { decision: "blocked", action: "blocked (self-edit)", notice: /^Sentrook blocked one of OpenClaw's background saves/ },
    error: { decision: "blocked_on_error", action: "blocked (scan error)", notice: /^Sentrook could not scan a tool call on an unattended run/ },
  },
  curator: {
    allow: { decision: "allowed", action: "allowed (self-edit)", notice: null },
    lenient: { decision: "allowed", action: "allowed (let through, self-edit)", notice: /^Sentrook let one of OpenClaw's background saves through/ },
    strict: { decision: "held", action: "held (self-edit)", notice: /^Sentrook held one of OpenClaw's background saves: it was not made/ },
    block: { decision: "blocked", action: "blocked (self-edit)", notice: /^Sentrook blocked one of OpenClaw's background saves/ },
    error: { decision: "blocked_on_error", action: "blocked (scan error)", notice: /^Sentrook could not scan a tool call on an unattended run/ },
  },
};

/** Where the record of a scan's notice is: the hold's, the draft's resolution (sent once OpenClaw ran it), or the scan's. */
function noticeOf(r: ReturnType<typeof registered>, rec: any, decision: string) {
  if (decision === "held") return rec.hold.notice;
  if (decision === "drafted") return r.records("resolution").find((x) => x.request_id === rec.request_id)?.notice;
  return rec.notice;
}

function setVerdict(cell: Cell) {
  unreachable = cell === "error";
  if (cell !== "error") reply = { ...VERDICTS[cell] };
}

function assertResult(cell: Cell, decision: string, out: any) {
  assert.equal(out?.requireApproval, undefined, "a background save is never asked about");
  if (decision === "allowed") assert.equal(out, undefined);
  else if (decision === "drafted") assert.deepEqual(out, { params: { action: "draft", name: "deploy-staging", content: SKILL, reason: bg.DRAFT_REASON } });
  else if (decision === "held") assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
  else if (decision === "blocked") assert.match(out.blockReason, /^Sentrook security block: .*changes the agent's own setup/);
  else {
    assert.equal(out.block, true, cell);
    assert.match(out.blockReason, /^Sentrook did not scan this tool call/);
  }
}

for (const run of Object.keys(RUNS) as (keyof typeof RUNS)[]) {
  for (const cell of ["allow", "lenient", "strict", "block", "error"] as Cell[]) {
    const want = EXPECTED[run][cell];

    test(`${run} × ${cell}: ${want.decision}, never a prompt, notice ${want.notice ? "sent" : "none"}`, async () => {
      const r = registered();
      await r.command("sentrook-notify", "here");
      setVerdict(cell);
      const { out, rec, planir } = await r.save(run);
      assertResult(cell, want.decision, out);
      assert.equal(rec.decision, want.decision);
      assert.equal(rec.lenient === true, cell === "lenient");
      assert.deepEqual(rec.background_save, { kind: { review: "background_review", flush: "memory_flush", curator: "curator" }[run], store: run === "flush" ? "memory" : "skills" });
      assert.equal(planir.trigger.kind, "system");
      assert.ok(planir.self_edit, "declared as a self-edit");
      const [scan, resolution] = recentScans(path.join(stateDir, "traffic.jsonl"), 1)[0]!;
      assert.equal(actionOf(scan, resolution), want.action);
      assert.ok(history().includes(want.action), `history shows ${want.action}`);
      if (want.notice) {
        assert.equal(r.sent.length, 1, "one notice");
        const text: string = r.sent[0].text;
        assert.match(text, want.notice);
        assert.match(text, WHERE[run]);
        assert.ok(!withoutCall(text).includes(BODY_MARKER), "nothing the saving model wrote reaches the notice outside the marked call");
        assert.ok(!/\b55\b|\b92\b|selfedit\.|selfmod\./.test(text), "no risk score or reason codes");
        assert.equal(r.sent[0].channel, "telegram");
        assert.deepEqual(noticeOf(r, rec, want.decision), { status: "queued", target: "telegram" });
      } else {
        assert.equal(r.sent.length, 0);
        assert.equal(rec.notice, undefined);
      }
      assert.equal(r.holds().length, 0, "background saves are never in the holds file");
      if (r.sent.length) assert.ok(!r.sent[0].text.includes("/sentrook-approve"), "nothing to approve");
    });

    if (cell !== "allow") {
      test(`${run} × ${cell} with no notify target: the same outcome, the notice unsent, status and verify say why`, async () => {
        const r = registered();
        setVerdict(cell);
        const { out, rec } = await r.save(run);
        assertResult(cell, want.decision, out);
        assert.equal(rec.decision, want.decision);
        assert.equal(r.sent.length, 0);
        assert.deepEqual(noticeOf(r, rec, want.decision), { status: "unsent", target: null, reason: hold.NOTIFY_UNSET });
        const status = await runSentrookCommand("status", { pluginConfig: {}, env: process.env });
        assert.match(status, /^background-save notices: cannot be delivered: no notify target is set; run \/sentrook-notify here/m);
        const check = (await runVerify({}, { env: process.env, fetchImpl: offline })).find((c) => c.name === "background-save notices");
        assert.match(check!.detail, /^cannot be delivered: no notify target is set; run \/sentrook-notify here/);
      });
    }
  }
}

const offline = (async () => {
  throw new Error("offline");
}) as unknown as typeof fetch;

test("status and verify name the notice target once it is set", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  const status = await runSentrookCommand("status", { pluginConfig: {}, env: process.env });
  assert.match(status, /^background-save notices: by a direct message on telegram$/m);
  const check = (await runVerify({}, { env: process.env, fetchImpl: offline })).find((c) => c.name === "background-save notices");
  assert.deepEqual(check, { name: "background-save notices", ok: true, detail: "by a direct message on telegram" });
});

test("status counts background saves by outcome, the lenient and drafted ones too", async () => {
  const r = registered();
  for (const cell of ["allow", "lenient", "strict", "block"] as Cell[]) {
    setVerdict(cell);
    await r.save("review");
  }
  setVerdict("strict");
  await r.save("flush");
  const status = await runSentrookCommand("status", { pluginConfig: {}, env: process.env });
  assert.match(
    status,
    /^skill review: allow; self-edits in the traffic log: 1 allowed, 1 blocked, 1 let through without asking, 1 saved as drafts, 1 held$/m,
  );
});

// ---- drafts -------------------------------------------------------------------------------------------------------

test("a write_file of the skill's SKILL.md drafts with exactly name, content and the reason", async () => {
  const r = registered();
  setVerdict("strict");
  const { out, rec } = await r.save("review", {
    toolName: "skill_workshop",
    params: { action: "write_file", name: "deploy-staging", file_path: "SKILL.md", content: SKILL },
  });
  assert.deepEqual(out, { params: { action: "draft", name: "deploy-staging", content: SKILL, reason: bg.DRAFT_REASON } });
  assert.equal(rec.decision, "drafted");
});

for (const [name, call] of [
  ["a patch", { toolName: "skill_workshop", params: { action: "patch", name: "deploy-staging", old_text: "a", new_text: "b" } }],
  ["a write_file of a support file", { toolName: "skill_workshop", params: { action: "write_file", name: "deploy-staging", file_path: "scripts/run.sh", content: "echo" } }],
  ["a create with no name", { toolName: "skill_workshop", params: { action: "create", content: SKILL } }],
  ["a file write into the Workshop", { toolName: "write", params: { path: "deploy-staging/SKILL.md", content: SKILL } }],
] as const) {
  test(`${name} in the review cannot be drafted: held, never asked`, async () => {
    const r = registered();
    await r.command("sentrook-notify", "here");
    setVerdict("strict");
    const { out, rec } = await r.save("review", call as any);
    assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
    assert.equal(rec.decision, "held");
    assert.match(r.sent[0].text, /^Sentrook held one of OpenClaw's background saves/);
  });
}

for (const version of ["2026.11.4", "2026.10.3", "2026.11.5-beta.1", "not-a-version", null]) {
  test(`on OpenClaw ${version ?? "of unknown version"} a reviewed new skill is held, never drafted or asked`, async () => {
    const r = registered({ version });
    setVerdict("strict");
    const { out, rec } = await r.save("review");
    assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
    assert.equal(rec.decision, "held");
  });
}

test("a newer OpenClaw drafts too; OPENCLAW_VERSION stands in when the runtime has no version", async () => {
  for (const version of ["2026.12.0", "2027.1.1", "2026.11.5+build.7"]) {
    const r = registered({ version });
    setVerdict("strict");
    assert.equal((await r.save("review")).out?.params?.action, "draft", version);
  }
  process.env.OPENCLAW_VERSION = "2026.11.5";
  const r = registered({ version: null });
  setVerdict("strict");
  assert.equal((await r.save("review")).out?.params?.action, "draft");
});

test("a drafted save goes to the scanner's history as a review nobody answered", async () => {
  const r = registered();
  setVerdict("strict");
  await r.save("review");
  setVerdict("allow");
  const { planir } = await r.save("review", { toolName: "skill_workshop", params: { action: "list" } });
  assert.equal(planir.history.at(-1).decision, "review_timed_out");
});

test("draftParams: only a create or a SKILL.md write_file on 2026.11.5 or newer", () => {
  const create = { action: "create", name: "n", content: "c", description: "d" };
  assert.deepEqual(bg.draftParams("skill_workshop", create, "2026.11.5"), { action: "draft", name: "n", content: "c", reason: bg.DRAFT_REASON });
  assert.deepEqual(bg.draftParams("skill_workshop", { action: "write_file", name: "n", file_path: "./SKILL.md", content: "c" }, "2026.11.5")?.action, "draft");
  assert.equal(bg.draftParams("skill_workshop", create, "2026.11.4"), null);
  assert.equal(bg.draftParams("skill_workshop", create, undefined), null);
  assert.equal(bg.draftParams("write", create, "2026.11.5"), null);
  assert.equal(bg.draftParams("skill_workshop", { ...create, action: "patch" }, "2026.11.5"), null);
  assert.equal(bg.draftParams("skill_workshop", { ...create, content: "  " }, "2026.11.5"), null);
  assert.equal(bg.draftParams("skill_workshop", { action: "write_file", name: "n", file_path: "SKILL.md.bak", content: "c" }, "2026.11.5"), null);
  assert.equal(bg.draftParams("skill_workshop", { action: "write_file", name: "n", file_path: "../other/SKILL.md", content: "c" }, "2026.11.5"), null);
});

// ---- lenient ------------------------------------------------------------------------------------------------------

test("must stay strict: a review with no self_edit field, or one not exactly lenient true, is not let through", async () => {
  for (const self_edit of [undefined, null, {}, { adds: [] }, { lenient: "true" }, { lenient: 1 }, [true]]) {
    const r = registered();
    reply = { ...VERDICTS.strict, self_edit };
    const { out, rec } = await r.save("flush");
    assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT }, JSON.stringify(self_edit));
    assert.equal(rec.lenient, undefined);
  }
});

test("must stay strict: a review the scanner enforces is never let through, lenient or not", async () => {
  const r = registered();
  reply = { ...VERDICTS.lenient, risk: 20, enforced: "review" };
  const { out, rec } = await r.save("flush");
  assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
  assert.equal(rec.decision, "held");
  assert.equal(bg.lenientOf({ ...BASE, ...VERDICTS.lenient, enforced: "review" } as any, 80), false);
  assert.equal(bg.lenientOf({ ...BASE, ...VERDICTS.lenient, enforced: null } as any, 80), true);
});

test("must stay strict: a block-level score the scanner caps at review (a retry nobody answered) is never let through", async () => {
  const r = registered();
  reply = { ...VERDICTS.lenient, risk: 92, ceiling: "review", reasons: [{ code: "cap.unanswered_retry" }] };
  const { out, rec } = await r.save("flush");
  assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
  assert.equal(rec.verdict, "review");
  assert.equal(rec.lenient, undefined);
  assert.equal(bg.lenientOf({ ...VERDICTS.lenient, risk: 80 } as any, 80), false);
});

test("one notice of each kind per run in the quiet period; another run is announced", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("lenient");
  await r.save("flush");
  const second = await r.save("flush");
  assert.equal(r.sent.length, 1);
  assert.deepEqual(second.rec.notice, { status: "quiet" });
  setVerdict("block");
  await r.save("flush");
  assert.equal(r.sent.length, 2, "a block in the same run is announced: another kind");
  setVerdict("lenient");
  await r.save("review");
  assert.equal(r.sent.length, 3, "another run is announced");
  assert.equal(bg.quietKey("lenient", null, "s_ab"), "background_lenient:session:s_ab");
  assert.equal(bg.quietKey("drafted", "job-1", "s_ab"), "background_drafted:job:job-1");
});

test("a notice that cannot be delivered reopens its quiet period", async () => {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  let fail = true;
  const sent: string[] = [];
  plugin.register({
    pluginConfig: {},
    registrationMode: "full",
    config: {},
    logger: { info: () => undefined, warn: () => undefined, error: () => undefined },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => (commands[def.name] = def),
    runtime: {
      version: "2026.11.5",
      channel: {
        outbound: {
          loadAdapter: async () => ({
            sendText: async (req: any) => {
              if (fail) throw new Error("chat not found");
              sent.push(req.text);
            },
          }),
        },
      },
    },
  } as any);
  await commands["sentrook-notify"].handler({ ...DM, args: "here" });
  const fire = async (hook: string, event: any, ctx: any) => {
    for (const h of on[hook] ?? []) await h(event, ctx);
  };
  setVerdict("lenient");
  const { ctx, prompt } = RUNS.flush;
  await fire("before_prompt_build", { runId: ctx.runId, prompt, messages: TRANSCRIPT }, ctx);
  await fire("before_tool_call", { ...SAVES.flush, toolCallId: "a1", runId: ctx.runId }, ctx);
  await hold.waitForNotices();
  fail = false;
  await fire("before_tool_call", { ...SAVES.flush, toolCallId: "a2", runId: ctx.runId }, ctx);
  await hold.waitForNotices();
  assert.equal(sent.length, 1, "the second save is announced: the first notice never arrived");
});

// ---- settings never bring the prompt back ------------------------------------------------------------------------

for (const [name, pluginConfig] of [
  ["skillReview review", { skillReview: "review" }],
  ["scheduledIntentKinds with system", { approval: { scheduledIntentKinds: ["cron", "subagent", "system"] } }],
  ["scheduledIntentKinds without cron or system", { approval: { scheduledIntentKinds: ["subagent"] } }],
] as const) {
  test(`with ${name}, no background save is ever asked about`, async () => {
    for (const run of Object.keys(RUNS) as (keyof typeof RUNS)[]) {
      for (const cell of ["strict", "error"] as Cell[]) {
        const r = registered({ pluginConfig });
        setVerdict(cell);
        const { out, rec } = await r.save(run);
        assert.equal(out?.requireApproval, undefined, `${run} × ${cell}`);
        assert.ok(out?.block || out?.params, `${run} × ${cell}`);
        assert.deepEqual(Object.keys(rec.background_save), ["kind", "store"]);
      }
    }
  });
}

test("with skillReview review the saves are not declared as self-edits, and a review is still never asked", async () => {
  const r = registered({ pluginConfig: { skillReview: "review" } });
  setVerdict("strict");
  const { out, planir, rec } = await r.save("curator");
  assert.equal(planir.self_edit, undefined);
  assert.equal(planir.trigger.kind, "scheduled");
  assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
  assert.equal(rec.skill_review, undefined);
  assert.equal(actionOf(rec, null), "held (self-edit)");
});

test("scan errors follow onScanError for unattended runs: allow runs the save, deny blocks it with a notice", async () => {
  for (const [policy, decision, notices] of [
    ["allow", "allowed_on_error", 0],
    ["deny", "blocked_on_error", 1],
    ["review", "blocked_on_error", 1],
  ] as const) {
    rmSync(path.join(stateDir, "scan-failure-notices.json"), { force: true });
    const r = registered({ pluginConfig: { onScanError: policy } });
    await r.command("sentrook-notify", "here");
    setVerdict("error");
    const { out, rec } = await r.save("review");
    assert.equal(out?.requireApproval, undefined, policy);
    assert.equal(rec.decision, decision, policy);
    assert.equal(r.sent.length, notices, policy);
    if (notices) assert.match(r.sent[0].text, WHERE.review);
  }
});

test("observe mode changes nothing: no draft, no hold, no notice", async () => {
  const r = registered({ pluginConfig: { mode: "observe" } });
  await r.command("sentrook-notify", "here");
  for (const cell of ["lenient", "strict", "block"] as Cell[]) {
    setVerdict(cell);
    const { out, rec } = await r.save("review");
    assert.equal(out, undefined, cell);
    assert.equal(rec.decision, "allowed");
  }
  assert.equal(r.sent.length, 0);
  assert.equal(r.holds().length, 0);
});

test("observe mode on a scan failure: the save runs, nothing is announced", async () => {
  const r = registered({ pluginConfig: { mode: "observe" } });
  await r.command("sentrook-notify", "here");
  setVerdict("error");
  const { out, rec } = await r.save("flush");
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed_on_error");
  assert.equal(r.sent.length, 0);
});

test("a snooze never lets a background save through, even when it is sent as the owner's message", async () => {
  // skillReview review sends the review run as the run's own (owner) message.
  const r = registered({ pluginConfig: { skillReview: "review" } });
  await r.command("sentrook-snooze", "1h --all");
  setVerdict("strict");
  const ctx: Record<string, any> = { ...RUNS.review.ctx, trigger: "user" };
  await r.fire("before_prompt_build", { runId: ctx.runId, prompt: RUNS.review.prompt, messages: TRANSCRIPT }, ctx);
  const out = await r.fire("before_tool_call", { ...SAVES.review, toolCallId: "z1", runId: ctx.runId }, ctx);
  const rec = r.records("scan").at(-1);
  assert.equal(scans.at(-1).trigger.kind, "message");
  assert.equal(rec.snoozed, undefined);
  assert.equal(rec.decision, "drafted");
  assert.equal(out.params.action, "draft");
});

test("with the traffic log off, notices carry no why id", async () => {
  const r = registered({ pluginConfig: { trafficLog: { enabled: false } } });
  await r.command("sentrook-notify", "here");
  setVerdict("block");
  await r.save("flush");
  assert.equal(r.sent.length, 1);
  assert.ok(!r.sent[0].text.includes("/sentrook-why"));
});

// ---- the fix round: what is let through, what is drafted, what is held ----------------------------------------

test("must stay strict: a degraded scan is never let through, lenient or not", async () => {
  const r = registered();
  reply = { ...VERDICTS.lenient, status: "degraded" };
  const { out, rec } = await r.save("flush");
  assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
  assert.equal(rec.lenient, undefined);
  assert.equal(bg.lenientOf({ ...VERDICTS.lenient, status: "degraded" } as any, 80), false);
});

test("must stay strict: lenient counts only when the save was declared as a self-edit (never with skillReview review)", async () => {
  const r = registered({ pluginConfig: { skillReview: "review" } });
  setVerdict("lenient");
  const flush = await r.save("flush");
  assert.equal(flush.planir.self_edit, undefined);
  assert.deepEqual(flush.out, { block: true, blockReason: bg.HELD_TEXT });
  assert.equal(flush.rec.lenient, undefined);
  const review = await r.save("review");
  assert.equal(review.rec.decision, "drafted", "a new skill still drafts");
});

test("a write_file with no file_path cannot be drafted: held", async () => {
  const r = registered();
  setVerdict("strict");
  const { out, rec } = await r.save("review", { toolName: "skill_workshop", params: { action: "write_file", name: "deploy-staging", content: SKILL } });
  assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
  assert.equal(rec.decision, "held");
});

test("a second block in the same run is quiet; a block in another run is announced", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("block");
  const first = await r.save("review");
  const second = await r.save("review");
  assert.deepEqual(first.rec.notice, { status: "queued", target: "telegram" });
  assert.deepEqual(second.rec.notice, { status: "quiet" });
  assert.equal(second.out.block, true);
  await r.save("flush");
  assert.equal(r.sent.length, 2);
});

test("a held save is announced once per run; a block-level retry after a draft is held and always announced", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const patch = { toolName: "skill_workshop", params: { action: "patch", name: "deploy-staging", old_text: "a", new_text: "b" } };
  await r.save("review", patch);
  const quiet = await r.save("review", patch);
  assert.deepEqual(quiet.rec.hold.notice, { status: "quiet" });
  assert.equal(r.sent.length, 1);
  const drafted = await r.save("review");
  assert.equal(drafted.rec.decision, "drafted");
  assert.equal(r.sent.length, 2, "the draft is announced");
  // The scanner sees the draft as a review nobody answered, so a block-level retry comes back capped at review.
  reply = { ...VERDICTS.block, ceiling: "review", reasons: [{ code: "cap.unanswered_retry" }, { code: "selfmod.plugin" }] };
  const retry = await r.save("review");
  assert.equal(retry.planir.history.at(-1).decision, "review_timed_out");
  assert.equal(retry.rec.verdict, "review");
  assert.deepEqual(retry.out, { block: true, blockReason: bg.HELD_TEXT }, "never a second draft");
  assert.equal(retry.rec.decision, "held");
  assert.deepEqual(retry.rec.hold.notice, { status: "queued", target: "telegram" }, "not silenced by the earlier held notice");
  assert.equal(r.sent.length, 3);
  assert.match(r.sent[2].text, /^Sentrook held one of OpenClaw's background saves/);
  assert.match(r.sent[2].text, /^More held retries of a blocked save in this run are not announced for 6 hours\.$/m);
  const again = await r.save("review");
  assert.equal(again.rec.decision, "held");
  assert.deepEqual(again.rec.hold.notice, { status: "quiet" }, "a model that keeps retrying does not flood the channel");
  assert.equal(r.sent.length, 3);
});

test("must hold, announced once: repeated block-level retries in one run send one notice; another run gets its own", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  reply = { ...VERDICTS.block, ceiling: "review", reasons: [{ code: "cap.unanswered_retry" }, { code: "selfmod.plugin" }] };
  const outs = [];
  for (let i = 0; i < 5; i++) outs.push(await r.save("flush"));
  for (const o of outs) {
    assert.equal(o.rec.decision, "held");
    assert.deepEqual(o.out, { block: true, blockReason: bg.HELD_TEXT });
  }
  assert.equal(r.sent.length, 1, "the first retry is announced, the rest are quiet");
  assert.deepEqual(outs[0]!.rec.hold.notice, { status: "queued", target: "telegram" });
  assert.deepEqual(outs[4]!.rec.hold.notice, { status: "quiet" });
  await r.save("curator");
  assert.equal(r.sent.length, 2, "another run's first retry is announced");
  assert.equal(bg.quietKey("held_retry", null, "s_ab"), "background_held_retry:session:s_ab");
});

test("a draft is announced only once OpenClaw reports it kept", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const { out, rec } = await r.save("review", SAVES.review, null);
  assert.equal(out.params.action, "draft");
  assert.equal(r.sent.length, 0, "nothing before the host has run the draft");
  assert.equal(actionOf(rec, null), "sent to drafts (self-edit)");
  await r.fire("after_tool_call", { toolName: "skill_workshop", toolCallId: "t1", runId: RUNS.review.ctx.runId, ...DRAFT_KEPT }, RUNS.review.ctx);
  await hold.waitForNotices();
  assert.equal(r.sent.length, 1);
  assert.match(r.sent[0].text, /as a Skill Workshop draft/);
  const [resolution] = r.records("resolution");
  assert.deepEqual(resolution, { ...resolution, request_id: rec.request_id, resolution: "draft_saved", decision: "drafted" });
  assert.match(history(), /drafted \(self-edit\) +in drafts$/m);
});

for (const [name, report] of [
  ["an error", DRAFT_REFUSED],
  ["a result that does not name a saved draft", { result: { content: [{ type: "text", text: "Learning is off for this agent." }] } }],
] as const) {
  test(`a draft OpenClaw does not keep (${name}) is recorded as not saved and announced as lost`, async () => {
    const r = registered();
    await r.command("sentrook-notify", "here");
    setVerdict("strict");
    const { rec } = await r.save("review", SAVES.review, report as any);
    assert.equal(r.sent.length, 1);
    assert.match(r.sent[0].text, /^Sentrook sent a new skill .* but OpenClaw did not keep the draft, so the save was not made/);
    assert.ok(!withoutCall(r.sent[0].text).includes(BODY_MARKER));
    const [resolution] = r.records("resolution");
    assert.equal(resolution.request_id, rec.request_id);
    assert.equal(resolution.resolution, "draft_failed");
    assert.match(history(), /not saved \(draft refused, self-edit\)/);
    setVerdict("allow");
    const next = await r.save("review", { toolName: "skill_workshop", params: { action: "list" } });
    const sent = next.planir.history.at(-1);
    assert.equal(sent.decision, "review_timed_out");
    if (name === "an error") assert.deepEqual(sent.result, { status: "error", size_bytes: 0 });
    const status = await runSentrookCommand("status", { pluginConfig: {}, env: process.env });
    assert.match(status, /1 drafts not kept/);
  });
}

test("background holds stay out of the holds file, so they never push out holds that can be approved", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  // an ordinary cron job's review: an approvable hold
  const ctx = { sessionKey: "agent:main:cron:job-9", sessionId: "J9", agentId: "main", runId: "r-j9", trigger: "cron" };
  await r.fire("before_prompt_build", { runId: "r-j9", prompt: "[cron:job9 daily-brief] post" }, ctx);
  await r.fire("before_tool_call", { toolName: "message", toolCallId: "m1", runId: "r-j9", params: { action: "send", channel: "discord", target: "#ops", message: "x" } }, ctx);
  for (let i = 0; i < 3; i++) await r.save("flush");
  assert.equal(r.holds().length, 1);
  const status = await runSentrookCommand("status", { pluginConfig: {}, env: process.env });
  assert.match(status, /^held calls: 1 waiting/m);
  assert.match(status, /3 held$/m);
  assert.equal(r.records("scan").at(-1).hold.id, null);
});

// ---- what stays as it was ----------------------------------------------------------------------------------------

test("must stay as before: an owner's own skill_workshop call in a chat still asks on a review", async () => {
  const r = registered();
  const ctx = { sessionKey: "agent:main:main", sessionId: "S1", agentId: "main", runId: "r1", trigger: "user", requester: { senderIsOwner: true, channel: "webchat" } };
  await r.fire("before_prompt_build", { runId: "r1", prompt: "save that as a skill", currentUserMessage: "save that as a skill" }, ctx);
  setVerdict("lenient");
  const out = await r.fire("before_tool_call", { toolName: "skill_workshop", toolCallId: "o1", runId: "r1", params: SAVES.review.params }, ctx);
  assert.ok(out?.requireApproval, "asked");
  assert.equal(out.params, undefined);
  const rec = r.records("scan").at(-1);
  assert.equal(rec.background_save, undefined);
  assert.equal(rec.decision, "review_timed_out");
});

// ---- a background run's other calls -------------------------------------------------------------------------------

/** A call of a background run that is not a save, and a review-band answer for it (the scanner reads no save in it). */
const OTHER = { toolName: "exec", params: { command: "ls skills" } };
const otherReview = () => {
  reply = { ...VERDICTS.strict, self_edit: undefined };
};
const KINDS = { review: "background_review", flush: "memory_flush", curator: "curator" } as const;
const HELD_CALL = /^Sentrook held a tool call in one of OpenClaw's background runs: it did not run/;

test("must hold: a background run's other call in the review band is never asked about, with one notice per run", async () => {
  for (const run of Object.keys(RUNS) as (keyof typeof RUNS)[]) {
    for (const pluginConfig of [{}, { skillReview: "review" }, { approval: { scheduledIntentKinds: ["subagent"] } }]) {
      const label = `${run} ${JSON.stringify(pluginConfig)}`;
      rmSync(path.join(stateDir, "scan-failure-notices.json"), { force: true });
      const r = registered({ pluginConfig });
      await r.command("sentrook-notify", "here");
      otherReview();
      for (const nth of [1, 2]) {
        const { out, rec } = await r.save(run, OTHER);
        assert.equal(out?.requireApproval, undefined, label);
        assert.deepEqual(out, { block: true, blockReason: bg.HELD_CALL_TEXT }, label);
        assert.equal(rec.decision, "held", label);
        assert.equal(rec.background_save, undefined, label);
        assert.equal(rec.hold.id, null, label);
        assert.equal(rec.hold.run, KINDS[run], label);
        assert.equal(rec.hold.notice.status, nth === 1 ? "queued" : "quiet", label);
        assert.equal(actionOf(rec, null), "held", label);
      }
      assert.equal(r.sent.length, 1, `one notice per run: ${label}`);
      const text: string = r.sent[0].text;
      assert.match(text, HELD_CALL, label);
      assert.match(text, WHERE[run], label);
      assert.match(text, /^Tool: exec: /m, label);
      assert.match(text, /^Held because /m, label);
      assert.match(text, /^To look at it: \/sentrook-why [0-9a-f]{8}; /m, label);
      assert.match(text, /^More held calls in this (run|job) are not announced for 6 hours\.$/m, label);
      // not an approvable hold: approving could not bring the run back
      assert.deepEqual(r.holds(), [], label);
    }
  }
});

test("must hold: a held call and a held save of one run each send their own notice", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  otherReview();
  await r.save("flush", OTHER);
  setVerdict("strict");
  await r.save("flush");
  assert.equal(r.sent.length, 2);
  assert.match(r.sent[0].text, HELD_CALL);
  assert.match(r.sent[1].text, /^Sentrook held one of OpenClaw's background saves/);
});

test("must hold: a held call's notice carries what the model wrote only inside the marked call block", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  otherReview();
  await r.save("review", { toolName: "exec", params: { command: `echo ${BODY_MARKER}` } });
  assert.equal(r.sent.length, 1);
  assert.ok(!withoutCall(r.sent[0].text).includes(BODY_MARKER));
  assert.ok(r.sent[0].text.includes(`command: echo ${BODY_MARKER}`), "the call, as data");
});

test("must hold: with hideToolCalls a notice carries nothing the model wrote", async () => {
  const r = registered({ pluginConfig: { hideToolCalls: true } });
  await r.command("sentrook-notify", "here");
  otherReview();
  await r.save("review", { toolName: "exec", params: { command: `echo ${BODY_MARKER}` } });
  assert.equal(r.sent.length, 1);
  assert.ok(!r.sent[0].text.includes(BODY_MARKER));
  assert.ok(!r.sent[0].text.includes(NOTICE_CALL_HEADER));
});

test("must show: a held save's notice shows what it would save after the Save line, marked as data", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const params = { action: "patch", name: "deploy-staging", old_text: "a", new_text: `b ${BODY_MARKER}` };
  await r.save("review", { toolName: "skill_workshop", params });
  const lines = r.sent[0].text.split("\n");
  const at = lines.indexOf(NOTICE_CALL_HEADER);
  assert.ok(at > 0 && lines[at - 1]!.startsWith("Save "), "right after the Save line");
  assert.deepEqual(lines.slice(at + 1, at + 7), ["```", "action: patch", "name: deploy-staging", "old_text: a", `new_text: b ${BODY_MARKER}`, "```"]);
});

test("must hold: without a notice target the call is still held, and the record says why nothing was sent", async () => {
  const r = registered();
  otherReview();
  const { out, rec } = await r.save("review", OTHER);
  assert.deepEqual(out, { block: true, blockReason: bg.HELD_CALL_TEXT });
  assert.equal(rec.hold.notice.status, "unsent");
  assert.equal(r.sent.length, 0);
});

test("must hold: a scan error on a background run's other call follows the unattended policy, never a prompt", async () => {
  for (const [policy, decision, notices] of [
    ["allow", "allowed_on_error", 0],
    ["deny", "blocked_on_error", 1],
    ["review", "blocked_on_error", 1],
  ] as const) {
    rmSync(path.join(stateDir, "scan-failure-notices.json"), { force: true });
    const r = registered({ pluginConfig: { onScanError: policy } });
    await r.command("sentrook-notify", "here");
    setVerdict("error");
    const { out, rec } = await r.save("review", OTHER);
    assert.equal(out?.requireApproval, undefined, policy);
    assert.equal(rec.decision, decision, policy);
    assert.equal(r.sent.length, notices, policy);
    if (notices) assert.match(r.sent[0].text, WHERE.review);
  }
});

test("must stay as before: a background run's other call that is allowed runs, and one that is blocked is blocked", async () => {
  for (const run of Object.keys(RUNS) as (keyof typeof RUNS)[]) {
    const r = registered();
    await r.command("sentrook-notify", "here");
    reply = { ...VERDICTS.allow, self_edit: undefined };
    assert.equal((await r.save(run, OTHER)).out, undefined, run);
    reply = { ...VERDICTS.block, self_edit: undefined };
    const { out, rec } = await r.save(run, OTHER);
    assert.equal(out?.block, true, run);
    assert.match(out.blockReason, /^Sentrook security block: /, run);
    assert.equal(rec.decision, "blocked", run);
    assert.equal(rec.hold, undefined, run);
    assert.equal(r.sent.length, 0, `a blocked call that is not a save sends no notice: ${run}`);
  }
});

test("must stay as before: observe mode never holds a background run's other call", async () => {
  const r = registered({ pluginConfig: { mode: "observe" } });
  await r.command("sentrook-notify", "here");
  otherReview();
  const { out, rec } = await r.save("review", OTHER);
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed");
  assert.equal(rec.hold, undefined);
  assert.equal(r.sent.length, 0);
});

test("must stay as before: the same call in an owner's chat still asks", async () => {
  const r = registered();
  const ctx = { sessionKey: "agent:main:main", sessionId: "S1", agentId: "main", runId: "r1", trigger: "user", requester: { senderIsOwner: true, channel: "webchat" } };
  await r.fire("before_prompt_build", { runId: "r1", prompt: "list the skills", currentUserMessage: "list the skills" }, ctx);
  otherReview();
  const out = await r.fire("before_tool_call", { ...OTHER, toolCallId: "o1", runId: "r1" }, ctx);
  assert.ok(out?.requireApproval, "asked");
  assert.equal(r.records("scan").at(-1).decision, "review_timed_out");
});

test("must hold: a review run's exec the scanner reads as a save is one of the run's saves, never asked", async () => {
  for (const [cell, decision] of [["strict", "held"], ["lenient", "held"], ["block", "blocked"]] as const) {
    const r = registered();
    setVerdict(cell);
    const { out, rec } = await r.save("review", { toolName: "exec", params: { command: "cat > a/SKILL.md <<'EOF'\nx\nEOF" } });
    assert.equal(out?.requireApproval, undefined, cell);
    assert.equal(out?.block, true, cell);
    // an exec carries no content a draft could keep, and the plugin never lets one through as lenient
    assert.equal(out?.params, undefined, cell);
    assert.equal(rec.decision, decision, cell);
    assert.deepEqual(rec.background_save, { kind: "background_review", store: "skills" }, cell);
    assert.equal(rec.skill_review, true, cell);
  }
});

test("notice texts: fixed words, the run, the call as a card shows it, and the why id", () => {
  const resp = { ...BASE, ...VERDICTS.block } as any;
  const where = hold.whereText(bg.RUN_LABELS.memory_flush, "s_0123abcd");
  const text = bg.noticeText("blocked", resp, "write", "memory", where, "3f9c2a1b-1111-2222-3333-444455556666", false);
  assert.equal(
    text,
    [
      "Sentrook blocked one of OpenClaw's background saves; it did not run and was not kept.",
      "Run: memory flush before compaction, session s_0123abcd",
      "Save memory note: Saves the skill deploy-staging (write)",
      "Blocked because it changes the agent's own setup, such as its configuration, memory, plugins, skills or scheduled jobs.",
      "For the reasons: /sentrook-why 3f9c2a1b",
      "More blocked saves in this run are not announced for 6 hours.",
    ].join("\n"),
  );
  const marked = { ...resp, entities: { E1: { kind: "skill", display: "[click](https://x.example) @everyone" } } };
  const drafted = bg.noticeText("drafted", marked, "skill_workshop", "skills", where, "3f9c2a1b", true);
  assert.ok(!/[[\]()<>|@`]/.test(drafted.split("\n")[2]!.replace(/\(skill_workshop\)$/, "")), "chat markup taken out");
  assert.match(drafted, /from this job are not announced/);
  assert.match(drafted, /\/learn drafts/);
  assert.equal(scanFailure.QUIET_MS, 6 * 3600_000);
});

test("atLeast reads OpenClaw's calendar versions", () => {
  assert.equal(bg.atLeast("2026.11.5"), true);
  assert.equal(bg.atLeast("v2026.11.5"), true);
  assert.equal(bg.atLeast("2026.11.10"), true);
  assert.equal(bg.atLeast("2026.11.4"), false);
  assert.equal(bg.atLeast("2026.11.5-beta.1"), false);
  assert.equal(bg.atLeast("2026.11"), false);
  assert.equal(bg.atLeast(""), false);
  assert.equal(bg.atLeast(undefined), false);
});

// ---- only saves whose content the scan read are let through; the model's own drafts -----------------------------

const UNREAD_ACTIONS = [
  { action: "restore", name: "deploy-staging", version: "v1" },
  { action: "archive", name: "security-checks", reason: "merged" },
  { action: "remove_file", name: "deploy-staging", file_path: "scripts/check.sh" },
  { action: "apply", name: "deploy-staging", draft_id: "d-1" },
  { action: "delete", name: "deploy-staging" },
];

for (const params of UNREAD_ACTIONS) {
  test(`must hold: a lenient skill_workshop ${params.action} (no content the scan read) is held, not let through`, async () => {
    const r = registered();
    await r.command("sentrook-notify", "here");
    setVerdict("lenient");
    const { out, rec } = await r.save("review", { toolName: "skill_workshop", params });
    assert.deepEqual(out, { block: true, blockReason: bg.HELD_TEXT });
    assert.equal(rec.decision, "held");
    assert.equal(rec.lenient, undefined);
    assert.match(r.sent[0].text, /^Sentrook held one of OpenClaw's background saves/);
  });
}

test("must stay as before: content-less skill_workshop actions still run on an allow and are blocked on a block", async () => {
  const r = registered();
  setVerdict("allow");
  assert.equal((await r.save("review", { toolName: "skill_workshop", params: UNREAD_ACTIONS[0]! })).out, undefined);
  setVerdict("block");
  assert.equal((await r.save("review", { toolName: "skill_workshop", params: UNREAD_ACTIONS[0]! })).rec.decision, "blocked");
});

const READ_SAVES: Array<[keyof typeof RUNS, { toolName: string; params: Record<string, unknown> }]> = [
  ["review", { toolName: "skill_workshop", params: { action: "create", name: "deploy-staging", content: SKILL } }],
  ["review", { toolName: "skill_workshop", params: { action: " Patch ", name: "deploy-staging", old_text: "a", new_text: "b" } }],
  ["review", { toolName: "skill_workshop", params: { action: "write_file", name: "deploy-staging", file_path: "scripts/run.sh", content: "echo" } }],
  ["review", { toolName: "skill_workshop", params: { action: "draft", name: "deploy-staging", content: SKILL } }],
  ["curator", { toolName: "write", params: { path: "deploy-staging/SKILL.md", content: SKILL } }],
  ["curator", { toolName: "edit", params: { path: "deploy-staging/SKILL.md", oldText: "a", newText: "b" } }],
  ["curator", { toolName: "apply_patch", params: { input: "*** Begin Patch\n*** Update File: deploy-staging/SKILL.md\n@@\n-a\n+b\n*** End Patch" } }],
  ["flush", SAVES.flush],
];

for (const [run, call] of READ_SAVES) {
  test(`must allow: a lenient ${call.toolName} ${String(call.params.action ?? "").trim()} in the ${run} is let through`, async () => {
    const r = registered();
    setVerdict("lenient");
    const { out, rec } = await r.save(run, call);
    assert.equal(out, undefined);
    assert.equal(rec.decision, "allowed");
    assert.equal(rec.lenient, true);
  });
}

test("must allow as a draft: the model's own skill_workshop draft in the review band runs as a draft, announced once kept", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const call = { toolName: "skill_workshop", params: { action: "draft", name: "deploy-staging", content: SKILL } };
  const { out, rec } = await r.save("review", call);
  assert.equal(out, undefined, "runs as the model asked: a draft does nothing until the owner applies it");
  assert.equal(rec.decision, "drafted");
  assert.equal(r.sent.length, 0, "nothing before the host has run the draft");
  const { ctx } = RUNS.review;
  await r.fire("after_tool_call", { ...call, toolCallId: "t1", runId: ctx.runId, ...DRAFT_KEPT }, ctx);
  await hold.waitForNotices();
  assert.equal(r.sent.length, 1);
  assert.match(r.sent[0].text, /as a Skill Workshop draft/);
  assert.match(history(), /drafted \(self-edit\) +in drafts$/m);
});

test("must hold: the model's own draft on a block-level score capped at review is held, and blocked on a block or an enforced block", async () => {
  const call = { toolName: "skill_workshop", params: { action: "draft", name: "deploy-staging", content: SKILL } };
  const r = registered();
  reply = { ...VERDICTS.block, ceiling: "review", reasons: [{ code: "cap.unanswered_retry" }] };
  const capped = await r.save("review", call);
  assert.deepEqual(capped.out, { block: true, blockReason: bg.HELD_TEXT });
  assert.equal(capped.rec.decision, "held");
  setVerdict("block");
  assert.equal((await r.save("review", call)).rec.decision, "blocked");
  reply = { ...VERDICTS.strict, risk: 30, enforced: "block" };
  assert.equal((await r.save("review", call)).rec.decision, "blocked");
});

// ---- the host ran the save live instead of the draft ------------------------------------------------------------

const CREATED_LIVE = {
  result: { content: [{ type: "text", text: 'Created "deploy-staging" (new). Undo with action=archive name=deploy-staging.' }], details: {} },
};

test("a create OpenClaw ran live instead of the draft is recorded as saved live and announced as such, not as not saved", async () => {
  const r = registered();
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const { out, rec } = await r.save("review", SAVES.review, null);
  assert.equal(out.params.action, "draft");
  const { ctx } = RUNS.review;
  // the host passed the call's own parameters on: the rewrite was not applied
  await r.fire("after_tool_call", { ...SAVES.review, toolCallId: "t1", runId: ctx.runId, ...CREATED_LIVE }, ctx);
  await hold.waitForNotices();
  const [resolution] = r.records("resolution");
  assert.equal(resolution.request_id, rec.request_id);
  assert.equal(resolution.resolution, "draft_ignored");
  const [scan, res] = recentScans(path.join(stateDir, "traffic.jsonl"), 1)[0]!;
  assert.equal(actionOf(scan, res), "saved live (draft ignored, self-edit)");
  assert.doesNotMatch(history(), /not saved/);
  assert.equal(r.sent.length, 1);
  assert.match(r.sent[0].text, /^Sentrook sent a new skill .* but OpenClaw saved it as a live skill instead/);
  assert.doesNotMatch(r.sent[0].text, /not made|not saved/);
  assert.ok(!withoutCall(r.sent[0].text).includes(BODY_MARKER));
  setVerdict("allow");
  const next = await r.save("review", { toolName: "skill_workshop", params: { action: "list" } });
  assert.equal(next.planir.history.at(-1).decision, "allowed", "the scanner is told the save ran");
  const status = await runSentrookCommand("status", { pluginConfig: {}, env: process.env });
  assert.match(status, /1 saved live \(draft ignored\)/);
});

test("with no params on after_tool_call the draft is judged by its result as before", async () => {
  const r = registered();
  setVerdict("strict");
  await r.save("review", SAVES.review, null);
  const { ctx } = RUNS.review;
  await r.fire("after_tool_call", { toolName: "skill_workshop", toolCallId: "t1", runId: ctx.runId, ...DRAFT_KEPT }, ctx);
  assert.equal(r.records("resolution")[0].resolution, "draft_saved");
});

// ---- what a background hold tells the agent ---------------------------------------------------------------------

test("a background hold tells the agent the save was not made, the owner was told, and not to retry; it never offers approval", async () => {
  assert.notEqual(bg.HELD_TEXT, hold.HELD_TEXT);
  assert.match(bg.HELD_TEXT, /not saved/);
  assert.match(bg.HELD_TEXT, /owner has been told/);
  assert.match(bg.HELD_TEXT, /Do not retry/);
  assert.doesNotMatch(bg.HELD_TEXT, /approv/i);
  const r = registered();
  setVerdict("strict");
  assert.equal((await r.save("flush")).out.blockReason, bg.HELD_TEXT);
});

// ---- patches: a target outside the store is never a save --------------------------------------------------------

for (const indent of ["  ", "\t", "  "]) {
  test(`must not declare a save: a curator patch with an indented (${JSON.stringify(indent)}) header outside the store`, async () => {
    const r = registered();
    setVerdict("lenient");
    const input = `*** Begin Patch\n*** Add File: deploy-staging/SKILL.md\n+x\n${indent}*** Add File: /home/node/.openclaw/hooks/x.js\n+y\n*** End Patch`;
    const { rec, planir } = await r.save("curator", { toolName: "apply_patch", params: { input } });
    assert.equal(rec.background_save, undefined);
    assert.equal(rec.lenient, undefined);
    assert.equal(planir.self_edit, undefined);
  });
}

// ---- a held patch of a skill's SKILL.md becomes a draft of the patched skill (OpenClaw 2026.11.5 or newer) ---------

/** The skill as it is live before the review patches it. */
const LIVE = "---\nname: deploy-staging\ndescription: Deploy to staging\n---\n1. Run make deploy-staging.\n2. Check the health page.\n";
const OLD = "2. Check the health page.";
const NEW = `2. Check the health page, then the logs. ${BODY_MARKER}`;
const PATCH = { action: "patch", name: "deploy-staging", old_text: OLD, new_text: NEW, reason: "tightened the check" };
const PATCHED = LIVE.replace(OLD, () => NEW);
const patchCall = (params: Record<string, unknown> = {}) => ({ toolName: "skill_workshop", params: { ...PATCH, ...params } });

/** A temporary agent dir holding the live skill; `resolveAgentDir` as 2026.11.5 offers it, recording its arguments. */
function agentHome(content: string | null = LIVE) {
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-agent-"));
  const skillDir = path.join(dir, "workshop-skills", "deploy-staging");
  mkdirSync(skillDir, { recursive: true });
  if (content !== null) writeFileSync(path.join(skillDir, "SKILL.md"), content);
  const calls: unknown[][] = [];
  const agent = {
    resolveAgentDir: (cfg: unknown, agentId: unknown) => {
      calls.push([cfg, agentId]);
      return dir;
    },
  };
  return { dir, skillDir, file: path.join(skillDir, "SKILL.md"), agent, calls };
}

const HELD = { block: true, blockReason: bg.HELD_TEXT };
const REASON = /^Held by Sentrook \(scan [0-9a-f]{8}\) for your review: the skill as it stood at \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC, with one change applied\.$/;

test("must draft: a reviewed background patch of SKILL.md matching once becomes a draft of the live skill with the patch applied", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall(), null);
  assert.deepEqual(Object.keys(out), ["params"]);
  assert.deepEqual(Object.keys(out.params), ["action", "name", "content", "reason"]);
  assert.equal(out.params.action, "draft");
  assert.equal(out.params.name, "deploy-staging");
  assert.equal(out.params.content, PATCHED);
  assert.match(out.params.reason, REASON);
  assert.ok(out.params.reason.includes(`(scan ${rec.request_id.slice(0, 8)})`), "the id /sentrook-why takes");
  assert.ok(out.params.reason.length <= 200, "a bounded reason");
  assert.ok(!out.params.reason.includes("tightened"), "nothing the saving model wrote in the reason");
  assert.equal(rec.decision, "drafted");
  assert.equal(rec.patch_draft, "drafted");
  assert.deepEqual(home.calls, [[HOST_CONFIG, "main"]], "the live config and the run's agent");
  assert.equal(readFileSync(home.file, "utf8"), LIVE, "the live skill is untouched");
  assert.equal(r.sent.length, 0, "nothing before the host has run the draft");
  assert.ok(!JSON.stringify(r.records("scan")).includes("Run make deploy-staging"), "the live file never reaches the traffic log");
  const { ctx } = RUNS.review;
  await r.fire("after_tool_call", { toolName: "skill_workshop", toolCallId: "t1", runId: ctx.runId, params: { ...PATCH, ...out.params }, ...DRAFT_KEPT }, ctx);
  await hold.waitForNotices();
  assert.equal(r.records("resolution")[0].resolution, "draft_saved");
  assert.match(history(), /drafted \(self-edit\) +in drafts$/m);
  assert.equal(r.sent.length, 1);
  const text: string = r.sent[0].text;
  assert.match(text, /^Sentrook saved a change to an existing skill from one of OpenClaw's background runs as a Skill Workshop draft/);
  assert.match(text, /the Skill Workshop drafts in the Control UI, or \/learn drafts in a chat with the agent/);
  assert.match(text, /Applying it replaces the skill with the version from when the change was held, with this one change: any later change to that skill would be undone\. It can be brought back from the skill's history\./);
  assert.ok(!withoutCall(text).includes(BODY_MARKER) && !text.includes("Run make deploy-staging"), "never the saved body");
});

for (const [name, params, want] of [
  ["file_path SKILL.md", { file_path: "SKILL.md" }, PATCHED],
  ["file_path with spaces around SKILL.md", { file_path: " SKILL.md " }, PATCHED],
  ["a blank file_path", { file_path: "  " }, PATCHED],
  ["no new_text (the host deletes the old text)", { new_text: undefined }, LIVE.replace(OLD, "")],
  ["a new_text with $& and $1 (inserted as written)", { new_text: "2. Check $& and $1." }, LIVE.replace(OLD, () => "2. Check $& and $1.")],
  ["a name with spaces around it (the host trims it)", { name: "  deploy-staging " }, PATCHED],
] as const) {
  test(`must draft: a patch with ${name}`, async () => {
    const home = agentHome();
    const r = registered({ agent: home.agent });
    setVerdict("strict");
    const { out, rec } = await r.save("review", patchCall(params as any));
    assert.equal(rec.decision, "drafted", name);
    assert.equal(out.params.content, want);
    assert.equal(out.params.name, "deploy-staging");
  });
}

test("must draft: line endings and whitespace are matched as written, as OpenClaw matches them", async () => {
  const crlf = LIVE.replace(/\n/g, "\r\n");
  const home = agentHome(crlf);
  const r = registered({ agent: home.agent });
  setVerdict("strict");
  const lf = await r.save("review", patchCall({ old_text: "1. Run make deploy-staging.\n2." }));
  assert.deepEqual(lf.out, HELD, "an LF old_text does not match a CRLF file");
  assert.equal(lf.rec.patch_draft, "no_match");
  const ok = await r.save("review", patchCall({ old_text: "1. Run make deploy-staging.\r\n2.", new_text: "1. Run it.\r\n2." }));
  assert.equal(ok.out.params.content, crlf.replace("1. Run make deploy-staging.\r\n2.", "1. Run it.\r\n2."));
});

for (const [name, setup, params, reason] of [
  ["old_text that does not match", null, { old_text: "3. Roll back." }, "no_match"],
  ["old_text that matches twice", `${LIVE}${OLD}\n`, {}, "several_matches"],
  ["old_text whose matches overlap (OpenClaw counts both)", `${LIVE}aaa\n`, { old_text: "aa" }, "several_matches"],
  ["an empty old_text", null, { old_text: "" }, "bad_patch"],
  ["old_text equal to new_text", null, { new_text: OLD }, "bad_patch"],
  ["old_text that is not a string", null, { old_text: 7 }, "bad_patch"],
  ["a missing SKILL.md", "missing", {}, "missing"],
  ["a name that climbs out of the Workshop", null, { name: "../deploy-staging" }, "bad_name"],
  ["an absolute name", null, { name: "/etc" }, "bad_name"],
  ["a name with a slash", null, { name: "deploy-staging/references" }, "bad_name"],
  ["a name in capitals (not a Workshop name)", null, { name: "Deploy-Staging" }, "bad_name"],
] as const) {
  test(`must hold: a patch with ${name}`, async () => {
    const home = agentHome(setup === "missing" ? null : (setup ?? LIVE));
    const r = registered({ agent: home.agent });
    await r.command("sentrook-notify", "here");
    setVerdict("strict");
    const { out, rec } = await r.save("review", patchCall(params as any));
    assert.deepEqual(out, HELD);
    assert.equal(rec.decision, "held");
    assert.equal(rec.patch_draft, reason);
    assert.match(r.sent[0].text, /^Sentrook held one of OpenClaw's background saves/);
    if (setup !== "missing") assert.equal(readFileSync(home.file, "utf8"), setup ?? LIVE);
  });
}

test("must hold: a symlinked skill folder that leads out of the Workshop", async () => {
  const home = agentHome(null);
  const outside = mkdtempSync(path.join(tmpdir(), "sentrook-outside-"));
  writeFileSync(path.join(outside, "SKILL.md"), LIVE);
  rmSync(home.skillDir, { recursive: true });
  symlinkSync(outside, home.skillDir);
  const r = registered({ agent: home.agent });
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall());
  assert.deepEqual(out, HELD);
  assert.equal(rec.patch_draft, "outside");
});

test("must hold: a SKILL.md that is a symlink, to a file outside or inside the Workshop", async () => {
  for (const inside of [false, true]) {
    const home = agentHome(null);
    const target = inside ? path.join(home.skillDir, "references.md") : path.join(mkdtempSync(path.join(tmpdir(), "sentrook-outside-")), "SKILL.md");
    writeFileSync(target, LIVE);
    symlinkSync(target, home.file);
    const r = registered({ agent: home.agent });
    setVerdict("strict");
    const { out, rec } = await r.save("review", patchCall());
    assert.deepEqual(out, HELD, inside ? "inside" : "outside");
    assert.equal(rec.patch_draft, "outside");
  }
});

test("must hold: a SKILL.md with another hard link (OpenClaw refuses to read it)", async () => {
  const home = agentHome();
  linkSync(home.file, path.join(mkdtempSync(path.join(tmpdir(), "sentrook-outside-")), "copy.md"));
  const r = registered({ agent: home.agent });
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall());
  assert.deepEqual(out, HELD);
  assert.equal(rec.patch_draft, "not_file");
});

test("must hold: a SKILL.md that is a folder", async () => {
  const home = agentHome(null);
  mkdirSync(home.file);
  const r = registered({ agent: home.agent });
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall());
  assert.deepEqual(out, HELD);
  assert.equal(rec.patch_draft, "not_file");
});

test("must hold: a live SKILL.md larger than OpenClaw reads", async () => {
  const home = agentHome(`${LIVE}${"x".repeat(bg.MAX_SKILL_FILE_BYTES)}`);
  const r = registered({ agent: home.agent });
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall());
  assert.deepEqual(out, HELD);
  assert.equal(rec.patch_draft, "too_large");
  const fits = agentHome(`${LIVE}${"x".repeat(bg.MAX_SKILL_FILE_BYTES - Buffer.byteLength(LIVE))}`);
  const r2 = registered({ agent: fits.agent });
  assert.equal((await r2.save("review", patchCall())).rec.decision, "drafted", "exactly at the bound still drafts");
});

for (const [name, agent, ctxPatch] of [
  ["no runtime.agent", undefined, {}],
  ["no resolveAgentDir", {}, {}],
  ["a resolveAgentDir that throws", { resolveAgentDir: () => { throw new Error("no such agent"); } }, {}],
  ["a resolveAgentDir that returns nothing", { resolveAgentDir: () => undefined }, {}],
  ["a resolveAgentDir that returns a relative path", { resolveAgentDir: () => "agents/main/agent" }, {}],
  ["no agentId on the hook context", "home", { agentId: undefined }],
] as const) {
  test(`must hold: a patch with ${name}`, async () => {
    const home = agentHome();
    const r = registered({ agent: agent === "home" ? home.agent : (agent as any) });
    await r.command("sentrook-notify", "here");
    setVerdict("strict");
    const ctx: Record<string, any> = { ...RUNS.review.ctx, ...ctxPatch };
    await r.fire("before_prompt_build", { runId: ctx.runId, prompt: RUNS.review.prompt, messages: TRANSCRIPT }, ctx);
    const out = await r.fire("before_tool_call", { ...patchCall(), toolCallId: "p1", runId: ctx.runId }, ctx);
    await hold.waitForNotices();
    assert.deepEqual(out, HELD);
    const rec = r.records("scan").at(-1);
    assert.equal(rec.decision, "held");
    assert.equal(rec.patch_draft, "no_agent_dir");
    assert.equal(r.sent.length, 1);
  });
}

for (const [name, params, reason] of [
  ["a support file", { file_path: "references/notes.md" }, "support_file"],
  ["./SKILL.md (OpenClaw reads it as a support file path and refuses it)", { file_path: "./SKILL.md" }, "support_file"],
  ["the action in capitals (OpenClaw does not know it)", { action: "Patch" }, undefined],
] as const) {
  test(`must hold: a patch of ${name}`, async () => {
    const home = agentHome();
    const r = registered({ agent: home.agent });
    setVerdict("strict");
    const { out, rec } = await r.save("review", patchCall(params as any));
    assert.deepEqual(out, HELD);
    assert.equal(rec.patch_draft, reason);
  });
}

test("must hold: a patch when the scan says the saved text adds a secret; the new skill and the model's own draft too", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  reply = { ...VERDICTS.strict, self_edit: { adds: ["command", "secret"], lenient: false } };
  const patch = await r.save("review", patchCall());
  assert.deepEqual(patch.out, HELD);
  assert.equal(patch.rec.patch_draft, "secret");
  // the existing new-skill drafts: a draft would keep the secret just the same
  for (const call of [
    SAVES.review,
    { toolName: "skill_workshop", params: { action: "write_file", name: "deploy-staging", file_path: "SKILL.md", content: SKILL } },
    { toolName: "skill_workshop", params: { action: "draft", name: "deploy-staging", content: SKILL } },
  ]) {
    const { out, rec } = await r.save("review", call);
    assert.deepEqual(out, HELD, String(call.params.action));
    assert.equal(rec.decision, "held");
  }
  assert.equal(readFileSync(home.file, "utf8"), LIVE);
});

test("must hold: a patch whose response has no self_edit (or no adds list); a new skill still drafts there as before", async () => {
  for (const self_edit of [undefined, null, {}, { adds: "secret" }, { lenient: false }]) {
    const home = agentHome();
    const r = registered({ agent: home.agent });
    reply = { ...VERDICTS.strict, self_edit };
    const { out, rec } = await r.save("review", patchCall());
    assert.deepEqual(out, HELD, JSON.stringify(self_edit));
    assert.equal(rec.patch_draft, "no_self_edit");
    if (self_edit === undefined) assert.equal((await r.save("review")).rec.decision, "drafted");
  }
});

test("must hold: with skillReview review (no self_edit is asked for) a patch is held", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent, pluginConfig: { skillReview: "review" } });
  setVerdict("strict");
  const { out, rec, planir } = await r.save("review", patchCall());
  assert.equal(planir.self_edit, undefined);
  assert.deepEqual(out, HELD);
  assert.equal(rec.patch_draft, "no_self_edit");
});

test("must block or hold: a patch on a block, an enforced block, or a block-level score capped at review", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  setVerdict("block");
  assert.equal((await r.save("review", patchCall())).rec.decision, "blocked");
  reply = { ...VERDICTS.strict, risk: 30, enforced: "block" };
  assert.equal((await r.save("review", patchCall())).rec.decision, "blocked");
  reply = { ...VERDICTS.block, ceiling: "review", reasons: [{ code: "cap.unanswered_retry" }], self_edit: { adds: ["command"], lenient: false } };
  const capped = await r.save("review", patchCall());
  assert.deepEqual(capped.out, HELD);
  assert.equal(capped.rec.verdict, "review");
  assert.equal(capped.rec.decision, "held");
  assert.equal(readFileSync(home.file, "utf8"), LIVE);
});

test("must draft as a create does: a review the scanner enforces (a rule floor) below the block line", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  reply = { ...VERDICTS.strict, enforced: "review" };
  assert.equal((await r.save("review")).rec.decision, "drafted", "a new skill");
  assert.equal((await r.save("review", patchCall())).rec.decision, "drafted", "a patch, the same");
});

test("must hold: a block-level retry after a patch draft stays held and is announced", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  assert.equal((await r.save("review", patchCall())).rec.decision, "drafted");
  reply = { ...VERDICTS.block, ceiling: "review", reasons: [{ code: "cap.unanswered_retry" }], self_edit: { adds: ["command"], lenient: false } };
  const retry = await r.save("review", patchCall());
  assert.equal(retry.planir.history.at(-1).decision, "review_timed_out");
  assert.deepEqual(retry.out, HELD, "never a second draft");
  assert.deepEqual(retry.rec.hold.notice, { status: "queued", target: "telegram" });
});

for (const version of ["2026.11.4", "2026.11.5-beta.1", null]) {
  test(`must hold: a patch on OpenClaw ${version ?? "of unknown version"}, with the agent dir there`, async () => {
    const home = agentHome();
    const r = registered({ agent: home.agent, version });
    setVerdict("strict");
    const { out, rec } = await r.save("review", patchCall());
    assert.deepEqual(out, HELD);
    assert.equal(rec.patch_draft, undefined, "not tried");
    assert.deepEqual(home.calls, [], "the agent dir is not even looked up");
  });
}

test("a patch draft OpenClaw ignored (the patch went live) is recorded and announced as saved live", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const { rec } = await r.save("review", patchCall(), null);
  const { ctx } = RUNS.review;
  await r.fire(
    "after_tool_call",
    {
      ...patchCall(),
      toolCallId: "t1",
      runId: ctx.runId,
      result: { content: [{ type: "text", text: 'Patched "deploy-staging" (patched SKILL.md). Saved previous version; undo with action=restore name=deploy-staging.' }], details: {} },
    },
    ctx,
  );
  await hold.waitForNotices();
  const [resolution] = r.records("resolution");
  assert.equal(resolution.request_id, rec.request_id);
  assert.equal(resolution.resolution, "draft_ignored");
  assert.match(history(), /saved live \(draft ignored, self-edit\)/);
  assert.equal(r.sent.length, 1);
  const text: string = r.sent[0].text;
  assert.match(text, /^Sentrook sent a change to an existing skill .* to the Skill Workshop drafts, but OpenClaw applied the change to the live skill instead/);
  assert.match(text, /To undo it, restore the skill's previous version from its history on Plugins → Skill workshop in the Control UI/);
  assert.ok(!withoutCall(text).includes(BODY_MARKER));
});

test("a patch draft OpenClaw did not keep is recorded and announced as not made", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  await r.save("review", patchCall(), DRAFT_REFUSED);
  assert.equal(r.records("resolution")[0].resolution, "draft_failed");
  assert.match(history(), /not saved \(draft refused, self-edit\)/);
  assert.match(r.sent[0].text, /^Sentrook sent a change to an existing skill .* but OpenClaw did not keep the draft, so the change was not made/);
  assert.equal(readFileSync(home.file, "utf8"), LIVE);
});

test("a patch draft has its own quiet key: the staleness note is not silenced by a new skill's draft notice", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  await r.save("review");
  await r.save("review", patchCall());
  assert.equal(r.sent.length, 2, "one new-skill draft notice, one patch draft notice");
  assert.match(r.sent[1].text, /any later change to that skill would be undone/);
  assert.doesNotMatch(r.sent[1].text, /drafts of this skill/, "the first draft of the skill");
  assert.match(r.sent[1].text, /^Each change sent to the drafts from this run is announced, up to 5 in 6 hours\.$/m);
});

test("must announce: a second draft of the same skill in one run is announced, with how many drafts of it the run made", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const first = await r.save("review", patchCall());
  const second = await r.save("review", patchCall({ old_text: "1. Run make deploy-staging.", new_text: "1. Run it." }));
  assert.equal(r.sent.length, 2, "both drafts announced");
  assert.match(r.sent[1].text, /^This run has now saved 2 drafts of this skill, each holding only its own change: applying them one after another keeps only the last one's change\. Apply one, or combine them with \/learn drafts\. Each draft's note names its scan\.$/m);
  assert.notEqual(first.out.params.reason, second.out.params.reason, "the two drafts' notes differ");
  assert.ok(second.out.params.reason.includes(second.rec.request_id.slice(0, 8)));
  // another skill's draft counts for the run, not for this skill
  setVerdict("allow");
  const next = await r.save("review", { toolName: "skill_workshop", params: { action: "list" } });
  assert.ok(next.planir.history.every((h: any) => h._patch_skill === undefined), "plugin bookkeeping is stripped");
});

test("flood control: at most five patch-draft notices per run, the fifth says further ones are not announced", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  await r.command("sentrook-notify", "here");
  setVerdict("strict");
  const recs = [];
  for (let i = 0; i < 7; i++) recs.push((await r.save("review", patchCall())).rec);
  assert.ok(recs.every((x) => x.decision === "drafted"));
  assert.equal(r.sent.length, 5);
  assert.match(r.sent[4].text, /^This run has now saved 5 drafts of this skill/m);
  assert.match(r.sent[4].text, /^Further changes sent to drafts from this run are not announced for 6 hours; the Skill Workshop drafts list them all\.$/m);
  const notices = r.records("resolution").map((x) => x.notice.status);
  assert.deepEqual(notices, ["queued", "queued", "queued", "queued", "queued", "quiet", "quiet"]);
  assert.equal(bg.quietKey("drafted", null, "s_ab", true, 3), "background_drafted_patch:session:s_ab#3");
});

test("observe mode never rewrites a patch", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent, pluginConfig: { mode: "observe" } });
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall());
  assert.equal(out, undefined);
  assert.equal(rec.decision, "allowed");
  assert.deepEqual(home.calls, []);
});

test("must stay as before: an owner's own patch in a chat still asks, never rewritten", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  const ctx = { sessionKey: "agent:main:main", sessionId: "S1", agentId: "main", runId: "r1", trigger: "user", requester: { senderIsOwner: true, channel: "webchat" } };
  await r.fire("before_prompt_build", { runId: "r1", prompt: "fix the skill", currentUserMessage: "fix the skill" }, ctx);
  setVerdict("strict");
  const out = await r.fire("before_tool_call", { ...patchCall(), toolCallId: "o1", runId: "r1" }, ctx);
  assert.ok(out?.requireApproval);
  assert.equal(out.params, undefined);
  assert.deepEqual(home.calls, []);
});

test("must stay as before: a lenient patch is let through, an allowed patch runs, neither reads the live file", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  setVerdict("lenient");
  assert.equal((await r.save("review", patchCall())).out, undefined);
  setVerdict("allow");
  assert.equal((await r.save("review", patchCall())).out, undefined);
  assert.deepEqual(home.calls, []);
});

test("held notices say where the owner can act: archive and restore on the Skill Workshop page, a support file removal there too", () => {
  const resp = { ...BASE, ...VERDICTS.strict } as any;
  const where = hold.whereText(bg.RUN_LABELS.background_review, "s_0123abcd");
  const text = (action: string) => bg.noticeText("held", resp, "skill_workshop", "skills", where, "3f9c2a1b", false, false, action);
  assert.match(text("archive"), /^To archive it yourself: Archive on the skill, on Plugins → Skill workshop in the Control UI\.$/m);
  assert.match(text("restore"), /^To restore it yourself: the skill's history, on Plugins → Skill workshop in the Control UI\.$/m);
  assert.match(text("remove_file"), /^The skill and its support files are on Plugins → Skill workshop in the Control UI; to remove the file, ask the agent for it in a chat\.$/m);
  for (const action of ["patch", "create", ""]) {
    assert.doesNotMatch(text(action), /Plugins → Skill workshop/, action);
    assert.match(text(action), /^To keep it, ask the agent for it in a chat\./m, action);
  }
  assert.doesNotMatch(bg.noticeText("held", resp, "write", "memory", where, null, false, false, "archive"), /Skill workshop/, "a file tool has no Workshop action");
});

test("applyPatch mirrors OpenClaw: exactly one occurrence, overlapping ones counted, the replacement inserted as written", () => {
  assert.deepEqual(bg.applyPatch("a-b-c", "-b-", "+"), { content: "a+c" });
  assert.deepEqual(bg.applyPatch("abc", "x", "y"), { skip: "no_match" });
  assert.deepEqual(bg.applyPatch("a b a", "a", "y"), { skip: "several_matches" });
  assert.deepEqual(bg.applyPatch("aaa", "aa", "b"), { skip: "several_matches" });
  assert.deepEqual(bg.applyPatch("x", "x", "$&$&"), { content: "$&$&" });
  assert.deepEqual(bg.applyPatch("x", "", "y"), { skip: "bad_patch" });
  assert.deepEqual(bg.applyPatch("x", "x", "x"), { skip: "bad_patch" });
});

test("patchDraftReason: fixed words and the UTC minute the skill was read", () => {
  assert.equal(
    bg.patchDraftReason(new Date("2026-11-19T20:15:42.123Z"), "3f9c2a1b-1111-2222-3333-444455556666"),
    "Held by Sentrook (scan 3f9c2a1b) for your review: the skill as it stood at 2026-11-19 20:15 UTC, with one change applied.",
  );
  assert.match(bg.patchDraftReason(new Date(), "<b>x</b>"), /^Held by Sentrook \(scan bb\) /, "only hex digits from the id");
  assert.match(bg.patchDraftReason(new Date(), "zz"), /^Held by Sentrook \(scan unknown\) /);
});

// ---- the review round: what readLiveSkill refuses on its own, and what is never looked up --------------------------

test("must hold, promptly: a SKILL.md that is a FIFO is never opened (it would block the gateway)", { timeout: 10_000 }, async () => {
  const home = agentHome(null);
  execFileSync("mkfifo", [home.file]);
  const started = Date.now();
  assert.deepEqual(bg.readLiveSkill(home.dir, "deploy-staging"), { skip: "not_file" });
  const r = registered({ agent: home.agent });
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall());
  assert.deepEqual(out, HELD);
  assert.equal(rec.patch_draft, "not_file");
  assert.ok(Date.now() - started < 5_000);
});

test("must hold: a skill folder swapped for a link between the check and the open is refused", () => {
  const home = agentHome();
  const other = mkdtempSync(path.join(tmpdir(), "sentrook-other-agent-"));
  writeFileSync(path.join(other, "SKILL.md"), LIVE.replace("2. Check", "OTHER AGENT 2. Check"));
  const fs = createRequire(import.meta.url)("node:fs");
  const real = fs.realpathSync;
  let calls = 0;
  fs.realpathSync = function (this: unknown, p: any, ...rest: any[]) {
    const out = real.call(this, p, ...rest);
    // after the file's own containment check, the folder is replaced by a link to another agent's skill
    if (++calls === 2) {
      renameSync(home.skillDir, `${home.skillDir}-moved`);
      symlinkSync(other, home.skillDir);
    }
    return out;
  };
  syncBuiltinESMExports();
  try {
    assert.deepEqual(bg.readLiveSkill(home.dir, "deploy-staging"), { skip: "outside" });
  } finally {
    fs.realpathSync = real;
    syncBuiltinESMExports();
  }
  assert.ok(calls >= 2, "containment is confirmed after the open");
});

test("readLiveSkill decides on the open file: a folder, a FIFO and a link named SKILL.md are refused, a missing one is missing", { timeout: 10_000 }, () => {
  const folder = agentHome(null);
  mkdirSync(folder.file);
  assert.deepEqual(bg.readLiveSkill(folder.dir, "deploy-staging"), { skip: "not_file" });
  const fifo = agentHome(null);
  execFileSync("mkfifo", [fifo.file]);
  assert.deepEqual(bg.readLiveSkill(fifo.dir, "deploy-staging"), { skip: "not_file" }, "opens at once and is refused");
  const link = agentHome(null);
  symlinkSync("/dev/null", link.file);
  assert.deepEqual(bg.readLiveSkill(link.dir, "deploy-staging"), { skip: "outside" }, "a link to a device is never followed");
  assert.deepEqual(bg.readLiveSkill(agentHome(null).dir, "deploy-staging"), { skip: "missing" });
});

test("readLiveSkill confines on its own: a name that climbs out, is absolute or has a slash is refused", () => {
  const home = agentHome();
  writeFileSync(path.join(home.dir, "SKILL.md"), LIVE);
  for (const name of ["../x", "..", "../workshop-skills/deploy-staging", "/etc", "deploy-staging/../deploy-staging", "a/b", ""]) {
    assert.deepEqual(bg.readLiveSkill(home.dir, name), { skip: "bad_name" }, name);
  }
  assert.deepEqual(bg.readLiveSkill(home.dir, "deploy-staging"), { live: LIVE });
});

test("must hold: a live SKILL.md that is not valid UTF-8 (the draft would change more than the one change)", async () => {
  const home = agentHome();
  writeFileSync(home.file, Buffer.concat([Buffer.from(LIVE), Buffer.from([0xff, 0xfe, 0x0a])]));
  const r = registered({ agent: home.agent });
  setVerdict("strict");
  const { out, rec } = await r.save("review", patchCall());
  assert.deepEqual(out, HELD);
  assert.equal(rec.patch_draft, "not_utf8");
  const ok = agentHome(`${LIVE}Ünïcödé ✓ 🪶\n`);
  const r2 = registered({ agent: ok.agent });
  assert.equal((await r2.save("review", patchCall())).out.params.content, `${PATCHED}Ünïcödé ✓ 🪶\n`, "valid UTF-8 drafts");
});

test("a blocked or capped patch never looks up the agent dir", async () => {
  const home = agentHome();
  const r = registered({ agent: home.agent });
  setVerdict("block");
  assert.equal((await r.save("review", patchCall())).rec.decision, "blocked");
  reply = { ...VERDICTS.block, ceiling: "review", reasons: [{ code: "cap.unanswered_retry" }], self_edit: { adds: ["command"], lenient: false } };
  assert.equal((await r.save("review", patchCall())).rec.decision, "held");
  assert.deepEqual(home.calls, []);
});

test("documents current behaviour: with no self_edit in the response, a new skill drafts whatever it holds (only OpenClaw's own check applies)", async () => {
  const r = registered();
  reply = { ...VERDICTS.strict, self_edit: undefined };
  const call = { toolName: "skill_workshop", params: { action: "create", name: "deploy-staging", content: `${SKILL}\ntoken: <REDACTED:api_key>\n` } };
  const { out, rec } = await r.save("review", call);
  assert.equal(rec.decision, "drafted");
  assert.equal(out.params.action, "draft");
});
