/**
 * Background saves: OpenClaw's own skill and memory saves are never asked about, because nobody can answer a prompt
 * in those runs. Allowed saves run; blocked ones are blocked and announced; reviewed ones are let through when the
 * scanner says they are lenient, saved as Skill Workshop drafts where OpenClaw can, or held; a scan failure follows
 * the policy for unattended runs. Every outcome but a plain allow sends the owner a notice where held-call notices go.
 */

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { clearScanTokenCache } from "./auth.ts";
import * as bg from "./backgroundSave.ts";
import { runSentrookCommand } from "./commands.ts";
import { actionOf, formatHistory, recentScans } from "./history.ts";
import * as hold from "./hold.ts";
import plugin from "./index.ts";
import * as scanFailure from "./scanFailureNotice.ts";
import { runVerify } from "./verify.ts";

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
}

function registered(opts: Opts = {}) {
  const on: Record<string, any[]> = {};
  const commands: Record<string, any> = {};
  const sent: any[] = [];
  const logs: string[] = [];
  const version = opts.version === undefined ? "2026.11.5" : opts.version;
  plugin.register({
    pluginConfig: opts.pluginConfig ?? {},
    registrationMode: "full",
    config: { tools: { exec: { mode: "full" } } },
    logger: { info: () => undefined, warn: (m: string) => logs.push(m), error: (m: string) => logs.push(m) },
    on: (hook: string, h: any) => (on[hook] ??= []).push(h),
    registerCommand: (def: any) => {
      commands[def.name] = def;
    },
    runtime: {
      ...(version === null ? {} : { version }),
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
        assert.ok(!text.includes(BODY_MARKER), "nothing the saving model wrote reaches the notice");
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
    assert.ok(!r.sent[0].text.includes(BODY_MARKER));
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

test("must stay as before: a review run's own exec is not a save and keeps its prompt", async () => {
  const r = registered();
  setVerdict("strict");
  const { out, rec } = await r.save("review", { toolName: "exec", params: { command: "ls" } });
  assert.ok(out?.requireApproval);
  assert.equal(rec.background_save, undefined);
  assert.equal(rec.host_process, "background_review");
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
  assert.ok(!r.sent[0].text.includes(BODY_MARKER));
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
