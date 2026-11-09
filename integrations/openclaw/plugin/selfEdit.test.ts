import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { actionOf } from "./history.ts";
import {
  hostRequestText,
  kindAtCall,
  lastOwnerMessage,
  NO_OWNER_REQUEST,
  resolveSetting,
  runKindOf,
  saveStoreOf,
  settingText,
  statusLine,
} from "./selfEdit.ts";

const REVIEW_ID = "skill-workshop-review:61d38354-3521-487d-8018-82ea16a0fed1";
const REVIEW_KEY = "agent:main:internal-session-effects:skill-workshop-review_61d38354-3521-487d-8018-82-710cf2955ab718fb";
const FLUSH_KEY = "agent:main:internal-session-effects:0b6f1e9a-58a1-4bb3-9a43-7d0c1e2f3a4b-3f9c2d1e0a7b6c5d";
const WORKSHOP = "/home/node/.openclaw/agents/main/agent/workshop-skills";
const CRON_KEY = "agent:main:cron:6f1205d4-ee20-48f0-8159-79550aef2f58:run:81986d2e-7a26-4a61-be11-5269cfd18e97";
const CURATOR_PROMPT =
  "[cron:6f1205d4-ee20-48f0-8159-79550aef2f58 skill-collection-review-main] Review this agent's Skill Workshop as a collection.";
const REVIEW_PROMPT = "Skill review. Distill new durable learning from the full retained conversation.";

// ---- recognition --------------------------------------------------------------------------------------------------

test("must recognise the Skill Workshop review by its runId and its internal session key together", () => {
  assert.equal(runKindOf(REVIEW_ID, { sessionKey: REVIEW_KEY, trigger: "user", workspaceDir: WORKSHOP }, REVIEW_PROMPT), "background_review");
  // propose mode runs in the ordinary workspace
  assert.equal(runKindOf(REVIEW_ID, { sessionKey: REVIEW_KEY, trigger: "user", workspaceDir: "/w" }, REVIEW_PROMPT), "background_review");
});

test("must stay silent on a forged runId alone (a gateway request chooses the runId, not the session key)", () => {
  assert.equal(runKindOf("skill-workshop-review:x5c2-spoof", { sessionKey: "agent:main:probe-x5c2-rpc", trigger: "user" }, "b"), null);
  assert.equal(runKindOf("skill-workshop-review:x", { sessionKey: "agent:main:main", trigger: "user", workspaceDir: WORKSHOP }, REVIEW_PROMPT), null);
});

test("must stay silent on the review prompt typed in chat", () => {
  assert.equal(runKindOf("4c1f7e0a-1b2c-4d3e-8f90-123456789abc", { sessionKey: "agent:main:main", trigger: "user" }, REVIEW_PROMPT), null);
  assert.equal(runKindOf("4c1f7e0a", { sessionKey: "agent:main:main", trigger: "user" }, CURATOR_PROMPT), null);
});

test("must recognise the memory flush by its trigger and an internal session key together", () => {
  assert.equal(runKindOf("0b6f1e9a-58a1-4bb3-9a43-7d0c1e2f3a4b", { sessionKey: FLUSH_KEY, trigger: "memory" }, "Pre-compaction memory flush."), "memory_flush");
  assert.equal(runKindOf("0b6f1e9a", { sessionKey: "agent:main:main", trigger: "memory" }, "x"), null);
  assert.equal(runKindOf("0b6f1e9a", { sessionKey: FLUSH_KEY, trigger: "user" }, "x"), null);
});

test("must recognise the skill collection review only as the rooted cron job with its tag", () => {
  assert.equal(runKindOf("f965ecc0", { sessionKey: CRON_KEY, trigger: "cron", workspaceDir: WORKSHOP }, CURATOR_PROMPT), "curator");
  assert.equal(runKindOf("f965ecc0", { sessionKey: CRON_KEY, trigger: "cron", workspaceDir: "/home/node/.openclaw/workspace" }, CURATOR_PROMPT), null);
  assert.equal(runKindOf("f965ecc0", { sessionKey: CRON_KEY, trigger: "cron", workspaceDir: WORKSHOP }, "[cron:abc daily-digest] Summarise."), null);
  assert.equal(runKindOf("f965ecc0", { sessionKey: "agent:main:main", trigger: "cron", workspaceDir: WORKSHOP }, CURATOR_PROMPT), null);
});

test("a run's kind holds at a call only in the session it was recognised in", () => {
  const run = { selfEdit: "background_review", selfEditSessionKey: REVIEW_KEY };
  assert.equal(kindAtCall(run, { sessionKey: REVIEW_KEY }), "background_review");
  assert.equal(kindAtCall(run, { sessionKey: "agent:main:main" }), null);
  assert.equal(kindAtCall({}, { sessionKey: REVIEW_KEY }), null);
});

// ---- which calls are saves ----------------------------------------------------------------------------------------

const NOW = new Date("2026-11-09T10:00:00Z");
const WS = "/home/node/.openclaw/workspace";

test("a review's file writes inside the Workshop and its skill_workshop changes are skill saves; its exec and reads are not", () => {
  const run = { workspaceDir: WORKSHOP };
  assert.equal(saveStoreOf("background_review", "write", { path: "deploy/SKILL.md", content: "x" }, run), "skills");
  assert.equal(saveStoreOf("background_review", "write", { path: `${WORKSHOP}/deploy/SKILL.md` }, run), "skills");
  assert.equal(saveStoreOf("background_review", "edit", { path: "./deploy/SKILL.md", edits: [] }, run), "skills");
  const patch = "*** Begin Patch\n*** Update File: deploy/SKILL.md\n@@\n-a\n+b\n*** Add File: notes/SKILL.md\n+c\n*** End Patch";
  assert.equal(saveStoreOf("background_review", "apply_patch", { input: patch }, run), "skills");
  assert.equal(saveStoreOf("background_review", "skill_workshop", { action: "create", name: "x" }, { workspaceDir: WS }), "skills");
  assert.equal(saveStoreOf("background_review", "skill_workshop", { action: "list" }, run), null);
  for (const tool of ["exec", "process", "read", "ls"]) assert.equal(saveStoreOf("background_review", tool, { command: "ls", path: "a" }, run), null);
  assert.equal(saveStoreOf("curator", "edit", { path: "a/SKILL.md" }, run), "skills");
});

test("must stay silent on a review's write outside the Workshop: an ordinary call, not a skill save", () => {
  const run = { workspaceDir: WORKSHOP };
  for (const p of ["/home/node/.openclaw/openclaw.json", "../../workspace/AGENTS.md", "~/.openclaw/openclaw.json", "", WORKSHOP]) {
    assert.equal(saveStoreOf("background_review", "write", { path: p, content: "x" }, run), null, p);
  }
  const escape = "*** Begin Patch\n*** Update File: deploy/SKILL.md\n+ok\n*** Update File: ../../workspace/AGENTS.md\n+bad\n*** End Patch";
  assert.equal(saveStoreOf("background_review", "apply_patch", { input: escape }, run), null);
  const moved = "*** Begin Patch\n*** Update File: deploy/SKILL.md\n*** Move to: /etc/cron.d/x\n*** End Patch";
  assert.equal(saveStoreOf("background_review", "apply_patch", { input: moved }, run), null);
  assert.equal(saveStoreOf("background_review", "apply_patch", { input: "no files named" }, run), null);
  // a review not rooted in the Workshop (propose mode) saves only through skill_workshop
  assert.equal(saveStoreOf("background_review", "write", { path: "x/SKILL.md" }, { workspaceDir: WS }), null);
});

test("the flush's save is its write to the day's note at the workspace root, nothing else", () => {
  const run = { workspaceDir: WS };
  assert.equal(saveStoreOf("memory_flush", "write", { path: "memory/2026-11-09.md", content: "x" }, run, NOW), "memory");
  assert.equal(saveStoreOf("memory_flush", "write", { path: `${WS}/memory/2026-11-08.md` }, run, NOW), "memory");
  for (const p of [
    "MEMORY.md",
    "memory/2020-01-01.md",
    "notes/memory/2026-11-09.md",
    "../../agents/main/agent/workshop-skills/memory/2026-11-09.md",
    "/etc/memory/2026-11-09.md",
  ]) {
    assert.equal(saveStoreOf("memory_flush", "write", { path: p }, run, NOW), null, p);
  }
  assert.equal(saveStoreOf("memory_flush", "read", { path: "memory/2026-11-09.md" }, run, NOW), null);
  assert.equal(saveStoreOf("memory_flush", "edit", { path: "memory/2026-11-09.md" }, run, NOW), null);
});

test("a recognised run's request is the owner's last message it read, or a fixed text", () => {
  const msgs = [
    { role: "user", content: "first", __openclaw: { senderIsOwner: true } },
    { role: "user", content: [{ type: "text", text: "from someone else" }], __openclaw: { senderIsOwner: false } },
    { role: "assistant", content: [{ type: "text", text: "ok" }] },
  ];
  assert.equal(lastOwnerMessage(msgs), "first");
  assert.equal(lastOwnerMessage([{ role: "user", content: "no flag" }]), undefined);
  assert.equal(hostRequestText({ ownerRequest: "first" }), "first");
  assert.equal(hostRequestText({}), NO_OWNER_REQUEST);
});

// ---- the setting --------------------------------------------------------------------------------------------------

test("skillReview: allow by default, review restores the old sending, anything else reads as allow and is named", () => {
  assert.deepEqual(resolveSetting(undefined), { setting: "allow", unknown: null });
  assert.deepEqual(resolveSetting(" Review "), { setting: "review", unknown: null });
  assert.deepEqual(resolveSetting("never"), { setting: "allow", unknown: "never" });
  assert.equal(settingText("allow", "nev\u0007er"), 'allow (unknown value "nev?er" read as allow)');
});

// ---- visibility ---------------------------------------------------------------------------------------------------

const scan = (id: string, verdict: string, decision: string, extra: Record<string, unknown> = {}) => ({
  kind: "scan",
  ts: "2026-11-09T10:00:00Z",
  request_id: id,
  tool: "write",
  mode: "enforce",
  verdict,
  decision,
  response: { risk: 10, reasons: [] },
  ...extra,
});

test("history labels self-edits; status counts them by outcome, and says when the log is off", () => {
  assert.equal(actionOf(scan("a", "allow", "allowed", { skill_review: true }), null), "allowed (self-edit)");
  assert.equal(actionOf(scan("b", "block", "blocked", { skill_review: true }), null), "blocked (self-edit)");
  assert.equal(actionOf(scan("r", "review", "review_timed_out", { skill_review: true }), null), "review (self-edit)");
  assert.equal(actionOf(scan("n", "review", "blocked", { skill_review: true }), null), "blocked (no reviewer, self-edit)");
  assert.equal(actionOf(scan("c", "allow", "allowed"), null), "allowed");
  const file = path.join(mkdtempSync(path.join(tmpdir(), "sentrook-se-")), "traffic.jsonl");
  const rows = [
    scan("a", "allow", "allowed", { skill_review: true }),
    scan("b", "block", "blocked", { skill_review: true }),
    scan("c", "review", "review_timed_out", { skill_review: true }),
    scan("d", "allow", "allowed"),
    scan("e", "allow", "allowed", { host_process: "background_review" }),
  ];
  writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  assert.equal(statusLine("allow", file), "allow; self-edits in the traffic log: 1 allowed, 1 blocked, 1 asked");
  assert.equal(statusLine("review", null), "review (self-edits not counted: the traffic log is off)");
});
