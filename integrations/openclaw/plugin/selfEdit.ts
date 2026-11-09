/**
 * OpenClaw's own background saves to the agent's skills and memory (self-edits).
 *
 * Three host processes save on their own, after or around a conversation, with nobody asking:
 * - the Skill Workshop review (`background_review`): queued after a long turn, it reads a copy of the conversation
 *   and saves skills, with file `write`, `edit` and `apply_patch` rooted in the agent's `workshop-skills` directory
 *   (autonomous mode `auto`) or with `skill_workshop` (mode `propose`);
 * - the memory flush before compaction (`memory_flush`): it saves durable notes from the conversation with a `write`
 *   to the day's note, `memory/YYYY-MM-DD.md`;
 * - the weekly skill collection review (`curator`): a system-owned cron job that tidies the Workshop's skills.
 *
 * The review inherits the owner's run context (trigger `user`, the owner flag), so without this module its calls
 * would be sent as the owner's own messages. A run is recognised only by signals chat cannot set, read on
 * `before_prompt_build` (which raw model runs skip) and checked again at each call:
 * - review: runId `skill-workshop-review:<uuid>` AND the review's internal session key
 *   (`agent:<id>:internal-session-effects:skill-workshop-review_…`). A gateway request can choose a runId, never the
 *   session key; the prompt text can be typed by anyone and is not used.
 * - flush: run trigger `memory` (set only by the flush; gateway runs are `user`) AND an internal session key.
 * - curator: run trigger `cron` on a cron session, rooted in the `workshop-skills` directory, AND the job's tag
 *   `[cron:<id> skill-collection-review-<agent>]` that the host puts before the prompt.
 *
 * With `skillReview: allow` (the default) every call of a recognised run is sent with trigger `system` (no owner, no
 * snooze) and, as its request, the last message the host flags as the owner's in the conversation the run read (a
 * fixed text when there is none), and its saves are declared as self-edits with the conversation the process
 * read (`conversation.ts`); the scanner judges them against it, and the verdict is applied like any other. Its other
 * calls (exec, reads) are scored as usual. `skillReview: review` changes nothing: every call is sent as before. Any
 * other value reads as allow, and status and the startup log name it.
 *
 * Out of reach: dreaming (memory-core writes MEMORY.md and DREAMS.md in code) and the session-memory hook (writes
 * recent messages into memory/ on /new and /reset) make no tool call, so no plugin hook sees them.
 */

import path from "node:path";

import { textOf } from "./conversation.ts";
import { actionOf, recentScans } from "./history.ts";
import type { RunContext } from "./store.ts";

export type SelfEditKind = "background_review" | "memory_flush" | "curator";
export type SelfEditStore = "skills" | "memory";

export const SETTINGS = ["allow", "review"] as const;
export type SkillReviewSetting = (typeof SETTINGS)[number];

const REVIEW_RUN = /^skill-workshop-review:/;
const REVIEW_SESSION = /^agent:[^:]+:internal-session-effects:skill-workshop-review_/;
const INTERNAL_SESSION = /^agent:[^:]+:internal-session-effects:/;
const CRON_SESSION = /^agent:[^:]+:cron:/;
const COLLECTION_JOB = /^\[cron:[^\]\s]+ skill-collection-review-[^\]\s]+\]/;
const WORKSHOP_DIR = "workshop-skills";
/** The day's note the flush appends to, relative to the workspace. */
const DAILY_NOTE = /^(?:\.\/)?memory\/(\d{4}-\d{2}-\d{2})\.md$/;
/** The files a patch in OpenClaw's `*** Begin Patch` format touches. */
const PATCH_FILE = /^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/gm;

/** The file tools a review or curator saves skills with, rooted in the Workshop directory. */
const FILE_SAVES = new Set(["write", "edit", "apply_patch"]);
/** `skill_workshop` actions that only read. */
const WORKSHOP_READS = new Set(["list", "get", "read", "show", "view", "search", "status", "inspect", "describe"]);

/** The request text of a recognised run's calls when its conversation holds no owner message. */
export const NO_OWNER_REQUEST =
  "No owner request: this call is made by OpenClaw's own background process, after or around a conversation.";

/** The PlanIR trigger every call of a recognised run is sent with. */
export const TRIGGER = { kind: "system", channel: null, sender: { relation: "unknown", basis: ["none"] } };

const isWorkshopDir = (dir: unknown) => typeof dir === "string" && path.basename(dir.replace(/\/+$/, "")) === WORKSHOP_DIR;

/**
 * Which self-editing process a run is, from its `before_prompt_build` (runId, context, prompt); null for any other
 * run.
 */
export function runKindOf(runId: unknown, ctx: any, prompt: unknown): SelfEditKind | null {
  const sk = typeof ctx?.sessionKey === "string" ? ctx.sessionKey : "";
  if (!sk) return null;
  if (typeof runId === "string" && REVIEW_RUN.test(runId) && REVIEW_SESSION.test(sk)) return "background_review";
  if (ctx?.trigger === "memory" && INTERNAL_SESSION.test(sk)) return "memory_flush";
  if (
    ctx?.trigger === "cron" &&
    CRON_SESSION.test(sk) &&
    isWorkshopDir(ctx?.workspaceDir) &&
    typeof prompt === "string" &&
    COLLECTION_JOB.test(prompt)
  ) {
    return "curator";
  }
  return null;
}

/** The run's self-edit kind at a tool call: recognised on `before_prompt_build`, in the same session. */
export function kindAtCall(run: RunContext, ctx: any): SelfEditKind | null {
  const kind = run.selfEdit as SelfEditKind | undefined;
  if (!kind || !run.selfEditSessionKey || run.selfEditSessionKey !== ctx?.sessionKey) return null;
  return kind;
}

/** `p`, resolved against `root` when relative, lies inside `root`. A `~` path never does. */
export function insideRoot(p: unknown, root: unknown): boolean {
  if (typeof p !== "string" || !p.trim() || typeof root !== "string" || !root) return false;
  if (p.trim().startsWith("~")) return false;
  const r = path.normalize(root).replace(/\/+$/, "");
  const abs = path.isAbsolute(p) ? path.normalize(p) : path.normalize(path.join(r, p));
  return abs.startsWith(`${r}/`);
}

/** The files a call writes: `path` for `write` and `edit`, every file a patch names for `apply_patch`. */
export function targetsOf(tool: string, params: any): string[] {
  if (tool === "apply_patch") {
    const input = typeof params?.input === "string" ? params.input : "";
    return [...input.matchAll(PATCH_FILE)].map((m) => m[1]!.trim());
  }
  return typeof params?.path === "string" ? [params.path] : [];
}

const DAY_MS = 86_400_000;

/** The flush's note: `memory/YYYY-MM-DD.md` at the workspace root, dated within a day of `now` (time zones). */
function isDayNote(p: unknown, workspace: unknown, now: Date): boolean {
  if (typeof p !== "string") return false;
  let rel = p;
  if (path.isAbsolute(p)) {
    if (!insideRoot(p, workspace)) return false;
    rel = path.relative(String(workspace), path.normalize(p));
  }
  const m = DAILY_NOTE.exec(rel);
  if (!m) return false;
  const day = Date.parse(`${m[1]}T12:00:00Z`);
  return !Number.isNaN(day) && Math.abs(day - now.getTime()) <= 1.5 * DAY_MS;
}

/**
 * Where a recognised run's call saves, or null when the call is not a save (exec, reads, a write anywhere else):
 * - flush: a `write` to the day's note at the workspace root;
 * - review and curator: a `skill_workshop` action that changes something, or a file `write`, `edit` or
 *   `apply_patch` whose every target lies inside the run's Workshop folder.
 */
export function saveStoreOf(
  kind: SelfEditKind,
  tool: string,
  params: any,
  run: RunContext,
  now = new Date(),
): SelfEditStore | null {
  if (kind === "memory_flush") {
    return tool === "write" && isDayNote(params?.path, run.workspaceDir, now) ? "memory" : null;
  }
  if (tool === "skill_workshop") {
    const action = String(params?.action ?? "").toLowerCase();
    return WORKSHOP_READS.has(action) ? null : "skills";
  }
  if (!FILE_SAVES.has(tool) || !isWorkshopDir(run.workspaceDir)) return null;
  const targets = targetsOf(tool, params);
  return targets.length && targets.every((t) => insideRoot(t, run.workspaceDir)) ? "skills" : null;
}

/** The last message the host flags as the owner's in a run's model context, if any. */
export function lastOwnerMessage(messages: unknown): string | undefined {
  if (!Array.isArray(messages)) return undefined;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (m?.role === "user" && m?.__openclaw?.senderIsOwner === true) {
      const text = textOf(m.content).trim();
      if (text) return text;
    }
  }
  return undefined;
}

/** A recognised run's request text: the owner's last message in the conversation it read, or a fixed text. */
export function hostRequestText(run: RunContext): string {
  return typeof run.ownerRequest === "string" && run.ownerRequest ? run.ownerRequest : NO_OWNER_REQUEST;
}

/** The setting, and the raw value when it was not understood (read as allow). */
export function resolveSetting(raw: unknown): { setting: SkillReviewSetting; unknown: string | null } {
  if (raw === undefined || raw === null || raw === "") return { setting: "allow", unknown: null };
  const v = String(raw).trim().toLowerCase();
  if ((SETTINGS as readonly string[]).includes(v)) return { setting: v as SkillReviewSetting, unknown: null };
  return { setting: "allow", unknown: String(raw) };
}

export function settingText(setting: SkillReviewSetting, unknown: string | null): string {
  if (unknown === null) return setting;
  const shown = [...unknown].map((c) => (/[\p{L}\p{N}\p{P}\p{S} ]/u.test(c) ? c : "?")).join("");
  return `${setting} (unknown value "${shown}" read as allow)`;
}

/** Self-edits in the recent traffic log, by what was done. */
export function counts(file: string): { allowed: number; blocked: number; asked: number } {
  const out = { allowed: 0, blocked: 0, asked: 0 };
  for (const [scan, resolution] of recentScans(file, 10_000)) {
    if (scan.skill_review !== true) continue;
    const action = actionOf(scan, resolution);
    if (action.startsWith("blocked")) out.blocked += 1;
    else if (action.startsWith("review")) out.asked += 1;
    else out.allowed += 1;
  }
  return out;
}

/** The `skill review:` line of status; `file` is null when the traffic log is off. */
export function statusLine(setting: string, file: string | null): string {
  if (file === null) return `${setting} (self-edits not counted: the traffic log is off)`;
  const c = counts(file);
  const asked = c.asked ? `, ${c.asked} asked` : "";
  return `${setting}; self-edits in the traffic log: ${c.allowed} allowed, ${c.blocked} blocked${asked}`;
}
