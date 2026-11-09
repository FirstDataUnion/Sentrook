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
 * snooze, unattended approval timing), and its saves are declared as self-edits with the conversation the process
 * read (`conversation.ts`); the scanner judges them against it, and the verdict is applied like any other. Its other
 * calls (exec, reads) are scored as usual. `skillReview: review` changes nothing: every call is sent as before. Any
 * other value reads as allow, and status and the startup log name it.
 *
 * Out of reach: dreaming (memory-core writes MEMORY.md and DREAMS.md in code) and the session-memory hook (writes
 * recent messages into memory/ on /new and /reset) make no tool call, so no plugin hook sees them.
 */

import path from "node:path";

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
/** The day's note the flush appends to. */
const DAILY_NOTE = /(?:^|\/)memory\/\d{4}-\d{2}-\d{2}\.md$/;

/** The file tools a review or curator saves skills with, rooted in the Workshop directory. */
const FILE_SAVES = new Set(["write", "edit", "apply_patch"]);
/** `skill_workshop` actions that only read. */
const WORKSHOP_READS = new Set(["list", "get", "read", "show", "view", "search", "status", "inspect", "describe"]);

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

/** Where a recognised run's call saves, or null when the call is not a save (exec, reads, anything else). */
export function saveStoreOf(kind: SelfEditKind, tool: string, params: any, run: RunContext): SelfEditStore | null {
  if (kind === "memory_flush") {
    return tool === "write" && typeof params?.path === "string" && DAILY_NOTE.test(params.path) ? "memory" : null;
  }
  if (tool === "skill_workshop") {
    const action = String(params?.action ?? "").toLowerCase();
    return WORKSHOP_READS.has(action) ? null : "skills";
  }
  return FILE_SAVES.has(tool) && isWorkshopDir(run.workspaceDir) ? "skills" : null;
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
