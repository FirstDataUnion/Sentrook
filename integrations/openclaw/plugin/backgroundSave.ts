/**
 * What happens to a save OpenClaw makes on its own (a background save, recognised in `selfEdit.ts`): the Skill
 * Workshop review's skill saves, the memory flush's note before compaction, and the skill collection review's
 * changes.
 *
 * Nobody can answer an approval prompt in these runs: OpenClaw cancels a plugin's prompt there at once, or ends the
 * run long before the prompt times out, and the save is then lost without anyone being told. So a background save is
 * never asked about, on any OpenClaw version and whatever the settings say. Instead:
 * - allow: the save runs;
 * - block: it does not run, and the owner is told;
 * - review, when the plugin declared the save as a self-edit, the scan is complete (`status: ok`), the score is below
 *   the block line and the scanner marks it `lenient`: it runs, and the owner is told it was let through;
 * - any other review below the block line: on OpenClaw 2026.11.5 or newer, a new skill (`skill_workshop` `create`, or
 *   `write_file` of its `SKILL.md`) is saved as a Skill Workshop draft instead, which does nothing until the owner
 *   applies it. The owner is told once OpenClaw reports the draft saved (`after_tool_call`), or that the save was lost
 *   when it reports a failure;
 * - everything else (a patch, a memory note, a file write, an older or unknown OpenClaw, or a block-level score the
 *   scanner capped at review because it retries a review nobody answered) is held: it does not run, the run is told
 *   not to retry it, and the owner is told. These holds are not kept in the holds file: `/sentrook-approve` could do
 *   nothing for them (it never makes the save), and they must not push out holds it can approve;
 * - a scan that gives no answer: the scan-error policy for unattended runs, with its failure notice
 *   (`scanErrorPolicy.ts`, `scanFailureNotice.ts`).
 *
 * The notices go where held-call notices go (`/sentrook-notify here`). They are built only from fixed text, the run
 * label, the tool name and the call's description as a review card shows it (entity display strings, made inert), so
 * nothing the saving model wrote reaches the owner beyond what a card shows. A notice of each kind goes once per run
 * (per cron job for the collection review) in the scan-failure notices' quiet period, except a hold of a block-level
 * score, which is always announced; `/sentrook-history` lists every save. Observe mode changes nothing and sends
 * nothing.
 */

import path from "node:path";

import { BLOCK_CATEGORIES, blockCategory, describe } from "./decision.ts";
import { inert, NOTIFY_UNSET, targetText } from "./hold.ts";
import type { ScanResponse } from "./scanClient.ts";
import { QUIET_MS } from "./scanFailureNotice.ts";
import type { SelfEditKind, SelfEditStore } from "./selfEdit.ts";
import type { NotifyTarget } from "./store.ts";

/** The outcomes a background save announces. `draft_failed`: OpenClaw did not keep a save sent to the drafts. */
export type Announced = "lenient" | "drafted" | "draft_failed" | "held" | "blocked";

/** The first OpenClaw that takes a Skill Workshop draft from a plugin's rewritten parameters in a background review. */
export const DRAFT_FLOOR: readonly [number, number, number] = [2026, 11, 5];

/** The reason stored with a draft; the Workshop shows it beside the draft. */
export const DRAFT_REASON = "Sentrook: saved as a draft for your review instead of a new skill";

const QUIET_HOURS = QUIET_MS / 3600_000;

/** How notices and status name each background run. */
export const RUN_LABELS: Record<SelfEditKind, string> = {
  background_review: "Skill Workshop background review",
  memory_flush: "memory flush before compaction",
  curator: "skill collection review",
};

const STORE_WORDS: Record<SelfEditStore, string> = { skills: "skill", memory: "memory note" };

/**
 * Whether the scanner marked a reviewed save as one to let through: only `self_edit.lenient === true` on a complete
 * scan (`status: ok`, not degraded) counts; a missing or malformed field is not lenient. Neither is a review the
 * scanner enforces (a floor is never relaxed) nor a block-level score lowered to a review (`capped`). The caller also
 * requires that the save was declared as a self-edit: the scanner judged it as one.
 */
export function lenientOf(resp: ScanResponse, blockAt: number): boolean {
  const se: unknown = (resp as { self_edit?: unknown }).self_edit;
  if (!se || typeof se !== "object" || Array.isArray(se)) return false;
  return (se as { lenient?: unknown }).lenient === true && resp.status === "ok" && resp.enforced !== "review" && !capped(resp, blockAt);
}

/** A score at or above the block line that reached a review only through the scanner's cap (or has no number). */
export function capped(resp: ScanResponse, blockAt: number): boolean {
  return !(typeof resp.risk === "number" && resp.risk < blockAt);
}

/**
 * Whether OpenClaw reports a draft saved, from `after_tool_call`: no error, no error status in the result's details,
 * and a result that names the draft (2026.11.5 answers "Saved draft <id> for ..."). Anything else counts as lost.
 */
export function draftSaved(event: any, text: string): boolean {
  if (event?.error) return false;
  const status = String(event?.result?.details?.status ?? "").toLowerCase();
  if (["error", "failed", "failure", "refused", "denied", "cancelled", "blocked"].includes(status)) return false;
  return /\bsaved draft\b/i.test(text);
}

/**
 * Whether `version` (OpenClaw's calendar version, `2026.11.5`) is at least `floor`. Unknown or unreadable versions are
 * not, and neither is a pre-release of the floor itself (`2026.11.5-beta.1`).
 */
export function atLeast(version: unknown, floor: readonly [number, number, number] = DRAFT_FLOOR): boolean {
  if (typeof version !== "string") return false;
  const m = /^v?(\d+)\.(\d+)\.(\d+)(-[^+\s]*)?(\+\S*)?$/.exec(version.trim());
  if (!m) return false;
  const parts = [Number(m[1]), Number(m[2]), Number(m[3])];
  for (let i = 0; i < 3; i++) {
    if (parts[i]! !== floor[i]) return parts[i]! > floor[i]!;
  }
  return m[4] === undefined;
}

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

/** `write_file` of the skill's own `SKILL.md` (a support file has no draft form). */
function isSkillFile(p: unknown): boolean {
  if (typeof p !== "string" || !p.trim()) return false;
  return path.posix.normalize(p.trim().replace(/\\/g, "/")) === "SKILL.md";
}

/**
 * The parameters that turn a reviewed background skill save into a Skill Workshop draft, or null when it has no
 * draft form here: only on OpenClaw `DRAFT_FLOOR` or newer, only a `skill_workshop` `create`, or a `write_file` of
 * `SKILL.md`, with a name and the full content. OpenClaw merges these over the call's own parameters, and the draft
 * action reads only these.
 */
export function draftParams(tool: string, params: any, hostVersion: unknown): Record<string, unknown> | null {
  if (tool !== "skill_workshop" || !atLeast(hostVersion)) return null;
  const action = String(params?.action ?? "").trim().toLowerCase();
  if (action !== "create" && !(action === "write_file" && isSkillFile(params?.file_path))) return null;
  if (!nonEmpty(params?.name) || typeof params?.content !== "string" || !params.content.trim()) return null;
  return { action: "draft", name: params.name, content: params.content, reason: DRAFT_REASON };
}

/** The quiet-period key of a notice: one per outcome and run (cron job, else session). */
export function quietKey(outcome: Announced, jobId: string | null | undefined, sessionRef: string): string {
  return `background_${outcome}:${jobId ? `job:${jobId}` : `session:${sessionRef}`}`;
}

/**
 * The notice for a background save; `where` is `hold.whereText`'s, already made inert. `quiet`: further notices of this
 * kind wait out the quiet period (every kind but a block-level hold).
 */
export function noticeText(
  outcome: Announced,
  resp: ScanResponse,
  tool: string,
  store: SelfEditStore,
  where: string,
  requestId: string | null,
  isJob: boolean,
  quiet = true,
): string {
  const what = `${STORE_WORDS[store]}: ${inert(describe(resp, tool), 160)} (${inert(tool, 80)})`;
  // the id only means something while the traffic log keeps the scan
  const id = requestId === null ? null : inert(requestId, 36).slice(0, 8);
  const look = id ? `/sentrook-why ${id}; /sentrook-history lists every background save.` : "/sentrook-history lists every background save.";
  const scope = isJob ? "job" : "run";
  const lines: Record<Announced, string[]> = {
    lenient: [
      "Sentrook let one of OpenClaw's background saves through that it would normally ask you about. Nobody can " +
        "answer a prompt in a background run, so saves like this one are kept and you are told.",
      `Run: ${where}`,
      `Saved ${what}`,
      `To look at it: ${look}`,
      `More saves let through in this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ],
    draft_failed: [
      "Sentrook sent a new skill from one of OpenClaw's background runs to the Skill Workshop drafts, but OpenClaw did " +
        "not keep the draft, so the save was not made.",
      `Run: ${where}`,
      `Save ${what}`,
      `To keep it, ask the agent for it in a chat. To look at it: ${look}`,
      `More lost drafts from this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ],
    held: [
      "Sentrook held one of OpenClaw's background saves: it was not made, and the run was told not to retry it.",
      `Run: ${where}`,
      `Save ${what}`,
      `Held because ${BLOCK_CATEGORIES[blockCategory(resp)]}.`,
      `To keep it, ask the agent for it in a chat. To look at it: ${look}`,
      `More held saves in this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ],
    drafted: [
      "Sentrook saved a new skill from one of OpenClaw's background runs as a Skill Workshop draft, for you to " +
        "review: it is not used until you apply it.",
      `Run: ${where}`,
      `Draft ${what}`,
      "To review and apply it: the Skill Workshop drafts in the Control UI, or /learn drafts in a chat with the agent.",
      ...(id ? [`Why it was not saved directly: /sentrook-why ${id}`] : []),
      `More drafts from this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ],
    blocked: [
      "Sentrook blocked one of OpenClaw's background saves; it did not run and was not kept.",
      `Run: ${where}`,
      `Save ${what}`,
      `Blocked because ${BLOCK_CATEGORIES[blockCategory(resp)]}.`,
      ...(id ? [`For the reasons: /sentrook-why ${id}`] : []),
      `More blocked saves in this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ],
  };
  const out = lines[outcome];
  return (quiet ? out : out.filter((l) => !l.startsWith("More "))).join("\n");
}

/** Where background-save notices go, as status and verify say it. */
export function noticeStatus(target: NotifyTarget | null): string {
  return target
    ? `by ${targetText(target)}`
    : `cannot be delivered: ${NOTIFY_UNSET}. Saves Sentrook lets through, drafts and holds still happen, unannounced`;
}
