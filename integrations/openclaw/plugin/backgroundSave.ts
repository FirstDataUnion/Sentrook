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
 * - review, when the plugin declared the save as a self-edit, the save carries the content it saves (so the scan read
 *   it: `selfEdit.contentSave`), the scan is complete (`status: ok`), the score is below the block line and the
 *   scanner marks it `lenient`: it runs, and the owner is told it was let through;
 * - any other review below the block line: the model's own `skill_workshop` `draft` runs as it is, and on OpenClaw
 *   2026.11.5 or newer a new skill (`skill_workshop` `create`, or `write_file` of its `SKILL.md`) is saved as a Skill
 *   Workshop draft instead, and so is a `patch` of a skill's `SKILL.md`, as the whole live file with the patch applied
 *   (`patchDraft`). A draft does nothing until the owner applies it. Never a draft the scan says adds a secret (it
 *   would keep it), and a patch only with the scan's `self_edit` reading. The owner is told once OpenClaw reports the
 *   draft saved (`after_tool_call`), that the save was lost when it reports a failure, or that it was saved live when
 *   OpenClaw ran the call's own action instead of the draft;
 * - everything else (a patch that cannot be applied to the live file, a support file, a memory note, a file write, a
 *   change that carries no content such as a restore, an older or unknown OpenClaw, or a block-level score the scanner
 *   capped at review because it retries a review nobody answered) is held: it does not run, the run is told it was not
 *   saved and not to retry it (`HELD_TEXT`), and the owner is told, with where to make an archive or restore
 *   themselves. These holds are not kept in the holds file: `/sentrook-approve` could do nothing for them (it never
 *   makes the save), and they must not push out holds it can approve;
 * - a scan that gives no answer: the scan-error policy for unattended runs, with its failure notice
 *   (`scanErrorPolicy.ts`, `scanFailureNotice.ts`).
 *
 * The notices go where held-call notices go (`/sentrook-notify here`). They are built only from fixed text, the run
 * label, the tool name and the call's description as a review card shows it (entity display strings, made inert), so
 * nothing the saving model wrote reaches the owner beyond what a card shows. A notice of each kind goes once per run
 * (per cron job for the collection review) in the scan-failure notices' quiet period. A hold of a block-level score
 * has its own kind, so the first one in a run is announced whatever was announced before; `/sentrook-history` lists
 * every save. Observe mode changes nothing and sends nothing.
 */

import { closeSync, constants as fsConstants, fstatSync, openSync, readSync, realpathSync } from "node:fs";
import path from "node:path";

import { BLOCK_CATEGORIES, blockCategory, describe } from "./decision.ts";
import { inert, NOTIFY_UNSET, targetText } from "./hold.ts";
import type { ScanResponse } from "./scanClient.ts";
import { QUIET_MS } from "./scanFailureNotice.ts";
import type { SelfEditKind, SelfEditStore } from "./selfEdit.ts";
import type { NotifyTarget } from "./store.ts";

/**
 * The outcomes a background save announces. `draft_failed`: OpenClaw did not keep a save sent to the drafts.
 * `draft_ignored`: OpenClaw ran the call's own `create` instead of the draft, so the skill was saved live.
 */
export type Announced = "lenient" | "drafted" | "draft_failed" | "draft_ignored" | "held" | "blocked";

/** What the agent is told when a background save is held: nobody can approve it, so retrying never helps. */
export const HELD_TEXT =
  "Sentrook did not allow this save, so it was not saved. The owner has been told. Do not retry it in this run.";

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
 * Whether OpenClaw ran a save sent to the drafts as the call's own action instead of the draft, from `after_tool_call`:
 * its parameters are there and are not a draft, and it did not fail. Without parameters this cannot be told.
 */
export function draftIgnored(event: any): boolean {
  const params = event?.params;
  if (!params || typeof params !== "object" || Array.isArray(params)) return false;
  if (String(params.action ?? "").trim().toLowerCase() === "draft") return false;
  const status = String(event?.result?.details?.status ?? "").toLowerCase();
  return !event?.error && !["error", "failed", "failure", "refused", "denied", "cancelled", "blocked"].includes(status);
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

// ---- a held patch of a skill's SKILL.md, sent to the drafts as the patched skill -----------------------------------

/** The most of a live `SKILL.md` read to build a patch draft: OpenClaw reads no more of it (1 MiB). */
export const MAX_SKILL_FILE_BYTES = 1_048_576;

/** OpenClaw's pattern for the name of an existing Workshop skill (one path segment, no dots). */
const SKILL_NAME = /^[a-z0-9][a-z0-9-]{0,254}$/;

/**
 * Why a reviewed background patch was not sent to the drafts (it is held instead), or `drafted`; the scan record keeps
 * it as `patch_draft`.
 */
export type PatchDraft =
  | "drafted"
  | "support_file"
  | "secret"
  | "no_self_edit"
  | "bad_name"
  | "bad_patch"
  | "no_agent_dir"
  | "outside"
  | "missing"
  | "not_file"
  | "too_large"
  | "unreadable"
  | "no_match"
  | "several_matches";

/** The response's `self_edit` object, or null when it has none (a save not declared as a self-edit). */
function selfEditOf(resp: ScanResponse): Record<string, unknown> | null {
  const se: unknown = (resp as { self_edit?: unknown }).self_edit;
  return se && typeof se === "object" && !Array.isArray(se) ? (se as Record<string, unknown>) : null;
}

/**
 * Whether a draft would keep a secret: the scan says the saved text adds one (`self_edit.adds` has `secret`), or its
 * `self_edit` has no readable `adds`. A response with no `self_edit` says nothing either way.
 */
export function keepsSecret(resp: ScanResponse): boolean {
  const se = selfEditOf(resp);
  if (!se) return false;
  return !Array.isArray(se.adds) || se.adds.includes("secret");
}

/**
 * The text OpenClaw's own `patch` would save: `old_text` must occur exactly once (occurrences are counted as OpenClaw
 * counts them, overlapping ones too), and it is replaced by `new_text` as written. Nothing is trimmed or normalised:
 * OpenClaw matches whitespace and line endings exactly. An empty `old_text`, or one equal to `new_text`, OpenClaw
 * refuses.
 */
export function applyPatch(live: string, oldText: string, newText: string): { content: string } | { skip: PatchDraft } {
  if (!oldText || oldText === newText) return { skip: "bad_patch" };
  const first = live.indexOf(oldText);
  if (first === -1) return { skip: "no_match" };
  if (live.indexOf(oldText, first + 1) !== -1) return { skip: "several_matches" };
  return { content: live.slice(0, first) + newText + live.slice(first + oldText.length) };
}

/**
 * The live `SKILL.md` of Workshop skill `name` under `agentDir`, or why it cannot be read safely. It must lie at
 * `<agentDir>/workshop-skills/<name>/SKILL.md` once every link is resolved (no link in the skill's folder or on the
 * file itself, as OpenClaw refuses them too), be a regular file with no other hard link, and hold at most
 * `MAX_SKILL_FILE_BYTES`. Never throws.
 */
export function readLiveSkill(agentDir: string, name: string): { live: string } | { skip: PatchDraft } {
  let fd: number | null = null;
  try {
    const root = realpathSync(path.join(agentDir, "workshop-skills"));
    const real = realpathSync(path.join(agentDir, "workshop-skills", name, "SKILL.md"));
    if (real !== path.join(root, name, "SKILL.md")) return { skip: "outside" };
    // O_NOFOLLOW: a link swapped in after the check above is refused, not followed.
    fd = openSync(real, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1) return { skip: "not_file" };
    if (st.size > MAX_SKILL_FILE_BYTES) return { skip: "too_large" };
    // Read to one byte past the bound, in case the file grew since fstat.
    const buf = Buffer.alloc(MAX_SKILL_FILE_BYTES + 1);
    let size = 0;
    while (size < buf.length) {
      const n = readSync(fd, buf, size, buf.length - size, null);
      if (n === 0) break;
      size += n;
    }
    if (size > MAX_SKILL_FILE_BYTES) return { skip: "too_large" };
    return { live: buf.subarray(0, size).toString("utf8") };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    const why: Record<string, PatchDraft> = { ENOENT: "missing", ENOTDIR: "missing", ELOOP: "outside", EISDIR: "not_file" };
    return { skip: code && Object.hasOwn(why, code) ? why[code]! : "unreadable" };
  } finally {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // already closed
      }
    }
  }
}

/** The reason stored with a patch draft: fixed words and the UTC minute the live skill was read. */
export function patchDraftReason(now: Date): string {
  const at = now.toISOString().slice(0, 16).replace("T", " ");
  return `Held by Sentrook for your review: the skill as it stood at ${at} UTC, with one change applied.`;
}

/**
 * Whether a call is a `skill_workshop` `patch` of the skill's `SKILL.md`, as OpenClaw reads it: the action exactly
 * `patch` once trimmed (OpenClaw does not fold case), and `file_path` absent, blank or `SKILL.md` once trimmed. Any
 * other `file_path` is a support file (or one OpenClaw refuses, such as `./SKILL.md`).
 */
export function isSkillPatch(tool: string, params: any): "skill" | "support_file" | null {
  if (tool !== "skill_workshop" || typeof params?.action !== "string" || params.action.trim() !== "patch") return null;
  const fp = typeof params?.file_path === "string" ? params.file_path.trim() : "";
  return fp === "" || fp === "SKILL.md" ? "skill" : "support_file";
}

/**
 * The parameters that turn a reviewed background `patch` of a skill's `SKILL.md` into a Skill Workshop draft of the
 * whole patched skill, or why it stays held; null when the call is no such patch or the host takes no drafts
 * (`DRAFT_FLOOR`). The patch is applied as OpenClaw applies it to the live file, read safely (`readLiveSkill`).
 * `declared`: the save was sent as a self-edit, so the response's `self_edit` is the scanner's reading of it. `agentDir`
 * is asked only when everything else allows a draft; whatever it returns or throws, nothing is allowed.
 *
 * The scan read the patch (the old and new text), not the rest of the live file, and the draft holds the whole file.
 * That is acceptable only because the rest is already the live skill, which the agent loads today: the draft adds
 * nothing to it but the change the scan judged. A draft never keeps a secret the scan saw in the change
 * (`keepsSecret`), and without a `self_edit` reading in the response it is not built at all.
 */
export function patchDraft(
  tool: string,
  params: any,
  hostVersion: unknown,
  resp: ScanResponse,
  declared: boolean,
  agentDir: () => unknown,
  now: Date,
): { params: Record<string, unknown> } | { skip: PatchDraft } | null {
  const kind = isSkillPatch(tool, params);
  if (!kind || !atLeast(hostVersion)) return null;
  if (kind === "support_file") return { skip: "support_file" };
  const se = selfEditOf(resp);
  if (!declared || !se || !Array.isArray(se.adds)) return { skip: "no_self_edit" };
  if (keepsSecret(resp)) return { skip: "secret" };
  const name = typeof params?.name === "string" ? params.name.trim() : "";
  if (!SKILL_NAME.test(name)) return { skip: "bad_name" };
  const oldText = typeof params?.old_text === "string" ? params.old_text : "";
  const newText = typeof params?.new_text === "string" ? params.new_text : "";
  if (!oldText || oldText === newText) return { skip: "bad_patch" };
  let dir: unknown;
  try {
    dir = agentDir();
  } catch {
    dir = undefined;
  }
  if (typeof dir !== "string" || !path.isAbsolute(dir)) return { skip: "no_agent_dir" };
  const read = readLiveSkill(dir, name);
  if ("skip" in read) return read;
  const patched = applyPatch(read.live, oldText, newText);
  if ("skip" in patched) return patched;
  return { params: { action: "draft", name, content: patched.content, reason: patchDraftReason(now) } };
}

/**
 * The quiet-period key of a notice: one per outcome and run (cron job, else session). `held_retry`: a hold of a
 * block-level score, kept apart from other holds so the first one in a run is always announced. `patch`: a patch sent
 * to the drafts has quiet periods of its own, so its note about applying it is not silenced by a new skill's notice.
 */
export function quietKey(
  outcome: Announced | "held_retry",
  jobId: string | null | undefined,
  sessionRef: string,
  patch = false,
): string {
  return `background_${outcome}${patch ? "_patch" : ""}:${jobId ? `job:${jobId}` : `session:${sessionRef}`}`;
}

/** Whether a notice is about a patch sent to the drafts (kept, run live, or not kept): it has words of its own. */
export function patchDraftNotice(outcome: Announced, tool: string, action: string): boolean {
  return tool === "skill_workshop" && action === "patch" && ["drafted", "draft_ignored", "draft_failed"].includes(outcome);
}

/** Where the owner can make a held Workshop change themselves, by `skill_workshop` action; other holds say to ask. */
const HELD_WORKSHOP_ACTS: Record<string, string> = {
  archive: "To archive it yourself: Archive on the skill, on Plugins → Skill workshop in the Control UI.",
  restore: "To restore it yourself: the skill's history, on Plugins → Skill workshop in the Control UI.",
  remove_file:
    "The skill and its support files are on Plugins → Skill workshop in the Control UI; to remove the file, ask the " +
    "agent for it in a chat.",
};

/**
 * The notice for a background save; `where` is `hold.whereText`'s, already made inert. `retry`: a hold of a block-level
 * score (a retry of a review nobody answered), whose further notices wait out their own quiet period. `action`: the
 * `skill_workshop` action, trimmed and in lower case (`patch` drafts and some holds have words of their own).
 */
export function noticeText(
  outcome: Announced,
  resp: ScanResponse,
  tool: string,
  store: SelfEditStore,
  where: string,
  requestId: string | null,
  isJob: boolean,
  retry = false,
  action = "",
): string {
  const what = `${STORE_WORDS[store]}: ${inert(describe(resp, tool), 160)} (${inert(tool, 80)})`;
  // the id only means something while the traffic log keeps the scan
  const id = requestId === null ? null : inert(requestId, 36).slice(0, 8);
  const look = id ? `/sentrook-why ${id}; /sentrook-history lists every background save.` : "/sentrook-history lists every background save.";
  const scope = isJob ? "job" : "run";
  if (patchDraftNotice(outcome, tool, action)) {
    return patchNotice(outcome as "drafted" | "draft_ignored" | "draft_failed", what, where, id, look, scope).join("\n");
  }
  const act = tool === "skill_workshop" && Object.hasOwn(HELD_WORKSHOP_ACTS, action) ? HELD_WORKSHOP_ACTS[action]! : null;
  const lines: Record<Announced, string[]> = {
    lenient: [
      "Sentrook let one of OpenClaw's background saves through that it would normally ask you about. Nobody can " +
        "answer a prompt in a background run, so saves like this one are kept and you are told.",
      `Run: ${where}`,
      `Saved ${what}`,
      `To look at it: ${look}`,
      `More saves let through in this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ],
    draft_ignored: [
      "Sentrook sent a new skill from one of OpenClaw's background runs to the Skill Workshop drafts, but OpenClaw " +
        "saved it as a live skill instead, without asking you.",
      `Run: ${where}`,
      `Saved ${what}`,
      `To remove it, ask the agent in a chat to archive it. To look at it: ${look}`,
      `More skills saved live from this ${scope} are not announced for ${QUIET_HOURS} hours.`,
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
      ...(act ? [act, `To look at it: ${look}`] : [`To keep it, ask the agent for it in a chat. To look at it: ${look}`]),
      retry
        ? `More held retries of a blocked save in this ${scope} are not announced for ${QUIET_HOURS} hours.`
        : `More held saves in this ${scope} are not announced for ${QUIET_HOURS} hours.`,
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
  return lines[outcome].join("\n");
}

/** The notice for a change to an existing skill sent to the drafts: kept, run live instead, or not kept. */
function patchNotice(
  outcome: "drafted" | "draft_ignored" | "draft_failed",
  what: string,
  where: string,
  id: string | null,
  look: string,
  scope: string,
): string[] {
  if (outcome === "drafted") {
    return [
      "Sentrook saved a change to an existing skill from one of OpenClaw's background runs as a Skill Workshop draft, " +
        "for you to review: the skill is unchanged until you apply it.",
      `Run: ${where}`,
      `Draft ${what}`,
      "To review and apply it: the Skill Workshop drafts in the Control UI, or /learn drafts in a chat with the agent.",
      "Applying it replaces the skill with the version from when the change was held, with this one change: any later " +
        "change to that skill would be undone. It can be brought back from the skill's history.",
      ...(id ? [`Why it was not saved directly: /sentrook-why ${id}`] : []),
      `More changes sent to drafts from this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ];
  }
  if (outcome === "draft_ignored") {
    return [
      "Sentrook sent a change to an existing skill from one of OpenClaw's background runs to the Skill Workshop drafts, " +
        "but OpenClaw applied the change to the live skill instead, without asking you.",
      `Run: ${where}`,
      `Saved ${what}`,
      "To undo it, restore the skill's previous version from its history on Plugins → Skill workshop in the Control UI. " +
        `To look at it: ${look}`,
      `More changes saved live from this ${scope} are not announced for ${QUIET_HOURS} hours.`,
    ];
  }
  return [
    "Sentrook sent a change to an existing skill from one of OpenClaw's background runs to the Skill Workshop drafts, " +
      "but OpenClaw did not keep the draft, so the change was not made.",
    `Run: ${where}`,
    `Save ${what}`,
    `To keep it, ask the agent for it in a chat. To look at it: ${look}`,
    `More lost changes from this ${scope} are not announced for ${QUIET_HOURS} hours.`,
  ];
}

/** Where background-save notices go, as status and verify say it. */
export function noticeStatus(target: NotifyTarget | null): string {
  return target
    ? `by ${targetText(target)}`
    : `cannot be delivered: ${NOTIFY_UNSET}. Saves Sentrook lets through, drafts and holds still happen, unannounced`;
}
