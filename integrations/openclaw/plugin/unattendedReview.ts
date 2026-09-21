/**
 * Hosted ``review`` on cron/heartbeat cannot wait on a plugin approval card.
 *
 * OpenClaw fails plugin ``requireApproval`` when ``trigger !== "user"``
 * (``resolveUnavailablePluginApprovalSurfaceReason``). Native exec automations
 * can still reach Control UI; plugin cards cannot. Until that host gap closes,
 * we veto with our own copy instead of handing off to a confusing cancel.
 *
 * Waiting on OpenClaw to restore live plugin review cards for unattended jobs:
 * {@link OPENCLAW_UNATTENDED_PLUGIN_APPROVAL_ISSUE}
 * Sentrook tracking: {@link SENTROOK_UNATTENDED_REVIEW_ISSUE}
 */

import {
  allowlistAdd,
  sensitivityCmd,
  sensitivitySession,
} from "./dashboardSlashHints.ts";
import { isHardReview } from "./sessionPolicy.ts";

/** OpenClaw native-tool / plugin-approval surface gap for scheduled runs. */
export const OPENCLAW_UNATTENDED_PLUGIN_APPROVAL_ISSUE =
  "https://github.com/openclaw/openclaw/issues/138853";

/** Sentrook tracking for the fail-closed workaround until the host can prompt again. */
export const SENTROOK_UNATTENDED_REVIEW_ISSUE =
  "https://github.com/FirstDataUnion/Sentrook/issues/59";

/** Operator-log resolution when we veto an unattended hosted review. */
export const UNATTENDED_BLOCK_DECISION = "unattended-block";

export function unattendedReviewBlockReason(opts: {
  eventId?: string;
  sessionKey?: string | null;
  command?: string;
  /**
   * `hard` when the review cannot be waived by any blanket session policy.
   *
   * Without this the message offered "raise the unattended floor so this
   * severity auto-approves" for **every** block, and that stopped being true
   * the moment `review_authority` reached the plugin: a hard review declines
   * the floor, the session floor, allow-all and quiet alike. Telling an
   * operator to raise a floor that cannot help is worse than saying nothing —
   * they change a global setting, the job blocks again, and the setting stays
   * changed.
   */
  reviewAuthority?: string;
}): string {
  const id = opts.eventId?.trim();
  const sessionKey = opts.sessionKey?.trim();
  const command = opts.command?.replace(/\s+/g, " ").trim();
  const add = allowlistAdd(id);
  const addCli = id
    ? `openclaw sentrook allowlist add ${id}`
    : "openclaw sentrook allowlist add <id>";
  const inspect = id ? `/sentrook history ${id}` : "/sentrook history";
  const hard = isHardReview(opts.reviewAuthority);
  const sessionFloor = sessionKey
    ? `\n       ${sensitivitySession(sessionKey, "unattended", "warning")}`
    : "";

  return [
    "Sentrook flagged this tool for human review. OpenClaw cannot show a plugin approval card on cron or heartbeat runs, so the call did not run.",
    "",
    command
      ? "Look at this command. If you trust it, add it to your allowlist and run the job again:"
      : "If you trust this job, add it to your allowlist and run the job again:",
    "",
    command ? `  ${command}` : undefined,
    command ? "" : undefined,
    `  1. ${add}`,
    `     ${addCli}`,
    "",
    "Matching later reviews skip the prompt. Scan still runs. Blocks still win.",
    "Pipes and curl|bash cannot be allowlisted. A curl/wget to a specific host and path can — a different URL will not match.",
    "",
    "Other options:",
    hard
      ? "  2. Not available for this rule. It is a hard review: no sensitivity floor, session floor, allow-all or quiet setting will approve it. The allowlist above is the only way to let this exact command run unattended, and that is deliberate — it is a decision about one command rather than a blanket posture."
      : `  2. Raise the unattended floor so this severity auto-approves:`,
    hard ? undefined : `       ${sensitivityCmd("unattended", "warning")}${sessionFloor}`,
    hard
      ? "  3. Replay the same command in an interactive chat and choose Allow always (same allowlist as 1)."
      : "  3. Replay the same command in an interactive chat and choose Allow always (same allowlist as 1).",
    "",
    "Allow-all and quiet do not apply to cron or heartbeat.",
    `Inspect: ${inspect}`,
    "",
    `Waiting on OpenClaw to deliver plugin reviews for scheduled runs again: ${OPENCLAW_UNATTENDED_PLUGIN_APPROVAL_ISSUE}`,
  ]
    .filter((line): line is string => line != null)
    .join("\n");
}
