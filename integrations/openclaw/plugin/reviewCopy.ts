/**
 * Operator-facing exec review copy for OpenClaw requireApproval.
 *
 * Hosted /scan still receives length-bounded, secret/PII-scrubbed PlanIR.
 * Approval cards are rebuilt from the local pending args so a long ``command``
 * is not shown as the PlanIR placeholder ``[TRUNCATED]``. Secrets are still
 * scrubbed because Discord/Telegram forward the same strings.
 */

import { packSignalExcerpt, scrubSecrets } from "./sanitize.ts";

export const REVIEW_TITLE_MAX = 80;
export const REVIEW_DESCRIPTION_MAX = 256;

const TRUNCATED_TOKEN = "[TRUNCATED]";
const HINT = "Allow once to run it, or deny to stop the agent.";
const MIN_COMMAND_CHARS = 16;

export function pendingDisplayCommand(
  args: Record<string, unknown> | undefined,
): string | undefined {
  if (!args) return undefined;
  for (const key of ["command", "cmd"] as const) {
    const value = args[key];
    if (typeof value !== "string") continue;
    const text = value.trim();
    if (text && text !== TRUNCATED_TOKEN) return text;
  }
  return undefined;
}

function clip(text: string, limit: number): string {
  const trimmed = text.trim();
  if (trimmed.length <= limit) return trimmed;
  if (limit <= 3) return trimmed.slice(0, limit);
  return `${trimmed.slice(0, limit - 3)}...`;
}

function likelyLine(scanDescription: string | undefined, pendingTool: string): string {
  const first = (scanDescription ?? "").split("\n")[0]?.trim() ?? "";
  if (first.toLowerCase().startsWith("likely:") && !first.includes(TRUNCATED_TOKEN)) {
    return first;
  }
  if (pendingTool === "exec") return "Likely: run a shell command";
  return `Likely: use the ${pendingTool} tool`;
}

function idClause(scanDescription: string | undefined): string {
  if (!scanDescription) return "";
  for (const line of scanDescription.split("\n")) {
    const trimmed = line.trim();
    if (/^\([A-Za-z0-9,.\s-]+\)$/.test(trimmed)) return trimmed;
  }
  return "";
}

function assembleDescription(
  likely: string,
  prefix: string,
  excerpt: string,
  ids: string,
  withHint: boolean,
): string {
  const lines = [likely, `${prefix}\`${excerpt}\``];
  if (ids) lines.push(ids);
  if (withHint) lines.push(HINT);
  return lines.join("\n");
}

/**
 * Build OpenClaw title/description from local pending args when available.
 *
 * Sidecar ``review_title`` / ``review_description`` are kept when there is no
 * local command. Otherwise the command excerpt comes from the unsanitized
 * local argv (secret-scrubbed, packed to OpenClaw's 80/256 caps).
 */
export function overlayApprovalCopy(input: {
  scanTitle?: string;
  scanDescription?: string;
  fallbackTitle: string;
  fallbackDescription: string;
  pendingTool: string;
  pendingArgs?: Record<string, unknown>;
}): { title: string; description: string } {
  const localCommand = pendingDisplayCommand(input.pendingArgs);
  const titleIn = input.scanTitle?.trim() || input.fallbackTitle;
  const descriptionIn = input.scanDescription?.trim() || input.fallbackDescription;

  if (!localCommand) {
    return {
      title: clip(titleIn, REVIEW_TITLE_MAX),
      description: clip(descriptionIn, REVIEW_DESCRIPTION_MAX),
    };
  }

  const scrubbed = scrubSecrets(localCommand);
  const likely = likelyLine(input.scanDescription, input.pendingTool);
  const ids = idClause(input.scanDescription);
  const prefix = input.pendingTool === "exec" ? "run: " : `\`${input.pendingTool}\`: `;

  const title =
    !input.scanTitle?.trim() || titleIn.includes(TRUNCATED_TOKEN)
      ? packSignalExcerpt(scrubbed, REVIEW_TITLE_MAX)
      : titleIn;

  let description = "";
  for (const withHint of [true, false]) {
    let fixed = likely.length + 1 + prefix.length + 2 + 1;
    if (ids) fixed += ids.length + 1;
    if (withHint) fixed += HINT.length + 1;
    const budget = Math.max(MIN_COMMAND_CHARS, REVIEW_DESCRIPTION_MAX - fixed);
    const excerpt = packSignalExcerpt(scrubbed, budget);
    const body = assembleDescription(likely, prefix, excerpt, ids, withHint);
    if (body.length <= REVIEW_DESCRIPTION_MAX) {
      description = body;
      break;
    }
  }
  if (!description) {
    description = clip(`${likely}\n${ids}`.trim(), REVIEW_DESCRIPTION_MAX);
  }

  return {
    title: clip(title, REVIEW_TITLE_MAX),
    description: clip(description, REVIEW_DESCRIPTION_MAX),
  };
}
