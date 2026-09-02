/**
 * Local session policy after a hosted ``review``: allow-all, quiet TTL, and
 * lenient (info-only). Never overrides block, scan-error, or unattended.
 */

export const QUIET_CAP_MS = 8 * 60 * 60 * 1000;
export const DEFAULT_HISTORY_LIMIT = 10;

export type Sensitivity = "strict" | "lenient";
export type ReviewSkipReason = "allowlist" | "quiet" | "lenient" | "allow-all";

export type SessionPolicyFlags = {
  allowAll: boolean;
  quietUntilMs: number | null;
};

const DURATION_RE =
  /^(\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)$/i;

export function parseSensitivity(raw: unknown, fallback: Sensitivity = "strict"): Sensitivity {
  if (typeof raw !== "string") return fallback;
  const n = raw.trim().toLowerCase();
  if (n === "strict" || n === "lenient") return n;
  return fallback;
}

export function resolveSensitivity(
  pluginCfg: Record<string, unknown> | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Sensitivity {
  if (typeof env.SENTROOK_SENSITIVITY === "string" && env.SENTROOK_SENSITIVITY.trim()) {
    return parseSensitivity(env.SENTROOK_SENSITIVITY, "strict");
  }
  return parseSensitivity(pluginCfg?.sensitivity, "strict");
}

export function parseOnOff(raw: string | undefined, defaultOn: boolean): boolean | { error: string } {
  if (raw == null || raw.trim() === "") return defaultOn;
  const n = raw.trim().toLowerCase();
  if (["on", "1", "true", "yes"].includes(n)) return true;
  if (["off", "0", "false", "no"].includes(n)) return false;
  return { error: `Use on or off, not "${raw.trim()}".` };
}

export function parseQuietDuration(
  raw: string,
  nowMs: number = Date.now(),
): { untilMs: number | null } | { error: string } {
  const n = raw.trim().toLowerCase();
  if (!n) {
    return { error: "Usage: /sentrook quiet <duration|off>  (e.g. 30m, 2h, 8h, off)" };
  }
  if (n === "off" || n === "0") return { untilMs: null };
  const match = n.match(DURATION_RE);
  if (!match) {
    return { error: "Duration must be like 30m, 2h, or 8h (max 8 hours), or off." };
  }
  const amount = Number.parseInt(match[1] ?? "0", 10);
  const unit = (match[2] ?? "m").charAt(0).toLowerCase();
  if (!Number.isFinite(amount) || amount <= 0) {
    return { error: "Duration must be a positive number." };
  }
  const ms =
    unit === "s" ? amount * 1000 : unit === "h" ? amount * 60 * 60 * 1000 : amount * 60 * 1000;
  if (ms > QUIET_CAP_MS) {
    return { error: "Quiet is capped at 8 hours. Use 8h or less, or off." };
  }
  return { untilMs: nowMs + ms };
}

export function quietRemainingMs(
  quietUntilMs: number | null,
  nowMs: number = Date.now(),
): number {
  if (quietUntilMs == null) return 0;
  return Math.max(0, quietUntilMs - nowMs);
}

export function formatDuration(ms: number): string {
  if (ms <= 0) return "0s";
  const totalSec = Math.round(ms / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const totalMin = Math.round(ms / 60000);
  if (totalMin < 60) return `${totalMin}m`;
  const hours = Math.floor(ms / 3600000);
  const mins = Math.round((ms % 3600000) / 60000);
  return mins > 0 ? `${hours}h${mins}m` : `${hours}h`;
}

export function resolveReviewSkip(input: {
  hostedDecision: "allow" | "review" | "block";
  unattended: boolean;
  allowAll: boolean;
  quietUntilMs: number | null;
  sensitivity: Sensitivity;
  reviewSeverity?: string;
  allowlistHit: boolean;
  nowMs?: number;
}): ReviewSkipReason | undefined {
  if (input.hostedDecision !== "review") return undefined;
  if (input.allowlistHit) return "allowlist";
  if (input.unattended) return undefined;
  if (input.allowAll) return "allow-all";
  const now = input.nowMs ?? Date.now();
  if (input.quietUntilMs != null && now < input.quietUntilMs) return "quiet";
  if (input.sensitivity === "lenient" && input.reviewSeverity === "info") return "lenient";
  return undefined;
}

export function skipLabelSource(
  reason: ReviewSkipReason,
): "allowlist" | "quiet" | "lenient" | "allow-all" {
  return reason;
}

export function skipResolutionDecision(
  reason: ReviewSkipReason,
): "allowlist-hit" | "quiet-skip" | "lenient-skip" | "allow-all-skip" {
  switch (reason) {
    case "allowlist":
      return "allowlist-hit";
    case "quiet":
      return "quiet-skip";
    case "lenient":
      return "lenient-skip";
    case "allow-all":
      return "allow-all-skip";
  }
}
