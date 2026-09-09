/**
 * Local session policy after a hosted ``review``: allow-all, quiet TTL, and
 * persisted attended / unattended severity floors (legacy ``lenient`` = info).
 * Never overrides block or scan-error. Allow-all and quiet stay attended-only
 * and only apply when that session’s attended floor is still Default.
 * Hard L2 reviews are included — the hosted scan already finished; if it still
 * returned review, the matching floor applies.
 */

export const QUIET_CAP_MS = 8 * 60 * 60 * 1000;

export type ReviewSeverity = "info" | "warning" | "critical";
/** ``strict`` prompts every hosted review. Otherwise auto-approve that severity and below. */
export type Sensitivity = "strict" | ReviewSeverity;
export type SensitivityScope = "attended" | "unattended";
export type ReviewSkipReason = "allowlist" | "quiet" | "lenient" | "allow-all" | "session";
export type SensitivityHighlight = "on" | "covered" | "off";

export const SENSITIVITY_BUTTONS: Sensitivity[] = ["strict", "info", "warning", "critical"];

const REVIEW_SEV_RANK: Record<ReviewSeverity, number> = { info: 0, warning: 1, critical: 2 };

const SENSITIVITY_ALIASES: Record<string, Sensitivity> = {
  strict: "strict",
  info: "info",
  lenient: "info",
  warning: "warning",
  warn: "warning",
  critical: "critical",
};

export type SessionPolicyFlags = {
  allowAll: boolean;
  quietUntilMs: number | null;
  /** Null / omit = inherit the matching global floor. */
  attendedSensitivity?: Sensitivity | null;
  unattendedSensitivity?: Sensitivity | null;
};

const DURATION_RE =
  /^(\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)$/i;

/** Canonical sensitivity, or undefined when the token is not recognised. ``lenient`` → ``info``. */
export function parseSensitivityToken(raw: unknown): Sensitivity | undefined {
  if (typeof raw !== "string") return undefined;
  return SENSITIVITY_ALIASES[raw.trim().toLowerCase()];
}

export function parseSensitivity(raw: unknown, fallback: Sensitivity = "strict"): Sensitivity {
  return parseSensitivityToken(raw) ?? fallback;
}

const SESSION_DEFAULT_TOKENS = new Set(["default", "off", "inherit", "none"]);

/**
 * Session floor token. ``null`` inherits the matching global floor.
 * ``undefined`` when the token is not recognised. ``lenient`` → ``info``.
 */
export function parseSessionSensitivityToken(raw: unknown): Sensitivity | null | undefined {
  if (typeof raw !== "string") return undefined;
  const n = raw.trim().toLowerCase();
  if (!n) return undefined;
  if (SESSION_DEFAULT_TOKENS.has(n)) return null;
  return parseSensitivityToken(n);
}

/** Display token for a session floor. ``null`` / omit → ``default``. */
export function sessionFloorLabel(value: Sensitivity | null | undefined): string {
  return value ?? "default";
}

/** Hosted default when ``review_severity`` is missing is warning (see serve/response.py). */
export function reviewSeverityOf(raw: string | undefined): ReviewSeverity {
  const n = (raw ?? "").trim().toLowerCase();
  if (n === "info" || n === "warning" || n === "critical") return n;
  return "warning";
}

function severityRank(value: Sensitivity): number {
  if (value === "strict") return -1;
  return REVIEW_SEV_RANK[value];
}

export function sensitivityCoversReview(
  sensitivity: Sensitivity,
  reviewSeverity: string | undefined,
): boolean {
  if (sensitivity === "strict") return false;
  return REVIEW_SEV_RANK[reviewSeverityOf(reviewSeverity)] <= REVIEW_SEV_RANK[sensitivity];
}

/** Selected button plus every lower auto-accept level (not strict). */
export function sensitivityFloorHighlight(
  selected: Sensitivity,
  button: Sensitivity,
): SensitivityHighlight {
  if (button === selected) return "on";
  if (selected === "strict" || button === "strict") return "off";
  return severityRank(button) < severityRank(selected) ? "covered" : "off";
}

export function resolveUnattendedSensitivity(
  pluginCfg: Record<string, unknown> | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Sensitivity {
  if (
    typeof env.SENTROOK_UNATTENDED_SENSITIVITY === "string" &&
    env.SENTROOK_UNATTENDED_SENSITIVITY.trim()
  ) {
    return parseSensitivity(env.SENTROOK_UNATTENDED_SENSITIVITY, "strict");
  }
  return parseSensitivity(pluginCfg?.unattendedSensitivity, "strict");
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

/** True when either the gateway-wide or session allow-all flag is on. */
export function combinedAllowAll(globalOn: boolean, sessionOn: boolean): boolean {
  return globalOn || sessionOn;
}

/** The later of two quiet deadlines (null means unset). */
export function laterQuietUntil(
  globalUntilMs: number | null,
  sessionUntilMs: number | null,
): number | null {
  if (globalUntilMs == null) return sessionUntilMs;
  if (sessionUntilMs == null) return globalUntilMs;
  return Math.max(globalUntilMs, sessionUntilMs);
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
  unattendedSensitivity?: Sensitivity;
  /** Set (not Default) session unattended floor. */
  sessionUnattended?: Sensitivity | null;
  /** Set (not Default) session attended floor. */
  sessionAttended?: Sensitivity | null;
  reviewSeverity?: string;
  allowlistHit: boolean;
  nowMs?: number;
}): ReviewSkipReason | undefined {
  if (input.hostedDecision !== "review") return undefined;
  if (input.allowlistHit) return "allowlist";
  if (input.unattended) {
    const sessionFloor = input.sessionUnattended ?? null;
    const floor = sessionFloor ?? input.unattendedSensitivity ?? "strict";
    if (sensitivityCoversReview(floor, input.reviewSeverity)) {
      return sessionFloor != null ? "session" : "lenient";
    }
    return undefined;
  }
  if (input.sessionAttended != null) {
    return sensitivityCoversReview(input.sessionAttended, input.reviewSeverity)
      ? "session"
      : undefined;
  }
  if (input.allowAll) return "allow-all";
  const now = input.nowMs ?? Date.now();
  if (input.quietUntilMs != null && now < input.quietUntilMs) return "quiet";
  if (sensitivityCoversReview(input.sensitivity, input.reviewSeverity)) return "lenient";
  return undefined;
}

export function skipLabelSource(
  reason: ReviewSkipReason,
): "allowlist" | "quiet" | "lenient" | "allow-all" | "session" {
  return reason;
}

export function skipResolutionDecision(
  reason: ReviewSkipReason,
): "allowlist-hit" | "quiet-skip" | "lenient-skip" | "allow-all-skip" | "session-skip" {
  switch (reason) {
    case "allowlist":
      return "allowlist-hit";
    case "quiet":
      return "quiet-skip";
    case "lenient":
      return "lenient-skip";
    case "allow-all":
      return "allow-all-skip";
    case "session":
      return "session-skip";
  }
}
