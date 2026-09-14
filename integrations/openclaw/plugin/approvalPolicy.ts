/**
 * Human approval timeouts for enforce-mode Sentrook reviews.
 *
 * OpenClaw 2.0 caps plugin-approval waits at 10 minutes and always denies
 * unresolved reviews (`timeoutBehavior` is ignored by the host). Interactive
 * and unattended (cron / heartbeat, plus subagents of those) reviews share
 * that 10-minute default and cap. `scheduledTimeoutBehavior: "allow"` is still
 * accepted so older configs load, but it has no effect.
 */

import {
  classifyAttendance,
  DEFAULT_UNATTENDED_ROOT_KINDS,
  type AttendanceSignals,
  type IntentKind,
} from "./attendance.ts";

export type { IntentKind };
export type TimeoutBehavior = "allow" | "deny";

export interface ApprovalPolicyConfig {
  /** Interactive review timeout (ms). Default 600_000 (10 min). Capped at 10 min. */
  interactiveTimeoutMs: number;
  /** Unattended review timeout (ms). Default 600_000 (10 min). Capped at 10 min. */
  scheduledTimeoutMs: number;
  /**
   * Deprecated. Parsed for compatibility and diagnostics only.
   * Unresolved reviews always deny (OpenClaw 2.0).
   */
  scheduledTimeoutBehavior: TimeoutBehavior;
  /**
   * Root intent kinds that use the scheduled (unattended) policy.
   * Default cron + heartbeat. Subagents inherit the parent unless
   * ``subagent`` is listed here.
   */
  scheduledIntentKinds: IntentKind[];
}

export interface ApprovalTiming {
  timeoutMs: number;
  /** Always `deny` — OpenClaw 2.0 ignores timeoutBehavior. */
  timeoutBehavior: "deny";
  unattended: boolean;
}

/** OpenClaw 2.0 host cap for `requireApproval.timeoutMs`. */
export const MAX_APPROVAL_TIMEOUT_MS = 600_000;
export const DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS = MAX_APPROVAL_TIMEOUT_MS;
export const DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS = MAX_APPROVAL_TIMEOUT_MS;

const ALL_INTENT_KINDS: IntentKind[] = [
  "user",
  "cron",
  "heartbeat",
  "subagent",
  "system",
];

function parsePositiveInt(raw: unknown, fallback: number): number {
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) {
    return Math.floor(raw);
  }
  if (typeof raw === "string" && raw.trim()) {
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.floor(parsed);
    }
  }
  return fallback;
}

function parseClampedTimeoutMs(raw: unknown, fallback: number): number {
  return Math.min(parsePositiveInt(raw, fallback), MAX_APPROVAL_TIMEOUT_MS);
}

function parseTimeoutBehavior(raw: unknown, fallback: TimeoutBehavior): TimeoutBehavior {
  if (raw === "allow" || raw === "deny") return raw;
  if (typeof raw === "string") {
    const normalized = raw.trim().toLowerCase();
    if (normalized === "allow" || normalized === "deny") return normalized;
  }
  return fallback;
}

function parseIntentKinds(raw: unknown): IntentKind[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    return [...DEFAULT_UNATTENDED_ROOT_KINDS];
  }
  const allowed = new Set<IntentKind>(ALL_INTENT_KINDS);
  const kinds = raw
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter((item): item is IntentKind => allowed.has(item as IntentKind));
  return kinds.length ? kinds : [...DEFAULT_UNATTENDED_ROOT_KINDS];
}

export function resolveIntentKind(
  intentKind: IntentKind | undefined,
  intent: string | undefined,
): IntentKind | undefined {
  if (intentKind) return intentKind;
  if (!intent?.trim()) return undefined;
  return classifyAttendance({ intentText: intent }).kind;
}

export function resolveApprovalPolicyConfig(sources: {
  pluginApproval?: Record<string, unknown>;
  env?: NodeJS.ProcessEnv;
}): ApprovalPolicyConfig {
  const cfg = sources.pluginApproval ?? {};
  const env = sources.env ?? {};

  return {
    interactiveTimeoutMs: parseClampedTimeoutMs(
      cfg.interactiveTimeoutMs ?? env.SENTROOK_APPROVAL_TIMEOUT_MS,
      DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS,
    ),
    scheduledTimeoutMs: parseClampedTimeoutMs(
      cfg.scheduledTimeoutMs ?? env.SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_MS,
      DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS,
    ),
    scheduledTimeoutBehavior: parseTimeoutBehavior(
      cfg.scheduledTimeoutBehavior ?? env.SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_BEHAVIOR,
      "deny",
    ),
    scheduledIntentKinds: parseIntentKinds(cfg.scheduledIntentKinds),
  };
}

export function resolveApprovalTiming(
  policy: ApprovalPolicyConfig,
  unattendedOrSignals: boolean | AttendanceSignals,
): ApprovalTiming {
  const unattended =
    typeof unattendedOrSignals === "boolean"
      ? unattendedOrSignals
      : classifyAttendance(unattendedOrSignals, policy.scheduledIntentKinds).unattended;

  if (unattended) {
    return {
      timeoutMs: policy.scheduledTimeoutMs,
      timeoutBehavior: "deny",
      unattended: true,
    };
  }

  return {
    timeoutMs: policy.interactiveTimeoutMs,
    timeoutBehavior: "deny",
    unattended: false,
  };
}
