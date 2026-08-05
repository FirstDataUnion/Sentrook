/**
 * Human approval timeouts for enforce-mode Sentrook reviews.
 *
 * Interactive sessions keep a short timeout with deny-on-timeout (operator is present).
 * Cron and subagent runs use a longer window and allow-on-timeout so unattended jobs
 * (morning brief, spawned collectors) are not blocked when nobody is at the keyboard.
 */

export type IntentKind = "user" | "cron" | "subagent" | "system";
export type TimeoutBehavior = "allow" | "deny";

export interface ApprovalPolicyConfig {
  /** Interactive review timeout (ms). Default 120_000 (2 min). */
  interactiveTimeoutMs: number;
  /** Unattended review timeout (ms). Default 900_000 (15 min). */
  scheduledTimeoutMs: number;
  /** When an unattended review times out. Default allow. */
  scheduledTimeoutBehavior: TimeoutBehavior;
  /** Apply scheduled policy to these intent kinds. Default cron + subagent. */
  scheduledIntentKinds: IntentKind[];
  /** When false, all intents use the interactive policy. */
  scheduledApprovalEnabled: boolean;
}

export interface ApprovalTiming {
  timeoutMs: number;
  timeoutBehavior: TimeoutBehavior;
  unattended: boolean;
}

export const DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS = 120_000;
export const DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS = 900_000;

const DEFAULT_SCHEDULED_INTENT_KINDS: IntentKind[] = ["cron", "subagent"];

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

function parseTimeoutBehavior(raw: unknown, fallback: TimeoutBehavior): TimeoutBehavior {
  if (raw === "allow" || raw === "deny") return raw;
  if (typeof raw === "string") {
    const normalized = raw.trim().toLowerCase();
    if (normalized === "allow" || normalized === "deny") return normalized;
  }
  return fallback;
}

function parseBool(raw: unknown, fallback: boolean): boolean {
  if (typeof raw === "boolean") return raw;
  if (typeof raw === "string") {
    const normalized = raw.trim().toLowerCase();
    if (normalized === "1" || normalized === "true" || normalized === "yes") return true;
    if (normalized === "0" || normalized === "false" || normalized === "no") return false;
  }
  return fallback;
}

function parseIntentKinds(raw: unknown): IntentKind[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    return [...DEFAULT_SCHEDULED_INTENT_KINDS];
  }
  const allowed = new Set<IntentKind>(["user", "cron", "subagent", "system"]);
  const kinds = raw
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter((item): item is IntentKind => allowed.has(item as IntentKind));
  return kinds.length ? kinds : [...DEFAULT_SCHEDULED_INTENT_KINDS];
}

export function resolveIntentKind(
  intentKind: IntentKind | undefined,
  intent: string | undefined,
): IntentKind | undefined {
  if (intentKind) return intentKind;
  if (!intent?.trim()) return undefined;
  const normalized = intent.trim();
  if (/^\s*\[cron:/i.test(normalized)) return "cron";
  if (/\[Subagent Context\]|\[Subagent Task\]/i.test(normalized)) return "subagent";
  if (/^\s*\[system[:\]]/i.test(normalized)) return "system";
  return "user";
}

export function resolveApprovalPolicyConfig(sources: {
  pluginApproval?: Record<string, unknown>;
  env?: NodeJS.ProcessEnv;
}): ApprovalPolicyConfig {
  const cfg = sources.pluginApproval ?? {};
  const env = sources.env ?? {};

  return {
    interactiveTimeoutMs: parsePositiveInt(
      cfg.interactiveTimeoutMs ?? env.SENTROOK_APPROVAL_TIMEOUT_MS,
      DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS,
    ),
    scheduledTimeoutMs: parsePositiveInt(
      cfg.scheduledTimeoutMs ?? env.SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_MS,
      DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS,
    ),
    scheduledTimeoutBehavior: parseTimeoutBehavior(
      cfg.scheduledTimeoutBehavior ?? env.SENTROOK_SCHEDULED_APPROVAL_TIMEOUT_BEHAVIOR,
      "allow",
    ),
    scheduledIntentKinds: parseIntentKinds(cfg.scheduledIntentKinds),
    scheduledApprovalEnabled: parseBool(
      cfg.enabled ?? env.SENTROOK_SCHEDULED_APPROVAL_ENABLED,
      true,
    ),
  };
}

export function resolveApprovalTiming(
  policy: ApprovalPolicyConfig,
  intentKind: IntentKind | undefined,
  intent: string | undefined,
): ApprovalTiming {
  const kind = resolveIntentKind(intentKind, intent);
  const unattended =
    policy.scheduledApprovalEnabled &&
    kind != null &&
    policy.scheduledIntentKinds.includes(kind);

  if (unattended) {
    return {
      timeoutMs: policy.scheduledTimeoutMs,
      timeoutBehavior: policy.scheduledTimeoutBehavior,
      unattended: true,
    };
  }

  return {
    timeoutMs: policy.interactiveTimeoutMs,
    timeoutBehavior: "deny",
    unattended: false,
  };
}
