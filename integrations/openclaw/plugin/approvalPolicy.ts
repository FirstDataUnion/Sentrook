/**
 * Human approval timeouts for enforce-mode Sentrook reviews.
 *
 * OpenClaw 2.0 caps plugin-approval waits at 10 minutes and always denies
 * unresolved reviews (`timeoutBehavior` is ignored by the host). Interactive
 * and unattended (cron/subagent) reviews share that 10-minute default and cap.
 * `scheduledTimeoutBehavior: "allow"` is still accepted so older configs load,
 * but it has no effect.
 */

export type IntentKind = "user" | "cron" | "subagent" | "system";
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
  /** Apply scheduled policy to these intent kinds. Default cron + subagent. */
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
  intentKind: IntentKind | undefined,
  intent: string | undefined,
): ApprovalTiming {
  const kind = resolveIntentKind(intentKind, intent);
  const unattended =
    kind != null && policy.scheduledIntentKinds.includes(kind);

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
