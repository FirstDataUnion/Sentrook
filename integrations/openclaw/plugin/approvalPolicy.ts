/**
 * Human approval timing for enforce-mode Sentrook reviews.
 *
 * A review in a chat waits `interactiveTimeoutMs` for an answer and is denied when nobody
 * answers (always fail-closed; not configurable). `scheduledIntentKinds` says which runs are
 * unattended: a review there is held for the owner (hold.ts) instead of asked. OpenClaw's own background runs, their
 * saves and every other call, are unattended whatever it says (backgroundSave.ts).
 */

export type IntentKind = "user" | "cron" | "subagent" | "system";

export interface ApprovalPolicyConfig {
  /** Interactive review timeout (ms). Default 300_000 (5 min). */
  interactiveTimeoutMs: number;
  /** Runs of these intent kinds are unattended: a review there is held. Default cron + subagent. */
  scheduledIntentKinds: IntentKind[];
}

export interface ApprovalTiming {
  /** How long a review asked in a chat waits for an answer. */
  timeoutMs: number;
  /** Nobody can answer a review in this run: it is held instead of asked. */
  unattended: boolean;
}

export const DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS = 300_000;

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
    scheduledIntentKinds: parseIntentKinds(cfg.scheduledIntentKinds),
  };
}

export function resolveApprovalTiming(
  policy: ApprovalPolicyConfig,
  intentKind: IntentKind | undefined,
  intent: string | undefined,
): ApprovalTiming {
  const kind = resolveIntentKind(intentKind, intent);
  return {
    timeoutMs: policy.interactiveTimeoutMs,
    unattended: kind != null && policy.scheduledIntentKinds.includes(kind),
  };
}
