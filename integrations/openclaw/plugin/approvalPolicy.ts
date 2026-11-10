/**
 * Human approval timeouts for enforce-mode Sentrook reviews.
 *
 * Interactive sessions keep a short timeout with deny-on-timeout (always fail-closed;
 * not configurable). Cron and subagent runs use a longer window but also default to
 * deny-on-timeout. scheduledTimeoutBehavior allow asks the host to let an unanswered
 * unattended review through, but it only takes effect on a host that reads the
 * approval's timeoutBehavior; see TIMEOUT_BEHAVIOR_IGNORED_THROUGH.
 */

export type IntentKind = "user" | "cron" | "subagent" | "system";
export type TimeoutBehavior = "allow" | "deny";

export interface ApprovalPolicyConfig {
  /** Interactive review timeout (ms). Default 300_000 (5 min). */
  interactiveTimeoutMs: number;
  /** Unattended review timeout (ms). Default 1_800_000 (30 min). */
  scheduledTimeoutMs: number;
  /** When an unattended review times out. Default deny (fail-closed). */
  scheduledTimeoutBehavior: TimeoutBehavior;
  /** Apply scheduled policy to these intent kinds. Default cron + subagent. */
  scheduledIntentKinds: IntentKind[];
}

export interface ApprovalTiming {
  timeoutMs: number;
  timeoutBehavior: TimeoutBehavior;
  unattended: boolean;
}

export const DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS = 300_000;
export const DEFAULT_SCHEDULED_APPROVAL_TIMEOUT_MS = 1_800_000;

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

/**
 * The newest OpenClaw release checked for `timeoutBehavior` on a plugin approval. No release up to and including
 * it reads the field: a plugin approval takes only `timeoutMs` and `timeoutReason`, and one nobody answers is
 * denied. Raise this when a newer release is checked and still ignores it; when one honours it, set this to the
 * release before it.
 */
export const TIMEOUT_BEHAVIOR_IGNORED_THROUGH = "2026.11.2";

/** `2026.10.3` (or `2026.10.3-beta.1`) as numbers; null for anything else. */
function releaseNumbers(version: string): number[] | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+.].*)?$/.exec(version.trim());
  return m ? m.slice(1, 4).map(Number) : null;
}

/** True when this host version is known to ignore a plugin approval's timeoutBehavior; false when unknown or newer. */
export function hostIgnoresTimeoutBehavior(hostVersion: string | undefined): boolean {
  const host = hostVersion ? releaseNumbers(hostVersion) : null;
  const last = releaseNumbers(TIMEOUT_BEHAVIOR_IGNORED_THROUGH)!;
  if (!host) return false;
  for (let i = 0; i < 3; i++) {
    if (host[i]! !== last[i]!) return host[i]! < last[i]!;
  }
  return true;
}

/**
 * One line for `status` and `verify` when scheduledTimeoutBehavior is allow but this host cannot honour it;
 * null otherwise (deny, or a host version that is unknown or newer than the last one checked).
 */
export function timeoutBehaviorNote(policy: ApprovalPolicyConfig, hostVersion: string | undefined): string | null {
  if (policy.scheduledTimeoutBehavior !== "allow" || !hostIgnoresTimeoutBehavior(hostVersion)) return null;
  return (
    `scheduledTimeoutBehavior allow is not honoured on OpenClaw ${hostVersion!.trim()}: ` +
    "an unattended review nobody answers is still denied"
  );
}
