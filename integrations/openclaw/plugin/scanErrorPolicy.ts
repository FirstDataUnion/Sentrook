/**
 * Scan-error policy when hosted Sentrook does not return a decision.
 *
 * Distinct from human-review timeouts (`approval.*`). Missing config keeps
 * today's fail-open (`allow`).
 */

export type OnScanError = "allow" | "deny" | "review";
export type ScanFailureKind = "rate_limited" | "http" | "timeout" | "network";

export interface ScanFailure {
  ok: false;
  kind: ScanFailureKind;
  status?: number;
  retryAfterSec?: number;
  detail: string;
}

export interface ScanErrorHookResult {
  block?: boolean;
  blockReason?: string;
  requireApproval?: {
    title: string;
    description: string;
    severity: "warning" | "critical";
    timeoutMs: number;
    timeoutBehavior: "allow" | "deny";
    allowedDecisions: Array<"allow-once" | "deny">;
  };
}

const AUTH_STATUSES = new Set([401, 403]);

export function parseOnScanError(raw: unknown, fallback: OnScanError = "allow"): OnScanError {
  if (raw === "allow" || raw === "deny" || raw === "review") return raw;
  if (typeof raw === "string") {
    const normalized = raw.trim().toLowerCase();
    if (normalized === "allow" || normalized === "deny" || normalized === "review") {
      return normalized;
    }
  }
  return fallback;
}

export function resolveOnScanError(sources: {
  pluginConfig?: unknown;
  env?: NodeJS.ProcessEnv;
}): OnScanError {
  const cfg = sources.pluginConfig;
  const env = sources.env ?? {};
  return parseOnScanError(cfg ?? env.SENTROOK_ON_SCAN_ERROR, "allow");
}

export function isScanFailure(value: unknown): value is ScanFailure {
  return typeof value === "object" && value !== null && (value as ScanFailure).ok === false;
}

export function isAuthFailure(failure: ScanFailure): boolean {
  return (
    failure.kind === "http" &&
    typeof failure.status === "number" &&
    AUTH_STATUSES.has(failure.status)
  );
}

export function scanErrorCopy(failure: ScanFailure): { title: string; description: string } {
  if (failure.kind === "rate_limited") {
    return {
      title: "Sentrook rate limited",
      description:
        "Sentrook rate-limited this scan. Continue this tool without a security scan?",
    };
  }
  if (isAuthFailure(failure)) {
    return {
      title: "Sentrook credentials rejected",
      description: "Sentrook rejected the scan credentials. The tool will not run.",
    };
  }
  return {
    title: "Sentrook unreachable",
    description:
      "Sentrook is unreachable, would you like your agent to continue anyway without scanning?",
  };
}

/**
 * Map a failed /scan attempt to an OpenClaw before_tool_call result.
 *
 * 401/403 always deny (misconfigured auth must not silently skip scans).
 * Unattended `review` applies scheduledTimeoutBehavior immediately (no 30 min wait).
 */
export function scanErrorToHookResult(
  failure: ScanFailure,
  opts: {
    onScanError: OnScanError;
    unattended: boolean;
    scheduledTimeoutBehavior: "allow" | "deny";
    interactiveTimeoutMs: number;
  },
): ScanErrorHookResult | undefined {
  if (isAuthFailure(failure)) {
    return {
      block: true,
      blockReason: "Sentrook rejected scan credentials",
    };
  }

  const policy = opts.onScanError;
  if (policy === "allow") return undefined;
  if (policy === "deny") {
    return {
      block: true,
      blockReason: blockReasonFor(failure),
    };
  }

  if (opts.unattended) {
    if (opts.scheduledTimeoutBehavior === "allow") return undefined;
    return {
      block: true,
      blockReason: blockReasonFor(failure),
    };
  }

  const copy = scanErrorCopy(failure);
  return {
    requireApproval: {
      title: copy.title,
      description: copy.description,
      severity: "warning",
      timeoutMs: opts.interactiveTimeoutMs,
      timeoutBehavior: "deny",
      allowedDecisions: ["allow-once", "deny"],
    },
  };
}

function blockReasonFor(failure: ScanFailure): string {
  if (failure.kind === "rate_limited") {
    return "Sentrook rate-limited this scan; the tool was not scanned";
  }
  return "Sentrook did not scan this tool call (unreachable or timed out)";
}

export function parseRetryAfterSeconds(header: string | null): number | undefined {
  if (!header) return undefined;
  const trimmed = header.trim();
  const asNumber = Number(trimmed);
  if (Number.isFinite(asNumber) && asNumber >= 0) return asNumber;
  const when = Date.parse(trimmed);
  if (!Number.isNaN(when)) {
    const delta = (when - Date.now()) / 1000;
    return delta > 0 ? delta : 0;
  }
  return undefined;
}
