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

function detailSnippet(failure: ScanFailure, limit = 100): string {
  const raw = (failure.detail || "").trim().replace(/\n/g, " ");
  if (!raw) return "";
  if (raw.length <= limit) return raw;
  return `${raw.slice(0, Math.max(0, limit - 3))}...`;
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
      title: "Sentrook authentication failed",
      description:
        "Sentrook could not authenticate to the scan service " +
        "(configuration error — not a security policy block). " +
        "Continue this tool without scanning?",
    };
  }
  return {
    title: "Sentrook unreachable",
    description:
      "Sentrook is unreachable, would you like your agent to continue anyway without scanning?",
  };
}

function blockReasonFor(failure: ScanFailure): string {
  const snippet = detailSnippet(failure);
  if (isAuthFailure(failure)) {
    const base =
      "Sentrook could not authenticate to the scan service " +
      "(configuration error, not a security policy deny). " +
      "Re-run `openclaw sentrook configure` / `verify`, and ensure " +
      "SENTROOK_OIDC_ISSUER matches this Sentrook environment. " +
      "The tool was not scanned or run.";
    return snippet ? `${base} Detail: ${snippet}` : base;
  }
  if (failure.kind === "rate_limited") {
    const base = "Sentrook rate-limited this scan; the tool was not scanned or run.";
    return snippet ? `${base} Detail: ${snippet}` : base;
  }
  const base =
    "Sentrook did not scan this tool call (unreachable or timed out). " +
    "This is a connectivity/service issue, not a security policy deny. " +
    "The tool was not run.";
  return snippet ? `${base} Detail: ${snippet}` : base;
}

/**
 * Map a failed /scan attempt to an OpenClaw before_tool_call result.
 *
 * Auth failures (401/403) never fail-open: ``onScanError=allow`` still blocks,
 * and unattended ``review`` never applies ``scheduledTimeoutBehavior: allow``.
 * Interactive ``review`` escalates with a configuration-error card.
 * Unattended ``review`` applies scheduledTimeoutBehavior immediately for
 * non-auth failures only (no 30 min wait).
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
    const policy = opts.onScanError;
    if (policy === "review" && !opts.unattended) {
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
    // allow, deny, or unattended review — never silently skip scans on bad auth
    return {
      block: true,
      blockReason: blockReasonFor(failure),
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
