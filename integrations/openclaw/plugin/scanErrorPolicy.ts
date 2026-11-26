/**
 * Scan-error policy when Sentrook does not return a usable score (unreachable, timed out, rate
 * limited, rejected, or `status: error`).
 *
 * Distinct from human-review timeouts (`approval.*`). Missing config defaults to `review` (ask when
 * attended, block when unattended). Auth and configuration failures never fail open.
 */

import { ConsentWithdrawnError } from "./auth.ts";
import { errorCard, errorCause, type SignInProblem } from "./card.ts";

export type OnScanError = "allow" | "deny" | "review";
export type ScanFailureKind = "rate_limited" | "http" | "timeout" | "network" | "config" | "scan_error";

export const DEFAULT_ON_SCAN_ERROR: OnScanError = "review";

/**
 * What happens to tool calls while an endpoint setting is invalid, for the owner's log. Every scan fails as a
 * configuration error, which `scanErrorToHookResult` never lets through; observe mode lets everything run.
 * Keep it identical to `invalid_endpoint_effect` in the Hermes plugin's `scan_error_policy.py`.
 */
export function invalidEndpointEffect(mode: string, onScanError: OnScanError): string {
  if (mode === "observe") return "no tool call is scanned until this is fixed (observe mode: nothing is blocked)";
  if (onScanError === "review") {
    return "every tool call will be held for review, or blocked on unattended runs, until this is fixed";
  }
  return "every tool call will be blocked until this is fixed";
}

export interface ScanFailure {
  ok: false;
  kind: ScanFailureKind;
  status?: number;
  retryAfterSec?: number;
  detail: string;
  /** Why the credentials did not work, when that is known; the fix is `openclaw sentrook login`. */
  setup?: SignInProblem;
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

export function parseOnScanError(
  raw: unknown,
  fallback: OnScanError = DEFAULT_ON_SCAN_ERROR,
): OnScanError {
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
  return parseOnScanError(cfg ?? env.SENTROOK_ON_SCAN_ERROR, DEFAULT_ON_SCAN_ERROR);
}

export function isScanFailure(value: unknown): value is ScanFailure {
  return typeof value === "object" && value !== null && (value as ScanFailure).ok === false;
}

export function isAuthFailure(failure: ScanFailure): boolean {
  if (failure.kind === "config") return true;
  return (
    failure.kind === "http" &&
    typeof failure.status === "number" &&
    AUTH_STATUSES.has(failure.status)
  );
}

/** Map OIDC mint / discovery errors to a scan failure (Hermes scan-auth path). */
export function scanAuthErrorToFailure(err: unknown): ScanFailure {
  if (err instanceof ConsentWithdrawnError) {
    return { ok: false, kind: "http", status: err.status, detail: "consent withdrawn on the FIDU portal", setup: "consent_withdrawn" };
  }
  const detail = (err instanceof Error ? err.message : String(err))
    .replace(/\n/g, " ")
    .trim()
    .slice(0, 200);
  const lower = detail.toLowerCase();
  const statusMatch = detail.match(/\bHTTP (\d{3})\b/i);
  const status = statusMatch ? Number(statusMatch[1]) : undefined;
  if (
    (status != null && AUTH_STATUSES.has(status)) ||
    lower.includes("unauthorized") ||
    lower.includes("invalid_client")
  ) {
    return {
      ok: false,
      kind: "http",
      status: status && AUTH_STATUSES.has(status) ? status : 401,
      detail: detail || "scan auth failed",
      ...(lower.includes("invalid_client") ? { setup: "sign_in_rejected" as const } : {}),
    };
  }
  if (lower.includes("timed out") || lower.includes("abort")) {
    return { ok: false, kind: "timeout", detail: detail || "scan auth timed out" };
  }
  return { ok: false, kind: "network", detail: detail || "scan auth failed" };
}

function detailSnippet(failure: ScanFailure, limit = 100): string {
  const raw = (failure.detail || "").trim().replace(/\n/g, " ");
  if (!raw) return "";
  if (raw.length <= limit) return raw;
  return `${raw.slice(0, Math.max(0, limit - 3))}...`;
}

/** The review card for a call that could not be scanned (`card.errorCard`). */
export function scanErrorCopy(failure: ScanFailure): { title: string; description: string } {
  return errorCard(errorCause(failure.kind, isAuthFailure(failure), failure.setup));
}

/** What the agent is told when the scan could not run for want of a working sign-in, by `ScanFailure.setup`. */
export const SIGN_IN_FIXES: Record<SignInProblem, string> = {
  not_signed_in:
    "Sentrook is not signed in on this machine, so this tool call was not scanned or run. This is a setup problem, " +
    "not a security finding. Tell the owner to run `openclaw sentrook login` in a terminal on the gateway machine. " +
    "Do not try to run it yourself or work around this.",
  sign_in_rejected:
    "Sentrook's sign-in was revoked or is wrong, so this tool call was not scanned or run. This is a setup problem, " +
    "not a security finding. Tell the owner to run `openclaw sentrook login` again in a terminal on the gateway " +
    "machine. Do not try to run it yourself or work around this.",
  consent_withdrawn:
    "The owner withdrew consent for Sentrook on the FIDU portal, so this tool call was not scanned or run. This is a " +
    "setup problem, not a security finding. Tell the owner to reconnect by running `openclaw sentrook login` in a " +
    "terminal on the gateway machine, or to switch Sentrook to observe mode. Do not try to run it yourself or work " +
    "around this.",
};

function blockReasonFor(failure: ScanFailure): string {
  if (failure.setup) return SIGN_IN_FIXES[failure.setup];
  const snippet = detailSnippet(failure);
  if (isAuthFailure(failure)) {
    const base =
      (failure.kind === "config"
        ? "Sentrook is not configured correctly "
        : "Sentrook could not authenticate to the scan service ") +
      "(configuration error, not a security policy deny). " +
      "Run `openclaw sentrook verify` and check SENTROOK_SCAN_URL, SENTROOK_OIDC_ISSUER and the " +
      "SENTROOK_SCAN_CLIENT_* credentials. " +
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
 * Auth failures (401/403) never fail-open: ``onScanError=allow`` still blocks.
 * Interactive ``review`` escalates with a configuration-error card.
 * Unattended ``review`` always blocks.
 */
export function scanErrorToHookResult(
  failure: ScanFailure,
  opts: {
    onScanError: OnScanError;
    unattended: boolean;
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
