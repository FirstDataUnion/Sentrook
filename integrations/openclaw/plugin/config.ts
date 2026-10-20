/**
 * Plugin configuration: endpoints, credentials, decision policy, storage and grants.
 *
 * Every value resolves as plugin config (openclaw.json `plugins.entries.sentrook.config`), then env
 * (process env plus the state-dir `.env`), then the default.
 *
 * Endpoints default to the hosted service. A non-default scan, Rookery or identity URL must be https
 * on a firstdataunion.org host: a scan URL the agent could redirect would send every tool call
 * somewhere else. `SENTROOK_DEV_ENDPOINTS=1` (env only) lifts that for local sandboxes and dev stacks.
 * An endpoint that fails these checks is a configuration error and scans fail closed.
 */

import path from "node:path";

import { type ApprovalPolicyConfig, resolveApprovalPolicyConfig } from "./approvalPolicy.ts";
import { type OnScanError, resolveOnScanError } from "./scanErrorPolicy.ts";

export const DEFAULT_SCAN_URL = "https://sentrook.firstdataunion.org";
export const DEFAULT_ROOKERY_URL = "https://rookery.firstdataunion.org";
export const DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org";
export const TRUSTED_ENDPOINT_DOMAIN = "firstdataunion.org";

export const DEFAULT_REVIEW_AT = 45;
export const DEFAULT_BLOCK_AT = 80;
export const DEFAULT_SCAN_TIMEOUT_MS = 30_000;
export const DEFAULT_HISTORY_LIMIT = 20;
export const DEFAULT_INPUT_CAP_BYTES = 256 * 1024;
export const DEFAULT_HISTORY_ARGS_CAP_BYTES = 4 * 1024;
export const DEFAULT_TRAFFIC_LOG_MAX_BYTES = 50 * 1024 * 1024;

export type Mode = "enforce" | "observe";

export type Endpoint = { ok: true; url: string } | { ok: false; reason: string };

export interface Endpoints {
  scan: Endpoint;
  rookery: Endpoint;
  issuer: Endpoint;
  dev: boolean;
}

export interface GrantConfig {
  kind: string;
  pattern: string;
  allows?: string[];
  scope?: "session" | "persistent";
  granted_at?: string;
}

export interface PluginConfig {
  endpoints: Endpoints;
  mode: Mode;
  reviewAt: number;
  blockAt: number;
  onScanError: OnScanError;
  timeoutMs: number;
  approval: ApprovalPolicyConfig;
  stateDir: string;
  trafficLog: { enabled: boolean; path: string; maxBytes: number };
  historyLimit: number;
  inputCapBytes: number;
  historyArgsCapBytes: number;
  packs: string[];
  trustedSenders: string[];
  trustedRoles: string[];
  grants: GrantConfig[];
}

type Env = NodeJS.ProcessEnv;

/** `<state>/sentrook`: every plugin-side file lives here (the scanner's guardrail list protects it). */
export function resolveStateDir(env: Env, override?: unknown): string {
  if (typeof override === "string" && override.trim()) return override.trim();
  const base =
    env.OPENCLAW_STATE_DIR?.trim() ||
    path.join(env.OPENCLAW_HOME?.trim() || env.HOME?.trim() || "/home/node", ".openclaw");
  return path.join(base, "sentrook");
}

function str(raw: unknown): string | undefined {
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  return undefined;
}

function bool(raw: unknown, fallback: boolean): boolean {
  if (typeof raw === "boolean") return raw;
  if (typeof raw === "string") {
    const v = raw.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(v)) return true;
    if (["0", "false", "no", "off"].includes(v)) return false;
  }
  return fallback;
}

function num(raw: unknown, fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  const n = typeof raw === "number" ? raw : typeof raw === "string" && raw.trim() ? Number(raw) : NaN;
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

function list(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === "string" && !!v.trim());
  if (typeof raw === "string" && raw.trim()) {
    return raw.split(",").map((v) => v.trim()).filter(Boolean);
  }
  return [];
}

/** Linear-time trailing-slash trim (a `/\/+$/` regex is polynomial on backtracking engines). */
export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") end -= 1;
  return value.slice(0, end);
}

function isTrustedHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === TRUSTED_ENDPOINT_DOMAIN || h.endsWith(`.${TRUSTED_ENDPOINT_DOMAIN}`);
}

/**
 * Rebuild an endpoint from its URL components so config text is never used as a fetch target
 * directly. Outside dev mode: https only, firstdataunion.org hosts only, no explicit port.
 */
export function parseEndpoint(raw: string, dev: boolean): Endpoint {
  let parsed: URL;
  try {
    parsed = new URL(raw.trim());
  } catch {
    return { ok: false, reason: `invalid URL: ${raw.slice(0, 80)}` };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, reason: `URL must be http or https (got ${parsed.protocol})` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: "URL must not include credentials" };
  }
  const host = parsed.hostname;
  if (!host || !/^[A-Za-z0-9._:\[\]-]+$/.test(host)) {
    return { ok: false, reason: "URL hostname is invalid" };
  }
  if (host === "169.254.169.254" || host === "[fd00:ec2::254]") {
    return { ok: false, reason: "URL must not target a metadata address" };
  }
  if (!dev) {
    if (parsed.protocol !== "https:") {
      return { ok: false, reason: "URL must be https (set SENTROOK_DEV_ENDPOINTS=1 for a local stack)" };
    }
    if (!isTrustedHost(host) || parsed.port) {
      return {
        ok: false,
        reason:
          `URL host ${host} is not a ${TRUSTED_ENDPOINT_DOMAIN} host ` +
          "(set SENTROOK_DEV_ENDPOINTS=1 for a local stack)",
      };
    }
  }
  return { ok: true, url: stripTrailingSlashes(parsed.origin + parsed.pathname) };
}

export function resolveEndpoints(cfg: Record<string, unknown>, env: Env): Endpoints {
  // Env only: plugin config is easier for an agent to reach than the gateway's environment.
  const dev = bool(env.SENTROOK_DEV_ENDPOINTS, false);
  const pick = (key: string, envVar: string, fallback: string) =>
    parseEndpoint(str(cfg[key]) ?? str(env[envVar]) ?? fallback, dev);
  return {
    scan: pick("scanUrl", "SENTROOK_SCAN_URL", DEFAULT_SCAN_URL),
    rookery: pick("rookeryUrl", "SENTROOK_ROOKERY_URL", DEFAULT_ROOKERY_URL),
    issuer: pick("oidcIssuer", "SENTROOK_OIDC_ISSUER", DEFAULT_OIDC_ISSUER),
    dev,
  };
}

function parseGrants(raw: unknown): GrantConfig[] {
  if (!Array.isArray(raw)) return [];
  const out: GrantConfig[] = [];
  for (const g of raw) {
    if (!g || typeof g !== "object") continue;
    const rec = g as Record<string, unknown>;
    const kind = str(rec.kind);
    const pattern = str(rec.pattern);
    if (!kind || !pattern) continue;
    out.push({
      kind,
      pattern,
      ...(Array.isArray(rec.allows) ? { allows: list(rec.allows) } : {}),
      scope: rec.scope === "session" ? "session" : "persistent",
      ...(str(rec.granted_at) ? { granted_at: str(rec.granted_at) } : {}),
    });
  }
  return out;
}

/**
 * Channel bindings (where a scheduled job or route is expected to deliver) become destination grants:
 * a cron delivery to its usual channel is sanctioned even though the channel is not in the prompt.
 */
function channelBindingGrants(raw: unknown): GrantConfig[] {
  return list(raw).map((pattern) => ({ kind: "destination", pattern, scope: "persistent" as const }));
}

export function resolveConfig(pluginConfig: Record<string, unknown> | undefined, env: Env): PluginConfig {
  const cfg = pluginConfig ?? {};
  const stateDir = resolveStateDir(env, cfg.stateDir);
  const mode = (str(cfg.mode) ?? str(env.SENTROOK_MODE))?.toLowerCase() === "observe" ? "observe" : "enforce";
  const reviewAt = num(cfg.reviewAt ?? env.SENTROOK_REVIEW_AT, DEFAULT_REVIEW_AT, 0, 100);
  const blockAt = Math.max(reviewAt, num(cfg.blockAt ?? env.SENTROOK_BLOCK_AT, DEFAULT_BLOCK_AT, 0, 101));
  const traffic = (cfg.trafficLog ?? {}) as Record<string, unknown>;
  return {
    endpoints: resolveEndpoints(cfg, env),
    mode,
    reviewAt,
    blockAt,
    onScanError: resolveOnScanError({ pluginConfig: cfg.onScanError, env }),
    timeoutMs: num(cfg.timeoutMs ?? env.SENTROOK_SCAN_TIMEOUT_MS, DEFAULT_SCAN_TIMEOUT_MS, 1000),
    approval: resolveApprovalPolicyConfig({
      pluginApproval: (cfg.approval ?? {}) as Record<string, unknown>,
      env,
    }),
    stateDir,
    trafficLog: {
      enabled: bool(traffic.enabled ?? env.SENTROOK_TRAFFIC_LOG_ENABLED, true),
      path: str(traffic.path) ?? str(env.SENTROOK_TRAFFIC_LOG) ?? path.join(stateDir, "traffic.jsonl"),
      maxBytes: num(traffic.maxBytes, DEFAULT_TRAFFIC_LOG_MAX_BYTES, 1024),
    },
    historyLimit: num(cfg.historyLimit, DEFAULT_HISTORY_LIMIT, 1, 200),
    inputCapBytes: num(cfg.inputCapBytes, DEFAULT_INPUT_CAP_BYTES, 1024),
    historyArgsCapBytes: num(cfg.historyArgsCapBytes, DEFAULT_HISTORY_ARGS_CAP_BYTES, 256),
    packs: list(cfg.packs).length ? list(cfg.packs) : ["tier1"],
    trustedSenders: list(cfg.trustedSenders ?? env.SENTROOK_TRUSTED_SENDERS),
    trustedRoles: list(cfg.trustedRoles ?? env.SENTROOK_TRUSTED_ROLES),
    grants: [...parseGrants(cfg.grants), ...channelBindingGrants(cfg.channelBindings)],
  };
}
