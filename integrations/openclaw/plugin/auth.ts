/**
 * Scan auth for hosted Sentrook: OIDC client_credentials (preferred) or static API key.
 *
 * Credentials are read from process env and, when missing, from ~/.openclaw/.env
 * (SENTROOK_SCAN_*). We do not put SecretRefs in openclaw.json — unresolved refs on
 * an enabled plugin fail-close the gateway. Optional plaintext overrides in plugin
 * config still work.
 *
 * Reading the state-dir dotenv ourselves matters on Docker: `printenv` inside
 * `docker compose exec` only shows Compose-injected env, not vars OpenClaw loaded
 * into the gateway Node process. File fallback keeps scans working either way.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

export type ScanApiKeyRef = {
  source?: string;
  provider?: string;
  id?: string;
};

export const DEFAULT_SCAN_ISSUER = "https://identity.firstdataunion.org";
export const DEFAULT_SCAN_AUDIENCE = "sentrook";
export const DEFAULT_SCAN_SCOPE = "sentrook.scan";
const TOKEN_EXPIRY_SKEW_SEC = 60;

export const CLIENT_ID_VAR = "SENTROOK_SCAN_CLIENT_ID";
export const CLIENT_SECRET_VAR = "SENTROOK_SCAN_CLIENT_SECRET";
export const API_KEY_VAR = "SENTROOK_SCAN_API_KEY";

export type ScanOidcCredentials = {
  clientId: string;
  clientSecret: string;
  issuer: string;
  audience: string;
  scope: string;
};

export type ScanAuthConfig = {
  apiKey: string | null;
  oidc: ScanOidcCredentials | null;
};

type TokenCache = {
  accessToken: string;
  expiresAtMs: number;
  cacheKey: string;
};

let tokenCache: TokenCache | null = null;

/** Test helper — clear in-memory access token cache. */
export function clearScanTokenCache(): void {
  tokenCache = null;
}

/** Parse KEY=VALUE lines (no export, no multiline). */
export function parseDotenvText(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (key) out[key] = value;
  }
  return out;
}

export function readDotenvFile(dotenvFile: string): Record<string, string> {
  if (!existsSync(dotenvFile)) return {};
  try {
    return parseDotenvText(readFileSync(dotenvFile, "utf8"));
  } catch {
    return {};
  }
}

/**
 * Fill missing keys from OpenClaw state-dir `.env`.
 * Never overrides non-empty keys already set in `env` (matches OpenClaw dotenv precedence).
 *
 * `docker compose exec … printenv` only shows Compose-injected env — not vars OpenClaw
 * loaded into the gateway Node process — so the plugin also reads this file directly.
 */
export function envWithOpenclawDotenv(
  env: NodeJS.ProcessEnv = process.env,
  opts: { stateDir?: string; dotenvPath?: string } = {},
): NodeJS.ProcessEnv {
  const dotenvFile =
    opts.dotenvPath?.trim() ||
    path.join(
      opts.stateDir?.trim() ||
        env.OPENCLAW_STATE_DIR?.trim() ||
        path.join(env.OPENCLAW_HOME?.trim() || env.HOME?.trim() || "/home/node", ".openclaw"),
      ".env",
    );

  const fromFile = readDotenvFile(dotenvFile);
  const merged: NodeJS.ProcessEnv = { ...env };
  for (const [key, value] of Object.entries(fromFile)) {
    const existing = merged[key];
    if (existing === undefined || existing === "") {
      merged[key] = value;
    }
  }
  return merged;
}

export function resolveSecretString(
  raw: unknown,
  env: NodeJS.ProcessEnv,
  envFallback?: string,
): string | null {
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    return trimmed || null;
  }

  if (raw && typeof raw === "object") {
    const ref = raw as ScanApiKeyRef;
    if (ref.source === "env" && typeof ref.id === "string" && ref.id) {
      const value = env[ref.id];
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }
  }

  if (envFallback) {
    const fallback = env[envFallback];
    if (typeof fallback === "string" && fallback.trim()) {
      return fallback.trim();
    }
  }
  return null;
}

export function resolveApiKey(
  raw: unknown,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  return resolveSecretString(raw, env, API_KEY_VAR);
}

export function resolveScanAuthConfig(
  cfg: Record<string, unknown>,
  env: NodeJS.ProcessEnv = process.env,
): ScanAuthConfig {
  const apiKey = resolveApiKey(cfg.apiKey, env);
  const clientId = resolveSecretString(cfg.clientId, env, CLIENT_ID_VAR);
  const clientSecret = resolveSecretString(
    cfg.clientSecret,
    env,
    CLIENT_SECRET_VAR,
  );
  const issuer =
    resolveSecretString(cfg.oidcIssuer, env, "SENTROOK_OIDC_ISSUER") ||
    DEFAULT_SCAN_ISSUER;
  const audience =
    resolveSecretString(cfg.oidcAudience, env, "SENTROOK_OIDC_AUDIENCE") ||
    DEFAULT_SCAN_AUDIENCE;
  const scope =
    resolveSecretString(cfg.oidcScope, env, "SENTROOK_OIDC_SCOPE") || DEFAULT_SCAN_SCOPE;

  const oidc =
    clientId && clientSecret
      ? { clientId, clientSecret, issuer: stripTrailingSlashes(issuer), audience, scope }
      : null;

  return { apiKey, oidc };
}

/** Linear-time trailing-slash trim. `/\/+$/` is polynomial ReDoS on backtracking engines. */
export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") {
    end -= 1;
  }
  return value.slice(0, end);
}

export type ParsedScanUrl =
  | { ok: true; href: string; https: boolean }
  | { ok: false; reason: string };

/**
 * Rebuild a scan base URL from URL components so file-derived config cannot be
 * forwarded as an arbitrary fetch target (SSRF / file-data-in-request).
 */
export function parseScanBaseUrl(raw: string): ParsedScanUrl {
  let parsed: URL;
  try {
    parsed = new URL(raw.trim());
  } catch {
    return { ok: false, reason: "invalid scan URL" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, reason: `scan URL must be http or https (got ${parsed.protocol})` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: "scan URL must not include credentials" };
  }
  const host = parsed.hostname;
  if (!host || !/^[A-Za-z0-9._:-]+$/.test(host)) {
    return { ok: false, reason: "scan URL hostname is invalid" };
  }
  if (host === "169.254.169.254" || host === "::ffff:169.254.169.254") {
    return { ok: false, reason: "scan URL must not target link-local metadata addresses" };
  }
  parsed.hash = "";
  parsed.search = "";
  return {
    ok: true,
    href: stripTrailingSlashes(parsed.origin + parsed.pathname),
    https: parsed.protocol === "https:",
  };
}

/** HTTPS scan endpoints need credentials; HTTP (forks pinning SCAN_BASE_URL) does not. */
export function urlRequiresScanApiKey(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return url.startsWith("https://");
  }
}

export function urlRequiresScanAuth(url: string): boolean {
  return urlRequiresScanApiKey(url);
}

export function hasScanCredentials(auth: ScanAuthConfig): boolean {
  return Boolean(auth.oidc || auth.apiKey);
}

function cacheKeyFor(oidc: ScanOidcCredentials): string {
  return `${oidc.issuer}|${oidc.clientId}|${oidc.audience}|${oidc.scope}`;
}

type DiscoveryDoc = {
  token_endpoint?: string;
};

async function fetchTokenEndpoint(
  issuer: string,
  fetchImpl: typeof fetch,
): Promise<string> {
  const discoveryUrl = `${stripTrailingSlashes(issuer)}/.well-known/openid-configuration`;
  const response = await fetchImpl(discoveryUrl);
  if (!response.ok) {
    throw new Error(`OIDC discovery failed: HTTP ${response.status}`);
  }
  const doc = (await response.json()) as DiscoveryDoc;
  if (!doc.token_endpoint || typeof doc.token_endpoint !== "string") {
    throw new Error("OIDC discovery missing token_endpoint");
  }
  return doc.token_endpoint;
}

function decodeJwtExpMs(accessToken: string): number | null {
  const parts = accessToken.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1]!, "base64url").toString("utf8"),
    ) as { exp?: number };
    if (typeof payload.exp === "number" && Number.isFinite(payload.exp)) {
      return payload.exp * 1000;
    }
  } catch {
    return null;
  }
  return null;
}

export async function getScanAccessToken(
  oidc: ScanOidcCredentials,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const key = cacheKeyFor(oidc);
  const now = Date.now();
  if (
    tokenCache &&
    tokenCache.cacheKey === key &&
    tokenCache.expiresAtMs > now + TOKEN_EXPIRY_SKEW_SEC * 1000
  ) {
    return tokenCache.accessToken;
  }

  const tokenEndpoint = await fetchTokenEndpoint(oidc.issuer, fetchImpl);
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: oidc.clientId,
    client_secret: oidc.clientSecret,
    scope: oidc.scope,
    audience: oidc.audience,
  });

  const response = await fetchImpl(tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const responseText = await response.text();
  if (!response.ok) {
    const hint = responseText.trim().slice(0, 200);
    throw new Error(
      `client_credentials token mint failed: HTTP ${response.status}` +
        (hint ? `: ${hint}` : ""),
    );
  }
  let payload: { access_token?: string; expires_in?: number };
  try {
    payload = JSON.parse(responseText) as {
      access_token?: string;
      expires_in?: number;
    };
  } catch {
    throw new Error("token response was not JSON");
  }
  if (!payload.access_token) {
    throw new Error("token response missing access_token");
  }

  const jwtExp = decodeJwtExpMs(payload.access_token);
  const expiresInSec =
    typeof payload.expires_in === "number" && payload.expires_in > 0
      ? payload.expires_in
      : 1800;
  const expiresAtMs = jwtExp ?? now + expiresInSec * 1000;

  tokenCache = {
    accessToken: payload.access_token,
    expiresAtMs,
    cacheKey: key,
  };
  return payload.access_token;
}

/** Resolve Bearer token: OIDC JWT preferred, else static API key. */
export async function resolveScanBearerToken(
  auth: ScanAuthConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<string | null> {
  if (auth.oidc) {
    return getScanAccessToken(auth.oidc, fetchImpl);
  }
  return auth.apiKey;
}

export async function buildScanAuthHeadersAsync(
  auth: ScanAuthConfig,
  extra: Record<string, string> = {},
  fetchImpl: typeof fetch = fetch,
): Promise<Record<string, string>> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...extra,
  };
  const bearer = await resolveScanBearerToken(auth, fetchImpl);
  if (bearer) {
    headers.authorization = `Bearer ${bearer}`;
  }
  return headers;
}

/** Sync helper for static API key only (tests / callers without OIDC). */
export function buildScanAuthHeaders(
  apiKey: string | null,
  extra: Record<string, string> = {},
): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...extra,
  };
  if (apiKey) {
    headers.authorization = `Bearer ${apiKey}`;
  }
  return headers;
}
