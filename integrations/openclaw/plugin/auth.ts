/**
 * Scan auth: OIDC client_credentials against the identity service.
 *
 * Credentials come from plugin config or env and, when missing, from the OpenClaw state-dir `.env`
 * (SENTROOK_SCAN_CLIENT_ID / SENTROOK_SCAN_CLIENT_SECRET). Secrets never go into openclaw.json:
 * unresolved SecretRefs on an enabled plugin fail-close the gateway.
 *
 * Reading the state-dir dotenv ourselves matters on Docker: `docker compose exec … printenv` only
 * shows Compose-injected env, not vars OpenClaw loaded into the gateway process.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { stripTrailingSlashes } from "./config.ts";

export const DEFAULT_SCAN_AUDIENCE = "sentrook";
export const DEFAULT_SCAN_SCOPE = "sentrook.scan";
export const DEFAULT_AUTH_TIMEOUT_MS = 30_000;
const TOKEN_EXPIRY_SKEW_SEC = 60;

export const CLIENT_ID_VAR = "SENTROOK_SCAN_CLIENT_ID";
export const CLIENT_SECRET_VAR = "SENTROOK_SCAN_CLIENT_SECRET";

export interface OidcCredentials {
  clientId: string;
  clientSecret: string;
  issuer: string;
  audience: string;
  scope: string;
}

type TokenCache = { accessToken: string; expiresAtMs: number; cacheKey: string };
let tokenCache: TokenCache | null = null;

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

/** Fill missing keys from the OpenClaw state-dir `.env`; never overrides non-empty env values. */
export function envWithOpenclawDotenv(
  env: NodeJS.ProcessEnv = process.env,
  opts: { dotenvPath?: string } = {},
): NodeJS.ProcessEnv {
  const dotenvFile =
    opts.dotenvPath?.trim() ||
    path.join(
      env.OPENCLAW_STATE_DIR?.trim() ||
        path.join(env.OPENCLAW_HOME?.trim() || env.HOME?.trim() || "/home/node", ".openclaw"),
      ".env",
    );
  let fromFile: Record<string, string> = {};
  if (existsSync(dotenvFile)) {
    try {
      fromFile = parseDotenvText(readFileSync(dotenvFile, "utf8"));
    } catch {
      fromFile = {};
    }
  }
  const merged: NodeJS.ProcessEnv = { ...env };
  for (const [key, value] of Object.entries(fromFile)) {
    if (merged[key] === undefined || merged[key] === "") merged[key] = value;
  }
  return merged;
}

/** A plain string, or an env SecretRef `{source: "env", id}`, else the env fallback. */
export function resolveSecretString(raw: unknown, env: NodeJS.ProcessEnv, envFallback?: string): string | null {
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  if (raw && typeof raw === "object") {
    const ref = raw as { source?: string; id?: string };
    if (ref.source === "env" && typeof ref.id === "string" && env[ref.id]?.trim()) {
      return env[ref.id]!.trim();
    }
  }
  if (envFallback && env[envFallback]?.trim()) return env[envFallback]!.trim();
  return null;
}

export function resolveOidcCredentials(
  cfg: Record<string, unknown>,
  env: NodeJS.ProcessEnv,
  issuer: string,
): OidcCredentials | null {
  const clientId = resolveSecretString(cfg.clientId, env, CLIENT_ID_VAR);
  const clientSecret = resolveSecretString(cfg.clientSecret, env, CLIENT_SECRET_VAR);
  if (!clientId || !clientSecret) return null;
  return {
    clientId,
    clientSecret,
    issuer: stripTrailingSlashes(issuer),
    audience: resolveSecretString(cfg.oidcAudience, env, "SENTROOK_OIDC_AUDIENCE") || DEFAULT_SCAN_AUDIENCE,
    scope: resolveSecretString(cfg.oidcScope, env, "SENTROOK_OIDC_SCOPE") || DEFAULT_SCAN_SCOPE,
  };
}

function fetchWithTimeout(
  fetchImpl: typeof fetch,
  timeoutMs: number,
  input: string,
  init?: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetchImpl(input, { ...init, signal: controller.signal, redirect: "error" })
    .catch((err) => {
      throw controller.signal.aborted ? new Error(`OIDC request timed out after ${timeoutMs}ms`) : err;
    })
    .finally(() => clearTimeout(timer));
}

function decodeJwtExpMs(token: string): number | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as { exp?: number };
    return typeof payload.exp === "number" && Number.isFinite(payload.exp) ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
}

/**
 * Discovery is fetched from the issuer and its `token_endpoint` must be on the issuer's origin, so a
 * tampered discovery document cannot send the client secret elsewhere.
 */
export async function getScanAccessToken(
  oidc: OidcCredentials,
  fetchImpl: typeof fetch = fetch,
  timeoutMs: number = DEFAULT_AUTH_TIMEOUT_MS,
): Promise<string> {
  const key = `${oidc.issuer}|${oidc.clientId}|${oidc.audience}|${oidc.scope}`;
  const now = Date.now();
  if (tokenCache && tokenCache.cacheKey === key && tokenCache.expiresAtMs > now + TOKEN_EXPIRY_SKEW_SEC * 1000) {
    return tokenCache.accessToken;
  }

  const discovery = await fetchWithTimeout(fetchImpl, timeoutMs, `${oidc.issuer}/.well-known/openid-configuration`);
  if (!discovery.ok) throw new Error(`OIDC discovery failed: HTTP ${discovery.status}`);
  const doc = (await discovery.json()) as { token_endpoint?: unknown };
  if (typeof doc.token_endpoint !== "string" || !doc.token_endpoint) {
    throw new Error("OIDC discovery missing token_endpoint");
  }
  if (new URL(doc.token_endpoint).origin !== new URL(oidc.issuer).origin) {
    throw new Error("OIDC token_endpoint is not on the issuer's origin");
  }

  const response = await fetchWithTimeout(fetchImpl, timeoutMs, doc.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: oidc.clientId,
      client_secret: oidc.clientSecret,
      scope: oidc.scope,
      audience: oidc.audience,
    }),
  });
  const text = await response.text();
  if (!response.ok) {
    const hint = text.trim().slice(0, 200);
    throw new Error(`client_credentials token mint failed: HTTP ${response.status}${hint ? `: ${hint}` : ""}`);
  }
  let payload: { access_token?: string; expires_in?: number };
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error("token response was not JSON");
  }
  if (!payload.access_token) throw new Error("token response missing access_token");
  const expiresIn = typeof payload.expires_in === "number" && payload.expires_in > 0 ? payload.expires_in : 1800;
  tokenCache = {
    accessToken: payload.access_token,
    expiresAtMs: decodeJwtExpMs(payload.access_token) ?? now + expiresIn * 1000,
    cacheKey: key,
  };
  return payload.access_token;
}
