/**
 * `openclaw sentrook verify`: endpoints valid, credentials present, scanner healthy, token mint works.
 */

import { clearScanTokenCache, envWithOpenclawDotenv, getScanAccessToken, resolveOidcCredentials } from "./auth.ts";
import { resolveConfig } from "./config.ts";

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export async function runVerify(
  pluginConfig: Record<string, unknown>,
  opts: { env?: NodeJS.ProcessEnv; fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<VerifyCheck[]> {
  const env = envWithOpenclawDotenv(opts.env ?? process.env);
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 8000;
  const cfg = resolveConfig(pluginConfig, env);
  const checks: VerifyCheck[] = [];
  const { scan, rookery, issuer, dev } = cfg.endpoints;

  for (const [name, ep] of [["scan URL", scan], ["Rookery URL", rookery], ["OIDC issuer", issuer]] as const) {
    checks.push({ name, ok: ep.ok, detail: ep.ok ? `${ep.url}${dev ? " (dev endpoints)" : ""}` : ep.reason });
  }
  const oidc = issuer.ok ? resolveOidcCredentials(pluginConfig, env, issuer.url) : null;
  checks.push({
    name: "credentials",
    ok: !!oidc,
    detail: oidc ? `client ${oidc.clientId}, audience ${oidc.audience}` : "SENTROOK_SCAN_CLIENT_ID / _SECRET not set",
  });

  if (scan.ok) {
    try {
      const res = await fetchImpl(`${scan.url}/healthz`, { redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      checks.push({
        name: "scanner health",
        ok: res.ok && body.ok !== false,
        detail: `HTTP ${res.status} version=${String(body.version ?? "?")} env=${String(body.environment ?? "?")}`,
      });
    } catch (err) {
      checks.push({ name: "scanner health", ok: false, detail: String(err).slice(0, 160) });
    }
  }
  if (oidc) {
    clearScanTokenCache();
    try {
      await getScanAccessToken(oidc, fetchImpl, timeoutMs);
      checks.push({ name: "token mint", ok: true, detail: `issued by ${oidc.issuer}` });
    } catch (err) {
      checks.push({ name: "token mint", ok: false, detail: String(err).slice(0, 200) });
    }
  }
  checks.push({
    name: "policy",
    ok: true,
    detail: `mode=${cfg.mode} review>=${cfg.reviewAt} block>=${cfg.blockAt} onScanError=${cfg.onScanError}`,
  });
  checks.push({
    name: "traffic log",
    ok: true,
    detail: cfg.trafficLog.enabled ? cfg.trafficLog.path : "off",
  });
  return checks;
}

export function formatVerifyReport(checks: VerifyCheck[]): string {
  return checks.map((c) => `${c.ok ? "ok  " : "FAIL"} ${c.name}: ${c.detail}`).join("\n");
}
