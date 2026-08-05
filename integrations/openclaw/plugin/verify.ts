/**
 * Lightweight verify for hosted Sentrook — no Python `sentrook` CLI required.
 * Used by `openclaw sentrook verify`.
 */

import { existsSync, readFileSync } from "node:fs";
import {
  API_KEY_VAR,
  CLIENT_ID_VAR,
  CLIENT_SECRET_VAR,
  DEFAULT_SCAN_URL,
  PLUGIN_ID,
  dotenvPath,
  openclawConfigPath,
  resolveStateDir,
} from "./configure.ts";
import { DEFAULT_SCAN_ISSUER, envWithOpenclawDotenv } from "./auth.ts";

export interface VerifyResult {
  ok: boolean;
  url: string;
  checks: Array<{ name: string; ok: boolean; detail: string }>;
}

function readDotenvValue(dotenvFile: string, key: string): string | undefined {
  if (!existsSync(dotenvFile)) return undefined;
  for (const line of readFileSync(dotenvFile, "utf8").split(/\r?\n/)) {
    if (line.startsWith(`${key}=`)) {
      const v = line.slice(key.length + 1).trim();
      return v || undefined;
    }
  }
  return undefined;
}

function normalizeIssuer(url: string): string {
  return url.trim().replace(/\/+$/, "").toLowerCase();
}

function readConfiguredUrl(stateDir: string): string | undefined {
  const cfgPath = openclawConfigPath(stateDir);
  if (!existsSync(cfgPath)) return undefined;
  try {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as {
      plugins?: { entries?: Record<string, { config?: { url?: string } }> };
    };
    const url = cfg.plugins?.entries?.[PLUGIN_ID]?.config?.url;
    return typeof url === "string" && url.trim() ? url.trim() : undefined;
  } catch {
    return undefined;
  }
}

function pluginEntryPresent(stateDir: string): boolean {
  const cfgPath = openclawConfigPath(stateDir);
  if (!existsSync(cfgPath)) return false;
  try {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as {
      plugins?: { entries?: Record<string, { enabled?: boolean }> };
    };
    const entry = cfg.plugins?.entries?.[PLUGIN_ID];
    return Boolean(entry && entry.enabled !== false);
  } catch {
    return false;
  }
}

export async function runVerify(opts: {
  url?: string;
  stateDir?: string;
  timeoutMs?: number;
}): Promise<VerifyResult> {
  const stateDir = opts.stateDir ?? resolveStateDir();
  const url = (opts.url?.trim() || readConfiguredUrl(stateDir) || DEFAULT_SCAN_URL).replace(
    /\/$/,
    "",
  );
  const timeoutMs = opts.timeoutMs ?? 8000;
  const checks: VerifyResult["checks"] = [];

  const entryOk = pluginEntryPresent(stateDir);
  checks.push({
    name: "plugin config",
    ok: entryOk,
    detail: entryOk
      ? `plugins.entries.${PLUGIN_ID} present in ${openclawConfigPath(stateDir)}`
      : `missing plugins.entries.${PLUGIN_ID} — run: openclaw sentrook configure`,
  });

  const dotenv = dotenvPath(stateDir);
  const merged = envWithOpenclawDotenv(process.env, { stateDir });
  const clientId =
    merged[CLIENT_ID_VAR]?.trim() || readDotenvValue(dotenv, CLIENT_ID_VAR);
  const clientSecret =
    merged[CLIENT_SECRET_VAR]?.trim() || readDotenvValue(dotenv, CLIENT_SECRET_VAR);
  const apiKey = merged[API_KEY_VAR]?.trim() || readDotenvValue(dotenv, API_KEY_VAR);
  const https = url.startsWith("https://");
  const credsOk = Boolean((clientId && clientSecret) || apiKey);
  if (https) {
    checks.push({
      name: "scan credentials",
      ok: credsOk,
      detail: credsOk
        ? clientId && clientSecret
          ? `${CLIENT_ID_VAR}+${CLIENT_SECRET_VAR} available via ~/.openclaw/.env and/or process env`
          : `${API_KEY_VAR} available (shared API key)`
        : `missing OIDC vars (need ${CLIENT_ID_VAR}+${CLIENT_SECRET_VAR} in ${dotenv})`,
    });
  } else {
    checks.push({
      name: "scan credentials",
      ok: true,
      detail: "local HTTP URL — scan auth not required",
    });
  }

  // Informational only: docker exec printenv often empty even when file-backed auth works.
  if (https && credsOk) {
    const inProcess = Boolean(
      (process.env[CLIENT_ID_VAR]?.trim() && process.env[CLIENT_SECRET_VAR]?.trim()) ||
        process.env[API_KEY_VAR]?.trim(),
    );
    checks.push({
      name: "credentials load path",
      ok: true,
      detail: inProcess
        ? "also visible in this openclaw CLI process.env (OpenClaw dotenv)"
        : "loaded from ~/.openclaw/.env file (plugin reads file directly; docker exec printenv may be empty)",
    });
  }

  const pluginIssuer = normalizeIssuer(
    merged.SENTROOK_OIDC_ISSUER?.trim() ||
      readDotenvValue(dotenv, "SENTROOK_OIDC_ISSUER") ||
      DEFAULT_SCAN_ISSUER,
  );

  let healthOk = false;
  let healthDetail = "";
  let healthBody: Record<string, unknown> = {};
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(`${url}/health`, { signal: controller.signal });
      const text = await resp.text();
      try {
        healthBody = JSON.parse(text) as Record<string, unknown>;
      } catch {
        healthBody = {};
      }
      healthOk = resp.ok && healthBody.status === "ok";
      const rules = healthBody.rules_loaded;
      const scanner = healthBody.scanner_version;
      healthDetail = healthOk
        ? `GET ${url}/health → ok` +
          (typeof rules === "number" ? `, rules_loaded=${rules}` : "") +
          (scanner ? `, scanner=${String(scanner)}` : "")
        : `GET ${url}/health → HTTP ${resp.status} status=${String(healthBody.status ?? "?")}`;
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    healthOk = false;
    healthDetail = `GET ${url}/health failed: ${err instanceof Error ? err.message : String(err)}`;
  }
  checks.push({ name: "scan service health", ok: healthOk, detail: healthDetail });

  if (https && healthOk) {
    const scanIssuerRaw =
      typeof healthBody.oidc_issuer === "string" ? healthBody.oidc_issuer.trim() : "";
    if (scanIssuerRaw) {
      const scanIssuer = normalizeIssuer(scanIssuerRaw);
      const match = pluginIssuer === scanIssuer;
      checks.push({
        name: "OIDC issuer alignment",
        ok: match,
        detail: match
          ? `plugin and scan agree on ${pluginIssuer}`
          : `mismatch: plugin=${pluginIssuer} scan=${scanIssuer} — set SENTROOK_OIDC_ISSUER on both OpenClaw ~/.openclaw/.env and Sentrook deploy .env (dig vs prod)`,
      });
    } else {
      checks.push({
        name: "OIDC issuer alignment",
        ok: true,
        detail:
          "scan /health has no oidc_issuer yet — redeploy Sentrook to enable dig/prod mismatch detection",
      });
    }
  }

  return {
    ok: checks.every((c) => c.ok),
    url,
    checks,
  };
}

export function formatVerifyReport(result: VerifyResult): string {
  const lines = [
    `=== Sentrook verify (${result.url}) ===`,
    ...result.checks.map((c) => `${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`),
    result.ok
      ? "OK — restart gateway if you have not since configure, then exercise a tool call."
      : "FAILED — fix the items above, then re-run: openclaw sentrook verify",
  ];
  return lines.join("\n");
}
