/**
 * `openclaw sentrook verify`: endpoints valid, credentials present, every plugin-config setting read as written,
 * scanner healthy, token mint works; notes on settings that leave something unscanned.
 */

import { clearScanTokenCache, envWithOpenclawDotenv, getScanAccessToken, resolveOidcCredentials } from "./auth.ts";
import { configProblemsSummary, resolveConfig } from "./config.ts";
import { noticeStatus } from "./backgroundSave.ts";
import { bindingProblemsSummary, unsentSummary } from "./grants.ts";
import { NOTIFY_UNSET, targetText } from "./hold.ts";
import * as passes from "./passes.ts";
import { memoryWriterChecks } from "./memoryWriters.ts";
import { Store } from "./store.ts";

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export async function runVerify(
  pluginConfig: Record<string, unknown>,
  opts: {
    env?: NodeJS.ProcessEnv;
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    /** OpenClaw's own config; undefined when it cannot be read. */
    hostConfig?: unknown;
  } = {},
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
    detail: oidc
      ? `client ${oidc.clientId}, audience ${oidc.audience}`
      : "not signed in: SENTROOK_SCAN_CLIENT_ID / _SECRET not set (run openclaw sentrook login)",
  });

  // Failed, not reported: a setting Sentrook cannot read is ignored or replaced, which may not be what the owner meant.
  checks.push({
    name: "settings",
    ok: cfg.configProblems.length === 0,
    detail: cfg.configProblems.length ? configProblemsSummary(cfg.configProblems) : "all read as written",
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
      const detail = String(err).slice(0, 200);
      checks.push({
        name: "token mint",
        ok: false,
        detail: detail.includes("invalid_client")
          ? "the identity service refused these credentials (revoked or wrong); run openclaw sentrook login"
          : detail,
      });
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
  // Reported, not failed: a config grant that is never sent only makes Sentrook stricter.
  const unsent = unsentSummary(cfg);
  checks.push({
    name: "config grants",
    ok: true,
    detail: `${cfg.grants.length} in config${unsent ? `; never sent: ${unsent}` : ""}`,
  });
  // Reported, not failed: a binding that never applies only makes Sentrook stricter.
  const problems = bindingProblemsSummary(cfg);
  checks.push({
    name: "channel bindings",
    ok: true,
    detail: `${cfg.channelBindings.length} in config${problems ? `; cannot apply: ${problems}` : ""}`,
  });
  // Reported, not failed: without a notify target a held call still waits; the owner is just not told.
  const target = new Store(cfg.stateDir).loadNotify();
  checks.push({ name: "held-call notices", ok: true, detail: target ? `by ${targetText(target)}` : `not sent: ${NOTIFY_UNSET}` });
  // Failed when unreadable: a pass or denial the owner set could not be applied, so the job is held again.
  const passState = passes.counts(cfg.stateDir, new Date());
  checks.push({ name: "held-call passes", ok: passState !== "passes file unreadable", detail: passState });
  // Reported, not failed: OpenClaw's background saves are never asked about; without a target the owner is not told
  // what was let through, saved as a draft, held or blocked.
  checks.push({ name: "background-save notices", ok: true, detail: noticeStatus(target) });
  // Reported, not failed: OpenClaw's own memory writers that no plugin sees, with the setting that turns each off.
  checks.push(...memoryWriterChecks(opts.hostConfig));
  return checks;
}

export function formatVerifyReport(checks: VerifyCheck[]): string {
  return checks.map((c) => `${c.ok ? "ok  " : "FAIL"} ${c.name}: ${c.detail}`).join("\n");
}
