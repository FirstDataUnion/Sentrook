/**
 * `openclaw sentrook verify`: endpoints valid, credentials present, every plugin-config setting read as written,
 * scanner healthy, token mint works; notes on settings that leave something unscanned, and on skills that replace
 * the ones the plugin ships.
 */

import { shadowCheck } from "./agentSkills.ts";
import { clearScanTokenCache, ConsentWithdrawnError, envWithOpenclawDotenv, getScanAccessToken, resolveOidcCredentials } from "./auth.ts";
import { configProblemsSummary, type PluginConfig, resolveConfig } from "./config.ts";
import { noticeStatus } from "./backgroundSave.ts";
import * as grants from "./grants.ts";
import { bindingProblemsSummary, clean, unsentSummary } from "./grants.ts";
import { NOTIFY_UNSET, targetText, unsetWarning } from "./hold.ts";
import * as passes from "./passes.ts";
import { memoryWriterChecks } from "./memoryWriters.ts";
import { FOREIGN_TEXT, OWN_TOOL_LABELS } from "./setupReport.ts";
import * as setup from "./setup.ts";
import { setupToolsCheck } from "./setupTools.ts";
import { Store } from "./store.ts";
import * as trust from "./trust.ts";

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
}

/**
 * The channel bindings in force (config and command) that no message send in the traffic log would carry
 * (`setup.unreachedBindings`), e.g. `discord:123…`; "" with the log off, no send in it, or every binding carried.
 */
export function unreachedSummary(cfg: PluginConfig, now: Date): string {
  if (!cfg.trafficLog.enabled) return "";
  const ev = setup.readEvidence(cfg.trafficLog.path, cfg.reviewAt, now);
  const force = setup.inForce(cfg, grants.load(cfg.stateDir), now);
  return setup.unreachedBindings(force, ev).map((p) => clean(p, 60)).join(", ");
}

export async function runVerify(
  pluginConfig: Record<string, unknown>,
  opts: {
    env?: NodeJS.ProcessEnv;
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    /** OpenClaw's own config; undefined when it cannot be read. */
    hostConfig?: unknown;
    /** The home folder, for `~` in OpenClaw's config and the personal skills folder; the user's own when not given. */
    home?: string;
    /** OpenClaw's version where the plugin runtime gives it; unknown on the command line. */
    hostVersion?: unknown;
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
        detail:
          err instanceof ConsentWithdrawnError
            ? "consent for Sentrook was withdrawn on the FIDU portal; run openclaw sentrook login to reconnect"
            : detail.includes("invalid_client")
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
  const unreached = unreachedSummary(cfg, new Date());
  checks.push({
    name: "channel bindings",
    ok: true,
    detail:
      `${cfg.channelBindings.length} in config${problems ? `; cannot apply: ${problems}` : ""}` +
      (unreached ? `; no message send in the traffic log matches: ${unreached}` : ""),
  });
  checks.push(trustCheck(cfg, opts.hostVersion));
  // Failed when calls are held and no notify target is set: the owner is told only where a fallback reaches them.
  const target = new Store(cfg.stateDir).loadNotify();
  const unset = unsetWarning(cfg.stateDir, target, new Date());
  checks.push({
    name: "held-call notices",
    ok: !unset,
    detail: (target ? `by ${targetText(target)}` : `not sent: ${NOTIFY_UNSET}`) + (unset ? `. ${unset}` : ""),
  });
  // Failed when unreadable: a pass or denial the owner set could not be applied, so the job is held again.
  const passState = passes.counts(cfg.stateDir, new Date());
  checks.push({ name: "held-call passes", ok: passState !== "passes file unreadable", detail: passState });
  // Reported, not failed: OpenClaw's background saves are never asked about; without a target the owner is not told
  // what was let through, saved as a draft, held or blocked.
  checks.push({ name: "background-save notices", ok: true, detail: noticeStatus(target) });
  // Reported, not failed: OpenClaw's own memory writers that no plugin sees, with the setting that turns each off.
  checks.push(...memoryWriterChecks(opts.hostConfig));
  // Reported, not failed: a workspace, project or managed skill with the name of one the plugin ships replaces it.
  checks.push(shadowCheck(opts.hostConfig, env, { home: opts.home }));
  // Reported, not failed: an allow or deny list that hides the agent's setup tools; /sentrook-setup still works.
  const setupTools = setupToolsCheck(opts.hostConfig);
  if (setupTools) checks.push(setupTools);
  // Reported, not failed: another plugin's tool ran under the name of one of the plugin's own, so every call of it is
  // scanned.
  for (const [tool, since] of Object.entries(new Store(cfg.stateDir).loadForeignTools())) {
    checks.push({ name: OWN_TOOL_LABELS[tool] ?? tool, ok: true, detail: `warning: ${FOREIGN_TEXT} (since ${since})` });
  }
  return checks;
}

/**
 * The trusted chats in force; failed for a trusted server this OpenClaw cannot match (it does not name a message's
 * server), and noted when no Discord message has named its server to the plugin yet.
 */
export function trustCheck(cfg: PluginConfig, hostVersion: unknown): VerifyCheck {
  let line: string;
  let servers = 0;
  try {
    line = trust.trustLine(cfg).split(". ")[0]!;
    servers = [...trust.of(cfg).chats.keys()].filter(trust.isServer).length;
  } catch (err) {
    return { name: "trusted chats", ok: false, detail: `cannot be read: ${String(err).slice(0, 120)}` };
  }
  if (!servers) return { name: "trusted chats", ok: true, detail: line };
  const why = trust.serverSupport(hostVersion);
  if (why) {
    return { name: "trusted chats", ok: false, detail: `${line}; the trusted servers never match: ${why}. Trust each chat by its id instead` };
  }
  const seen = new Store(cfg.stateDir).serverSeenAt();
  return {
    name: "trusted chats",
    ok: true,
    detail: seen
      ? `${line}; OpenClaw last named a Discord message's server at ${seen}`
      : `${line}; no Discord message has named its server to the plugin yet (a trusted server matches once one does)`,
  };
}

export function formatVerifyReport(checks: VerifyCheck[]): string {
  return checks.map((c) => `${c.ok ? "ok  " : "FAIL"} ${c.name}: ${c.detail}`).join("\n");
}
