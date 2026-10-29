/**
 * `/sentrook <subcommand>` in chat and `openclaw sentrook <subcommand>` on the command line.
 *
 * Both routes run the same subcommand table, so they print the same text. Subcommands report what the
 * plugin can see locally and never print credential values.
 */

import { CLIENT_ID_VAR, CLIENT_SECRET_VAR, envWithOpenclawDotenv, resolveSecretString } from "./auth.ts";
import { resolveConfig } from "./config.ts";
import { PLUGIN_VERSION } from "./planir.ts";

export interface CommandContext {
  pluginConfig: Record<string, unknown>;
  /** Process env; the state-dir `.env` is merged in the same way as for scans. */
  env: NodeJS.ProcessEnv;
}

export interface Subcommand {
  description: string;
  run: (ctx: CommandContext) => string | Promise<string>;
}

export const SUBCOMMANDS: Record<string, Subcommand> = {
  status: {
    description: "Plugin version, policy, scan host and whether credentials are set",
    run: (ctx) => statusText(ctx),
  },
  help: {
    description: "List these subcommands",
    run: () => helpText(),
  },
};

export function helpText(): string {
  const names = Object.keys(SUBCOMMANDS);
  const width = Math.max(...names.map((n) => n.length));
  return ["Sentrook commands:", ...names.map((n) => `  /sentrook ${n.padEnd(width)}  ${SUBCOMMANDS[n]!.description}`)].join(
    "\n",
  );
}

/** Runs the subcommand named by the first word of `args`; anything else gets the help text. */
export async function runSentrookCommand(args: string | undefined, ctx: CommandContext): Promise<string> {
  const name = (args ?? "").trim().split(/\s+/)[0]!.toLowerCase();
  const sub = Object.hasOwn(SUBCOMMANDS, name) ? SUBCOMMANDS[name]! : SUBCOMMANDS.help!;
  return await sub.run(ctx);
}

function statusText(ctx: CommandContext): string {
  const env = envWithOpenclawDotenv(ctx.env);
  const cfg = resolveConfig(ctx.pluginConfig, env);
  const { scan, dev } = cfg.endpoints;
  const scanHost = scan.ok ? `${new URL(scan.url).host}${dev ? " (dev endpoints)" : ""}` : `invalid (${scan.reason})`;
  const missing = [
    resolveSecretString(ctx.pluginConfig.clientId, env, CLIENT_ID_VAR) ? null : CLIENT_ID_VAR,
    resolveSecretString(ctx.pluginConfig.clientSecret, env, CLIENT_SECRET_VAR) ? null : CLIENT_SECRET_VAR,
  ].filter(Boolean);
  return [
    `Sentrook plugin: ${PLUGIN_VERSION}`,
    `mode: ${cfg.mode}`,
    `review at: ${cfg.reviewAt}, block at: ${cfg.blockAt}`,
    `on scan error: ${cfg.onScanError}`,
    `scan host: ${scanHost}`,
    `credentials: ${missing.length ? `no (${missing.join(", ")} not set)` : "yes"}`,
    `traffic log: ${cfg.trafficLog.enabled ? "enabled" : "disabled"}, ${cfg.trafficLog.path}`,
    `config grants: ${cfg.grants.length}`,
  ].join("\n");
}
