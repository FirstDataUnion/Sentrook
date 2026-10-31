/**
 * `/sentrook <subcommand>` in chat and `openclaw sentrook <subcommand>` on the command line.
 *
 * Both routes run the same subcommand table, so they print the same text. Subcommands report what the
 * plugin can see locally and never print credential values.
 *
 * `history` and `why` show past traffic, `grants`, `grant`, `revoke` and `bind` list and change the
 * grants and channel bindings set by command, and `snooze` relaxes review prompts, so only the owner
 * may run them. `snooze` and a session `grant` cover the session the command was sent from; the
 * command line has none, so there a snooze needs `--all` and a session grant `--session`. OpenClaw tells a
 * command handler who the owner is only when the whole command requires a gateway scope, so they are
 * commands of their own (`/sentrook-history`, `/sentrook-grant`, ...), registered through
 * `ownerCommand`; `/sentrook` and its status stay open to everyone.
 */

import { CLIENT_ID_VAR, CLIENT_SECRET_VAR, envWithOpenclawDotenv, resolveSecretString } from "./auth.ts";
import { type PluginConfig, resolveConfig } from "./config.ts";
import * as grants from "./grants.ts";
import {
  formatHistory,
  formatWhy,
  HISTORY_DEFAULT,
  HISTORY_MAX,
  LOG_OFF,
  NO_SCANS,
  parseCount,
  parseRef,
  recentScans,
} from "./history.ts";
import { OWNER_SCOPES, refusal } from "./owner.ts";
import { PLUGIN_VERSION, sessionRef } from "./planir.ts";
import * as snooze from "./snooze.ts";

/** Who ran an owner-only command, and what a change goes through. */
export interface OwnerRun {
  /** Stored as `set_by` on what the command adds. */
  by: { basis: string[]; channel: string | null; sender_ref: string | null };
  /** Throws once the sender is no longer the owner; called before each write. */
  beforeWrite: () => void;
  /** Writes one record to the traffic log. */
  record: (record: Record<string, unknown>) => void;
}

export interface CommandContext {
  pluginConfig: Record<string, unknown>;
  /** Process env; the state-dir `.env` is merged in the same way as for scans. */
  env: NodeJS.ProcessEnv;
  /** Set for owner-only subcommands once the sender has passed the owner check. */
  owner?: OwnerRun;
  /** The session the command was sent from (as scans key it); unset when there is none. */
  session?: string;
}

/** How the owner types an owner-only subcommand, for usage and hints. */
const CMD: grants.Cmd = (sub) => `/sentrook-${sub}`;

export interface Subcommand {
  description: string;
  /** `rest` is the input after the subcommand name, trimmed. */
  run: (ctx: CommandContext, rest: string) => string | Promise<string>;
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

export interface OwnerSubcommand extends Subcommand {
  /** The chat command, registered with the owner scopes. */
  command: string;
  /** The arguments, as shown in help. */
  args: string;
  /** The CLI takes everything after the subcommand (flags included) instead of one optional word. */
  cliRest?: boolean;
}

export const OWNER_SUBCOMMANDS: Record<string, OwnerSubcommand> = {
  history: {
    command: "sentrook-history",
    args: "[n]",
    description: `Last n scans (default ${HISTORY_DEFAULT}, at most ${HISTORY_MAX}): time, session, tool, risk, action, review`,
    run: (ctx, rest) => historyText(ctx, rest),
  },
  why: {
    command: "sentrook-why",
    args: "[request_id|last]",
    description: "One scan's risk, tier scores, reason codes and entities",
    run: (ctx, rest) => whyText(ctx, rest),
  },
  grants: {
    command: "sentrook-grants",
    args: "",
    description: "Grants in force: from config (read-only) and set by command",
    run: (ctx) => {
      const cfg = configOf(ctx);
      return grants.formatGrants(cfg, grants.load(cfg.stateDir), new Date(), CMD, refOf(ctx));
    },
  },
  grant: {
    command: "sentrook-grant",
    args: "<kind> <pattern> [flags]",
    description:
      "Add a grant: kind destination|file|provider; flags --persistent (default: this session only, " +
      "not cron jobs, subagents or other chats), --session <ref> (from history), --allows read,write (file only), --expires 12h",
    cliRest: true,
    run: (ctx, rest) =>
      changed(ctx, "grant", (cfg, o) => grants.addGrant(cfg.stateDir, rest, refOf(ctx), o.by, new Date(), CMD, o.beforeWrite)),
  },
  revoke: {
    command: "sentrook-revoke",
    args: "<id>",
    description: "Remove a grant set by command",
    cliRest: true,
    run: (ctx, rest) =>
      changed(ctx, "revoke", (cfg, o) => grants.revoke(cfg.stateDir, cfg, rest, new Date(), CMD, o.beforeWrite)),
  },
  bind: {
    command: "sentrook-bind",
    args: "add|remove|list [channel]",
    description: "List, add or remove a channel binding (an expected delivery destination)",
    cliRest: true,
    run: (ctx, rest) =>
      changed(ctx, "bind", (cfg, o) => grants.bind(cfg.stateDir, cfg, rest, o.by, new Date(), CMD, o.beforeWrite)),
  },
  snooze: {
    command: "sentrook-snooze",
    args: "[duration|off|status] [--all]",
    description:
      "Allow review prompts in this session (--all: every session) for a duration, default 1h, at most 24h; " +
      "never blocks, enforced reviews or unattended runs; off; status",
    cliRest: true,
    run: (ctx, rest) =>
      changed(
        ctx,
        "snooze",
        (cfg, o) =>
          snooze.run(
            cfg.stateDir,
            rest,
            refOf(ctx),
            o.by,
            new Date(),
            CMD,
            o.beforeWrite,
          ),
        "snooze",
      ),
  },
};

/** The `session_ref` of the session the command was sent from; null when there is none. */
function refOf(ctx: CommandContext): string | null {
  return ctx.session ? sessionRef(ctx.session) : null;
}

function configOf(ctx: CommandContext): PluginConfig {
  return resolveConfig(ctx.pluginConfig, envWithOpenclawDotenv(ctx.env));
}

/** Runs a change for the owner and writes it (if any) to the traffic log as a `kind` record. */
function changed(
  ctx: CommandContext,
  verb: string,
  fn: (cfg: PluginConfig, owner: OwnerRun) => { reply: string; change: object | null },
  kind = "grants",
): string {
  if (!ctx.owner) return refusal(verb);
  const { reply, change } = fn(configOf(ctx), ctx.owner);
  if (change) ctx.owner.record({ kind, ...change, by: ctx.owner.by });
  return reply;
}

export function helpText(): string {
  const names = Object.keys(SUBCOMMANDS);
  const width = Math.max(...names.map((n) => n.length));
  const owner = Object.values(OWNER_SUBCOMMANDS).map((o) => [`/${o.command} ${o.args}`.trimEnd(), o.description] as const);
  const ownerWidth = Math.max(...owner.map(([usage]) => usage.length));
  return [
    "Sentrook commands:",
    ...names.map((n) => `  /sentrook ${n.padEnd(width)}  ${SUBCOMMANDS[n]!.description}`),
    `Owner only (gateway scope ${OWNER_SCOPES.join(", ")}):`,
    ...owner.map(([usage, description]) => `  ${usage.padEnd(ownerWidth)}  ${description}`),
  ].join("\n");
}

/** Runs the subcommand named by the first word of `args`; anything else gets the help text. */
export async function runSentrookCommand(args: string | undefined, ctx: CommandContext): Promise<string> {
  const [first = "", ...rest] = (args ?? "").trim().split(/\s+/);
  const name = first.toLowerCase();
  if (Object.hasOwn(OWNER_SUBCOMMANDS, name)) {
    const o = OWNER_SUBCOMMANDS[name]!;
    return `/sentrook ${name} is for the owner only: use ${`/${o.command} ${o.args}`.trimEnd()}.`;
  }
  const sub = Object.hasOwn(SUBCOMMANDS, name) ? SUBCOMMANDS[name]! : SUBCOMMANDS.help!;
  return await sub.run(ctx, rest.join(" "));
}

function historyText(ctx: CommandContext, rest: string): string {
  const cfg = resolveConfig(ctx.pluginConfig, envWithOpenclawDotenv(ctx.env));
  if (!cfg.trafficLog.enabled) return LOG_OFF;
  const n = parseCount(rest);
  if (n === null) return `usage: /sentrook-history [n], n from 1 to ${HISTORY_MAX}`;
  return formatHistory(recentScans(cfg.trafficLog.path, n), "/sentrook-why");
}

function whyText(ctx: CommandContext, rest: string): string {
  const cfg = resolveConfig(ctx.pluginConfig, envWithOpenclawDotenv(ctx.env));
  if (!cfg.trafficLog.enabled) return LOG_OFF;
  const match = parseRef(rest);
  if (match === null) return "usage: /sentrook-why [request_id|last], with an id (or its start) from /sentrook-history";
  const [found] = recentScans(cfg.trafficLog.path, 1, match);
  if (found) return formatWhy(...found);
  return rest === "" || rest.toLowerCase() === "last" ? NO_SCANS : `No scan ${rest} in the recent traffic log.`;
}

function statusText(ctx: CommandContext): string {
  const env = envWithOpenclawDotenv(ctx.env);
  const cfg = resolveConfig(ctx.pluginConfig, env);
  const [grantCount, bindingCount] = grants.counts(cfg, grants.load(cfg.stateDir));
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
    `grants: ${grantCount}`,
    `channel bindings: ${bindingCount}`,
    `snooze: ${snooze.statusLine(snooze.load(cfg.stateDir), new Date())}`,
  ].join("\n");
}
