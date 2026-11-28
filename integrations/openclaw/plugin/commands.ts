/**
 * `/sentrook <subcommand>` in chat and `openclaw sentrook <subcommand>` on the command line.
 *
 * Both routes run the same subcommand table, so they print the same text. Subcommands report what the
 * plugin can see locally and never print credential values.
 *
 * `history` and `why` show past traffic, `report` packs one scan for sending to Sentrook, `grants`, `grant`, `revoke` and `bind` list and change the
 * grants and channel bindings set by command, `snooze` relaxes review prompts, `allow` and `deny` (and `approve`,
 * the same as `allow`) answer a call held on an unattended run, `dismiss` takes held calls off the list unanswered, `passes` lists and revokes what those answers set
 * (passes.ts), `notify` says where the notice of a held call goes (see `hold.ts`), `trust-chat` and `trust-user` list
 * and change the chats and people whose messages count as trusted, never as the owner's (trust.ts), and `setup` shows what would stop
 * Sentrook asking about routine work and sets it with the screen's code (see `setup.ts`), so only the owner may run
 * them. `snooze` and a session `grant` cover the session the command was sent from; the
 * command line has none, so there a snooze needs `--all` and a session grant `--session`. OpenClaw tells a
 * command handler who the owner is only when the whole command requires a gateway scope, so they are
 * commands of their own (`/sentrook-history`, `/sentrook-grant`, ...), registered through
 * `ownerCommand`, which also refuses them in a group or channel room, where everyone would see the reply;
 * `/sentrook` and its status stay open to everyone.
 */

import { CLIENT_ID_VAR, CLIENT_SECRET_VAR, envWithOpenclawDotenv, resolveSecretString } from "./auth.ts";
import { configProblemsSummary, HIDE_SETTING, openclawDir, type PluginConfig, resolveConfig } from "./config.ts";
import { noticeStatus } from "./backgroundSave.ts";
import * as alwaysAllow from "./alwaysAllow.ts";
import * as grants from "./grants.ts";
import * as hold from "./hold.ts";
import * as passes from "./passes.ts";
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
import { OWNER_ROUTES, refusal } from "./owner.ts";
import * as report from "./report.ts";
import * as runNow from "./runNow.ts";
import { PLUGIN_VERSION, sessionRef } from "./planir.ts";
import * as selfEdit from "./selfEdit.ts";
import * as setup from "./setup.ts";
import * as snooze from "./snooze.ts";
import { FOREIGN_TEXT, OWN_TOOL_LABELS } from "./setupReport.ts";
import { Store } from "./store.ts";
import * as trust from "./trust.ts";

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
  /** The chat the command came from (channel, sender, account, thread); unset on the command line. */
  chat?: hold.NotifyContext;
  /** How `allow` starts a held call's job again (runNow.ts); a test replaces it. */
  runNow?: hold.RunNow;
  /** OpenClaw's config as it is now (its MCP servers), for `setup`. */
  hostConfig?: unknown;
  /** OpenClaw's state directory as the gateway started with it (its job store), for `setup`. */
  openclawDir?: string;
  /** OpenClaw's version where the plugin runtime gives it, for a trusted server (`trust.serverSupport`). */
  hostVersion?: unknown;
}

/** How the owner types an owner-only subcommand, for usage and hints. */
export const CMD: grants.Cmd = (sub) => `/sentrook-${sub}`;

export interface Subcommand {
  description: string;
  /** `rest` is the input after the subcommand name, trimmed. */
  run: (ctx: CommandContext, rest: string) => string | Promise<string>;
}

export const SUBCOMMANDS: Record<string, Subcommand> = {
  status: {
    description: "Plugin version, policy, scan host, whether credentials are set, held calls and where their notices go",
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
    description:
      "One scan's risk, tier scores, reason codes and entities; for a held call's id, also the hold, the answers it offers and the grant Sentrook suggests",
    run: (ctx, rest) => whyText(ctx, rest),
  },
  report: {
    command: "sentrook-report",
    args: "[request_id|last] [--full|--github|--save]",
    description:
      "A report of a scan that looks wrong, to send to Sentrook: --full adds the exact request (send it privately), " +
      "--github links a public issue with the summary filled in, --save writes the report and full record to a file to email",
    cliRest: true,
    run: (ctx, rest) => reportText(ctx, rest),
  },
  grants: {
    command: "sentrook-grants",
    args: "",
    description: "Grants in force: from config (read-only) and set by command",
    run: (ctx) => {
      const cfg = configOf(ctx);
      const now = new Date();
      const listing = grants.formatGrants(cfg, grants.load(cfg.stateDir), now, CMD, refOf(ctx), cfg.stateDir);
      const standing = alwaysAllow.formatLines(cfg.stateDir, now, CMD);
      return standing.length ? [listing, "", ...standing].join("\n") : listing;
    },
  },
  grant: {
    command: "sentrook-grant",
    args: "<kind> <pattern> [flags]",
    description:
      "Add a grant: kind destination|file|provider|repo; flags --persistent (default: this session only, " +
      "not cron jobs, subagents or other chats), --session <ref> (from history), --allows read,write (file only), --expires 12h",
    cliRest: true,
    run: (ctx, rest) =>
      changed(ctx, "grant", (cfg, o) => grants.addGrant(cfg.stateDir, rest, refOf(ctx), o.by, new Date(), CMD, o.beforeWrite)),
  },
  revoke: {
    command: "sentrook-revoke",
    args: "<id>",
    description: "Remove a grant set by command, or an Always answer kept for an MCP tool",
    cliRest: true,
    run: (ctx, rest) =>
      changed(ctx, "revoke", (cfg, o) => {
        const now = new Date();
        // an Always answer kept for an MCP tool on its server (alwaysAllow.ts), listed with the grants
        const done = rest.trim().startsWith("aa-") ? alwaysAllow.revoke(cfg.stateDir, rest.trim(), now, o.beforeWrite) : null;
        return done ?? grants.revoke(cfg.stateDir, cfg, rest, now, CMD, o.beforeWrite);
      }),
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
      "in beta, blocks in a chat you attend ask instead, with a warning, except changes to Sentrook itself; " +
      "never enforced reviews or unattended runs; off; status",
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
  allow: {
    command: "sentrook-allow",
    args: "<id> [now|later|always|all]",
    description:
      "Answer a call held on an unattended run, by the id in Sentrook's notice, within 7 days: run the cron job again " +
      "now, letting the call through once in that run (now: even when the held run had already sent or written " +
      "something; later: on the job's next scheduled run instead), or with always for 30 days on that job, where the " +
      "notice offers it; Sentrook never runs the held call itself",
    cliRest: true,
    run: (ctx, rest) => answerText(ctx, "allow", rest),
  },
  deny: {
    command: "sentrook-deny",
    args: "<id>",
    description:
      "Refuse a call held on a cron job, by the id in Sentrook's notice: that job is refused the same call for 30 " +
      "days, with no more notices",
    cliRest: true,
    run: (ctx, rest) => answerText(ctx, "deny", rest),
  },
  dismiss: {
    command: "sentrook-dismiss",
    args: "<id>|all",
    description:
      "Take a held call (or all of them) off the waiting list without answering it, as if it had expired now: the " +
      "call never runs and nothing is set, so a call like it is held again",
    cliRest: true,
    run: (ctx, rest) => {
      if (!ctx.owner) return refusal("dismiss");
      const o = ctx.owner;
      return hold.dismiss(configOf(ctx).stateDir, rest, o.by, new Date(), CMD, o.record, o.beforeWrite);
    },
  },
  approve: {
    command: "sentrook-approve",
    args: "<id>",
    description: "The same as /sentrook-allow (kept for one release)",
    cliRest: true,
    run: (ctx, rest) => answerText(ctx, "approve", rest),
  },
  passes: {
    command: "sentrook-passes",
    args: "[revoke <id>]",
    description: "Passes and denials your answers to held calls set, with their use counts; revoke one by its id",
    cliRest: true,
    run: (ctx, rest) => {
      if (!ctx.owner) return refusal("passes");
      const cfg = configOf(ctx);
      const [op = "", ...arg] = rest.trim().split(/\s+/);
      if (!op || op.toLowerCase() === "list") return passes.formatPasses(cfg.stateDir, new Date(), CMD);
      if (op.toLowerCase() !== "revoke") return `usage: ${CMD("passes")} [revoke <id>]`;
      return changed(ctx, "passes", (c, o) => passes.revoke(c.stateDir, arg.join(" "), new Date(), o.beforeWrite), "passes");
    },
  },
  notify: {
    command: "sentrook-notify",
    args: "here|off|status",
    description:
      "Where the notice of a held call goes: here (run it as a direct message to the agent; notices come to you " +
      "there), off, or status",
    cliRest: true,
    run: (ctx, rest) =>
      changed(
        ctx,
        "notify",
        (cfg, o) => hold.runNotify(cfg.stateDir, rest, ctx.chat ?? {}, o.by, new Date(), o.beforeWrite),
        "notify",
      ),
  },
  "trust-chat": {
    command: "sentrook-trust-chat",
    args: "add|remove|list [<platform>:<chat id>] [--owner-only] [--confirm]",
    description:
      "List, add or remove a group chat whose members you all know: their messages count as from someone you trust, " +
      "not a stranger (never as yours); its reviews are answered as OpenClaw allows there unless added with " +
      "--owner-only, which holds them for you; adding needs --confirm",
    cliRest: true,
    run: (ctx, rest) => trustText(ctx, "chat", rest),
  },
  "trust-user": {
    command: "sentrook-trust-user",
    args: "add|remove|list [<platform>:<user id>] [--confirm]",
    description:
      "List, add or remove a person you know: their messages count as from someone you trust, not a stranger " +
      "(never as yours); adding needs --confirm",
    cliRest: true,
    run: (ctx, rest) => trustText(ctx, "user", rest),
  },
  setup: {
    command: "sentrook-setup",
    args: "[apply <code> [1,3] | discard <id>]",
    description:
      "What would stop Sentrook asking about routine work: channels your cron jobs deliver to, your MCP servers, " +
      "grants Sentrook suggested on reviews you approved, and the agent's proposals, each described by Sentrook; " +
      "apply <code> [1,3] [--expires 90d | --until-revoked] sets them with the code the list shows; discard <id> " +
      "drops an agent proposal",
    cliRest: true,
    run: (ctx, rest) => {
      if (!ctx.owner) return refusal("setup");
      const o = ctx.owner;
      return setup.run(configOf(ctx), rest, o.by, new Date(), CMD, o.record, o.beforeWrite, {
        openclawDir: ctx.openclawDir ?? openclawDir(ctx.env),
        hostConfig: ctx.hostConfig,
      });
    },
  },
};

/** `trust-chat` or `trust-user` (trust.ts), recorded as a `settings` change naming the platform only. */
function trustText(ctx: CommandContext, kind: "chat" | "user", rest: string): string {
  return changed(
    ctx,
    `trust-${kind}`,
    (cfg, o) => trust.run(cfg, kind, rest, o.by, { ...(ctx.chat ?? {}), hostVersion: ctx.hostVersion }, ctx.hostConfig, new Date(), CMD, o.beforeWrite),
    "settings",
  );
}

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
    `Owner only, ${OWNER_ROUTES}:`,
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

/** An answer to a held call (hold.answer), then the held calls' history set to the owner's answer. */
async function answerText(ctx: CommandContext, verb: "allow" | "deny" | "approve", rest: string): Promise<string> {
  if (!ctx.owner) return refusal(verb);
  const o = ctx.owner;
  const cfg = configOf(ctx);
  // allow on a cron job's hold starts the job again now, unless a guard applies (runNow.ts). OpenClaw's state
  // directory as the gateway started with it, not from `.env`, which the agent can write.
  const starter =
    ctx.runNow ?? new runNow.Adapter(ctx.openclawDir ?? openclawDir(ctx.env), cfg.mode === "observe", runNow.runChild, runNow.openclawCommand(), cfg.stateDir);
  const done = await hold.answer(cfg.stateDir, verb, rest, o.by, new Date(), CMD, o.record, o.beforeWrite, starter);
  if (done.decision) await hold.settle(cfg.stateDir, done.held, done.decision);
  return done.reply;
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
  if (hold.isId(rest)) return hold.whyText(cfg.stateDir, cfg.trafficLog.path, rest, CMD, !cfg.hideToolCalls);
  const match = parseRef(rest);
  if (match === null) {
    return "usage: /sentrook-why [request_id|last], with an id (or its start) from /sentrook-history, or the id in a held-call notice";
  }
  const [found] = recentScans(cfg.trafficLog.path, 1, match);
  if (found) return formatWhy(...found, !cfg.hideToolCalls, HIDE_SETTING);
  return rest === "" || rest.toLowerCase() === "last" ? NO_SCANS : `No scan ${rest} in the recent traffic log.`;
}

export const REPORT_USAGE =
  "usage: /sentrook-report [request_id|last] [--full|--github|--save], with an id (or its start) from /sentrook-history";

function reportText(ctx: CommandContext, rest: string): string {
  const cfg = resolveConfig(ctx.pluginConfig, envWithOpenclawDotenv(ctx.env));
  if (!cfg.trafficLog.enabled) return LOG_OFF;
  const args = report.parseArgs(rest);
  const match = args === null ? null : parseRef(args[0]);
  if (args === null || match === null) return REPORT_USAGE;
  const found = report.find(cfg.trafficLog.path, match);
  if (found === null) {
    return args[0] === "" || args[0].toLowerCase() === "last" ? NO_SCANS : `No scan ${args[0]} in the recent traffic log.`;
  }
  return report.reply(found, args[1], CMD, cfg.stateDir);
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
  const target = new Store(cfg.stateDir).loadNotify();
  const foreign = new Store(cfg.stateDir).loadForeignTools();
  const lines = [
    `Sentrook plugin: ${PLUGIN_VERSION}`,
    `mode: ${cfg.mode}`,
    `review at: ${cfg.reviewAt}, block at: ${cfg.blockAt}`,
    `on scan error: ${cfg.onScanError}`,
    `scan host: ${scanHost}`,
    `credentials: ${missing.length ? `no (${missing.join(", ")} not set; run openclaw sentrook login on the gateway machine)` : "yes"}`,
    `traffic log: ${cfg.trafficLog.enabled ? "enabled" : "disabled"}, ${cfg.trafficLog.path}`,
    `grants: ${grantCount}`,
    `channel bindings: ${bindingCount}`,
    `snooze: ${snooze.statusLine(snooze.load(cfg.stateDir), new Date())}`,
    `held calls: ${hold.statusLine(cfg.stateDir, target, new Date())}`,
    `passes: ${passes.counts(cfg.stateDir, new Date())}`,
    `background-save notices: ${noticeStatus(target)}`,
    `skill review: ${selfEdit.statusLine(
      selfEdit.settingText(cfg.skillReview, cfg.skillReviewUnknown),
      cfg.trafficLog.enabled ? cfg.trafficLog.path : null,
    )}`,
    `settings: ${
      cfg.configProblems.length
        ? `${cfg.configProblems.length} not read as written: ${configProblemsSummary(cfg.configProblems)} (see openclaw sentrook verify)`
        : "all read as written"
    }`,
    ...Object.entries(foreign).map(([tool, since]) => `${OWN_TOOL_LABELS[tool] ?? tool}: ${FOREIGN_TEXT} (since ${since})`),
  ];
  return lines.join("\n");
}
