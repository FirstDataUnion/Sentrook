/**
 * Sentrook for OpenClaw.
 *
 * Scans every tool call before it runs: builds a PlanIR 2.0 request from the hook and the context
 * gathered on other hooks, sends it to Sentrook's /scan over OIDC, and allows, asks the user, or
 * blocks. Every request and response is redacted on the host and appended to a local traffic log.
 */

import { createHash } from "node:crypto";
import { homedir } from "node:os";

import { agentRules, reportedTool, shadowingSkills, shippedSkillTexts, SKILL_READ_TOOL } from "./agentSkills.ts";
import {
  CLIENT_ID_VAR,
  CLIENT_SECRET_VAR,
  envWithOpenclawDotenv,
  resolveOidcCredentials,
  resolveSecretString,
} from "./auth.ts";
import { resolveApprovalTiming, type IntentKind } from "./approvalPolicy.ts";
import * as bg from "./backgroundSave.ts";
import { CMD, OWNER_SUBCOMMANDS, runSentrookCommand } from "./commands.ts";
import {
  configProblemsNotice,
  configProblemsSummary,
  type GrantConfig,
  openclawDir,
  type PluginConfig,
  resolveConfig,
} from "./config.ts";
import * as cronDelivery from "./cronDelivery.ts";
import * as dashboard from "./dashboard.ts";
import * as folders from "./folders.ts";
import * as conversation from "./conversation.ts";
import * as grants from "./grants.ts";
import * as history from "./history.ts";
import * as hold from "./hold.ts";
import * as alwaysAllow from "./alwaysAllow.ts";
import * as passes from "./passes.ts";
import * as runNow from "./runNow.ts";
import { reviewCard } from "./card.ts";
import { blockReason, decide, describe as describeCall, severity, tiersOf, unattendedView, type Verdict } from "./decision.ts";
import {
  buildPlanir,
  heartbeatEventsOf,
  hostLabels,
  PLUGIN_VERSION,
  priorAgentTextOf,
  sessionRef,
  TOOL_CALL_NAMES,
  toolKind,
  triggerKind,
  unwrapToolCall,
} from "./planir.ts";
import { capHeadTail, createRedactor } from "./redact.ts";
import { postScan, type ScanOk } from "./scanClient.ts";
import { invalidEndpointEffect, type ScanFailure, scanErrorToHookResult } from "./scanErrorPolicy.ts";
import * as scanFailure from "./scanFailureNotice.ts";
import * as consent from "./consent.ts";
import { ownerCommand, type OwnerContext, senderRef } from "./owner.ts";
import * as selfEdit from "./selfEdit.ts";
import * as setup from "./setup.ts";
import * as proposals from "./proposals.ts";
import * as setupReport from "./setupReport.ts";
import * as snooze from "./snooze.ts";
import { type HistoryEntry, type JobRunLink, type RunContext, type Session, Store } from "./store.ts";
import { TrafficLog } from "./traffic.ts";

type Json = Record<string, unknown>;
type Resolution = "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled";

interface PluginLogger {
  info: (m: string) => void;
  warn: (m: string) => void;
  error: (m: string) => void;
}

interface OpenClawPluginApi {
  pluginConfig?: Json;
  config?: any;
  logger: PluginLogger;
  registrationMode?: string;
  /** The folder OpenClaw installed the plugin in; the code may run from a copy elsewhere. */
  rootDir?: string;
  runtime?: {
    version?: unknown;
    config?: { current?: () => unknown };
    channel?: { outbound?: hold.Outbound };
    /** 2026.11.5: the agent's own directory, which holds its Workshop skills. */
    agent?: { resolveAgentDir?: (cfg: unknown, agentId: string) => unknown };
  };
  on: (hook: string, handler: (event: any, ctx: any) => unknown, opts?: { priority?: number }) => void;
  registerCli?: (registrar: (ctx: { program: any }) => void | Promise<void>, opts?: Json) => void;
  registerCommand?: (def: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requiredScopes?: string[];
    /** Lines OpenClaw puts in the agent's system prompt while the command is registered. */
    agentPromptGuidance?: string[];
    handler: (ctx: any) => Promise<{ text?: string }>;
  }) => void;
  registerAgentToolResultMiddleware?: (handler: (event: any, ctx: any) => unknown, opts?: Json) => void;
  /** A tool, or a factory OpenClaw runs whenever a run assembles its tools; null from the factory offers none. */
  registerTool?: (tool: ((ctx: any) => Json | null) | Json, opts?: { name?: string; optional?: boolean }) => void;
  registerHttpRoute?: (route: {
    path: string;
    auth: "gateway" | "plugin";
    match?: "exact" | "prefix";
    handler: (req: any, res: any) => boolean | Promise<boolean>;
  }) => void;
  /** Deprecated flat alias of `session.controls.registerControlUiDescriptor`, kept for older hosts. */
  registerControlUiDescriptor?: (descriptor: Json) => void;
  session?: { controls?: { registerControlUiDescriptor?: (descriptor: Json) => void } };
}

export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  requireApproval?: {
    title: string;
    description: string;
    severity?: "info" | "warning" | "critical";
    timeoutMs?: number;
    timeoutBehavior?: "allow" | "deny";
    allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
    onResolution?: (decision: Resolution) => void | Promise<void>;
  };
  /** Parameters OpenClaw merges over the call's own before it runs (a background skill save turned into a draft). */
  params?: Record<string, unknown>;
}

/** Tool search's discovery tools: no side effects, and names OpenClaw keeps for itself. */
const DISCOVERY_TOOLS = new Set(["tool_search", "tool_describe"]);
/** OpenClaw tools that read one file whole or in part: a read `folders.attest` may vouch for. */
const FOLDER_READ_TOOLS: ReadonlySet<string> = new Set(["read"]);

/**
 * Tool search: discovery tools have no side effects, and the dispatcher (`tool_call`, `dispatch_action` from OpenClaw
 * 2026.11.3) only dispatches; the call they lead to is scanned on its own (a dispatched call fires its own tool hooks,
 * with its own result). Only one of the dispatcher's names is reserved on a given OpenClaw, and none is with tool search
 * off, so a call by either name is skipped only when it names a tool the way the dispatcher takes it; anything else is
 * another tool of that name and is scanned.
 */
const isUnscanned = (event: any) =>
  DISCOVERY_TOOLS.has(event?.toolName) || (TOOL_CALL_NAMES.has(event?.toolName) && unwrapToolCall(event?.params) !== null);

/** History decisions after which the tool did not run. */
const NOT_RUN = new Set(["blocked", "denied_by_user", "review_timed_out", "blocked_on_error", "held", "draft_failed"]);

const LOG = "[sentrook]";

/** Must match `contracts.agentToolResultMiddleware` in openclaw.plugin.json. */
export const MIDDLEWARE_RUNTIMES = ["openclaw"];

function intentKindOf(triggerKind: string): IntentKind {
  if (triggerKind === "message") return "user";
  if (triggerKind === "subagent") return "subagent";
  if (triggerKind === "scheduled" || triggerKind === "heartbeat" || triggerKind === "hook") return "cron";
  return "system";
}

function resultText(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object" && Array.isArray((v as any).content)) {
    return (v as any).content
      .map((b: any) => (b?.type === "text" && typeof b.text === "string" ? b.text : b?.type ? `[${b.type}]` : ""))
      .filter(Boolean)
      .join("\n");
  }
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/**
 * The text a `read` showed the model, when its result is plain text: a string, or exactly one text block. Null for
 * anything else (an image, several blocks, an unknown shape), which a folder grant never vouches for. `text` is the
 * result's full text (from the result middleware when it ran).
 */
export function readShown(result: unknown, text: string): string | null {
  if (typeof result === "string") return text;
  const blocks = result && typeof result === "object" ? (result as any).content : undefined;
  if (!Array.isArray(blocks) || blocks.length !== 1) return null;
  const [b] = blocks;
  return b?.type === "text" && typeof b.text === "string" ? text : null;
}

function sessionIdOf(ctx: any): string {
  return ctx?.sessionId || ctx?.sessionKey || "unknown";
}

/** The session a command was sent from, keyed as `sessionIdOf` keys scans; undefined when there is none. */
function commandSessionOf(ctx: any): string | undefined {
  const sid = ctx?.sessionId || ctx?.sessionKey;
  return typeof sid === "string" && sid ? sid : undefined;
}

const plugin = {
  id: "sentrook",
  name: "Sentrook",
  description: "Scans agent tool calls with Sentrook and allows, asks for approval, or blocks them.",

  register(api: OpenClawPluginApi) {
    const mode = api.registrationMode ?? "full";
    // The runtime is a proxy that throws outside full registration, so read its version only when needed.
    const runtimeVersion = (): string | undefined => {
      try {
        const v = api.runtime?.version;
        return typeof v === "string" && v ? v : undefined;
      } catch {
        return undefined;
      }
    };
    // OpenClaw's config as it is now. `api.config` is a snapshot taken at load, so a later `config set` (an exec
    // mode, an MCP server) would not reach the scan; `runtime.config.current()` is the live one where the host has it.
    const hostConfig = (): any => {
      try {
        const live = api.runtime?.config?.current?.();
        if (live && typeof live === "object") return live;
      } catch {
        // The runtime throws outside full registration.
      }
      return api.config;
    };
    /**
     * The directory of the agent a hook's call belongs to (its Workshop skills are under it), as OpenClaw resolves it;
     * undefined when the host cannot say. May throw: the caller treats that as unknown.
     */
    const agentDirOf = (ctx: any): unknown => {
      const agentId = ctx?.agentId;
      if (typeof agentId !== "string" || !agentId) return undefined;
      const agent = api.runtime?.agent;
      if (typeof agent?.resolveAgentDir !== "function") return undefined;
      return agent.resolveAgentDir(hostConfig(), agentId);
    };
    if (api.registerCli && (mode === "cli-metadata" || mode === "discovery" || mode === "full")) {
      api.registerCli(
        async ({ program }) => {
          const { registerSentrookCli } = await import("./cli.ts");
          registerSentrookCli(program, () => api.pluginConfig ?? {}, hostConfig);
        },
        { descriptors: [{ name: "sentrook", description: "Sentrook plugin helpers (verify, status)", hasSubcommands: true }] },
      );
      if (mode === "cli-metadata") return;
    }

    // `/sentrook <subcommand>` in chat; the host answers it without a model request. Its prompt guidance carries the
    // agent rules, so the agent has them whether or not it opens one of the plugin's skills.
    try {
      const rules = agentRules();
      if (!rules.length) api.logger.warn(`${LOG} agent rules missing from the plugin folder; the agent is not given them`);
      api.registerCommand?.({
        name: "sentrook",
        description: "Sentrook plugin status and help",
        acceptsArgs: true,
        ...(rules.length ? { agentPromptGuidance: rules } : {}),
        handler: async (ctx) => ({
          text: await runSentrookCommand(ctx?.args, { pluginConfig: api.pluginConfig ?? {}, env: process.env }),
        }),
      });
    } catch (err) {
      api.logger.warn(`${LOG} /sentrook command unavailable: ${String(err)}`);
    }

    const loadConfig = (): { cfg: PluginConfig; env: NodeJS.ProcessEnv } => {
      const env = envWithOpenclawDotenv(process.env);
      return { cfg: resolveConfig(api.pluginConfig, env), env };
    };
    const boot = loadConfig().cfg;
    if (mode === "full") {
      const { cfg: bootCfg, env: bootEnv } = loadConfig();
      const issuer = bootCfg.endpoints.issuer;
      if (issuer.ok && !resolveOidcCredentials(api.pluginConfig ?? {}, bootEnv, issuer.url)) {
        api.logger.warn(
          `${LOG} not signed in; every tool call is stopped until you run openclaw sentrook login on this machine`,
        );
      }
    }
    /** The plugin's own skill texts as it loaded them: a read is the plugin's skill read only if it returned these. */
    const skillTexts = shippedSkillTexts();
    /** The folder OpenClaw installed the plugin in: its plugin-skills links point there, not into a copy the code runs from. */
    const installRoot = typeof api.rootDir === "string" && api.rootDir ? api.rootDir : null;
    /** OpenClaw's state directory as the gateway started with it (not from `.env`, which the agent can write). */
    const ocDir = openclawDir(process.env);
    const hostVersion = runtimeVersion();
    const store = new Store(boot.stateDir);
    const traffic = new TrafficLog(boot.trafficLog.path, boot.trafficLog.maxBytes, boot.trafficLog.enabled, (m) =>
      api.logger.warn(`${LOG} ${m}`),
    );
    // The read-only dashboard: a Gateway route behind gateway auth, shown as a Control UI tab.
    if (api.registerHttpRoute) {
      try {
        api.registerHttpRoute({
          path: dashboard.ROUTE,
          auth: "gateway",
          match: "prefix",
          handler: (req, res) => dashboard.handleRequest(req, res, () => loadConfig().cfg),
        });
        const tab = { ...dashboard.TAB, requiredScopes: [...dashboard.TAB.requiredScopes] };
        const controls = api.session?.controls;
        if (typeof controls?.registerControlUiDescriptor === "function") controls.registerControlUiDescriptor(tab);
        else api.registerControlUiDescriptor?.(tab);
      } catch (err) {
        api.logger.warn(`${LOG} dashboard unavailable: ${String(err)}`);
      }
    }
    // `/sentrook-history`, `/sentrook-why`, the grants commands and the rest: owner only, never in a group or channel
    // room, audited in the traffic log.
    for (const [verb, sub] of Object.entries(OWNER_SUBCOMMANDS)) {
      try {
        api.registerCommand?.({
          ...ownerCommand<OwnerContext & { args?: string; sessionId?: string; sessionKey?: string }>(
            {
              name: sub.command,
              verb,
              description: sub.description,
              handler: async (ctx, gate) => ({
                text: await sub.run(
                  {
                    pluginConfig: api.pluginConfig ?? {},
                    env: process.env,
                    owner: {
                      by: {
                        basis: gate.basis,
                        channel: typeof ctx.channel === "string" ? ctx.channel : null,
                        sender_ref: senderRef(ctx.senderId, store.salt()),
                      },
                      beforeWrite: gate.beforeWrite,
                      record: (record) => traffic.write(record),
                    },
                    session: commandSessionOf(ctx),
                    hostConfig: hostConfig(),
                    openclawDir: ocDir,
                    chat: {
                      channel: ctx.channel,
                      senderId: ctx.senderId,
                      from: (ctx as any).from,
                      to: (ctx as any).to,
                      sessionKey: ctx.sessionKey,
                      accountId: (ctx as any).accountId,
                      messageThreadId: (ctx as any).messageThreadId,
                    },
                  },
                  (ctx.args ?? "").trim(),
                ),
              }),
            },
            { traffic, salt: () => store.salt() },
            hostConfig,
          ),
          acceptsArgs: true,
        });
      } catch (err) {
        api.logger.warn(`${LOG} /${sub.command} command unavailable: ${String(err)}`);
      }
    }
    // ---- the plugin's own agent tools, for the owner's own direct chat: the read-only setup report (setupReport.ts)
    // and the setup proposal (proposals.ts). Neither sets anything Sentrook allows. ---------------------------------
    /**
     * The calls `before_tool_call` allowed, one set of markers per tool, by session and call id, for that tool's own
     * `execute` to take: a marker for one tool never answers a call of the other.
     */
    const ownMarkers = new Map<string, setupReport.Markers>([
      [setupReport.TOOL, new setupReport.Markers()],
      [proposals.TOOL, new setupReport.Markers()],
    ]);
    /**
     * For each allowed call (`ownKey`): the inputs its tool reads, as the gate saw them, which `execute` must find the
     * same (a plugin that changed the arguments after this one's hook leaves the call refused); and whether the session
     * held content no scan had seen yet.
     */
    const ownInputs = new Map<string, { inputs: string; unchecked: boolean }>();
    const ownKey = (tool: string, sid: string, callId: unknown) => `${tool}\n${sid}\n${String(callId)}`;
    /** Sessions the factories offered the tools in (OpenClaw said the sender is the owner), most recent last. */
    const ownOffered = new Map<string, number>();
    /** The own tools OpenClaw took a registration for. */
    const ownRegistered = new Set<string>();
    /** Own tools another plugin's tool of the same name ran in place of, in this process: their calls are scanned. */
    const ownForeign = new Set<string>();
    const OWN_RECORD = new Map<string, string>([
      [setupReport.TOOL, "setup_report"],
      [proposals.TOOL, "setup_proposal"],
    ]);
    const ownRecord = (tool: string, sid: string, outcome: string, extra: Json) =>
      traffic.write({ kind: OWN_RECORD.get(tool)!, session_ref: sessionRef(sid), outcome, ...extra });
    const itemsAsked = (params: unknown): Json => {
      const items = params && typeof params === "object" ? (params as any).items : undefined;
      return { items: Array.isArray(items) ? items.length : 0 };
    };
    const reportText = (days: number, now: Date): string => {
      const { cfg, env } = loadConfig();
      const target = store.loadNotify();
      let shadowed: string[] = [];
      try {
        shadowed = shadowingSkills(hostConfig(), process.env).map((s) => s.split(" at ")[0]!);
      } catch {
        shadowed = [];
      }
      const pc = api.pluginConfig ?? {};
      const state: setupReport.ReportState = {
        plugin_version: PLUGIN_VERSION,
        mode: cfg.mode,
        review_at: cfg.reviewAt,
        block_at: cfg.blockAt,
        scan_ok: cfg.endpoints.scan.ok && cfg.endpoints.issuer.ok,
        credentials_missing: [
          resolveSecretString(pc.clientId, env, CLIENT_ID_VAR) ? null : CLIENT_ID_VAR,
          resolveSecretString(pc.clientSecret, env, CLIENT_SECRET_VAR) ? null : CLIENT_SECRET_VAR,
        ].filter((v): v is string => v !== null),
        notice: target
          ? { target: hold.targetText(target), source: "/sentrook-notify here" }
          : { target: null, why: hold.NOTIFY_UNSET },
        attended_platforms: null,
        unsent_grants: Object.keys(cfg.unsentGrants ?? {}).length,
        shadowed_skills: [...new Set(shadowed)],
        traffic_log: cfg.trafficLog.enabled,
        held_waiting: hold.waiting(cfg.stateDir, now),
      };
      const force = setup.inForce(cfg, grants.load(cfg.stateDir), now);
      const log = cfg.trafficLog.enabled ? cfg.trafficLog.path : null;
      const ev = setup.readEvidence(log, cfg.reviewAt, now, days * 86_400_000);
      return setupReport.render(state, force, ev, now, days, log !== null && setupReport.logCapped(log));
    };
    /** Each own tool: what `execute` answers for a call its marker allowed, and what the traffic log records of it. */
    const OWN_TOOLS: Array<{
      name: string;
      label: string;
      description: string;
      parameters: unknown;
      /** What the tool reads from its arguments; a marker holds it as the gate saw it. */
      inputs: (params: unknown) => unknown;
      answer: (sid: string, params: unknown, unchecked: boolean) => { text: string; logged: Json };
    }> = [
      {
        name: setupReport.TOOL,
        label: "Sentrook setup report",
        description: setupReport.DESCRIPTION,
        parameters: setupReport.PARAMETERS,
        inputs: setupReport.daysOf,
        answer: (_sid, params) => {
          const days = setupReport.daysOf(params);
          return { text: reportText(days, new Date()), logged: { outcome: "answered", days } };
        },
      },
      {
        name: proposals.TOOL,
        label: "Sentrook setup proposal",
        description: proposals.description(CMD),
        parameters: proposals.PARAMETERS,
        inputs: proposals.check,
        answer: (sid, params, unchecked) => {
          const { cfg } = loadConfig();
          return proposals.propose(cfg.stateDir, proposals.check(params), sessionRef(sid), new Date(), CMD, proposals.newId, unchecked);
        },
      },
    ];
    const ownTool = (spec: (typeof OWN_TOOLS)[number], toolCtx: any): Json => ({
      name: spec.name,
      label: spec.label,
      description: spec.description,
      parameters: spec.parameters,
      async execute(toolCallId: string, params: unknown) {
        const sid = sessionIdOf(toolCtx);
        const extra = spec.name === proposals.TOOL ? itemsAsked(params) : {};
        let text: string = setupReport.REFUSAL;
        try {
          const seen = ownInputs.get(ownKey(spec.name, sid, toolCallId));
          ownInputs.delete(ownKey(spec.name, sid, toolCallId));
          if (!ownMarkers.get(spec.name)!.take(sid, toolCallId)) {
            ownRecord(spec.name, sid, "refused", { reason: "no_marker", ...extra });
          } else if (!seen || seen.inputs !== JSON.stringify(spec.inputs(params))) {
            ownRecord(spec.name, sid, "refused", { reason: "changed", ...extra });
          } else {
            const got = spec.answer(sid, params, seen.unchecked);
            text = got.text;
            ownRecord(spec.name, sid, got.logged.outcome as string, Object.fromEntries(Object.entries(got.logged).filter(([k]) => k !== "outcome")));
          }
        } catch (err) {
          api.logger.warn(`${LOG} ${spec.name} failed: ${String(err)}`);
          text = setupReport.REFUSAL;
          safely(`${spec.name} record`, () => ownRecord(spec.name, sid, "refused", { reason: "error", ...extra }));
        }
        return { content: [{ type: "text", text }], details: {} };
      },
    });
    for (const spec of OWN_TOOLS) {
      try {
        if (typeof api.registerTool !== "function") break;
        api.registerTool(
          (toolCtx: any) => {
            // Detached cron runs never carry the owner's identity; anyone else is not offered the tool at all.
            if (toolCtx?.senderIsOwner !== true) return null;
            for (const key of [toolCtx.sessionKey, toolCtx.sessionId]) {
              if (typeof key !== "string" || !key) continue;
              ownOffered.delete(key);
              ownOffered.set(key, Date.now());
            }
            while (ownOffered.size > 500) ownOffered.delete(ownOffered.keys().next().value!);
            return ownTool(spec, toolCtx);
          },
          { name: spec.name },
        );
        ownRegistered.add(spec.name);
      } catch (err) {
        api.logger.warn(`${LOG} ${spec.name} tool unavailable: ${String(err)}`);
      }
    }
    /**
     * The own tool a call is of, when it is one: a tool the plugin registered, offered in this session, and not found
     * answered by another plugin's tool (`foreignOwnTool`). Such a call is not scanned (`ownToolGate`).
     */
    const ownToolCall = (event: any, ctx: any): string | null =>
      typeof event?.toolName === "string" &&
      ownRegistered.has(event.toolName) &&
      !ownForeign.has(event.toolName) &&
      [ctx?.sessionKey, ctx?.sessionId].some((k) => typeof k === "string" && ownOffered.has(k))
        ? event.toolName
        : null;
    /**
     * After a call of an own tool `before_tool_call` allowed: OpenClaw runs the factory before it drops a tool whose
     * name another plugin already took, so a call can be allowed and then reach the other plugin's tool. A mark still
     * there on a call that ran without error means this plugin's `execute` never ran: the call is recorded as
     * `foreign_tool` (`FOREIGN_TEXT`, in status and verify) and every later call of that name is scanned like any other.
     */
    /**
     * The id of the owner's folder grant that vouches for the file this read took (`folders.attest`), or null. Only an
     * absolute or `~/` path: OpenClaw resolves a relative one against a working folder the plugin cannot be sure of
     * (as `agentSkills.ts` reads it), so such a read is never vouched for. `seen` is what the read showed the model:
     * OpenClaw's `read` answers the file's own text (or the lines an offset and limit picked), in one text block.
     */
    const trustedFolder = (cfg: PluginConfig, sid: string, params: unknown, seen: string | null): string | null => {
      const p = params as Record<string, unknown> | null | undefined;
      const filePath = [p?.path, p?.file_path, p?.filePath].find((v) => typeof v === "string" && v !== "");
      if (typeof filePath !== "string" || !seen) return null;
      const live = grants
        .effective(cfg, store.loadGrants(), new Date(), sessionRef(sid))
        .filter((g) => g.kind === "folder" && typeof g._id === "string")
        .map((g): [string, string] => [g._id!, g.pattern]);
      if (!live.length) return null;
      try {
        return folders.attest(cfg.stateDir, live, filePath, { home: homedir(), seen });
      } catch (err) {
        // a read the plugin cannot check is simply not vouched for
        api.logger.warn(`${LOG} folder check failed: ${String(err)}`);
        return null;
      }
    };

    const foreignOwnTool = (event: any, ctx: any): void => {
      const tool = event?.toolName;
      const callId = event?.toolCallId ?? ctx?.toolCallId;
      if (typeof tool !== "string" || !OWN_RECORD.has(tool) || !callId) return;
      const sid = sessionIdOf(ctx);
      ownInputs.delete(ownKey(tool, sid, callId));
      if (!ownMarkers.get(tool)!.drop(sid, callId) || event?.error) return;
      ownForeign.add(tool);
      api.logger.warn(`${LOG} ${tool}: ${setupReport.FOREIGN_TEXT}`);
      safely(`${tool} record`, () => ownRecord(tool, sid, "foreign_tool", {}));
      safely(`${tool} flag`, () => store.saveForeignTool(tool, new Date()));
    };

    // Full tool results from the result middleware, keyed by host call id (after_tool_call is capped).
    const fullResults = new Map<string, string>();
    /**
     * Background saves sent to the Skill Workshop drafts, by request id, until OpenClaw reports what it did with the
     * draft: kept it, did not keep it, or ran the call's own save instead.
     */
    const pendingDrafts = new Map<string, (outcome: bg.Announced, drafts: bg.PatchDraftCount | null) => Json>();

    const remember = (runId: string | undefined, ctx: any, patch: Json) => {
      store.mergeRun(runId, {
        trigger: ctx?.trigger,
        channel: ctx?.channel ?? ctx?.channelId,
        messageProvider: ctx?.messageProvider,
        senderId: ctx?.senderId,
        workspaceDir: ctx?.workspaceDir,
        inputProvenance: ctx?.inputProvenance,
        jobId: ctx?.jobId,
        ...patch,
      });
      safely("job run link", () => keepJobRun(runId, ctx));
      // A cron run's job target, kept once, at the first agent hook: before any of the run's tool calls.
      if (runId && ctx?.trigger === "cron" && !store.loadRun(runId).jobDeliveryRead) {
        let kept: cronDelivery.DeliverySnapshot | null = null;
        try {
          kept = cronDelivery.snapshot({
            trigger: ctx.trigger,
            jobId: ctx.jobId,
            agentId: ctx.agentId,
            hostConfig: hostConfig(),
            openclawDir: ocDir,
          });
        } catch (err) {
          api.logger.warn(`${LOG} cron job delivery lookup failed: ${String(err)}`);
        }
        store.mergeRun(runId, { jobDeliveryRead: true, jobDelivery: kept ?? undefined });
      }
    };

    const safely = (name: string, fn: () => void) => {
      try {
        fn();
      } catch (err) {
        api.logger.warn(`${LOG} ${name} failed: ${String(err)}`);
      }
    };

    /**
     * Keeps the cron run a session serves now (`Store.jobRunOf`), from the run's own agent hooks: the job OpenClaw's
     * run metadata names (`hold.cronJobId`) and the run's id. Another run in the same session (the owner's chat after
     * a cron run in the main session) drops it, as does the cron run's end (`agent_end`). A sub-agent spawned while it
     * stands takes it (`subagent_spawned`), so its holds and passes are the job's.
     */
    const keepJobRun = (runId: string | undefined, ctx: any): void => {
      const key = ctx?.sessionKey;
      if (!runId || typeof key !== "string" || !key) return;
      const jobId = hold.cronJobId(ctx, store.loadRun(runId));
      const cur = store.jobRunOf(key);
      if (jobId) {
        if (cur?.job_id !== jobId || cur.run_id !== runId || cur.via !== "cron") {
          store.setJobRun(key, { job_id: jobId, run_id: runId, via: "cron" });
        }
      } else if (cur?.via === "cron" && cur.run_id !== runId) {
        store.setJobRun(key, null);
      }
    };

    /**
     * The conversation logs are kept only while self-edits are declared; once the setting reads as review, they are
     * deleted (by the first hook that sees it) and nothing is kept.
     */
    const capturing = (cfg: PluginConfig): boolean => {
      if (cfg.skillReview === "allow") return true;
      try {
        if (store.deleteConversations()) api.logger.info(`${LOG} skillReview is review: self-edit conversation logs deleted`);
      } catch (err) {
        api.logger.warn(`${LOG} deleting self-edit conversation logs failed: ${String(err)}`);
      }
      return false;
    };
    safely("startup", () => {
      if (capturing(boot)) store.pruneConversations();
    });

    // ---- context joins -------------------------------------------------------------------------
    api.on("before_prompt_build", (event: any, ctx: any) =>
      safely("before_prompt_build", () => {
        const runId = event?.runId ?? ctx?.runId;
        const patch: Json = { currentUserMessage: event?.currentUserMessage, prompt: event?.prompt };
        // The agent's message a short reply from the owner answers (sent only with such a reply, `planir.ts`): read
        // once, at the run's first prompt build, before the run's own messages can be in the list.
        if (runId && !store.loadRun(runId).priorAgentRead) {
          patch.priorAgentRead = true;
          patch.priorAgentText = priorAgentTextOf(event?.messages, event?.currentUserMessage ?? event?.prompt);
        }
        // OpenClaw's own background process (selfEdit.ts): recognised here, where raw model runs never arrive.
        const kind = selfEdit.runKindOf(runId, ctx, event?.prompt);
        if (kind) {
          Object.assign(patch, {
            selfEdit: kind,
            selfEditSessionKey: ctx.sessionKey,
            ownerRequest: selfEdit.lastOwnerMessage(event?.messages),
          });
        }
        remember(runId, ctx, patch);
        if (!kind || !runId || !capturing(loadConfig().cfg)) return;
        // What the process reads: its copy of the conversation, then (after_tool_call) its own tool results.
        const redactor = createRedactor("standard", store.salt());
        const read = conversation.fromMessages(event?.messages, redactor);
        store.updateConversation(runId, (prior) => conversation.trim([...read, ...prior.filter((e) => e._own)]));
      }),
    );
    api.on("before_agent_run", (event: any, ctx: any) =>
      safely("before_agent_run", () => {
        const runId = event?.runId ?? ctx?.runId;
        const patch: Json = { senderIsOwner: event?.senderIsOwner };
        if (!store.loadRun(runId).prompt) patch.prompt = event?.prompt;
        if (ctx?.trigger === "heartbeat") patch.heartbeatEvents = heartbeatEventsOf(event?.messages);
        remember(runId, ctx, patch);
      }),
    );
    for (const hook of ["agent_turn_prepare", "before_model_resolve", "message_received"]) {
      api.on(hook, (event: any, ctx: any) =>
        safely(hook, () => {
          const runId = event?.runId ?? ctx?.runId;
          if (!runId) return;
          const patch: Json = {};
          if (hook === "message_received" && !store.loadRun(runId).prompt) patch.prompt = event?.content;
          remember(runId, ctx, patch);
        }),
      );
    }
    for (const hook of ["subagent_spawned", "subagent_delivery_target"]) {
      api.on(hook, (event: any, ctx: any) =>
        safely(hook, () => {
          const child = event?.childSessionKey ?? ctx?.childSessionKey;
          const parent = ctx?.requesterSessionKey ?? event?.requesterSessionKey;
          if (child && parent) store.setParent(child, parent);
          // A sub-agent of a cron run (or of one of its sub-agents) belongs to the run's job: the link is taken from
          // the parent session as the plugin keeps it now, never from text.
          const link = child && parent ? store.jobRunOf(parent) : null;
          if (link && child !== parent) store.setJobRun(child, { job_id: link.job_id, run_id: link.run_id, via: "subagent" });
        }),
      );
    }
    // Written before the batch's first tool hook: the only upfront view of narration and siblings.
    // Must stay synchronous.
    api.on("before_message_write", (event: any, ctx: any) => {
      safely("before_message_write", () => {
        if (event?.message?.role !== "assistant" || !ctx?.sessionKey) return;
        const content = Array.isArray(event.message.content) ? event.message.content : [];
        store.saveAssistant(ctx.sessionKey, {
          text: content.filter((c: any) => c?.type === "text").map((c: any) => c.text).join("\n"),
          calls: content
            .filter((c: any) => c?.type === "toolCall")
            .map((c: any) => ({ id: c.id, name: c.name, arguments: c.arguments })),
        });
      });
      return undefined;
    });

    try {
      // Name the runtime: without `runtimes`, OpenClaw 2026.9 targets every runtime it knows (openclaw and
      // codex) and rejects the registration when the manifest's contract names fewer.
      api.registerAgentToolResultMiddleware?.(
        (event: any) => {
          const id = event?.toolCallId;
          if (typeof id === "string") {
            fullResults.set(id, resultText(event?.result));
            if (fullResults.size > 500) fullResults.delete(fullResults.keys().next().value!);
          }
          return undefined;
        },
        { runtimes: MIDDLEWARE_RUNTIMES },
      );
    } catch (err) {
      api.logger.warn(`${LOG} result middleware unavailable (tool results capped at the hook's 8K): ${String(err)}`);
    }

    // ---- tool results --------------------------------------------------------------------------
    api.on("after_tool_call", async (event: any, ctx: any) => {
      safely("own tool check", () => foreignOwnTool(event, ctx));
      try {
        const hostId: string | undefined = event?.toolCallId ?? ctx?.toolCallId;
        if (!hostId || DISCOVERY_TOOLS.has(event?.toolName)) return;
        // A dispatcher call that was skipped left no history entry: its result (the envelope) belongs only to an
        // entry of that tool, never to another call that had the same host id (some providers reuse them).
        const dispatcher = TOOL_CALL_NAMES.has(event?.toolName);
        const { cfg } = loadConfig();
        const sid = sessionIdOf(ctx);
        await store.withSession(sid, () => {
          const sess = store.loadSession(sid);
          const entry = [...sess.history].reverse().find((h) => h._host_call_id === hostId || h.call_id === hostId);
          if (!entry || (dispatcher && entry.tool !== event.toolName)) return;
          const text = fullResults.get(hostId) ?? resultText(event?.result ?? event?.error);
          if (entry.decision === "drafted") {
            // Only now is the draft known kept, lost, or ignored (OpenClaw ran the call's own create, so the skill
            // was saved live): recorded and announced here, not when it was sent.
            const ignored = bg.draftIgnored(event);
            const saved = !ignored && bg.draftSaved(event, text);
            const outcome: bg.Announced = ignored ? "draft_ignored" : saved ? "drafted" : "draft_failed";
            // a save that ran live goes to the scanner as one that ran
            if (ignored) entry.decision = "allowed";
            else if (!saved) entry.decision = "draft_failed";
            const announce = pendingDrafts.get(entry.request_id);
            pendingDrafts.delete(entry.request_id);
            // A kept patch draft is announced with its place in the run: drafts of one skill undo each other.
            const drafts =
              outcome === "drafted" && typeof entry._patch_skill === "string"
                ? bg.patchDraftCount(sess.history, entry._patch_skill)
                : null;
            let notice: Json | null = null;
            if (announce) safely("draft notice", () => void (notice = announce(outcome, drafts)));
            traffic.write({
              kind: "resolution",
              request_id: entry.request_id,
              resolution: ignored ? "draft_ignored" : saved ? "draft_saved" : "draft_failed",
              decision: entry.decision,
              ...(notice ? { notice } : {}),
            });
          }
          fullResults.delete(hostId);
          const sizeBytes = Buffer.byteLength(text, "utf8");
          const ran = !(NOT_RUN.has(entry.decision) && event?.error);
          entry.result = { status: event?.error || !ran ? "error" : "ok", size_bytes: ran ? sizeBytes : 0 };
          // A read of one of the plugin's own skill files that succeeded goes to the scanner as a read of the agent's
          // own skills (`agentSkills.ts`).
          if (entry.tool === "read" || entry.tool === SKILL_READ_TOOL) {
            const ok = ran && !event?.error;
            entry.tool = reportedTool(entry.tool, ok ? (event?.params ?? entry.arguments) : null, ok ? text : "", {
              texts: skillTexts,
              installRoot,
            });
          }
          if (ran) {
            const redactor = createRedactor("standard", store.salt());
            const redacted = redactor.string(text);
            const runId = event?.runId ?? ctx?.runId;
            if (runId && selfEdit.kindAtCall(store.loadRun(runId), ctx) && capturing(cfg)) {
              // A review's or curator's own reads are what its save draws on.
              safely("self-edit conversation", () =>
                store.updateConversation(runId, (prior) => {
                  const turn = Math.max(1, ...prior.map((e) => Number(e.turn) || 1));
                  const own = conversation.toolEntry(turn, entry.tool, event?.params ?? entry.arguments, redacted, redactor);
                  return conversation.trim([...prior, { ...own, _own: true }]);
                }),
              );
            }
            const capped = capHeadTail(redacted, cfg.inputCapBytes);
            sess.inputSeq += 1;
            const trusted =
              !event?.error && FOLDER_READ_TOOLS.has(entry.tool)
                ? trustedFolder(cfg, sid, event?.params ?? entry.arguments, readShown(event?.result, text))
                : null;
            sess.buffer.push({
              ...(trusted ? { _trusted_grant: trusted } : {}),
              input_seq: sess.inputSeq,
              kind: "tool_result",
              call_id: entry.call_id,
              tool: entry.tool,
              tool_kind: entry.tool_kind,
              provider: entry.provider,
              status: event?.error ? "error" : "ok",
              content_type: "text",
              content: capped.text,
              size_bytes: sizeBytes,
              truncated: capped.truncated,
            });
          }
          store.saveSession(sid, sess, cfg.historyLimit * 2);
        });
      } catch (err) {
        api.logger.warn(`${LOG} after_tool_call failed: ${String(err)}`);
      }
    });

    // ---- the scan ------------------------------------------------------------------------------
    api.on(
      "before_tool_call",
      async (event: any, ctx: any): Promise<BeforeToolCallResult | undefined> => {
        if (isUnscanned(event)) return undefined;
        const own = ownToolCall(event, ctx);
        if (own) return ownToolGate(event, ctx, own);
        try {
          const { cfg, env } = loadConfig();
          if (cfg.configProblems.length) settingsNotice(cfg);
          const sid = sessionIdOf(ctx);
          return await store.withSession(sid, () => scanOne(cfg, env, sid, event, ctx));
        } catch (err) {
          api.logger.warn(`${LOG} before_tool_call failed: ${String(err)}`);
          const detail = String(err).replace(/\n/g, " ").trim().slice(0, 160);
          return { block: true, blockReason: `Sentrook plugin error; this tool was not scanned or run. Detail: ${detail}` };
        }
      },
      { priority: 10 },
    );

    /**
     * `before_tool_call` for the plugin's own agent tools: not scanned, and allowed only on the owner's own message in
     * a direct chat (`setupReport.reportAllowed`, from the run's trigger as the plugin recorded it). An allowed call
     * gets its marker (session and call id) and a step in the session's history, so its result goes to the next scan
     * like any tool result. Anything else, a failure included, gets `setupReport.REFUSAL` and nothing more.
     */
    async function ownToolGate(event: any, ctx: any, tool: string): Promise<BeforeToolCallResult | undefined> {
      const sid = sessionIdOf(ctx);
      const refuse = (reason: string): BeforeToolCallResult => {
        const extra = tool === proposals.TOOL ? itemsAsked(event?.params) : {};
        safely(`${tool} record`, () => ownRecord(tool, sid, "refused", { reason, ...extra }));
        return { block: true, blockReason: setupReport.REFUSAL };
      };
      try {
        const { cfg } = loadConfig();
        return await store.withSession(sid, () => {
          const runId = event?.runId ?? ctx?.runId;
          const run = store.loadRun(runId);
          const callId = event?.toolCallId ?? ctx?.toolCallId;
          if (!runId || typeof callId !== "string" || !callId || !setupReport.reportAllowed(run, ctx, cfg, hostConfig())) {
            return refuse("not_owner_turn");
          }
          const sess = store.loadSession(sid);
          const built = buildPlanir({
            hostConfig: hostConfig(),
            cfg,
            redactor: createRedactor("standard", store.salt()),
            event,
            ctx,
            sid,
            sess,
            run,
            assistant: store.loadAssistant(ctx?.sessionKey),
            parents: store.parents(),
            grants: [],
            hostVersion,
            hostProcess: false,
            selfEdit: null,
          });
          sess.history.push({
            step: built.step,
            turn: built.turn,
            call_id: built.callId,
            tool: event.toolName,
            tool_kind: built.toolKind,
            provider: built.provider,
            arguments: built.historyArgs,
            result: null,
            action_fingerprint: null,
            risk: null,
            tiers: null,
            request_id: built.planir.request_id,
            decision: "allowed",
            ...(built.hostCallId ? { _host_call_id: built.hostCallId } : {}),
          });
          store.saveSession(sid, sess, cfg.historyLimit * 2);
          ownMarkers.get(tool)!.put(sid, callId);
          // Content the chat read since the last scan reaches the scanner only with the next scanned call: what it
          // was cannot be checked now, so the owner is told. The plugin's own tools' results are its own text.
          const unchecked = (built.planir.new_inputs as any[]).some((i) => !OWN_RECORD.has(i?.tool));
          const spec = OWN_TOOLS.find((t) => t.name === tool)!;
          ownInputs.set(ownKey(tool, sid, callId), { inputs: JSON.stringify(spec.inputs(event?.params)), unchecked });
          while (ownInputs.size > 500) ownInputs.delete(ownInputs.keys().next().value!);
          return undefined;
        });
      } catch (err) {
        api.logger.warn(`${LOG} ${tool} check failed: ${String(err)}`);
        return refuse("error");
      }
    }

    /** On a cron run, the grant for its job's own delivery target (`cronDelivery.ts`); a failed read gives none. */
    function jobDeliveryGrant(run: RunContext, ctx: any, sess: Session, sid: string, params: unknown): GrantConfig[] {
      try {
        const g = cronDelivery.deliveryGrant({
          run,
          kind: triggerKind(run),
          argsText: JSON.stringify(params ?? {}),
          agentId: ctx?.agentId,
          hostConfig: hostConfig(),
          history: sess.history,
          sessionRef: sessionRef(sid),
          openclawDir: ocDir,
        });
        return g ? [g] : [];
      } catch (err) {
        api.logger.warn(`${LOG} cron job delivery lookup failed: ${String(err)}`);
        return [];
      }
    }

    async function scanOne(
      cfg: PluginConfig,
      env: NodeJS.ProcessEnv,
      sid: string,
      event: any,
      ctx: any,
    ): Promise<BeforeToolCallResult | undefined> {
      const sess = store.loadSession(sid);
      const runId = event?.runId ?? ctx?.runId;
      const run = store.loadRun(runId);
      const redactor = createRedactor("standard", store.salt());
      // OpenClaw's own background process: sent as the host's, and its saves as self-edits (selfEdit.ts).
      const runKind = selfEdit.kindAtCall(run, ctx);
      const runStore = runKind ? selfEdit.saveStoreOf(runKind, event.toolName, event?.params, run) : null;
      // One of its saves: never asked about, whatever the settings say (backgroundSave.ts).
      let bgSave = runKind && runStore ? { kind: runKind, store: runStore } : null;
      const hostKind = cfg.skillReview === "allow" ? runKind : null;
      const saveStore = hostKind ? runStore : null;
      // Any exec of the run is declared too, with the run's store: the scanner reads it as a self-edit only when the
      // command writes into that store, and answers with `self_edit` only then (selfEdit.execStoreOf).
      const execStore = hostKind && !saveStore ? selfEdit.execStoreOf(hostKind, toolKind(event.toolName)) : null;
      const declaredStore = saveStore ?? execStore;
      let selfEditBlock: Json | null = null;
      if (hostKind && declaredStore) {
        const params = redactor.value(event?.params ?? {});
        try {
          const saveArgs = execStore ? selfEdit.execSaveArgs(params) : params;
          selfEditBlock = conversation.block(hostKind, declaredStore, store.loadConversation(runId), saveArgs);
        } catch (err) {
          api.logger.warn(`${LOG} self-edit conversation failed: ${String(err)}`);
          selfEditBlock = { kind: hostKind, store: declaredStore, conversation: [] };
        }
      }
      const built = buildPlanir({
        hostConfig: hostConfig(),
        cfg,
        redactor,
        event,
        ctx,
        sid,
        sess,
        run,
        assistant: store.loadAssistant(ctx?.sessionKey),
        parents: store.parents(),
        grants: [
          ...grants.effective(cfg, store.loadGrants(), new Date(), sessionRef(sid)),
          ...jobDeliveryGrant(run, ctx, sess, sid, event?.params),
        ],
        hostVersion,
        hostProcess: hostKind !== null,
        selfEdit: selfEditBlock,
      });
      const body = JSON.stringify(built.planir);
      const triggerKind: string = built.planir.trigger.kind;
      const timing = resolveApprovalTiming(cfg.approval, intentKindOf(triggerKind), undefined);
      // Nobody can answer a prompt in one of OpenClaw's background runs, on any OpenClaw: the host cancels it or ends
      // the run. That holds for every call of the run, not only its saves (backgroundSave.ts). Nor in a subagent's run,
      // even one the owner's own chat started: OpenClaw refuses a plugin's approval request from a subagent's run (its
      // gateway identity has no approvals scope), so its reviews are held, bound to the parent session (`runSource`),
      // whatever `approval.scheduledIntentKinds` says.
      const unattended = timing.unattended || runKind !== null || triggerKind === "subagent";

      let result: ScanOk | ScanFailure;
      let oidc: ReturnType<typeof resolveOidcCredentials> = null;
      const { scan, issuer } = cfg.endpoints;
      if (!scan.ok) result = { ok: false, kind: "config", detail: `scan URL: ${scan.reason}` };
      else if (!issuer.ok) result = { ok: false, kind: "config", detail: `OIDC issuer: ${issuer.reason}` };
      else {
        oidc = resolveOidcCredentials(api.pluginConfig ?? {}, env, issuer.url);
        result = await postScan({
          scanUrl: scan.url,
          oidc,
          body,
          timeoutMs: cfg.timeoutMs,
        });
      }

      const entry: HistoryEntry = {
        step: built.step,
        turn: built.turn,
        call_id: built.callId,
        tool: event.toolName,
        tool_kind: built.toolKind,
        provider: built.provider,
        arguments: built.historyArgs,
        result: null,
        action_fingerprint: null,
        risk: null,
        tiers: null,
        request_id: built.planir.request_id,
        decision: "allowed",
        ...(built.hostCallId ? { _host_call_id: built.hostCallId } : {}),
      };

      let hook: BeforeToolCallResult | undefined;
      let verdict: Verdict | null = null;
      let onError = false;
      let snoozed = false;
      /** What the scan record says about a notice other than a hold's (a scan failure, a background save). */
      let notice: Json | null = null;
      let relaxed = false;
      /** A relaxed block with a strong signal (snooze.asks): a stronger warning on the card. */
      let strong = false;
      let lenient = false;
      /** What a reviewed background save becomes in the drafts; `params` null: the model's own draft, run as it is. */
      let drafting: { params: Record<string, unknown> | null } | null = null;
      /** Whether a reviewed background patch went to the drafts, or why not (the scan record's `patch_draft`). */
      let patchDraft: bg.PatchDraft | null = null;
      const workshopAction = event.toolName === "skill_workshop" ? selfEdit.workshopAction(event?.params) : "";
      const toDraft = (resp: ScanOk["response"]): { params: Record<string, unknown> | null } | null => {
        const version = hostVersion ?? process.env.OPENCLAW_VERSION;
        const patch = bg.patchDraft(event.toolName, event?.params, version, resp, selfEditBlock !== null, () => agentDirOf(ctx), new Date(), built.planir.request_id);
        if (patch) {
          patchDraft = "params" in patch ? "drafted" : patch.skip;
          return "params" in patch ? { params: patch.params } : null;
        }
        // A draft keeps what it saves until the owner looks: never one the scan says holds a secret.
        if (bg.keepsSecret(resp)) return null;
        if (workshopAction === "draft" && event.toolName === "skill_workshop") return { params: null };
        const params = bg.draftParams(event.toolName, event?.params, version);
        return params ? { params } : null;
      };
      let held: Json | null = null;
      /** The owner's pass or denial that settled an unattended review (passes.ts). */
      let byPass: Json | null = null;
      /** The suggested grant "allow always" sets, when the prompt offers it. */
      let remember: grants.Entry | null = null;
      /** What "Always allow" keeps for an MCP tool on its server when it sets no grant (alwaysAllow.ts). */
      let standingOffer: Json | null = null;
      /** The earlier "Always allow" answer that let this review through. */
      let alwaysAllowed: Json | null = null;
      let alwaysKey: string | null = null;
      let standing: [Json, Json] | null = null;
      /**
       * The standing allowance key "Always allow" on this review would keep, and a later review is matched by
       * (alwaysAllow.ts): an MCP tool call with a server identity, from the owner's own message on the main agent
       * outside a group chat; never for a block a snooze turned into a review or a score at the block line.
       */
      const alwaysKeyOf = (resp: ScanOk["response"], relaxedNow: boolean): string | null => {
        const risk = passes.riskOf(resp);
        if (relaxedNow || !grants.mayRemember(built.planir) || risk === null || risk >= cfg.blockAt) return null;
        return alwaysAllow.keyOf(event.toolName, built.provider, resp, store.salt());
      };
      const alwaysAllows = (): Json | null => {
        try {
          return alwaysAllow.load(cfg.stateDir);
        } catch (err) {
          api.logger.warn(`${LOG} could not read the Always answers: ${String(err)}`);
          return null;
        }
      };
      if (result.ok) {
        const resp = result.response;
        // An exec the scanner read as a save into the run's store is one of the run's saves: never asked about, and
        // held or blocked as a file save is (it carries no content a draft could keep).
        if (!bgSave && runKind && execStore && selfEdit.scannedAsSelfEdit(resp)) {
          bgSave = { kind: runKind, store: execStore };
        }
        // A run nobody can answer lowers a block to a review only for a retry of a review nobody answered or code
        // that reaches no network sink: that call is held for the owner. The attended-owner ceiling is dropped there
        // (`unattendedView`).
        verdict = decide(unattended ? unattendedView(resp) : resp, cfg);
        // The turn's own channel as OpenClaw names it, before the plugin folds it into a few kinds.
        const rawChannel = ctx?.requester?.channel ?? run.channel ?? run.messageProvider ?? null;
        const asked =
          snooze.asks(resp, verdict, built.planir, { channel: typeof rawChannel === "string" ? rawChannel : null }) ??
          // a review of an action the owner was asked about with the warning asks the same way, never snoozed
          (verdict === "review" && snooze.askedBefore(sess, resp) ? "strong" : null);
        if (
          // Only a human's message, as for a snoozed review: an unattended run is never relaxed.
          cfg.mode !== "observe" &&
          triggerKind === "message" &&
          !unattended &&
          asked !== null &&
          snooze.active(store.loadSnooze(), built.planir.session.session_ref, new Date())
        ) {
          // The owner snoozed this attended session: the block asks instead (`snooze.asks`), at critical severity,
          // offering Allow once and Deny only. It is never allowed silently.
          verdict = "review";
          relaxed = true;
          strong = asked === "strong";
        }
        sess.token = resp.state ?? null;
        sess.buffer = [];
        entry.action_fingerprint = resp.action_fingerprint ?? null;
        entry.risk = resp.risk;
        entry.tiers = tiersOf(resp);
        if (cfg.mode === "observe" || verdict === "allow") {
          entry.decision = "allowed";
        } else if (verdict === "block") {
          entry.decision = "blocked";
          hook = { block: true, blockReason: blockReason(resp) };
          if (bgSave) notice = backgroundNotice(cfg, "blocked", built, resp, event.toolName, bgSave, triggerKind, run);
        } else if (
          // Only a human's message: a run whose trigger is unknown or not a message is never snoozed,
          // whatever the approval timeout policy calls attended.
          !relaxed &&
          triggerKind === "message" &&
          !unattended &&
          snooze.applies(resp, cfg.blockAt) &&
          snooze.active(store.loadSnooze(), built.planir.session.session_ref, new Date())
        ) {
          // The owner snoozed reviews for this session: scanned and logged, not asked.
          entry.decision = "allowed";
          snoozed = true;
        } else if (
          selfEditBlock &&
          bgSave &&
          selfEdit.contentSave(event.toolName, event?.params) &&
          bg.lenientOf(resp, cfg.blockAt)
        ) {
          // A declared background save the scanner marks lenient, whose content the scan read: kept, and the owner
          // told. A change that carries no content (a restore, an archive) saves what the scan never saw: held below.
          entry.decision = "allowed";
          lenient = true;
          notice = backgroundNotice(cfg, "lenient", built, resp, event.toolName, bgSave, triggerKind, run);
        } else if (bgSave && !bg.capped(resp, cfg.blockAt) && (drafting = toDraft(resp))) {
          // The model's own draft, a new skill, or a patch of a skill's SKILL.md applied to the live file (OpenClaw
          // 2026.11.5 or newer): kept as a Workshop draft, inert until the owner applies it. The owner is told once
          // OpenClaw reports what it did with the draft (after_tool_call).
          entry.decision = "drafted";
          if (drafting.params) hook = { params: drafting.params };
          if (patchDraft === "drafted" && typeof drafting.params?.name === "string") entry._patch_skill = drafting.params.name;
          const save = bgSave;
          pendingDrafts.set(built.planir.request_id, (outcome, drafts) =>
            backgroundNotice(cfg, outcome, built, resp, event.toolName, save, triggerKind, run, false, workshopAction, drafts),
          );
          if (pendingDrafts.size > 200) pendingDrafts.delete(pendingDrafts.keys().next().value!);
        } else if (bgSave) {
          // Nothing better applies: not saved, and the owner told; nobody can approve it, so the agent is told so. The
          // first block-level score the scanner capped at review in a run is announced whatever was announced before;
          // later ones wait out their own quiet period, so a model that keeps retrying cannot flood the channel.
          entry.decision = "held";
          hook = { block: true, blockReason: bg.HELD_TEXT };
          held = {
            id: null,
            background: true,
            notice: backgroundNotice(
              cfg,
              "held",
              built,
              resp,
              event.toolName,
              bgSave,
              triggerKind,
              run,
              bg.capped(resp, cfg.blockAt),
              workshopAction,
            ),
          };
        } else if (runKind) {
          // Another call of one of OpenClaw's background runs: nobody can answer it, and approving it later could
          // not bring the run back. Not run, the agent told so, and the owner told once per run (backgroundSave.ts).
          entry.decision = "held";
          hook = { block: true, blockReason: bg.HELD_CALL_TEXT };
          held = { id: null, background: true, run: runKind, notice: heldCallNotice(cfg, built, resp, event.toolName, triggerKind, run, runKind) };
        } else if (unattended) {
          // Nobody can answer a review here: the owner's denial or pass for this job and action settles it
          // (passes.ts); otherwise the call waits for the owner (hold.ts).
          // A sub-agent of a cron run (or of one of its sub-agents): the job's own holds and passes apply, with the
          // run's key and start (`jobRunOf`). Until OpenClaw reports the spawn, its parent session is its source.
          const jobRun = triggerKind === "subagent" && hold.cronJobId(ctx, run) === null ? jobRunOf(ctx) : null;
          const jobId = jobRun ? jobRun.job_id : hold.cronJobId(ctx, run);
          /** The agent run whose run key and start the job's holds and passes use: the cron run's own. */
          const jobRunId = jobRun ? jobRun.run_id : runId;
          // Off a cron job, where the run came from, when OpenClaw names it: the answers are bound to it.
          const source = jobId === null ? runSource(triggerKind, ctx, built) : null;
          const match = passes.matchOf(event.toolName, resp, event?.params ?? {}, store.salt(), jobId === null && source === null);
          // A run the plugin started for an owner's allow (runNow.ts): its pass serves this run only, its sub-agents
          // included.
          const rerun = jobId ? startedRun(cfg, jobId, jobRunId) : null;
          const rerunId = typeof rerun?.id === "string" ? rerun.id : null;
          let settled: Json | null = null;
          try {
            settled = passes.check(cfg.stateDir, passes.jobRef(jobId) ?? source?.ref ?? null, match, resp, new Date(), rerunId);
          } catch (err) {
            api.logger.warn(`${LOG} could not read the passes: ${String(err)}`);
          }
          if (settled?.kind === "deny") {
            entry.decision = "denied_by_owner";
            hook = { block: true, blockReason: passes.DECLINED_TEXT };
            byPass = { id: settled.id, kind: "deny" };
          } else if (settled) {
            entry.decision = "allowed_by_pass";
            byPass = { id: settled.id, kind: "allow", uses: settled.uses, use_count: settled.use_count };
            if (rerunId && settled.id === rerunId) noteRun(cfg, rerunId, { passed: true });
          } else {
            entry.decision = "held";
            hook = { block: true, blockReason: hold.HELD_TEXT };
            held = holdCall(cfg, built, resp, event.toolName, triggerKind, run, {
              sid,
              jobId,
              source,
              match,
              // a sub-agent's hold counts what the cron run itself had already sent or written
              acted: !!run.acted || (jobRun !== null && !!store.loadRun(jobRun.run_id).acted),
              ...(jobId ? runIdentity(jobId, jobRunId) : { runKey: null, runStart: null }),
              acts: passes.acts(built.toolKind, resp),
              jobRun: jobRun ? store.loadRun(jobRun.run_id) : null,
            });
            if (rerunId && typeof held?.id === "string") noteRun(cfg, rerunId, { held: held.id });
          }
        } else if (
          (standing = alwaysAllow.covering(
            alwaysAllows(),
            (alwaysKey = alwaysKeyOf(resp, relaxed)),
            resp,
            new Date(),
            cfg.blockAt,
          )) !== null
        ) {
          // The owner answered "Always allow" for a call of this MCP tool on this server, at most 10 points below this
          // risk, with every attack-type warning this one carries (alwaysAllow.ts). History says allowed: the owner
          // was not shown this call.
          entry.decision = "allowed";
          alwaysAllowed = { by: standing[1].request_id ?? null, id: standing[0].id ?? null };
        } else {
          // Provisional until the user answers.
          entry.decision = "review_timed_out";
          // The grant the scan suggests: the prompt shows its command, and "allow always" sets it where the owner is
          // the one answering. Never for a block a snooze turned into a review.
          const hint = grants.ownerSender(built.planir) ? hold.grantHint(resp, cfg.reviewAt) : null;
          remember = hint !== null && !relaxed && grants.mayRemember(built.planir) ? hint : null;
          // Without a grant to set, "allow always" on an MCP tool call keeps that tool on that server (alwaysAllow.ts).
          const server = alwaysAllow.serverOf(built.provider);
          const risk = passes.riskOf(resp);
          standingOffer =
            remember === null && alwaysKey !== null && server !== null && risk !== null
              ? { key: alwaysKey, tool: event.toolName, server: server[0], identity: server[1], risk, warnings: passes.warnings(resp) }
              : null;
          if (relaxed) snooze.noteAsked(sess, resp);
          const copy = reviewCard(resp, event.toolName, {
            relaxed,
            strong,
            hint,
            remember: remember !== null,
            always: standingOffer !== null,
            whyId: cfg.trafficLog.enabled ? built.planir.request_id : null,
          });
          hook = {
            requireApproval: {
              ...copy,
              severity: severity(resp, cfg, relaxed),
              timeoutMs: timing.timeoutMs,
              // An unanswered card never runs the call, on a host that reads this or not.
              timeoutBehavior: "deny",
              allowedDecisions: remember || standingOffer ? ["allow-once", "allow-always", "deny"] : ["allow-once", "deny"],
            },
          };
        }
      } else {
        onError = true;
        // Observe mode never interferes, not even on errors.
        hook =
          cfg.mode === "observe"
            ? undefined
            : scanErrorToHookResult(result, {
                onScanError: cfg.onScanError,
                unattended,
                interactiveTimeoutMs: cfg.approval.interactiveTimeoutMs,
              });
        entry.decision = hook?.block || hook?.requireApproval ? "blocked_on_error" : "allowed_on_error";
        api.logger.warn(`${LOG} scan failed (${result.kind}): ${result.detail}`);
        const withdrawn = result.setup === "consent_withdrawn" && oidc !== null;
        // One notice for the withdrawal, in either mode, instead of one per job or session.
        if (withdrawn) notice = consentNotice(cfg, oidc!.clientId);
        else if (hook?.block && unattended) {
          notice = scanFailureCall(cfg, built, result, event.toolName, triggerKind, run, runKind);
        }
      }

      // A declared exec is a self-edit only when the scanner read it as one (it writes into the run's store).
      const scannedSelfEdit =
        selfEditBlock !== null && (execStore === null || (result.ok && selfEdit.scannedAsSelfEdit(result.response)));

      sess.history.push(entry);
      store.saveSession(sid, sess, cfg.historyLimit * 2);
      // A call that runs and sends or writes something: a later hold in this run says so (runNow.ts).
      if (result.ok && !NOT_RUN.has(entry.decision) && entry.decision !== "drafted" && passes.acts(entry.tool_kind, result.response)) {
        if (runId && !run.acted) safely("acted", () => store.mergeRun(runId, { acted: true }));
      }

      traffic.write({
        kind: "scan",
        request_id: built.planir.request_id,
        session_ref: built.planir.session.session_ref,
        step: built.step,
        tool: event.toolName,
        mode: cfg.mode,
        verdict,
        decision: entry.decision,
        ...(snoozed ? { snoozed: true } : {}),
        ...(relaxed ? { relaxed: true } : {}),
        ...(strong ? { relaxed_strong: true } : {}),
        ...(lenient ? { lenient: true } : {}),
        ...(held ? { hold: held } : {}),
        ...(byPass ? { pass: byPass } : {}),
        ...(alwaysAllowed ? { always_allowed: alwaysAllowed } : {}),
        ...(notice ? { notice } : {}),
        ...(scannedSelfEdit ? { skill_review: true, self_edit: { kind: hostKind, store: declaredStore } } : {}),
        ...(hostKind && !scannedSelfEdit ? { host_process: hostKind } : {}),
        ...(bgSave ? { background_save: bgSave } : {}),
        ...(patchDraft ? { patch_draft: patchDraft } : {}),
        latency_ms: result.ok ? result.latencyMs : null,
        host_labels: hostLabels(run, ctx),
        planir: built.planir,
        response: result.ok ? result.response : null,
        failure: result.ok ? null : { kind: result.kind, status: result.status ?? null, detail: result.detail },
      });
      api.logger.info(
        `${LOG} scan step=${built.step} tool=${event.toolName} ` +
          (result.ok
            ? `risk=${result.response.risk} enforced=${result.response.enforced} status=${result.response.status} verdict=${verdict}${snoozed ? " (snoozed)" : strong ? " (block with a strong signal asked by snooze)" : relaxed ? " (block relaxed to review by snooze)" : byPass ? ` (${byPass.kind === "deny" ? "refused by" : "let through by"} ${byPass.id})` : ""}${scannedSelfEdit ? " (self-edit)" : hostKind ? " (host process)" : ""}${bgSave ? ` background_save=${entry.decision}${lenient ? " (lenient)" : ""}` : ""} mode=${cfg.mode}`
            : `failed=${result.kind} decision=${entry.decision}`) +
          ` ms=${result.ok ? result.latencyMs : "-"}`,
      );

      if (hook?.requireApproval) {
        const requestId = built.planir.request_id;
        hook.requireApproval.onResolution = async (decision: Resolution) => {
          const approved = decision === "allow-once" || decision === "allow-always";
          const final = onError
            ? approved
              ? "allowed_on_error"
              : "blocked_on_error"
            : approved
              ? "approved_by_user"
              : decision === "deny"
                ? "denied_by_user"
                : decision === "timeout"
                  ? "review_timed_out"
                  : "blocked";
          let grantId: string | null = null;
          if (decision === "allow-always" && remember && !onError) {
            // Approved for good: the suggested grant, persistent for 30 days, once per review. A grant that cannot be
            // written is logged; the answer itself stands.
            const by = { basis: ["review_always"], platform: String(built.planir.trigger?.channel ?? "") };
            try {
              const { reply, change } = grants.addSuggested(cfg.stateDir, remember, by, new Date(), hold.GRANT_TTL_MS, requestId, () => {}, "from_review");
              if (change) {
                grantId = String(change.entry.id);
                if (!change.existing) traffic.write({ kind: "grants", ...change, by });
              } else {
                api.logger.warn(`${LOG} could not set the suggested grant: ${reply}`);
              }
            } catch (err) {
              api.logger.warn(`${LOG} could not set the suggested grant: ${String(err)}`);
            }
          }
          let alwaysId: string | null = null;
          if (decision === "allow-always" && !remember && standingOffer && !onError) {
            // Approved for good on an MCP tool call with no grant to set: that tool on that server (alwaysAllow.ts).
            const offer = standingOffer;
            try {
              const kept = alwaysAllow.add(cfg.stateDir, {
                key: String(offer.key),
                tool: String(offer.tool),
                server: String(offer.server),
                identity: String(offer.identity),
                risk: Number(offer.risk),
                seen: (offer.warnings as string[]).map(String),
                requestId,
                now: new Date(),
              });
              if (kept) alwaysId = String(kept.id);
              else api.logger.warn(`${LOG} could not keep the Always answer: ${alwaysAllow.FILE} cannot be read`);
            } catch (err) {
              api.logger.warn(`${LOG} could not keep the Always answer: ${String(err)}`);
            }
          }
          try {
            await store.withSession(sid, () => {
              const s = store.loadSession(sid);
              const h = s.history.find((x) => x.request_id === requestId);
              if (h) h.decision = final;
              store.saveSession(sid, s, cfg.historyLimit * 2);
            });
          } catch (err) {
            api.logger.warn(`${LOG} recording review outcome failed: ${String(err)}`);
          }
          traffic.write({
            kind: "resolution",
            request_id: requestId,
            resolution: decision,
            decision: final,
            ...(grantId ? { grant_id: grantId } : {}),
            ...(alwaysId ? { always_allow: alwaysId } : {}),
          });
        };
      }
      return hook;
    }

    /**
     * Where an unattended run that is not a cron job came from, as OpenClaw's run metadata names it, for binding a held
     * call's answers (`passes.Source`); null when OpenClaw names nothing usable. Never from the prompt or the call:
     * - a heartbeat: its agent (`ctx.agentId`, from OpenClaw's settings: one heartbeat per agent);
     * - a subagent: its parent session (`parent_session_ref`, from the spawn hooks' requester session key).
     * A webhook or event run has none: OpenClaw gives plugins no hook or mapping id, and the run's job id, run id and
     * (isolated) session key are new for every request.
     */
    function runSource(triggerKind: string, ctx: any, built: { planir: any }): passes.Source | null {
      if (triggerKind === "heartbeat") {
        return typeof ctx?.agentId === "string" ? passes.sourceOf("heartbeat", ctx.agentId) : null;
      }
      if (triggerKind === "subagent") {
        const parent = built.planir?.session?.parent_session_ref;
        return typeof parent === "string" ? passes.sourceOf("subagent", parent) : null;
      }
      return null;
    }

    /**
     * The cron run a sub-agent's call belongs to: the link its session took from its parent session when OpenClaw
     * reported the spawn (`subagent_spawned`), the parent being the cron run's own session or another sub-agent of
     * it. OpenClaw gives a sub-agent's run no cron metadata of its own (no trigger, no provenance), and the parent is
     * known only from the spawn hooks' requester session key. Null when the spawn is not reported yet, or the parent
     * was not serving a cron run then. Never from the prompt or the session key's text.
     */
    function jobRunOf(ctx: any): JobRunLink | null {
      try {
        const link = store.jobRunOf(ctx?.sessionKey);
        return link?.via === "subagent" ? link : null;
      } catch (err) {
        api.logger.warn(`${LOG} could not read the sub-agent's cron run: ${String(err)}`);
        return null;
      }
    }

    /**
     * The unattended run a call belongs to, as the owner's notices name it: a cron job by its id (`subagent`: a call
     * of a sub-agent of the job's run), else the run (one of OpenClaw's background runs by what it is), with its
     * source when a hold's answers are bound to one.
     */
    function unattendedRun(
      sref: string,
      triggerKind: string,
      run: any,
      kind: selfEdit.SelfEditKind | null = null,
      boundJob?: string | null,
      source: passes.Source | null = null,
      subagent = false,
    ): { where: string; jobId: string | null } {
      const label: Record<string, string> = {
        scheduled: "scheduled run",
        heartbeat: "heartbeat run",
        hook: "webhook or event run",
        subagent: "subagent run",
      };
      // The job OpenClaw's run metadata names comes first; the prompt's tag only names a run the metadata does not.
      const tagged = triggerKind === "scheduled" || kind === "curator" ? hold.cronJobOf(run?.prompt) : null;
      // A hold names the job its answers are bound to (`boundJob`, from the run metadata), never the tag alone.
      const hostJob = boundJob !== undefined ? boundJob : hold.cronJobId(null, run);
      const job = hostJob ? { id: hostJob, name: tagged?.id === hostJob ? tagged.name : null } : boundJob !== undefined ? null : tagged;
      const name = kind ? bg.RUN_LABELS[kind] : (label[triggerKind] ?? "unattended run");
      return { where: hold.whereText(name, sref, job?.id, job?.name, job ? null : source, subagent && !!job), jobId: job?.id ?? null };
    }

    /**
     * The run of cron job `jobId` as a key: the run id on its running receipt (what `openclaw cron run` returned for a
     * run the plugin started), else the agent run's own id; and when it started, when the receipt says.
     */
    function runKeyOf(jobId: string, runId: string | undefined): { runKey: string | null; startedAt: Date | null } {
      const found = runNow.activeRun(ocDir, jobId);
      if (found) return found;
      return { runKey: runId ? `agent:${runId}` : null, startedAt: null };
    }

    /**
     * The run of cron job `jobId` as a hold keeps it: its key (`runKeyOf`) and when it started, from its running
     * receipt, else when the plugin first heard of the agent run (its first hook); null when neither is known.
     */
    function runIdentity(jobId: string, runId: string | undefined): { runKey: string | null; runStart: Date | null } {
      const { runKey, startedAt } = runKeyOf(jobId, runId);
      if (startedAt) return { runKey, runStart: startedAt };
      const seen = store.loadRun(runId).seenAtMs;
      return { runKey, runStart: typeof seen === "number" ? new Date(seen) : null };
    }

    /**
     * The record of a run the plugin started for an answer, when this run of `jobId` is it (passes.runOf); earlier such
     * runs of the job that ended unseen get their outcome line now.
     */
    function startedRun(cfg: PluginConfig, jobId: string, runId: string | undefined): Json | null {
      try {
        const { runKey, startedAt } = runKeyOf(jobId, runId);
        const { mine, gone } = passes.runOf(cfg.stateDir, passes.jobRef(jobId), runKey, startedAt, new Date());
        for (const rec of gone) outcomeNotice(cfg, rec);
        return mine;
      } catch (err) {
        api.logger.warn(`${LOG} could not read the started runs: ${String(err)}`);
        return null;
      }
    }

    function noteRun(cfg: PluginConfig, id: string, what: { passed?: boolean; held?: string }): void {
      safely("started run note", () => passes.note(cfg.stateDir, id, what));
    }

    /**
     * Where a notice about a held call goes: the owner's notify target; with none set, the chat cron job `jobId`
     * delivers to, then the owner's direct message (`hold.fallbackTarget`). `via` names a fallback.
     */
    function noticeRoute(jobId: string | null): { target: hold.Fallback["target"] | null; via: hold.Via | null } {
      const set = store.loadNotify();
      if (set) return { target: set, via: null };
      try {
        const job = jobId ? cronDelivery.readCronJob(ocDir, jobId) : null;
        const found = hold.fallbackTarget(job?.delivery, hostConfig());
        return found ? { target: found.target, via: found.via } : { target: null, via: null };
      } catch (err) {
        api.logger.warn(`${LOG} could not look for a fallback notice target: ${String(err)}`);
        return { target: null, via: null };
      }
    }

    /** A notice's text for `noticeRoute`'s target: a fallback's says where it went and how to set a target. */
    const noticeFor = (text: string, via: hold.Via | null) => (via ? `${text}\n\n${hold.fallbackNote(via)}` : text);
    const queuedTo = (target: hold.Fallback["target"], via: hold.Via | null): Json => ({
      status: "queued",
      target: target.channel,
      ...(via ? { via } : {}),
    });

    /** Tells the owner how a run started for their answer went (passes.outcomeText), and logs it. Never throws. */
    function outcomeNotice(cfg: PluginConfig, rec: Json): void {
      safely("started run outcome", () => {
        const { target, via } = noticeRoute(typeof rec.job_id === "string" ? rec.job_id : null);
        const text = noticeFor(passes.outcomeText(rec, hold.OUTCOMES), via);
        const outbound = outboundOf();
        let notice: Json = { status: "unsent", target: null, reason: hold.NOTIFY_UNSET };
        if (target && outbound?.loadAdapter) {
          notice = queuedTo(target, via);
          hold.track(
            hold.deliver(outbound, hostConfig(), target, text).then((why) => {
              if (why) api.logger.warn(`${LOG} started-run notice not delivered: ${why}`);
            }),
          );
        } else if (target) {
          notice = { status: "unsent", target: null, reason: "this OpenClaw has no outbound adapters for plugins" };
        }
        traffic.write({
          kind: "run_now",
          op: "ended",
          pass_id: rec.id ?? null,
          hold_id: rec.hold_id ?? null,
          job_ref: rec.job_ref ?? null,
          passed: !!rec.passed,
          held: Array.isArray(rec.held) ? rec.held : [],
          notice,
        });
      });
    }

    // The end of a cron run: the owner gets one line listing the run's other held calls (`hold.endOfRun`), and, for a
    // run the plugin started for an owner's allow, one line on how it went. The session no longer serves the run.
    api.on("agent_end", (event: any, ctx: any) =>
      safely("agent_end", () => {
        const runId = event?.runId ?? ctx?.runId;
        const jobId = hold.cronJobId(ctx, store.loadRun(runId));
        if (!jobId) return;
        const cfg = loadConfig().cfg;
        const now = new Date();
        const { runKey, startedAt } = runKeyOf(jobId, runId);
        const rec = passes.runEnd(cfg.stateDir, passes.jobRef(jobId), runKey, startedAt, now);
        if (rec) outcomeNotice(cfg, rec);
        endLines(cfg, passes.jobRef(jobId), runKey, now, jobId);
        safely("job run link", () => {
          const cur = store.jobRunOf(ctx?.sessionKey);
          if (cur?.via === "cron" && cur.run_id === runId) store.setJobRun(ctx.sessionKey, null);
        });
      }),
    );

    /** Sends the run's end line (`hold.endLineText`) for each group the run leads, and logs it. Never throws. */
    function endLines(cfg: PluginConfig, ref: string | null, runKey: string | null, now: Date, jobId: string | null): void {
      safely("run end line", () => {
        const groups = hold.endOfRun(cfg.stateDir, ref, runKey, now);
        if (!groups.length) return;
        const { target, via } = noticeRoute(jobId);
        const outbound = outboundOf();
        for (const [lead, members, canAll] of groups) {
          let notice: Json = { status: "unsent", target: null, reason: hold.NOTIFY_UNSET };
          if (target && outbound?.loadAdapter) {
            notice = queuedTo(target, via);
            sendLine(target, noticeFor(hold.endLineText(lead, members, (v) => `/sentrook-${v}`, canAll), via), "run end line");
          } else if (target) {
            notice = { status: "unsent", target: null, reason: "this OpenClaw has no outbound adapters for plugins" };
          }
          if (notice.status === "unsent") api.logger.warn(`${LOG} run ended with held calls but sent no end line: ${String(notice.reason)}`);
          traffic.write({
            kind: "run_group",
            op: "end_line",
            lead: lead.id ?? null,
            listed: members.map((m) => m.id),
            job_ref: ref,
            notice,
          });
        }
      });
    }

    /** Sends one line to the owner's notify target; a failed delivery is logged. */
    function sendLine(target: hold.Fallback["target"], text: string, what: string): void {
      hold.track(
        hold.deliver(outboundOf(), hostConfig(), target, text).then((why) => {
          if (why) api.logger.warn(`${LOG} ${what} not delivered: ${why}`);
        }),
      );
    }

    function outboundOf(): hold.Outbound | undefined {
      try {
        return api.runtime?.channel?.outbound;
      } catch {
        return undefined; // the runtime throws outside full registration
      }
    }

    /** When this process last sent or found quiet each settings notice. */
    const settingsNoticeAt = new Map<string, number>();

    /**
     * Tells the owner about settings Sentrook cannot read, at a scanned call: once per set of problems, then not
     * again for the quiet period while they stand. The call's outcome never depends on it.
     */
    function settingsNotice(cfg: PluginConfig): void {
      try {
        const key = `settings:${createHash("sha256").update(cfg.configProblems.join("\n")).digest("hex").slice(0, 16)}`;
        // Checked here first, so a call in the quiet period does not wait on the notice file's lock.
        const last = settingsNoticeAt.get(key);
        if (last !== undefined && Date.now() - last < scanFailure.QUIET_MS) return;
        // Unsent (no notify target) is not logged per call: the start-up warning, verify and status already say it.
        const out = quietNotice(cfg, key, () => configProblemsNotice(cfg.configProblems, scanFailure.QUIET_MS / 3600_000), "settings");
        if (out.status === "queued" || out.status === "quiet") settingsNoticeAt.set(key, Date.now());
      } catch (err) {
        api.logger.warn(`${LOG} settings notice failed: ${String(err)}`);
      }
    }

    /**
     * Sends a notice that has a quiet period: none for `key` while it is in one. Returns what the scan record says about
     * it. Never throws: the call's outcome stands whatever happens here.
     */
    function quietNotice(cfg: PluginConfig, key: string | null, text: () => string, what: string): Json {
      const target = store.loadNotify();
      const outbound = outboundOf();
      if (!target) return { status: "unsent", target: null, reason: hold.NOTIFY_UNSET };
      if (!outbound?.loadAdapter) return { status: "unsent", target: null, reason: "this OpenClaw has no outbound adapters for plugins" };
      let stamp: string | null = null;
      try {
        if (key !== null) {
          stamp = scanFailure.claim(cfg.stateDir, key, new Date());
          if (stamp === null) return { status: "quiet" };
        }
      } catch (err) {
        if (!(err instanceof hold.LockTimeoutError)) api.logger.warn(`${LOG} could not read or write notice times: ${String(err)}`);
        return { status: "unsent", target: null, reason: err instanceof hold.LockTimeoutError ? "notice file locked" : "notice file not written" };
      }
      const reopen = () => {
        if (key === null) return;
        try {
          scanFailure.release(cfg.stateDir, key, stamp!);
        } catch (err) {
          api.logger.warn(`${LOG} could not reopen ${what} notices for ${key}: ${String(err)}`);
        }
      };
      let body: string;
      try {
        body = text();
      } catch (err) {
        // A malformed response: the outcome stands, not announced.
        api.logger.warn(`${LOG} could not build a ${what} notice: ${String(err)}`);
        reopen();
        return { status: "unsent", target: null, reason: "notice could not be built" };
      }
      hold.track(
        hold.deliver(outbound, hostConfig(), target, body).then((why) => {
          if (!why) return;
          api.logger.warn(`${LOG} ${what} notice not delivered: ${why}`);
          // Not delivered: the next one with this key is announced instead.
          reopen();
        }),
      );
      return { status: "queued", target: target.channel };
    }

    /**
     * Tells the owner, once for these credentials, that the identity service refuses them because consent was
     * withdrawn. Kept in the state folder, so a restart does not send it again; `openclaw sentrook login` resets it.
     * Returns what the scan record says about the notice. Never throws: the call's outcome stands whatever happens.
     */
    function consentNotice(cfg: PluginConfig, clientId: string): Json {
      const target = store.loadNotify();
      const outbound = outboundOf();
      if (!target) return { status: "unsent", target: null, reason: hold.NOTIFY_UNSET };
      if (!outbound?.loadAdapter) return { status: "unsent", target: null, reason: "this OpenClaw has no outbound adapters for plugins" };
      try {
        if (!consent.claim(cfg.stateDir, clientId, new Date())) return { status: "quiet" };
      } catch (err) {
        if (!(err instanceof hold.LockTimeoutError)) api.logger.warn(`${LOG} could not read or write the consent notice: ${String(err)}`);
        return { status: "unsent", target: null, reason: err instanceof hold.LockTimeoutError ? "notice file locked" : "notice file not written" };
      }
      hold.track(
        hold.deliver(outbound, hostConfig(), target, consent.withdrawnText()).then((why) => {
          if (!why) return;
          api.logger.warn(`${LOG} consent notice not delivered: ${why}`);
          // Not delivered: the next refused scan announces it instead.
          try {
            consent.release(cfg.stateDir, clientId);
          } catch (err) {
            api.logger.warn(`${LOG} could not reopen the consent notice: ${String(err)}`);
          }
        }),
      );
      return { status: "queued", target: target.channel };
    }

    /**
     * Tells the owner a scan failure blocked a call on an unattended run: once per cron job (or session) per quiet
     * period. Returns what the scan record says about the notice. Never throws: the call is blocked whatever happens.
     */
    function scanFailureCall(
      cfg: PluginConfig,
      built: { planir: any },
      failure: ScanFailure,
      tool: string,
      triggerKind: string,
      run: any,
      kind: selfEdit.SelfEditKind | null,
    ): Json {
      const sref: string = built.planir.session.session_ref;
      const { where, jobId } = unattendedRun(sref, triggerKind, run, kind);
      return quietNotice(
        cfg,
        scanFailure.quietKey(jobId, sref),
        () => scanFailure.noticeText(failure, tool, where, jobId !== null, "openclaw sentrook verify"),
        "scan-failure",
      );
    }

    /**
     * Tells the owner what happened to one of OpenClaw's background saves (blocked, let through, kept as a draft, lost
     * as a draft, saved live instead of a draft, held): once per outcome and run (cron job for the collection review)
     * per quiet period. `retry`: a hold of a block-level score, with a quiet period of its own. `action`: the
     * `skill_workshop` action; a patch sent to the drafts has notices and quiet periods of its own. `drafts`: a kept
     * patch draft's place in its run (`bg.patchDraftCount`). Never throws.
     */
    function backgroundNotice(
      cfg: PluginConfig,
      outcome: bg.Announced,
      built: { planir: any },
      resp: any,
      tool: string,
      save: { kind: selfEdit.SelfEditKind; store: selfEdit.SelfEditStore },
      triggerKind: string,
      run: any,
      retry = false,
      action = "",
      drafts: bg.PatchDraftCount | null = null,
    ): Json {
      const sref: string = built.planir.session.session_ref;
      const { where, jobId } = unattendedRun(sref, triggerKind, run, save.kind);
      const rid = cfg.trafficLog.enabled ? built.planir.request_id : null;
      // Kept patch drafts: each one its own key, up to the last one announced, which says more are not.
      const nth = drafts ? Math.min(drafts.run, bg.PATCH_DRAFT_NOTICES) : null;
      const out = quietNotice(
        cfg,
        bg.quietKey(retry ? "held_retry" : outcome, jobId, sref, bg.patchDraftNotice(outcome, tool, action), nth),
        () => bg.noticeText(outcome, resp, tool, save.store, where, rid, jobId !== null, retry, action, drafts, noticeCall(cfg, built)),
        "background-save",
      );
      if (out.status === "unsent") api.logger.warn(`${LOG} background save ${outcome} but sent no notice: ${String(out.reason)}`);
      return out;
    }

    /** The call as a background notice shows it: none when the owner hid calls. */
    function noticeCall(cfg: PluginConfig, built: { planir: any }): string[] {
      if (cfg.hideToolCalls) return [];
      const call = built.planir?.pending_call;
      return history.callLines(call && typeof call === "object" ? call : null, history.NOTICE_CALL_TOTAL, history.NOTICE_CALL_HEADER);
    }

    /**
     * Tells the owner a call of one of OpenClaw's background runs, not a save, was held: once per run (cron job for the
     * collection review) per quiet period. Never throws.
     */
    function heldCallNotice(
      cfg: PluginConfig,
      built: { planir: any },
      resp: any,
      tool: string,
      triggerKind: string,
      run: any,
      kind: selfEdit.SelfEditKind,
    ): Json {
      const sref: string = built.planir.session.session_ref;
      const { where, jobId } = unattendedRun(sref, triggerKind, run, kind);
      const rid = cfg.trafficLog.enabled ? built.planir.request_id : null;
      const out = quietNotice(
        cfg,
        bg.quietKey("held_call", jobId, sref),
        () => bg.heldCallText(resp, tool, where, rid, jobId !== null, noticeCall(cfg, built)),
        "background-call",
      );
      if (out.status === "unsent") api.logger.warn(`${LOG} background run call held but sent no notice: ${String(out.reason)}`);
      return out;
    }

    /**
     * Stores the hold and sends the owner's notice; returns what the scan record says about it. The call is held
     * whatever happens here: a hold that cannot be stored only cannot be answered. A repeat of a waiting hold of the
     * same job and action is counted on it, and no notice is sent; nor for a hold that joins its cron run's group
     * (`hold.create`), which the run's end line lists. `jobRun`: the cron run's own run record, for a sub-agent of it.
     */
    function holdCall(
      cfg: PluginConfig,
      built: { planir: any },
      resp: any,
      tool: string,
      triggerKind: string,
      run: any,
      bound: {
        sid: string;
        jobId: string | null;
        source?: passes.Source | null;
        match: passes.Match;
        acted?: boolean;
        runKey?: string | null;
        /** When the held run started, for closing earlier runs' groups (`hold.staleGroups`); null when not known. */
        runStart?: Date | null;
        acts?: boolean;
        jobRun?: RunContext | null;
      },
    ): Json {
      const now = new Date();
      const sref: string = built.planir.session.session_ref;
      const source = bound.jobId ? null : (bound.source ?? null);
      // a sub-agent's hold names the job as its cron run does (the run's prompt tag gives the name)
      const { where } = bound.jobRun
        ? unattendedRun(sref, "scheduled", bound.jobRun, null, bound.jobId, null, true)
        : unattendedRun(sref, triggerKind, run, null, bound.jobId, source);
      const { target, via } = noticeRoute(bound.jobId);
      const outbound = outboundOf();
      let notice: Json = target ? queuedTo(target, via) : { status: "unsent", target: null, reason: hold.NOTIFY_UNSET };
      if (target && !outbound?.loadAdapter) {
        notice = { status: "unsent", target: null, reason: "this OpenClaw has no outbound adapters for plugins" };
      }
      const hint = grants.ownerSender(built.planir) ? hold.grantHint(resp, cfg.reviewAt) : null;
      const record = (r: Record<string, unknown>) => traffic.write(r);
      const level = passes.offeredLevel(resp);
      const offers = passes.offers(bound.jobId, level, bound.match.named, passes.riskOf(resp), cfg.blockAt, !!bound.acted, source !== null);
      let jobDigest: string | null = null;
      if (bound.jobId) {
        try {
          jobDigest = runNow.jobDigest(ocDir, bound.jobId);
        } catch (err) {
          api.logger.warn(`${LOG} could not read the held call's job: ${String(err)}`);
        }
      }
      let description = "";
      try {
        description = hold.inert(describeCall(resp, tool), 160);
      } catch {
        // a malformed response: no description
      }
      const ref = passes.jobRef(bound.jobId);
      if (ref && target) {
        // an earlier run of the job that ended where the plugin could not see it: its end line goes out first
        try {
          for (const [lead, members, canAll] of hold.staleGroups(cfg.stateDir, ref, bound.runKey ?? null, bound.runStart ?? null, now)) {
            sendLine(target, noticeFor(hold.endLineText(lead, members, (v) => `/sentrook-${v}`, canAll), via), "earlier run's end line");
          }
        } catch (err) {
          // those holds stay listed in status
          api.logger.warn(`${LOG} could not send an earlier run's end line: ${String(err)}`);
        }
      }
      let id: string | null = null;
      let repeat = false;
      let lead: string | undefined;
      try {
        ({ id, repeat, lead } = hold.create(
          cfg.stateDir,
          {
            requestId: built.planir.request_id,
            sessionRef: sref,
            tool,
            where,
            hint,
            notice,
            sid: bound.sid,
            jobId: bound.jobId,
            source,
            match: bound.match,
            level,
            offers,
            description,
            jobDigest,
            acted: !!bound.acted,
            runKey: bound.runKey ?? null,
            acts: !!bound.acts,
          },
          now,
          record,
        ));
        if (id === null) notice = { status: "unsent", target: null, reason: "holds file unreadable" };
      } catch (err) {
        const locked = err instanceof hold.LockTimeoutError;
        if (!locked) api.logger.warn(`${LOG} could not store a hold: ${String(err)}`);
        notice = { status: "unsent", target: null, reason: locked ? "holds file locked" : "holds file not written" };
      }
      if (repeat) {
        notice = { status: "not_sent", target: null, reason: "repeat of a waiting hold" };
      } else if (lead) {
        // one notice per run: this call is listed in the run's end line (`hold.endOfRun`)
        notice = { status: "not_sent", target: null, reason: "in the run's group", lead };
      } else if (id !== null && target && notice.status === "queued") {
        try {
          const scope: hold.Scope = bound.jobId !== null ? "job" : (source?.kind ?? null);
          const text = noticeFor(hold.noticeText(resp, tool, where, id, offers, (v) => `/sentrook-${v}`, scope), via);
          const sent = hold.deliver(outbound, hostConfig(), target, text).then((why) => {
            if (why) api.logger.warn(`${LOG} held-call notice not delivered: ${why}`);
          });
          hold.track(sent);
        } catch (err) {
          // A malformed response: still held, not announced.
          api.logger.warn(`${LOG} held a call but could not build its notice: ${String(err)}`);
          notice = { status: "unsent", target: null, reason: "notice could not be built" };
        }
      } else {
        api.logger.warn(`${LOG} held a call but sent no notice: ${String(notice.reason)}`);
      }
      return {
        id,
        expires_at: id && !repeat ? `${new Date(now.getTime() + hold.HOLD_TTL_MS).toISOString().slice(0, 19)}Z` : null,
        hint: hint !== null,
        offers: id ? offers : [],
        ...(repeat ? { repeat: true } : {}),
        notice,
      };
    }

    const ep = boot.endpoints;
    const show = (e: typeof ep.scan) => (e.ok ? e.url : `INVALID (${e.reason})`);
    api.logger.info(
      `${LOG} ${PLUGIN_VERSION} registered: scan=${show(ep.scan)} issuer=${show(ep.issuer)}` +
        `${ep.dev ? " (dev endpoints)" : ""} mode=${boot.mode} review>=${boot.reviewAt} block>=${boot.blockAt} ` +
        `onScanError=${boot.onScanError} skillReview=${boot.skillReview} ` +
        `traffic=${boot.trafficLog.enabled ? boot.trafficLog.path : "off"}`,
    );
    if (boot.configProblems.length) {
      api.logger.warn(
        `${LOG} settings not read as written (${boot.configProblems.length}): ${configProblemsSummary(boot.configProblems)}. ` +
          "Scanning is on, with each of them ignored or replaced as shown; fix plugins.entries.sentrook.config in " +
          "openclaw.json, then run openclaw sentrook verify",
      );
    }
    // From the environment (a config value is in the list above).
    if (boot.skillReviewUnknown !== null && api.pluginConfig?.skillReview == null) {
      api.logger.warn(`${LOG} skillReview ${JSON.stringify(boot.skillReviewUnknown)} is not allow or review; reading it as allow`);
    }
    if (!ep.scan.ok || !ep.issuer.ok) {
      api.logger.error(`${LOG} endpoint configuration is invalid; ${invalidEndpointEffect(boot.mode, boot.onScanError)}`);
    }
    const unsent = grants.unsentSummary(boot);
    if (unsent) {
      api.logger.warn(
        `${LOG} config grants never sent: ${unsent}. A config grant has no session: drop its scope to apply it in ` +
          "every session, or use /sentrook-grant for one session; see /sentrook-grants",
      );
    }
  },
};

export default plugin;
