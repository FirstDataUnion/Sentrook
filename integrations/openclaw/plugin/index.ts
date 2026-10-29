/**
 * Sentrook for OpenClaw.
 *
 * Scans every tool call before it runs: builds a PlanIR 2.0 request from the hook and the context
 * gathered on other hooks, sends it to Sentrook's /scan over OIDC, and allows, asks the user, or
 * blocks. Every request and response is redacted on the host and appended to a local traffic log.
 */

import { envWithOpenclawDotenv, resolveOidcCredentials } from "./auth.ts";
import { resolveApprovalTiming, type IntentKind } from "./approvalPolicy.ts";
import { OWNER_SUBCOMMANDS, runSentrookCommand } from "./commands.ts";
import { type PluginConfig, resolveConfig } from "./config.ts";
import * as grants from "./grants.ts";
import { blockReason, decide, reviewCopy, severity, tiersOf, type Verdict } from "./decision.ts";
import { buildPlanir, heartbeatEventsOf, hostLabels, PLUGIN_VERSION } from "./planir.ts";
import { capHeadTail, createRedactor } from "./redact.ts";
import { postScan, type ScanOk } from "./scanClient.ts";
import { type ScanFailure, scanErrorToHookResult } from "./scanErrorPolicy.ts";
import { ownerCommand, type OwnerContext, senderRef } from "./owner.ts";
import * as snooze from "./snooze.ts";
import { type HistoryEntry, Store } from "./store.ts";
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
  runtime?: { version?: unknown };
  on: (hook: string, handler: (event: any, ctx: any) => unknown, opts?: { priority?: number }) => void;
  registerCli?: (registrar: (ctx: { program: any }) => void | Promise<void>, opts?: Json) => void;
  registerCommand?: (def: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requiredScopes?: string[];
    handler: (ctx: any) => Promise<{ text?: string }>;
  }) => void;
  registerAgentToolResultMiddleware?: (handler: (event: any, ctx: any) => unknown, opts?: Json) => void;
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
}

/** Discovery tools have no side effects; the call they lead to is scanned on its own. */
const UNSCANNED_TOOLS = new Set(["tool_search", "tool_describe"]);

/** History decisions after which the tool did not run. */
const NOT_RUN = new Set(["blocked", "denied_by_user", "review_timed_out", "blocked_on_error"]);

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
    if (api.registerCli && (mode === "cli-metadata" || mode === "discovery" || mode === "full")) {
      api.registerCli(
        async ({ program }) => {
          const { registerSentrookCli } = await import("./cli.ts");
          registerSentrookCli(program, () => api.pluginConfig ?? {});
        },
        { descriptors: [{ name: "sentrook", description: "Sentrook plugin helpers (verify, status)", hasSubcommands: true }] },
      );
      if (mode === "cli-metadata") return;
    }

    // `/sentrook <subcommand>` in chat; the host answers it without a model request.
    try {
      api.registerCommand?.({
        name: "sentrook",
        description: "Sentrook plugin status and help",
        acceptsArgs: true,
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
    // The runtime is a proxy that throws outside full registration.
    let hostVersion: string | undefined;
    try {
      const v = api.runtime?.version;
      if (typeof v === "string" && v) hostVersion = v;
    } catch {
      hostVersion = undefined;
    }
    const store = new Store(boot.stateDir);
    const traffic = new TrafficLog(boot.trafficLog.path, boot.trafficLog.maxBytes, boot.trafficLog.enabled, (m) =>
      api.logger.warn(`${LOG} ${m}`),
    );
    // `/sentrook-history`, `/sentrook-why`, the grants commands and `/sentrook-snooze`: owner only,
    // audited in the traffic log.
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
                  },
                  (ctx.args ?? "").trim(),
                ),
              }),
            },
            { traffic, salt: () => store.salt() },
          ),
          acceptsArgs: true,
        });
      } catch (err) {
        api.logger.warn(`${LOG} /${sub.command} command unavailable: ${String(err)}`);
      }
    }
    // Full tool results from the result middleware, keyed by host call id (after_tool_call is capped).
    const fullResults = new Map<string, string>();

    const remember = (runId: string | undefined, ctx: any, patch: Json) => {
      store.mergeRun(runId, {
        trigger: ctx?.trigger,
        channel: ctx?.channel ?? ctx?.channelId,
        messageProvider: ctx?.messageProvider,
        senderId: ctx?.senderId,
        workspaceDir: ctx?.workspaceDir,
        inputProvenance: ctx?.inputProvenance,
        ...patch,
      });
    };

    const safely = (name: string, fn: () => void) => {
      try {
        fn();
      } catch (err) {
        api.logger.warn(`${LOG} ${name} failed: ${String(err)}`);
      }
    };

    // ---- context joins -------------------------------------------------------------------------
    api.on("before_prompt_build", (event: any, ctx: any) =>
      safely("before_prompt_build", () =>
        remember(event?.runId ?? ctx?.runId, ctx, {
          currentUserMessage: event?.currentUserMessage,
          prompt: event?.prompt,
        }),
      ),
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
      try {
        const hostId: string | undefined = event?.toolCallId ?? ctx?.toolCallId;
        if (!hostId || UNSCANNED_TOOLS.has(event?.toolName)) return;
        const { cfg } = loadConfig();
        const sid = sessionIdOf(ctx);
        await store.withSession(sid, () => {
          const sess = store.loadSession(sid);
          const entry = [...sess.history].reverse().find((h) => h._host_call_id === hostId || h.call_id === hostId);
          if (!entry) return;
          const text = fullResults.get(hostId) ?? resultText(event?.result ?? event?.error);
          fullResults.delete(hostId);
          const sizeBytes = Buffer.byteLength(text, "utf8");
          const ran = !(NOT_RUN.has(entry.decision) && event?.error);
          entry.result = { status: event?.error || !ran ? "error" : "ok", size_bytes: ran ? sizeBytes : 0 };
          if (ran) {
            const redactor = createRedactor("standard", store.salt());
            const capped = capHeadTail(redactor.string(text), cfg.inputCapBytes);
            sess.inputSeq += 1;
            sess.buffer.push({
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
        if (UNSCANNED_TOOLS.has(event?.toolName)) return undefined;
        try {
          const { cfg, env } = loadConfig();
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

    async function scanOne(
      cfg: PluginConfig,
      env: NodeJS.ProcessEnv,
      sid: string,
      event: any,
      ctx: any,
    ): Promise<BeforeToolCallResult | undefined> {
      const sess = store.loadSession(sid);
      const run = store.loadRun(event?.runId ?? ctx?.runId);
      const redactor = createRedactor("standard", store.salt());
      const built = buildPlanir({
        hostConfig: api.config,
        cfg,
        redactor,
        event,
        ctx,
        sid,
        sess,
        run,
        assistant: store.loadAssistant(ctx?.sessionKey),
        parents: store.parents(),
        grants: grants.effective(cfg, store.loadGrants(), new Date()),
        hostVersion,
      });
      const body = JSON.stringify(built.planir);
      const triggerKind: string = built.planir.trigger.kind;
      const timing = resolveApprovalTiming(cfg.approval, intentKindOf(triggerKind), undefined);

      let result: ScanOk | ScanFailure;
      const { scan, issuer } = cfg.endpoints;
      if (!scan.ok) result = { ok: false, kind: "config", detail: `scan URL: ${scan.reason}` };
      else if (!issuer.ok) result = { ok: false, kind: "config", detail: `OIDC issuer: ${issuer.reason}` };
      else {
        result = await postScan({
          scanUrl: scan.url,
          oidc: resolveOidcCredentials(api.pluginConfig ?? {}, env, issuer.url),
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
      if (result.ok) {
        const resp = result.response;
        verdict = decide(resp, cfg);
        sess.token = resp.state ?? null;
        sess.buffer = [];
        entry.action_fingerprint = resp.action_fingerprint ?? null;
        entry.risk = resp.risk;
        entry.tiers = tiersOf(resp);
        if (cfg.mode === "observe" || verdict === "allow") {
          entry.decision = "allowed";
        } else if (verdict === "block") {
          entry.decision = "blocked";
          hook = { block: true, blockReason: blockReason(resp, event.toolName) };
        } else if (
          // Only a human's message: a run whose trigger is unknown or not a message is never snoozed,
          // whatever the approval timeout policy calls attended.
          triggerKind === "message" &&
          !timing.unattended &&
          snooze.applies(resp) &&
          snooze.active(store.loadSnooze(), built.planir.session.session_ref, new Date())
        ) {
          // The owner snoozed reviews for this session: scanned and logged, not asked.
          entry.decision = "allowed";
          snoozed = true;
        } else {
          // Provisional until the user answers.
          entry.decision = "review_timed_out";
          const copy = reviewCopy(resp, event.toolName);
          hook = {
            requireApproval: {
              ...copy,
              severity: severity(resp),
              timeoutMs: timing.timeoutMs,
              timeoutBehavior: timing.timeoutBehavior,
              allowedDecisions: ["allow-once", "deny"],
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
                unattended: timing.unattended,
                interactiveTimeoutMs: cfg.approval.interactiveTimeoutMs,
              });
        entry.decision = hook?.block || hook?.requireApproval ? "blocked_on_error" : "allowed_on_error";
        api.logger.warn(`${LOG} scan failed (${result.kind}): ${result.detail}`);
      }

      sess.history.push(entry);
      store.saveSession(sid, sess, cfg.historyLimit * 2);

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
        latency_ms: result.ok ? result.latencyMs : null,
        host_labels: hostLabels(run, ctx),
        planir: built.planir,
        response: result.ok ? result.response : null,
        failure: result.ok ? null : { kind: result.kind, status: result.status ?? null, detail: result.detail },
      });
      api.logger.info(
        `${LOG} scan step=${built.step} tool=${event.toolName} ` +
          (result.ok
            ? `risk=${result.response.risk} enforced=${result.response.enforced} status=${result.response.status} verdict=${verdict}${snoozed ? " (snoozed)" : ""} mode=${cfg.mode}`
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
          traffic.write({ kind: "resolution", request_id: requestId, resolution: decision, decision: final });
        };
      }
      return hook;
    }

    const ep = boot.endpoints;
    const show = (e: typeof ep.scan) => (e.ok ? e.url : `INVALID (${e.reason})`);
    api.logger.info(
      `${LOG} ${PLUGIN_VERSION} registered: scan=${show(ep.scan)} issuer=${show(ep.issuer)}` +
        `${ep.dev ? " (dev endpoints)" : ""} mode=${boot.mode} review>=${boot.reviewAt} block>=${boot.blockAt} ` +
        `onScanError=${boot.onScanError} traffic=${boot.trafficLog.enabled ? boot.trafficLog.path : "off"}`,
    );
    if (!ep.scan.ok || !ep.issuer.ok) {
      api.logger.error(`${LOG} endpoint configuration is invalid; every tool call will fail closed until fixed`);
    }
  },
};

export default plugin;
