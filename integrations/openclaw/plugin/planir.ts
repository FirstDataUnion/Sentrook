/**
 * PlanIR 2.0 assembly from OpenClaw hook data.
 *
 * The plugin reports facts; Sentrook classifies trust. Hook data that OpenClaw only exposes on
 * other hooks is joined in: run context by `runId`, the assistant message (narration and the
 * batch's sibling calls) by `sessionKey`, the subagent parent by the spawn hooks.
 */

import { createHash, randomUUID } from "node:crypto";
import { homedir, platform as osPlatform } from "node:os";

import type { GrantConfig, PluginConfig } from "./config.ts";
import { capArgs, type Redactor } from "./redact.ts";
import type { BufferedInput, HistoryEntry, Provider, RunContext, Session } from "./store.ts";

export const PLUGIN_VERSION = "2.0.0-beta.1";

const TOOL_KIND: Record<string, string> = {
  exec: "exec",
  process: "exec",
  bash: "exec",
  code_mode_exec: "exec",
  read: "file_read",
  write: "file_write",
  edit: "file_edit",
  apply_patch: "file_edit",
  web_fetch: "web_fetch",
  web_search: "web_fetch",
  browser: "browser",
  message: "message_send",
  sessions_send: "message_send",
  sessions_spawn: "subagent_spawn",
  memory_write: "memory_write",
};

export function toolKind(name: string): string {
  if (TOOL_KIND[name]) return TOOL_KIND[name]!;
  if (name.includes("__")) return "mcp";
  return "other";
}

const hash12 = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 12);

function normaliseTransport(t: unknown): string | null {
  if (typeof t !== "string" || !t) return null;
  const v = t.toLowerCase();
  if (v === "streamable-http" || v === "http" || v === "https") return "http";
  if (v === "sse" || v === "stdio") return v;
  return null;
}

/** MCP tools are named `<server>__<tool>`; identity comes from the server's config entry. */
export function providerFor(config: any, name: string): Provider {
  if (!name.includes("__")) return { kind: "host", name: null, identity: null, transport: null };
  const server = name.split("__")[0]!;
  const cfg = config?.mcp?.servers?.[server];
  if (!cfg) return { kind: "mcp", name: server, identity: null, transport: null };
  let identity: string | null = null;
  const transport = normaliseTransport(cfg.transport) ?? (cfg.url ? "http" : cfg.command ? "stdio" : null);
  if (typeof cfg.url === "string") {
    try {
      identity = `remote:${new URL(cfg.url).host}`;
    } catch {
      identity = null;
    }
  } else if (typeof cfg.command === "string") {
    const args: string[] = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
    const pkg = args.find((a) => !a.startsWith("-"));
    if (["npx", "pnpm", "bunx"].includes(cfg.command) && pkg) identity = `npm:${pkg}`;
    else if (["uvx", "pipx"].includes(cfg.command) && pkg) identity = `pypi:${pkg}`;
    else identity = `local:${hash12([cfg.command, ...args].join(" "))}`;
  }
  return { kind: "mcp", name: server, identity, transport };
}

/**
 * A turn of OpenClaw's built-in system agent (the Control UI's setup and repair assistant): run with
 * trigger `manual` on message provider `openclaw`. OpenClaw serves that chat only to an `operator.admin`
 * client, the same test it uses to flag a chat sender as the owner, so the operator typed this turn.
 */
export function isSystemAgentTurn(run: RunContext): boolean {
  return run.trigger === "manual" && run.messageProvider === "openclaw";
}

/** Host-authored marker lines OpenClaw prefixes to a system agent turn (not the operator's words). */
const SYSTEM_AGENT_MARKERS = /^(?:\[(?:ui-context|proposal-resolved)\][^\n]*\n)+/;

export function requestTextOf(run: RunContext): string {
  const text = String(run.currentUserMessage ?? run.prompt ?? "");
  return isSystemAgentTurn(run) ? text.replace(SYSTEM_AGENT_MARKERS, "") : text;
}

/** The raw host labels the trigger and sender were derived from, for the local traffic log only. */
export function hostLabels(run: RunContext, ctx: any): Record<string, unknown> {
  const requester = ctx?.requester;
  return {
    trigger: run.trigger ?? null,
    channel: run.channel ?? null,
    message_provider: run.messageProvider ?? null,
    sender_is_owner: run.senderIsOwner ?? null,
    agent_id: ctx?.agentId ?? null,
    requester: requester
      ? {
          channel: requester.channel ?? null,
          sender_is_owner: requester.senderIsOwner ?? null,
          has_sender_id: requester.senderId != null,
        }
      : null,
  };
}

export function triggerKind(run: RunContext): string {
  if (run.inputProvenance?.sourceRole === "subagent") return "subagent";
  if (isSystemAgentTurn(run)) return "message";
  switch (run.trigger) {
    case "user":
      return "message";
    case "cron":
      return "scheduled";
    case "heartbeat":
      return "heartbeat";
    case undefined:
    case null:
      return "unknown";
    default:
      return "system";
  }
}

const CHANNELS = new Set(["discord", "telegram", "slack", "email", "webhook"]);
function channelOf(v: unknown): string | null {
  if (typeof v !== "string" || !v) return null;
  const c = v.toLowerCase();
  if (CHANNELS.has(c)) return c;
  if (["webchat", "chat", "cli", "control-ui"].includes(c)) return "chat";
  return "other";
}

export function senderOf(
  requester: any,
  run: RunContext,
  cfg: Pick<PluginConfig, "trustedSenders" | "trustedRoles">,
): { relation: string; basis: string[] } {
  if (
    requester?.senderIsOwner === true ||
    (!requester && run.senderIsOwner === true) ||
    isSystemAgentTurn(run)
  ) {
    return { relation: "owner", basis: ["host_owner_flag"] };
  }
  const senderId = requester?.senderId ?? run.senderId;
  if (senderId && cfg.trustedSenders.includes(String(senderId))) {
    return { relation: "trusted", basis: ["plugin_allowlist:sender"] };
  }
  const roles: string[] = Array.isArray(requester?.roleIds) ? requester.roleIds.map(String) : [];
  if (roles.some((r) => cfg.trustedRoles.includes(r))) {
    return { relation: "trusted", basis: ["plugin_allowlist:role"] };
  }
  if (requester) return { relation: "other", basis: ["none"] };
  return { relation: "unknown", basis: ["none"] };
}

export function execPolicy(config: any): { exec_mode: string; approval_gating: boolean } {
  const exec = config?.tools?.exec ?? {};
  const mode = exec.mode ?? exec.security;
  if (mode === "full" || mode === "auto") return { exec_mode: "full", approval_gating: false };
  if (mode === "allowlist") return { exec_mode: "allowlist", approval_gating: true };
  if (mode === "ask") return { exec_mode: "unknown", approval_gating: true };
  return { exec_mode: "unknown", approval_gating: false };
}

/** Only grants plausibly relevant to this call: the pattern (minus globs) appears in its arguments. */
export function relevantGrants(grants: GrantConfig[], argsText: string): Array<Record<string, unknown>> {
  const text = argsText.toLowerCase();
  const out: Array<Record<string, unknown>> = [];
  grants.forEach((g, i) => {
    const needle = g.pattern.toLowerCase().replace(/^\*\.?/, "").replace(/\*+/g, "");
    if (needle.length < 3 || !text.includes(needle)) return;
    out.push({
      grant_ref: `g_${i + 1}`,
      kind: g.kind,
      pattern: g.pattern,
      ...(g.allows ? { allows: g.allows } : {}),
      scope: g.scope ?? "persistent",
      ...(g.granted_at ? { granted_at: g.granted_at } : {}),
    });
  });
  return out;
}

export interface BuildInput {
  hostConfig: any;
  cfg: PluginConfig;
  redactor: Redactor;
  event: { toolName: string; params?: Record<string, unknown>; toolCallId?: string; runId?: string };
  ctx: { sessionKey?: string; sessionId?: string; agentId?: string; runId?: string; requester?: any; toolCallId?: string };
  sid: string;
  sess: Session;
  run: RunContext;
  assistant: any;
  parents: Record<string, string>;
  /** OpenClaw's version, from the plugin runtime. */
  hostVersion?: string;
}

export interface Built {
  planir: Record<string, any>;
  callId: string;
  hostCallId: string | undefined;
  step: number;
  turn: number;
  toolKind: string;
  provider: Provider;
  /** Redacted, capped arguments as recorded in history. */
  historyArgs: Record<string, unknown>;
  /** The buffered inputs this request carries (cleared from the buffer on success). */
  sentInputs: BufferedInput[];
}

/** Mutates `sess` (step, runs, seen call ids); the caller saves it. */
export function buildPlanir(b: BuildInput): Built {
  const { cfg, redactor, event, ctx, sess, run } = b;
  const runId = event.runId ?? ctx.runId;
  const hostCallId = event.toolCallId ?? ctx.toolCallId;
  let callId = hostCallId ?? `${runId ?? "run"}:${sess.nextStep}`;
  // Host ids are not reliable (some providers reuse per-response indexes like `call_0`).
  if (hostCallId && sess.seenCallIds.includes(hostCallId)) callId = `${runId ?? "run"}:${hostCallId}`;
  if (hostCallId) sess.seenCallIds.push(hostCallId);
  if (runId && !sess.runs.includes(runId)) sess.runs.push(runId);
  const turn = Math.max(1, sess.runs.length);
  const step = sess.nextStep;
  sess.nextStep += 1;

  const sessionKey = ctx.sessionKey;
  const isSub = !!sessionKey && /(^|:)subagent:/.test(sessionKey);
  const parent = isSub ? b.parents[sessionKey!] : undefined;
  const assistant = b.assistant;
  const inBatch = !!assistant?.calls?.some((c: any) => c.id === hostCallId);
  const narration: string | undefined = (inBatch && assistant.text) || run.lastAssistantText || undefined;
  const tk = toolKind(event.toolName);
  const provider = providerFor(b.hostConfig, event.toolName);
  const args = redactor.value(event.params ?? {});
  const siblings = inBatch
    ? assistant.calls
        .filter((c: any) => c.id !== hostCallId)
        .map((c: any) => ({
          call_id: c.id,
          tool: c.name ?? "unknown",
          tool_kind: toolKind(c.name ?? ""),
          provider: providerFor(b.hostConfig, c.name ?? ""),
          arguments: capArgs(redactor.value(c.arguments ?? {}), cfg.historyArgsCapBytes),
        }))
    : [];

  const window = sess.history.slice(-cfg.historyLimit);
  const windowIds = new Set(window.map((h) => h.call_id));
  // Every tool result must refer to a call in the history window (a scanner invariant).
  const sentInputs = sess.buffer.filter((i) => windowIds.has(i.call_id));
  const history = window.map(({ _host_call_id: _drop, ...h }) => h as Omit<HistoryEntry, "_host_call_id">);

  const requestText = requestTextOf(run);
  const { exec_mode, approval_gating } = execPolicy(b.hostConfig);
  const os = osPlatform() === "darwin" ? "macos" : osPlatform() === "win32" ? "windows" : "linux";

  const planir = {
    planir_version: "2.0",
    request_id: randomUUID(),
    run_ref: runId ? `r_${hash12(runId)}` : `r_${hash12(b.sid)}`,
    sent_at: new Date().toISOString(),
    scan_kind: "pending_call",
    origin: "live",
    host: {
      platform: "openclaw",
      platform_version: b.hostVersion ?? process.env.OPENCLAW_VERSION ?? "unknown",
      plugin_version: PLUGIN_VERSION,
      workspace_root: run.workspaceDir ?? "",
      home: homedir(),
      os,
      policy: { exec_mode, approval_gating, result_masking: true },
    },
    session: {
      session_ref: `s_${hash12(b.sid)}`,
      routing_key: sessionKey ? `h_${hash12(sessionKey)}` : null,
      agent_ref: `a_${ctx.agentId ?? "main"}`,
      agent_role: isSub ? "subagent" : "main",
      parent_session_ref: parent ? `h_${hash12(parent)}` : null,
      turn,
      step,
      state: sess.token,
    },
    trigger: {
      kind: triggerKind(run),
      channel: isSystemAgentTurn(run)
        ? "chat"
        : (channelOf(ctx.requester?.channel) ?? channelOf(run.channel) ?? channelOf(run.messageProvider)),
      sender: senderOf(ctx.requester, run, cfg),
    },
    request: { text: redactor.string(String(requestText)), carried_from_turn: null },
    new_inputs: sentInputs,
    history,
    pending_call: {
      call_id: callId,
      ...(hostCallId ? { host_call_id: hostCallId } : {}),
      tool: event.toolName,
      tool_kind: tk,
      provider,
      host_approval: "unknown",
      ...(narration ? { agent_narration: redactor.string(String(narration)).slice(0, 4000) } : {}),
      arguments: capArgs(args, cfg.inputCapBytes),
      batch: { siblings },
    },
    grants: relevantGrants(cfg.grants, JSON.stringify(event.params ?? {})),
    options: { packs: cfg.packs, redaction: redactor.level },
  };

  return {
    planir,
    callId,
    hostCallId,
    step,
    turn,
    toolKind: tk,
    provider,
    historyArgs: capArgs(args, cfg.historyArgsCapBytes),
    sentInputs,
  };
}
