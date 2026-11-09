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
import { hostRequestText, TRIGGER as SELF_EDIT_TRIGGER } from "./selfEdit.ts";
import type { BufferedInput, HistoryEntry, Provider, RunContext, Session } from "./store.ts";

export const PLUGIN_VERSION = "2.0.0-beta.7";

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

/** Tool search's dispatcher: `{id, args}` runs the named tool, which fires its own tool hooks. */
export const TOOL_CALL = "tool_call";

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** A wrapper's id as OpenClaw writes it into the id of the call it dispatches. */
const dispatchIdPart = (id: string) => id.trim().replace(/[^A-Za-z0-9_.:-]+/g, "_").slice(0, 120) || "call";

/**
 * The wrapper's id part of a dispatched call's id, `tool_call:<wrapper id>:<tool>:<n>`. Tool names hold no `:`, so
 * the last two fields are the tool and the count, and the wrapper id may itself hold `:`.
 */
const dispatcherOf = (hostCallId: string | undefined) =>
  hostCallId ? /^tool_call:(.+):[^:]+:\d+$/.exec(hostCallId)?.[1] : undefined;

/** Tool search names a tool by its name or its catalog id, `<source>:<source name>:<tool name>`. */
const CATALOG_ID = /^(?:openclaw|mcp|client):[^:]*:(.+)$/;
const SELECTORS = ["id", "toolId", "name"];
const isDotted = (k: string) => k.startsWith("args.") && k.length > 5;

/**
 * The call a `tool_call` wrapper names, read as OpenClaw reads it: the tool from `id`, `toolId` or `name`; the
 * arguments from `args` (or `input`), else the wrapper's other fields; `args.<key>` fields join either.
 */
export function unwrapToolCall(params: unknown): { tool: string; arguments: Record<string, unknown> } | null {
  if (!isRecord(params)) return null;
  const key = SELECTORS.find((k) => params[k] != null);
  // OpenClaw also takes a selector given inside the arguments (`{args: {id, ...}}`).
  const inside = params.args;
  if (!key) return isRecord(inside) && SELECTORS.some((k) => inside[k] != null) ? unwrapToolCall(inside) : null;
  if (typeof params[key] !== "string" || !(params[key] as string).trim()) return null;
  const selector = (params[key] as string).trim();
  const dotted = Object.fromEntries(Object.entries(params).filter(([k]) => isDotted(k)).map(([k, v]) => [k.slice(5), v]));
  const nested = params.args ?? params.input;
  let args: Record<string, unknown>;
  if (nested != null && !(isRecord(nested) && !Object.keys(nested).length)) {
    args = isRecord(nested) ? { ...dotted, ...nested } : { value: nested };
  } else {
    const rest = Object.entries(params).filter(([k]) => k !== key && k !== "args" && k !== "input" && !isDotted(k));
    args = { ...dotted, ...Object.fromEntries(rest) };
  }
  return { tool: CATALOG_ID.exec(selector)?.[1] ?? selector, arguments: args };
}

export const hash12 =(s: string) => createHash("sha256").update(s).digest("hex").slice(0, 12);

/** A session's `session_ref`: what a scan of it sends, and what snoozes and session grants are bound to. */
export const sessionRef = (sid: string) => `s_${hash12(sid)}`;

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

/**
 * The queued system events of a heartbeat run. OpenClaw sends the generic heartbeat prompt as the turn's prompt
 * and the events beside it, in a runtime-context message that closes the message list (`before_agent_run`), with
 * the events as `conversation-data` fragments of `System: [time] text` lines. The events are what the heartbeat is
 * about, so they go into the request text as those plain lines; fragments of any other kind are left out. A
 * carrier that is not the last message belongs to an earlier turn.
 */
export function heartbeatEventsOf(messages: unknown): string | undefined {
  if (!Array.isArray(messages) || !messages.length) return undefined;
  const last = messages[messages.length - 1];
  if (last?.role !== "custom" || last?.customType !== "openclaw.runtime-context") return undefined;
  const fragments: unknown[] = Array.isArray(last.details?.fragments) ? last.details.fragments : [];
  const text = fragments
    .map((f: any) => (f?.kind === "conversation-data" && typeof f?.text === "string" ? f.text.trim() : ""))
    .filter(Boolean)
    .join("\n");
  return text || undefined;
}

export function requestTextOf(run: RunContext): string {
  const text = String(run.currentUserMessage ?? run.prompt ?? "");
  if (isSystemAgentTurn(run)) return text.replace(SYSTEM_AGENT_MARKERS, "");
  if (run.trigger === "heartbeat" && run.heartbeatEvents) return [text, run.heartbeatEvents].filter(Boolean).join("\n\n");
  return text;
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

/**
 * The pattern's pieces between `*`s appear in `text`, in order (a leading `*.` also matches the apex, a trailing `/`
 * the folder or scope itself).
 */
function piecesIn(pattern: string, text: string): boolean {
  pattern = pattern.replace(/\/+$/, "");
  const pieces = (pattern.startsWith("*.") ? pattern.slice(2) : pattern).split("*").filter(Boolean);
  if (pieces.reduce((n, p) => n + p.length, 0) < 3) return false;
  let at = 0;
  for (const p of pieces) {
    at = text.indexOf(p, at);
    if (at < 0) return false;
    at += p.length;
  }
  return true;
}

/** The arguments the scanner reads a command's working directory from, in its order. */
const CWD_KEYS = ["cwd", "dir", "working_directory", "workdir"];
/** A path that starts with `./`, where the scanner finds one (also after a JSON-escaped newline or tab). */
const DOT_PATH = /(?:(?<![\p{L}\p{N}_.:-])|(?<=\\[ntr]))\.\//gu;

/** The working directory a command names for itself, if any. The scanner reads it for exec calls only. */
export function callCwd(args: unknown): string | null {
  if (!args || typeof args !== "object") return null;
  for (const k of CWD_KEYS) {
    const v = (args as Record<string, unknown>)[k];
    if (typeof v === "string" && v) return v;
  }
  return null;
}

/**
 * Only grants that could cover this call. The scanner decides what a grant covers; this only keeps the owner's
 * other grants out of the request, so it errs towards sending. A provider grant is also matched against the
 * call's provider identity. Paths are read the way the scanner resolves them: under home in any form (`~/…`,
 * `$HOME/…` or full), and `./…` against the command's `cwd`, else the workspace.
 */
export function relevantGrants(
  grants: GrantConfig[],
  argsText: string,
  opts: { identity?: string | null; home?: string; workspace?: string | null; cwd?: string | null } = {},
): Array<Record<string, unknown>> {
  const text = argsText.toLowerCase();
  let texts = [text];
  const base = opts.cwd || opts.workspace;
  if (base) texts.push(text.replace(DOT_PATH, () => `${base.replace(/\/+$/, "").toLowerCase()}/`));
  let pats = grants.map((g) => g.pattern.toLowerCase());
  if (opts.home) {
    const root = opts.home.replace(/\/+$/, "").toLowerCase();
    texts = texts.map((t) => t.replaceAll("~/", `${root}/`).replaceAll("$home/", `${root}/`));
    pats = pats.map((p) => (p.startsWith("~/") ? root + p.slice(1) : p));
  }
  const out: Array<Record<string, unknown>> = [];
  grants.forEach((g, i) => {
    const hay = [...texts];
    if (g.kind === "provider" && opts.identity) hay.push(opts.identity.toLowerCase());
    if (!hay.some((h) => piecesIn(pats[i]!, h))) return;
    out.push({
      grant_ref: `g_${i + 1}`,
      kind: g.kind,
      pattern: g.pattern,
      ...(g.allows ? { allows: g.allows } : {}),
      scope: g.scope ?? "persistent",
      ...(g.granted_at ? { granted_at: g.granted_at } : {}),
      ...(g.session_ref ? { session_ref: g.session_ref } : {}),
      ...(g.expires_at ? { expires_at: g.expires_at } : {}),
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
  /**
   * Every grant in force (`grants.effective`); the persistent config grants alone when not given (a
   * config grant has no session, so a session one is never sent).
   */
  grants?: GrantConfig[];
  /** A call of OpenClaw's own background process (`selfEdit.ts`): sent with trigger `system`, not the run's own. */
  hostProcess?: boolean;
  /** A self-edit's `self_edit` block (`conversation.block`); sent only with `hostProcess`. */
  selfEdit?: Record<string, unknown> | null;
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
  const calls: any[] = Array.isArray(assistant?.calls) ? assistant.calls : [];
  // A call a `tool_call` wrapper dispatched is in the message through its wrapper, which is not its sibling.
  const outer = dispatcherOf(hostCallId);
  const wrapper =
    outer === undefined
      ? undefined
      : calls.find((c) => c.name === TOOL_CALL && typeof c.id === "string" && dispatchIdPart(c.id) === outer);
  const inBatch = !!wrapper || calls.some((c) => c.id === hostCallId);
  const narration: string | undefined = (inBatch && assistant.text) || run.lastAssistantText || undefined;
  const tk = toolKind(event.toolName);
  const provider = providerFor(b.hostConfig, event.toolName);
  const args = redactor.value(event.params ?? {});
  const siblings = inBatch
    ? calls
        .filter((c) => c.id !== hostCallId && c !== wrapper)
        .map((c) => {
          // A sibling wrapper is shown as the call it dispatches.
          const inner = c.name === TOOL_CALL ? unwrapToolCall(c.arguments) : null;
          const name: string = inner?.tool ?? c.name ?? "unknown";
          return {
            call_id: c.id,
            tool: name,
            tool_kind: toolKind(name),
            provider: providerFor(b.hostConfig, name),
            arguments: capArgs(redactor.value(inner?.arguments ?? c.arguments ?? {}), cfg.historyArgsCapBytes),
          };
        })
    : [];

  const window = sess.history.slice(-cfg.historyLimit);
  const windowIds = new Set(window.map((h) => h.call_id));
  // Every tool result must refer to a call in the history window (a scanner invariant).
  const sentInputs = sess.buffer.filter((i) => windowIds.has(i.call_id));
  const history = window.map(({ _host_call_id: _drop, ...h }) => h as Omit<HistoryEntry, "_host_call_id">);

  const requestText = b.hostProcess ? hostRequestText(run) : requestTextOf(run);
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
      session_ref: sessionRef(b.sid),
      routing_key: sessionKey ? `h_${hash12(sessionKey)}` : null,
      agent_ref: `a_${ctx.agentId ?? "main"}`,
      agent_role: isSub ? "subagent" : "main",
      parent_session_ref: parent ? `h_${hash12(parent)}` : null,
      turn,
      step,
      state: sess.token,
    },
    trigger: b.hostProcess
      ? structuredClone(SELF_EDIT_TRIGGER)
      : {
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
    grants: relevantGrants(b.grants ?? cfg.grants.filter((g) => g.scope === "persistent"), JSON.stringify(event.params ?? {}), {
      identity: provider.identity,
      home: homedir(),
      workspace: run.workspaceDir,
      cwd: tk === "exec" ? callCwd(event.params) : null,
    }),
    options: { packs: cfg.packs, redaction: redactor.level },
    ...(b.hostProcess && b.selfEdit ? { self_edit: b.selfEdit } : {}),
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
