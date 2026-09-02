/**
 * ``/sentrook`` chat command family (OpenClaw ``api.registerCommand``).
 *
 * Owner-only. Returns ``{ text }`` for the originating channel. Lists stay
 * short; ``pending <id>`` / ``history <id>`` post the full scrubbed command
 * (no AIRA ids, no tool results).
 */

import {
  formatAllowlistList,
  resolveAllowlistCliPath,
} from "./allowlistCli.ts";
import { loadAllowlist, saveAllowlist, type AllowlistConfig } from "./localAllowlist.ts";
import { unlinkSync } from "node:fs";

import {
  DEFAULT_MAX_AGE_DAYS,
  DEFAULT_MAX_BYTES,
  getOperatorLogEvent,
  operatorLogStats,
  purgeOperatorLog,
  queryOperatorLog,
  scrubOperatorArgs,
  type OperatorLogConfig,
  type OperatorLogEvent,
} from "./operatorLog.ts";
import {
  DEFAULT_HISTORY_LIMIT,
  formatDuration,
  parseOnOff,
  parseQuietDuration,
  parseSensitivity,
  quietRemainingMs,
  type Sensitivity,
  type SessionPolicyFlags,
} from "./sessionPolicy.ts";
import { sessionIdsOf, type SessionIds } from "./sessionStore.ts";

export const SENTROOK_COMMAND_NAME = "sentrook";
export const CHANNEL_DISCLOSURE =
  "These replies are ordinary channel messages. In a public Discord/Telegram " +
  "server anyone in the room can read the command (secrets are scrubbed, not " +
  "a guarantee). Prefer a DM, a private channel, or the dashboard.";

export type SlashPendingCall = {
  tool: string;
  args: Record<string, unknown>;
  awaitingApproval?: boolean;
  eventId?: string;
};

export type SlashSession = SessionPolicyFlags & {
  pending: Map<string, SlashPendingCall>;
};

export type SlashCommandContext = {
  args?: string;
  sessionId?: string;
  sessionKey?: string;
  senderIsOwner?: boolean;
  isAuthorizedSender?: boolean;
  channel?: string;
  agentId?: string;
};

export type SlashDeps = {
  sessionOf: (ids: SessionIds) => SlashSession;
  sensitivity: () => Sensitivity;
  setSensitivity: (value: Sensitivity) => { persisted: boolean; error?: string };
  operatorLog: () => OperatorLogConfig;
  setOperatorLogRetention: (patch: {
    maxAgeDays?: number;
    maxBytes?: number;
  }) => { persisted: boolean; error?: string };
  allowlist: AllowlistConfig;
  now: () => number;
};

export type SlashReply = { text: string };

const HELP_TEXT = [
  "Sentrook session controls (owner-only).",
  "",
  "/sentrook help",
  "/sentrook status",
  "/sentrook pending [id]     list short; <id> = full scrubbed command",
  "/sentrook history [n|id|all]  default = review/block/scan-error",
  "/sentrook log [retention|purge]",
  "/sentrook sensitivity [strict|lenient]",
  "/sentrook allow-all [on|off]",
  "/sentrook quiet <duration|off>   e.g. 30m, 2h, 8h (session, in-memory)",
  "/sentrook allowlist [rm n]",
  "",
  "Allow-all and quiet skip future reviews only — already-open cards still",
  "need /approve. Block, scan errors, and unattended runs are never skipped.",
  "",
  "Dashboard: /sentrook on this gateway (same port as Control UI, usually 18789).",
  CHANNEL_DISCLOSURE,
].join("\n");

function firstToken(raw: string | undefined): { cmd: string; rest: string } {
  const text = (raw ?? "").trim();
  if (!text) return { cmd: "", rest: "" };
  const space = text.search(/\s/);
  if (space < 0) return { cmd: text.toLowerCase(), rest: "" };
  return { cmd: text.slice(0, space).toLowerCase(), rest: text.slice(space).trim() };
}

function pendingCommandText(args: Record<string, unknown> | undefined): string {
  if (!args) return "";
  const command = args.command ?? args.cmd;
  if (typeof command === "string" && command.trim()) return command;
  try {
    return JSON.stringify(args);
  } catch {
    return String(args);
  }
}

function scrubbedCommand(args: Record<string, unknown> | undefined): string {
  if (!args) return "(no args)";
  const cleaned = scrubOperatorArgs(args);
  const text = pendingCommandText(cleaned);
  return text || "(empty)";
}

function leadIn(text: string, limit = 72): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  if (oneLine.length <= limit) return oneLine;
  return `${oneLine.slice(0, limit - 1)}…`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const mib = bytes / (1024 * 1024);
  if (mib >= 1) return `${mib.toFixed(1)} MiB`;
  return `${(bytes / 1024).toFixed(1)} KiB`;
}

function eventCommand(event: OperatorLogEvent): string {
  const pending = event.pending;
  if (!pending || typeof pending !== "object") return "";
  return pendingCommandText((pending as { args?: Record<string, unknown> }).args);
}

function eventTool(event: OperatorLogEvent): string {
  const pending = event.pending;
  if (pending && typeof pending === "object" && typeof (pending as { tool?: unknown }).tool === "string") {
    return (pending as { tool: string }).tool;
  }
  return "tool";
}

function eventDecision(event: OperatorLogEvent): string {
  if (event.event === "scan_error") {
    const kind = (event.scan_error as { kind?: string } | undefined)?.kind;
    return kind ? `error:${kind}` : "scan-error";
  }
  const decision = (event.scan as { decision?: string } | undefined)?.decision;
  return decision ?? event.event;
}

function isDefaultHistoryEvent(event: OperatorLogEvent): boolean {
  if (event.event === "scan_error") return true;
  if (event.event !== "scan") return false;
  const decision = (event.scan as { decision?: string } | undefined)?.decision;
  return decision === "review" || decision === "block";
}

function sessionQuery(ids: SessionIds): { sessionId?: string; sessionKey?: string } {
  if (ids.sessionId) return { sessionId: ids.sessionId };
  if (ids.sessionKey) return { sessionKey: ids.sessionKey };
  return {};
}

function historyEvents(deps: SlashDeps, ids: SessionIds): OperatorLogEvent[] {
  const log = deps.operatorLog();
  const filter = sessionQuery(ids);
  if (!filter.sessionId && !filter.sessionKey) {
    return queryOperatorLog(log, { event: ["scan", "scan_error"] });
  }
  return queryOperatorLog(log, { ...filter, event: ["scan", "scan_error"] });
}

function formatHistoryRow(event: OperatorLogEvent): string {
  const ts = event.ts.slice(11, 19) || event.ts;
  return `${ts}  ${eventDecision(event).padEnd(12)}  ${eventTool(event)}  ${event.id}  ${leadIn(eventCommand(event) || "(no command)")}`;
}

function formatEventDetail(event: OperatorLogEvent): string {
  const tool = eventTool(event);
  const command = eventCommand(event) || "(no command)";
  const lines = [
    `${event.id}  ${eventDecision(event)}  ${tool}  ${event.ts}`,
    command,
    "",
    CHANNEL_DISCLOSURE,
  ];
  return lines.join("\n");
}

function formatPendingList(session: SlashSession): string {
  const rows: string[] = [];
  for (const [toolCallId, call] of session.pending) {
    if (!call.awaitingApproval) continue;
    const id = call.eventId ?? toolCallId;
    rows.push(`${id}  ${call.tool}  ${leadIn(scrubbedCommand(call.args))}`);
  }
  if (rows.length === 0) {
    return "No pending Sentrook reviews in this session.\nAlready-open cards still need /approve.";
  }
  return [
    `Pending reviews (${rows.length}) — short list; use /sentrook pending <id> for the full command.`,
    ...rows,
    "",
    "Already-open cards still need /approve. Allow-all/quiet do not close them.",
    CHANNEL_DISCLOSURE,
  ].join("\n");
}

function findPending(
  session: SlashSession,
  id: string,
): { call: SlashPendingCall; toolCallId: string } | undefined {
  const needle = id.trim().toLowerCase();
  if (!needle) return undefined;
  for (const [toolCallId, call] of session.pending) {
    if (!call.awaitingApproval) continue;
    const eventId = (call.eventId ?? "").toLowerCase();
    if (eventId === needle || eventId.startsWith(needle)) return { call, toolCallId };
    if (toolCallId.toLowerCase() === needle) return { call, toolCallId };
  }
  return undefined;
}

function formatStatus(deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  const log = deps.operatorLog();
  const stats = operatorLogStats(log);
  const now = deps.now();
  const quietMs = quietRemainingMs(session.quietUntilMs, now);
  const pendingCount = [...session.pending.values()].filter((c) => c.awaitingApproval).length;
  const last = queryOperatorLog(log, { ...sessionQuery(ids), limit: 1 })[0];
  const lastLine = last
    ? `${last.ts} ${eventDecision(last)} ${eventTool(last)} ${last.id}`
    : "(none this session)";
  return [
    "Sentrook status",
    `session_id: ${ids.sessionId ?? "(none)"}`,
    `session_key: ${ids.sessionKey ?? "(none)"}`,
    `sensitivity: ${deps.sensitivity()}`,
    `allow-all: ${session.allowAll ? "on" : "off"} (this session, in-memory)`,
    `quiet: ${quietMs > 0 ? `on (${formatDuration(quietMs)} left)` : "off"} (this session, in-memory)`,
    `pending reviews: ${pendingCount}`,
    `operator log: ${log.enabled ? "on" : "off"}  ${stats.path}`,
    `  ${formatBytes(stats.bytes)}, ${stats.lines} lines, last ${lastLine}`,
    `dashboard: /sentrook on this gateway`,
  ].join("\n");
}

function handleLog(deps: SlashDeps, rest: string): string {
  const { cmd, rest: tail } = firstToken(rest);
  const log = deps.operatorLog();
  if (!cmd) {
    const stats = operatorLogStats(log);
    return [
      `Operator log: ${log.enabled ? "on" : "off"}`,
      `path: ${stats.path}`,
      `size: ${formatBytes(stats.bytes)} / ${formatBytes(log.maxBytes)} (${stats.lines} lines)`,
      `oldest: ${stats.oldestTs ?? "(empty)"}`,
      `newest: ${stats.newestTs ?? "(empty)"}`,
      `retention: ${log.maxAgeDays} days, rotate at ${formatBytes(log.maxBytes)}`,
      `off: SENTROOK_OPERATOR_LOG=0  (scanning still works; history is empty after restart)`,
    ].join("\n");
  }
  if (cmd === "retention") {
    return handleLogRetention(deps, tail);
  }
  if (cmd === "purge") {
    return handleLogPurge(deps, tail);
  }
  return "Usage: /sentrook log [retention <days|size>|purge [all] confirm]";
}

function parseRetention(raw: string): { maxAgeDays?: number; maxBytes?: number } | { error: string } {
  const n = raw.trim().toLowerCase();
  if (!n) {
    return { error: "Usage: /sentrook log retention <days|size>  e.g. 14, 7d, 32MiB" };
  }
  const size = n.match(/^(\d+(?:\.\d+)?)\s*(b|kb|kib|mb|mib)$/);
  if (size) {
    const amount = Number.parseFloat(size[1] ?? "0");
    const unit = size[2] ?? "mib";
    let bytes = amount;
    if (unit === "kb" || unit === "kib") bytes = amount * 1024;
    else if (unit === "mb" || unit === "mib") bytes = amount * 1024 * 1024;
    if (!Number.isFinite(bytes) || bytes < 1024) {
      return { error: "Size must be at least 1 KiB." };
    }
    return { maxBytes: Math.round(bytes) };
  }
  const days = n.match(/^(\d+)\s*d(?:ays?)?$/) ?? n.match(/^(\d+)$/);
  if (days) {
    const amount = Number.parseInt(days[1] ?? "0", 10);
    if (!Number.isFinite(amount) || amount < 0) {
      return { error: "Days must be 0 or a positive integer (0 = no age purge)." };
    }
    return { maxAgeDays: amount };
  }
  return { error: "Use a day count (14 or 7d) or a size (32MiB)." };
}

function handleLogRetention(deps: SlashDeps, raw: string): string {
  const parsed = parseRetention(raw);
  if ("error" in parsed) return parsed.error;
  const result = deps.setOperatorLogRetention(parsed);
  const log = deps.operatorLog();
  const saved = result.persisted
    ? "Saved in plugin config."
    : `Live until restart${result.error ? ` (${result.error})` : ""}.`;
  const parts = [`Retention updated. ${saved}`];
  if (parsed.maxAgeDays != null) {
    parts.push(`max age: ${log.maxAgeDays} days (default ${DEFAULT_MAX_AGE_DAYS}).`);
  }
  if (parsed.maxBytes != null) {
    parts.push(`max size: ${formatBytes(log.maxBytes)} (default ${formatBytes(DEFAULT_MAX_BYTES)}).`);
  }
  return parts.join(" ");
}

function handleLogPurge(deps: SlashDeps, raw: string): string {
  const tokens = raw.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const all = tokens.includes("all");
  const confirm = tokens.includes("confirm") || tokens.includes("yes");
  const log = deps.operatorLog();
  if (!confirm) {
    return all
      ? "This deletes the operator log files. Re-run: /sentrook log purge all confirm"
      : `This drops lines older than ${log.maxAgeDays} days. Re-run: /sentrook log purge confirm`;
  }
  if (all) {
    const dropped = wipeOperatorLog(log);
    return `Purged operator log (${dropped} lines removed).`;
  }
  const dropped = purgeOperatorLog(log);
  return dropped === 0
    ? "Nothing to purge (no lines older than retention)."
    : `Purged ${dropped} line${dropped === 1 ? "" : "s"} older than ${log.maxAgeDays} days.`;
}

function wipeOperatorLog(config: OperatorLogConfig): number {
  const before = operatorLogStats(config).lines;
  for (const path of [config.path, `${config.path}.1`]) {
    try {
      unlinkSync(path);
    } catch {
      /* missing */
    }
  }
  return before;
}

function handleAllowlist(deps: SlashDeps, rest: string): string {
  const { cmd, rest: tail } = firstToken(rest);
  const path = deps.allowlist.path || resolveAllowlistCliPath();
  if (!cmd) return formatAllowlistList(path);
  if (cmd === "rm" || cmd === "remove") {
    const n = Number.parseInt(tail, 10);
    if (!Number.isFinite(n) || n < 1) {
      return "Usage: /sentrook allowlist rm <n>  (1-based index from the list)";
    }
    return removeAllowlistEntry(path, n);
  }
  return "Usage: /sentrook allowlist [rm n]";
}

function removeAllowlistEntry(path: string, index1: number): string {
  const file = loadAllowlist(path);
  if (index1 > file.entries.length) {
    return `No allowlist entry ${index1} (${file.entries.length} stored).`;
  }
  const removed = file.entries.splice(index1 - 1, 1)[0];
  saveAllowlist(path, file);
  const label =
    removed?.kind === "script_bind"
      ? `${removed.interpreter} ${removed.script_path}`
      : removed?.kind === "skeleton"
        ? removed.skeleton
        : "entry";
  return `Removed [${index1}] ${removed?.kind ?? "entry"} ${leadIn(label, 80)}`;
}

function handleHistory(deps: SlashDeps, ids: SessionIds, rest: string): string {
  const log = deps.operatorLog();
  if (!log.enabled) {
    return "Operator log is off (SENTROOK_OPERATOR_LOG=0). History is empty.";
  }
  const trimmed = rest.trim();
  if (trimmed && /^(sr_[0-9a-f]+|[0-9a-f]{4,})$/i.test(trimmed.split(/\s+/)[0] ?? "")) {
    const id = trimmed.split(/\s+/)[0] ?? "";
    const event = getOperatorLogEvent(log, id);
    if (!event) return `No log event matching ${id}.`;
    return formatEventDetail(event);
  }
  const tokens = trimmed.toLowerCase().split(/\s+/).filter(Boolean);
  const includeAll = tokens.includes("all");
  const countTok = tokens.find((t) => /^\d+$/.test(t));
  const limit = countTok ? Number.parseInt(countTok, 10) : DEFAULT_HISTORY_LIMIT;
  if (!Number.isFinite(limit) || limit <= 0) {
    return "Usage: /sentrook history [n|id|all]";
  }
  const events = historyEvents(deps, ids).filter((event) => includeAll || isDefaultHistoryEvent(event));
  const slice = events.slice(0, limit);
  if (slice.length === 0) {
    return includeAll
      ? "No scan events in the operator log for this session."
      : "No review/block/scan-error events for this session. Try /sentrook history all.";
  }
  return [
    `History (${includeAll ? "all scans" : "review/block/scan-error"}, newest first, ${slice.length}/${events.length})`,
    ...slice.map(formatHistoryRow),
    "",
    "Use /sentrook history <id> for the full scrubbed command.",
  ].join("\n");
}

function handlePending(deps: SlashDeps, session: SlashSession, rest: string): string {
  const id = rest.trim();
  if (!id) return formatPendingList(session);
  const found = findPending(session, id);
  if (found) {
    return [
      `${found.call.eventId ?? found.toolCallId}  pending  ${found.call.tool}`,
      scrubbedCommand(found.call.args),
      "",
      CHANNEL_DISCLOSURE,
    ].join("\n");
  }
  const event = getOperatorLogEvent(deps.operatorLog(), id);
  if (event) return formatEventDetail(event);
  return `No pending review matching ${id}.`;
}

export function handleSentrookCommand(ctx: SlashCommandContext, deps: SlashDeps): SlashReply {
  if (ctx.senderIsOwner === false) {
    return { text: "⚠️ /sentrook is owner-only." };
  }
  const ids = sessionIdsOf({ sessionId: ctx.sessionId, sessionKey: ctx.sessionKey });
  const session = deps.sessionOf(ids);
  const { cmd, rest } = firstToken(ctx.args);
  if (!cmd || cmd === "help") return { text: HELP_TEXT };

  if (cmd === "status") return { text: formatStatus(deps, ids, session) };

  if (cmd === "pending") return { text: handlePending(deps, session, rest) };

  if (cmd === "history") return { text: handleHistory(deps, ids, rest) };

  if (cmd === "log") return { text: handleLog(deps, rest) };

  if (cmd === "sensitivity") {
    if (!rest) return { text: `Sensitivity: ${deps.sensitivity()} (strict = default, lenient = skip info-only reviews).` };
    const value = parseSensitivity(rest, "strict");
    if (rest.trim().toLowerCase() !== value) {
      return { text: "Usage: /sentrook sensitivity [strict|lenient]" };
    }
    const result = deps.setSensitivity(value);
    const saved = result.persisted
      ? "Saved in plugin config."
      : `Live until restart${result.error ? ` (${result.error})` : ""}.`;
    return { text: `Sensitivity ${value}. ${saved} Hosted L2/L3 is unchanged.` };
  }

  if (cmd === "allow-all" || cmd === "allowall") {
    const parsed = parseOnOff(rest, true);
    if (typeof parsed !== "boolean") return { text: parsed.error };
    session.allowAll = parsed;
    return {
      text: parsed
        ? "Allow-all on for this session. Future hosted reviews skip the card (still scanned). Blocks, scan errors, and unattended runs are not skipped. Already-open cards still need /approve. Gateway restart or session end clears this."
        : "Allow-all off. Future reviews will prompt again.",
    };
  }

  if (cmd === "quiet") {
    const parsed = parseQuietDuration(rest, deps.now());
    if ("error" in parsed) return { text: parsed.error };
    session.quietUntilMs = parsed.untilMs;
    if (parsed.untilMs == null) {
      return { text: "Quiet off. Future reviews will prompt again." };
    }
    const left = formatDuration(quietRemainingMs(parsed.untilMs, deps.now()));
    return {
      text: `Quiet on for ${left} in this session. Future hosted reviews skip the card (still scanned). Blocks, scan errors, and unattended runs are not skipped. Already-open cards still need /approve.`,
    };
  }

  if (cmd === "allowlist") return { text: handleAllowlist(deps, rest) };

  return { text: `Unknown /sentrook ${cmd}. Try /sentrook help.` };
}

export const SENTROOK_COMMAND_DEF = {
  name: SENTROOK_COMMAND_NAME,
  description: "Sentrook session scan controls (status, pending, allow-all, quiet)",
  acceptsArgs: true,
  requireAuth: true,
  requiredScopes: ["operator.admin"],
};
