/**
 * ``/sentrook`` chat command family (OpenClaw ``api.registerCommand``).
 *
 * Owner-only. Returns ``{ text }`` for the originating channel. Lists stay
 * short; ``pending <id>`` / ``history <id>`` reconstruct the review (command,
 * decision, what happened next — no AIRA ids, no tool results).
 */

import {
  formatAllowlistList,
  resolveAllowlistCliPath,
} from "./allowlistCli.ts";
import { addAllowlistFromHistory } from "./allowlistFromLog.ts";
import { allowlistAdd } from "./dashboardSlashHints.ts";
import { loadAllowlist, saveAllowlist, type AllowlistConfig } from "./localAllowlist.ts";

import {
  DEFAULT_MAX_AGE_DAYS,
  DEFAULT_MAX_BYTES,
  getOperatorLogEvent,
  operatorLogStats,
  purgeOperatorLog,
  queryOperatorLog,
  scrubOperatorArgs,
  wipeOperatorLog,
  type OperatorLogConfig,
  type OperatorLogEvent,
} from "./operatorLog.ts";
import {
  allowAllHint,
  feedbackHint,
  quietHint,
  quietLeftLabel,
  scanErrorHint,
  sensitivityHint,
  sessionFloorOverrideNote,
  type FeedbackMode,
} from "./policyCopy.ts";
import { parseOnScanError, type OnScanError } from "./scanErrorPolicy.ts";
import {
  formatDuration,
  parseOnOff,
  parseQuietDuration,
  parseSessionSensitivityToken,
  parseSensitivityToken,
  quietRemainingMs,
  sessionFloorLabel,
  type Sensitivity,
  type SessionPolicyFlags,
} from "./sessionPolicy.ts";
import { sessionIdsOf, type SessionIds } from "./sessionStore.ts";
import { mergeSessionRows, sessionDisplayName, type HostSession } from "./hostSessions.ts";
import { operatorSummary, ruleMeanings } from "./dashboardPresent.ts";
import {
  approveAlways,
  approveDeny,
  approveOnce,
  pendingInspect,
} from "./dashboardSlashHints.ts";

export const SENTROOK_COMMAND_NAME = "sentrook";
export const CHANNEL_DISCLOSURE =
  "Public Discord, Telegram, or WhatsApp: anyone in the room can read these " +
  "replies (secrets are scrubbed, not a guarantee). Prefer a DM, a private " +
  "channel, or the dashboard.";

const MORE_COMMANDS = "More commands: /sentrook help";
const DASHBOARD_LINE = "Dashboard: Sentrook tab in the OpenClaw Control UI (2026.9.2+).";
const OPEN_CARDS = "Open cards still need /approve.";
/** Discord hard-caps slash replies; keep `/sentrook help` under this. */
export const DISCORD_MESSAGE_MAX = 2000;
const SKIP_FUTURE =
  "Future attended reviews skip the prompt. Scan still runs. Blocks, scan errors, and unattended runs still stop.";
const SNAPSHOT_PENDING_CAP = 5;
const PENDING_ALL_CAP = 20;
const HISTORY_PAGE_DEFAULT = 8;
const HISTORY_PAGE_CAP = 20;
const HISTORY_USAGE =
  "Usage: /sentrook history [all | gateway | before <id> | n | <id>]\nTry: /sentrook history help";

export type SlashPendingCall = {
  tool: string;
  args: Record<string, unknown>;
  awaitingApproval?: boolean;
  eventId?: string;
};

export type SlashSession = SessionPolicyFlags & {
  pending: Map<string, SlashPendingCall>;
  sessionId?: string;
  sessionKey?: string;
};

export type SlashCard = {
  eventId: string;
  toolCallId: string;
  tool: string;
  args: Record<string, unknown>;
  sessionId?: string;
  sessionKey?: string;
  approvalId?: string;
  intent?: string | null;
  intentKind?: string | null;
  scan?: {
    decision?: string;
    risk?: number;
    summary?: string;
    matched_rules?: string[];
    review_severity?: string;
  };
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

export type SlashPersistResult = { persisted: boolean; error?: string };

export type SlashDeps = {
  sessionOf: (ids: SessionIds) => SlashSession;
  listSessions: () => SlashSession[];
  listHostSessions?: () => HostSession[];
  listCards?: () => SlashCard[];
  /** Join host-minted ``plugin:`` ids onto pending cards before rendering. */
  joinCards?: () => Promise<void>;
  sensitivity: () => Sensitivity;
  setSensitivity: (value: Sensitivity) => SlashPersistResult;
  unattendedSensitivity: () => Sensitivity;
  setUnattendedSensitivity: (value: Sensitivity) => SlashPersistResult;
  allowAll: () => boolean;
  setAllowAll: (value: boolean) => void;
  syncSessionFlags?: (session: SlashSession) => void;
  quietUntilMs: () => number | null;
  setQuietUntilMs: (value: number | null) => void;
  feedbackMode: () => FeedbackMode;
  setFeedbackMode: (value: FeedbackMode) => SlashPersistResult;
  onScanError: () => OnScanError;
  setOnScanError: (value: OnScanError) => SlashPersistResult;
  operatorLog: () => OperatorLogConfig;
  setOperatorLogRetention: (patch: {
    maxAgeDays?: number;
    maxBytes?: number;
  }) => SlashPersistResult;
  allowlist: AllowlistConfig;
  now: () => number;
};

export type SlashReply = { text: string };

const HELP_TEXT = [
  "Sentrook — scan controls",
  "",
  "Add help after any command for options and the current value.",
  "",
  "/sentrook",
  "  Snapshot: policy plus pending. One review is shown in full.",
  "/sentrook help",
  "  This catalog.",
  "/sentrook status",
  "  Settings for this chat and the gateway (no pending list).",
  "/sentrook policy",
  "  All settings, with a short explanation of the current choice.",
  "/sentrook pending [all | <id>]",
  "  Waiting reviews. all = every session. One review is shown in full.",
  "/sentrook history [all | gateway | before <id> | n | <id>]",
  "  Newest 8 (20 max). Reviews/blocks/errors this chat. all = allows here. gateway = every session, never allows. before <id> older; n = page size.",
  "/sentrook sessions",
  "  Sessions plus floors, quiet, and allow-all. Use the key column next.",
  "/sentrook allow-all [all | session <key>] [on | off]",
  "  Skip future attended reviews. Passing no arguments = on for this session. Session floors ignore this.",
  "/sentrook quiet [all | session <key>] <duration | off>",
  "  Same skip, with a timer (30m, 2h, 8h max). Session floors ignore this.",
  "/sentrook sensitivity [attended | unattended | session <key> attended|unattended] [level | default]",
  "  Gateway or per-session floors. default inherits global. critical needs confirm.",
  "/sentrook feedback [submit | off]",
  "  Whether sanitized reviews go to the community corpus.",
  "/sentrook scan-error [review | deny | allow]",
  "  When Sentrook cannot scan. allow needs confirm.",
  "/sentrook allowlist [add <id> | rm n]",
  "  Local allow-always. add uses a history id. rm is 1-based.",
  "/sentrook log [retention | purge]",
  "  Local history. purge confirm / purge all confirm.",
  "",
  "Allow-all and quiet skip future reviews; open cards still need /approve.",
  "Blocks and scan errors always stop. Cron: /sentrook allowlist add <id>, then re-run.",
  "",
  DASHBOARD_LINE,
  "",
  CHANNEL_DISCLOSURE,
].join("\n");

const VERB_HELP = new Set([
  "status",
  "policy",
  "pending",
  "history",
  "sessions",
  "allow-all",
  "allowall",
  "quiet",
  "sensitivity",
  "feedback",
  "scan-error",
  "scanerror",
  "allowlist",
  "log",
]);

function firstToken(raw: string | undefined): { cmd: string; rest: string } {
  const text = (raw ?? "").trim();
  if (!text) return { cmd: "", rest: "" };
  const space = text.search(/\s/);
  if (space < 0) return { cmd: text.toLowerCase(), rest: "" };
  return { cmd: text.slice(0, space).toLowerCase(), rest: text.slice(space).trim() };
}

function isHelpToken(raw: string | undefined): boolean {
  const t = firstToken(raw).cmd;
  return t === "help" || t === "?" || t === "-h" || t === "--help";
}

function splitConfirm(raw: string): { rest: string; confirm: boolean } {
  const tokens = raw.trim().split(/\s+/).filter(Boolean);
  const last = tokens[tokens.length - 1]?.toLowerCase();
  if (last === "confirm" || last === "yes") {
    tokens.pop();
    return { rest: tokens.join(" "), confirm: true };
  }
  return { rest: raw.trim(), confirm: false };
}

function savedLine(result: SlashPersistResult): string {
  return result.persisted
    ? "Saved."
    : `Live until restart${result.error ? ` (${result.error})` : ""}.`;
}

function kv(label: string, value: string, width = 12): string {
  return `  ${padCell(label, width)}  ${value}`;
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

function fence(body: string): string {
  const text = body.replace(/\r\n/g, "\n").replace(/```/g, "`\u200b``");
  return `\`\`\`\n${text}\n\`\`\``;
}

function padCell(value: string, width: number): string {
  const t = value.replace(/\s+/g, " ").trim();
  if (t.length >= width) return t;
  return t + " ".repeat(width - t.length);
}

function formatPlainTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
  const fmt = (cells: string[]) =>
    cells.map((c, i) => (i === cells.length - 1 ? (c ?? "") : padCell(c ?? "", widths[i]!))).join("  ");
  return fence([fmt(headers), ...rows.map(fmt)].join("\n"));
}

function lookupPendingCard(deps: SlashDeps, call: SlashPendingCall): SlashCard | undefined {
  const needle = (call.eventId ?? "").toLowerCase();
  if (!needle) return undefined;
  return deps.listCards?.().find(
    (c) => c.eventId.toLowerCase() === needle || c.eventId.toLowerCase().startsWith(needle),
  );
}

function pendingScanOf(
  deps: SlashDeps,
  call: SlashPendingCall,
): SlashCard["scan"] | undefined {
  const fromCard = lookupPendingCard(deps, call)?.scan;
  if (fromCard) return fromCard;
  if (!call.eventId) return undefined;
  const event = getOperatorLogEvent(deps.operatorLog(), call.eventId);
  const scan = event?.scan;
  if (!scan || typeof scan !== "object") return undefined;
  return scan as SlashCard["scan"];
}

function riskLine(risk: number | undefined): string | undefined {
  if (typeof risk !== "number" || !Number.isFinite(risk)) return undefined;
  const pct = Math.min(100, Math.max(0, risk <= 1 ? Math.round(risk * 100) : Math.round(risk)));
  return `${pct} / 100`;
}

function scanSeverity(scan: SlashCard["scan"] | undefined): string {
  const sev = scan?.review_severity?.trim() || scan?.decision?.trim();
  return sev || "—";
}

function scanWhy(scan: { matched_rules?: string[]; summary?: string } | undefined): string[] {
  const meanings = ruleMeanings(scan?.matched_rules);
  const summary = operatorSummary(scan?.summary);
  return [summary, ...meanings.filter((m) => m !== summary)].filter(Boolean);
}

function historyTime(ts: string, now: number): string {
  const clock = ts.slice(11, 19);
  if (!clock) return ts;
  const day = ts.slice(0, 10);
  const nowDay = new Date(now).toISOString().slice(0, 10);
  if (day === nowDay) return clock;
  return `${ts.slice(5, 10)} ${ts.slice(11, 16)}`;
}

function intentKindLabel(kind: string | null | undefined): string {
  const k = (kind ?? "").trim().toLowerCase();
  if (!k || k === "user") return "";
  if (k === "cron") return "Cron";
  if (k === "heartbeat") return "Heartbeat";
  if (k === "subagent") return "Subagent";
  if (k === "system") return "System";
  return k;
}

function pendingSessionLine(
  deps: SlashDeps,
  call: SlashPendingCall,
  session?: SlashSession,
): string | undefined {
  const card = lookupPendingCard(deps, call);
  const key = card?.sessionKey ?? session?.sessionKey;
  const id = card?.sessionId ?? session?.sessionId;
  const host = (deps.listHostSessions?.() ?? []).find(
    (h) => (key && h.sessionKey === key) || (id && h.sessionId === id),
  );
  const name = host ? sessionDisplayName(host) : undefined;
  if (name && key && name !== key) return `${name}  (key ${key})`;
  if (key) return key;
  if (id) return id;
  return undefined;
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

function gatewayAllowAllMode(deps: SlashDeps): "off" | "session" | "on" {
  if (deps.allowAll()) return "on";
  if (deps.listSessions().some((s) => s.allowAll)) return "session";
  return "off";
}

function pendingRows(session: SlashSession): SlashPendingCall[] {
  return [...session.pending.values()].filter((c) => c.awaitingApproval);
}

function findNamedSession(deps: SlashDeps, token: string): SlashSession | undefined {
  const needle = token.trim().toLowerCase();
  if (!needle) return undefined;
  const sessions = deps.listSessions();
  const exact = sessions.find(
    (s) => s.sessionKey?.toLowerCase() === needle || s.sessionId?.toLowerCase() === needle,
  );
  if (exact) return exact;
  if (needle.length >= 4) {
    const prefix = sessions.find((s) => s.sessionId?.toLowerCase().startsWith(needle));
    if (prefix) return prefix;
  }
  const host = deps.listHostSessions?.() ?? [];
  const hostHit =
    host.find(
      (s) => s.sessionKey.toLowerCase() === needle || s.sessionId?.toLowerCase() === needle,
    ) ??
    (needle.length >= 4
      ? host.find((s) => s.sessionId?.toLowerCase().startsWith(needle))
      : undefined);
  if (!hostHit) return undefined;
  const created = deps.sessionOf({
    sessionId: hostHit.sessionId,
    sessionKey: hostHit.sessionKey,
  });
  if (hostHit.sessionId) created.sessionId = hostHit.sessionId;
  if (hostHit.sessionKey) created.sessionKey = hostHit.sessionKey;
  return created;
}

function sessionLabel(session: SlashSession): string {
  return session.sessionKey || session.sessionId || "(unnamed)";
}

function sessionFloorLine(session: Sensitivity | null | undefined, global: Sensitivity): string {
  if (session == null) return `default (${global})`;
  return `${session} (overrides global ${global})`;
}

function resolveSessionByKey(deps: SlashDeps, token: string): SlashSession | undefined {
  const named = findNamedSession(deps, token);
  if (named) return named;
  const key = token.trim();
  if (!key) return undefined;
  const created = deps.sessionOf({ sessionKey: key });
  created.sessionKey = key;
  return created;
}

function operatorJoinKey(event: OperatorLogEvent): string {
  const meta = (event.metadata ?? {}) as { tool_call_id?: unknown };
  const tc = typeof meta.tool_call_id === "string" ? meta.tool_call_id.trim() : "";
  if (tc) return `tc:${tc}`;
  return `run:${event.run_id}`;
}

type ScanOutcome = {
  decision?: string;
  labelSource?: string;
  effect?: string;
  resultOk?: boolean;
};

function scanOutcomeIndex(events: OperatorLogEvent[]): Map<string, ScanOutcome> {
  const out = new Map<string, ScanOutcome>();
  const take = (key: string) => {
    const cur = out.get(key) ?? {};
    out.set(key, cur);
    return cur;
  };
  for (const event of events) {
    const key = operatorJoinKey(event);
    if (event.event === "resolution") {
      const decision = (event.resolution as { decision?: string } | undefined)?.decision;
      if (!decision) continue;
      const row = take(key);
      if (!row.decision) {
        row.decision = decision;
        row.labelSource = typeof event.label_source === "string" ? event.label_source : undefined;
        row.effect = typeof event.effect === "string" ? event.effect : undefined;
      }
    } else if (event.event === "result") {
      const ok = (event.result as { ok?: boolean } | undefined)?.ok;
      const row = take(key);
      if (row.resultOk == null && typeof ok === "boolean") row.resultOk = ok;
    }
  }
  return out;
}

function hookSkipReason(event: OperatorLogEvent): string | undefined {
  const skip = (event.hook as { skip_reason?: string } | undefined)?.skip_reason;
  return typeof skip === "string" && skip.trim() ? skip : undefined;
}

function shortResolution(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  switch (raw) {
    case "allowlist-hit":
    case "allowlist":
      return "allowlist";
    case "quiet-skip":
    case "quiet":
      return "quiet";
    case "lenient-skip":
    case "lenient":
      return "floor";
    case "session-skip":
    case "session":
      return "session";
    case "allow-all-skip":
    case "allow-all":
      return "allow-all";
    case "allow-once":
    case "allow-always":
    case "deny":
    case "timeout":
    case "cancelled":
      return raw;
    case "unattended-block":
      return "unattended";
    default:
      return raw.replace(/-skip$/, "").replace(/-hit$/, "");
  }
}

function thenLabel(event: OperatorLogEvent, outcome: ScanOutcome | undefined): string | undefined {
  return shortResolution(outcome?.decision) ?? shortResolution(hookSkipReason(event));
}

function listOutcome(event: OperatorLogEvent, outcome: ScanOutcome | undefined): string {
  const hosted = eventDecision(event);
  if (hosted !== "review") return hosted;
  const then = thenLabel(event, outcome);
  return then ? `review → ${then}` : "review → waiting";
}

function ranLabel(event: OperatorLogEvent, outcome: ScanOutcome | undefined): string {
  const hosted = eventDecision(event);
  const then = thenLabel(event, outcome);
  const effect =
    outcome?.effect ?? (typeof event.effect === "string" ? event.effect : undefined);
  if (hosted === "review" && !then) return "waiting";
  if (effect === "ran") return "yes";
  if (effect === "never_ran" || effect === "blocked") return "no";
  if (typeof outcome?.resultOk === "boolean") return "yes";
  if (hosted === "allow" || then === "allowlist" || then === "quiet" || then === "allow-all" || then === "floor") {
    return "yes";
  }
  if (hosted === "block" || hosted.startsWith("error") || then === "deny" || then === "timeout" || then === "cancelled" || then === "unattended") {
    return "no";
  }
  if (then === "allow-once" || then === "allow-always") return "yes";
  return "waiting";
}

function historyCells(
  event: OperatorLogEvent,
  outcome: ScanOutcome | undefined,
  now: number,
): string[] {
  return [
    event.id,
    historyTime(event.ts, now),
    listOutcome(event, outcome),
    eventTool(event),
    leadIn(eventCommand(event) || "(no command)", 48),
  ];
}

function formatEventDetail(event: OperatorLogEvent, outcome: ScanOutcome | undefined = undefined): string {
  const hosted = eventDecision(event);
  const then = thenLabel(event, outcome);
  const thenValue = then
    ? `${then}${outcome?.labelSource ? ` (${outcome.labelSource})` : ""}`
    : hosted === "review"
      ? "waiting"
      : undefined;
  const scan = event.scan as
    | { review_severity?: string; matched_rules?: string[]; summary?: string }
    | undefined;
  const severity = scan?.review_severity;
  const scanValue =
    hosted === "review" && typeof severity === "string" && severity.trim()
      ? `review (${severity.trim()})`
      : hosted;
  const why = scanWhy(scan);
  const command = eventCommand(event) || "(no command)";
  return [
    `History  ${event.id}`,
    "",
    kv("When", event.ts),
    kv("Tool", eventTool(event)),
    kv("Scan", scanValue),
    thenValue ? kv("Then", thenValue) : undefined,
    kv("Ran", ranLabel(event, outcome)),
    why.length ? kv("Why", why[0]!) : undefined,
    ...why.slice(1).map((line) => kv("", line)),
    "",
    "Command",
    fence(command),
    hosted === "review"
      ? [
          "",
          "If you trust this command:",
          `  ${allowlistAdd(event.id)}`,
        ].join("\n")
      : undefined,
  ]
    .filter((line): line is string => line != null)
    .join("\n");
}

function isHistoryEventId(token: string): boolean {
  return /^(sr_[0-9a-z]+|[0-9a-f]{4,})$/i.test(token);
}

function isScanLike(event: OperatorLogEvent): boolean {
  return event.event === "scan" || event.event === "scan_error";
}

type HistoryListQuery = {
  gateway: boolean;
  includeAll: boolean;
  beforeId?: string;
  page: number;
  askedPage?: number;
};

function parseHistoryRest(
  rest: string,
): { kind: "id"; id: string } | { kind: "list"; query: HistoryListQuery } | { kind: "error"; error: string } {
  const tokens = rest.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    return {
      kind: "list",
      query: { gateway: false, includeAll: false, page: HISTORY_PAGE_DEFAULT },
    };
  }
  if (tokens.length === 1 && isHistoryEventId(tokens[0]!)) {
    return { kind: "id", id: tokens[0]! };
  }
  let gateway = false;
  let includeAll = false;
  let beforeId: string | undefined;
  let askedPage: number | undefined;
  for (let i = 0; i < tokens.length; i += 1) {
    const raw = tokens[i]!;
    const t = raw.toLowerCase();
    if (t === "gateway" || t === "global") {
      gateway = true;
      continue;
    }
    if (t === "all") {
      includeAll = true;
      continue;
    }
    if (t === "before") {
      const next = tokens[i + 1];
      if (!next) return { kind: "error", error: HISTORY_USAGE };
      beforeId = next;
      i += 1;
      continue;
    }
    if (/^\d+$/.test(t)) {
      askedPage = Number.parseInt(t, 10);
      continue;
    }
    if (isHistoryEventId(raw)) {
      return { kind: "id", id: raw };
    }
    return { kind: "error", error: HISTORY_USAGE };
  }
  if (gateway) includeAll = false;
  if (askedPage != null && (!Number.isFinite(askedPage) || askedPage <= 0)) {
    return { kind: "error", error: HISTORY_USAGE };
  }
  const page = Math.min(HISTORY_PAGE_CAP, askedPage ?? HISTORY_PAGE_DEFAULT);
  return { kind: "list", query: { gateway, includeAll, beforeId, page, askedPage } };
}

function historyOlderCommand(query: HistoryListQuery, lastId: string): string {
  const parts = ["/sentrook history"];
  if (query.gateway) parts.push("gateway");
  if (query.includeAll) parts.push("all");
  if (query.askedPage != null) parts.push(String(query.page));
  parts.push("before", lastId);
  return parts.join(" ");
}

function findHistoryCursor(
  events: OperatorLogEvent[],
  needle: string,
): OperatorLogEvent | undefined {
  const want = needle.trim().toLowerCase();
  if (!want) return undefined;
  const exact = events.find((event) => event.id.toLowerCase() === want);
  if (exact) return exact;
  const prefixed = events.filter((event) => event.id.toLowerCase().startsWith(want));
  return prefixed.length === 1 ? prefixed[0] : undefined;
}

function formatPolicyBlock(deps: SlashDeps, ids: SessionIds, session: SlashSession): string[] {
  const now = deps.now();
  const sessionQuiet = quietRemainingMs(session.quietUntilMs, now);
  const globalQuiet = quietRemainingMs(deps.quietUntilMs(), now);
  const log = deps.operatorLog();
  const stats = operatorLogStats(log);
  const last = queryOperatorLog(log, { ...sessionQuery(ids), limit: 1 })[0];
  const lastLine = last
    ? `${last.ts} ${eventDecision(last)} ${eventTool(last)} ${last.id}`
    : "(none this session)";
  const allowAll = `gateway ${deps.allowAll() ? "on" : "off"} / this session ${session.allowAll ? "on" : "off"}`;
  const quiet =
    `gateway ${globalQuiet > 0 ? `on (${formatDuration(globalQuiet)} left)` : "off"} / this session ${
      sessionQuiet > 0 ? `on (${formatDuration(sessionQuiet)} left)` : "off"
    }`;
  return [
    "Session",
    kv("id", ids.sessionId ?? "(none)"),
    kv("key", ids.sessionKey ?? "(none)"),
    "",
    "Policy",
    kv("attended", sessionFloorLine(session.attendedSensitivity, deps.sensitivity())),
    kv("unattended", sessionFloorLine(session.unattendedSensitivity, deps.unattendedSensitivity())),
    kv("allow-all", allowAll),
    kv("quiet", quiet),
    kv("feedback", deps.feedbackMode()),
    kv("scan-error", deps.onScanError()),
    kv("log", `${log.enabled ? "on" : "off"}  ${stats.path}`),
    kv("", `${formatBytes(stats.bytes)}, ${stats.lines} lines`),
    kv("", `last ${lastLine}`),
  ];
}

function formatSnapshot(deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  const rows = pendingRows(session);
  const shown = rows.slice(0, SNAPSHOT_PENDING_CAP);
  const extra =
    rows.length > SNAPSHOT_PENDING_CAP ? `  … ${rows.length - SNAPSHOT_PENDING_CAP} more` : "";
  if (rows.length === 1) {
    return [
      "Sentrook",
      "",
      ...formatPolicyBlock(deps, ids, session),
      "",
      pendingDetail(deps, rows[0]!, session),
      "",
      MORE_COMMANDS,
    ].join("\n");
  }
  const pendingBlock =
    rows.length === 0
      ? ["Pending", kv("waiting", "0")]
      : [
          "Pending",
          kv("waiting", String(rows.length)),
          ...shown.flatMap((call) => {
            const id = call.eventId ?? "(no id)";
            return [
              `  ${id}  ${call.tool}  ${leadIn(scrubbedCommand(call.args), 56)}`,
              `    ${pendingInspect(call.eventId)}`,
            ];
          }),
          extra,
        ].filter(Boolean);
  return ["Sentrook", "", ...formatPolicyBlock(deps, ids, session), "", ...pendingBlock, "", DASHBOARD_LINE, MORE_COMMANDS].join(
    "\n",
  );
}

function formatStatus(deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  return ["Sentrook status", "", ...formatPolicyBlock(deps, ids, session), "", DASHBOARD_LINE, MORE_COMMANDS].join("\n");
}

function formatPolicyShow(deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  const now = deps.now();
  const mode = gatewayAllowAllMode(deps);
  return [
    "Sentrook policy",
    "",
    ...formatPolicyBlock(deps, ids, session),
    "",
    "What this means",
    kv("attended", sensitivityHint("attended", deps.sensitivity())),
    kv("unattended", sensitivityHint("unattended", deps.unattendedSensitivity())),
    kv("allow-all", allowAllHint(mode)),
    kv("quiet", quietHint(deps.quietUntilMs(), now)),
    kv("feedback", feedbackHint(deps.feedbackMode())),
    kv("scan-error", scanErrorHint(deps.onScanError())),
    "",
    "Change a setting",
    "  /sentrook allow-all help",
    "  /sentrook quiet help",
    "  /sentrook sensitivity help",
    "  /sentrook feedback help",
    "  /sentrook scan-error help",
  ].join("\n");
}

function formatSessions(deps: SlashDeps): string {
  const now = deps.now();
  const rows = mergeSessionRows(
    deps.listHostSessions?.() ?? [],
    deps.listSessions().map((s) => ({
      sessionId: s.sessionId,
      sessionKey: s.sessionKey,
      allowAll: s.allowAll,
      quietUntilMs: s.quietUntilMs,
      attendedSensitivity: s.attendedSensitivity ?? null,
      unattendedSensitivity: s.unattendedSensitivity ?? null,
      pending: pendingRows(s).length,
    })),
  );
  if (rows.length === 0) {
    return "No OpenClaw sessions found.";
  }
  const table = formatPlainTable(
    ["name", "key", "id", "pending", "attended", "unattended", "allow-all", "quiet"],
    rows.map((s) => {
      const key = s.sessionKey ?? "—";
      const name = sessionDisplayName(s);
      return [
        name && name !== key ? name : "—",
        key,
        s.sessionId ?? "—",
        String(s.pending),
        sessionFloorLabel(s.attendedSensitivity),
        sessionFloorLabel(s.unattendedSensitivity),
        s.allowAll ? "on" : "off",
        quietLeftLabel(s.quietUntilMs, now),
      ];
    }),
  );
  return [
    "OpenClaw sessions",
    "",
    "Use the key column with:",
    "  /sentrook sensitivity session <key> attended|unattended <level|default>",
    "  /sentrook quiet session <key> 30m|off",
    "  /sentrook allow-all session <key> on|off",
    "",
    table,
  ].join("\n");
}

function verbHelp(cmd: string, deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  const now = deps.now();
  const mode = gatewayAllowAllMode(deps);
  switch (cmd) {
    case "status":
      return [
        "Usage: /sentrook status",
        "",
        "Shows current config settings and policies for this chat and the gateway. Does not list pending reviews.",
        "",
        formatStatus(deps, ids, session),
      ].join("\n");
    case "policy":
      return [
        "Usage: /sentrook policy",
        "",
        "All settings, with a short explanation of the current choice.",
        "Use the commands below to change a value.",
        "",
        formatPolicyShow(deps, ids, session),
      ].join("\n");
    case "pending":
      return [
        "Usage: /sentrook pending [all | <id>]",
        "",
        "Reviews waiting on you.",
        "",
        "  (default)   This chat. One review is shown in full; two or more is a list.",
        "  all         Every session on this gateway.",
        "  <id>        Full command, why it was flagged, and /approve lines when known.",
        "",
        OPEN_CARDS,
        `This session: ${pendingRows(session).length} pending.`,
      ].join("\n");
    case "history":
      return [
        "Usage: /sentrook history [all | gateway | before <id> | n | <id>]",
        "",
        "Newest first. 8 per reply, 20 max. Reads the local operator log on this host.",
        "",
        "  (default)     Reviews, blocks, and scan errors in this chat.",
        "  all           Every scan in this chat, including allows.",
        "  gateway       Same as default, across every session (cron, other chats, subagents). Never includes allows.",
        "  before <id>   Older than that row, same filters.",
        "  <id>          Full detail for one event (any session).",
        "  n             Page size (1–20).",
      ].join("\n");
    case "sessions":
      return [
        "Usage: /sentrook sessions",
        "",
        "OpenClaw sessions with Sentrook floors and quiet.",
        "Pass the key column to sensitivity session <key>, quiet session <key>, and allow-all session <key>.",
        "",
        formatSessions(deps),
      ].join("\n");
    case "allow-all":
    case "allowall":
      return [
        "Usage:",
        "  /sentrook allow-all [on | off]                 this session (bare = on)",
        "  /sentrook allow-all all [on | off]              every attended session",
        "  /sentrook allow-all session <key> [on | off]   one live session",
        "",
        SKIP_FUTURE,
        "Turning all off also clears every session flag.",
        "A session allow-all or quiet flag clears when that session ends.",
        "Sessions with their own attended floor ignore allow-all.",
        OPEN_CARDS,
        "",
        `Now: gateway ${deps.allowAll() ? "on" : "off"}; this session ${session.allowAll ? "on" : "off"}.`,
        allowAllHint(mode),
      ].join("\n");
    case "quiet":
      return [
        "Usage:",
        "  /sentrook quiet <duration | off>                 this session",
        "  /sentrook quiet all <duration | off>              every attended session",
        "  /sentrook quiet session <key> <duration | off>   one live session",
        "",
        "Same skip as allow-all, with a timer (30m, 2h, 8h max). Attended only.",
        "Sessions with their own attended floor ignore quiet.",
        OPEN_CARDS,
        "",
        `Now: gateway ${quietLeftLabel(deps.quietUntilMs(), now)}; this session ${quietLeftLabel(session.quietUntilMs, now)}.`,
        quietHint(deps.quietUntilMs(), now),
      ].join("\n");
    case "sensitivity":
      return [
        "Usage:",
        "  /sentrook sensitivity [attended | unattended] [strict | info | warning | critical] [confirm]",
        "  /sentrook sensitivity session <key> attended|unattended <level | default> [confirm]",
        "",
        "Each level includes every lower one. Blocks and scan errors still stop.",
        "critical needs a trailing confirm. lenient is an alias for info.",
        "default on a session inherits the matching global floor.",
        "A set attended floor overrides global attended, allow-all, and quiet for that session.",
        "",
        "If SENTROOK_SENSITIVITY or SENTROOK_UNATTENDED_SENSITIVITY is set, it",
        "overrides the global floor after a restart. Session floors still apply.",
        "",
        "Now",
        kv("attended", deps.sensitivity()),
        kv("unattended", deps.unattendedSensitivity()),
        kv("this session attended", sessionFloorLabel(session.attendedSensitivity)),
        kv("this session unattended", sessionFloorLabel(session.unattendedSensitivity)),
        "",
        "What this means",
        kv("attended", sensitivityHint("attended", deps.sensitivity())),
        kv("unattended", sensitivityHint("unattended", deps.unattendedSensitivity())),
      ].join("\n");
    case "feedback":
      return [
        "Usage: /sentrook feedback [submit | off]",
        "",
        "Whether sanitized allow-once and deny reviews are posted to the community corpus.",
        "",
        "Now",
        kv("feedback", deps.feedbackMode()),
        "",
        feedbackHint(deps.feedbackMode()),
      ].join("\n");
    case "scan-error":
    case "scanerror":
      return [
        "Usage: /sentrook scan-error [review | deny | allow] [confirm]",
        "",
        "What happens when Sentrook cannot scan. Auth failures still block.",
        "allow needs a trailing confirm.",
        "",
        "Now",
        kv("scan-error", deps.onScanError()),
        "",
        scanErrorHint(deps.onScanError()),
      ].join("\n");
    case "allowlist": {
      const path = deps.allowlist.path || resolveAllowlistCliPath();
      const n = loadAllowlist(path).entries.length;
      return [
        "Usage:",
        "  /sentrook allowlist                 list",
        "  /sentrook allowlist add <id>       trust the command from a history event",
        "  /sentrook allowlist rm <n>         remove the 1-based index from the list",
        "",
        "After you allow-always or allowlist add, matching calls skip the prompt.",
        "They are still scanned. Blocks always win. Cron reviews cannot wait on a",
        "card (OpenClaw has no plugin-approval surface for scheduled runs); add the",
        "history id from the block message, then re-run the job.",
        "",
        "Command match",
        "  Same tool and argument shape. Dates, UUIDs, and numbers may change.",
        "  curl/wget keep the host and path (query string may change). A different",
        "  host or path is a different match. A new flag or binary is too.",
        "",
        "Script match",
        "  Interpreter, file path, and a content hash. Editing the file breaks the match.",
        "  Does not cover inline -c or curl | bash.",
        "",
        "Not stored: pipes, curl|bash, and a bare curl/wget with no URL.",
        "",
        "Now",
        kv("entries", String(n)),
        kv("path", path),
      ].join("\n");
    }
    case "log": {
      const log = deps.operatorLog();
      const stats = operatorLogStats(log);
      return [
        "Usage:",
        "  /sentrook log                              stats",
        "  /sentrook log retention <days | size>     e.g. 14, 7d, 32MiB",
        "  /sentrook log purge confirm                  drop lines older than retention",
        "  /sentrook log purge all confirm              delete the log",
        "",
        "A local history file on this host. Never uploaded. /sentrook history",
        "and the dashboard timeline read it.",
        "",
        "To turn off: SENTROOK_OPERATOR_LOG=0  (scans still run; history is empty after a restart)",
        "",
        "Now",
        kv("log", log.enabled ? "on" : "off"),
        kv("path", stats.path),
        kv("size", `${formatBytes(stats.bytes)}, ${stats.lines} lines`),
        kv("keep", `${log.maxAgeDays}d, rotate ${formatBytes(log.maxBytes)}`),
      ].join("\n");
    }
    default:
      return HELP_TEXT;
  }
}

function pendingCallFromCard(card: SlashCard): SlashPendingCall {
  return { tool: card.tool, args: card.args, awaitingApproval: true, eventId: card.eventId };
}

function formatPendingShort(
  items: Array<{
    eventId?: string;
    tool: string;
    args: Record<string, unknown>;
    sessionKey?: string;
    severity?: string;
  }>,
  scope: string,
  sessionColumn: boolean,
): string {
  const headers = sessionColumn
    ? ["id", "session", "sev", "tool", "command"]
    : ["id", "sev", "tool", "command"];
  const table = formatPlainTable(
    headers,
    items.map((c) => {
      const command = leadIn(scrubbedCommand(c.args), 48);
      const sev = c.severity || "—";
      return sessionColumn
        ? [c.eventId || "—", c.sessionKey ?? "—", sev, c.tool, command]
        : [c.eventId || "—", sev, c.tool, command];
    }),
  );
  const inspect = items
    .map((c) => pendingInspect(c.eventId))
    .filter((cmd, i, all) => cmd !== "/sentrook pending" && all.indexOf(cmd) === i);
  return [
    `Pending reviews (${items.length}) — ${scope}`,
    "",
    table,
    "",
    "Inspect one:",
    ...inspect.map((cmd) => `  ${cmd}`),
    "",
    OPEN_CARDS,
  ].join("\n");
}

function formatPendingList(deps: SlashDeps, session: SlashSession): string {
  const rows = pendingRows(session);
  if (rows.length === 0) {
    return "No pending reviews in this session.\n" + OPEN_CARDS;
  }
  if (rows.length === 1) return pendingDetail(deps, rows[0]!, session);
  return formatPendingShort(
    rows.map((call) => ({
      eventId: call.eventId,
      tool: call.tool,
      args: call.args,
      sessionKey: session.sessionKey,
      severity: scanSeverity(pendingScanOf(deps, call)),
    })),
    "this session",
    false,
  );
}

function formatPendingAll(deps: SlashDeps): string {
  const cards = deps.listCards?.() ?? [];
  const fromSessions =
    cards.length > 0
      ? cards.map((c) => ({
          eventId: c.eventId,
          tool: c.tool,
          args: c.args,
          sessionKey: c.sessionKey ?? c.sessionId,
          severity: scanSeverity(c.scan),
        }))
      : deps.listSessions().flatMap((s) =>
          pendingRows(s).map((call) => ({
            eventId: call.eventId ?? "",
            tool: call.tool,
            args: call.args,
            sessionKey: s.sessionKey,
            severity: scanSeverity(pendingScanOf(deps, call)),
          })),
        );
  if (fromSessions.length === 0) {
    return "No pending reviews on this gateway.\n" + OPEN_CARDS;
  }
  if (fromSessions.length === 1) {
    const only = fromSessions[0]!;
    const card = cards.find((c) => c.eventId === only.eventId);
    const session = deps
      .listSessions()
      .find((s) => s.sessionKey === only.sessionKey || pendingRows(s).some((c) => c.eventId === only.eventId));
    return pendingDetail(deps, card ? pendingCallFromCard(card) : { ...only, awaitingApproval: true }, session);
  }
  const shown = fromSessions.slice(0, PENDING_ALL_CAP);
  const extra =
    fromSessions.length > PENDING_ALL_CAP ? `\n… ${fromSessions.length - PENDING_ALL_CAP} more` : "";
  return `${formatPendingShort(shown, "across sessions", true)}${extra}`;
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

function findPendingAnywhere(
  deps: SlashDeps,
  id: string,
): { call: SlashPendingCall; session?: SlashSession } | undefined {
  const inSession = (s: SlashSession) => {
    const hit = findPending(s, id);
    return hit ? { call: hit.call, session: s } : undefined;
  };
  for (const s of deps.listSessions()) {
    const hit = inSession(s);
    if (hit) return hit;
  }
  const needle = id.trim().toLowerCase();
  const card = deps.listCards?.().find(
    (c) =>
      c.eventId.toLowerCase() === needle ||
      c.eventId.toLowerCase().startsWith(needle) ||
      c.toolCallId.toLowerCase() === needle,
  );
  if (!card) return undefined;
  return { call: pendingCallFromCard(card) };
}

function pendingDetail(deps: SlashDeps, call: SlashPendingCall, session?: SlashSession): string {
  const card = lookupPendingCard(deps, call);
  const scan = pendingScanOf(deps, call);
  const id = call.eventId ?? "(no id)";
  const severity = scan?.review_severity?.trim() || scan?.decision?.trim();
  const risk = riskLine(scan?.risk);
  const why = scanWhy(scan);
  const kind = intentKindLabel(card?.intentKind);
  const intent = card?.intent?.trim();
  const intentLine = intent ? (kind ? `${kind} — ${intent}` : intent) : kind || undefined;
  const sessionLine = pendingSessionLine(deps, call, session);
  const facts = [
    kv("Tool", call.tool),
    sessionLine ? kv("Session", sessionLine) : undefined,
    severity ? kv("Severity", severity) : undefined,
    risk ? kv("Risk", risk) : undefined,
    why.length ? kv("Why", why[0]!) : undefined,
    ...why.slice(1).map((line) => kv("", line)),
    intentLine ? kv("Intent", leadIn(intentLine, 120)) : undefined,
  ].filter((line): line is string => Boolean(line));
  const once = approveOnce(card?.approvalId);
  const always = approveAlways(card?.approvalId);
  const deny = approveDeny(card?.approvalId);
  const decide =
    once && always && deny
      ? ["Decide", `  ${once}`, `  ${always}`, `  ${deny}`]
      : [
          "No /approve id yet. Use the approval card in chat, or Allow / Deny on the Sentrook page.",
          `Inspect: ${pendingInspect(call.eventId)}`,
        ];
  return [
    `Pending review  ${id}`,
    "",
    ...facts,
    "",
    "Command",
    fence(scrubbedCommand(call.args)),
    "",
    ...decide,
    "",
    OPEN_CARDS,
  ].join("\n");
}

function handleLog(deps: SlashDeps, rest: string): string {
  const { cmd, rest: tail } = firstToken(rest);
  const log = deps.operatorLog();
  if (!cmd) {
    const stats = operatorLogStats(log);
    return [
      "Operator log",
      "",
      kv("status", log.enabled ? "on" : "off"),
      kv("path", stats.path),
      kv("size", `${formatBytes(stats.bytes)} / ${formatBytes(log.maxBytes)} (${stats.lines} lines)`),
      kv("oldest", stats.oldestTs ?? "(empty)"),
      kv("newest", stats.newestTs ?? "(empty)"),
      kv("retention", `${log.maxAgeDays} days, rotate at ${formatBytes(log.maxBytes)}`),
    ].join("\n");
  }
  if (cmd === "retention") {
    return handleLogRetention(deps, tail);
  }
  if (cmd === "purge") {
    return handleLogPurge(deps, tail);
  }
    return "Usage: /sentrook log [retention <days | size> | purge [all] confirm]\nTry: /sentrook log help.";
}

function parseRetention(raw: string): { maxAgeDays?: number; maxBytes?: number } | { error: string } {
  const n = raw.trim().toLowerCase();
  if (!n) {
    return { error: "Usage: /sentrook log retention <days | size>   e.g. 14, 7d, 32MiB" };
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
  const parts = [`Retention updated. ${savedLine(result)}`];
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
      ? "This deletes the log. Re-run: /sentrook log purge all confirm"
      : `This drops lines older than ${log.maxAgeDays} days. Re-run: /sentrook log purge confirm`;
  }
  if (all) {
    const dropped = wipeOperatorLog(log);
    return `Purged the log (${dropped} lines removed).`;
  }
  const dropped = purgeOperatorLog(log);
  return dropped === 0
    ? "Nothing to purge (no lines older than retention)."
    : `Purged ${dropped} line${dropped === 1 ? "" : "s"} older than ${log.maxAgeDays} days.`;
}

function handleAllowlist(deps: SlashDeps, rest: string): string {
  const { cmd, rest: tail } = firstToken(rest);
  const path = deps.allowlist.path || resolveAllowlistCliPath();
  if (!cmd) return formatAllowlistList(path);
  if (cmd === "add") {
    if (!tail || !isHistoryEventId(tail.split(/\s+/)[0] ?? "")) {
      return "Usage: /sentrook allowlist add <id>   (id from /sentrook history)";
    }
    const id = tail.split(/\s+/)[0] ?? "";
    return addAllowlistFromHistory(deps.operatorLog(), deps.allowlist, id).message;
  }
  if (cmd === "rm" || cmd === "remove") {
    const n = Number.parseInt(tail, 10);
    if (!Number.isFinite(n) || n < 1) {
      return "Usage: /sentrook allowlist rm <n>   (1-based index from the list)";
    }
    return removeAllowlistEntry(path, n);
  }
  return "Usage: /sentrook allowlist [add <id> | rm n]\nTry: /sentrook allowlist help.";
}

function removeAllowlistEntry(path: string, index1: number): string {
  const file = loadAllowlist(path);
  if (index1 > file.entries.length) {
    return `No allowlist entry ${index1} (${file.entries.length} stored).`;
  }
  const removed = file.entries.splice(index1 - 1, 1)[0];
  saveAllowlist(path, file);
  const kind =
    removed?.kind === "script_bind" ? "script" : removed?.kind === "skeleton" ? "command" : "entry";
  const label =
    removed?.kind === "script_bind"
      ? `${removed.interpreter} ${removed.script_path}`
      : removed?.kind === "skeleton"
        ? removed.skeleton
        : "entry";
  return `Removed [${index1}] ${kind} ${leadIn(label, 80)}`;
}

function historyDetail(log: OperatorLogConfig, id: string): string {
  const events = queryOperatorLog(log);
  const hit = findHistoryCursor(events, id);
  if (!hit) return `No log event matching ${id}.`;
  const outcomes = scanOutcomeIndex(events);
  const scan =
    isScanLike(hit)
      ? hit
      : events.find((event) => isScanLike(event) && operatorJoinKey(event) === operatorJoinKey(hit));
  const page = scan ?? hit;
  return formatEventDetail(page, outcomes.get(operatorJoinKey(page)));
}

function handleHistory(deps: SlashDeps, ids: SessionIds, rest: string): string {
  const log = deps.operatorLog();
  if (!log.enabled) {
    return "History is off (SENTROOK_OPERATOR_LOG=0). Nothing to list.";
  }
  const parsed = parseHistoryRest(rest);
  if (parsed.kind === "error") return parsed.error;
  if (parsed.kind === "id") return historyDetail(log, parsed.id);

  const query = parsed.query;
  const filter = query.gateway ? {} : sessionQuery(ids);
  const unscoped = !query.gateway && !filter.sessionId && !filter.sessionKey;
  const events = queryOperatorLog(log, unscoped || query.gateway ? {} : filter);
  const outcomes = scanOutcomeIndex(events);
  const scans = events.filter(isScanLike);
  const interesting = scans.filter((event) => query.includeAll || isDefaultHistoryEvent(event));
  let window = interesting;
  if (query.beforeId) {
    const cursor = findHistoryCursor(scans, query.beforeId);
    if (!cursor) {
      return `No history event matching ${query.beforeId} in this view. Try /sentrook history ${query.beforeId}.`;
    }
    const idx = interesting.findIndex((event) => event.id === cursor.id);
    window = idx >= 0 ? interesting.slice(idx + 1) : interesting.filter((event) => event.ts < cursor.ts);
  }
  const slice = window.slice(0, query.page);
  const scope = query.gateway
    ? "every session"
    : query.includeAll
      ? "this chat, including allows"
      : "this chat";
  if (slice.length === 0) {
    if (query.beforeId) return "No older events in this view.";
    return query.gateway
      ? "No reviews, blocks, or scan errors in the log."
      : query.includeAll
        ? "No scan events in the log for this chat."
        : "No reviews, blocks, or scan errors for this chat. Try /sentrook history all.";
  }
  const last = slice[slice.length - 1]!;
  const older = window.length > slice.length;
  const capped = query.askedPage != null && query.askedPage > HISTORY_PAGE_CAP;
  const lines = [
    `History — ${scope} — ${slice.length} newest${capped ? ` (max ${HISTORY_PAGE_CAP})` : ""}`,
    "",
    formatPlainTable(
      ["id", "time", "outcome", "tool", "command"],
      slice.map((event) => historyCells(event, outcomes.get(operatorJoinKey(event)), deps.now())),
    ),
    "",
    "Details: /sentrook history <id>",
  ];
  if (older) {
    lines.push(`… older: ${historyOlderCommand(query, last.id)}`);
  }
  return lines.join("\n");
}

function handlePending(deps: SlashDeps, session: SlashSession, rest: string): string {
  const id = rest.trim();
  if (!id) return formatPendingList(deps, session);
  if (id.toLowerCase() === "all") return formatPendingAll(deps);
  const local = findPending(session, id);
  if (local) return pendingDetail(deps, local.call, session);
  const found = findPendingAnywhere(deps, id);
  if (found) return pendingDetail(deps, found.call, found.session);
  const event = getOperatorLogEvent(deps.operatorLog(), id);
  if (event) {
    return ["Not waiting any more — from history.", "", historyDetail(deps.operatorLog(), id)].join("\n");
  }
  return `No pending review matching ${id}.`;
}

function applyAllowAll(target: SlashSession | "gateway", on: boolean, deps: SlashDeps): string {
  if (target === "gateway") {
    deps.setAllowAll(on);
    if (!on) {
      for (const st of deps.listSessions()) {
        st.allowAll = false;
        deps.syncSessionFlags?.(st);
      }
    }
    return on
      ? [
          "Allow-all on for every attended session.",
          "",
          SKIP_FUTURE,
          OPEN_CARDS,
          sessionFloorOverrideNote("attended"),
        ].join("\n")
      : "Allow-all off gateway-wide. Session allow-all flags cleared. Future reviews will prompt again.";
  }
  target.allowAll = on;
  deps.syncSessionFlags?.(target);
  return on
    ? [
        "Allow-all on for this session.",
        "",
        SKIP_FUTURE,
        OPEN_CARDS,
        "This session flag clears when the session ends.",
      ].join("\n")
    : "Allow-all off. Future reviews will prompt again.";
}

function handleAllowAll(deps: SlashDeps, session: SlashSession, rest: string): string {
  const { cmd, rest: tail } = firstToken(rest);
  if (cmd === "all" || cmd === "global" || cmd === "gateway") {
    const parsed = parseOnOff(tail, true);
    if (typeof parsed !== "boolean") return parsed.error;
    return applyAllowAll("gateway", parsed, deps);
  }
  if (cmd === "session") {
    const { cmd: key, rest: flag } = firstToken(tail);
    if (!key) return "Usage: /sentrook allow-all session <key> [on | off]";
    const named = findNamedSession(deps, key);
    if (!named) return `No live session matching ${key}.`;
    const parsed = parseOnOff(flag, true);
    if (typeof parsed !== "boolean") return parsed.error;
    named.allowAll = parsed;
    deps.syncSessionFlags?.(named);
    return parsed
      ? `Allow-all on for session ${sessionLabel(named)}. ${OPEN_CARDS}`
      : `Allow-all off for session ${sessionLabel(named)}.`;
  }
  const parsed = parseOnOff(rest, true);
  if (typeof parsed !== "boolean") return parsed.error;
  return applyAllowAll(session, parsed, deps);
}

function applyQuiet(target: SlashSession | "gateway", untilMs: number | null, deps: SlashDeps): string {
  if (target === "gateway") {
    deps.setQuietUntilMs(untilMs);
    if (untilMs == null) return "Quiet off gateway-wide. Future reviews will prompt again.";
    const left = formatDuration(quietRemainingMs(untilMs, deps.now()));
    return [
      `Quiet on for ${left} on every attended session.`,
      "",
      SKIP_FUTURE,
      OPEN_CARDS,
      sessionFloorOverrideNote("attended"),
    ].join("\n");
  }
  target.quietUntilMs = untilMs;
  deps.syncSessionFlags?.(target);
  if (untilMs == null) return "Quiet off. Future reviews will prompt again.";
  const left = formatDuration(quietRemainingMs(untilMs, deps.now()));
  return [
    `Quiet on for ${left} in this session.`,
    "",
    SKIP_FUTURE,
    OPEN_CARDS,
  ].join("\n");
}

function handleQuiet(deps: SlashDeps, session: SlashSession, rest: string): string {
  const { cmd, rest: tail } = firstToken(rest);
  if (cmd === "all" || cmd === "global" || cmd === "gateway") {
    const parsed = parseQuietDuration(tail, deps.now());
    if ("error" in parsed) return parsed.error;
    return applyQuiet("gateway", parsed.untilMs, deps);
  }
  if (cmd === "session") {
    const { cmd: key, rest: dur } = firstToken(tail);
    if (!key) return "Usage: /sentrook quiet session <key> <duration | off>";
    const named = findNamedSession(deps, key);
    if (!named) return `No live session matching ${key}.`;
    const parsed = parseQuietDuration(dur, deps.now());
    if ("error" in parsed) return parsed.error;
    named.quietUntilMs = parsed.untilMs;
    deps.syncSessionFlags?.(named);
    if (parsed.untilMs == null) return `Quiet off for session ${sessionLabel(named)}.`;
    const left = formatDuration(quietRemainingMs(parsed.untilMs, deps.now()));
    return `Quiet on for ${left} on session ${sessionLabel(named)}.`;
  }
  const parsed = parseQuietDuration(rest, deps.now());
  if ("error" in parsed) return parsed.error;
  return applyQuiet(session, parsed.untilMs, deps);
}

function handleSensitivity(deps: SlashDeps, rest: string): string {
  const { rest: withoutConfirm, confirm } = splitConfirm(rest);
  const { cmd: first, rest: tail } = firstToken(withoutConfirm);
  if (!first) {
    return [
      `Attended sensitivity: ${deps.sensitivity()}`,
      `Unattended sensitivity: ${deps.unattendedSensitivity()}`,
      "strict = prompt every review; info / warning / critical = auto-approve that severity and below.",
      "Per-session: /sentrook sensitivity session <key> attended|unattended <level|default>",
    ].join("\n");
  }
  if (first === "session") {
    return handleSessionSensitivity(deps, tail, confirm);
  }
  const scoped = first === "attended" || first === "unattended";
  const scope = scoped ? first : "attended";
  const token = scoped ? tail : withoutConfirm;
  if (!token) {
    const current = scope === "unattended" ? deps.unattendedSensitivity() : deps.sensitivity();
    return `${scope === "unattended" ? "Unattended" : "Attended"} sensitivity: ${current}`;
  }
  const value = parseSensitivityToken(token);
  if (!value) {
    return "Usage: /sentrook sensitivity [attended | unattended] [strict | info | warning | critical]  (lenient = info)\nTry: /sentrook sensitivity help.";
  }
  if (value === "critical" && !confirm) {
    return scope === "unattended"
      ? "critical auto-approves every review on cron, heartbeat, and jobs they spawn. Re-run: /sentrook sensitivity unattended critical confirm"
      : "critical auto-approves every review while you are present. Re-run: /sentrook sensitivity critical confirm";
  }
  const result =
    scope === "unattended" ? deps.setUnattendedSensitivity(value) : deps.setSensitivity(value);
  const label = scope === "unattended" ? "Unattended" : "Attended";
  return `${label} sensitivity ${value}. ${savedLine(result)} Blocks and scan errors still stop. ${sessionFloorOverrideNote(scope)}`;
}

function handleSessionSensitivity(deps: SlashDeps, rest: string, confirm: boolean): string {
  const usage =
    "Usage: /sentrook sensitivity session <key> attended|unattended <strict | info | warning | critical | default>\nTry: /sentrook sensitivity help.";
  const { cmd: key, rest: afterKey } = firstToken(rest);
  if (!key) return usage;
  const named = resolveSessionByKey(deps, key);
  if (!named) return `No session matching ${key}.`;
  const { cmd: scopeToken, rest: levelToken } = firstToken(afterKey);
  if (!scopeToken) {
    return [
      `Session ${sessionLabel(named)}`,
      kv("attended", sessionFloorLine(named.attendedSensitivity, deps.sensitivity())),
      kv("unattended", sessionFloorLine(named.unattendedSensitivity, deps.unattendedSensitivity())),
    ].join("\n");
  }
  if (scopeToken !== "attended" && scopeToken !== "unattended") return usage;
  if (!levelToken) {
    const current =
      scopeToken === "unattended" ? named.unattendedSensitivity : named.attendedSensitivity;
    return `${scopeToken} floor for ${sessionLabel(named)}: ${sessionFloorLine(current, scopeToken === "unattended" ? deps.unattendedSensitivity() : deps.sensitivity())}`;
  }
  const parsed = parseSessionSensitivityToken(levelToken);
  if (parsed === undefined) return usage;
  if (parsed === "critical" && !confirm) {
    return scopeToken === "unattended"
      ? `critical auto-approves every unattended review in this session. Re-run: /sentrook sensitivity session ${sessionLabel(named)} unattended critical confirm`
      : "critical auto-approves every attended review in this session. Re-run: /sentrook sensitivity session " +
          `${sessionLabel(named)} attended critical confirm`;
  }
  if (scopeToken === "unattended") named.unattendedSensitivity = parsed;
  else named.attendedSensitivity = parsed;
  deps.syncSessionFlags?.(named);
  if (parsed == null) {
    return scopeToken === "unattended"
      ? `Unattended floor default for session ${sessionLabel(named)} (inherits global ${deps.unattendedSensitivity()}).`
      : `Attended floor default for session ${sessionLabel(named)} (inherits global ${deps.sensitivity()}). Allow-all and quiet apply again for attended runs in this session.`;
  }
  return scopeToken === "unattended"
    ? `Unattended floor ${parsed} for session ${sessionLabel(named)}. This overrides the global unattended floor for that session until you set default.`
    : `Attended floor ${parsed} for session ${sessionLabel(named)}. This overrides the global attended floor, allow-all, and quiet for that session until you set default.`;
}

function handleFeedback(deps: SlashDeps, rest: string): string {
  const token = rest.trim().toLowerCase();
  if (!token) {
    return `Feedback: ${deps.feedbackMode()}. ${feedbackHint(deps.feedbackMode())}`;
  }
  if (token !== "submit" && token !== "off") {
    return "Usage: /sentrook feedback [submit | off]\nTry: /sentrook feedback help.";
  }
  const result = deps.setFeedbackMode(token);
  return `Feedback ${token}. ${savedLine(result)} ${feedbackHint(token)}`;
}

function handleScanError(deps: SlashDeps, rest: string): string {
  const { rest: withoutConfirm, confirm } = splitConfirm(rest);
  const token = withoutConfirm.trim().toLowerCase();
  if (!token) {
    return `Scan-error: ${deps.onScanError()}. ${scanErrorHint(deps.onScanError())}`;
  }
  const value = parseOnScanError(token, deps.onScanError());
  if (token !== "review" && token !== "deny" && token !== "allow") {
    return "Usage: /sentrook scan-error [review | deny | allow]\nTry: /sentrook scan-error help.";
  }
  if (value === "allow" && !confirm) {
    return "allow continues tool calls without scanning when Sentrook is unreachable. Auth failures still block. Re-run: /sentrook scan-error allow confirm";
  }
  const result = deps.setOnScanError(value);
  return `Scan-error ${value}. ${savedLine(result)} ${scanErrorHint(value)}`;
}

function handleSentrookCommandSync(ctx: SlashCommandContext, deps: SlashDeps): SlashReply {
  if (ctx.senderIsOwner === false) {
    return { text: "/sentrook is owner-only." };
  }
  const ids = sessionIdsOf({ sessionId: ctx.sessionId, sessionKey: ctx.sessionKey });
  const session = deps.sessionOf(ids);
  if (ids.sessionId) session.sessionId = ids.sessionId;
  if (ids.sessionKey) session.sessionKey = ids.sessionKey;
  const { cmd, rest } = firstToken(ctx.args);

  if (!cmd) return { text: formatSnapshot(deps, ids, session) };
  if (cmd === "help") return { text: HELP_TEXT };

  if (VERB_HELP.has(cmd) && isHelpToken(rest)) {
    return { text: verbHelp(cmd, deps, ids, session) };
  }

  if (cmd === "status") return { text: formatStatus(deps, ids, session) };
  if (cmd === "policy") return { text: formatPolicyShow(deps, ids, session) };
  if (cmd === "sessions") return { text: formatSessions(deps) };
  if (cmd === "pending") return { text: handlePending(deps, session, rest) };
  if (cmd === "history") return { text: handleHistory(deps, ids, rest) };
  if (cmd === "log") return { text: handleLog(deps, rest) };
  if (cmd === "sensitivity") return { text: handleSensitivity(deps, rest) };
  if (cmd === "allow-all" || cmd === "allowall") return { text: handleAllowAll(deps, session, rest) };
  if (cmd === "quiet") return { text: handleQuiet(deps, session, rest) };
  if (cmd === "feedback") return { text: handleFeedback(deps, rest) };
  if (cmd === "scan-error" || cmd === "scanerror") return { text: handleScanError(deps, rest) };
  if (cmd === "allowlist") return { text: handleAllowlist(deps, rest) };

  return { text: `Unknown command: ${cmd}. Try /sentrook help.` };
}

export function handleSentrookCommand(
  ctx: SlashCommandContext,
  deps: SlashDeps,
): SlashReply | Promise<SlashReply> {
  const { cmd } = firstToken(ctx.args);
  if (deps.joinCards && (!cmd || cmd === "pending" || cmd === "status")) {
    return deps.joinCards().then(() => handleSentrookCommandSync(ctx, deps));
  }
  return handleSentrookCommandSync(ctx, deps);
}

export const SENTROOK_COMMAND_DEF = {
  name: SENTROOK_COMMAND_NAME,
  description: "Sentrook scan controls (snapshot, pending, policy, allow-all, quiet)",
  acceptsArgs: true,
  requireAuth: true,
  requiredScopes: ["operator.admin"],
};
