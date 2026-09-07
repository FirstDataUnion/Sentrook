/**
 * ``/sentrook`` chat command family (OpenClaw ``api.registerCommand``).
 *
 * Owner-only. Returns ``{ text }`` for the originating channel. Lists stay
 * short; ``pending <id>`` / ``history <id>`` reconstruct the review (command,
 * (no AIRA ids, no tool results).
 */

import {
  formatAllowlistList,
  resolveAllowlistCliPath,
} from "./allowlistCli.ts";
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
  type FeedbackMode,
} from "./policyCopy.ts";
import { parseOnScanError, type OnScanError } from "./scanErrorPolicy.ts";
import {
  formatDuration,
  parseOnOff,
  parseQuietDuration,
  parseSensitivityToken,
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

const MORE_COMMANDS = "More commands: /sentrook help";
const SNAPSHOT_PENDING_CAP = 5;
const PENDING_ALL_CAP = 20;
const HISTORY_PAGE_DEFAULT = 8;
const HISTORY_PAGE_CAP = 20;
const HISTORY_USAGE =
  "Usage: /sentrook history [all|gateway|before <id>|n|id]. Try /sentrook history help.";

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
  listCards?: () => SlashCard[];
  sensitivity: () => Sensitivity;
  setSensitivity: (value: Sensitivity) => SlashPersistResult;
  unattendedSensitivity: () => Sensitivity;
  setUnattendedSensitivity: (value: Sensitivity) => SlashPersistResult;
  allowAll: () => boolean;
  setAllowAll: (value: boolean) => void;
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
  "Sentrook (owner-only). Each verb accepts `help` for options and current state.",
  "",
  "/sentrook                    snapshot (policy + pending)",
  "/sentrook help               this catalog",
  "/sentrook status             policy knobs (no pending list)",
  "/sentrook policy             all settings + current-choice lines",
  "/sentrook pending [all|id]   this session; all = gateway; <id> = full command",
  "/sentrook history [all|gateway|before <id>|n|id]  newest 8, max 20",
  "/sentrook sessions           live session allow-all / quiet",
  "/sentrook allow-all [all|session <key>] [on|off]",
  "/sentrook quiet [all|session <key>] <duration|off>",
  "/sentrook sensitivity [attended|unattended] [strict|info|warning|critical]",
  "/sentrook feedback [submit|off]",
  "/sentrook scan-error [review|deny|allow]",
  "/sentrook allowlist [rm n]",
  "/sentrook log [retention|purge]",
  "",
  "Allow-all and quiet skip future attended reviews only — already-open cards",
  "still need /approve. Unattended uses /sentrook sensitivity unattended.",
  "Block and scan errors are never skipped.",
  "",
  "Dashboard: /sentrook on this gateway (same port as Control UI, usually 18789).",
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
    ? "Saved in plugin config."
    : `Live until restart${result.error ? ` (${result.error})` : ""}.`;
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
  if (needle.length < 4) return undefined;
  return sessions.find((s) => s.sessionId?.toLowerCase().startsWith(needle));
}

function sessionLabel(session: SlashSession): string {
  return session.sessionKey || session.sessionId || "(unnamed)";
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
    case "allow-all-skip":
    case "allow-all":
      return "allow-all";
    case "allow-once":
    case "allow-always":
    case "deny":
    case "timeout":
    case "cancelled":
      return raw;
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
  if (hosted === "block" || hosted.startsWith("error") || then === "deny" || then === "timeout" || then === "cancelled") {
    return "no";
  }
  if (then === "allow-once" || then === "allow-always") return "yes";
  return "waiting";
}

function formatHistoryRow(event: OperatorLogEvent, outcome: ScanOutcome | undefined): string {
  const ts = event.ts.slice(11, 19) || event.ts;
  return `${ts}  ${listOutcome(event, outcome)}  ${eventTool(event)}  ${event.id}  ${leadIn(eventCommand(event) || "(no command)")}`;
}

function formatEventDetail(event: OperatorLogEvent, outcome: ScanOutcome | undefined = undefined): string {
  const hosted = eventDecision(event);
  const then = thenLabel(event, outcome);
  const thenLine =
    hosted === "review"
      ? then
        ? `then: ${then}${outcome?.labelSource ? ` (${outcome.labelSource})` : ""}`
        : "then: waiting"
      : then
        ? `then: ${then}${outcome?.labelSource ? ` (${outcome.labelSource})` : ""}`
        : undefined;
  const severity = (event.scan as { review_severity?: string } | undefined)?.review_severity;
  const hostedLine =
    hosted === "review" && typeof severity === "string" && severity.trim()
      ? `hosted: review (${severity.trim()})`
      : `hosted: ${hosted}`;
  const lines = [
    `${event.id}  ${event.ts}  ${eventTool(event)}`,
    hostedLine,
    thenLine,
    `ran: ${ranLabel(event, outcome)}`,
    "",
    eventCommand(event) || "(no command)",
    "",
    CHANNEL_DISCLOSURE,
  ].filter((line): line is string => line != null);
  return lines.join("\n");
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
  return [
    `session_id: ${ids.sessionId ?? "(none)"}`,
    `session_key: ${ids.sessionKey ?? "(none)"}`,
    `attended sensitivity: ${deps.sensitivity()}`,
    `unattended sensitivity: ${deps.unattendedSensitivity()}`,
    `allow-all gateway: ${deps.allowAll() ? "on" : "off"} (in-memory)`,
    `allow-all this session: ${session.allowAll ? "on" : "off"} (in-memory)`,
    `quiet gateway: ${globalQuiet > 0 ? `on (${formatDuration(globalQuiet)} left)` : "off"} (in-memory)`,
    `quiet this session: ${sessionQuiet > 0 ? `on (${formatDuration(sessionQuiet)} left)` : "off"} (in-memory)`,
    `feedback: ${deps.feedbackMode()}`,
    `scan-error: ${deps.onScanError()}`,
    `operator log: ${log.enabled ? "on" : "off"}  ${stats.path}`,
    `  ${formatBytes(stats.bytes)}, ${stats.lines} lines, last ${lastLine}`,
  ];
}

function formatSnapshot(deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  const rows = pendingRows(session);
  const leads = rows.slice(0, SNAPSHOT_PENDING_CAP).map((call) => {
    const id = call.eventId ?? "(no id)";
    return `  ${id}  ${call.tool}  ${leadIn(scrubbedCommand(call.args), 56)}`;
  });
  const extra = rows.length > SNAPSHOT_PENDING_CAP ? `  … ${rows.length - SNAPSHOT_PENDING_CAP} more` : "";
  const pendingBlock =
    rows.length === 0
      ? ["pending reviews: 0"]
      : [`pending reviews: ${rows.length}`, ...leads, extra].filter(Boolean);
  return [
    "Sentrook",
    ...formatPolicyBlock(deps, ids, session),
    ...pendingBlock,
    `dashboard: /sentrook on this gateway`,
    MORE_COMMANDS,
  ].join("\n");
}

function formatStatus(deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  return ["Sentrook status", ...formatPolicyBlock(deps, ids, session), `dashboard: /sentrook on this gateway`].join(
    "\n",
  );
}

function formatPolicyShow(deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  const now = deps.now();
  const mode = gatewayAllowAllMode(deps);
  return [
    "Sentrook policy",
    ...formatPolicyBlock(deps, ids, session),
    "",
    `attended: ${sensitivityHint("attended", deps.sensitivity())}`,
    `unattended: ${sensitivityHint("unattended", deps.unattendedSensitivity())}`,
    `allow-all: ${allowAllHint(mode)}`,
    `quiet: ${quietHint(deps.quietUntilMs(), now)}`,
    `feedback: ${feedbackHint(deps.feedbackMode())}`,
    `scan-error: ${scanErrorHint(deps.onScanError())}`,
    "",
    "Deep pages: /sentrook allow-all help, quiet help, sensitivity help, feedback help, scan-error help.",
  ].join("\n");
}

function formatSessions(deps: SlashDeps): string {
  const now = deps.now();
  const rows = deps.listSessions();
  if (rows.length === 0) {
    return "No live sessions.";
  }
  const lines = [
    "Live sessions",
    "key  id  pending  allow-all  quiet",
    ...rows.map((s) => {
      const pending = pendingRows(s).length;
      const quiet = quietLeftLabel(s.quietUntilMs, now);
      return `${s.sessionKey ?? "—"}  ${s.sessionId ?? "—"}  ${pending}  ${s.allowAll ? "on" : "off"}  ${quiet}`;
    }),
    "",
    "/sentrook allow-all session <key> on|off    /sentrook quiet session <key> 30m|off",
  ];
  return lines.join("\n");
}

function verbHelp(cmd: string, deps: SlashDeps, ids: SessionIds, session: SlashSession): string {
  const now = deps.now();
  const mode = gatewayAllowAllMode(deps);
  switch (cmd) {
    case "status":
      return [
        "Usage: /sentrook status",
        "Policy knobs for this chat and the gateway (no pending list). Bare /sentrook adds pending.",
        "",
        formatStatus(deps, ids, session),
      ].join("\n");
    case "policy":
      return [
        "Usage: /sentrook policy",
        "All settings with the current-choice lines from the dashboard. Setters stay on the verbs below.",
        "",
        formatPolicyShow(deps, ids, session),
      ].join("\n");
    case "pending":
      return [
        "Usage: /sentrook pending [all|id]",
        "Short list of hosted reviews waiting on a human. <id> posts the full scrubbed command.",
        "all = every session on this gateway. Default is this session.",
        "Already-open cards still need /approve. Allow-all/quiet do not close them.",
        `This session: ${pendingRows(session).length} pending.`,
      ].join("\n");
    case "history":
      return [
        "Usage: /sentrook history [all|gateway|before <id>|n|id]",
        "Newest first, 8 per reply (max 20). Default = review/block/scan-error for this session.",
        "all = every scan in this session (includes allows). gateway = interesting events across sessions.",
        "before <id> = older than that row. <id> = hosted decision, what happened next, whether it ran, full command.",
        "Lists never include rule ids. Not a dump of the dashboard timeline.",
      ].join("\n");
    case "sessions":
      return [
        "Usage: /sentrook sessions",
        "Live sessions and their in-memory allow-all / quiet flags (dashboard Per session table).",
        "Set with /sentrook allow-all session <key> on|off and /sentrook quiet session <key> 30m|off.",
        "",
        formatSessions(deps),
      ].join("\n");
    case "allow-all":
    case "allowall":
      return [
        "Allow-all skips future hosted reviews (still scanned). Never skips block, scan errors, or unattended runs.",
        "In-memory: gateway restart clears gateway flags; session_end clears that session. Cards already waiting still need /approve.",
        "",
        "Usage:",
        "  /sentrook allow-all [on|off]                 this session (bare = on)",
        "  /sentrook allow-all all [on|off]             gateway-wide; off also clears every session flag",
        "  /sentrook allow-all session <key> [on|off]   one live session",
        "",
        `Now: gateway ${deps.allowAll() ? "on" : "off"}; this session ${session.allowAll ? "on" : "off"}.`,
        allowAllHint(mode),
      ].join("\n");
    case "quiet":
      return [
        "Quiet is the same skip as allow-all, with a TTL (30m, 2h, 8h max). Attended only. In-memory.",
        "",
        "Usage:",
        "  /sentrook quiet <duration|off>                 this session",
        "  /sentrook quiet all <duration|off>             gateway-wide",
        "  /sentrook quiet session <key> <duration|off>   one live session",
        "",
        `Now: gateway ${quietLeftLabel(deps.quietUntilMs(), now)}; this session ${quietLeftLabel(session.quietUntilMs, now)}.`,
        quietHint(deps.quietUntilMs(), now),
      ].join("\n");
    case "sensitivity":
      return [
        "Persisted review floors after hosted review. Each step includes every lower level. Blocks and scan errors still stop.",
        "Environment SENTROOK_SENSITIVITY / SENTROOK_UNATTENDED_SENSITIVITY still win after a restart.",
        "critical requires a trailing confirm.",
        "",
        "Usage: /sentrook sensitivity [attended|unattended] [strict|info|warning|critical] [confirm]",
        `lenient = info. Now: attended ${deps.sensitivity()}; unattended ${deps.unattendedSensitivity()}.`,
        "",
        `attended: ${sensitivityHint("attended", deps.sensitivity())}`,
        `unattended: ${sensitivityHint("unattended", deps.unattendedSensitivity())}`,
      ].join("\n");
    case "feedback":
      return [
        "Whether sanitized allow-once / deny reviews are posted to the community corpus. Persists in plugin config.",
        "",
        "Usage: /sentrook feedback [submit|off]",
        `Now: ${deps.feedbackMode()}. ${feedbackHint(deps.feedbackMode())}`,
      ].join("\n");
    case "scan-error":
    case "scanerror":
      return [
        "What happens if hosted /scan fails. Auth failures still block. allow requires a trailing confirm. Persists in plugin config.",
        "",
        "Usage: /sentrook scan-error [review|deny|allow] [confirm]",
        `Now: ${deps.onScanError()}. ${scanErrorHint(deps.onScanError())}`,
      ].join("\n");
    case "allowlist": {
      const path = deps.allowlist.path || resolveAllowlistCliPath();
      const n = loadAllowlist(path).entries.length;
      return [
        "Local short-circuit after a hosted review. Matching calls skip the prompt; they still go to /scan. Hosted blocks always win.",
        "",
        "Skeleton: same tool and argument shape. Volatile bits (dates, UUIDs, integers) may change. A new flag or a different binary is a different skeleton.",
        "Script bind: interpreter + path + content hash, plus a narrow args skeleton. Editing the file breaks the bind. Not inline -c / curl | bash.",
        "",
        "Usage: /sentrook allowlist            list",
        "       /sentrook allowlist rm <n>     remove 1-based index",
        `Now: ${n} ${n === 1 ? "entry" : "entries"} at ${path}`,
      ].join("\n");
    }
    case "log": {
      const log = deps.operatorLog();
      const stats = operatorLogStats(log);
      return [
        "Local JSONL on this host. Never uploaded. Timeline and /sentrook history read it.",
        "",
        "Usage: /sentrook log                         stats",
        "       /sentrook log retention <days|size>   e.g. 14, 7d, 32MiB  (persists)",
        "       /sentrook log purge confirm           drop lines older than retention",
        "       /sentrook log purge all confirm       delete the log files",
        "",
        `Now: ${log.enabled ? "on" : "off"}  ${stats.path}  ${formatBytes(stats.bytes)}, ${stats.lines} lines, keep ${log.maxAgeDays}d, rotate ${formatBytes(log.maxBytes)}.`,
      ].join("\n");
    }
    default:
      return HELP_TEXT;
  }
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

function formatPendingAll(deps: SlashDeps): string {
  const cards = deps.listCards?.() ?? [];
  if (cards.length === 0) {
    const fromSessions = deps.listSessions().flatMap((s) =>
      pendingRows(s).map((call) => ({
        eventId: call.eventId ?? "",
        tool: call.tool,
        args: call.args,
        sessionKey: s.sessionKey,
      })),
    );
    if (fromSessions.length === 0) {
      return "No pending Sentrook reviews on this gateway.\nAlready-open cards still need /approve.";
    }
    const shown = fromSessions.slice(0, PENDING_ALL_CAP);
    const extra = fromSessions.length > PENDING_ALL_CAP ? `\n… ${fromSessions.length - PENDING_ALL_CAP} more` : "";
    return [
      `Pending reviews (${fromSessions.length}) across sessions.`,
      ...shown.map(
        (c) => `${c.eventId || "—"}  ${c.sessionKey ?? "—"}  ${c.tool}  ${leadIn(scrubbedCommand(c.args), 48)}`,
      ),
      extra,
      "",
      "Use /sentrook pending <id> for the full command. Already-open cards still need /approve.",
      CHANNEL_DISCLOSURE,
    ]
      .filter((line) => line !== "")
      .join("\n");
  }
  const shown = cards.slice(0, PENDING_ALL_CAP);
  const extra = cards.length > PENDING_ALL_CAP ? `\n… ${cards.length - PENDING_ALL_CAP} more` : "";
  return [
    `Pending reviews (${cards.length}) across sessions.`,
    ...shown.map(
      (c) => `${c.eventId}  ${c.sessionKey ?? c.sessionId ?? "—"}  ${c.tool}  ${leadIn(scrubbedCommand(c.args), 48)}`,
    ),
    extra,
    "",
    "Use /sentrook pending <id> for the full command. Already-open cards still need /approve.",
    CHANNEL_DISCLOSURE,
  ]
    .filter((line) => line !== "")
    .join("\n");
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
  return {
    call: { tool: card.tool, args: card.args, awaitingApproval: true, eventId: card.eventId },
  };
}

function pendingDetail(call: SlashPendingCall): string {
  return [
    `${call.eventId ?? "(no id)"}  pending  ${call.tool}`,
    scrubbedCommand(call.args),
    "",
    "Already-open cards still need /approve. Allow-all/quiet do not close them.",
    CHANNEL_DISCLOSURE,
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
  return "Usage: /sentrook log [retention <days|size>|purge [all] confirm]. Try /sentrook log help.";
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
  return "Usage: /sentrook allowlist [rm n]. Try /sentrook allowlist help.";
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
    return "Operator log is off (SENTROOK_OPERATOR_LOG=0). History is empty.";
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
    ? "gateway"
    : query.includeAll
      ? "all scans this session"
      : "this session · review/block/scan-error";
  if (slice.length === 0) {
    if (query.beforeId) return "No older events in this view.";
    return query.gateway
      ? "No review/block/scan-error events in the operator log."
      : query.includeAll
        ? "No scan events in the operator log for this session."
        : "No review/block/scan-error events for this session. Try /sentrook history all.";
  }
  const last = slice[slice.length - 1]!;
  const older = window.length > slice.length;
  const capped = query.askedPage != null && query.askedPage > HISTORY_PAGE_CAP;
  const lines = [
    `History · ${scope} · newest first · ${slice.length}${capped ? ` (max ${HISTORY_PAGE_CAP})` : ""}`,
    ...slice.map((event) => formatHistoryRow(event, outcomes.get(operatorJoinKey(event)))),
    "",
    "Use /sentrook history <id> for what happened (command, decision, whether it ran).",
  ];
  if (older) {
    lines.push(`… older: ${historyOlderCommand(query, last.id)}`);
  }
  return lines.join("\n");
}

function handlePending(deps: SlashDeps, session: SlashSession, rest: string): string {
  const id = rest.trim();
  if (!id) return formatPendingList(session);
  if (id.toLowerCase() === "all") return formatPendingAll(deps);
  const local = findPending(session, id);
  if (local) return pendingDetail(local.call);
  const found = findPendingAnywhere(deps, id);
  if (found) return pendingDetail(found.call);
  const event = getOperatorLogEvent(deps.operatorLog(), id);
  if (event) return historyDetail(deps.operatorLog(), id);
  return `No pending review matching ${id}.`;
}

function applyAllowAll(target: SlashSession | "gateway", on: boolean, deps: SlashDeps): string {
  if (target === "gateway") {
    deps.setAllowAll(on);
    if (!on) {
      for (const st of deps.listSessions()) st.allowAll = false;
    }
    return on
      ? "Allow-all on for every attended session. Future hosted reviews skip the card (still scanned). Blocks, scan errors, and unattended runs are not skipped. Already-open cards still need /approve. Gateway restart clears this."
      : "Allow-all off gateway-wide. Session allow-all flags cleared. Future reviews will prompt again.";
  }
  target.allowAll = on;
  return on
    ? "Allow-all on for this session. Future hosted reviews skip the card (still scanned). Blocks, scan errors, and unattended runs are not skipped. Already-open cards still need /approve. Gateway restart or session end clears this."
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
    if (!key) return "Usage: /sentrook allow-all session <sessionKey> [on|off]";
    const named = findNamedSession(deps, key);
    if (!named) return `No live session matching ${key}.`;
    const parsed = parseOnOff(flag, true);
    if (typeof parsed !== "boolean") return parsed.error;
    named.allowAll = parsed;
    return parsed
      ? `Allow-all on for session ${sessionLabel(named)}. Already-open cards still need /approve.`
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
    return `Quiet on for ${left} on every attended session. Future hosted reviews skip the card (still scanned). Blocks, scan errors, and unattended runs are not skipped. Already-open cards still need /approve.`;
  }
  target.quietUntilMs = untilMs;
  if (untilMs == null) return "Quiet off. Future reviews will prompt again.";
  const left = formatDuration(quietRemainingMs(untilMs, deps.now()));
  return `Quiet on for ${left} in this session. Future hosted reviews skip the card (still scanned). Blocks, scan errors, and unattended runs are not skipped. Already-open cards still need /approve.`;
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
    if (!key) return "Usage: /sentrook quiet session <sessionKey> <duration|off>";
    const named = findNamedSession(deps, key);
    if (!named) return `No live session matching ${key}.`;
    const parsed = parseQuietDuration(dur, deps.now());
    if ("error" in parsed) return parsed.error;
    named.quietUntilMs = parsed.untilMs;
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
      "strict = prompt every review; info / warning / critical = auto-approve that severity and below, including hard reviews.",
    ].join("\n");
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
    return "Usage: /sentrook sensitivity [attended|unattended] [strict|info|warning|critical]  (lenient = info). Try /sentrook sensitivity help.";
  }
  if (value === "critical" && !confirm) {
    return scope === "unattended"
      ? "critical auto-approves every hosted review on cron/subagent runs. Re-run: /sentrook sensitivity unattended critical confirm"
      : "critical auto-approves every hosted review while you are present. Re-run: /sentrook sensitivity critical confirm";
  }
  const result =
    scope === "unattended" ? deps.setUnattendedSensitivity(value) : deps.setSensitivity(value);
  return `${scope === "unattended" ? "Unattended" : "Attended"} sensitivity ${value}. ${savedLine(result)} Hosted L2/L3 is unchanged.`;
}

function handleFeedback(deps: SlashDeps, rest: string): string {
  const token = rest.trim().toLowerCase();
  if (!token) {
    return `Feedback: ${deps.feedbackMode()}. ${feedbackHint(deps.feedbackMode())}`;
  }
  if (token !== "submit" && token !== "off") {
    return "Usage: /sentrook feedback [submit|off]. Try /sentrook feedback help.";
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
    return "Usage: /sentrook scan-error [review|deny|allow]. Try /sentrook scan-error help.";
  }
  if (value === "allow" && !confirm) {
    return "allow continues tool calls without scanning when Sentrook is unreachable. Auth failures still block. Re-run: /sentrook scan-error allow confirm";
  }
  const result = deps.setOnScanError(value);
  return `Scan-error ${value}. ${savedLine(result)} ${scanErrorHint(value)}`;
}

export function handleSentrookCommand(ctx: SlashCommandContext, deps: SlashDeps): SlashReply {
  if (ctx.senderIsOwner === false) {
    return { text: "⚠️ /sentrook is owner-only." };
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

  return { text: `Unknown /sentrook ${cmd}. Try /sentrook help.` };
}

export const SENTROOK_COMMAND_DEF = {
  name: SENTROOK_COMMAND_NAME,
  description: "Sentrook scan controls (snapshot, pending, policy, allow-all, quiet)",
  acceptsArgs: true,
  requireAuth: true,
  requiredScopes: ["operator.admin"],
};
