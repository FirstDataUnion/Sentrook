/**
 * Gateway HTTP panel at ``/sentrook`` (same port as Control UI).
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  listPluginApprovals,
  matchApprovalId,
  resolvePluginApproval,
  type PluginRuntimeGateway,
  type ResolveDecision,
} from "./approvalGateway.ts";
import { loadAllowlist, saveAllowlist, type AllowlistConfig } from "./localAllowlist.ts";
import {
  operatorLogStats,
  purgeOperatorLog,
  tailOperatorLog,
  wipeOperatorLog,
  DEFAULT_TIMELINE_SCAN_LIMIT,
  type OperatorLogConfig,
  type OperatorLogEvent,
} from "./operatorLog.ts";
import { renderDashboardPage } from "./dashboardPage.ts";
import { ReviewCardStore } from "./reviewCards.ts";
import { parseOnScanError, type OnScanError } from "./scanErrorPolicy.ts";
import {
  parseQuietDuration,
  parseSensitivityToken,
  type Sensitivity,
} from "./sessionPolicy.ts";
import { sessionIdsOf, type SessionIds } from "./sessionStore.ts";

export type DashboardFeedbackMode = "off" | "submit";
export type AllowAllMode = "off" | "session" | "on";

export const DASHBOARD_PATH = "/sentrook";

export type DashboardSession = {
  sessionId?: string;
  sessionKey?: string;
  allowAll: boolean;
  quietUntilMs: number | null;
  pending: Map<string, { awaitingApproval?: boolean }>;
};

export type DashboardSessionStore = {
  uniqueValues(): DashboardSession[];
  getOrCreate(ids: SessionIds, factory: () => DashboardSession): DashboardSession;
};

export type DashboardPersistResult = { persisted: boolean; error?: string };

export type DashboardDeps = {
  cards: ReviewCardStore;
  sessions: DashboardSessionStore;
  sessionFactory: () => DashboardSession;
  sensitivity: () => Sensitivity;
  setSensitivity: (value: Sensitivity) => DashboardPersistResult;
  unattendedSensitivity: () => Sensitivity;
  setUnattendedSensitivity: (value: Sensitivity) => DashboardPersistResult;
  allowAll: () => boolean;
  setAllowAll: (value: boolean) => void;
  quietUntilMs: () => number | null;
  setQuietUntilMs: (value: number | null) => void;
  feedbackMode: () => DashboardFeedbackMode;
  setFeedbackMode: (value: DashboardFeedbackMode) => DashboardPersistResult;
  onScanError: () => OnScanError;
  setOnScanError: (value: OnScanError) => DashboardPersistResult;
  operatorLog: () => OperatorLogConfig;
  setOperatorLogRetention: (patch: { maxAgeDays?: number; maxBytes?: number }) => DashboardPersistResult;
  allowlist: AllowlistConfig;
  gateway?: PluginRuntimeGateway;
  config?: unknown;
  now?: () => number;
};

function send(res: ServerResponse, status: number, body: string, type: string): void {
  res.statusCode = status;
  res.setHeader("content-type", type);
  res.setHeader("cache-control", "no-store");
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  send(res, status, JSON.stringify(body), "application/json; charset=utf-8");
}

function routePath(req: IncomingMessage): { rest: string; handled: boolean } {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  let pathname = url.pathname;
  if (pathname.length > 1 && pathname.endsWith("/")) pathname = pathname.slice(0, -1);
  if (pathname === DASHBOARD_PATH) return { rest: "", handled: true };
  if (pathname.startsWith(`${DASHBOARD_PATH}/`)) {
    return { rest: pathname.slice(DASHBOARD_PATH.length), handled: true };
  }
  // Host already stripped the /sentrook prefix (common for match: "prefix").
  if (pathname === "/" || pathname.startsWith("/api/")) {
    return { rest: pathname === "/" ? "" : pathname, handled: true };
  }
  return { rest: pathname, handled: false };
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  const parsed = JSON.parse(raw) as unknown;
  return parsed && typeof parsed === "object" && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

function parseAllowAllMode(raw: unknown): AllowAllMode | { error: string } | undefined {
  if (raw == null) return undefined;
  if (raw === "off" || raw === "session" || raw === "on") return raw;
  return { error: "allowAllMode must be off, session, or on" };
}

function parseFeedbackMode(raw: unknown): DashboardFeedbackMode | { error: string } | undefined {
  if (raw == null) return undefined;
  if (raw === "off" || raw === "submit") return raw;
  return { error: "feedbackMode must be submit or off" };
}

function parseRetentionDays(raw: unknown): number | { error: string } | undefined {
  if (raw == null) return undefined;
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw < 0 || raw > 3650) {
    return { error: "maxAgeDays must be an integer from 0 to 3650 (0 = no age purge)" };
  }
  return raw;
}

function parseRetentionBytes(raw: unknown): number | { error: string } | undefined {
  if (raw == null) return undefined;
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw < 1024 || raw > 1024 * 1024 * 1024) {
    return { error: "maxBytes must be between 1 KiB and 1 GiB" };
  }
  return Math.round(raw);
}

function foldPersist(
  acc: DashboardPersistResult | undefined,
  next: DashboardPersistResult,
): DashboardPersistResult {
  if (!acc) return { persisted: next.persisted, error: next.error };
  if (acc.persisted && next.persisted) return { persisted: true };
  return { persisted: false, error: acc.error || next.error };
}

function persistPayload(persist: DashboardPersistResult | undefined): {
  ok: true;
  persisted?: boolean;
  error?: string;
} {
  if (!persist) return { ok: true };
  if (persist.persisted) return { ok: true, persisted: true };
  return {
    ok: true,
    persisted: false,
    error: persist.error || "Applied now, but not saved to openclaw.json.",
  };
}

function eventCommand(event: OperatorLogEvent): string {
  const pending = event.pending as { args?: Record<string, unknown>; tool?: string } | undefined;
  const args = pending?.args ?? {};
  const command = args.command ?? args.cmd;
  if (typeof command === "string" && command.trim()) return command;
  try {
    return JSON.stringify(args);
  } catch {
    return "";
  }
}

function eventDecision(event: OperatorLogEvent): string {
  if (event.event === "scan_error") {
    return `error:${(event.scan_error as { kind?: string } | undefined)?.kind ?? "scan"}`;
  }
  return (event.scan as { decision?: string } | undefined)?.decision ?? event.event;
}

function eventTool(event: OperatorLogEvent): string {
  const tool = (event.pending as { tool?: string } | undefined)?.tool;
  return typeof tool === "string" ? tool : "tool";
}

const TIMELINE_LIMIT = DEFAULT_TIMELINE_SCAN_LIMIT;

function auditTone(decision: string): "allow" | "review" | "block" | "error" {
  if (decision.startsWith("error")) return "error";
  if (decision === "block") return "block";
  if (decision === "review") return "review";
  return "allow";
}

function joinKey(event: OperatorLogEvent): string {
  const meta = (event.metadata ?? {}) as { tool_call_id?: unknown };
  const tc = typeof meta.tool_call_id === "string" ? meta.tool_call_id.trim() : "";
  if (tc) return `tc:${tc}`;
  return `run:${event.run_id}`;
}

function metaSession(event: OperatorLogEvent): { sessionKey: string; sessionId: string } {
  const meta = (event.metadata ?? {}) as { session_id?: unknown; session_key?: unknown };
  const sessionKey = typeof meta.session_key === "string" ? meta.session_key : "";
  const sessionId = typeof meta.session_id === "string" ? meta.session_id : "";
  return { sessionKey: sessionKey || sessionId, sessionId };
}

function eventArgs(event: OperatorLogEvent): Record<string, unknown> | undefined {
  const args = (event.pending as { args?: unknown } | undefined)?.args;
  if (args && typeof args === "object" && !Array.isArray(args)) {
    return args as Record<string, unknown>;
  }
  return undefined;
}

function runFamily(runId: string): string {
  const i = runId.lastIndexOf(":");
  return i > 0 ? runId.slice(0, i) : runId;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
  return items.length ? items : undefined;
}

function buildTimeline(log: OperatorLogConfig) {
  const events = tailOperatorLog(log, { scanLimit: TIMELINE_LIMIT });
  const resolutions = new Map<string, { decision: string; ts: string; labelSource?: string }>();
  const results = new Map<
    string,
    {
      excerpt?: string;
      ok?: boolean;
      ts: string;
      byteSize?: number;
      truncated?: boolean;
      urls?: string[];
      paths?: string[];
      injectionMarkers?: boolean;
    }
  >();
  for (const event of events) {
    const key = joinKey(event);
    if (event.event === "resolution") {
      const decision = (event.resolution as { decision?: string } | undefined)?.decision;
      if (decision && !resolutions.has(key)) {
        resolutions.set(key, {
          decision,
          ts: event.ts,
          labelSource: asString(event.label_source),
        });
      }
    } else if (event.event === "result") {
      const result = event.result as
        | {
            excerpt?: string;
            ok?: boolean;
            byte_size?: number;
            extracted?: { urls?: unknown; paths?: unknown };
            flags?: { truncated?: boolean; injection_markers?: boolean };
          }
        | undefined;
      if (result && !results.has(key)) {
        results.set(key, {
          excerpt: result.excerpt,
          ok: result.ok,
          ts: event.ts,
          byteSize: asNumber(result.byte_size),
          truncated: result.flags?.truncated === true,
          urls: stringList(result.extracted?.urls),
          paths: stringList(result.extracted?.paths),
          injectionMarkers: result.flags?.injection_markers === true,
        });
      }
    }
  }
  const scans = events.filter((event) => event.event === "scan" || event.event === "scan_error");
  const audit = { scanned: 0, allow: 0, review: 0, block: 0, error: 0 };
  for (const event of scans) {
    audit.scanned += 1;
    audit[auditTone(eventDecision(event))] += 1;
  }
  const history = scans.map((event) => {
    const scan = event.scan as
      | {
          summary?: string | null;
          matched_rules?: string[];
          risk?: number | null;
          block_reason?: string | null;
          review_severity?: string | null;
          winning_rule_id?: string | null;
          log?: { winning_rule_id?: unknown };
        }
      | undefined;
    const err = event.scan_error as
      | { kind?: string; detail?: string | null; status?: number | null }
      | undefined;
    const hook = event.hook as { skip_reason?: string; allowlist_label?: string } | undefined;
    const key = joinKey(event);
    const joined = results.get(key);
    const resolved = resolutions.get(key);
    const { sessionKey, sessionId } = metaSession(event);
    const meta = (event.metadata ?? {}) as { agent_id?: unknown; step_seq?: unknown };
    const intent = typeof event.intent === "string" ? event.intent : null;
    const intentKind = typeof event.intent_kind === "string" ? event.intent_kind : null;
    const scannedTool = eventTool(event);
    const hostTool = asString(event.host_tool);
    return {
      id: event.id,
      ts: event.ts,
      event: event.event,
      decision: eventDecision(event),
      tool: scannedTool,
      hostTool: hostTool && hostTool !== scannedTool ? hostTool : undefined,
      command: eventCommand(event),
      args: eventArgs(event),
      summary: scan?.summary ?? undefined,
      matched_rules: scan?.matched_rules,
      winningRule: asString(scan?.winning_rule_id ?? scan?.log?.winning_rule_id),
      reviewSeverity: asString(scan?.review_severity ?? undefined),
      excerpt: joined?.excerpt,
      resultOk: joined?.ok,
      resultTs: joined?.ts,
      resultBytes: joined?.byteSize,
      resultTruncated: joined?.truncated,
      resultUrls: joined?.urls,
      resultPaths: joined?.paths,
      injectionMarkers: joined?.injectionMarkers,
      sessionKey,
      sessionId: sessionId || undefined,
      agentId: asString(meta.agent_id),
      risk: typeof scan?.risk === "number" ? scan.risk : undefined,
      blockReason: scan?.block_reason ?? undefined,
      intent,
      intentKind,
      resolution: resolved?.decision,
      resolutionTs: resolved?.ts,
      resolutionSource: resolved?.labelSource,
      errorKind: asString(err?.kind),
      errorDetail: err?.detail ?? undefined,
      errorStatus: asNumber(err?.status),
      unattended: event.unattended === true,
      labelSource: asString(event.label_source),
      skipReason: asString(hook?.skip_reason),
      allowlistLabel: asString(hook?.allowlist_label),
      effect: asString(event.effect),
      runId: event.run_id,
      stepSeq: asNumber(meta.step_seq),
      neighbors: [] as Array<{ id: string; tool: string; command: string }>,
    };
  });
  const families = new Map<string, typeof history>();
  for (const row of history) {
    const fam = runFamily(row.runId);
    const list = families.get(fam) ?? [];
    list.push(row);
    families.set(fam, list);
  }
  for (const row of history) {
    row.neighbors = (families.get(runFamily(row.runId)) ?? [])
      .filter((other) => other.id !== row.id && other.ts < row.ts)
      .sort((a, b) => a.ts.localeCompare(b.ts))
      .slice(0, 6)
      .map((other) => ({
        id: other.id,
        tool: other.tool,
        command: other.command,
      }));
  }
  return { history, audit };
}

async function buildState(deps: DashboardDeps) {
  const listed = await listPluginApprovals(deps.gateway);
  const pending = deps.cards.list().map((card) => {
    const args = card.args;
    const command =
      typeof args.command === "string"
        ? args.command
        : typeof args.cmd === "string"
          ? args.cmd
          : JSON.stringify(args);
    return {
      eventId: card.eventId,
      toolCallId: card.toolCallId,
      approvalId: matchApprovalId(listed, card.toolCallId),
      tool: card.tool,
      command,
      args: card.args,
      scan: card.scan,
      sessionId: card.sessionId,
      sessionKey: card.sessionKey,
      agentId: card.agentId,
      timeoutMs: card.timeoutMs,
      createdAtMs: card.createdAtMs,
      intent: card.intent ?? null,
      intentKind: card.intentKind ?? null,
      priorSteps: card.priorSteps ?? [],
      priorOmitted: card.priorOmitted ?? 0,
    };
  });
  const log = deps.operatorLog();
  const stats = operatorLogStats(log);
  const now = deps.now?.() ?? Date.now();
  const { history, audit } = buildTimeline(log);
  const sessions = deps.sessions.uniqueValues().map((st) => ({
    sessionId: st.sessionId,
    sessionKey: st.sessionKey,
    allowAll: st.allowAll,
    quietUntilMs: st.quietUntilMs,
    pending: [...st.pending.values()].filter((call) => call.awaitingApproval).length,
  }));
  const file = loadAllowlist(deps.allowlist.path);
  const allowlist = file.entries.map((entry, i) => {
    if (entry.kind === "script_bind") {
      return {
        index: i + 1,
        kind: entry.kind,
        tool: entry.tool,
        label: `${entry.interpreter} ${entry.script_path}`,
        detail: entry.args_skeleton,
        createdAt: entry.created_at,
      };
    }
    return {
      index: i + 1,
      kind: entry.kind,
      tool: entry.tool,
      label: entry.skeleton,
      createdAt: entry.created_at,
    };
  });
  const persistError: string[] = [];
  return {
    pending,
    history,
    audit,
    sessions,
    sensitivity: deps.sensitivity(),
    unattendedSensitivity: deps.unattendedSensitivity(),
    allowAll: deps.allowAll(),
    quietUntilMs: deps.quietUntilMs(),
    feedbackMode: deps.feedbackMode(),
    onScanError: deps.onScanError(),
    log: {
      enabled: log.enabled,
      path: stats.path,
      bytes: stats.bytes,
      lines: stats.lines,
      maxAgeDays: log.maxAgeDays,
      maxBytes: log.maxBytes,
    },
    allowlist,
    resolveAvailable: Boolean(deps.gateway) || pending.some((card) => card.approvalId),
  };
}

export async function handleSentrookHttp(
  req: IncomingMessage,
  res: ServerResponse,
  deps: DashboardDeps,
): Promise<boolean> {
  const { rest, handled } = routePath(req);
  if (!handled) {
    return false;
  }
  const method = (req.method ?? "GET").toUpperCase();
  try {
    if (method === "GET" && (rest === "" || rest === "/")) {
      const state = await buildState(deps);
      send(res, 200, renderDashboardPage(state, deps.now?.() ?? Date.now()), "text/html; charset=utf-8");
      return true;
    }
    if (method === "GET" && rest === "/api/state") {
      sendJson(res, 200, await buildState(deps));
      return true;
    }
    if (method === "POST" && rest === "/api/resolve") {
      const body = await readJson(req);
      const decision = body.decision;
      if (decision !== "allow-once" && decision !== "allow-always" && decision !== "deny") {
        sendJson(res, 400, { error: "decision must be allow-once, allow-always, or deny" });
        return true;
      }
      const id = typeof body.toolCallId === "string" ? body.toolCallId : typeof body.eventId === "string" ? body.eventId : "";
      const card = deps.cards.get(id);
      if (!card) {
        sendJson(res, 404, { error: "No pending review for that id" });
        return true;
      }
      const listed = await listPluginApprovals(deps.gateway);
      const approvalId =
        (typeof body.approvalId === "string" && body.approvalId) ||
        matchApprovalId(listed, card.toolCallId);
      if (!approvalId) {
        sendJson(res, 409, {
          error: "OpenClaw has not exposed a plugin: approval id yet. Use /approve in chat.",
        });
        return true;
      }
      await resolvePluginApproval({
        gateway: deps.gateway,
        config: deps.config,
        approvalId,
        decision: decision as ResolveDecision,
      });
      deps.cards.take(card.toolCallId);
      sendJson(res, 200, { ok: true, id: approvalId, decision });
      return true;
    }
    if (method === "POST" && rest === "/api/policy") {
      const body = await readJson(req);
      let persist: DashboardPersistResult | undefined;
      if (typeof body.sensitivity === "string") {
        const value = parseSensitivityToken(body.sensitivity);
        if (!value) {
          sendJson(res, 400, { error: "sensitivity must be strict, info, warning, or critical" });
          return true;
        }
        persist = foldPersist(persist, deps.setSensitivity(value));
      }
      if (typeof body.unattendedSensitivity === "string") {
        const value = parseSensitivityToken(body.unattendedSensitivity);
        if (!value) {
          sendJson(res, 400, { error: "unattendedSensitivity must be strict, info, warning, or critical" });
          return true;
        }
        persist = foldPersist(persist, deps.setUnattendedSensitivity(value));
      }
      const feedback = parseFeedbackMode(body.feedbackMode);
      if (typeof feedback === "object") {
        sendJson(res, 400, { error: feedback.error });
        return true;
      }
      if (feedback) persist = foldPersist(persist, deps.setFeedbackMode(feedback));
      if (body.onScanError != null) {
        const value = parseOnScanError(body.onScanError, deps.onScanError());
        if (typeof body.onScanError !== "string" || body.onScanError.trim().toLowerCase() !== value) {
          sendJson(res, 400, { error: "onScanError must be review, deny, or allow" });
          return true;
        }
        persist = foldPersist(persist, deps.setOnScanError(value));
      }
      const mode = parseAllowAllMode(body.allowAllMode);
      if (typeof mode === "object") {
        sendJson(res, 400, { error: mode.error });
        return true;
      }
      if (mode === "on") {
        deps.setAllowAll(true);
      } else if (mode === "off") {
        deps.setAllowAll(false);
        for (const st of deps.sessions.uniqueValues()) st.allowAll = false;
      } else if (mode === "session") {
        deps.setAllowAll(false);
      }
      if (typeof body.globalQuiet === "string") {
        const parsed = parseQuietDuration(body.globalQuiet, deps.now?.() ?? Date.now());
        if ("error" in parsed) {
          sendJson(res, 400, { error: parsed.error });
          return true;
        }
        deps.setQuietUntilMs(parsed.untilMs);
      }
      const ids = sessionIdsOf({
        sessionId: typeof body.sessionId === "string" ? body.sessionId : undefined,
        sessionKey: typeof body.sessionKey === "string" ? body.sessionKey : undefined,
      });
      if (typeof body.allowAll === "boolean" || typeof body.quiet === "string") {
        const st = deps.sessions.getOrCreate(ids, deps.sessionFactory);
        if (ids.sessionId) st.sessionId = ids.sessionId;
        if (ids.sessionKey) st.sessionKey = ids.sessionKey;
        if (typeof body.allowAll === "boolean") {
          deps.setAllowAll(false);
          st.allowAll = body.allowAll;
        }
        if (typeof body.quiet === "string") {
          const parsed = parseQuietDuration(body.quiet, deps.now?.() ?? Date.now());
          if ("error" in parsed) {
            sendJson(res, 400, { error: parsed.error });
            return true;
          }
          st.quietUntilMs = parsed.untilMs;
        }
      }
      sendJson(res, 200, persistPayload(persist));
      return true;
    }
    if (method === "POST" && rest === "/api/log") {
      const body = await readJson(req);
      const days = parseRetentionDays(body.maxAgeDays);
      if (days && typeof days === "object") {
        sendJson(res, 400, { error: days.error });
        return true;
      }
      const bytes = parseRetentionBytes(body.maxBytes);
      if (bytes && typeof bytes === "object") {
        sendJson(res, 400, { error: bytes.error });
        return true;
      }
      let persist: DashboardPersistResult | undefined;
      if (typeof days === "number" || typeof bytes === "number") {
        persist = deps.setOperatorLogRetention({
          maxAgeDays: typeof days === "number" ? days : undefined,
          maxBytes: typeof bytes === "number" ? bytes : undefined,
        });
      }
      if (body.wipe === "confirm") {
        wipeOperatorLog(deps.operatorLog());
      } else if (body.purge === "confirm" || body.purge === true) {
        purgeOperatorLog(deps.operatorLog());
      }
      sendJson(res, 200, persistPayload(persist));
      return true;
    }
    if (method === "POST" && rest === "/api/allowlist/rm") {
      const body = await readJson(req);
      const index = typeof body.index === "number" ? body.index : Number(body.index);
      const file = loadAllowlist(deps.allowlist.path);
      if (!Number.isInteger(index) || index < 1 || index > file.entries.length) {
        sendJson(res, 400, { error: "invalid allowlist index" });
        return true;
      }
      file.entries.splice(index - 1, 1);
      try {
        saveAllowlist(deps.allowlist.path, file);
      } catch (err) {
        sendJson(res, 500, {
          error: `Could not write allowlist: ${err instanceof Error ? err.message : String(err)}`,
        });
        return true;
      }
      sendJson(res, 200, { ok: true });
      return true;
    }
    sendJson(res, 404, { error: "unknown /sentrook route" });
    return true;
  } catch (err) {
    sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
    return true;
  }
}
