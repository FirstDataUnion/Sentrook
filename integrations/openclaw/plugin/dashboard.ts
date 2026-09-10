/**
 * Gateway HTTP panel at ``/sentrook`` (same port as Control UI).
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import {
  listPluginApprovals,
  matchApprovalId,
  isSentrookApproval,
  type ListPluginApprovalsOptions,
  type PluginRuntimeGateway,
  type ApprovalListItem,
} from "./approvalGateway.ts";
import { loadAllowlist, type AllowlistConfig } from "./localAllowlist.ts";
import {
  operatorLogStats,
  tailOperatorLog,
  DEFAULT_TIMELINE_SCAN_LIMIT,
  waitingOperatorReview,
  operatorPluginVersion,
  type OperatorLogConfig,
  type OperatorLogEvent,
} from "./operatorLog.ts";
import { renderDashboardPage } from "./dashboardPage.ts";
import {
  ACCESS_MISSING,
  DASHBOARD_PATH,
  accessFromRequest,
  accessTokensEqual,
  applyDashboardCors,
  dashboardRestFromPathname,
} from "./dashboardAuth.ts";
import { ReviewCardStore, type ReviewCard } from "./reviewCards.ts";
import { type OnScanError } from "./scanErrorPolicy.ts";
import { type Sensitivity } from "./sessionPolicy.ts";
import { type SessionIds } from "./sessionStore.ts";
import {
  FeatureOperationError,
  httpStatusForCode,
  opAllowlistAdd,
  opAllowlistRemove,
  opLog,
  opPolicy,
  opResolve,
  opSetup,
  opVerify,
} from "./dashboardOperations.ts";
import type { FeatureHandlers } from "./featureOperations.ts";
import { mergeSessionRows, type HostSession } from "./hostSessions.ts";
import type {
  DashboardSetupInput,
  DashboardSetupResult,
} from "./dashboardSetup.ts";
import type { VerifyResult } from "./verify.ts";

export type DashboardFeedbackMode = "off" | "submit";
export type AllowAllMode = "off" | "session" | "on";

export { DASHBOARD_API_PATH, DASHBOARD_PATH } from "./dashboardAuth.ts";

export type DashboardSession = {
  sessionId?: string;
  sessionKey?: string;
  allowAll: boolean;
  quietUntilMs: number | null;
  attendedSensitivity?: Sensitivity | null;
  unattendedSensitivity?: Sensitivity | null;
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
  syncSessionFlags?: (session: DashboardSession) => void;
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
  logger?: { warn: (msg: string) => void; info?: (msg: string) => void };
  listHostSessions?: () => HostSession[];
  now?: () => number;
  /** Process token from the Control UI tab path. When set, every request must present it. */
  accessToken?: string;
  /** Live credential check — not the boot-time resolveConfig snapshot. */
  setupNeeded?: () => boolean;
  saveSetup?: (input: DashboardSetupInput) => Promise<DashboardSetupResult>;
  verifyConnection?: () => Promise<VerifyResult>;
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
  if (pathname === DASHBOARD_PATH || pathname === "") return { rest: "", handled: true };
  const tab = dashboardRestFromPathname(pathname);
  if (tab) return tab;
  if (pathname.startsWith(`${DASHBOARD_PATH}/api/`)) {
    return { rest: pathname.slice(DASHBOARD_PATH.length), handled: true };
  }
  if (pathname.startsWith("/api/")) return { rest: pathname, handled: true };
  // Host stripped ``/sentrook/api`` (match: "prefix") → ``/state``, ``/policy``, …
  if (
    pathname === "/state" ||
    pathname === "/resolve" ||
    pathname === "/policy" ||
    pathname === "/log" ||
    pathname === "/setup" ||
    pathname === "/verify" ||
    pathname.startsWith("/allowlist")
  ) {
    return { rest: `/api${pathname}`, handled: true };
  }
  return { rest: pathname, handled: false };
}

const TAB_RPC = new Set(["state", "policy", "resolve", "log", "setup", "verify", "allowlist/rm", "allowlist/add"]);

function acceptWantsJson(req: IncomingMessage): boolean {
  const accept = typeof req.headers.accept === "string" ? req.headers.accept : "";
  return accept.includes("application/json") && !accept.includes("text/html");
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

/**
 * Runs a shared dashboard operation and replies as the HTTP panel always has.
 * Operation errors carry a code so both surfaces agree on what went wrong.
 */
async function runOperation<T>(
  res: ServerResponse,
  run: () => T | Promise<T>,
  statusOf: (value: T) => number = () => 200,
): Promise<true> {
  try {
    const value = await run();
    sendJson(res, statusOf(value), value);
  } catch (err) {
    if (!(err instanceof FeatureOperationError)) throw err;
    sendJson(res, httpStatusForCode(err.code), { error: err.message });
  }
  return true;
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

function nonemptyStr(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function commandFromArgs(args: Record<string, unknown>): string {
  if (typeof args.command === "string") return args.command;
  if (typeof args.cmd === "string") return args.cmd;
  try {
    return JSON.stringify(args);
  } catch {
    return "";
  }
}

function argsFromOperatorPending(event: OperatorLogEvent | undefined): Record<string, unknown> {
  const pending = event?.pending;
  if (!pending || typeof pending !== "object") return {};
  const args = (pending as { args?: unknown }).args;
  if (args && typeof args === "object" && !Array.isArray(args)) {
    return { ...(args as Record<string, unknown>) };
  }
  return {};
}

function cardFromWaitingApproval(
  item: ApprovalListItem,
  logEvent: OperatorLogEvent | undefined,
  now: number,
): ReviewCard {
  const req = item.request ?? {};
  const toolCallId = nonemptyStr(req.toolCallId) ?? item.id;
  const args = argsFromOperatorPending(logEvent);
  if (!args.command && !args.cmd && nonemptyStr(req.title)) {
    args.command = req.title as string;
  }
  const pendingTool = logEvent?.pending && typeof logEvent.pending === "object"
    ? nonemptyStr((logEvent.pending as { tool?: unknown }).tool)
    : undefined;
  const scanDoc = logEvent?.scan && typeof logEvent.scan === "object"
    ? (logEvent.scan as Record<string, unknown>)
    : {};
  const createdAtMs = logEvent?.ts ? Date.parse(String(logEvent.ts)) : now;
  return {
    eventId: nonemptyStr(logEvent?.id) ?? `approval:${item.id}`,
    toolCallId,
    tool: pendingTool ?? nonemptyStr(req.toolName) ?? "exec",
    args,
    scan: {
      decision: nonemptyStr(scanDoc.decision) ?? (logEvent?.event === "scan_error" ? "scan_error" : "review"),
      risk: typeof scanDoc.risk === "number" ? scanDoc.risk : undefined,
      summary: nonemptyStr(scanDoc.summary) ?? nonemptyStr(req.description) ?? undefined,
      matched_rules: Array.isArray(scanDoc.matched_rules)
        ? scanDoc.matched_rules.filter((id): id is string => typeof id === "string")
        : undefined,
      review_severity: nonemptyStr(scanDoc.review_severity) ?? nonemptyStr(req.severity) ?? undefined,
      block_reason: nonemptyStr(scanDoc.block_reason),
    },
    sessionId: nonemptyStr(logEvent?.metadata && (logEvent.metadata as { session_id?: unknown }).session_id),
    sessionKey: nonemptyStr(logEvent?.metadata && (logEvent.metadata as { session_key?: unknown }).session_key),
    timeoutMs: typeof req.timeoutMs === "number" && req.timeoutMs > 0 ? req.timeoutMs : 600_000,
    createdAtMs: Number.isFinite(createdAtMs) ? createdAtMs : now,
    intent: nonemptyStr(logEvent?.intent) ?? null,
    intentKind: nonemptyStr(logEvent?.intent_kind) ?? null,
    approvalId: item.id,
  };
}

function presentPendingCard(
  card: ReviewCard,
  listed: ApprovalListItem[],
  approvalIdHint?: string,
): DashboardViewPending {
  const args = card.args ?? {};
  const approvalId =
    nonemptyStr(approvalIdHint) ||
    nonemptyStr(card.approvalId) ||
    matchApprovalId(listed, [card.toolCallId, card.eventId, card.approvalId]);
  return {
    eventId: card.eventId,
    toolCallId: card.toolCallId,
    approvalId,
    tool: card.tool,
    command: commandFromArgs(args),
    args,
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
}

type DashboardViewPending = {
  eventId: string;
  toolCallId: string;
  approvalId?: string;
  tool: string;
  command: string;
  args: Record<string, unknown>;
  scan: ReviewCard["scan"];
  sessionId?: string;
  sessionKey?: string;
  agentId?: string;
  timeoutMs: number;
  createdAtMs: number;
  intent: string | null;
  intentKind: string | null;
  priorSteps: NonNullable<ReviewCard["priorSteps"]>;
  priorOmitted: number;
};

function collectPending(
  deps: DashboardDeps,
  listed: ApprovalListItem[],
  now: number,
): DashboardViewPending[] {
  const fromStore = deps.cards.list();
  const seen = new Set(fromStore.map((card) => card.toolCallId));
  const extras: Array<{ card: ReviewCard; approvalId: string }> = [];
  const log = deps.operatorLog();
  for (const item of listed) {
    if (!isSentrookApproval(item)) continue;
    const toolCallId = nonemptyStr(item.request?.toolCallId) ?? item.id;
    if (seen.has(toolCallId) || seen.has(item.id)) continue;
    seen.add(toolCallId);
    extras.push({
      card: cardFromWaitingApproval(item, waitingOperatorReview(log, toolCallId), now),
      approvalId: item.id,
    });
  }
  for (const row of extras) {
    deps.cards.put(row.card);
  }
  const pending = [
    ...fromStore.map((card) => presentPendingCard(card, listed)),
    ...extras.map((row) => presentPendingCard(row.card, listed, row.approvalId)),
  ].sort((a, b) => b.createdAtMs - a.createdAtMs);
  for (const row of pending) {
    if (row.approvalId) deps.cards.attachApprovalId(row.toolCallId, row.approvalId);
  }
  return pending;
}

function listApprovalOpts(deps: DashboardDeps): ListPluginApprovalsOptions {
  return { config: deps.config, logger: deps.logger };
}

export async function buildState(deps: DashboardDeps) {
  const listed = await listPluginApprovals(deps.gateway, listApprovalOpts(deps));
  const now = deps.now?.() ?? Date.now();
  const pending = collectPending(deps, listed, now);
  const log = deps.operatorLog();
  const stats = operatorLogStats(log);
  const { history, audit } = buildTimeline(log);
  const sessions = mergeSessionRows(
    deps.listHostSessions?.() ?? [],
    deps.sessions.uniqueValues().map((st) => ({
      sessionId: st.sessionId,
      sessionKey: st.sessionKey,
      allowAll: st.allowAll,
      quietUntilMs: st.quietUntilMs,
      attendedSensitivity: st.attendedSensitivity ?? null,
      unattendedSensitivity: st.unattendedSensitivity ?? null,
      pending: [...st.pending.values()].filter((call) => call.awaitingApproval).length,
    })),
  );
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
    setupNeeded: deps.setupNeeded?.() ?? false,
  };
}

function sendAccessDenied(req: IncomingMessage, res: ServerResponse, method: string, rest: string): void {
  const dest = req.headers["sec-fetch-dest"];
  const accept = req.headers.accept;
  const destStr = typeof dest === "string" ? dest : "";
  const acceptStr = typeof accept === "string" ? accept : "";
  const pageGet = method === "GET" && (rest === "" || rest === "/");
  const wantsHtml = destStr === "iframe" || destStr === "document" || acceptStr.includes("text/html");
  if (pageGet && wantsHtml) {
    send(
      res,
      401,
      `<!doctype html><meta charset="utf-8"/><title>Sentrook</title><p>${ACCESS_MISSING}</p>`,
      "text/html; charset=utf-8",
    );
    return;
  }
  sendJson(res, 401, { error: ACCESS_MISSING });
}

export async function handleSentrookHttp(
  req: IncomingMessage,
  res: ServerResponse,
  deps: DashboardDeps,
): Promise<boolean> {
  const routed = routePath(req);
  if (!routed.handled) {
    return false;
  }
  let rest = routed.rest;
  const method = (req.method ?? "GET").toUpperCase();
  applyDashboardCors(req, res);
  if (method === "OPTIONS") {
    res.statusCode = 204;
    res.setHeader("cache-control", "no-store");
    res.end();
    return true;
  }
  let parsedBody: Record<string, unknown> | undefined;
  const bodyOf = async (): Promise<Record<string, unknown>> => {
    parsedBody ??= await readJson(req);
    return parsedBody;
  };
  try {
    const allowCookie = method === "GET" || method === "HEAD";
    let presented = accessFromRequest(req, { allowCookie });
    if (method === "POST") {
      const tok = (await bodyOf())._tok;
      if (typeof tok === "string" && tok.trim()) presented = tok.trim();
    }
    if (deps.accessToken && !accessTokensEqual(deps.accessToken, presented)) {
      sendAccessDenied(req, res, method, rest);
      return true;
    }
    if ((rest === "" || rest === "/") && method === "GET" && acceptWantsJson(req)) {
      rest = "/api/state";
    }
    if ((rest === "" || rest === "/") && method === "POST") {
      const rpc = String((await bodyOf())._srk ?? "").trim();
      if (TAB_RPC.has(rpc)) rest = `/api/${rpc}`;
    }
    if (method === "GET" && (rest === "" || rest === "/")) {
      const state = await buildState(deps);
      send(
        res,
        200,
        renderDashboardPage(
          state,
          deps.now?.() ?? Date.now(),
          deps.accessToken ?? "",
          operatorPluginVersion(),
        ),
        "text/html; charset=utf-8",
      );
      return true;
    }
    if ((method === "GET" || method === "POST") && rest === "/api/state") {
      sendJson(res, 200, await buildState(deps));
      return true;
    }
    if (method === "POST" && rest === "/api/resolve") {
      const body = await bodyOf();
      return runOperation(res, () => opResolve(deps, body as never));
    }
    if (method === "POST" && rest === "/api/policy") {
      const body = await bodyOf();
      return runOperation(res, () => opPolicy(deps, body as never));
    }
    if (method === "POST" && rest === "/api/log") {
      const body = await bodyOf();
      return runOperation(res, () => opLog(deps, body as never));
    }
    if (method === "POST" && rest === "/api/allowlist/rm") {
      const body = await bodyOf();
      return runOperation(res, () => opAllowlistRemove(deps, body as never));
    }
    if (method === "POST" && rest === "/api/allowlist/add") {
      const body = await bodyOf();
      return runOperation(res, () => opAllowlistAdd(deps, body as never));
    }
    if (method === "POST" && rest === "/api/setup") {
      const body = await bodyOf();
      // Setup reports a rejected credential in the body, not by throwing.
      return runOperation(
        res,
        () => opSetup(deps, body as never),
        (result) => (result.ok ? 200 : 400),
      );
    }
    if (method === "POST" && rest === "/api/verify") {
      return runOperation(res, () => opVerify(deps));
    }
    sendJson(res, 404, { error: "unknown /sentrook route" });
    return true;
  } catch (err) {
    console.error("sentrook dashboard request failed", err);
    sendJson(res, 500, { error: "internal server error" });
    return true;
  }
}

/**
 * The contract handlers backing the native Control UI page.
 *
 * Same functions the HTTP panel routes to, so the two surfaces cannot drift.
 * ``onChange`` fires after a mutation lands so the plugin can emit the event
 * that makes watching clients refetch instead of poll.
 */
export function createSentrookFeatureHandlers(
  deps: DashboardDeps,
  onChange?: (event: "reviews_changed" | "policy_changed" | "log_changed") => void,
): FeatureHandlers {
  const changed = (event: "reviews_changed" | "policy_changed" | "log_changed") => {
    onChange?.(event);
  };
  return {
    state: () => buildState(deps) as never,
    resolve: async (input) => {
      const result = await opResolve(deps, input);
      changed("reviews_changed");
      return result;
    },
    policy: (input) => {
      const result = opPolicy(deps, input);
      changed("policy_changed");
      return result;
    },
    log: (input) => {
      const result = opLog(deps, input);
      changed("log_changed");
      return result;
    },
    "allowlist.rm": (input) => {
      const result = opAllowlistRemove(deps, input);
      changed("policy_changed");
      return result;
    },
    "allowlist.add": (input) => {
      const result = opAllowlistAdd(deps, input);
      changed("policy_changed");
      return result;
    },
    setup: async (input) => {
      const result = await opSetup(deps, input);
      if (result.ok) changed("policy_changed");
      return result;
    },
    verify: () => opVerify(deps),
  };
}
