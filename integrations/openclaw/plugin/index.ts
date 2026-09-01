/**
 * Sentrook OpenClaw plugin (the "layer").
 *
 * Awaits hosted /scan and maps allow / review / block to OpenClaw
 * before_tool_call decisions (block veto or requireApproval). PlanIR is
 * always scrubbed before egress.
 */

import {
  buildScanAuthHeadersAsync,
  envWithOpenclawDotenv,
  hasScanCredentials,
  parseScanBaseUrl,
  resolveScanAuthConfig,
  type ScanAuthConfig,
  urlRequiresScanAuth,
} from "./auth.ts";
import {
  type ApprovalPolicyConfig,
  resolveApprovalPolicyConfig,
  resolveApprovalTiming,
} from "./approvalPolicy.ts";
import {
  type OnScanError,
  type ScanFailure,
  isScanFailure,
  parseRetryAfterSeconds,
  resolveOnScanError,
  scanAuthErrorToFailure,
  scanErrorToHookResult,
} from "./scanErrorPolicy.ts";
import { maybeSanitizePlanir } from "./sanitize.ts";
import { honestMissTitle, overlayApprovalCopy } from "./reviewCopy.ts";
import {
  type AllowlistConfig,
  matchAllowlist,
  recordAllowAlways,
  resolveAllowlistConfig,
} from "./localAllowlist.ts";
import {
  buildPlanirSnapshot,
  lastPendingStep,
  type IntentKind,
  type PlanIR,
  type SnapshotCall,
} from "./planir.ts";
import { SCAN_BASE_URL } from "./scanEndpoint.ts";
import {
  appendDevLog,
  buildScanDevEvent,
  buildScanErrorDevEvent,
  resolveDevLogConfig,
  scrubDevText,
} from "./devLog.ts";

export type { PlanIR } from "./planir.ts";

// ---- Minimal local typings for the OpenClaw plugin SDK surface we use --------

type Json = Record<string, unknown>;

interface PluginLogger {
  debug?: (m: string) => void;
  info: (m: string) => void;
  warn: (m: string) => void;
  error: (m: string) => void;
}

type FeedbackMode = "off" | "submit";
type ApprovalResolution =
  | "allow-once"
  | "allow-always"
  | "deny"
  | "timeout"
  | "cancelled";
type ReviewSeverity = "info" | "warning" | "critical";

interface BeforePromptBuildEvent {
  prompt: string;
  runId?: string;
}
interface BeforeToolCallEvent {
  toolName: string;
  params?: Json;
  runId?: string;
  toolCallId?: string;
}
interface AfterToolCallEvent {
  toolName: string;
  params?: Json;
  result?: unknown;
  error?: string;
  runId?: string;
  toolCallId?: string;
}
interface AgentContext {
  agentId?: string;
  sessionId?: string;
  sessionKey?: string;
  runId?: string;
}
interface SessionContext {
  sessionId?: string;
  sessionKey?: string;
  agentId?: string;
}

interface RequireApproval {
  title: string;
  description: string;
  severity?: ReviewSeverity;
  timeoutMs?: number;
  timeoutBehavior?: "allow" | "deny";
  allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
  onResolution?: (decision: ApprovalResolution) => void | Promise<void>;
}

export interface BeforeToolCallResult {
  params?: Json;
  block?: boolean;
  blockReason?: string;
  requireApproval?: RequireApproval;
}

interface OpenClawPluginApi {
  pluginConfig?: Json;
  logger: PluginLogger;
  registrationMode?:
    | "full"
    | "discovery"
    | "cli-metadata"
    | "setup-only"
    | "setup-runtime"
    | "tool-discovery";
  on: (hook: string, handler: (event: any, ctx: any) => unknown, opts?: { priority?: number }) => void;
  registerCli?: (
    registrar: (ctx: { program: any }) => void | Promise<void>,
    opts?: {
      commands?: string[];
      descriptors?: Array<{ name: string; description: string; hasSubcommands?: boolean }>;
      parentPath?: string[];
    },
  ) => void;
}

interface RunIntent {
  intent: string;
  kind: IntentKind;
}

export interface ScanResponse {
  block: boolean;
  decision: "allow" | "review" | "block";
  risk?: number;
  summary?: string;
  pending_tool?: string;
  matched_rules?: string[];
  block_reason?: string;
  review_title?: string;
  review_description?: string;
  review_severity?: ReviewSeverity;
  log?: Json;
  timing?: {
    engine_ms?: number;
    request_ms?: number;
  };
  error?: string;
}

export interface ScanTiming {
  /** Wall-clock time for the full plugin POST /scan round trip (ms). */
  pluginE2eMs: number;
  /** Engine processing time reported by the scan service (ms). */
  engineMs: number | null;
  /** Scan-service handler time including JSON parse/serialize (ms). */
  requestMs: number | null;
  /** Estimated transport overhead: pluginE2eMs - engineMs (ms). */
  transportMs: number | null;
  /** Whether PlanIR sanitization ran before POST. */
  sanitizeEnabled: boolean;
  /** Wall-clock time spent in PlanIR sanitization (ms). */
  sanitizeMs: number;
}

export interface SanitizeTiming {
  enabled: boolean;
  ms: number;
}

const DISABLED_SANITIZE_TIMING: SanitizeTiming = { enabled: false, ms: 0 };

export type { OnScanError, ScanFailure } from "./scanErrorPolicy.ts";
export { scanErrorToHookResult } from "./scanErrorPolicy.ts";

const SCAN_DECISIONS = new Set(["allow", "review", "block"]);

/** Parse a 200 ``/scan`` body. Unknown or missing decisions fail closed. */
export function parseScanResponse(body: unknown): ScanResponse | ScanFailure {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return {
      ok: false,
      kind: "http",
      status: 200,
      detail: "scan response is not an object",
    };
  }
  const doc = body as Record<string, unknown>;
  const raw = doc.decision;
  let decision = typeof raw === "string" ? raw.trim().toLowerCase() : undefined;
  const block = Boolean(doc.block);
  if (!decision || !SCAN_DECISIONS.has(decision)) {
    if (block) {
      decision = "block";
    } else {
      return {
        ok: false,
        kind: "http",
        status: 200,
        detail: `unknown scan decision: ${raw ?? "missing"}`,
      };
    }
  }
  const log = doc.log && typeof doc.log === "object" && !Array.isArray(doc.log) ? (doc.log as Json) : undefined;
  const timing =
    doc.timing && typeof doc.timing === "object" && !Array.isArray(doc.timing)
      ? (doc.timing as ScanResponse["timing"])
      : undefined;
  return {
    block,
    decision: decision as ScanResponse["decision"],
    risk: typeof doc.risk === "number" ? doc.risk : undefined,
    summary: typeof doc.summary === "string" ? doc.summary : undefined,
    pending_tool: typeof doc.pending_tool === "string" ? doc.pending_tool : undefined,
    matched_rules: Array.isArray(doc.matched_rules)
      ? doc.matched_rules.filter((id): id is string => typeof id === "string")
      : undefined,
    block_reason: typeof doc.block_reason === "string" ? doc.block_reason : undefined,
    review_title: typeof doc.review_title === "string" ? doc.review_title : undefined,
    review_description: typeof doc.review_description === "string" ? doc.review_description : undefined,
    review_severity:
      doc.review_severity === "info" ||
      doc.review_severity === "warning" ||
      doc.review_severity === "critical"
        ? doc.review_severity
        : undefined,
    log,
    timing,
    error: typeof doc.error === "string" ? doc.error : undefined,
  };
}

export interface PostScanResult {
  scan: ScanResponse;
  timing: ScanTiming;
}

interface PluginConfig {
  /** Pinned SCAN_BASE_URL origin — not read from pluginConfig. */
  url: string;
  auth: ScanAuthConfig;
  timeoutMs: number;
  feedbackMode: FeedbackMode;
  approval: ApprovalPolicyConfig;
  allowlist: AllowlistConfig;
  onScanError: OnScanError;
}

// ---- Per-session trajectory state -------------------------------------------

interface SessionState {
  runIntents: Map<string, RunIntent>;
  executed: SnapshotCall[];
  pending: Map<string, { tool: string; args: Json }>;
  stepSeq: number;
}

const MAX_TRAJECTORY = 200;
const MAX_RESULT_TEXT = 20_000;
const DEFAULT_SCAN_TIMEOUT_MS = 60_000;

/** Scan POST timeout: explicit config/env, else 60000ms. */
export function resolveScanTimeoutMs(
  cfgTimeout: unknown,
  env: NodeJS.ProcessEnv = process.env,
): number {
  if (typeof cfgTimeout === "number" && Number.isFinite(cfgTimeout) && cfgTimeout > 0) {
    return Math.round(cfgTimeout);
  }
  const envMs = Number(env.SENTROOK_SCAN_TIMEOUT_MS);
  if (Number.isFinite(envMs) && envMs > 0) {
    return Math.round(envMs);
  }
  return DEFAULT_SCAN_TIMEOUT_MS;
}

function classifyIntent(text: string): IntentKind {
  const normalized = text.trim();
  if (/^\s*\[cron:/i.test(normalized)) return "cron";
  if (/\[Subagent Context\]|\[Subagent Task\]/i.test(normalized)) return "subagent";
  if (/^\s*\[system[:\]]/i.test(normalized)) return "system";
  return "user";
}

function resolveRunId(eventRunId?: string, ctxRunId?: string): string {
  return String(eventRunId ?? ctxRunId ?? "run_1");
}

function resolveConfig(api: OpenClawPluginApi): PluginConfig {
  const cfg = api.pluginConfig ?? {};

  const parsed = parseScanBaseUrl(SCAN_BASE_URL);
  if (!parsed.ok) {
    throw new Error(`SCAN_BASE_URL is invalid (${parsed.reason}): ${SCAN_BASE_URL}`);
  }
  const url = parsed.href;
  const timeoutMs = resolveScanTimeoutMs(cfg.timeoutMs, process.env);

  const feedbackCfg =
    cfg.feedback && typeof cfg.feedback === "object"
      ? (cfg.feedback as Json)
      : {};
  const feedbackModeRaw =
    (typeof feedbackCfg.mode === "string" && feedbackCfg.mode) ||
    process.env.SENTROOK_FEEDBACK_MODE ||
    "off";
  // "queue" previously meant "post to Sentrook"; same as submit on the plugin side.
  const feedbackMode: FeedbackMode =
    feedbackModeRaw === "submit" || feedbackModeRaw === "queue" ? "submit" : "off";

  const approvalCfg =
    cfg.approval && typeof cfg.approval === "object"
      ? (cfg.approval as Json)
      : {};
  const approval = resolveApprovalPolicyConfig({
    pluginApproval: approvalCfg,
    env: process.env,
  });

  const auth = resolveScanAuthConfig(
    cfg as Record<string, unknown>,
    envWithOpenclawDotenv(process.env),
  );

  const allowlist = resolveAllowlistConfig(
    cfg as Record<string, unknown>,
    process.env,
  );

  const onScanError = resolveOnScanError({
    pluginConfig: cfg.onScanError,
    env: process.env,
  });

  return {
    url,
    auth,
    timeoutMs,
    feedbackMode,
    approval,
    allowlist,
    onScanError,
  };
}

function resultToText(result: unknown, error?: string): string {
  let text = "";
  if (error) text = String(error);
  else if (typeof result === "string") text = result;
  else if (result != null) {
    try {
      text = JSON.stringify(result);
    } catch {
      text = String(result);
    }
  }
  return text.length > MAX_RESULT_TEXT ? text.slice(0, MAX_RESULT_TEXT) : text;
}

function readPositiveInt(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.round(value)
    : null;
}

export function extractEngineMs(scan: ScanResponse): number | null {
  const fromTiming = readPositiveInt(scan.timing?.engine_ms);
  if (fromTiming !== null) return fromTiming;
  const log = scan.log;
  if (log && typeof log === "object") {
    return readPositiveInt((log as Json).total_ms);
  }
  return null;
}

export function extractRequestMs(scan: ScanResponse): number | null {
  return readPositiveInt(scan.timing?.request_ms);
}

export function computeTransportMs(
  pluginE2eMs: number,
  engineMs: number | null,
): number | null {
  if (engineMs === null) return null;
  return Math.max(0, pluginE2eMs - engineMs);
}

export function buildScanTiming(
  scan: ScanResponse,
  pluginE2eMs: number,
  sanitize: SanitizeTiming = DISABLED_SANITIZE_TIMING,
): ScanTiming {
  const engineMs = extractEngineMs(scan);
  const requestMs = extractRequestMs(scan);
  return {
    pluginE2eMs,
    engineMs,
    requestMs,
    transportMs: computeTransportMs(pluginE2eMs, engineMs),
    sanitizeEnabled: sanitize.enabled,
    sanitizeMs: sanitize.ms,
  };
}

function pendingToolName(plan: PlanIR): string {
  return lastPendingStep(plan)?.tool ?? "unknown";
}

function formatScanTimingLog(
  plan: PlanIR,
  scan: ScanResponse,
  timing: ScanTiming,
): string {
  return JSON.stringify({
    event: "scan_timing",
    tool_call_id: plan.metadata.tool_call_id ?? null,
    session_id: plan.metadata.session_id ?? null,
    run_id: plan.run_id,
    pending_tool: pendingToolName(plan),
    decision: scan.decision,
    plugin_e2e_ms: timing.pluginE2eMs,
    engine_ms: timing.engineMs,
    request_ms: timing.requestMs,
    transport_ms: timing.transportMs,
    sanitize_enabled: timing.sanitizeEnabled,
    sanitize_ms: timing.sanitizeMs,
  });
}

function recordScanLatency(
  url: string,
  auth: ScanAuthConfig,
  plan: PlanIR,
  scan: ScanResponse,
  timing: ScanTiming,
): void {
  void (async () => {
    try {
      const headers = await buildScanAuthHeadersAsync(auth);
      await fetch(`${url}/latency`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          tool_call_id: plan.metadata.tool_call_id ?? null,
          session_id: plan.metadata.session_id ?? null,
          run_id: plan.run_id,
          pending_tool: pendingToolName(plan),
          decision: scan.decision,
          plugin_e2e_ms: timing.pluginE2eMs,
          engine_ms: timing.engineMs,
          request_ms: timing.requestMs,
          transport_ms: timing.transportMs,
          sanitize_enabled: timing.sanitizeEnabled,
          sanitize_ms: timing.sanitizeMs,
        }),
      });
    } catch {
      // Best-effort; gateway logs still carry the timing line.
    }
  })();
}

export async function postScan(
  url: string,
  timeoutMs: number,
  plan: PlanIR,
  auth: ScanAuthConfig | null = null,
  logger?: PluginLogger,
): Promise<PostScanResult | ScanFailure> {
  const resolvedAuth: ScanAuthConfig = auth ?? { apiKey: null, oidc: null };
  const { plan: outbound, sanitizeMs } = maybeSanitizePlanir(plan);
  const sanitizeTiming: SanitizeTiming = {
    enabled: true,
    ms: sanitizeMs,
  };
  const body = JSON.stringify(outbound);

  // Mint OIDC outside the scan AbortController. Cold discovery+token can take
  // a couple of seconds; a hung Identity host must not stall the hook forever.
  let headers: Record<string, string>;
  try {
    headers = await buildScanAuthHeadersAsync(resolvedAuth);
  } catch (err) {
    const failure = scanAuthErrorToFailure(err);
    logger?.warn(`[sentrook-openclaw] scan auth failed: ${failure.detail}`);
    return failure;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = performance.now();
  const deadline = started + timeoutMs;
  let retried429 = false;
  try {
    while (true) {
      const response = await fetch(`${url}/scan`, {
        method: "POST",
        headers,
        body,
        signal: controller.signal,
      });
      if (response.ok) {
        let raw: unknown;
        try {
          raw = await response.json();
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          logger?.warn(`[sentrook-openclaw] scan HTTP 200: invalid JSON: ${msg}`);
          return {
            ok: false,
            kind: "http",
            status: 200,
            detail: `invalid scan JSON: ${msg}`,
          };
        }
        const parsed = parseScanResponse(raw);
        if (isScanFailure(parsed)) {
          logger?.warn(`[sentrook-openclaw] scan HTTP 200: ${parsed.detail}`);
          return parsed;
        }
        const pluginE2eMs = Math.round(performance.now() - started);
        return { scan: parsed, timing: buildScanTiming(parsed, pluginE2eMs, sanitizeTiming) };
      }

      let detail = "";
      try {
        detail = (await response.text()).slice(0, 200);
      } catch {
        detail = "";
      }

      if (response.status === 429 && !retried429) {
        const retryAfterSec = parseRetryAfterSeconds(response.headers.get("retry-after")) ?? 1;
        const waitMs = Math.ceil(retryAfterSec * 1000);
        const remainingMs = deadline - performance.now();
        if (waitMs + 50 < remainingMs) {
          retried429 = true;
          logger?.warn(
            `[sentrook-openclaw] scan HTTP 429: rate limited; Retry-After=${retryAfterSec}; retrying`,
          );
          await sleepMs(waitMs, controller.signal);
          continue;
        }
        logger?.warn(
          `[sentrook-openclaw] scan HTTP 429: rate limited; Retry-After=${retryAfterSec}` +
            (detail ? `: ${detail}` : ""),
        );
        return {
          ok: false,
          kind: "rate_limited",
          status: 429,
          retryAfterSec,
          detail: detail || "rate limited",
        };
      }

      if (response.status === 429) {
        const retryAfterSec = parseRetryAfterSeconds(response.headers.get("retry-after"));
        logger?.warn(
          `[sentrook-openclaw] scan HTTP 429: rate limited` +
            (retryAfterSec != null ? `; Retry-After=${retryAfterSec}` : "") +
            (detail ? `: ${detail}` : ""),
        );
        return {
          ok: false,
          kind: "rate_limited",
          status: 429,
          retryAfterSec,
          detail: detail || "rate limited",
        };
      }

      logger?.warn(
        `[sentrook-openclaw] scan HTTP ${response.status}` + (detail ? `: ${detail}` : ""),
      );
      return {
        ok: false,
        kind: "http",
        status: response.status,
        detail: detail || `HTTP ${response.status}`,
      };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const aborted = msg.toLowerCase().includes("abort");
    logger?.warn(
      `[sentrook-openclaw] scan ${aborted ? "timed out" : "failed"}: ${msg}`,
    );
    return {
      ok: false,
      kind: aborted ? "timeout" : "network",
      detail: msg,
    };
  } finally {
    clearTimeout(timer);
  }
}

function sleepMs(ms: number, signal: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(), ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error("aborted"));
    };
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function postFeedback(
  url: string,
  auth: ScanAuthConfig,
  payload: {
    plan: PlanIR;
    resolution: ApprovalResolution;
    log?: Json;
    provenance?: Json;
  },
  logger: PluginLogger,
): Promise<void> {
  const { plan: outbound } = maybeSanitizePlanir(payload.plan);
  return (async () => {
    try {
      const headers = await buildScanAuthHeadersAsync(auth);
      const res = await fetch(`${url}/feedback`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          plan: outbound,
          resolution: payload.resolution,
          log: payload.log,
          provenance: payload.provenance ?? {},
        }),
      });
      const text = await res.text();
      let body: {
        status?: string;
        feedback_status?: string;
        reason?: string;
        feedback_reason?: string;
      } | null = null;
      try {
        body = text ? (JSON.parse(text) as typeof body) : null;
      } catch {
        body = null;
      }
      if (!res.ok) {
        logger.warn(
          `[sentrook-openclaw] feedback HTTP ${res.status}: ${text.slice(0, 200) || "(empty)"}`,
        );
        return;
      }
      const status = body?.status ?? body?.feedback_status ?? "ok";
      const reason = body?.reason ?? body?.feedback_reason;
      if (
        status === "skipped" ||
        status === "error" ||
        status === "feedback_error"
      ) {
        logger.warn(
          `[sentrook-openclaw] feedback not submitted: status=${status}` +
            (reason ? ` reason=${reason}` : ""),
        );
        return;
      }
      logger.info(`[sentrook-openclaw] feedback ${status}`);
    } catch (err: unknown) {
      logger.warn(`[sentrook-openclaw] feedback post failed: ${String(err)}`);
    }
  })();
}

export function translateScanResponse(
  scan: ScanResponse,
  ctx: {
    plan: PlanIR;
    url: string;
    auth: ScanAuthConfig;
    feedbackMode: FeedbackMode;
    approval: ApprovalPolicyConfig;
    allowlist?: AllowlistConfig;
    logger: PluginLogger;
    /** Unredacted pending tool args from the live hook (operator review only). */
    pendingArgs?: Json;
  },
): BeforeToolCallResult | undefined {
  if (scan.block || scan.decision === "block") {
    return {
      block: true,
      blockReason:
        scan.block_reason ||
        scan.summary ||
        "Sentrook blocked this tool call due to security policy",
    };
  }

  if (scan.decision === "review") {
    const plan = ctx.plan;
    const log = scan.log;
    const pending = lastPendingStep(plan);
    const pendingTool = pending?.tool ?? "tool";

    if (ctx.allowlist?.enabled) {
      const match = matchAllowlist(
        plan,
        log && typeof log === "object" ? log : undefined,
        ctx.allowlist,
      );
      if (match.hit) {
        const rules = (match.matchedRuleIds ?? []).join(",") || "?";
        const detail = match.entryDetail ?? "";
        ctx.logger.warn(
          `[sentrook-openclaw] local allowlist hit (${match.kind ?? "unknown"}); skipping requireApproval; rules=${rules}; ${detail}`,
        );
        return undefined;
      }
    }

    const timing = resolveApprovalTiming(
      ctx.approval,
      plan.intent_kind ?? undefined,
      plan.intent ?? undefined,
    );
    if (timing.unattended) {
      ctx.logger.info(
        `[sentrook-openclaw] unattended review (${plan.intent_kind ?? "unknown"}): ` +
          `timeout=${timing.timeoutMs}ms behavior=${timing.timeoutBehavior}`,
      );
    }
    const copy = overlayApprovalCopy({
      scanTitle: scan.review_title,
      scanDescription: scan.review_description,
      fallbackTitle: honestMissTitle(pendingTool),
      fallbackDescription:
        scan.summary || "Sentrook flagged this tool call for human review",
      pendingTool,
      pendingArgs: ctx.pendingArgs,
    });
    return {
      requireApproval: {
        title: copy.title,
        description: copy.description,
        severity: scan.review_severity || "warning",
        timeoutMs: timing.timeoutMs,
        timeoutBehavior: timing.timeoutBehavior,
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        onResolution: async (decision) => {
          if (decision === "allow-always" && ctx.allowlist?.enabled) {
            try {
              const recorded = recordAllowAlways(
                plan,
                log && typeof log === "object" ? log : undefined,
                ctx.allowlist,
              );
              if (recorded.status === "recorded") {
                ctx.logger.info(
                  `[sentrook-openclaw] local allowlist recorded (${recorded.kind})`,
                );
              } else if (recorded.status === "skipped") {
                ctx.logger.info(
                  `[sentrook-openclaw] local allowlist skip: ${recorded.reason ?? "unknown"}`,
                );
              }
            } catch (err: unknown) {
              ctx.logger.warn(
                `[sentrook-openclaw] local allowlist record failed: ${String(err)}`,
              );
            }
          }
          if (decision === "allow-always" || ctx.feedbackMode !== "off") {
            await postFeedback(
              ctx.url,
              ctx.auth,
              { plan, resolution: decision, log },
              ctx.logger,
            );
          }
        },
      },
    };
  }

  return undefined;
}

function rememberPending(
  st: SessionState,
  toolCallId: string | undefined,
  pendingCall: SnapshotCall,
): void {
  if (!toolCallId) return;
  st.pending.set(toolCallId, { tool: pendingCall.tool, args: pendingCall.args });
}

function dropPending(st: SessionState, toolCallId: string | undefined): void {
  if (!toolCallId) return;
  st.pending.delete(toolCallId);
}

/** Keep session pending only for allow / in-flight review; drop on block/deny. */
function applyPendingLifecycle(
  result: BeforeToolCallResult | undefined,
  st: SessionState,
  toolCallId: string | undefined,
  pendingCall: SnapshotCall,
): BeforeToolCallResult | undefined {
  if (result?.block) return result;
  rememberPending(st, toolCallId, pendingCall);
  const approval = result?.requireApproval;
  if (!approval || !toolCallId) return result;
  const inner = approval.onResolution;
  approval.onResolution = async (decision) => {
    if (decision === "deny" || decision === "timeout" || decision === "cancelled") {
      dropPending(st, toolCallId);
    }
    if (inner) await inner(decision);
  };
  return result;
}

function attachDevLogResolution(
  result: BeforeToolCallResult | undefined,
  plan: PlanIR,
  pendingCall: SnapshotCall,
  logger?: PluginLogger,
): BeforeToolCallResult | undefined {
  const approval = result?.requireApproval;
  if (!approval?.onResolution) return result;
  const inner = approval.onResolution;
  approval.onResolution = async (decision) => {
    appendDevLog(
      resolveDevLogConfig(),
      {
        event: "resolution",
        session_id: plan.metadata.session_id ?? null,
        run_id: plan.run_id,
        tool_call_id: plan.metadata.tool_call_id ?? null,
        tool: pendingCall.tool,
        decision,
      },
      logger,
    );
    await inner(decision);
  };
  return result;
}

const plugin = {
  id: "sentrook-openclaw",
  name: "Sentrook OpenClaw",
  description:
    "Sentrook trajectory scanner (hosted HTTPS). Scans tool calls and can allow, require approval, or block flagged actions.",

  register(api: OpenClawPluginApi) {
    const mode = api.registrationMode ?? "full";

    if (
      api.registerCli &&
      (mode === "cli-metadata" || mode === "discovery" || mode === "full")
    ) {
      api.registerCli(
        async ({ program }) => {
          const { registerSentrookCli } = await import("./cli.ts");
          registerSentrookCli(program);
        },
        {
          descriptors: [
            {
              name: "sentrook",
              description: "Sentrook hosted scan plugin helpers (configure, verify, allowlist)",
              hasSubcommands: true,
            },
          ],
        },
      );
      if (mode === "cli-metadata") return;
    }

    const config = resolveConfig(api);
    const sessions = new Map<string, SessionState>();

    if (urlRequiresScanAuth(config.url) && !hasScanCredentials(config.auth)) {
      api.logger.warn(
        "[sentrook-openclaw] hosted scan URL has no credentials — " +
          "run: openclaw sentrook configure  (or set SENTROOK_SCAN_CLIENT_ID + " +
          "SENTROOK_SCAN_CLIENT_SECRET in ~/.openclaw/.env)",
      );
    }

    const sessionKeyOf = (ctx: AgentContext | SessionContext): string =>
      ctx.sessionId || ctx.sessionKey || "unknown";

    const getSession = (key: string): SessionState => {
      let st = sessions.get(key);
      if (!st) {
        st = { runIntents: new Map(), executed: [], pending: new Map(), stepSeq: 0 };
        sessions.set(key, st);
      }
      return st;
    };

    const resolveLiveAuth = (): ScanAuthConfig =>
      resolveScanAuthConfig(
        (api.pluginConfig ?? {}) as Record<string, unknown>,
        envWithOpenclawDotenv(process.env),
      );

    const bootDevLog = resolveDevLogConfig();
    if (bootDevLog.enabled) {
      api.logger.info(`[sentrook-openclaw] diagnostic log ${bootDevLog.path}`);
      appendDevLog(
        bootDevLog,
        { event: "register", path: bootDevLog.path },
        api.logger,
      );
    }

    api.on("before_prompt_build", (event: BeforePromptBuildEvent, ctx: AgentContext) => {
      const st = getSession(sessionKeyOf(ctx));
      const runId = resolveRunId(event.runId, ctx.runId);
      if (typeof event?.prompt === "string" && event.prompt.trim()) {
        const intent = event.prompt.trim();
        st.runIntents.set(runId, { intent, kind: classifyIntent(intent) });
      }
    });

    api.on(
      "before_tool_call",
      async (event: BeforeToolCallEvent, ctx: AgentContext) => {
        try {
          const sid = ctx.sessionId || ctx.sessionKey;
          const st = getSession(sessionKeyOf(ctx));
          const pendingCall: SnapshotCall = {
            tool: event.toolName,
            args: (event.params as Json) ?? {},
          };
          const coPending: SnapshotCall[] = [];
          for (const [id, peer] of st.pending) {
            if (event.toolCallId && id === event.toolCallId) continue;
            coPending.push({ tool: peer.tool, args: peer.args });
          }
          const batchSize = coPending.length + 1;
          st.stepSeq += 1;
          const runId = resolveRunId(event.runId, ctx.runId);
          const runIntent = st.runIntents.get(runId);
          const plan = buildPlanirSnapshot({
            executed: st.executed.slice(-MAX_TRAJECTORY),
            pending: pendingCall,
            coPending: coPending.length ? coPending : undefined,
            runId: `${sid ?? "session"}:${runId}`,
            intent: runIntent?.intent,
            intentKind: runIntent?.kind,
            sessionId: sid,
            agentId: ctx.agentId,
            toolCallId: event.toolCallId,
            stepSeq: st.stepSeq,
            batchSize: batchSize > 1 ? batchSize : undefined,
          });

          // Re-resolve auth per call so ~/.openclaw/.env updates apply without
          // relying on Compose-injected process env (printenv won't show those).
          const liveAuth = resolveLiveAuth();
          const scanResult = await postScan(
            config.url,
            config.timeoutMs,
            plan,
            liveAuth,
            api.logger,
          );
          if (isScanFailure(scanResult)) {
            const timing = resolveApprovalTiming(
              config.approval,
              plan.intent_kind ?? undefined,
              plan.intent ?? undefined,
            );
            const mapped = scanErrorToHookResult(scanResult, {
              onScanError: config.onScanError,
              unattended: timing.unattended,
              interactiveTimeoutMs: config.approval.interactiveTimeoutMs,
            });
            if (mapped == null) {
              api.logger.warn(
                `[sentrook-openclaw] scan error (${scanResult.kind}); continuing without scan (onScanError=allow)`,
              );
            }
            appendDevLog(
              resolveDevLogConfig(),
              buildScanErrorDevEvent({
                plan,
                pendingArgs: pendingCall.args,
                failure: scanResult,
                hookResult: mapped,
              }),
              api.logger,
            );
            return attachDevLogResolution(
              applyPendingLifecycle(mapped, st, event.toolCallId, pendingCall),
              plan,
              pendingCall,
              api.logger,
            );
          }

          const { scan, timing } = scanResult;
          api.logger.info(`[sentrook-openclaw] ${formatScanTimingLog(plan, scan, timing)}`);
          recordScanLatency(config.url, liveAuth, plan, scan, timing);

          const translated = translateScanResponse(scan, {
            plan,
            url: config.url,
            auth: liveAuth,
            feedbackMode: config.feedbackMode,
            approval: config.approval,
            allowlist: config.allowlist,
            logger: api.logger,
            pendingArgs: pendingCall.args,
          });
          const allowlistHit = scan.decision === "review" && translated == null;
          appendDevLog(
            resolveDevLogConfig(),
            buildScanDevEvent({
              plan,
              pendingArgs: pendingCall.args,
              scan,
              timing,
              hookResult: translated,
              allowlistHit,
            }),
            api.logger,
          );
          return attachDevLogResolution(
            applyPendingLifecycle(translated, st, event.toolCallId, pendingCall),
            plan,
            pendingCall,
            api.logger,
          );
        } catch (err) {
          api.logger.warn(`[sentrook-openclaw] before_tool_call failed: ${String(err)}`);
          const detail = String(err).replace(/\n/g, " ").trim().slice(0, 160);
          appendDevLog(
            resolveDevLogConfig(),
            {
              event: "plugin_error",
              tool: event.toolName,
              tool_call_id: event.toolCallId ?? null,
              detail,
            },
            api.logger,
          );
          return {
            block: true,
            blockReason: detail
              ? `Sentrook plugin error; this tool was not scanned or run. Detail: ${detail}`
              : "Sentrook plugin error; this tool was not scanned or run.",
          };
        }
      },
      { priority: 10 },
    );

    api.on("after_tool_call", (event: AfterToolCallEvent, ctx: AgentContext) => {
      try {
        const st = getSession(sessionKeyOf(ctx));
        let call = event.toolCallId ? st.pending.get(event.toolCallId) : undefined;
        if (call && event.toolCallId) st.pending.delete(event.toolCallId);
        if (!call) call = { tool: event.toolName, args: (event.params as Json) ?? {} };

        const command =
          call.tool === "exec"
            ? String((call.args.command ?? call.args.cmd ?? "") as string) || undefined
            : undefined;

        const resultText = resultToText(event.result, event.error);
        st.executed.push({
          tool: call.tool,
          args: call.args,
          resultText,
          resultOk: !event.error,
          command,
        });
        if (st.executed.length > MAX_TRAJECTORY) {
          st.executed.splice(0, st.executed.length - MAX_TRAJECTORY);
        }
        appendDevLog(
          resolveDevLogConfig(),
          {
            event: "action",
            session_id: ctx.sessionId ?? ctx.sessionKey ?? null,
            run_id: ctx.runId ?? null,
            tool_call_id: event.toolCallId ?? null,
            tool: call.tool,
            command: command ? scrubDevText(command) : null,
            result_ok: !event.error,
            result_chars: resultText.length,
            error: event.error ? scrubDevText(String(event.error), 200) : null,
          },
          api.logger,
        );
      } catch (err) {
        api.logger.warn(`[sentrook-openclaw] after_tool_call failed: ${String(err)}`);
      }
    });

    api.on("session_end", (_event: unknown, ctx: SessionContext) => {
      sessions.delete(sessionKeyOf(ctx));
    });

    const approvalSummary =
      `interactive=${config.approval.interactiveTimeoutMs}ms/deny, ` +
      `scheduled=${config.approval.scheduledTimeoutMs}ms/${config.approval.scheduledTimeoutBehavior} ` +
      `(${config.approval.scheduledIntentKinds.join("+")})`;
    const scanAuthSummary = hasScanCredentials(config.auth)
      ? config.auth.oidc
        ? "scan-auth=oidc"
        : "scan-auth=apikey"
      : urlRequiresScanAuth(config.url)
        ? "scan-auth=missing"
        : "scan-auth=off";
    api.logger.info(
      `[sentrook-openclaw] registered (url=${config.url}, ` +
        `${scanAuthSummary}, timeout=${config.timeoutMs}ms, onScanError=${config.onScanError}, ` +
        `feedback=${config.feedbackMode}, ` +
        `sanitization=on, approval: ${approvalSummary})`,
    );
  },
};

export default plugin;
