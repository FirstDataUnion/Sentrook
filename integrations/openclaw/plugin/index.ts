/**
 * Sentrook OpenClaw plugin (the "layer").
 *
 * Awaits hosted /scan and maps allow / review / block to OpenClaw
 * before_tool_call decisions (block veto or requireApproval). Unattended
 * hosted reviews are a Sentrook veto until OpenClaw can deliver plugin
 * cards on cron (https://github.com/openclaw/openclaw/issues/138853).
 * PlanIR is always scrubbed before egress.
 */

import { join } from "node:path";
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
  classifyAttendance,
  extractIntentText,
  firstNonemptyIntent,
  type Attendance,
  type IntentKind,
} from "./attendance.ts";
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
import { honestMissTitle, overlayApprovalCopy, pendingTrustPreview } from "./reviewCopy.ts";
import {
  type AllowlistConfig,
  matchAllowlist,
  recordAllowAlways,
  resolveAllowlistConfig,
} from "./localAllowlist.ts";
import {
  buildPlanirSnapshot,
  lastPendingStep,
  unwrapHostToolResult,
  type PlanIR,
  type SnapshotCall,
} from "./planir.ts";
import { SCAN_BASE_URL } from "./scanEndpoint.ts";
import { DualIndexMap, runIdPrefix, sessionIdsOf } from "./sessionStore.ts";
import { LivePolicyStore, LIVE_POLICY_FILE } from "./livePolicy.ts";
import { agentIdsFromConfig, listHostSessions } from "./hostSessions.ts";
import { ReviewCardStore, snapshotReviewPrior, PENDING_CARDS_FILE } from "./reviewCards.ts";
import {
  applyApprovalRequested,
  joinCardApprovalIds,
  scheduleApprovalIdJoin,
  startApprovalIdCapture,
  stopApprovalIdCapture,
} from "./approvalGateway.ts";
import { DASHBOARD_PATH, createSentrookFeatureHandlers, handleSentrookHttp } from "./dashboard.ts";
import { SENTROOK_PLUGIN_ID } from "./featureContract.ts";
import {
  registerFeatureEvents,
  registerFeatureOperations,
  type SessionActionRegistration,
} from "./featureOperations.ts";
import { hostUiSupport, customPluginUiEnabled, readOnlyTabMessage, resolveHostVersion } from "./hostVersion.ts";
import {
  resolveDashboardAccessToken,
  dashboardTabPath,
} from "./dashboardAuth.ts";
import {
  applyDashboardSetup,
  dashboardSetupNeeded,
  type DashboardSetupInput,
} from "./dashboardSetup.ts";
import { resolveStateDir } from "./configure.ts";
import { runVerify } from "./verify.ts";
import {
  appendOperatorLog,
  buildResolutionOperatorEvent,
  buildResultOperatorEvent,
  buildScanErrorOperatorEvent,
  buildScanOperatorEvent,
  mintOperatorLogId,
  operatorPluginVersion,
  purgeOperatorLog,
  resolutionPostsFeedback,
  resolveOperatorLogConfig,
  scrubOperatorArgs,
} from "./operatorLog.ts";
import { ensureConversationAccess, patchSentrookPluginConfig } from "./pluginConfigPatch.ts";
import {
  resolveReviewSkip,
  resolveSensitivity,
  resolveUnattendedSensitivity,
  skipResolutionDecision,
  combinedAllowAll,
  laterQuietUntil,
  type Sensitivity,
} from "./sessionPolicy.ts";
import {
  UNATTENDED_BLOCK_DECISION,
  unattendedReviewBlockReason,
} from "./unattendedReview.ts";
import {
  handleSentrookCommand,
  SENTROOK_COMMAND_DEF,
  type SlashSession,
} from "./slashCommand.ts";
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
  prompt?: string;
  messages?: unknown[];
  runId?: string;
}
interface MessageReceivedEvent {
  content?: unknown;
  prompt?: string;
  text?: string;
  body?: string;
  runId?: string;
}
interface BeforeToolCallEvent {
  toolName: string;
  params?: Json;
  runId?: string;
  toolCallId?: string;
  tool_call_id?: string;
  callId?: string;
}
interface AfterToolCallEvent {
  toolName: string;
  params?: Json;
  result?: unknown;
  error?: string;
  runId?: string;
  toolCallId?: string;
  tool_call_id?: string;
  callId?: string;
}
interface AgentContext {
  agentId?: string;
  sessionId?: string;
  sessionKey?: string;
  runId?: string;
  abortSignal?: AbortSignal;
  /** Host trigger on agent-turn hooks: user / cron / heartbeat. Absent on before_tool_call. */
  trigger?: string;
  /** Originating cron job id on agent-turn hooks. Absent on before_tool_call. */
  jobId?: string;
  childSessionKey?: string;
  requesterSessionKey?: string;
}

interface SubagentSpawnEvent {
  childSessionKey?: string;
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
  pluginId?: string;
  onResolution?: (decision: ApprovalResolution) => void | Promise<void>;
  /** Host may call this with the minted ``plugin:`` id after requireApproval returns. */
  onRegistered?: (handle: { approvalId?: string }) => void;
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
  on: (
    hook: string,
    handler: (event: any, ctx: any) => unknown,
    opts?: { priority?: number; timeoutMs?: number },
  ) => void;
  registerCli?: (
    registrar: (ctx: { program: any }) => void | Promise<void>,
    opts?: {
      commands?: string[];
      descriptors?: Array<{ name: string; description: string; hasSubcommands?: boolean }>;
      parentPath?: string[];
    },
  ) => void;
  registerCommand?: (command: {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    requiredScopes?: string[];
    handler: (ctx: {
      args?: string;
      sessionId?: string;
      sessionKey?: string;
      senderIsOwner?: boolean;
      isAuthorizedSender?: boolean;
      channel?: string;
      agentId?: string;
    }) => { text: string } | Promise<{ text: string }>;
  }) => void;
  registerHttpRoute?: (params: {
    path: string;
    auth: "gateway" | "plugin";
    match?: "exact" | "prefix";
    handler: (
      req: import("node:http").IncomingMessage,
      res: import("node:http").ServerResponse,
    ) => Promise<boolean | void> | boolean | void;
  }) => void;
  runtime?: {
    gateway?: {
      isAvailable?: () => Promise<boolean>;
      request: (method: string, params?: unknown, opts?: { timeoutMs?: number }) => Promise<unknown>;
    };
    agent?: {
      session?: {
        listSessionEntries?: (params?: {
          agentId?: string;
          readOnly?: boolean;
        }) => Array<{
          sessionKey?: string;
          entry?: {
            sessionId?: string;
            sessionKey?: string;
            archivedAt?: number | null;
            updatedAt?: number;
            lastInteractionAt?: number;
          };
        }>;
      };
    };
  };
  config?: unknown;
  /** Present since the host gained plugin session actions; see featureOperations.ts. */
  registerSessionAction?: (action: SessionActionRegistration) => void;
  registerService?: (service: {
    id: string;
    start: (ctx: { gatewayEvents?: { emit: (event: string, payload: unknown, opts?: { scope?: string }) => void } }) => void;
    stop?: () => void;
  }) => void;
  session?: {
    controls?: {
      registerControlUiDescriptor?: (descriptor: {
        surface: string;
        id: string;
        label: string;
        description?: string;
        path?: string;
        auth?: string;
        group?: string;
        requiredScopes?: string[];
      }) => void;
      registerSessionAction?: (action: SessionActionRegistration) => void;
    };
  };
}

interface RunIntent {
  intent: string;
  kind: IntentKind;
  trigger?: string;
  jobId?: string;
  unattended: boolean;
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
  sensitivity: Sensitivity;
  unattendedSensitivity: Sensitivity;
}

// ---- Per-session trajectory state -------------------------------------------

interface SessionState {
  sessionId?: string;
  sessionKey?: string;
  lastIntent?: string;
  runIntents: Map<string, RunIntent>;
  executed: SnapshotCall[];
  pending: Map<
    string,
    {
      tool: string;
      args: Json;
      stepSeq: number;
      runId: string;
      eventId?: string;
      awaitingApproval?: boolean;
    }
  >;
  stepSeq: number;
  allowAll: boolean;
  quietUntilMs: number | null;
  attendedSensitivity?: Sensitivity | null;
  unattendedSensitivity?: Sensitivity | null;
}

const MAX_TRAJECTORY = 200;
const MAX_RESULT_TEXT = 20_000;
/** Default scan wait. 14s leaves 1s slack under OpenClaw 2.0's 15s fail-closed hook. */
export const DEFAULT_SCAN_TIMEOUT_MS = 14_000;
/** OpenClaw host cap for `api.on(..., { timeoutMs })`. */
export const OPENCLAW_HOOK_TIMEOUT_CAP_MS = 600_000;
/** JS / mint-cached slack so the host await outlasts the scan abort. */
const BEFORE_TOOL_CALL_SLACK_MS = 1_000;

function clampPositiveMs(value: number, cap: number): number {
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_SCAN_TIMEOUT_MS;
  return Math.min(Math.round(value), cap);
}

/** Scan POST timeout: explicit config/env, else 14000ms. Capped at the hook max. */
export function resolveScanTimeoutMs(
  cfgTimeout: unknown,
  env: NodeJS.ProcessEnv = process.env,
): number {
  if (typeof cfgTimeout === "number" && Number.isFinite(cfgTimeout) && cfgTimeout > 0) {
    return clampPositiveMs(cfgTimeout, OPENCLAW_HOOK_TIMEOUT_CAP_MS);
  }
  const envMs = Number(env.SENTROOK_SCAN_TIMEOUT_MS);
  if (Number.isFinite(envMs) && envMs > 0) {
    return clampPositiveMs(envMs, OPENCLAW_HOOK_TIMEOUT_CAP_MS);
  }
  return DEFAULT_SCAN_TIMEOUT_MS;
}

/** Host `before_tool_call` await budget: scan timeout plus 1s slack, capped at 10 min. */
export function resolveBeforeToolCallTimeoutMs(scanTimeoutMs: number): number {
  return clampPositiveMs(scanTimeoutMs + BEFORE_TOOL_CALL_SLACK_MS, OPENCLAW_HOOK_TIMEOUT_CAP_MS);
}

function resolveRunId(eventRunId?: string, ctxRunId?: string): string {
  return String(eventRunId ?? ctxRunId ?? "run_1");
}

function attendanceFromPlan(
  plan: PlanIR,
  scheduledKinds: ApprovalPolicyConfig["scheduledIntentKinds"],
  unattendedOverride?: boolean,
): Attendance {
  const kind = plan.intent_kind ?? undefined;
  const trigger =
    kind === "cron" || kind === "heartbeat" || kind === "user" ? kind : undefined;
  const classified = classifyAttendance(
    {
      trigger,
      sessionKey: plan.metadata.session_key,
      intentText: plan.intent,
    },
    scheduledKinds,
  );
  if (typeof unattendedOverride === "boolean") {
    return { kind: classified.kind, unattended: unattendedOverride };
  }
  return classified;
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
    sensitivity: resolveSensitivity(cfg, process.env),
    unattendedSensitivity: resolveUnattendedSensitivity(cfg, process.env),
  };
}

function resultBody(result: unknown, error?: string): string {
  return unwrapHostToolResult(result, error).text;
}

function resultToText(result: unknown, error?: string): string {
  const text = resultBody(result, error);
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
      const { plan: outbound } = maybeSanitizePlanir(plan);
      const headers = await buildScanAuthHeadersAsync(auth);
      await fetch(`${url}/latency`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          tool_call_id: outbound.metadata.tool_call_id ?? null,
          session_id: outbound.metadata.session_id ?? null,
          run_id: outbound.run_id,
          pending_tool: pendingToolName(outbound),
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
  abortSignal?: AbortSignal,
): Promise<PostScanResult | ScanFailure> {
  const resolvedAuth: ScanAuthConfig = auth ?? { apiKey: null, oidc: null };
  const { plan: outbound, sanitizeMs } = maybeSanitizePlanir(plan);
  const sanitizeTiming: SanitizeTiming = {
    enabled: true,
    ms: sanitizeMs,
  };
  const body = JSON.stringify(outbound);

  if (abortSignal?.aborted) {
    logger?.warn("[sentrook-openclaw] scan aborted before request");
    return { ok: false, kind: "timeout", detail: "aborted" };
  }

  // Mint + POST share one budget so a hung Identity host cannot overrun
  // OpenClaw 2.0's fail-closed before_tool_call wait (default 15s).
  const started = performance.now();
  const deadline = started + timeoutMs;
  const remainingMs = (): number => Math.max(1, Math.ceil(deadline - performance.now()));

  let headers: Record<string, string>;
  try {
    headers = await buildScanAuthHeadersAsync(resolvedAuth, {}, fetch, remainingMs());
  } catch (err) {
    const failure = scanAuthErrorToFailure(err);
    logger?.warn(`[sentrook-openclaw] scan auth failed: ${failure.detail}`);
    return failure;
  }

  const controller = new AbortController();
  const onParentAbort = () => controller.abort();
  if (abortSignal) {
    if (abortSignal.aborted) controller.abort();
    else abortSignal.addEventListener("abort", onParentAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), remainingMs());
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
    abortSignal?.removeEventListener("abort", onParentAbort);
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
    /** Set when a local allowlist entry short-circuits a hosted review. */
    allowlistHitLabel?: string;
    /** Operator-log / ``/sentrook pending`` id for the review-card footer. */
    eventId?: string;
    /** When set, wins over re-classifying the plan (subagent inheritance). */
    unattended?: boolean;
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
        ctx.allowlistHitLabel =
          (detail.startsWith("skeleton=") ? detail.slice("skeleton=".length) : detail) ||
          match.kind ||
          "";
        return undefined;
      }
    }

    const timing = resolveApprovalTiming(
      ctx.approval,
      attendanceFromPlan(plan, ctx.approval.scheduledIntentKinds, ctx.unattended).unattended,
    );
    if (timing.unattended) {
      ctx.logger.info(
        `[sentrook-openclaw] unattended review (${plan.intent_kind ?? "unknown"}): ` +
          `blocking; OpenClaw cannot deliver a plugin approval card on cron/heartbeat ` +
          `(https://github.com/openclaw/openclaw/issues/138853)`,
      );
      return {
        block: true,
        blockReason: unattendedReviewBlockReason({
          eventId: ctx.eventId,
          sessionKey: plan.metadata.session_key,
          command: pendingTrustPreview(pendingTool, ctx.pendingArgs ?? pending?.args),
        }),
      };
    }
    const copy = overlayApprovalCopy({
      scanTitle: scan.review_title,
      scanDescription: scan.review_description,
      fallbackTitle: honestMissTitle(pendingTool),
      fallbackDescription:
        scan.summary || "Sentrook flagged this tool call for human review",
      pendingTool,
      pendingArgs: ctx.pendingArgs,
      eventId: ctx.eventId,
    });
    return {
      requireApproval: {
        title: copy.title,
        description: copy.description,
        severity: scan.review_severity || "warning",
        timeoutMs: timing.timeoutMs,
        timeoutBehavior: timing.timeoutBehavior,
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        pluginId: "sentrook-openclaw",
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
          if (resolutionPostsFeedback(decision, ctx.feedbackMode !== "off")) {
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

function toolCallIdFromEvent(event: BeforeToolCallEvent): string | undefined {
  for (const value of [event.toolCallId, event.tool_call_id, event.callId]) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function rememberPending(
  st: SessionState,
  toolCallId: string | undefined,
  pendingCall: SnapshotCall,
  meta: {
    stepSeq: number;
    runId: string;
    eventId?: string;
    awaitingApproval?: boolean;
  },
): void {
  if (!toolCallId) return;
  st.pending.set(toolCallId, {
    tool: pendingCall.tool,
    args: pendingCall.args,
    stepSeq: meta.stepSeq,
    runId: meta.runId,
    eventId: meta.eventId,
    awaitingApproval: Boolean(meta.awaitingApproval),
  });
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
  meta: { stepSeq: number; runId: string; eventId?: string },
  cards?: ReviewCardStore,
): BeforeToolCallResult | undefined {
  if (result?.block) return result;
  rememberPending(st, toolCallId, pendingCall, {
    ...meta,
    awaitingApproval: Boolean(result?.requireApproval),
  });
  const approval = result?.requireApproval;
  if (!approval || !toolCallId) return result;
  const innerRegistered = approval.onRegistered;
  approval.onRegistered = (handle) => {
    const id = typeof handle?.approvalId === "string" ? handle.approvalId.trim() : "";
    if (id) cards?.attachApprovalId(toolCallId, id);
    innerRegistered?.(handle);
  };
  const inner = approval.onResolution;
  approval.onResolution = async (decision) => {
    const remembered = st.pending.get(toolCallId);
    if (remembered) remembered.awaitingApproval = false;
    cards?.take(toolCallId);
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

function attachOperatorLogResolution(
  result: BeforeToolCallResult | undefined,
  plan: PlanIR,
  logger?: PluginLogger,
  opts: {
    contributeEligible?: boolean;
    unattended?: boolean;
    parentSessionId?: string | null;
  } = {},
): BeforeToolCallResult | undefined {
  const approval = result?.requireApproval;
  if (!approval?.onResolution) return result;
  const inner = approval.onResolution;
  approval.onResolution = async (decision) => {
    const feedbackPosted = resolutionPostsFeedback(
      decision,
      Boolean(opts.contributeEligible),
    );
    appendOperatorLog(
      resolveOperatorLogConfig(),
      buildResolutionOperatorEvent({
        plan,
        decision,
        feedbackPosted,
        unattended: opts.unattended,
        contributeEligible: opts.contributeEligible,
        parentSessionId: opts.parentSessionId,
      }),
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
    "Sentrook trajectory scanner. Scans tool calls and can allow, require approval, or block flagged actions.",

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
              description: "Sentrook plugin helpers (configure, verify, allowlist)",
              hasSubcommands: true,
            },
          ],
        },
      );
      if (mode === "cli-metadata") return;
    }

    const config = resolveConfig(api);
    const sessions = new DualIndexMap<SessionState>();
    const livePolicy = new LivePolicyStore(join(resolveStateDir(), LIVE_POLICY_FILE));

    if (urlRequiresScanAuth(config.url) && !hasScanCredentials(config.auth)) {
      api.logger.warn(
        "[sentrook-openclaw] hosted scan URL has no credentials — " +
          "open the Sentrook tab to finish setup, or run: openclaw sentrook configure  " +
          "(or set SENTROOK_SCAN_CLIENT_ID + SENTROOK_SCAN_CLIENT_SECRET in ~/.openclaw/.env)",
      );
    }

    if (mode === "full") {
      const access = ensureConversationAccess();
      if (access.ok && access.wrote) {
        api.logger.info(
          "[sentrook-openclaw] wrote hooks.allowConversationAccess=true in openclaw.json — " +
            "restart the gateway if operator-log intent stays empty",
        );
      }
    }

    const emptySession = (): SessionState => ({
      runIntents: new Map(),
      executed: [],
      pending: new Map(),
      stepSeq: 0,
      allowAll: false,
      quietUntilMs: null,
      attendedSensitivity: null,
      unattendedSensitivity: null,
    });

    const MAX_LINEAGE = 512;
    const sessionUnattended = new Map<string, boolean>();
    const subagentParents = new Map<string, string>();

    const rememberBounded = <V>(map: Map<string, V>, key: string, value: V): void => {
      if (map.has(key)) map.delete(key);
      map.set(key, value);
      while (map.size > MAX_LINEAGE) {
        const oldest = map.keys().next().value;
        if (oldest === undefined) break;
        map.delete(oldest);
      }
    };

    const rememberParent = (child?: string, parent?: string): void => {
      const childKey = child?.trim();
      const parentKey = parent?.trim();
      if (!childKey || !parentKey || childKey === parentKey) return;
      rememberBounded(subagentParents, childKey, parentKey);
    };

    const classifyCall = (ctx: AgentContext, runIntent?: RunIntent): Attendance => {
      const sessionKey = ctx.sessionKey?.trim() || undefined;
      const parentSessionKey = sessionKey ? subagentParents.get(sessionKey) : undefined;
      const parentUnattended = parentSessionKey
        ? sessionUnattended.get(parentSessionKey)
        : undefined;
      const attendance = classifyAttendance(
        {
          trigger: ctx.trigger ?? runIntent?.trigger,
          jobId: ctx.jobId ?? runIntent?.jobId,
          sessionKey,
          parentSessionKey,
          parentUnattended,
          intentText: runIntent?.intent,
        },
        config.approval.scheduledIntentKinds,
      );
      if (sessionKey) rememberBounded(sessionUnattended, sessionKey, attendance.unattended);
      return attendance;
    };

    const stashRunAttendance = (
      st: SessionState,
      runId: string,
      ctx: AgentContext,
      intent: string,
    ): Attendance => {
      const attendance = classifyCall(ctx, {
        intent,
        kind: "user",
        unattended: false,
        trigger: ctx.trigger,
        jobId: ctx.jobId,
      });
      st.runIntents.set(runId, {
        intent,
        kind: attendance.kind,
        trigger: ctx.trigger,
        jobId: ctx.jobId,
        unattended: attendance.unattended,
      });
      return attendance;
    };

    const getSession = (ctx: AgentContext | SessionContext): SessionState => {
      livePolicy.hydrateInto(sessions, emptySession);
      const ids = sessionIdsOf(ctx);
      const st = sessions.getOrCreate(ids, emptySession);
      if (ids.sessionId) st.sessionId = ids.sessionId;
      if (ids.sessionKey) st.sessionKey = ids.sessionKey;
      const flags = livePolicy.sessionFlags(ids);
      st.allowAll = flags.allowAll;
      st.quietUntilMs = flags.quietUntilMs;
      st.attendedSensitivity = flags.attendedSensitivity;
      st.unattendedSensitivity = flags.unattendedSensitivity;
      const snap = livePolicy.read();
      live.allowAll = snap.allowAll;
      live.quietUntilMs = snap.quietUntilMs;
      return st;
    };

    const listHost = () =>
      listHostSessions(api.runtime?.agent?.session, {
        agentIds: agentIdsFromConfig(api.config),
      });

    const reviewCards = new ReviewCardStore({
      persistPath: join(resolveStateDir(), PENDING_CARDS_FILE),
    });

    const live = {
      sensitivity: config.sensitivity,
      unattendedSensitivity: config.unattendedSensitivity,
      feedbackMode: config.feedbackMode,
      onScanError: config.onScanError,
      allowAll: livePolicy.read().allowAll,
      quietUntilMs: livePolicy.read().quietUntilMs as number | null,
    };

    const syncSessionFlags = (st: {
      sessionId?: string;
      sessionKey?: string;
      allowAll: boolean;
      quietUntilMs: number | null;
      attendedSensitivity?: Sensitivity | null;
      unattendedSensitivity?: Sensitivity | null;
    }) => {
      livePolicy.writeSession(
        { sessionId: st.sessionId, sessionKey: st.sessionKey },
        {
          allowAll: st.allowAll,
          quietUntilMs: st.quietUntilMs,
          attendedSensitivity: st.attendedSensitivity ?? null,
          unattendedSensitivity: st.unattendedSensitivity ?? null,
        },
      );
    };

    const setAllowAll = (value: boolean) => {
      live.allowAll = value;
      livePolicy.writeGlobal({ allowAll: value, clearSessionAllowAll: !value });
      if (!value) {
        for (const st of sessions.uniqueValues()) st.allowAll = false;
      }
    };

    const setQuietUntilMs = (value: number | null) => {
      live.quietUntilMs = value;
      livePolicy.writeGlobal({ quietUntilMs: value });
    };

    const pluginCfgNow = (): Record<string, unknown> =>
      (api.pluginConfig ?? {}) as Record<string, unknown>;

    const operatorLogNow = () => resolveOperatorLogConfig(process.env, pluginCfgNow());

    const slashSessionOf = (ids: ReturnType<typeof sessionIdsOf>): SlashSession =>
      getSession(ids) as SlashSession;

    const persistResult = (persisted: ReturnType<typeof patchSentrookPluginConfig>) =>
      persisted.ok
        ? { persisted: true as const }
        : { persisted: false as const, error: persisted.error };

    const setSensitivity = (value: typeof live.sensitivity) => {
      live.sensitivity = value;
      const cfg = pluginCfgNow();
      cfg.sensitivity = value;
      api.pluginConfig = cfg;
      return persistResult(patchSentrookPluginConfig({ sensitivity: value }));
    };

    const setUnattendedSensitivity = (value: typeof live.unattendedSensitivity) => {
      live.unattendedSensitivity = value;
      const cfg = pluginCfgNow();
      cfg.unattendedSensitivity = value;
      api.pluginConfig = cfg;
      return persistResult(patchSentrookPluginConfig({ unattendedSensitivity: value }));
    };

    const setFeedbackMode = (value: typeof live.feedbackMode) => {
      live.feedbackMode = value;
      const cfg = pluginCfgNow();
      const prev =
        cfg.feedback && typeof cfg.feedback === "object"
          ? { ...(cfg.feedback as Record<string, unknown>) }
          : {};
      cfg.feedback = { ...prev, mode: value };
      api.pluginConfig = cfg;
      return persistResult(patchSentrookPluginConfig({ feedback: { mode: value } }));
    };

    const setOnScanError = (value: typeof live.onScanError) => {
      live.onScanError = value;
      const cfg = pluginCfgNow();
      cfg.onScanError = value;
      api.pluginConfig = cfg;
      return persistResult(patchSentrookPluginConfig({ onScanError: value }));
    };

    const setOperatorLogRetention = (patch: { maxAgeDays?: number; maxBytes?: number }) => {
      const current = operatorLogNow();
      if (patch.maxAgeDays != null) current.maxAgeDays = patch.maxAgeDays;
      if (patch.maxBytes != null) current.maxBytes = patch.maxBytes;
      const cfg = pluginCfgNow();
      const prev =
        cfg.operatorLog && typeof cfg.operatorLog === "object"
          ? { ...(cfg.operatorLog as Record<string, unknown>) }
          : {};
      cfg.operatorLog = { ...prev, ...patch };
      api.pluginConfig = cfg;
      return persistResult(patchSentrookPluginConfig({ operatorLog: patch }));
    };

    if (api.registerCommand) {
      api.registerCommand({
        ...SENTROOK_COMMAND_DEF,
        handler: (ctx) =>
          handleSentrookCommand(ctx, {
            sessionOf: slashSessionOf,
            listSessions: () => {
              livePolicy.hydrateInto(sessions, emptySession);
              return sessions.uniqueValues() as SlashSession[];
            },
            listHostSessions: listHost,
            listCards: () =>
              reviewCards.list().map((card) => ({
                eventId: card.eventId,
                toolCallId: card.toolCallId,
                tool: card.tool,
                args: card.args,
                sessionId: card.sessionId,
                sessionKey: card.sessionKey,
                approvalId: card.approvalId,
                intent: card.intent,
                intentKind: card.intentKind,
                scan: card.scan,
              })),
            joinCards: () =>
              joinCardApprovalIds(reviewCards, api.runtime?.gateway, {
                config: api.config,
                logger: api.logger,
              }).then(() => undefined),
            sensitivity: () => live.sensitivity,
            setSensitivity,
            unattendedSensitivity: () => live.unattendedSensitivity,
            setUnattendedSensitivity,
            allowAll: () => livePolicy.read().allowAll,
            setAllowAll,
            quietUntilMs: () => livePolicy.read().quietUntilMs,
            setQuietUntilMs,
            syncSessionFlags,
            feedbackMode: () => live.feedbackMode,
            setFeedbackMode,
            onScanError: () => live.onScanError,
            setOnScanError,
            operatorLog: operatorLogNow,
            setOperatorLogRetention,
            allowlist: config.allowlist,
            now: () => Date.now(),
          }),
      });
    }

    const resolveLiveAuth = (): ScanAuthConfig =>
      resolveScanAuthConfig(
        (api.pluginConfig ?? {}) as Record<string, unknown>,
        envWithOpenclawDotenv(process.env),
      );

    const featureEvents = registerFeatureEvents(api, SENTROOK_PLUGIN_ID);
    const emitReviewsChanged = () => featureEvents.emit("reviews_changed");
    const listApprovalOpts = () => ({ config: api.config, logger: api.logger });
    const rememberApprovalCard = (card: Parameters<ReviewCardStore["put"]>[0]) => {
      reviewCards.put(card);
      emitReviewsChanged();
      scheduleApprovalIdJoin(reviewCards, api.runtime?.gateway, listApprovalOpts());
    };

    if ((api.registrationMode ?? "full") === "full") {
      void startApprovalIdCapture({
        config: api.config,
        logger: api.logger,
        onRequested: (item) => {
          applyApprovalRequested(reviewCards, item);
          emitReviewsChanged();
        },
      });
      api.registerService?.({
        id: "sentrook-approval-ids",
        start: () => {},
        stop: () => {
          void stopApprovalIdCapture();
        },
      });
    }

    const dashboardDeps = {
      cards: reviewCards,
      sessions: {
        uniqueValues: () => {
          livePolicy.hydrateInto(sessions, emptySession);
          return sessions.uniqueValues();
        },
        getOrCreate: (ids: ReturnType<typeof sessionIdsOf>, factory: () => SessionState) => {
          livePolicy.hydrateInto(sessions, emptySession);
          return sessions.getOrCreate(ids, factory);
        },
      },
      sessionFactory: emptySession,
      listHostSessions: listHost,
      sensitivity: () => live.sensitivity,
      setSensitivity,
      unattendedSensitivity: () => live.unattendedSensitivity,
      setUnattendedSensitivity,
      allowAll: () => livePolicy.read().allowAll,
      setAllowAll,
      quietUntilMs: () => livePolicy.read().quietUntilMs,
      setQuietUntilMs,
      syncSessionFlags,
      feedbackMode: () => live.feedbackMode,
      setFeedbackMode,
      onScanError: () => live.onScanError,
      setOnScanError,
      operatorLog: operatorLogNow,
      setOperatorLogRetention,
      allowlist: config.allowlist,
      gateway: api.runtime?.gateway,
      config: api.config,
      logger: api.logger,
      setupNeeded: () => dashboardSetupNeeded(resolveLiveAuth()),
      saveSetup: (input: DashboardSetupInput) =>
        applyDashboardSetup({
          input,
          stateDir: resolveStateDir(),
          setFeedbackMode,
          setOnScanError,
        }),
      verifyConnection: () => runVerify({}),
    };

    const hostVersion = resolveHostVersion();
    const uiSupport = hostUiSupport(hostVersion);
    const registered = registerFeatureOperations(
      api,
      createSentrookFeatureHandlers(dashboardDeps, (event) => featureEvents.emit(event)),
    );
    if (registered > 0) {
      api.logger.info(
        `[sentrook-openclaw] ${registered} dashboard operations registered ` +
          `(OpenClaw ${hostVersion ?? "unknown"}; native page needs Labs → Custom plugin UI)`,
      );
    }

    if (api.registerHttpRoute) {
      const accessToken = resolveDashboardAccessToken(resolveStateDir());
      const httpDeps = { ...dashboardDeps, accessToken };
      const dashboardHttp = (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) =>
        handleSentrookHttp(req, res, httpDeps);
      api.registerHttpRoute({
        path: DASHBOARD_PATH,
        auth: "plugin",
        match: "prefix",
        handler: dashboardHttp,
      });

      // Iframe tab is the GET-only fallback when Labs native UI is off.
      // Native Settings writes patch openclaw.json and can remount this tab;
      // skip it when Custom plugin UI is on so operators only have Sentrook.
      if (!customPluginUiEnabled(api.config)) {
        api.session?.controls?.registerControlUiDescriptor?.({
          surface: "tab",
          id: "sentrook",
          label: "Sentrook (read-only)",
          description: readOnlyTabMessage(uiSupport, hostVersion),
          path: dashboardTabPath(accessToken),
          group: "control",
          requiredScopes: ["operator.admin"],
        });
      } else {
        api.logger.info(
          "[sentrook-openclaw] native Control UI is on; Sentrook (read-only) iframe tab is not registered",
        );
      }
      api.logger.info(`[sentrook-openclaw] dashboard ${DASHBOARD_PATH} on this gateway`);
    }

    if (config.approval.scheduledTimeoutBehavior === "allow") {
      api.logger.warn(
        "[sentrook-openclaw] approval.scheduledTimeoutBehavior=allow is ignored; " +
          "unresolved reviews always deny (OpenClaw 2.0)",
      );
    }

    const bootDevLog = resolveDevLogConfig();
    if (bootDevLog.enabled) {
      api.logger.info(`[sentrook-openclaw] diagnostic log ${bootDevLog.path}`);
      appendDevLog(
        bootDevLog,
        { event: "register", path: bootDevLog.path },
        api.logger,
      );
    }

    const operatorLog = operatorLogNow();
    if (operatorLog.enabled) {
      purgeOperatorLog(operatorLog, api.logger);
      api.logger.info(`[sentrook-openclaw] operator log ${operatorLog.path}`);
    }

    api.on("before_prompt_build", (event: BeforePromptBuildEvent, ctx: AgentContext) => {
      const st = getSession(ctx);
      const runId = resolveRunId(event.runId, ctx.runId);
      const extracted = extractIntentText(event);
      const existing = st.runIntents.get(runId);
      const intent = firstNonemptyIntent(extracted, existing?.intent, st.lastIntent);
      if (extracted) st.lastIntent = extracted;
      stashRunAttendance(st, runId, ctx, intent);
    });

    api.on("message_received", (event: MessageReceivedEvent, ctx: AgentContext) => {
      const extracted = extractIntentText(event);
      if (!extracted) return;
      const st = getSession(ctx);
      st.lastIntent = extracted;
      const runId = event.runId ?? ctx.runId;
      if (runId) stashRunAttendance(st, String(runId), ctx, extracted);
    });

    api.on("heartbeat_prompt_contribution", (_event: unknown, ctx: AgentContext) => {
      const st = getSession(ctx);
      const runId = resolveRunId(undefined, ctx.runId);
      const existing = st.runIntents.get(runId);
      stashRunAttendance(
        st,
        runId,
        { ...ctx, trigger: ctx.trigger || "heartbeat" },
        firstNonemptyIntent(existing?.intent, st.lastIntent),
      );
    });

    api.on("subagent_spawned", (event: SubagentSpawnEvent, ctx: AgentContext) => {
      rememberParent(event.childSessionKey ?? ctx.childSessionKey, ctx.requesterSessionKey);
    });

    api.on("subagent_delivery_target", (event: SubagentSpawnEvent & { requesterSessionKey?: string }, ctx: AgentContext) => {
      rememberParent(
        event.childSessionKey ?? ctx.childSessionKey,
        event.requesterSessionKey ?? ctx.requesterSessionKey,
      );
    });

    api.on(
      "before_tool_call",
      async (event: BeforeToolCallEvent, ctx: AgentContext) => {
        try {
          const ids = sessionIdsOf(ctx);
          const st = getSession(ctx);
          const pendingCall: SnapshotCall = {
            tool: event.toolName,
            args: (event.params as Json) ?? {},
          };
          const coPending: SnapshotCall[] = [];
          const coPendingIds: string[] = [];
          const callIdHint = toolCallIdFromEvent(event);
          for (const [id, peer] of st.pending) {
            if (callIdHint && id === callIdHint) continue;
            coPending.push({ tool: peer.tool, args: peer.args });
            coPendingIds.push(id);
          }
          const batchSize = coPending.length + 1;
          st.stepSeq += 1;
          const runId = resolveRunId(event.runId, ctx.runId);
          const eventId = mintOperatorLogId();
          const callId = callIdHint ?? eventId;
          const pendingMeta = { stepSeq: st.stepSeq, runId, eventId };
          const runIntent = st.runIntents.get(runId);
          const intentText = firstNonemptyIntent(runIntent?.intent, st.lastIntent);
          const attendance = classifyCall(ctx, {
            intent: intentText,
            kind: runIntent?.kind ?? "user",
            unattended: runIntent?.unattended ?? false,
            trigger: ctx.trigger ?? runIntent?.trigger,
            jobId: ctx.jobId ?? runIntent?.jobId,
          });
          st.runIntents.set(runId, {
            intent: intentText,
            kind: attendance.kind,
            unattended: attendance.unattended,
            trigger: ctx.trigger ?? runIntent?.trigger,
            jobId: ctx.jobId ?? runIntent?.jobId,
          });
          const parentSessionId = ids.sessionKey
            ? (subagentParents.get(ids.sessionKey) ?? null)
            : null;
          const plan = buildPlanirSnapshot({
            executed: st.executed.slice(-MAX_TRAJECTORY),
            pending: pendingCall,
            coPending: coPending.length ? coPending : undefined,
            runId: `${runIdPrefix(ids)}:${runId}`,
            intent: intentText || null,
            intentKind: attendance.kind,
            sessionId: ids.sessionId,
            sessionKey: ids.sessionKey,
            agentId: ctx.agentId,
            toolCallId: callId,
            stepSeq: st.stepSeq,
            batchSize,
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
            ctx.abortSignal,
          );
          if (isScanFailure(scanResult)) {
            const timing = resolveApprovalTiming(config.approval, attendance.unattended);
            const mapped = scanErrorToHookResult(scanResult, {
              onScanError: live.onScanError,
              unattended: timing.unattended,
              interactiveTimeoutMs: config.approval.interactiveTimeoutMs,
              eventId,
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
            appendOperatorLog(
              operatorLogNow(),
              {
                ...buildScanErrorOperatorEvent({
                  plan,
                  pendingArgs: pendingCall.args,
                  hostTool: event.toolName,
                  failure: scanResult,
                  hookResult: mapped,
                  coPendingIds,
                  unattended: timing.unattended,
                  contributeEligible: live.feedbackMode === "submit",
                  parentSessionId,
                }),
                id: eventId,
              },
              api.logger,
            );
            if (mapped?.requireApproval) {
              mapped.requireApproval.pluginId ??= "sentrook-openclaw";
              rememberApprovalCard({
                eventId,
                toolCallId: callId,
                tool: event.toolName,
                args: pendingCall.args,
                scan: {
                  decision: "scan_error",
                  summary: mapped.requireApproval.description,
                  block_reason: scanResult.kind,
                },
                sessionId: ids.sessionId,
                sessionKey: ids.sessionKey,
                agentId: ctx.agentId,
                timeoutMs: mapped.requireApproval.timeoutMs ?? 600_000,
                intent: plan.intent,
                intentKind: plan.intent_kind,
                ...snapshotReviewPrior(st.executed),
              });
            }
            return attachOperatorLogResolution(
              attachDevLogResolution(
                applyPendingLifecycle(
                  mapped,
                  st,
                  callId,
                  pendingCall,
                  pendingMeta,
                  reviewCards,
                ),
                plan,
                pendingCall,
                api.logger,
              ),
              plan,
              api.logger,
              {
                contributeEligible: live.feedbackMode === "submit",
                unattended: attendance.unattended,
                parentSessionId,
              },
            );
          }

          const { scan, timing } = scanResult;
          api.logger.info(`[sentrook-openclaw] ${formatScanTimingLog(plan, scan, timing)}`);
          recordScanLatency(config.url, liveAuth, plan, scan, timing);

          const scanCtx = {
            plan,
            url: config.url,
            auth: liveAuth,
            feedbackMode: live.feedbackMode,
            approval: config.approval,
            allowlist: config.allowlist,
            logger: api.logger,
            pendingArgs: pendingCall.args,
            allowlistHitLabel: undefined as string | undefined,
            eventId,
            unattended: attendance.unattended,
          };
          const translated = translateScanResponse(scan, scanCtx);
          const unattended = attendance.unattended;
          const allowlistHit = scan.decision === "review" && translated == null;
          const flags = livePolicy.sessionFlags(ids);
          const skipReason = resolveReviewSkip({
            hostedDecision: scan.decision,
            unattended,
            allowAll: combinedAllowAll(livePolicy.read().allowAll, flags.allowAll),
            quietUntilMs: laterQuietUntil(livePolicy.read().quietUntilMs, flags.quietUntilMs),
            sensitivity: live.sensitivity,
            unattendedSensitivity: live.unattendedSensitivity,
            sessionAttended: flags.attendedSensitivity,
            sessionUnattended: flags.unattendedSensitivity,
            reviewSeverity: scan.review_severity,
            allowlistHit,
          });
          let hookResult = translated;
          if (skipReason && skipReason !== "allowlist") {
            hookResult = undefined;
            api.logger.info(
              `[sentrook-openclaw] skipping requireApproval (${skipReason}) after hosted review`,
            );
          }
          appendDevLog(
            resolveDevLogConfig(),
            buildScanDevEvent({
              plan,
              pendingArgs: pendingCall.args,
              scan,
              timing,
              hookResult,
              allowlistHit: skipReason === "allowlist",
            }),
            api.logger,
          );
          appendOperatorLog(
            operatorLogNow(),
            {
              ...buildScanOperatorEvent({
                plan,
                pendingArgs: pendingCall.args,
                hostTool: event.toolName,
                scan,
                hookResult,
                skipReason,
                allowlistLabel: scanCtx.allowlistHitLabel,
                coPendingIds,
                unattended,
                contributeEligible: live.feedbackMode === "submit",
                parentSessionId,
              }),
              id: eventId,
            },
            api.logger,
          );
          if (skipReason) {
            appendOperatorLog(
              operatorLogNow(),
              buildResolutionOperatorEvent({
                plan,
                decision: skipResolutionDecision(skipReason),
                feedbackPosted: false,
                unattended,
                contributeEligible: live.feedbackMode === "submit",
                parentSessionId,
              }),
              api.logger,
            );
          } else if (unattended && hookResult?.block && scan.decision === "review") {
            appendOperatorLog(
              operatorLogNow(),
              buildResolutionOperatorEvent({
                plan,
                decision: UNATTENDED_BLOCK_DECISION,
                feedbackPosted: false,
                unattended,
                contributeEligible: live.feedbackMode === "submit",
                parentSessionId,
              }),
              api.logger,
            );
          }
          if (hookResult?.requireApproval) {
            hookResult.requireApproval.pluginId ??= "sentrook-openclaw";
            rememberApprovalCard({
              eventId,
              toolCallId: callId,
              tool: event.toolName,
              args: pendingCall.args,
              scan: {
                decision: scan.decision,
                risk: scan.risk,
                summary: scan.summary,
                matched_rules: scan.matched_rules,
                review_severity: scan.review_severity,
                block_reason: scan.block_reason,
              },
              sessionId: ids.sessionId,
              sessionKey: ids.sessionKey,
              agentId: ctx.agentId,
              timeoutMs: hookResult.requireApproval.timeoutMs ?? 600_000,
              intent: plan.intent,
              intentKind: plan.intent_kind,
              ...snapshotReviewPrior(st.executed),
            });
          }
          return attachOperatorLogResolution(
            attachDevLogResolution(
              applyPendingLifecycle(
                hookResult,
                st,
                callId,
                pendingCall,
                pendingMeta,
                reviewCards,
              ),
              plan,
              pendingCall,
              api.logger,
            ),
            plan,
            api.logger,
            {
              contributeEligible: live.feedbackMode === "submit",
              unattended,
              parentSessionId,
            },
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
          const ids = sessionIdsOf(ctx);
          const runId = resolveRunId(event.runId, ctx.runId);
          const parentKey = ids.sessionKey ? subagentParents.get(ids.sessionKey) : undefined;
          appendOperatorLog(
            operatorLogNow(),
            {
              event: "scan_error",
              id: mintOperatorLogId(),
              run_id: `${runIdPrefix(ids)}:${runId}`,
              metadata: {
                adapter: "openclaw",
                agent_id: ctx.agentId ?? null,
                session_id: ids.sessionId ?? null,
                session_key: ids.sessionKey ?? null,
                hook: "before_tool_call",
                tool_call_id: event.toolCallId ?? null,
                batch_size: 1,
              },
              pending: {
                id: "s0",
                tool: event.toolName,
                status: "pending",
                args: scrubOperatorArgs((event.params as Json) ?? {}),
              },
              scan_error: { kind: "plugin_error", detail, status: null },
              hook: { action: "block" },
              effect: "blocked",
              label_source: "scanner",
              plugin_version: operatorPluginVersion(),
              parent_session_id: parentKey ?? null,
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
      { priority: 10, timeoutMs: resolveBeforeToolCallTimeoutMs(config.timeoutMs) },
    );

    api.on("after_tool_call", (event: AfterToolCallEvent, ctx: AgentContext) => {
      try {
        const st = getSession(ctx);
        const ids = sessionIdsOf(ctx);
        const callId = toolCallIdFromEvent(event);
        let remembered = callId ? st.pending.get(callId) : undefined;
        if (remembered && callId) st.pending.delete(callId);
        const runId = remembered?.runId ?? resolveRunId(event.runId, ctx.runId);
        const call = remembered ?? {
          tool: event.toolName,
          args: (event.params as Json) ?? {},
          stepSeq: st.stepSeq,
          runId,
        };

        const command =
          call.tool === "exec"
            ? String((call.args.command ?? call.args.cmd ?? "") as string) || undefined
            : undefined;

        const unwrapped = unwrapHostToolResult(event.result, event.error);
        const runIntent = st.runIntents.get(runId);
        const attendance = classifyCall(ctx, runIntent);
        appendOperatorLog(
          operatorLogNow(),
          buildResultOperatorEvent({
            runId: `${runIdPrefix(ids)}:${runId}`,
            metadata: {
              session_id: ids.sessionId ?? null,
              session_key: ids.sessionKey ?? null,
              agent_id: ctx.agentId ?? null,
              tool_call_id: event.toolCallId ?? null,
              step_seq: remembered?.stepSeq ?? null,
              batch_size: 1,
            },
            resultText: unwrapped.text,
            contentType: unwrapped.contentType,
            ok: !event.error,
            command,
            intent: runIntent?.intent ?? st.lastIntent ?? null,
            intentKind: attendance.kind,
            unattended: attendance.unattended,
            contributeEligible: live.feedbackMode === "submit",
            parentSessionId: ids.sessionKey
              ? (subagentParents.get(ids.sessionKey) ?? null)
              : null,
          }),
          api.logger,
        );
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
            session_id: ctx.sessionId ?? null,
            session_key: ctx.sessionKey ?? null,
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
      const ids = sessionIdsOf(ctx);
      livePolicy.clearSession(ids);
      sessions.delete(ids);
      const key = ids.sessionKey?.trim();
      if (key) {
        sessionUnattended.delete(key);
        subagentParents.delete(key);
        const orphaned = [...subagentParents]
          .filter(([, parent]) => parent === key)
          .map(([child]) => child);
        for (const child of orphaned) subagentParents.delete(child);
      }
    });

    const approvalSummary =
      `interactive=${config.approval.interactiveTimeoutMs}ms/deny, ` +
      `scheduled=${config.approval.scheduledTimeoutMs}ms/deny ` +
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
        `${scanAuthSummary}, timeout=${config.timeoutMs}ms, ` +
        `hook=${resolveBeforeToolCallTimeoutMs(config.timeoutMs)}ms, ` +
        `onScanError=${live.onScanError}, ` +
        `feedback=${live.feedbackMode}, ` +
        `sensitivity=${live.sensitivity}, ` +
        `unattendedSensitivity=${live.unattendedSensitivity}, ` +
        `sanitization=on, approval: ${approvalSummary})`,
    );
  },
};

export default plugin;
