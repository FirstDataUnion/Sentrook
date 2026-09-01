/**
 * Maintainer-only local JSONL diagnostic log.
 *
 * Off by default. Not in the plugin schema, configure wizard, or public README.
 * Enable with SENTROOK_DEV_LOG=1 in process env or ~/.openclaw/.env; optional
 * SENTROOK_DEV_LOG_PATH overrides the default
 * ($OPENCLAW_STATE_DIR/sentrook-dev.log).
 *
 * Records local pending argv, scrubbed egress PlanIR, hosted scan decisions,
 * and the OpenClaw review-card copy actually shown — so a bad card or a
 * surprising review can be compared against the corpus without reconstructing
 * the hook from gateway lines.
 *
 * Secrets/PII are pattern-scrubbed (same rules as review cards / PlanIR
 * egress). The file is still sensitive: chmod 600, treat like openclaw.json.
 * Never logs OIDC tokens or scan credentials. Failures never affect the hook.
 */

import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  renameSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { dirname, isAbsolute, resolve as pathResolve } from "node:path";
import { homedir } from "node:os";

import { envWithOpenclawDotenv } from "./auth.ts";
import { lastPendingStep, type PlanIR } from "./planir.ts";
import {
  honestMissTitle,
  overlayApprovalCopy,
  pendingDisplayCommand,
  REVIEW_DESCRIPTION_MAX,
  REVIEW_TITLE_MAX,
  type ApprovalCopy,
} from "./reviewCopy.ts";
import { maybeSanitizePlanir, scrubSecrets } from "./sanitize.ts";
import type { ScanFailure } from "./scanErrorPolicy.ts";

type Json = Record<string, unknown>;

/** Structural subset of the plugin scan response — avoid importing index.ts. */
export interface DevLogScanResponse {
  decision: "allow" | "review" | "block";
  risk?: number;
  summary?: string;
  pending_tool?: string;
  matched_rules?: string[];
  block_reason?: string;
  review_title?: string;
  review_description?: string;
  review_severity?: string;
  log?: Json;
  error?: string;
}

export interface DevLogScanTiming {
  pluginE2eMs: number;
  engineMs: number | null;
  requestMs: number | null;
  transportMs: number | null;
  sanitizeMs: number;
}

export const DEV_LOG_SCHEMA = "sentrook.plugin.devlog/v1";
export const DEFAULT_DEV_LOG_NAME = "sentrook-dev.log";
export const DEV_LOG_MAX_BYTES = 8 * 1024 * 1024;
export const DEV_LOG_STRING_MAX = 8_000;
export const DEV_LOG_INTENT_MAX = 2_000;

export interface DevLogConfig {
  enabled: boolean;
  path: string;
}

export type DevLogEventName =
  | "register"
  | "scan"
  | "scan_error"
  | "resolution"
  | "action"
  | "plugin_error";

export type DevLogEvent = Json & {
  ts: string;
  schema_version: typeof DEV_LOG_SCHEMA;
  event: DevLogEventName;
};

interface LoggerLike {
  warn: (m: string) => void;
}

function parseEnabled(raw: unknown): boolean {
  if (typeof raw === "boolean") return raw;
  if (typeof raw !== "string") return false;
  const n = raw.trim().toLowerCase();
  return n === "1" || n === "true" || n === "yes" || n === "on";
}

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return pathResolve(homedir(), p.slice(2));
  return p;
}

function defaultStateDir(env: NodeJS.ProcessEnv): string {
  const stateDir = env.OPENCLAW_STATE_DIR?.trim();
  if (stateDir) return pathResolve(expandHome(stateDir));
  const home = env.OPENCLAW_HOME?.trim() || env.HOME?.trim();
  if (home) return pathResolve(expandHome(home), ".openclaw");
  return pathResolve(homedir(), ".openclaw");
}

/** Resolve from process env + ~/.openclaw/.env (same merge as scan credentials). */
export function resolveDevLogConfig(
  env: NodeJS.ProcessEnv = process.env,
): DevLogConfig {
  const merged = envWithOpenclawDotenv(env);
  const enabled = parseEnabled(merged.SENTROOK_DEV_LOG);
  const override = merged.SENTROOK_DEV_LOG_PATH?.trim();
  const path = override
    ? pathResolve(expandHome(override))
    : pathResolve(defaultStateDir(merged), DEFAULT_DEV_LOG_NAME);
  return { enabled, path };
}

export function scrubDevText(text: string, maxChars = DEV_LOG_STRING_MAX): string {
  const scrubbed = scrubSecrets(text);
  if (scrubbed.length <= maxChars) return scrubbed;
  return `${scrubbed.slice(0, maxChars - 3)}...`;
}

export function scrubDevValue(value: unknown, depth = 0): unknown {
  if (value == null) return value;
  if (depth > 8) return "[…]";
  if (typeof value === "string") return scrubDevText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.slice(0, 40).map((item) => scrubDevValue(item, depth + 1));
  }
  if (typeof value === "object") {
    const out: Json = {};
    let n = 0;
    for (const [key, child] of Object.entries(value as Json)) {
      if (n >= 40) break;
      out[key] = scrubDevValue(child, depth + 1);
      n += 1;
    }
    return out;
  }
  return String(value);
}

function pendingCommandFromArgs(args: Json | undefined): string | undefined {
  if (!args) return undefined;
  return pendingDisplayCommand(args);
}

function pendingCommandFromPlan(plan: PlanIR | undefined): string | undefined {
  if (!plan) return undefined;
  const pending = lastPendingStep(plan);
  return pendingCommandFromArgs(pending?.args);
}

function rotateIfNeeded(path: string): void {
  if (!existsSync(path)) return;
  let size = 0;
  try {
    size = statSync(path).size;
  } catch {
    return;
  }
  if (size < DEV_LOG_MAX_BYTES) return;
  const bak = `${path}.1`;
  try {
    unlinkSync(bak);
  } catch {
    /* no previous rotation */
  }
  renameSync(path, bak);
}

export function appendDevLog(
  config: DevLogConfig,
  event: Omit<DevLogEvent, "ts" | "schema_version"> & Partial<Pick<DevLogEvent, "ts" | "schema_version">>,
  logger?: LoggerLike,
): void {
  if (!config.enabled) return;
  const path = config.path;
  if (!path || !isAbsolute(path)) return;
  const record: DevLogEvent = {
    ts: event.ts ?? new Date().toISOString(),
    schema_version: DEV_LOG_SCHEMA,
    ...event,
  };
  let line: string;
  try {
    line = `${JSON.stringify(record)}\n`;
  } catch (err) {
    logger?.warn(`[sentrook-openclaw] dev log serialize failed: ${String(err)}`);
    return;
  }
  try {
    mkdirSync(dirname(path), { recursive: true });
    rotateIfNeeded(path);
    const created = !existsSync(path);
    appendFileSync(path, line, { encoding: "utf8", mode: 0o600 });
    if (created) {
      try {
        chmodSync(path, 0o600);
      } catch {
        /* best-effort */
      }
    }
  } catch (err) {
    logger?.warn(`[sentrook-openclaw] dev log write failed: ${String(err)}`);
  }
}

function hookOutcome(result: {
  block?: boolean;
  requireApproval?: unknown;
} | undefined): {
  block: boolean;
  require_approval: boolean;
} {
  return {
    block: Boolean(result?.block),
    require_approval: Boolean(result?.requireApproval),
  };
}

export function buildScanDevEvent(input: {
  plan: PlanIR;
  pendingArgs?: Json;
  scan: DevLogScanResponse;
  timing: DevLogScanTiming;
  hookResult?: { block?: boolean; requireApproval?: { title?: string; description?: string } };
  allowlistHit?: boolean;
  allowlistDetail?: string;
}): Omit<DevLogEvent, "ts" | "schema_version"> {
  const pendingTool = lastPendingStep(input.plan)?.tool ?? input.scan.pending_tool ?? "unknown";
  const localCommandRaw = pendingCommandFromArgs(input.pendingArgs);
  const { plan: outbound } = maybeSanitizePlanir(input.plan);
  const egressCommand = pendingCommandFromPlan(outbound);
  const localCommand = localCommandRaw ? scrubDevText(localCommandRaw) : undefined;

  let card: ApprovalCopy | undefined;
  if (input.scan.decision === "review" && !input.allowlistHit) {
    card = overlayApprovalCopy({
      scanTitle: input.scan.review_title,
      scanDescription: input.scan.review_description,
      fallbackTitle: honestMissTitle(pendingTool),
      fallbackDescription:
        input.scan.summary || "Sentrook flagged this tool call for human review",
      pendingTool,
      pendingArgs: input.pendingArgs,
    });
  }

  const shown = input.hookResult?.requireApproval;

  return {
    event: "scan",
    session_id: input.plan.metadata.session_id ?? null,
    run_id: input.plan.run_id,
    tool_call_id: input.plan.metadata.tool_call_id ?? null,
    agent_id: input.plan.metadata.agent_id ?? null,
    step_seq: input.plan.metadata.step_seq ?? null,
    intent_kind: input.plan.intent_kind ?? null,
    intent: input.plan.intent
      ? scrubDevText(input.plan.intent, DEV_LOG_INTENT_MAX)
      : null,
    tool: pendingTool,
    local: {
      args: scrubDevValue(input.pendingArgs ?? lastPendingStep(input.plan)?.args ?? {}),
      command: localCommand ?? null,
      command_chars: localCommandRaw?.length ?? 0,
    },
    egress: {
      pending_command: egressCommand ? scrubDevText(egressCommand) : null,
      pending_command_chars: egressCommand?.length ?? 0,
      truncated:
        Boolean(localCommandRaw) &&
        Boolean(egressCommand) &&
        localCommandRaw !== egressCommand,
      sanitize_ms: input.timing.sanitizeMs,
    },
    scan: {
      decision: input.scan.decision,
      risk: input.scan.risk ?? null,
      summary: input.scan.summary ? scrubDevText(input.scan.summary, 500) : null,
      matched_rules: input.scan.matched_rules ?? [],
      block_reason: input.scan.block_reason
        ? scrubDevText(input.scan.block_reason, 500)
        : null,
      review_title: input.scan.review_title ?? null,
      review_description: input.scan.review_description ?? null,
      review_severity: input.scan.review_severity ?? null,
      log: scrubDevValue(input.scan.log ?? null),
      error: input.scan.error ?? null,
      timing: {
        plugin_e2e_ms: input.timing.pluginE2eMs,
        engine_ms: input.timing.engineMs,
        request_ms: input.timing.requestMs,
        transport_ms: input.timing.transportMs,
      },
    },
    card: card
      ? {
          title: shown?.title ?? card.title,
          description: shown?.description ?? card.description,
          source: card.source,
          command_found: card.commandFound,
          title_chars: (shown?.title ?? card.title).length,
          description_chars: (shown?.description ?? card.description).length,
          title_max: REVIEW_TITLE_MAX,
          description_max: REVIEW_DESCRIPTION_MAX,
        }
      : null,
    hook: {
      ...hookOutcome(input.hookResult),
      allowlist_hit: Boolean(input.allowlistHit),
      allowlist_detail: input.allowlistDetail ?? null,
    },
  };
}

export function buildScanErrorDevEvent(input: {
  plan: PlanIR;
  pendingArgs?: Json;
  failure: ScanFailure;
  hookResult?: { block?: boolean; requireApproval?: { title?: string; description?: string } };
}): Omit<DevLogEvent, "ts" | "schema_version"> {
  const pendingTool = lastPendingStep(input.plan)?.tool ?? "unknown";
  const localCommandRaw = pendingCommandFromArgs(input.pendingArgs);
  return {
    event: "scan_error",
    session_id: input.plan.metadata.session_id ?? null,
    run_id: input.plan.run_id,
    tool_call_id: input.plan.metadata.tool_call_id ?? null,
    tool: pendingTool,
    local: {
      args: scrubDevValue(input.pendingArgs ?? {}),
      command: localCommandRaw ? scrubDevText(localCommandRaw) : null,
      command_chars: localCommandRaw?.length ?? 0,
    },
    failure: {
      kind: input.failure.kind,
      status: input.failure.status ?? null,
      retry_after_sec: input.failure.retryAfterSec ?? null,
      detail: scrubDevText(input.failure.detail, 400),
    },
    hook: hookOutcome(input.hookResult),
    card: input.hookResult?.requireApproval
      ? {
          title: input.hookResult.requireApproval.title ?? null,
          description: input.hookResult.requireApproval.description ?? null,
        }
      : null,
  };
}
