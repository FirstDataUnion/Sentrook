/**
 * Local operator log (``sentrook.operator.log/v1``).
 *
 * On by default. Path: ``$OPENCLAW_STATE_DIR/sentrook-operator.jsonl``.
 * Secret/PII-scrubbed, no per-field truncation. Retention is age + size, not
 * payload chopping. Failures never affect the scan hook.
 *
 * Distinct from SENTROOK_DEV_LOG (maintainer diagnostics, off by default).
 */

import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, resolve as pathResolve } from "node:path";
import { homedir } from "node:os";

import { envWithOpenclawDotenv } from "./auth.ts";
import {
  buildResultSummary,
  canonicalToolName,
  lastPendingStep,
  type PlanIR,
} from "./planir.ts";
import { DEFAULT_RULES, scrubOperatorValue, scrubSecretsAndPii } from "./sanitize.ts";
import type { ScanFailure } from "./scanErrorPolicy.ts";

export const OPERATOR_LOG_SCHEMA = "sentrook.operator.log/v1";
export const DEFAULT_OPERATOR_LOG_NAME = "sentrook-operator.jsonl";
export const DEFAULT_MAX_AGE_DAYS = 14;
export const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;
/** Newest scan/scan_error rows the dashboard timeline loads. */
export const DEFAULT_TIMELINE_SCAN_LIMIT = 100;
const JSONL_TAIL_CHUNK = 64 * 1024;
const NEWLINE = 0x0a;

export type OperatorEventKind = "scan" | "result" | "resolution" | "scan_error";

export interface OperatorLogConfig {
  enabled: boolean;
  path: string;
  maxAgeDays: number;
  maxBytes: number;
}

export type OperatorLogEvent = Record<string, unknown> & {
  schema_version: typeof OPERATOR_LOG_SCHEMA;
  id: string;
  ts: string;
  event: OperatorEventKind;
  run_id: string;
  metadata: Record<string, unknown>;
};

export interface OperatorLogQuery {
  sessionId?: string;
  sessionKey?: string;
  id?: string;
  decision?: string;
  event?: OperatorEventKind | OperatorEventKind[];
  since?: Date;
  until?: Date;
  commandSubstring?: string;
  limit?: number;
}

export interface OperatorLogStats {
  path: string;
  enabled: boolean;
  bytes: number;
  lines: number;
  oldestTs: string | null;
  newestTs: string | null;
}

interface LoggerLike {
  warn: (m: string) => void;
}

function parseEnabled(raw: unknown, defaultOn: boolean): boolean {
  if (raw == null || raw === "") return defaultOn;
  if (typeof raw === "boolean") return raw;
  if (typeof raw !== "string") return defaultOn;
  const n = raw.trim().toLowerCase();
  if (["0", "false", "no", "off"].includes(n)) return false;
  if (["1", "true", "yes", "on"].includes(n)) return true;
  return defaultOn;
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

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw?.trim()) return fallback;
  const n = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export function resolveOperatorLogConfig(
  env: NodeJS.ProcessEnv = process.env,
  pluginCfg?: Record<string, unknown>,
): OperatorLogConfig {
  const merged = envWithOpenclawDotenv(env);
  const raw =
    pluginCfg?.operatorLog && typeof pluginCfg.operatorLog === "object"
      ? (pluginCfg.operatorLog as Record<string, unknown>)
      : {};
  const enabled = parseEnabled(
    merged.SENTROOK_OPERATOR_LOG ?? raw.enabled,
    true,
  );
  const override = merged.SENTROOK_OPERATOR_LOG_PATH?.trim();
  const cfgPath = typeof raw.path === "string" ? raw.path.trim() : "";
  const path = override
    ? pathResolve(expandHome(override))
    : cfgPath
      ? pathResolve(expandHome(cfgPath))
      : pathResolve(defaultStateDir(merged), DEFAULT_OPERATOR_LOG_NAME);
  const daysFallback =
    typeof raw.maxAgeDays === "number" && Number.isFinite(raw.maxAgeDays)
      ? Math.max(0, Math.round(raw.maxAgeDays))
      : DEFAULT_MAX_AGE_DAYS;
  const bytesFallback =
    typeof raw.maxBytes === "number" && Number.isFinite(raw.maxBytes)
      ? Math.max(0, Math.round(raw.maxBytes))
      : DEFAULT_MAX_BYTES;
  return {
    enabled,
    path,
    maxAgeDays: parsePositiveInt(merged.SENTROOK_OPERATOR_LOG_MAX_DAYS, daysFallback),
    maxBytes: parsePositiveInt(merged.SENTROOK_OPERATOR_LOG_MAX_BYTES, bytesFallback),
  };
}

export function mintOperatorLogId(): string {
  return `sr_${randomBytes(6).toString("hex")}`;
}

function rotateIfNeeded(path: string, maxBytes: number, lineBytes: number): void {
  let size = 0;
  try {
    size = statSync(path).size;
  } catch {
    return;
  }
  if (size === 0) return;
  // Rotate when the live file is already over budget or this write would
  // push it over. A single oversized event still writes in full to a fresh
  // file — never prefix-cut the payload.
  if (size < maxBytes && size + lineBytes < maxBytes) return;
  const bak = `${path}.1`;
  try {
    unlinkSync(bak);
  } catch {
    /* no previous rotation */
  }
  renameSync(path, bak);
}

function appendLineSync(path: string, line: string): void {
  const fd = openSync(
    path,
    constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY,
    0o600,
  );
  try {
    writeSync(fd, line, null, "utf8");
    try {
      fchmodSync(fd, 0o600);
    } catch {
      /* best-effort */
    }
  } finally {
    closeSync(fd);
  }
}

function parseOperatorLine(line: string): OperatorLogEvent | undefined {
  const trimmed = line.trim();
  if (!trimmed) return undefined;
  try {
    const parsed = JSON.parse(trimmed) as OperatorLogEvent;
    if (parsed && typeof parsed === "object" && parsed.event) return parsed;
  } catch {
    /* skip malformed */
  }
  return undefined;
}

function readJsonl(path: string): OperatorLogEvent[] {
  let raw = "";
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const out: OperatorLogEvent[] = [];
  for (const line of raw.split("\n")) {
    const parsed = parseOperatorLine(line);
    if (parsed) out.push(parsed);
  }
  return out;
}

/**
 * Walk a JSONL file from EOF (newest first). ``visit`` returning false stops.
 * Handles lines larger than the read chunk.
 */
export function forEachJsonlFromEnd(
  filePath: string,
  visit: (event: OperatorLogEvent) => boolean,
  chunkBytes: number = JSONL_TAIL_CHUNK,
): void {
  let fd: number;
  try {
    fd = openSync(filePath, constants.O_RDONLY);
  } catch {
    return;
  }
  try {
    const size = fstatSync(fd).size;
    if (size <= 0) return;
    const chunk = Math.max(1, chunkBytes);
    let pos = size;
    let newerCarry = Buffer.alloc(0);
    while (pos > 0) {
      const n = Math.min(chunk, pos);
      pos -= n;
      const buf = Buffer.alloc(n);
      const got = readSync(fd, buf, 0, n, pos);
      const olderChunk = got === n ? buf : buf.subarray(0, got);
      const joined = Buffer.concat([olderChunk, newerCarry]);
      const firstNl = joined.indexOf(NEWLINE);
      if (firstNl === -1) {
        newerCarry = joined;
        continue;
      }
      const rest = joined.subarray(firstNl + 1);
      const complete: Buffer[] = [];
      let start = 0;
      for (let i = 0; i < rest.length; i++) {
        if (rest[i] === NEWLINE) {
          complete.push(rest.subarray(start, i));
          start = i + 1;
        }
      }
      if (start < rest.length) complete.push(rest.subarray(start));
      for (let i = complete.length - 1; i >= 0; i--) {
        const event = parseOperatorLine(complete[i]!.toString("utf8"));
        if (event && !visit(event)) return;
      }
      newerCarry = joined.subarray(0, firstNl);
    }
    const event = parseOperatorLine(newerCarry.toString("utf8"));
    if (event) visit(event);
  } finally {
    closeSync(fd);
  }
}

function operatorLogPaths(config: OperatorLogConfig): string[] {
  return [config.path, `${config.path}.1`];
}

/**
 * Newest-first events from the live JSONL then ``.1``, stopping after
 * ``scanLimit`` scan / scan_error rows. Resolution and result lines closer
 * to EOF (written after the scan) are included so the dashboard can join them.
 */
export function tailOperatorLog(
  config: OperatorLogConfig,
  opts: { scanLimit?: number; chunkBytes?: number } = {},
): OperatorLogEvent[] {
  const limit = Math.max(1, opts.scanLimit ?? DEFAULT_TIMELINE_SCAN_LIMIT);
  const out: OperatorLogEvent[] = [];
  let scans = 0;
  for (const path of operatorLogPaths(config)) {
    let stop = false;
    forEachJsonlFromEnd(
      path,
      (event) => {
        out.push(event);
        if (event.event === "scan" || event.event === "scan_error") {
          scans += 1;
          if (scans >= limit) {
            stop = true;
            return false;
          }
        }
        return true;
      },
      opts.chunkBytes,
    );
    if (stop) break;
  }
  return out;
}

function firstOperatorEvent(path: string): OperatorLogEvent | undefined {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY);
  } catch {
    return undefined;
  }
  try {
    const size = fstatSync(fd).size;
    if (size <= 0) return undefined;
    const buf = Buffer.alloc(Math.min(JSONL_TAIL_CHUNK, size));
    const got = readSync(fd, buf, 0, buf.length, 0);
    const slice = buf.subarray(0, got);
    const nl = slice.indexOf(NEWLINE);
    const line = (nl === -1 ? slice : slice.subarray(0, nl)).toString("utf8");
    return parseOperatorLine(line);
  } finally {
    closeSync(fd);
  }
}

function lastOperatorEvent(path: string): OperatorLogEvent | undefined {
  let found: OperatorLogEvent | undefined;
  forEachJsonlFromEnd(path, (event) => {
    found = event;
    return false;
  });
  return found;
}

function countNewlines(path: string): number {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY);
  } catch {
    return 0;
  }
  try {
    const size = fstatSync(fd).size;
    if (size <= 0) return 0;
    const buf = Buffer.alloc(JSONL_TAIL_CHUNK);
    let pos = 0;
    let lines = 0;
    while (pos < size) {
      const n = Math.min(buf.length, size - pos);
      const got = readSync(fd, buf, 0, n, pos);
      if (got <= 0) break;
      for (let i = 0; i < got; i++) {
        if (buf[i] === NEWLINE) lines += 1;
      }
      pos += got;
    }
    return lines;
  } finally {
    closeSync(fd);
  }
}

function pendingCommand(event: OperatorLogEvent): string {
  const pending = event.pending;
  if (!pending || typeof pending !== "object") return "";
  const args = (pending as { args?: Record<string, unknown> }).args;
  if (!args) return "";
  const command = args.command ?? args.cmd;
  return typeof command === "string" ? command : JSON.stringify(args);
}

export function appendOperatorLog(
  config: OperatorLogConfig,
  event: Omit<OperatorLogEvent, "ts" | "schema_version" | "id"> &
    Partial<Pick<OperatorLogEvent, "ts" | "schema_version" | "id">>,
  logger?: LoggerLike,
): string | undefined {
  const id = event.id ?? mintOperatorLogId();
  if (!config.enabled) return id;
  const path = config.path;
  if (!path || !isAbsolute(path)) return id;
  const record = {
    ...event,
    ts: event.ts ?? new Date().toISOString(),
    schema_version: OPERATOR_LOG_SCHEMA,
    id,
  };
  let line: string;
  try {
    line = `${JSON.stringify(record)}\n`;
  } catch (err) {
    logger?.warn(`[sentrook-openclaw] operator log serialize failed: ${String(err)}`);
    return id;
  }
  try {
    mkdirSync(dirname(path), { recursive: true });
    rotateIfNeeded(path, config.maxBytes, Buffer.byteLength(line));
    appendLineSync(path, line);
  } catch (err) {
    logger?.warn(`[sentrook-openclaw] operator log write failed: ${String(err)}`);
  }
  return id;
}

export function queryOperatorLog(
  config: OperatorLogConfig,
  query: OperatorLogQuery = {},
): OperatorLogEvent[] {
  const paths = [config.path, `${config.path}.1`];
  const events: OperatorLogEvent[] = [];
  for (const path of paths) {
    events.push(...readJsonl(path));
  }
  const kinds = query.event
    ? new Set(Array.isArray(query.event) ? query.event : [query.event])
    : null;
  const needle = query.commandSubstring?.toLowerCase();
  const matched = events.filter((event) => {
    const meta = event.metadata ?? {};
    if (query.id) {
      const needle = query.id.trim().toLowerCase();
      const id = String(event.id ?? "").toLowerCase();
      if (id !== needle && !id.startsWith(needle)) return false;
    }
    if (query.sessionId && meta.session_id !== query.sessionId) return false;
    if (query.sessionKey && meta.session_key !== query.sessionKey) return false;
    if (kinds && !kinds.has(event.event)) return false;
    if (query.decision) {
      const scan = event.scan as { decision?: string } | undefined;
      if (scan?.decision !== query.decision) return false;
    }
    const ts = Date.parse(event.ts);
    if (query.since && (!Number.isFinite(ts) || ts < query.since.getTime())) return false;
    if (query.until && (!Number.isFinite(ts) || ts > query.until.getTime())) return false;
    if (needle && !pendingCommand(event).toLowerCase().includes(needle)) return false;
    return true;
  });
  matched.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
  if (query.limit && query.limit > 0) return matched.slice(0, query.limit);
  return matched;
}

export function getOperatorLogEvent(
  config: OperatorLogConfig,
  id: string,
): OperatorLogEvent | undefined {
  const needle = id.trim();
  if (!needle) return undefined;
  const matches = queryOperatorLog(config, { id: needle });
  if (matches.length === 0) return undefined;
  const exact = matches.find((event) => event.id.toLowerCase() === needle.toLowerCase());
  if (exact) return exact;
  if (matches.length === 1) return matches[0];
  return undefined;
}

export function purgeOperatorLog(
  config: OperatorLogConfig,
  logger?: LoggerLike,
): number {
  if (!config.enabled) return 0;
  if (config.maxAgeDays <= 0) return 0;
  const cutoff = Date.now() - config.maxAgeDays * 24 * 60 * 60 * 1000;
  let dropped = 0;
  for (const path of [config.path, `${config.path}.1`]) {
    const events = readJsonl(path);
    if (events.length === 0) continue;
    const kept = events.filter((event) => {
      const ts = Date.parse(event.ts);
      if (!Number.isFinite(ts) || ts < cutoff) {
        dropped += 1;
        return false;
      }
      return true;
    });
    if (kept.length === events.length) continue;
    try {
      const tmp = `${path}.tmp`;
      const body = kept.map((event) => JSON.stringify(event)).join("\n");
      writeFileSync(tmp, body ? `${body}\n` : "", { mode: 0o600 });
      renameSync(tmp, path);
    } catch (err) {
      logger?.warn(`[sentrook-openclaw] operator log purge failed: ${String(err)}`);
    }
  }
  return dropped;
}

/** Delete the live JSONL and the rotated `.1` copy. Returns lines that were present. */
export function wipeOperatorLog(
  config: OperatorLogConfig,
  logger?: LoggerLike,
): number {
  const before = operatorLogStats(config).lines;
  for (const path of [config.path, `${config.path}.1`]) {
    try {
      unlinkSync(path);
    } catch {
      /* missing */
    }
  }
  if (before > 0) {
    logger?.info(`[sentrook-openclaw] operator log cleared (${before} lines)`);
  }
  return before;
}

export function operatorLogStats(config: OperatorLogConfig): OperatorLogStats {
  const live = config.path;
  const rotated = `${live}.1`;
  let bytes = 0;
  try {
    bytes = statSync(live).size;
  } catch {
    bytes = 0;
  }
  const lines = countNewlines(live) + countNewlines(rotated);
  const newest = lastOperatorEvent(live) ?? lastOperatorEvent(rotated);
  const oldest = firstOperatorEvent(rotated) ?? firstOperatorEvent(live);
  return {
    path: live,
    enabled: config.enabled,
    bytes,
    lines,
    oldestTs: oldest?.ts ?? null,
    newestTs: newest?.ts ?? null,
  };
}

/** Scrub a pending-args object for durable history (no field cap). */
export function scrubOperatorArgs(args: Record<string, unknown>): Record<string, unknown> {
  const cleaned = scrubOperatorValue(args);
  return cleaned && typeof cleaned === "object" && !Array.isArray(cleaned)
    ? (cleaned as Record<string, unknown>)
    : {};
}

type Json = Record<string, unknown>;

export interface OperatorScanResponse {
  decision: "allow" | "review" | "block";
  risk?: number;
  summary?: string;
  matched_rules?: string[];
  block_reason?: string;
  review_severity?: string;
  log?: Json;
}

export interface OperatorHookResult {
  block?: boolean;
  requireApproval?: unknown;
}

let cachedPluginVersion: string | undefined;

export function operatorPluginVersion(): string {
  if (cachedPluginVersion) return cachedPluginVersion;
  const candidates = [new URL("./package.json", import.meta.url), new URL("../package.json", import.meta.url)];
  for (const url of candidates) {
    try {
      const pkg = JSON.parse(readFileSync(url, "utf8")) as { name?: string; version?: string };
      if (pkg.name !== "@firstdataunion/sentrook-openclaw") continue;
      if (typeof pkg.version === "string" && pkg.version) {
        cachedPluginVersion = pkg.version;
        return cachedPluginVersion;
      }
    } catch {
      /* try the next candidate */
    }
  }
  cachedPluginVersion = "unknown";
  return cachedPluginVersion;
}

function hookAction(result: OperatorHookResult | undefined): "requireApproval" | "block" | "continue" {
  if (result?.block) return "block";
  if (result?.requireApproval) return "requireApproval";
  return "continue";
}

function scanEffect(
  result: OperatorHookResult | undefined,
): "ran" | "blocked" | "never_ran" {
  if (result?.block) return "blocked";
  if (result?.requireApproval) return "never_ran";
  return "ran";
}

function operatorMetadata(plan: PlanIR, hook = "before_tool_call"): Record<string, unknown> {
  return {
    adapter: plan.metadata.adapter ?? "openclaw",
    agent_id: plan.metadata.agent_id ?? null,
    session_id: plan.metadata.session_id ?? null,
    session_key: plan.metadata.session_key ?? null,
    hook,
    tool_call_id: plan.metadata.tool_call_id ?? null,
    step_seq: plan.metadata.step_seq ?? null,
    batch_size: plan.metadata.batch_size ?? null,
  };
}

function pendingStepForLog(
  plan: PlanIR,
  hostTool: string,
  rawArgs: Json,
): Record<string, unknown> {
  const pending = lastPendingStep(plan);
  return {
    id: pending?.id ?? "s1",
    tool: pending?.tool ?? canonicalToolName(hostTool, rawArgs),
    status: "pending",
    args: scrubOperatorArgs(rawArgs),
  };
}

function envelopeExtras(input: {
  unattended?: boolean;
  contributeEligible?: boolean;
  hostTool?: string;
  planTool?: string;
}): Record<string, unknown> {
  const hostTool =
    input.hostTool && input.planTool && input.hostTool !== input.planTool
      ? input.hostTool
      : undefined;
  return {
    plugin_version: operatorPluginVersion(),
    rules_version: DEFAULT_RULES.version,
    unattended: input.unattended ?? false,
    contribute_eligible: input.contributeEligible ?? false,
    ...(hostTool ? { host_tool: hostTool } : {}),
  };
}

export function buildScanOperatorEvent(input: {
  plan: PlanIR;
  pendingArgs: Json;
  hostTool: string;
  scan: OperatorScanResponse;
  hookResult?: OperatorHookResult;
  allowlistHit?: boolean;
  skipReason?: "allowlist" | "quiet" | "lenient" | "allow-all";
  allowlistLabel?: string;
  coPendingIds?: string[];
  unattended?: boolean;
  contributeEligible?: boolean;
}): Omit<OperatorLogEvent, "ts" | "schema_version" | "id"> {
  const pending = pendingStepForLog(input.plan, input.hostTool, input.pendingArgs);
  const skipReason = input.skipReason ?? (input.allowlistHit ? "allowlist" : undefined);
  const labelSource = skipReason ?? "scanner";
  return {
    event: "scan",
    run_id: input.plan.run_id,
    intent: input.plan.intent ? scrubSecretsAndPii(input.plan.intent) : null,
    intent_kind: input.plan.intent_kind ?? null,
    metadata: operatorMetadata(input.plan),
    pending,
    co_pending: input.coPendingIds ?? [],
    scan: {
      decision: input.scan.decision,
      risk: input.scan.risk ?? null,
      summary: input.scan.summary ? scrubSecretsAndPii(input.scan.summary) : null,
      matched_rules: input.scan.matched_rules ?? [],
      review_severity: input.scan.review_severity ?? null,
      block_reason: input.scan.block_reason
        ? scrubSecretsAndPii(input.scan.block_reason)
        : null,
      winning_rule_id:
        typeof input.scan.log?.winning_rule_id === "string"
          ? input.scan.log.winning_rule_id
          : null,
      log: input.scan.log ? (scrubOperatorValue(input.scan.log) as Json) : null,
    },
    hook: {
      action: hookAction(input.hookResult),
      ...(skipReason ? { skip_reason: skipReason } : {}),
      ...(input.allowlistLabel
        ? { allowlist_label: scrubSecretsAndPii(input.allowlistLabel) }
        : {}),
    },
    effect: scanEffect(input.hookResult),
    label_source: labelSource,
    feedback_posted: false,
    ...envelopeExtras({
      unattended: input.unattended,
      contributeEligible: input.contributeEligible,
      hostTool: input.hostTool,
      planTool: String(pending.tool),
    }),
  };
}

export function buildScanErrorOperatorEvent(input: {
  plan: PlanIR;
  pendingArgs: Json;
  hostTool: string;
  failure: ScanFailure;
  hookResult?: OperatorHookResult;
  coPendingIds?: string[];
  unattended?: boolean;
  contributeEligible?: boolean;
}): Omit<OperatorLogEvent, "ts" | "schema_version" | "id"> {
  const pending = pendingStepForLog(input.plan, input.hostTool, input.pendingArgs);
  return {
    event: "scan_error",
    run_id: input.plan.run_id,
    intent: input.plan.intent ? scrubSecretsAndPii(input.plan.intent) : null,
    intent_kind: input.plan.intent_kind ?? null,
    metadata: operatorMetadata(input.plan),
    pending,
    co_pending: input.coPendingIds ?? [],
    scan_error: {
      kind: input.failure.kind,
      detail: input.failure.detail ? scrubSecretsAndPii(input.failure.detail) : null,
      status: input.failure.status ?? null,
    },
    hook: { action: hookAction(input.hookResult) },
    effect: scanEffect(input.hookResult),
    label_source: "scanner",
    feedback_posted: false,
    ...envelopeExtras({
      unattended: input.unattended,
      contributeEligible: input.contributeEligible,
      hostTool: input.hostTool,
      planTool: String(pending.tool),
    }),
  };
}

export function buildResolutionOperatorEvent(input: {
  plan: PlanIR;
  decision: string;
  feedbackPosted?: boolean;
}): Omit<OperatorLogEvent, "ts" | "schema_version" | "id"> {
  const ran =
    input.decision === "allow-once" ||
    input.decision === "allow-always" ||
    input.decision.endsWith("-skip") ||
    input.decision === "allowlist-hit";
  const labelSource =
    input.decision === "timeout"
      ? "timeout"
      : input.decision === "quiet-skip"
        ? "quiet"
        : input.decision === "lenient-skip"
          ? "lenient"
          : input.decision === "allowlist-hit"
            ? "allowlist"
            : input.decision === "allow-all-skip"
              ? "allow-all"
              : input.decision === "cancelled"
                ? "human"
                : "human";
  return {
    event: "resolution",
    run_id: input.plan.run_id,
    intent_kind: input.plan.intent_kind ?? null,
    metadata: operatorMetadata(input.plan),
    resolution: {
      decision: input.decision,
      feedback_posted: Boolean(input.feedbackPosted),
    },
    effect: ran ? "ran" : "never_ran",
    label_source: labelSource,
    feedback_posted: Boolean(input.feedbackPosted),
    plugin_version: operatorPluginVersion(),
    rules_version: DEFAULT_RULES.version,
  };
}

export function buildResultOperatorEvent(input: {
  runId: string;
  metadata: Record<string, unknown>;
  resultText: string;
  ok: boolean;
  command?: string;
}): Omit<OperatorLogEvent, "ts" | "schema_version" | "id"> {
  const summary = buildResultSummary(input.resultText, {
    ok: input.ok,
    command: input.command,
    excerptLimit: Number.POSITIVE_INFINITY,
    hostTruncated: false,
  });
  summary.excerpt = scrubSecretsAndPii(summary.excerpt);
  if (summary.extracted.commands.length) {
    summary.extracted.commands = summary.extracted.commands.map((item) =>
      scrubSecretsAndPii(item),
    );
  }
  return {
    event: "result",
    run_id: input.runId,
    metadata: {
      adapter: "openclaw",
      hook: "after_tool_call",
      ...input.metadata,
    },
    result: summary,
    effect: "ran",
    label_source: "scanner",
    host_truncated: false,
    plugin_version: operatorPluginVersion(),
    rules_version: DEFAULT_RULES.version,
  };
}

/** Newest waiting ``requireApproval`` scan for a tool call, or undefined if it already resolved. */
export function waitingOperatorReview(
  log: OperatorLogConfig,
  toolCallId: string,
): OperatorLogEvent | undefined {
  const id = toolCallId.trim();
  if (!id) return undefined;
  let found: OperatorLogEvent | undefined;
  forEachJsonlFromEnd(log.path, (event) => {
    const meta = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
    const tid = typeof meta.tool_call_id === "string" ? meta.tool_call_id : "";
    if (tid !== id) return true;
    if (event.event === "resolution" || event.event === "result") return false;
    if (event.event === "scan" || event.event === "scan_error") {
      const hook = event.hook && typeof event.hook === "object" ? (event.hook as { action?: unknown }) : {};
      if (hook.action === "requireApproval") {
        found = event;
        return false;
      }
    }
    return true;
  });
  return found;
}
