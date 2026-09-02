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
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, resolve as pathResolve } from "node:path";
import { homedir } from "node:os";

import { envWithOpenclawDotenv } from "./auth.ts";
import { scrubOperatorValue } from "./sanitize.ts";

export const OPERATOR_LOG_SCHEMA = "sentrook.operator.log/v1";
export const DEFAULT_OPERATOR_LOG_NAME = "sentrook-operator.jsonl";
export const DEFAULT_MAX_AGE_DAYS = 14;
export const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;

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
): OperatorLogConfig {
  const merged = envWithOpenclawDotenv(env);
  const enabled = parseEnabled(merged.SENTROOK_OPERATOR_LOG, true);
  const override = merged.SENTROOK_OPERATOR_LOG_PATH?.trim();
  const path = override
    ? pathResolve(expandHome(override))
    : pathResolve(defaultStateDir(merged), DEFAULT_OPERATOR_LOG_NAME);
  return {
    enabled,
    path,
    maxAgeDays: parsePositiveInt(merged.SENTROOK_OPERATOR_LOG_MAX_DAYS, DEFAULT_MAX_AGE_DAYS),
    maxBytes: parsePositiveInt(merged.SENTROOK_OPERATOR_LOG_MAX_BYTES, DEFAULT_MAX_BYTES),
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

function readJsonl(path: string): OperatorLogEvent[] {
  let raw = "";
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const out: OperatorLogEvent[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as OperatorLogEvent;
      if (parsed && typeof parsed === "object" && parsed.event) out.push(parsed);
    } catch {
      /* skip malformed */
    }
  }
  return out;
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
): void {
  if (!config.enabled) return;
  const path = config.path;
  if (!path || !isAbsolute(path)) return;
  const record: OperatorLogEvent = {
    ...event,
    ts: event.ts ?? new Date().toISOString(),
    schema_version: OPERATOR_LOG_SCHEMA,
    id: event.id ?? mintOperatorLogId(),
  };
  let line: string;
  try {
    line = `${JSON.stringify(record)}\n`;
  } catch (err) {
    logger?.warn(`[sentrook-openclaw] operator log serialize failed: ${String(err)}`);
    return;
  }
  try {
    mkdirSync(dirname(path), { recursive: true });
    rotateIfNeeded(path, config.maxBytes, Buffer.byteLength(line));
    appendLineSync(path, line);
  } catch (err) {
    logger?.warn(`[sentrook-openclaw] operator log write failed: ${String(err)}`);
  }
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

export function operatorLogStats(config: OperatorLogConfig): OperatorLogStats {
  const events = queryOperatorLog(config);
  let bytes = 0;
  try {
    bytes = statSync(config.path).size;
  } catch {
    bytes = 0;
  }
  const oldest = events.length ? events[events.length - 1] : null;
  const newest = events.length ? events[0] : null;
  return {
    path: config.path,
    enabled: config.enabled,
    bytes,
    lines: events.length,
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
