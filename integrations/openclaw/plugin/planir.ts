/**
 * PlanIR 1.0 builder — mirrors Python ``sentrook.adapters.snapshot`` +
 * ``planir.args`` + ``sanitize.core.redact_args`` for golden parity.
 */

import type { IntentKind } from "./attendance.ts";
import { packSignalExcerpt } from "./sanitize.ts";

export type { IntentKind };
export type Json = Record<string, unknown>;

export interface ResultSummaryExtracted {
  urls: string[];
  paths: string[];
  commands: string[];
}

export interface ResultSummaryFlags {
  truncated: boolean;
  injection_markers: boolean;
}

export interface ResultSummary {
  ok: boolean;
  content_type?: string | null;
  byte_size: number;
  excerpt: string;
  extracted: ResultSummaryExtracted;
  flags: ResultSummaryFlags;
}

export interface PlanStep {
  id: string;
  tool: string;
  status: "executed" | "pending";
  args: Json;
  result_summary?: ResultSummary | null;
}

export interface PlanMetadata {
  adapter: string;
  agent_id?: string | null;
  session_id?: string | null;
  session_key?: string | null;
  hook: string;
  tool_call_id?: string | null;
  step_seq?: number | null;
  batch_size?: number | null;
}

export interface PlanIR {
  version: "1.0";
  run_id: string;
  intent?: string | null;
  intent_kind?: IntentKind | null;
  steps: PlanStep[];
  metadata: PlanMetadata;
}

export interface SnapshotCall {
  tool: string;
  args: Json;
  /** Raw tool result text (executed calls only). */
  resultText?: string;
  resultOk?: boolean;
  contentType?: string | null;
  command?: string | null;
  /** Prebuilt summary when available (tests / replay). */
  result_summary?: ResultSummary | null;
}

const EXEC_COMMAND_ALIASES = ["cmd", "shell", "script", "line", "data"] as const;
/** process actions that inject/run a command — fold onto exec so shell rules apply. */
const PROCESS_EXEC_ACTIONS = new Set(["write", "submit", "start", "spawn"]);
const WRITE_PATH_ALIASES = ["file", "filepath", "target"] as const;
const MESSAGE_BODY_ALIASES = ["body", "content", "message", "msg"] as const;

const URL_RE = /https?:\/\/[^\s"'<>]+/g;
const PATH_RE = /(?:\/[\w.\-]+)+/g;
const INJECTION_MARKERS =
  /(?:ignore (?:all |the |your )?(?:previous|prior|above|earlier)\b|ignore (?:all |the |your )?safety\b|(?:system|admin|developer)\s+override|disregard (?:all |the |your )?(?:previous|prior|above|earlier|safety)|system prompt|<\/s>|<\|im_start\|>|exfiltrat|upload\s+\S*(?:auth-profiles|openclaw-agent\.sqlite|database\.sqlite|credentials|secrets|\.ssh)\S*\s+to\s+https?:\/\/|(?:important|mandatory|required)\s*:\s*before\b.{0,60}\b(?:upload|send|post|transmit)\b)/i;

const EXCERPT_LIMIT = 500;
const EXTRACTED_LIMIT = 20;
const REDACTED = "[REDACTED]";
const TRUNCATED = "[TRUNCATED]";
const STRING_LEAF_MAX = 500;
const CREDENTIAL_FIELD =
  /(token|password|passwd|(?<![a-z])pass(?![a-z])|secret|api[_-]?key|auth|credential|bearer)/i;
const CONTENT_LIKE_KEYS = new Set(["content", "text", "body", "message", "command", "cmd"]);

export function stringifyArgValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(stringifyArgValue).join(" ");
  if (typeof value === "object") {
    return Object.values(value as Json)
      .map(stringifyArgValue)
      .join(" ");
  }
  return String(value);
}

function writeBodyText(args: Json): string {
  const pieces: string[] = [];
  if ("content" in args) pieces.push(stringifyArgValue(args.content));
  if ("edits" in args) pieces.push(stringifyArgValue(args.edits));
  for (const key of ["newText", "new_string", "text", "body"] as const) {
    if (key in args) pieces.push(stringifyArgValue(args[key]));
  }
  return pieces.filter(Boolean).join(" ");
}

export function canonicalToolName(tool: string, args: Json | undefined = undefined): string {
  if (tool === "process") {
    const action = String(args?.action ?? "")
      .trim()
      .toLowerCase();
    if (PROCESS_EXEC_ACTIONS.has(action)) return "exec";
    return "process";
  }
  return tool;
}

export function canonicalizeToolArgs(tool: string, args: Json): Json {
  if (!args || Object.keys(args).length === 0) return {};
  const canonicalTool = canonicalToolName(tool, args);
  if (canonicalTool === "exec") {
    const out: Json = { ...args };
    if (!("command" in out)) {
      for (const alias of EXEC_COMMAND_ALIASES) {
        if (alias in out) {
          out.command = out[alias];
          delete out[alias];
          break;
        }
      }
    }
    if ("command" in out) out.command = stringifyArgValue(out.command);
    return out;
  }
  if (tool === "write" || tool === "edit") {
    const out: Json = { ...args };
    if (!("path" in out)) {
      for (const alias of WRITE_PATH_ALIASES) {
        if (alias in out) {
          out.path = out[alias];
          delete out[alias];
          break;
        }
      }
    }
    if ("path" in out) out.path = stringifyArgValue(out.path);
    const body = writeBodyText(out);
    if (body) out.content = body;
    return out;
  }
  if (tool === "message") {
    const out: Json = { ...args };
    if (!("text" in out)) {
      for (const alias of MESSAGE_BODY_ALIASES) {
        if (alias in out) {
          out.text = out[alias];
          delete out[alias];
          break;
        }
      }
    }
    if ("text" in out) out.text = stringifyArgValue(out.text);
    return out;
  }
  return { ...args };
}

export function redactArgs(args: Json): Json {
  const out: Json = {};
  for (const [key, value] of Object.entries(args)) {
    if (CREDENTIAL_FIELD.test(key)) {
      out[key] = REDACTED;
    } else if (typeof value === "string" && value.length > STRING_LEAF_MAX) {
      out[key] = CONTENT_LIKE_KEYS.has(key.toLowerCase())
        ? packSignalExcerpt(value, STRING_LEAF_MAX)
        : TRUNCATED;
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      out[key] = redactArgs(value as Json);
    } else if (Array.isArray(value)) {
      out[key] = value.map((item) =>
        item && typeof item === "object" && !Array.isArray(item)
          ? redactArgs(item as Json)
          : typeof item === "string" && item.length > STRING_LEAF_MAX
            ? TRUNCATED
            : item,
      );
    } else {
      out[key] = value;
    }
  }
  return out;
}

function guessContentType(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      JSON.parse(trimmed);
      return "application/json";
    } catch {
      return "text/plain";
    }
  }
  return "text/plain";
}

function contentPartText(part: unknown): string {
  if (typeof part === "string") return part;
  if (!part || typeof part !== "object" || Array.isArray(part)) return "";
  const rec = part as Record<string, unknown>;
  if (typeof rec.text === "string") return rec.text;
  if (typeof rec.content === "string") return rec.content;
  return "";
}

function isHostToolEnvelope(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const rec = value as Record<string, unknown>;
  if (Array.isArray(rec.content)) {
    return rec.content.some((part) => contentPartText(part).length > 0);
  }
  return typeof rec.content === "string" || typeof rec.text === "string";
}

function stringifyResult(value: unknown): { text: string; contentType: string | null } {
  if (typeof value === "string") {
    return { text: value, contentType: guessContentType(value) };
  }
  if (value == null) return { text: "", contentType: null };
  try {
    const text = JSON.stringify(value);
    return { text, contentType: "application/json" };
  } catch {
    const text = String(value);
    return { text, contentType: guessContentType(text) };
  }
}

/**
 * OpenClaw ``after_tool_call`` often wraps stdout as
 * ``{ content: [{ type: "text", text: "..." }] }``. Unwrap that envelope so
 * operator-log excerpts and extracted paths are the inner body, not the JSON
 * wrapper. Plain JSON tool output is left alone.
 */
export function unwrapHostToolResult(
  result: unknown,
  error?: string,
  depth = 0,
): { text: string; contentType: string | null } {
  if (error) {
    const text = String(error);
    return { text, contentType: guessContentType(text) };
  }
  if (depth > 4) return stringifyResult(result);
  if (typeof result === "string") {
    const trimmed = result.trim();
    if (
      (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
      try {
        const parsed: unknown = JSON.parse(trimmed);
        if (isHostToolEnvelope(parsed) || Array.isArray(parsed)) {
          return unwrapHostToolResult(parsed, undefined, depth + 1);
        }
      } catch {
        /* keep the original string */
      }
    }
    return { text: result, contentType: guessContentType(result) };
  }
  if (Array.isArray(result)) {
    const parts = result.map(contentPartText).filter((part) => part.length > 0);
    if (parts.length) {
      const text = parts.join("\n");
      return { text, contentType: guessContentType(text) };
    }
    return stringifyResult(result);
  }
  if (isHostToolEnvelope(result)) {
    if (Array.isArray(result.content)) {
      const parts = result.content.map(contentPartText).filter((part) => part.length > 0);
      if (parts.length) {
        return unwrapHostToolResult(parts.join(""), undefined, depth + 1);
      }
    }
    if (typeof result.content === "string") {
      return unwrapHostToolResult(result.content, undefined, depth + 1);
    }
    if (typeof result.text === "string") {
      return unwrapHostToolResult(result.text, undefined, depth + 1);
    }
  }
  return stringifyResult(result);
}

/** Drop table-cell / IP / version false positives from PATH_RE. */
export function extractedFilesystemPaths(body: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const match of body.match(PATH_RE) ?? []) {
    const path = match.replace(/[.,;:]+$/u, "");
    if (!isFilesystemPath(path) || seen.has(path)) continue;
    seen.add(path);
    out.push(path);
    if (out.length >= EXTRACTED_LIMIT) break;
  }
  return out;
}

function isFilesystemPath(value: string): boolean {
  if (value.length < 2 || value === "/") return false;
  if (/^\/\d{1,3}(?:\.\d{1,3}){3}\b/.test(value)) return false;
  const parts = value.split("/").filter(Boolean);
  if (parts.length === 0) return false;
  const last = parts[parts.length - 1] ?? "";
  if (/^\d+(?:\.\d+)?[kKmM]?$/.test(last)) return false;
  if (parts.length === 1) return /\.[A-Za-z][A-Za-z0-9]{0,7}$/.test(last);
  if (/^[A-Za-z0-9-]+-\d+\.\d+$/.test(last)) return false;
  return true;
}

export function buildResultSummary(
  text: string,
  opts: {
    ok?: boolean;
    contentType?: string | null;
    command?: string | null;
    excerptLimit?: number;
    hostTruncated?: boolean;
  } = {},
): ResultSummary {
  const body = text || "";
  const byteSize = Buffer.byteLength(body, "utf8");
  const limit = opts.excerptLimit ?? EXCERPT_LIMIT;
  const excerpt = body.length <= limit ? body : body.slice(0, limit);
  const truncated = opts.hostTruncated ?? body.length > limit;
  const urls = [...new Set(body.match(URL_RE) ?? [])].slice(0, EXTRACTED_LIMIT);
  const paths = extractedFilesystemPaths(body);
  const commands = opts.command ? [String(opts.command)] : [];
  return {
    ok: opts.ok ?? true,
    content_type: opts.contentType !== undefined ? opts.contentType : guessContentType(body),
    byte_size: byteSize,
    excerpt,
    extracted: { urls, paths, commands },
    flags: {
      truncated,
      injection_markers: INJECTION_MARKERS.test(body),
    },
  };
}

export function makePlanStep(
  stepId: string,
  tool: string,
  args: Json,
  status: "executed" | "pending",
  resultSummary?: ResultSummary | null,
): PlanStep {
  const step: PlanStep = {
    id: stepId,
    tool: canonicalToolName(tool, args),
    status,
    args: redactArgs(canonicalizeToolArgs(tool, args)),
  };
  if (resultSummary != null) step.result_summary = resultSummary;
  return step;
}

/** Last pending step in trajectory order (the step under scan). */
export function lastPendingStep(plan: PlanIR): PlanStep | undefined {
  for (let i = plan.steps.length - 1; i >= 0; i--) {
    if (plan.steps[i].status === "pending") return plan.steps[i];
  }
  return undefined;
}

export function buildPlanirSnapshot(input: {
  executed: SnapshotCall[];
  pending: SnapshotCall;
  coPending?: SnapshotCall[];
  runId: string;
  intent?: string | null;
  intentKind?: IntentKind | null;
  sessionId?: string | null;
  sessionKey?: string | null;
  agentId?: string | null;
  adapter?: string;
  hook?: string;
  toolCallId?: string | null;
  stepSeq?: number | null;
  batchSize?: number | null;
}): PlanIR {
  const coPending = input.coPending ?? [];
  const steps: PlanStep[] = [];
  let index = 1;
  for (const call of input.executed) {
    const summary =
      call.result_summary ??
      (call.resultText != null
        ? buildResultSummary(call.resultText, {
            ok: call.resultOk ?? true,
            contentType: call.contentType,
            command: call.command,
          })
        : null);
    steps.push(makePlanStep(`s${index}`, call.tool, call.args, "executed", summary));
    index += 1;
  }
  for (const call of coPending) {
    steps.push(makePlanStep(`s${index}`, call.tool, call.args, "pending"));
    index += 1;
  }
  steps.push(makePlanStep(`s${index}`, input.pending.tool, input.pending.args, "pending"));

  return {
    version: "1.0",
    run_id: input.runId,
    intent: input.intent ?? null,
    intent_kind: input.intentKind ?? null,
    steps,
    metadata: {
      adapter: input.adapter ?? "openclaw",
      agent_id: input.agentId ?? "main",
      session_id: input.sessionId ?? null,
      session_key: input.sessionKey ?? null,
      hook: input.hook ?? "before_tool_call",
      tool_call_id: input.toolCallId ?? null,
      step_seq: input.stepSeq ?? null,
      batch_size: input.batchSize ?? null,
    },
  };
}

/** Stable JSON for golden parity (sorted keys, no undefined). */
export function canonicalPlanirJson(plan: PlanIR): string {
  return JSON.stringify(sortKeysDeep(plan));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      const v = obj[key];
      if (v === undefined) continue;
      out[key] = sortKeysDeep(v);
    }
    return out;
  }
  return value;
}
