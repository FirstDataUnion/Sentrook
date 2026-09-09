/**
 * Attended vs unattended classification for OpenClaw tool reviews.
 *
 * Host-authoritative signals (preferred):
 * - ``ctx.trigger`` / ``ctx.jobId`` on agent-turn hooks (not on ``before_tool_call``)
 * - canonical session keys (``cron:`` / isolated ``:heartbeat`` / ``subagent:``)
 *
 * Subagents inherit the parent: a child of a user session is attended; a child
 * of cron or heartbeat is unattended. Prompt ``[cron:]`` markers are a last
 * resort for older hosts.
 */

import { DEFAULT_RULES } from "./sanitize.ts";

export type IntentKind = "user" | "cron" | "heartbeat" | "subagent" | "system";
export type AgentTrigger = "user" | "cron" | "heartbeat";

/** Root kinds that use the unattended floor. Subagents inherit; they are not a root. */
export const DEFAULT_UNATTENDED_ROOT_KINDS: IntentKind[] = ["cron", "heartbeat"];

export interface AttendanceSignals {
  trigger?: string | null;
  jobId?: string | null;
  sessionKey?: string | null;
  parentSessionKey?: string | null;
  parentUnattended?: boolean;
  intentText?: string | null;
}

export interface Attendance {
  kind: IntentKind;
  unattended: boolean;
}

function nonempty(value: string | null | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

/** Agent-scoped rest (``cron:…``) or the raw key when it is not ``agent:id:…``. */
export function parseAgentSessionRest(sessionKey?: string | null): string | undefined {
  const raw = nonempty(sessionKey)?.toLowerCase();
  if (!raw) return undefined;
  if (!raw.startsWith("agent:")) return raw;
  const agentIdEnd = raw.indexOf(":", "agent:".length);
  if (agentIdEnd === -1) return undefined;
  const rest = raw.slice(agentIdEnd + 1);
  if (!rest || rest.startsWith(":")) return undefined;
  return rest;
}

/** OpenClaw ``agent:<id>:cron:<jobId>`` and ``…:cron:<jobId>:run:<runId>``. */
export function isCronSessionKey(sessionKey?: string | null): boolean {
  const rest = parseAgentSessionRest(sessionKey);
  return rest?.startsWith("cron:") === true;
}

/** ``subagent:…`` or ``agent:<id>:subagent:…``. */
export function isSubagentSessionKey(sessionKey?: string | null): boolean {
  const raw = nonempty(sessionKey)?.toLowerCase();
  if (!raw) return false;
  if (raw.startsWith("subagent:")) return true;
  const rest = parseAgentSessionRest(sessionKey);
  return rest?.startsWith("subagent:") === true;
}

/**
 * Isolated heartbeat keys end with ``:heartbeat`` (``agent:main:main:heartbeat``).
 * A dedicated ``heartbeat`` rest is also treated as heartbeat. Cron/subagent
 * keys win when both could match.
 */
export function isHeartbeatSessionKey(sessionKey?: string | null): boolean {
  if (isCronSessionKey(sessionKey) || isSubagentSessionKey(sessionKey)) return false;
  const rest = parseAgentSessionRest(sessionKey);
  if (!rest) return false;
  return rest === "heartbeat" || rest.endsWith(":heartbeat");
}

function asTrigger(raw?: string | null): AgentTrigger | undefined {
  const value = nonempty(raw)?.toLowerCase();
  if (value === "cron" || value === "heartbeat" || value === "user") return value;
  return undefined;
}

function promptKind(intentText?: string | null): IntentKind | undefined {
  const normalized = nonempty(intentText);
  if (!normalized) return undefined;
  if (/^\s*\[cron:/i.test(normalized)) return "cron";
  if (/\[Subagent Context\]|\[Subagent Task\]/i.test(normalized)) return "subagent";
  if (/^\s*\[heartbeat[:\]]/i.test(normalized)) return "heartbeat";
  if (/^\s*\[system[:\]]/i.test(normalized)) return "system";
  return undefined;
}

function unattendedRoots(kinds: readonly IntentKind[]): Set<IntentKind> {
  return new Set(kinds.length ? kinds : DEFAULT_UNATTENDED_ROOT_KINDS);
}

/**
 * Classify a run. Prefer host trigger/jobId, then session key, then prompt
 * markers. Subagent attendance follows the parent unless ``subagent`` is in
 * the unattended-root list (legacy override).
 */
export function classifyAttendance(
  signals: AttendanceSignals,
  unattendedRootKinds: readonly IntentKind[] = DEFAULT_UNATTENDED_ROOT_KINDS,
): Attendance {
  const trigger = asTrigger(signals.trigger);
  const jobId = nonempty(signals.jobId);
  const sessionKey = nonempty(signals.sessionKey);
  const parentKey = nonempty(signals.parentSessionKey);
  const fromPrompt = promptKind(signals.intentText);
  const roots = unattendedRoots(unattendedRootKinds);

  const hostRoot: "cron" | "heartbeat" | undefined =
    trigger === "cron" || jobId
      ? "cron"
      : trigger === "heartbeat"
        ? "heartbeat"
        : isCronSessionKey(sessionKey)
          ? "cron"
          : isHeartbeatSessionKey(sessionKey)
            ? "heartbeat"
            : fromPrompt === "cron" || fromPrompt === "heartbeat"
              ? fromPrompt
              : undefined;

  const isSubagent =
    isSubagentSessionKey(sessionKey) || fromPrompt === "subagent";

  if (isSubagent) {
    if (roots.has("subagent")) return { kind: "subagent", unattended: true };
    if (hostRoot && roots.has(hostRoot)) return { kind: "subagent", unattended: true };
    let parentUnattended = signals.parentUnattended;
    if (parentUnattended === undefined && parentKey) {
      parentUnattended = classifyAttendance(
        { sessionKey: parentKey },
        unattendedRootKinds,
      ).unattended;
    }
    return { kind: "subagent", unattended: parentUnattended === true };
  }

  const kind: IntentKind = hostRoot ?? (fromPrompt === "system" ? "system" : "user");
  return { kind, unattended: roots.has(kind) };
}

const PROMPT_KEYS = [
  "prompt",
  "cleanedBody",
  "text",
  "content",
  "body",
  "user_message",
  "message",
] as const;

const SKIP_MESSAGE_ROLES = new Set(["assistant", "system", "tool", "function", "model"]);

function clipIntent(text: string, maxChars: number): string {
  const trimmed = text.trim();
  if (trimmed.length <= maxChars) return trimmed;
  return trimmed.slice(0, maxChars);
}

function flattenText(value: unknown, depth = 0): string | undefined {
  if (depth > 6 || value == null) return undefined;
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || undefined;
  }
  if (typeof value === "number" || typeof value === "boolean") return undefined;
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const item of value) {
      const piece = flattenText(item, depth + 1);
      if (piece) parts.push(piece);
    }
    return parts.length ? parts.join("\n") : undefined;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj.text === "string") {
      const trimmed = obj.text.trim();
      if (trimmed) return trimmed;
    }
    if ("content" in obj) {
      const nested = flattenText(obj.content, depth + 1);
      if (nested) return nested;
    }
  }
  return undefined;
}

function fromPromptKeys(obj: Record<string, unknown>): string | undefined {
  for (const key of PROMPT_KEYS) {
    if (!(key in obj)) continue;
    const found = flattenText(obj[key]);
    if (found) return found;
  }
  return undefined;
}

function messageRole(value: unknown): string {
  if (!value || typeof value !== "object") return "";
  const role = (value as { role?: unknown }).role;
  return typeof role === "string" ? role.trim().toLowerCase() : "";
}

function lastUserMessageText(messages: unknown[]): string | undefined {
  for (let i = messages.length - 1; i >= 0; i--) {
    const role = messageRole(messages[i]);
    if (role && SKIP_MESSAGE_ROLES.has(role)) continue;
    if (role && role !== "user" && role !== "human") continue;
    const found = flattenText(messages[i]);
    if (found) return found;
  }
  for (let i = messages.length - 1; i >= 0; i--) {
    if (SKIP_MESSAGE_ROLES.has(messageRole(messages[i]))) continue;
    const found = flattenText(messages[i]);
    if (found) return found;
  }
  return undefined;
}

/** First non-empty trimmed candidate; empty string if none. */
export function firstNonemptyIntent(
  ...values: Array<string | null | undefined>
): string {
  for (const value of values) {
    const trimmed = value?.trim();
    if (trimmed) return trimmed;
  }
  return "";
}

/**
 * Pull operator-facing intent text from a host hook payload.
 * Prefers ``prompt`` / inbound ``content``, then the last user message.
 */
export function extractIntentText(
  source: unknown,
  maxChars: number = DEFAULT_RULES.intentMaxChars,
): string | undefined {
  if (typeof source === "string") {
    const clipped = clipIntent(source, maxChars);
    return clipped || undefined;
  }
  if (!source || typeof source !== "object") return undefined;
  const obj = source as Record<string, unknown>;
  const direct = fromPromptKeys(obj);
  if (direct) return clipIntent(direct, maxChars);
  if (Array.isArray(obj.messages)) {
    const fromMessages = lastUserMessageText(obj.messages);
    if (fromMessages) return clipIntent(fromMessages, maxChars);
  }
  return undefined;
}
