/**
 * PlanIR 1.0 sanitization (Options A, B, D, G).
 * Rules mirror sentrook/sentrook/sanitize/rules.yaml — keep in sync.
 *
 * Env-style credential assignments (export FOO_PASS=…) and CLI secret flags
 * (--password …) are handled in code (same as sentrook.sanitize.core) because
 * keyword-only regex replacement leaves values intact.
 */

import { createHash } from "node:crypto";

import type { PlanIR } from "./planir.ts";

export interface SanitizeRules {
  version: number;
  redacted: string;
  truncated: string;
  resultTextMaxChars: number;
  intentMaxChars: number;
  stringLeafMaxChars: number;
  sessionHashPrefix: string;
  sessionHashHexChars: number;
  credentialField: RegExp;
  secretValuePatterns: RegExp[];
  piiPatterns: RegExp[];
  piiArgKeys: ReadonlySet<string>;
  allowedResultKeys: ReadonlySet<string>;
}

/** Underscore-delimited credential segments (LIBRARY_BOT_PASS, not COMPASS). */
const CREDENTIAL_VAR_SEGMENT =
  /(?:^|_)(pass(?:wd|word)?|secret|token|api[_-]?key|auth|credential|bearer)(?:_|$)/i;

// Quoted values use the unrolled form `[^"\\]*(?:\\.[^"\\]*)*` so each character
// has one match path (`(?:\\.|[^"\\])*` is polynomial ReDoS on backtracking engines).
const ENV_ASSIGNMENT =
  /((?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&]+)/gi;

const CLI_SECRET_FLAG =
  /(--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)(?:-\w+)?)(\s*=\s*|\s+)(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&]+)/gi;

export const DEFAULT_RULES: SanitizeRules = {
  version: 1,
  redacted: "[REDACTED]",
  truncated: "[TRUNCATED]",
  resultTextMaxChars: 500,
  intentMaxChars: 1000,
  stringLeafMaxChars: 500,
  sessionHashPrefix: "sess_",
  sessionHashHexChars: 12,
  // Bounded ``pass`` — see rules.yaml credential_field_pattern.
  credentialField: /(token|password|passwd|(?<![a-z])pass(?![a-z])|secret|api[_-]?key|auth|credential|bearer)/i,
  secretValuePatterns: [
    /(?<![-_])\b(api[_-]?key|password|secret)\b(?!\s*=)|bearer\s+[A-Za-z0-9._=-]+/gi,
    /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-[a-z0-9]{10,}/g,
    /sk-ant-[a-z0-9-]{10,}/g,
    /gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/g,
    /glpat-[A-Za-z0-9_-]{20,}/g,
    /xox[baprs]-[A-Za-z0-9-]{10,}|xoxe(?:\.xox[bp])?-\d-[A-Za-z0-9]+|xapp-\d-[A-Za-z0-9-]+/gi,
    /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/_-]+/g,
    /[MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,110}/g,
    /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/(?:\d+|\[REDACTED\])\/[A-Za-z0-9_-]+/g,
    /\b\d{5,16}:A[A-Za-z0-9_-]{34}\b/g,
    /\bnpm_[A-Za-z0-9]{36}\b/g,
    /\bSK[0-9a-fA-F]{32}\b/g,
    /\bEAA[A-Za-z0-9]{40,}\b/g,
    /(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/g,
    /AIza[0-9A-Za-z_-]{35}/g,
    /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g,
    /hf_[A-Za-z0-9]{20,}/g,
    /gsk_[A-Za-z0-9]{20,}/g,
    /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/g,
  ],
  piiPatterns: [
    /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    // Option C — structured IDs before loose phone/card digit runs
    /\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][a-z]+|[A-Z]{1,3}\d?[A-Za-z]?)\s+(?:[A-Z][a-z]+\s+){0,3}(?:Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Close|Crescent|Cres\.?|Grove|Hill|Row)\b/gi,
    /\b(?:GIR\s?0AA|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})\b/gi,
    /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
    /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/gi,
    /\b(?:\d[ -]*?){13,19}\b/g,
    /\+?[0-9][0-9()\-\s.]{7,}[0-9]/g,
  ],
  piiArgKeys: new Set(["command", "cmd", "message", "text", "content", "body"]),
  allowedResultKeys: new Set([
    "ok",
    "content_type",
    "byte_size",
    "excerpt",
    "extracted",
    "flags",
  ]),
};

export interface SanitizePlanIRResult {
  plan: PlanIR;
  sanitizeMs: number;
}

export interface SanitizationConfig {
  /** @deprecated Always true; PlanIR is always scrubbed before egress. */
  enabled: boolean;
}

export const ALWAYS_SANITIZE: SanitizationConfig = { enabled: true };

export function resolveSanitizationConfig(
  _pluginCfg?: Record<string, unknown>,
  _env: NodeJS.ProcessEnv = process.env,
): SanitizationConfig {
  return ALWAYS_SANITIZE;
}

export function hashSessionId(sessionId: string, rules: SanitizeRules = DEFAULT_RULES): string {
  const digest = createHash("sha256").update(sessionId, "utf8").digest("hex");
  return `${rules.sessionHashPrefix}${digest.slice(0, rules.sessionHashHexChars)}`;
}

/** Prose arg keys and exec argv where late-payload attacks are common (mirror Python). */
const CONTENT_LIKE_KEYS = new Set(["content", "text", "body", "message", "command", "cmd"]);

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const SENSITIVE_PATH_RE =
  /auth-profiles(?:\.json)?|openclaw-agent\.sqlite|database\.sqlite|~?\/\.ssh(?:\/[^\s"']*)?|MEMORY\.md|authorized_keys|\/etc\/[^\s"']+/gi;
const COMMANDISH_LINE_RE = /^.*(?:\bcurl\b|\bwget\b|\btar\b.+\||\bPOST\b|\bpip\s+install\b).*$/gim;
const INJECTION_MARKERS =
  /ignore (?:all |the |your )?(?:previous|prior|above|earlier)\b|ignore (?:all |the |your )?safety\b|(?:system|admin|developer)\s+override|disregard (?:all |the |your )?(?:previous|prior|above|earlier|safety)|system prompt|exfiltrat|upload\s+\S*(?:auth-profiles|openclaw-agent\.sqlite|database\.sqlite|credentials|secrets|\.ssh)\S*\s+to\s+https?:\/\/|(?:important|mandatory|required)\s*:\s*before\b.{0,60}\b(?:upload|send|post|transmit)\b/gi;

const SIGNAL_SEP = " … ";
const MARKER_PAD = 60;

function isContentLikeKey(key: string | null | undefined): boolean {
  if (!key) return false;
  return CONTENT_LIKE_KEYS.has(key.toLowerCase());
}

function signalBudgets(limit: number): { head: number; tail: number } {
  let head: number;
  let tail: number;
  if (limit <= 40) {
    head = Math.max(8, Math.floor(limit / 3));
    tail = Math.max(6, Math.floor(limit / 4));
  } else if (limit <= 100) {
    head = Math.max(24, Math.floor(limit / 3));
    tail = Math.max(16, Math.floor(limit / 4));
  } else {
    head = Math.min(120, Math.max(40, Math.floor(limit / 4)));
    tail = Math.min(80, Math.max(24, Math.floor(limit / 6)));
  }
  const reserved = SIGNAL_SEP.length * 2 + 3;
  while (head + tail + reserved > limit && (head > 8 || tail > 6)) {
    if (head >= tail && head > 8) head -= 1;
    else if (tail > 6) tail -= 1;
    else break;
  }
  return { head, tail };
}

function collectSignalSpans(text: string): Array<{ start: number; end: number; snippet: string }> {
  const raw: Array<{ start: number; end: number; snippet: string }> = [];

  for (const re of [URL_RE, SENSITIVE_PATH_RE]) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      raw.push({ start: match.index, end: match.index + match[0].length, snippet: match[0] });
    }
  }

  COMMANDISH_LINE_RE.lastIndex = 0;
  let cmdMatch: RegExpExecArray | null;
  while ((cmdMatch = COMMANDISH_LINE_RE.exec(text)) !== null) {
    const snippet = cmdMatch[0].trim();
    URL_RE.lastIndex = 0;
    if (!snippet || URL_RE.test(snippet)) continue;
    raw.push({
      start: cmdMatch.index,
      end: cmdMatch.index + cmdMatch[0].length,
      snippet,
    });
  }

  INJECTION_MARKERS.lastIndex = 0;
  let inj: RegExpExecArray | null;
  while ((inj = INJECTION_MARKERS.exec(text)) !== null) {
    let start = Math.max(0, inj.index - MARKER_PAD);
    let end = Math.min(text.length, inj.index + inj[0].length + MARKER_PAD);
    const lineStart = text.lastIndexOf("\n", inj.index) + 1;
    const lineEndRaw = text.indexOf("\n", inj.index + inj[0].length);
    const lineEnd = lineEndRaw < 0 ? text.length : lineEndRaw;
    if (lineStart >= start - 20) start = Math.min(start, lineStart);
    if (lineEnd <= end + 20) end = Math.max(end, lineEnd);
    const snippet = text.slice(start, end).trim();
    if (snippet) raw.push({ start, end, snippet });
  }

  raw.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const merged: Array<{ start: number; end: number; snippet: string }> = [];
  for (const span of raw) {
    if (merged.length && span.start < merged[merged.length - 1].end) continue;
    merged.push(span);
  }
  return merged;
}

/** Pack long prose into ``limit`` chars keeping URLs/paths/markers (mirror Python). */
export function packSignalExcerpt(text: string, limit: number, ellipsis = "..."): string {
  if (limit <= 0) return "";
  if (text.length <= limit) return text;
  if (limit <= 3) return ellipsis.slice(0, limit);

  const { head: headBudget, tail: tailBudget } = signalBudgets(limit);
  const head = text.slice(0, headBudget);
  const tail = alignedTail(text, tailBudget);

  const signals: string[] = [];
  const seen = new Set<string>();
  for (const span of collectSignalSpans(text)) {
    const snippet = span.snippet.trim();
    if (!snippet || seen.has(snippet)) continue;
    if (head.includes(snippet)) continue;
    seen.add(snippet);
    signals.push(snippet);
  }

  const parts: string[] = [head];
  let used = head.length;

  for (let signal of signals) {
    const maxSignal = Math.max(24, Math.floor(limit / 2));
    if (signal.length > maxSignal) {
      URL_RE.lastIndex = 0;
      const urlMatch = URL_RE.exec(signal);
      if (urlMatch && urlMatch[0].length <= maxSignal) {
        signal = urlMatch[0];
      } else if (urlMatch && urlMatch[0].length > maxSignal) {
        signal = `${urlMatch[0].slice(0, maxSignal - 3)}${ellipsis}`;
      } else {
        signal = `${signal.slice(0, maxSignal - 3)}${ellipsis}`;
      }
    }
    const cost = SIGNAL_SEP.length + signal.length;
    if (used + cost > limit) break;
    const remainingAfter = limit - (used + cost);
    const needTail = tail && !head.includes(tail) ? 1 : 0;
    const minTailRoom = needTail ? SIGNAL_SEP.length + Math.min(tail.length, 8) : 0;
    if (remainingAfter < minTailRoom && needTail) break;
    parts.push(signal);
    used += cost;
  }

  if (tail && !head.includes(tail)) {
    // Skip tail only when a packed signal already contains it. A short URL
    // inside the tail must not drop the rest (curl|bash after a long prefix).
    const already = parts.slice(1).some((p) => p.includes(tail));
    const room = limit - used - SIGNAL_SEP.length;
    if (!already && room >= 8) {
      const clipped =
        tail.length <= room ? tail : `${tail.slice(-(room - 3))}${ellipsis}`;
      parts.push(clipped);
    } else if (!already && room > 3) {
      parts.push(ellipsis.slice(0, room));
    }
  }

  let packed = parts.join(SIGNAL_SEP);
  if (packed.length > limit) {
    packed = `${packed.slice(0, limit - 3)}${ellipsis}`;
  }
  if (packed === head && head.length < limit) {
    return limit > 3 ? `${head.slice(0, limit - 3)}${ellipsis}` : ellipsis.slice(0, limit);
  }
  return packed;
}

function alignedTail(text: string, budget: number): string {
  if (budget <= 0 || !text) return "";
  let tail = text.slice(-budget);
  for (const sep of ["\n", " ", "\t"]) {
    const idx = tail.indexOf(sep);
    if (idx >= 0 && idx <= Math.min(24, Math.max(0, Math.floor(budget / 4)))) {
      return tail.slice(idx + 1);
    }
  }
  return tail;
}

function truncate(
  text: string,
  limit: number,
  rules: SanitizeRules,
  options: { signalAware?: boolean } = {},
): string {
  if (text.length <= limit) return text;
  if (limit <= 3) return rules.truncated;
  if (options.signalAware) {
    return packSignalExcerpt(text, limit, "...");
  }
  return `${text.slice(0, limit - 3)}...`;
}

function isCredentialVarName(name: string): boolean {
  return CREDENTIAL_VAR_SEGMENT.test(name);
}

function isShellStyleAssignmentName(name: string): boolean {
  // Underscore / uniform case → scrub. CamelCase apiKey= left for token patterns.
  if (name.includes("_") || name === name.toUpperCase() || name === name.toLowerCase()) {
    return true;
  }
  return false;
}

function redactEnvSecretAssignments(text: string, placeholder: string): string {
  return text.replace(ENV_ASSIGNMENT, (match, exportPrefix: string, name: string) => {
    if (!isCredentialVarName(name)) return match;
    if (!exportPrefix && !isShellStyleAssignmentName(name)) return match;
    return `${exportPrefix}${name}=${placeholder}`;
  });
}

function redactCliSecretFlags(text: string, placeholder: string): string {
  return text.replace(CLI_SECRET_FLAG, (_match, flag: string, sep: string) => {
    return `${flag}${sep}${placeholder}`;
  });
}

function applyPatterns(text: string, patterns: RegExp[], replacement: string): string {
  let out = text;
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    out = out.replace(pattern, replacement);
  }
  return out;
}

function applySecretPatterns(text: string, rules: SanitizeRules): string {
  let cleaned = redactEnvSecretAssignments(text, rules.redacted);
  cleaned = redactCliSecretFlags(cleaned, rules.redacted);
  return applyPatterns(cleaned, rules.secretValuePatterns, rules.redacted);
}

/** Secret-pattern scrub for operator-facing copy (no PII, no length placeholder). */
export function scrubSecrets(text: string, rules: SanitizeRules = DEFAULT_RULES): string {
  return applySecretPatterns(text, rules);
}

function scrubString(
  text: string,
  rules: SanitizeRules,
  options: { pii: boolean; maxChars: number; key?: string | null },
): string {
  let cleaned = applySecretPatterns(text, rules);
  if (options.pii) {
    cleaned = applyPatterns(cleaned, rules.piiPatterns, rules.redacted);
  }
  return truncate(cleaned, options.maxChars, rules, {
    signalAware: isContentLikeKey(options.key),
  });
}

function isCredentialField(key: string, rules: SanitizeRules): boolean {
  rules.credentialField.lastIndex = 0;
  return rules.credentialField.test(key);
}

function sanitizeValue(
  value: unknown,
  rules: SanitizeRules,
  options: {
    parentKey: string | null;
    pii: boolean;
    maxChars: number;
    piiKeys?: ReadonlySet<string>;
  },
): unknown {
  if (options.parentKey !== null && isCredentialField(options.parentKey, rules)) {
    return rules.redacted;
  }
  if (typeof value === "string") {
    return scrubString(value, rules, {
      pii: options.pii,
      maxChars: options.maxChars,
      key: options.parentKey,
    });
  }
  if (Array.isArray(value)) {
    return value.map((item) =>
      sanitizeValue(item, rules, {
        parentKey: null,
        pii: false,
        maxChars: options.maxChars,
        piiKeys: options.piiKeys,
      }),
    );
  }
  if (value !== null && typeof value === "object") {
    const nestedPii =
      options.pii || (options.parentKey !== null && options.parentKey.toLowerCase() === "env");
    return sanitizeMapping(value as Record<string, unknown>, rules, {
      pii: nestedPii,
      maxChars: options.maxChars,
      piiKeys: options.piiKeys,
    });
  }
  return value;
}

function sanitizeMapping(
  mapping: Record<string, unknown>,
  rules: SanitizeRules,
  options: { pii: boolean; maxChars: number; piiKeys?: ReadonlySet<string> },
): Record<string, unknown> {
  const piiKeys = options.piiKeys ?? new Set<string>();
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(mapping)) {
    out[key] = sanitizeValue(value, rules, {
      parentKey: key,
      pii: options.pii || piiKeys.has(key),
      maxChars: options.maxChars,
      piiKeys,
    });
  }
  return out;
}

function sanitizeResultSummary(
  summary: Record<string, unknown>,
  rules: SanitizeRules,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...summary };
  if (typeof summary.excerpt === "string") {
    const scrubbed = scrubString(summary.excerpt, rules, {
      pii: false,
      maxChars: rules.resultTextMaxChars,
      key: "excerpt",
    });
    out.excerpt = scrubbed;
    out.byte_size = Buffer.byteLength(scrubbed, "utf8");
  }
  const extracted = summary.extracted;
  if (extracted && typeof extracted === "object" && !Array.isArray(extracted)) {
    const ext = extracted as Record<string, unknown>;
    const cleaned: Record<string, unknown> = { ...ext };
    if (Array.isArray(ext.commands)) {
      cleaned.commands = ext.commands.map((item) =>
        typeof item === "string"
          ? scrubString(item, rules, {
              pii: true,
              maxChars: rules.stringLeafMaxChars,
              key: "command",
            })
          : item,
      );
    }
    out.extracted = cleaned;
  }
  return out;
}

function sanitizeStep(
  step: Record<string, unknown>,
  rules: SanitizeRules,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...step };
  if (step.args && typeof step.args === "object" && !Array.isArray(step.args)) {
    out.args = sanitizeMapping(step.args as Record<string, unknown>, rules, {
      pii: false,
      maxChars: rules.stringLeafMaxChars,
      piiKeys: rules.piiArgKeys,
    });
  }
  if (
    step.result_summary &&
    typeof step.result_summary === "object" &&
    !Array.isArray(step.result_summary)
  ) {
    out.result_summary = sanitizeResultSummary(
      step.result_summary as Record<string, unknown>,
      rules,
    );
  }
  return out;
}

function rewriteRunId(runId: string, originalSessionId: string, hashedSessionId: string): string {
  const prefix = `${originalSessionId}:`;
  if (runId.startsWith(prefix)) {
    return `${hashedSessionId}:${runId.slice(prefix.length)}`;
  }
  return runId;
}

export function sanitizePlanirDict(
  payload: Record<string, unknown>,
  rules: SanitizeRules = DEFAULT_RULES,
): Record<string, unknown> {
  const data = structuredClone(payload);

  const metadata =
    data.metadata && typeof data.metadata === "object" && !Array.isArray(data.metadata)
      ? (data.metadata as Record<string, unknown>)
      : {};
  data.metadata = metadata;

  const originalSessionId = metadata.session_id;
  if (typeof originalSessionId === "string" && originalSessionId) {
    const hashed = hashSessionId(originalSessionId, rules);
    metadata.session_id = hashed;
    if (typeof data.run_id === "string") {
      data.run_id = rewriteRunId(data.run_id, originalSessionId, hashed);
    }
  }

  if (typeof data.intent === "string") {
    data.intent = scrubString(data.intent, rules, {
      pii: true,
      maxChars: rules.intentMaxChars,
    });
  }

  if (Array.isArray(data.steps)) {
    data.steps = data.steps
      .filter((item): item is Record<string, unknown> => !!item && typeof item === "object")
      .map((item) => sanitizeStep(item, rules));
  }

  return data;
}

export function sanitizePlanir(
  plan: PlanIR,
  rules: SanitizeRules = DEFAULT_RULES,
): SanitizePlanIRResult {
  const started = performance.now();
  const cleaned = sanitizePlanirDict(plan as unknown as Record<string, unknown>, rules);
  const elapsedMs = Math.round(performance.now() - started);
  return {
    plan: cleaned as PlanIR,
    sanitizeMs: elapsedMs,
  };
}

export function maybeSanitizePlanir(
  plan: PlanIR,
  _config: SanitizationConfig = ALWAYS_SANITIZE,
  rules: SanitizeRules = DEFAULT_RULES,
): SanitizePlanIRResult {
  return sanitizePlanir(plan, rules);
}
