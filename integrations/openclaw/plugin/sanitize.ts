/**
 * PlanIR 1.0 sanitization (Options A, B, D, G).
 * Rules mirror sentrook/sentrook/sanitize/rules.yaml — keep in sync.
 *
 * Env-style credential assignments (export FOO_PASS=…) and CLI secret flags
 * (--password …) are handled in code (same as sentrook.sanitize.core) because
 * keyword-only regex replacement leaves values intact.
 */

import { createHash, createHmac, randomBytes } from "node:crypto";

import { GITLEAKS_RULES, type GitleaksRule } from "./gitleaksRules.ts";
import type { PlanIR } from "./planir.ts";

export interface SecretValuePattern {
  pattern: RegExp;
  keepPrefix?: boolean;
}

export interface SanitizeRules {
  version: number;
  redacted: string;
  truncated: string;
  resultTextMaxChars: number;
  intentMaxChars: number;
  stringLeafMaxChars: number;
  /** Argv budget — larger than prose so exec_shape can parse real shell. */
  commandMaxChars: number;
  sessionHashPrefix: string;
  sessionHashHexChars: number;
  credentialField: RegExp;
  secretValuePatterns: SecretValuePattern[];
  piiPatterns: Array<{ pattern: RegExp; validator?: PiiValidator }>;
  piiArgKeys: ReadonlySet<string>;
  allowedResultKeys: ReadonlySet<string>;
}

/** Underscore-delimited credential segments (LIBRARY_BOT_PASS, not COMPASS). */
const CREDENTIAL_VAR_SEGMENT =
  /(?:^|_)(pass(?:wd|word)?|secret|token|api[_-]?key|auth|credential|bearer)(?:_|$)/i;

// Quoted values use the unrolled form `[^"\\]*(?:\\.[^"\\]*)*` so each character
// has one match path (`(?:\\.|[^"\\])*` is polynomial ReDoS on backtracking engines).
// The var-name pattern `(?=[A-Za-z_])[A-Za-z0-9_]+` uses a lookahead to assert the
// first char without consuming it, so the entire identifier is one `[A-Za-z0-9_]+`
// atom — no split-point backtracking on long underscore runs.
// The bare-value branch excludes quote characters on purpose. With `[^\s;|&]+`
// an assignment *inside* a quoted string swallowed the closing quote:
//   curl -d "token=ghp_abc"  ->  curl -d "token=[REDACTED]
// leaving the command unbalanced and therefore unparseable, so it could never
// match an allow rule. A quote terminates a shell value, so this is also correct.
const ENV_ASSIGNMENT =
  /((?:export\s+)?)((?=[A-Za-z_])[A-Za-z0-9_]+)\s*=\s*(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&"']+)/gi;

const CLI_SECRET_FLAG =
  /(--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)(?:-\w+)?)(\s*=\s*|\s+)(?:"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&"']+)/gi;

/**
 * Checksum / plausibility validators. Mirror of `_VALIDATORS` in core.py.
 *
 * This is the one thing Presidio does that a bare regex cannot: a pattern loose
 * enough to *find* candidates always over-matches, and only a check can separate
 * a real card number from an epoch-ms timestamp. We borrow the discipline, not
 * the dependency — Presidio needs a 382 MB spaCy model and cannot run here at all.
 */
export type PiiValidator = "luhn" | "iban_mod97" | "phone_plausible" | "uk_postcode_plausible";

function luhnValid(value: string): boolean {
  const digits = [...value].filter((c) => c >= "0" && c <= "9").map(Number);
  if (digits.length < 13 || digits.length > 19) return false;
  let total = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
    double = !double;
  }
  return total % 10 === 0;
}

function ibanMod97Valid(value: string): boolean {
  const compact = value.replace(/\s+/g, "").toUpperCase();
  if (compact.length < 15 || compact.length > 34) return false;
  if (!/^[A-Z]{2}[0-9]{2}/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const chunk = /[0-9]/.test(ch)
      ? ch
      : /[A-Z]/.test(ch)
        ? String(ch.charCodeAt(0) - 55)
        : null;
    if (chunk === null) return false;
    for (const d of chunk) remainder = (remainder * 10 + Number(d)) % 97;
  }
  return remainder === 1;
}

/**
 * E.164 caps a phone at 15 digits, and real phones in prose carry punctuation.
 * Together these reject epoch-ms timestamps, byte counts and concatenated ids,
 * which the pattern alone cannot distinguish. Known gap: a bare unpunctuated
 * `07700900123` is not redacted — the cost of not redacting every timestamp,
 * which would fabricate cross-step marker linkages Phase 4 reads as dataflow.
 */
function phonePlausible(value: string): boolean {
  const digits = [...value].filter((c) => c >= "0" && c <= "9").length;
  if (digits < 7 || digits > 15) return false;
  return value.trimStart().startsWith("+") || /[ .\-()]/.test(value.trim());
}

/**
 * Reject hex runs that look like a UK postcode. The bare pattern matches 6-char
 * hex (`e629fa`, `c6f3ac`), so git short SHAs, docker ids and hex colours were
 * redacted — both ubiquitous in agent output, and each match mints a marker,
 * fabricating cross-step linkage. The space is the discriminator: real postcodes
 * usually carry one, hex ids never do.
 */
function ukPostcodePlausible(value: string): boolean {
  const compact = value.trim();
  if (/\s/.test(compact)) return true;
  return !/^[0-9a-f]+$/i.test(compact);
}

const PII_VALIDATORS: Record<PiiValidator, (value: string) => boolean> = {
  luhn: luhnValid,
  iban_mod97: ibanMod97Valid,
  phone_plausible: phonePlausible,
  uk_postcode_plausible: ukPostcodePlausible,
};

export const DEFAULT_RULES: SanitizeRules = {
  // Bump on ANY change; surfaces as `rules_version` in the operator log so a
  // log line identifies the sanitize ruleset that produced it.
  version: 4,
  redacted: "[REDACTED]",
  truncated: "[TRUNCATED]",
  resultTextMaxChars: 500,
  intentMaxChars: 1000,
  stringLeafMaxChars: 500,
  commandMaxChars: 4000,
  sessionHashPrefix: "sess_",
  sessionHashHexChars: 12,
  // Bounded ``pass`` — see rules.yaml credential_field_pattern.
  credentialField: /(token|password|passwd|(?<![a-z])pass(?![a-z])|secret|api[_-]?key|auth|credential|bearer)/i,
  secretValuePatterns: [
    { pattern: /(bearer\s+)[A-Za-z0-9._=-]+/gi, keepPrefix: true },
    {
      pattern:
        /(sk-(?:proj|svcacct|admin|live)-)[A-Za-z0-9_-]{8,}|(sk-)[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|(sk-)[a-z0-9]{10,}/gi,
      keepPrefix: true,
    },
    { pattern: /(sk-ant-)[a-z0-9-]{10,}/gi, keepPrefix: true },
    { pattern: /(gh[pousr]_)[A-Za-z0-9]{20,}|(github_pat_)[A-Za-z0-9_]{20,}/gi, keepPrefix: true },
    { pattern: /(glpat-)[A-Za-z0-9_-]{20,}/gi, keepPrefix: true },
    {
      pattern:
        /(xox[baprs]-)[A-Za-z0-9-]{10,}|(xoxe(?:\.xox[bp])?-\d-)[A-Za-z0-9]+|(xapp-\d-)[A-Za-z0-9-]+/gi,
      keepPrefix: true,
    },
    {
      pattern: /(https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/)[A-Za-z0-9+\/_-]+/gi,
      keepPrefix: true,
    },
    { pattern: /[MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,110}/gi },
    {
      pattern:
        /(https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/)(?:\d+|\[REDACTED\])\/[A-Za-z0-9_-]+/gi,
      keepPrefix: true,
    },
    { pattern: /\b\d{5,16}:A[A-Za-z0-9_-]{34}\b/gi },
    { pattern: /\b(npm_)[A-Za-z0-9]{36}\b/gi, keepPrefix: true },
    { pattern: /\b(SK)[0-9a-fA-F]{32}\b/gi, keepPrefix: true },
    { pattern: /\b(EAA)[A-Za-z0-9]{40,}\b/gi, keepPrefix: true },
    { pattern: /((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA))[A-Z0-9]{16}/gi, keepPrefix: true },
    { pattern: /(AIza)[0-9A-Za-z_-]{35}/gi, keepPrefix: true },
    { pattern: /((?:sk|rk)_(?:live|test)_)[A-Za-z0-9]{20,}/gi, keepPrefix: true },
    { pattern: /(hf_)[A-Za-z0-9]{20,}/gi, keepPrefix: true },
    { pattern: /(gsk_)[A-Za-z0-9]{20,}/gi, keepPrefix: true },
    // Three base64url segments; `eyJ` is base64 of `{"` so the prefix is
    // self-identifying and false positives are negligible. Covers OIDC access
    // tokens, k8s service-account tokens and session JWTs — none of which a
    // provider-prefix pattern catches when they appear bare.
    { pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/gi },
    // Cookie/iSet-Cookie header values and bare session=/sid= assignments, which
    // the credential var-name segment (underscore-delimited) does not cover.
    // Terminated on quotes so a header value cannot swallow the closing quote.
    {
      pattern:
        /((?:set-)?cookie\s*:\s*)[^\r\n"']+|((?:session|sessid|sid|auth_?session)\s*=\s*)[^\s;&"']+/gi,
      keepPrefix: true,
    },
    { pattern: /-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----/gi },
  ],
  piiPatterns: [
    { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
    // Option C — structured IDs before loose phone/card digit runs
    { pattern: /\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][a-z]+|[A-Z]{1,3}\d?[A-Za-z]?)\s+(?:[A-Z][a-z]+\s+){0,3}(?:Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Close|Crescent|Cres\.?|Grove|Hill|Row)\b/gi },
    { pattern: /\b(?:GIR\s?0AA|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})\b/gi, validator: "uk_postcode_plausible" as const },
    { pattern: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi },
    { pattern: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/gi, validator: "iban_mod97" as const },
    { pattern: /\b(?:\d[ -]*?){13,19}\b/g, validator: "luhn" as const },
    { pattern: /(?:\+\d{1,3}[\s.-]?)?\(\d{2,5}\)[\s.-]?(?:\d[\s.()-]?){5,12}\d|(?:\+\d{1,3}[\s.-]?)?(?:\d[\s.()-]?){8,14}\d/g, validator: "phone_plausible" as const },
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

/**
 * Argv keys, which get `commandMaxChars` instead of `stringLeafMaxChars`.
 * Mirrors `COMMAND_LIKE_KEYS` in sentrook/sanitize/signal_excerpt.py. A packed
 * excerpt is not valid shell, so argv must survive whole for the scanner to
 * derive exec_shape from it; prose keeps the smaller budget because that is
 * where secret/PII density is highest and nothing downstream parses it.
 */
const COMMAND_LIKE_KEYS = new Set(["command", "cmd"]);

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

export function isCommandLikeKey(key: string | null | undefined): boolean {
  if (!key) return false;
  return COMMAND_LIKE_KEYS.has(key.toLowerCase());
}

/** Truncation budget for one leaf, by key class. Mirrors SanitizeRules.leaf_max_chars. */
export function leafMaxChars(rules: SanitizeRules, key: string | null | undefined): number {
  return isCommandLikeKey(key) ? rules.commandMaxChars : rules.stringLeafMaxChars;
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

/**
 * Mints value-stable redaction placeholders for one session (D15).
 * Mirror of `SecretMarker` in sentrook/sanitize/core.py — keep in lockstep.
 *
 * Without a marker every secret collapses to the same `[REDACTED]`, so a value
 * read in one step is indistinguishable from any other in the next. A marker
 * makes the *same value* recognisable across steps without disclosing it:
 * `[REDACTED]` becomes `[REDACTED:a3f19c]`.
 *
 * The salt is random per session and never transmitted, so the digest is not
 * invertible even for a low-entropy secret; a fresh salt per session means no
 * cross-session correlation; and the plaintext is discarded immediately after
 * hashing rather than retained in a lookup map. The digest lives inside the
 * existing brackets so a marked command parses exactly as an unmarked one.
 */
export class SecretMarker {
  // Explicit fields: node --experimental-strip-types rejects parameter properties.
  readonly #salt: Buffer;
  readonly #scope: string;

  constructor(salt: Buffer, scope: string = "") {
    this.#salt = salt;
    this.#scope = scope;
  }

  static forSession(sessionId?: string | null, salt?: Buffer): SecretMarker {
    return new SecretMarker(salt ?? randomBytes(32), sessionId ?? "");
  }

  digest(value: string): string {
    return createHmac("sha256", this.#salt)
      .update(`${this.#scope}\u0000${normalizeSecret(value)}`, "utf8")
      .digest("hex")
      .slice(0, MARKER_HEX_CHARS);
  }

  mint(placeholder: string, value: string): string {
    const d = this.digest(value);
    return placeholder.endsWith("]")
      ? `${placeholder.slice(0, -1)}:${d}]`
      : `${placeholder}:${d}`;
  }
}

export const MARKER_HEX_CHARS = 6;

/**
 * Process-lifetime salt for session markers. Random at import, never persisted
 * and never transmitted — so markers are meaningless to anyone but this
 * gateway, and rotate on restart. Mixing the session id into the HMAC scope
 * gives per-session semantics without holding any per-session state.
 */
const PROCESS_MARKER_SALT = randomBytes(32);

/**
 * Whether to mint value-stable markers. **Opt-in, default off.**
 *
 * A marker publishes one extra bit about the session: that two redacted
 * positions held the same value. That is strictly more than a bare
 * `[REDACTED]` discloses, so it is a deliberate choice rather than a default —
 * and it changes the sanitized wire format, which the shared parity fixtures
 * correctly refuse to accept silently.
 *
 * Set `SENTROOK_SECRET_MARKERS=1` on hosts collecting Phase 4 research traffic.
 */
export function secretMarkersEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return /^(1|true|yes|on)$/i.test(env.SENTROOK_SECRET_MARKERS ?? "");
}

/** Marker for one session, or undefined when markers are off. */
export function markerForSession(
  sessionId?: string | null,
  env: NodeJS.ProcessEnv = process.env,
): SecretMarker | undefined {
  if (!secretMarkersEnabled(env)) return undefined;
  return new SecretMarker(PROCESS_MARKER_SALT, sessionId ?? "");
}

/** Quoting and trailing punctuation that different patterns capture inconsistently. */
const SECRET_EDGE = /^[\s"'`]+|[\s"'`,;:)\]}]+$/g;

/** Canonical form of a secret for marker digesting. Mirror of `normalize_secret`. */
export function normalizeSecret(value: string): string {
  SECRET_EDGE.lastIndex = 0;
  return value.trim().replace(SECRET_EDGE, "");
}

/** True when `value` is already a redaction placeholder, marked or not. */
export function isPlaceholder(value: string, placeholder: string): boolean {
  // Trimmed, not normalizeSecret — that strips a trailing `]`, part of the
  // placeholder itself.
  const v = value.trim();
  if (v === placeholder) return true;
  if (!placeholder.endsWith("]")) return false;
  const base = `${placeholder.slice(0, -1)}:`;
  if (!v.startsWith(base) || !v.endsWith("]")) return false;
  const digest = v.slice(base.length, -1);
  return digest.length > 0 && /^[A-Za-z0-9]+$/.test(digest);
}

/**
 * Placeholder for one redacted value — marked when a marker is supplied.
 *
 * **Already-redacted values pass through verbatim.** Only the plugin holds a
 * session salt, so only the plugin mints markers; the scan server re-sanitizes
 * on ingress and must not disturb them. Without this guard that re-scrub rewrote
 * `[REDACTED:48df5d]` back to a bare `[REDACTED]` — markers never reached the
 * scanner and Phase 4 saw nothing — and a *different* marker would re-mint a
 * wrong digest and invent false linkages.
 */
function mint(placeholder: string, value: string, marker?: SecretMarker): string {
  if (isPlaceholder(value, placeholder)) return value.trim();
  return marker ? marker.mint(placeholder, value) : placeholder;
}

const LEADING_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** [start, end, token] of the command-name token, skipping env assignments. */
function headSpan(text: string): [number, number, string] | null {
  const re = /\S+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (LEADING_ASSIGNMENT.test(m[0])) continue;
    return [m.index, m.index + m[0].length, m[0]];
  }
  return null;
}

/**
 * Undo any scrubbing that altered the command name (D14).
 *
 * A binary name is not a secret, so a pattern matching there is a false positive
 * by definition — and it is the one position where the placeholder destroys the
 * parse, and therefore `exec_shape.heads`, which every rule downstream keys on.
 * Splices by character span so surrounding whitespace is untouched.
 */
export function restoreHeadToken(
  original: string,
  scrubbed: string,
  isSecret?: (token: string) => boolean,
): string {
  const src = headSpan(original);
  const dst = headSpan(scrubbed);
  if (!src || !dst || src[2] === dst[2]) return scrubbed;
  // CRITICAL: never restore a head that is itself a secret. Without this the
  // guard silently undoes a correct redaction — `ghp_AbC…` alone as a command is
  // redacted to `ghp_[REDACTED]`, the heads differ, and restoring puts the
  // credential straight back. Safe only when scrubbing the head *on its own*
  // leaves it unchanged, meaning its redaction was collateral from a longer
  // match (e.g. gitleaks' `curl-auth-header`, whose span starts at `curl`).
  if (isSecret && isSecret(src[2])) return scrubbed;
  return scrubbed.slice(0, dst[0]) + src[2] + scrubbed.slice(dst[1]);
}

function redactEnvSecretAssignments(
  text: string,
  placeholder: string,
  marker?: SecretMarker,
): string {
  return text.replace(ENV_ASSIGNMENT, (match, exportPrefix: string, name: string) => {
    if (!isCredentialVarName(name)) return match;
    if (!exportPrefix && !isShellStyleAssignmentName(name)) return match;
    const value = match.slice(match.indexOf("=") + 1);
    return `${exportPrefix}${name}=${mint(placeholder, value, marker)}`;
  });
}

function redactCliSecretFlags(
  text: string,
  placeholder: string,
  marker?: SecretMarker,
): string {
  return text.replace(CLI_SECRET_FLAG, (match, flag: string, sep: string) => {
    const value = match.slice(flag.length + sep.length);
    return `${flag}${sep}${mint(placeholder, value, marker)}`;
  });
}

/**
 * Structured tokens that are never PII and must survive scrubbing intact:
 * ISO-8601 timestamps and UUIDs. Both are digit-and-dash shaped, so loose PII
 * patterns match them — observed redacting every `date` and `created_at` field
 * in real result excerpts, which destroys the data for research and makes
 * markers collide on timestamps. Mirror of `_STRUCTURED_TOKEN` in core.py.
 */
const STRUCTURED_TOKEN =
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b/gi;

/** Private-use sentinel; will not occur in argv or JSON text. */
const HOLD = "\ue000";

function applyPatterns(
  text: string,
  patterns: Array<{ pattern: RegExp; validator?: PiiValidator }>,
  replacement: string,
  marker?: SecretMarker,
): string {
  const held: string[] = [];
  const hold = (match: string) => {
    held.push(match);
    return `${HOLD}${held.length - 1}${HOLD}`;
  };
  // Hold out placeholders we already produced. A marker digest is 6 hex chars
  // and ~2.7% of them match `uk_postcode` (`[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}`
  // under IGNORECASE matches strings like `fb89ad`), which re-redacted the
  // digest *inside* its own placeholder and produced the nested
  // `[REDACTED:[REDACTED:…]]` seen in live logs — intermittently, because it
  // depends on the digest.
  const base = replacement.endsWith("]") ? replacement.slice(0, -1) : replacement;
  const placeholderRe = new RegExp(
    `${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?::[0-9a-zA-Z]+)?${replacement.endsWith("]") ? "\\]" : ""}`,
    "g",
  );
  STRUCTURED_TOKEN.lastIndex = 0;
  // Strip any pre-existing sentinel so the restore cannot be spoofed by input.
  let out = text.split(HOLD).join("").replace(placeholderRe, hold).replace(STRUCTURED_TOKEN, hold);
  for (const { pattern, validator } of patterns) {
    pattern.lastIndex = 0;
    const check = validator ? PII_VALIDATORS[validator] : undefined;
    out = out.replace(pattern, (match: string) =>
      // A candidate that fails its checksum is not PII — leave it alone.
      check && !check(match) ? match : mint(replacement, match, marker),
    );
  }
  return out.replace(
    new RegExp(`${HOLD}(\\d+)${HOLD}`, "g"),
    (_m, i: string) => held[Number(i)],
  );
}

function applySecretValuePatterns(
  text: string,
  patterns: SecretValuePattern[],
  redacted: string,
  marker?: SecretMarker,
): string {
  let out = text;
  for (const { pattern, keepPrefix } of patterns) {
    pattern.lastIndex = 0;
    out = out.replace(pattern, (match: string, ...args: unknown[]) => {
      // The marker always digests the WHOLE match, never the suffix after the
      // kept prefix — otherwise `ghp_abc…` caught here (prefix kept) and the
      // same value caught by `TOKEN=ghp_abc…` (prefix not kept) would mint
      // different markers and the dataflow link would silently fail.
      if (!keepPrefix) {
        return mint(redacted, match, marker);
      }
      for (const arg of args) {
        if (typeof arg === "number") break;
        if (typeof arg === "string" && arg.length > 0) {
          // Idempotence: if what follows the kept prefix is already a
          // placeholder, leave the match alone. Digesting the *whole* match
          // (needed so one secret marks identically however it was captured)
          // would otherwise re-mint on every pass.
          if (isPlaceholder(match.slice(arg.length), redacted)) return match;
          return `${arg}${mint(redacted, match, marker)}`;
        }
      }
      return mint(redacted, match, marker);
    });
  }
  return out;
}

/**
 * Bits per character — gitleaks' own measure of "is this random enough".
 * A provider prefix makes a pattern specific; entropy is what lets a *generic*
 * pattern tell an actual credential from an ordinary identifier of the same
 * shape. Mirror of `shannon_entropy` in sanitize/gitleaks.py.
 */
export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let total = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    total -= p * Math.log2(p);
  }
  return total;
}

/**
 * Never treated as credentials by the catalogue: UUIDs and ISO-8601 timestamps
 * are identifiers, not secrets. `generic-api-key` matches `auth` as a substring
 * (so `author_id` fires) and would otherwise redact every UUID in a JSON result
 * — destroying the document and minting one shared marker across every event
 * with the same id, the cross-step "same value" signal Phase 4 reads as dataflow.
 * Mirror of `_NOT_A_SECRET` in sanitize/gitleaks.py.
 */
const NOT_A_SECRET =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$/i;

let compiledGitleaks: Array<{ rule: GitleaksRule; pattern: RegExp }> | null = null;

function gitleaksPatterns(): Array<{ rule: GitleaksRule; pattern: RegExp }> {
  if (compiledGitleaks) return compiledGitleaks;
  compiledGitleaks = GITLEAKS_RULES.map((rule) => ({
    rule,
    pattern: new RegExp(rule.regex, rule.ignorecase ? "gi" : "g"),
  }));
  return compiledGitleaks;
}

/**
 * Vendored gitleaks catalogue. Sentrook does not maintain its own secret-pattern
 * catalogue — see sanitize/gitleaks.py. Generated from one pinned TOML into both
 * languages so they cannot drift.
 */
function applyGitleaksPatterns(
  text: string,
  placeholder: string,
  marker?: SecretMarker,
): string {
  let out = text;
  for (const { rule, pattern } of gitleaksPatterns()) {
    pattern.lastIndex = 0;
    if (!pattern.test(out)) continue;
    pattern.lastIndex = 0;
    out = out.replace(pattern, (match: string, ...args: unknown[]) => {
      // Prefer the rule's capture group. Several catalogue rules deliberately
      // match surrounding context — `generic-api-key` spans the key name *and*
      // the closing quote — so replacing the whole match ate JSON structure
      // (`"author_id": "…"` became `"[REDACTED]`, unbalanced). Redacting only
      // the captured credential leaves the document intact.
      const groupIndex = rule.secretGroup ?? 1;
      const candidate = args[groupIndex - 1];
      const secret = typeof candidate === "string" && candidate.length > 0 ? candidate : match;
      // UUIDs and ISO timestamps are identifiers, not credentials.
      if (NOT_A_SECRET.test(secret.trim().replace(/^["']|["']$/g, ""))) return match;
      // Below the rule's own entropy floor this is not a credential — leave it.
      if (rule.entropy !== null && shannonEntropy(secret) < rule.entropy) return match;
      const minted = mint(placeholder, secret, marker);
      return secret === match ? minted : match.split(secret).join(minted);
    });
  }
  return out;
}

function applySecretPatterns(
  text: string,
  rules: SanitizeRules,
  marker?: SecretMarker,
): string {
  let cleaned = redactEnvSecretAssignments(text, rules.redacted, marker);
  cleaned = redactCliSecretFlags(cleaned, rules.redacted, marker);
  cleaned = applySecretValuePatterns(cleaned, rules.secretValuePatterns, rules.redacted, marker);
  // Catalogue runs LAST: Sentrook's own patterns keep provider prefixes
  // (`sk-ant-[REDACTED]`) that L2 rules match on, and gitleaks would replace the
  // whole match. Placeholders are inert, so it never re-redacts.
  return applyGitleaksPatterns(cleaned, rules.redacted, marker);
}

/** Secret-pattern scrub for operator-facing copy (no PII, no length placeholder). */
export function scrubSecrets(
  text: string,
  rules: SanitizeRules = DEFAULT_RULES,
  marker?: SecretMarker,
): string {
  return applySecretPatterns(text, rules, marker);
}

/** Secret + PII scrub with no length cap (local operator log). */
export function scrubSecretsAndPii(
  text: string,
  rules: SanitizeRules = DEFAULT_RULES,
  marker?: SecretMarker,
): string {
  let cleaned = applySecretPatterns(text, rules, marker);
  cleaned = applyPatterns(cleaned, rules.piiPatterns, rules.redacted, marker);
  return cleaned;
}

const OPERATOR_SCRUB_MAX_DEPTH = 16;

/** Redact credential fields and secret/PII patterns; never truncate. */
export function scrubOperatorValue(
  value: unknown,
  rules: SanitizeRules = DEFAULT_RULES,
  options: {
    parentKey?: string | null;
    pii?: boolean;
    depth?: number;
    marker?: SecretMarker;
  } = {},
): unknown {
  const depth = options.depth ?? 0;
  const parentKey = options.parentKey ?? null;
  const pii = options.pii ?? false;
  if (depth > OPERATOR_SCRUB_MAX_DEPTH) return "[…]";
  if (parentKey && isCredentialField(parentKey, rules)) return rules.redacted;
  if (typeof value === "string") {
    return scrubSecretsAndPii(value, rules, options.marker);
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const nestedPii = pii || (parentKey != null && parentKey.toLowerCase() === "env");
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      out[key] = scrubOperatorValue(child, rules, {
        parentKey: key,
        pii: nestedPii,
        depth: depth + 1,
        marker: options.marker,
      });
    }
    return out;
  }
  if (Array.isArray(value)) {
    return value.map((item) =>
      scrubOperatorValue(item, rules, { pii, depth: depth + 1, marker: options.marker }),
    );
  }
  return value;
}

function scrubString(
  text: string,
  rules: SanitizeRules,
  options: { pii: boolean; maxChars: number; key?: string | null; marker?: SecretMarker },
): string {
  let cleaned = applySecretPatterns(text, rules, options.marker);
  if (options.pii) {
    cleaned = applyPatterns(cleaned, rules.piiPatterns, rules.redacted, options.marker);
  }
  if (isCommandLikeKey(options.key)) {
    // D14: a binary name is never a secret, and it is the one position where the
    // placeholder destroys the parse and therefore exec_shape.heads.
    cleaned = restoreHeadToken(
      text,
      cleaned,
      (token) => applySecretPatterns(token, rules) !== token,
    );
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
    marker?: SecretMarker;
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
      marker: options.marker,
    });
  }
  if (Array.isArray(value)) {
    return value.map((item) =>
      sanitizeValue(item, rules, {
        parentKey: null,
        pii: false,
        maxChars: options.maxChars,
        piiKeys: options.piiKeys,
        marker: options.marker,
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
      marker: options.marker,
    });
  }
  return value;
}

function sanitizeMapping(
  mapping: Record<string, unknown>,
  rules: SanitizeRules,
  options: {
    pii: boolean;
    maxChars: number;
    piiKeys?: ReadonlySet<string>;
    marker?: SecretMarker;
  },
): Record<string, unknown> {
  const piiKeys = options.piiKeys ?? new Set<string>();
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(mapping)) {
    // Argv keys carry the larger command budget; prose keys keep options.maxChars.
    const keyMax = isCommandLikeKey(key)
      ? Math.max(options.maxChars, rules.commandMaxChars)
      : options.maxChars;
    out[key] = sanitizeValue(value, rules, {
      parentKey: key,
      pii: options.pii || piiKeys.has(key),
      maxChars: keyMax,
      piiKeys,
      marker: options.marker,
    });
  }
  return out;
}

function sanitizeResultSummary(
  summary: Record<string, unknown>,
  rules: SanitizeRules,
  marker?: SecretMarker,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...summary };
  if (typeof summary.excerpt === "string") {
    const scrubbed = scrubString(summary.excerpt, rules, {
      pii: false,
      maxChars: rules.resultTextMaxChars,
      key: "excerpt",
      marker,
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
              maxChars: rules.commandMaxChars,
              key: "command",
              marker,
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
  marker?: SecretMarker,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...step };
  if (step.args && typeof step.args === "object" && !Array.isArray(step.args)) {
    out.args = sanitizeMapping(step.args as Record<string, unknown>, rules, {
      pii: false,
      maxChars: rules.stringLeafMaxChars,
      piiKeys: rules.piiArgKeys,
      marker,
    });
  }
  if (
    step.result_summary &&
    typeof step.result_summary === "object" &&
    !Array.isArray(step.result_summary)
  ) {
    // Phase 4 needs markers on BOTH ends — the executed step's result and the
    // pending step's argv — or the flow is invisible.
    out.result_summary = sanitizeResultSummary(
      step.result_summary as Record<string, unknown>,
      rules,
      marker,
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

function hashMetadataId(
  data: Record<string, unknown>,
  metadata: Record<string, unknown>,
  field: string,
  rules: SanitizeRules,
  rewriteRunIdField: boolean,
): void {
  const original = metadata[field];
  if (typeof original !== "string" || !original) return;
  const hashed = hashSessionId(original, rules);
  metadata[field] = hashed;
  if (rewriteRunIdField && typeof data.run_id === "string") {
    data.run_id = rewriteRunId(data.run_id, original, hashed);
  }
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
  const hasSessionId = typeof originalSessionId === "string" && Boolean(originalSessionId);
  hashMetadataId(data, metadata, "session_id", rules, true);
  // ``run_id`` is ``{episode||key}:{run}``. Hash ``session_key`` always; only
  // rewrite ``run_id`` from it when there is no episode id.
  hashMetadataId(data, metadata, "session_key", rules, !hasSessionId);

  // Minted from the ORIGINAL session id, before it is hashed, so the scope is
  // stable across every step of one session — which is what makes step-to-step
  // dataflow linkage work.
  const marker = markerForSession(hasSessionId ? (originalSessionId as string) : null);

  if (typeof data.intent === "string") {
    data.intent = scrubString(data.intent, rules, {
      pii: true,
      maxChars: rules.intentMaxChars,
      marker,
    });
  }

  if (Array.isArray(data.steps)) {
    data.steps = data.steps
      .filter((item): item is Record<string, unknown> => !!item && typeof item === "object")
      .map((item) => sanitizeStep(item, rules, marker));
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
