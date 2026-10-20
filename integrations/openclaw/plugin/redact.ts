/**
 * Host-side redaction, applied to everything that leaves the host (the PlanIR sent to Sentrook and
 * the local traffic log).
 *
 * `standard` replaces secrets with `⟦secret:<kind>:<ref>⟧`. The ref is a keyed hash of the value, so
 * the same secret gets the same placeholder across steps of a session without the value ever being
 * stored. Recipients, hosts and email addresses stay: the scanner needs them to judge whether a call
 * matches the request. Content is capped head and tail, since a payload placed after a cut-off is
 * the obvious evasion.
 *
 * Every pattern does bounded work per position (no nested quantifiers; quoted values use the
 * unrolled `[^"\\]*(?:\\.[^"\\]*)*` form).
 */

import { createHmac } from "node:crypto";

export type RedactionLevel = "off" | "standard" | "strict";

export interface Redactor {
  level: RedactionLevel;
  string(text: string): string;
  value<T>(value: T): T;
}

interface Shape {
  kind: string;
  re: RegExp;
  /** Replace only this named group; the rest of the match (a key, a scheme) stays. */
  group?: string;
}

const KEY_NAMES =
  "api[_-]?key|apikey|secret|token|access[_-]?key|private[_-]?key|passw(?:or)?d|passwd|client[_-]?secret|auth[_-]?token";

const SHAPES: Shape[] = [
  { kind: "private_key", re: /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[A-Za-z0-9+/=\r\n \t]{0,8000}(?:-----END [A-Z ]{0,40}PRIVATE KEY-----)?/g },
  { kind: "jwt", re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { kind: "openai", re: /sk-(?:proj|svcacct|admin|live)-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g },
  { kind: "anthropic", re: /sk-ant-[A-Za-z0-9_-]{10,}/g },
  { kind: "github", re: /gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}/g },
  { kind: "gitlab", re: /glpat-[A-Za-z0-9_-]{20,}/g },
  { kind: "slack", re: /xox[baprs]-[A-Za-z0-9-]{10,}|xoxe(?:\.xox[bp])?-\d-[A-Za-z0-9]+|xapp-\d-[A-Za-z0-9-]+/gi },
  { kind: "slack_webhook", re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/_-]+/g },
  { kind: "discord_webhook", re: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
  { kind: "telegram", re: /\b\d{5,16}:A[A-Za-z0-9_-]{34}\b/g },
  { kind: "npm", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { kind: "aws_access_key", re: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { kind: "google_api_key", re: /AIza[0-9A-Za-z_-]{35}/g },
  { kind: "stripe", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g },
  { kind: "huggingface", re: /\bhf_[A-Za-z0-9]{20,}/g },
  { kind: "groq", re: /\bgsk_[A-Za-z0-9]{20,}/g },
  {
    kind: "bearer",
    re: /(?:authorization["']?[ \t]*[:=][ \t]*["']?)?bearer[ \t]+(?<v>[^\s"'⟦][^\s"']{19,})/gi,
    group: "v",
  },
  {
    // `--password x`, `--api-key=x`, `--token "x"`
    kind: "credential",
    re: /--(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth(?:entication)?(?:-?token)?|credential)(?:-\w+)?(?:\s*=\s*|\s+)(?<v>"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^\s;|&⟦-][^\s;|&]*)/gi,
    group: "v",
  },
  {
    // `GITHUB_TOKEN=x`, `"api_key": "x"`, `?token=x` (`_` is not alphanumeric, so the key's own
    // prefix passes the lookbehind). A key right after `/` (a URL segment) or `⟦` (a placeholder
    // label) does not count; values that are variable references or masks stay.
    kind: "credential",
    re: new RegExp(
      `(?<![A-Za-z0-9/⟦])(?:${KEY_NAMES})(?![A-Za-z0-9])["']?\\s*[=:]\\s*["']?` +
        `(?!\\d{1,5}(?![0-9A-Za-z]))(?<v>[^\\s"'⟦$*{<%&,;\`][^\\s"'&,;<>\`]{7,})`,
      "gi",
    ),
    group: "v",
  },
];

/** Object keys whose whole value is a credential. Bounded `pass` so `compass` and `passage` stay. */
const CREDENTIAL_FIELD =
  /^(?:.*[_-])?(?:token|password|passwd|pass|secret|api[_-]?key|apikey|auth[_-]?token|credentials?|bearer|private[_-]?key|client[_-]?secret)$/i;

function spansOf(text: string): Array<[number, number, string]> {
  const spans: Array<[number, number, string]> = [];
  for (const shape of SHAPES) {
    const re = shape.group ? new RegExp(shape.re.source, `${shape.re.flags.replace("d", "")}d`) : shape.re;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }
      if (shape.group) {
        const idx = m.indices?.groups?.[shape.group];
        if (idx) spans.push([idx[0], idx[1], shape.kind]);
      } else {
        spans.push([m.index, m.index + m[0].length, shape.kind]);
      }
    }
  }
  spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged: Array<[number, number, string]> = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && s[0] < last[1]) {
      last[1] = Math.max(last[1], s[1]);
      continue;
    }
    merged.push([...s]);
  }
  return merged;
}

export function createRedactor(level: RedactionLevel, salt: string): Redactor {
  const ref = (value: string) => createHmac("sha256", salt).update(value).digest("hex").slice(0, 4);
  const placeholder = (kind: string, value: string) => `⟦secret:${kind}:${ref(value)}⟧`;

  const redactString = (text: string): string => {
    if (level === "off" || !text) return text;
    const spans = spansOf(text);
    if (!spans.length) return text;
    let out = "";
    let pos = 0;
    for (const [start, end, kind] of spans) {
      out += text.slice(pos, start) + placeholder(kind, text.slice(start, end));
      pos = end;
    }
    return out + text.slice(pos);
  };

  const walk = (value: unknown, depth: number): unknown => {
    if (typeof value === "string") return redactString(value);
    if (!value || typeof value !== "object" || depth > 32) return value;
    if (Array.isArray(value)) return value.map((v) => walk(v, depth + 1));
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (level !== "off" && CREDENTIAL_FIELD.test(k) && typeof v === "string" && v && !v.startsWith("⟦")) {
        out[k] = placeholder("credential", v);
      } else {
        out[k] = walk(v, depth + 1);
      }
    }
    return out;
  };

  return {
    level,
    string: redactString,
    value: <T>(value: T): T => walk(value, 0) as T,
  };
}

export interface Capped {
  text: string;
  truncated: boolean;
  sizeBytes: number;
}

/** Cap text at `capBytes` (UTF-8), keeping two thirds head and one third tail. */
export function capHeadTail(text: string, capBytes: number): Capped {
  const sizeBytes = Buffer.byteLength(text, "utf8");
  if (sizeBytes <= capBytes) return { text, truncated: false, sizeBytes };
  const marker = `\n…[sentrook: ${sizeBytes - capBytes} bytes cut]…\n`;
  const budget = Math.max(0, capBytes - Buffer.byteLength(marker, "utf8"));
  const buf = Buffer.from(text, "utf8");
  const headBytes = Math.floor((budget * 2) / 3);
  const tailBytes = budget - headBytes;
  // toString on a cut multi-byte sequence yields U+FFFD; trim it rather than send a broken char.
  const head = buf.subarray(0, headBytes).toString("utf8").replace(/\uFFFD$/, "");
  const tail = buf.subarray(buf.length - tailBytes).toString("utf8").replace(/^\uFFFD/, "");
  return { text: head + marker + tail, truncated: true, sizeBytes };
}

/**
 * Cap an arguments object at about `capBytes` of JSON while keeping it an object: long string leaves
 * are cut head and tail to a share of the budget. Anything still over (very wide objects) collapses
 * to `{ _truncated: "<capped JSON>" }`.
 */
export function capArgs(value: unknown, capBytes: number): Record<string, unknown> {
  const obj = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : { value };
  const json = JSON.stringify(obj);
  if (Buffer.byteLength(json, "utf8") <= capBytes) return obj;
  let leaves = 0;
  const count = (v: unknown, d: number): void => {
    if (typeof v === "string") leaves += 1;
    else if (v && typeof v === "object" && d < 32) Object.values(v as object).forEach((x) => count(x, d + 1));
  };
  count(obj, 0);
  const leafCap = Math.max(200, Math.floor(capBytes / Math.max(1, leaves)));
  const cut = (v: unknown, d: number): unknown => {
    if (typeof v === "string") return capHeadTail(v, leafCap).text;
    if (Array.isArray(v)) return d < 32 ? v.map((x) => cut(x, d + 1)) : v;
    if (v && typeof v === "object" && d < 32) {
      return Object.fromEntries(Object.entries(v as object).map(([k, x]) => [k, cut(x, d + 1)]));
    }
    return v;
  };
  const shrunk = cut(obj, 0) as Record<string, unknown>;
  const shrunkJson = JSON.stringify(shrunk);
  if (Buffer.byteLength(shrunkJson, "utf8") <= capBytes * 1.25) return shrunk;
  return { _truncated: capHeadTail(shrunkJson, capBytes).text };
}
