/**
 * Plugin-local allowlist for Sentrook enforce-mode "allow-always" short-circuit.
 *
 * Two entry kinds (orthogonal):
 * - skeleton: constrained command/arg shape for general tools
 * - script_bind: interpreter + concrete local script file (path + content SHA-256)
 *   with narrow-volatile trailing args (dates / UUIDs / ints only)
 *
 * Never overrides Sentrook `block`. Never skips /scan. Never stores bare interpreters.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve as pathResolve } from "node:path";
import { homedir } from "node:os";

import type { ShadowSnapshot } from "./index.ts";

export type AllowlistEntryKind = "skeleton" | "script_bind";

export interface AllowlistConfig {
  enabled: boolean;
  path: string;
  scriptBind: boolean;
}

export interface SkeletonEntry {
  kind: "skeleton";
  tool: string;
  matched_rule_ids: string[];
  skeleton: string;
  created_at: string;
  source: "allow-always";
}

export interface ScriptBindEntry {
  kind: "script_bind";
  tool: string;
  interpreter: string;
  script_path: string;
  content_sha256: string;
  args_skeleton: string;
  matched_rule_ids: string[];
  created_at: string;
  source: "allow-always";
}

export type AllowlistEntry = SkeletonEntry | ScriptBindEntry;

export interface AllowlistFile {
  version: 1;
  entries: AllowlistEntry[];
}

export interface BindableScript {
  interpreter: string;
  scriptPath: string;
  trailingArgs: string[];
}

export interface RecordResult {
  status: "recorded" | "duplicate" | "skipped";
  kind?: AllowlistEntryKind;
  reason?: string;
}

export interface MatchResult {
  hit: boolean;
  kind?: AllowlistEntryKind;
  reason?: string;
  /** Overlap between entry rule ids and the current scan log (audit logging). */
  matchedRuleIds?: string[];
  /** Human-readable entry fingerprint for audit logging. */
  entryDetail?: string;
}

export type FileReader = (absPath: string) => Buffer | null;

const INTERPRETER_RE =
  /^(python3(?:\.\d+)?|python|node|nodejs|bash|sh|zsh)$/i;

const SCRIPT_EXT_RE = /\.(py|sh|bash|zsh|js|mjs|cjs)$/i;

const INLINE_EVAL_FLAGS = new Set([
  "-c",
  "-e",
  "-p",
  "-r",
  "-E",
  "--eval",
  "--print",
]);

const HIGH_RISK_SHELL_RE = /(?:\|\||&&|;|`|\$\(|<\(|>\(|\|)/;

const URL_RE = /^https?:\/\/|^[a-z0-9.-]+:\d+$/i;
const EMAIL_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISO_DATE_RE =
  /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;
const INT_RE = /^-?\d+$/;
const LONG_HEX_RE = /^[0-9a-f]{16,}$/i;

const BARE_DANGEROUS_BINS = new Set([
  "curl",
  "wget",
  "bash",
  "sh",
  "zsh",
  "python",
  "python3",
  "node",
  "nodejs",
  "perl",
  "ruby",
  "php",
  "lua",
  "osascript",
]);

export function resolveAllowlistConfig(
  pluginCfg: Record<string, unknown> | undefined,
  env: NodeJS.ProcessEnv = process.env,
): AllowlistConfig {
  const raw =
    pluginCfg?.allowlist && typeof pluginCfg.allowlist === "object"
      ? (pluginCfg.allowlist as Record<string, unknown>)
      : {};

  const enabled = parseBool(
    raw.enabled ?? env.SENTROOK_ALLOWLIST_ENABLED,
    true,
  );
  const scriptBind = parseBool(
    raw.scriptBind ?? env.SENTROOK_ALLOWLIST_SCRIPT_BIND,
    true,
  );

  let path: string;
  if (typeof raw.path === "string" && raw.path.trim()) {
    path = pathResolve(expandHome(raw.path.trim()));
  } else if (env.SENTROOK_ALLOWLIST_PATH?.trim()) {
    path = pathResolve(expandHome(env.SENTROOK_ALLOWLIST_PATH.trim()));
  } else {
    const stateDir = env.OPENCLAW_STATE_DIR?.trim();
    const root = stateDir
      ? pathResolve(expandHome(stateDir))
      : pathResolve(homedir(), ".openclaw");
    path = pathResolve(root, "sentrook-allowlist.json");
  }

  return { enabled, path, scriptBind };
}

function parseBool(raw: unknown, fallback: boolean): boolean {
  if (typeof raw === "boolean") return raw;
  if (typeof raw === "string") {
    const n = raw.trim().toLowerCase();
    if (n === "1" || n === "true" || n === "yes") return true;
    if (n === "0" || n === "false" || n === "no") return false;
  }
  return fallback;
}

function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return pathResolve(homedir(), p.slice(2));
  return p;
}

export function resolveScriptPath(scriptPath: string, cwd: string = process.cwd()): string {
  const expanded = expandHome(scriptPath);
  return isAbsolute(expanded) ? pathResolve(expanded) : pathResolve(cwd, expanded);
}

export function extractMatchedRuleIds(log: Record<string, unknown> | undefined): string[] {
  if (!log) return [];
  const matched = log.matched_rules;
  if (!Array.isArray(matched)) return [];
  const ids: string[] = [];
  for (const item of matched) {
    if (typeof item === "string" && item.trim()) {
      ids.push(item.trim());
    } else if (item && typeof item === "object") {
      const id = (item as Record<string, unknown>).id;
      if (typeof id === "string" && id.trim()) ids.push(id.trim());
    }
  }
  return [...new Set(ids)].sort();
}

function ruleOverlap(a: string[], b: string[]): boolean {
  if (a.length === 0 || b.length === 0) return false;
  const set = new Set(a);
  return b.some((id) => set.has(id));
}

/** Simple argv tokenizer: whitespace split with "..." and '...' support. */
export function tokenizeArgv(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

function basenameOf(token: string): string {
  const parts = token.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || token;
}

function normalizeInterpreter(token: string): string | null {
  const base = basenameOf(token);
  if (!INTERPRETER_RE.test(base)) return null;
  const lower = base.toLowerCase();
  if (lower.startsWith("python")) return "python";
  if (lower === "nodejs" || lower === "node") return "node";
  if (lower === "bash" || lower === "zsh") return lower;
  if (lower === "sh") return "sh";
  return lower;
}

function looksLikeScriptPath(token: string): boolean {
  if (!token || token.startsWith("-")) return false;
  if (URL_RE.test(token)) return false;
  return SCRIPT_EXT_RE.test(token) || token.startsWith("./") || token.startsWith("../");
}

export function isHighRiskCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed) return true;
  if (HIGH_RISK_SHELL_RE.test(trimmed)) return true;

  const tokens = tokenizeArgv(trimmed);
  if (tokens.length === 0) return true;

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const base = basenameOf(t).toLowerCase();
    if (INLINE_EVAL_FLAGS.has(t) || INLINE_EVAL_FLAGS.has(base)) {
      return true;
    }
    // python -c / bash -c etc.
    if (normalizeInterpreter(t) && tokens[i + 1] && INLINE_EVAL_FLAGS.has(tokens[i + 1])) {
      return true;
    }
  }

  // curl|wget ... sh patterns without needing the pipe char already caught above;
  // also catch "bash /dev/stdin" style.
  const joined = tokens.join(" ").toLowerCase();
  if (/\b(curl|wget)\b/.test(joined) && /\b(bash|sh|zsh)\b/.test(joined)) {
    return true;
  }
  return false;
}

/**
 * Detect interpreter + single local script file forms.
 * Returns null when not bindable (inline eval, pipes, ambiguous, etc.).
 */
export function parseBindableScript(command: string): BindableScript | null {
  if (isHighRiskCommand(command)) return null;

  const tokens = tokenizeArgv(command.trim());
  if (tokens.length === 0) return null;

  // Direct script: ./foo.py or /path/foo.sh
  if (looksLikeScriptPath(tokens[0]) && SCRIPT_EXT_RE.test(tokens[0])) {
    const ext = tokens[0].toLowerCase();
    let interpreter = "sh";
    if (ext.endsWith(".py")) interpreter = "python";
    else if (ext.endsWith(".js") || ext.endsWith(".mjs") || ext.endsWith(".cjs")) {
      interpreter = "node";
    } else if (ext.endsWith(".bash")) interpreter = "bash";
    else if (ext.endsWith(".zsh")) interpreter = "zsh";
    return {
      interpreter,
      scriptPath: tokens[0],
      trailingArgs: tokens.slice(1),
    };
  }

  const interpreter = normalizeInterpreter(tokens[0]);
  if (!interpreter) return null;

  // Skip leading interpreter flags that are not inline-eval (e.g. -u, -O)
  // until we find a script path. Fail if we hit inline-eval.
  let i = 1;
  while (i < tokens.length) {
    const t = tokens[i];
    if (INLINE_EVAL_FLAGS.has(t)) return null;
    if (t.startsWith("-")) {
      // Flags that take a value (best-effort): -W, --check, etc. Keep simple —
      // only skip lone short/long flags without consuming next as script unless
      // next clearly looks like a script.
      i += 1;
      continue;
    }
    break;
  }

  if (i >= tokens.length) return null;
  const scriptPath = tokens[i];
  if (!looksLikeScriptPath(scriptPath) && !SCRIPT_EXT_RE.test(scriptPath)) {
    // Allow extensionless paths only if they contain a path separator
    // (e.g. ./bin/helper); otherwise refuse (could be a module name).
    if (!scriptPath.includes("/") && !scriptPath.includes("\\")) return null;
  }
  if (scriptPath.startsWith("-")) return null;

  return {
    interpreter,
    scriptPath,
    trailingArgs: tokens.slice(i + 1),
  };
}

function isPathLike(token: string): boolean {
  return (
    token.startsWith("/") ||
    token.startsWith("./") ||
    token.startsWith("../") ||
    token.startsWith("~/") ||
    /^[A-Za-z]:[\\/]/.test(token)
  );
}

/** Narrow volatiles for script_bind trailing args. */
export function skeletonizeScriptArgs(args: string[]): string {
  return args.map(skeletonizeScriptArgToken).join(" ");
}

function skeletonizeScriptArgToken(token: string): string {
  if (URL_RE.test(token) || EMAIL_RE.test(token) || isPathLike(token)) {
    return token;
  }
  if (token.startsWith("-")) return token;
  if (UUID_RE.test(token)) return "<uuid>";
  if (ISO_DATE_RE.test(token)) return "<date>";
  if (INT_RE.test(token)) return "<int>";
  return token;
}

/** Broader volatiles for general command skeletons. */
export function skeletonizeCommand(command: string): string | null {
  if (isHighRiskCommand(command)) return null;

  const tokens = tokenizeArgv(command.trim());
  if (tokens.length === 0) return null;

  const bin = basenameOf(tokens[0]).toLowerCase();
  // Bare dangerous binary with no further literal structure beyond volatiles
  if (BARE_DANGEROUS_BINS.has(bin) || normalizeInterpreter(tokens[0])) {
    // Interpreters / dangerous bins need remaining literal structure after skeletonize
    const rest = tokens.slice(1).map(skeletonizeGeneralToken);
    const literalRest = rest.filter(
      (t) => !t.startsWith("<") && !t.endsWith(">") && t !== "<file>",
    );
    if (literalRest.length === 0) return null;
    return [tokens[0], ...rest].join(" ");
  }

  return tokens.map(skeletonizeGeneralToken).join(" ");
}

function skeletonizeGeneralToken(token: string): string {
  if (token.startsWith("-") && !ISO_DATE_RE.test(token)) return token;
  if (URL_RE.test(token)) return token.startsWith("http") ? "<url>" : token;
  if (EMAIL_RE.test(token)) return "<email>";
  if (UUID_RE.test(token)) return "<uuid>";
  if (ISO_DATE_RE.test(token)) return "<date>";
  if (INT_RE.test(token)) return "<int>";
  if (LONG_HEX_RE.test(token)) return "<hex>";
  if (isPathLike(token)) {
    // Keep directory prefix; replace volatile-looking leaf
    const normalized = token.replace(/\\/g, "/");
    const parts = normalized.split("/");
    const leaf = parts[parts.length - 1] || "";
    if (UUID_RE.test(leaf) || ISO_DATE_RE.test(leaf) || INT_RE.test(leaf) || LONG_HEX_RE.test(leaf)) {
      parts[parts.length - 1] = "<file>";
      return parts.join("/");
    }
    return token;
  }
  return token;
}

function pendingCommand(snapshot: ShadowSnapshot): string | null {
  const args = snapshot.pending?.args;
  if (!args || typeof args !== "object") return null;
  const command = (args as Record<string, unknown>).command ?? (args as Record<string, unknown>).cmd;
  return typeof command === "string" ? command : null;
}

function pendingPrimaryText(snapshot: ShadowSnapshot): string | null {
  const tool = snapshot.pending?.tool ?? "";
  const args = (snapshot.pending?.args ?? {}) as Record<string, unknown>;
  if (tool === "exec") {
    return pendingCommand(snapshot);
  }
  // Non-exec: fingerprint tool + stable JSON of args (string leaves only, sorted keys)
  try {
    return `${tool} ${stableArgsText(args)}`;
  } catch {
    return tool || null;
  }
}

function stableArgsText(args: Record<string, unknown>): string {
  const keys = Object.keys(args).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const value = args[key];
    if (typeof value === "string") {
      parts.push(`${key}=${skeletonizeGeneralToken(value)}`);
    } else if (typeof value === "number" || typeof value === "boolean") {
      parts.push(`${key}=${String(value)}`);
    }
  }
  return parts.join(" ");
}

export function sha256Buffer(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

const defaultFileReader: FileReader = (absPath) => {
  try {
    if (!existsSync(absPath)) return null;
    return readFileSync(absPath);
  } catch {
    return null;
  }
};

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;
const ALLOWLIST_SOURCE = "allow-always";
/** Tolerate minor host clock skew when validating created_at. */
const CREATED_AT_FUTURE_SKEW_MS = 60_000;

export function loadAllowlist(
  path: string,
  opts: { nowMs?: number } = {},
): AllowlistFile {
  const nowMs = opts.nowMs ?? Date.now();
  try {
    if (!existsSync(path)) return { version: 1, entries: [] };
    const raw = JSON.parse(readFileSync(path, "utf8")) as AllowlistFile;
    if (!raw || raw.version !== 1 || !Array.isArray(raw.entries)) {
      return { version: 1, entries: [] };
    }
    return {
      version: 1,
      entries: raw.entries.filter((entry) => isValidEntry(entry, nowMs)),
    };
  } catch {
    return { version: 1, entries: [] };
  }
}

function isValidMatchedRuleIds(raw: unknown): raw is string[] {
  if (!Array.isArray(raw) || raw.length === 0) return false;
  return raw.every((id) => typeof id === "string" && id.trim().length > 0);
}

function isValidCreatedAt(iso: string, nowMs: number): boolean {
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) return false;
  return parsed <= nowMs + CREATED_AT_FUTURE_SKEW_MS;
}

function hasValidEntryMetadata(e: Record<string, unknown>, nowMs: number): boolean {
  return (
    e.source === ALLOWLIST_SOURCE &&
    typeof e.created_at === "string" &&
    isValidCreatedAt(e.created_at, nowMs) &&
    isValidMatchedRuleIds(e.matched_rule_ids)
  );
}

/** Reject hand-edited or poisoned entries missing plugin-recorded metadata. */
export function isValidEntry(
  entry: unknown,
  nowMs: number = Date.now(),
): entry is AllowlistEntry {
  if (!entry || typeof entry !== "object") return false;
  const e = entry as Record<string, unknown>;
  if (!hasValidEntryMetadata(e, nowMs)) return false;

  if (e.kind === "skeleton") {
    return (
      typeof e.tool === "string" &&
      e.tool.trim().length > 0 &&
      typeof e.skeleton === "string" &&
      e.skeleton.trim().length > 0
    );
  }
  if (e.kind === "script_bind") {
    return (
      typeof e.tool === "string" &&
      e.tool.trim().length > 0 &&
      typeof e.interpreter === "string" &&
      e.interpreter.trim().length > 0 &&
      typeof e.script_path === "string" &&
      e.script_path.trim().length > 0 &&
      typeof e.content_sha256 === "string" &&
      SHA256_HEX_RE.test(e.content_sha256) &&
      typeof e.args_skeleton === "string"
    );
  }
  return false;
}

export function saveAllowlist(path: string, file: AllowlistFile): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
}

function entryDedupeKey(entry: AllowlistEntry): string {
  if (entry.kind === "skeleton") {
    return [
      "skeleton",
      entry.tool,
      entry.skeleton,
      [...entry.matched_rule_ids].sort().join(","),
    ].join("|");
  }
  return [
    "script_bind",
    entry.interpreter,
    entry.script_path,
    entry.content_sha256,
    entry.args_skeleton,
    [...entry.matched_rule_ids].sort().join(","),
  ].join("|");
}

export function matchAllowlist(
  snapshot: ShadowSnapshot,
  log: Record<string, unknown> | undefined,
  config: AllowlistConfig,
  opts: { readFile?: FileReader; cwd?: string } = {},
): MatchResult {
  if (!config.enabled) return { hit: false, reason: "allowlist disabled" };

  const ruleIds = extractMatchedRuleIds(log);
  if (ruleIds.length === 0) return { hit: false, reason: "no matched rules" };

  const file = loadAllowlist(config.path);
  if (file.entries.length === 0) return { hit: false, reason: "empty allowlist" };

  const tool = snapshot.pending?.tool ?? "";
  const command = pendingCommand(snapshot);
  const readFile = opts.readFile ?? defaultFileReader;
  const cwd = opts.cwd ?? process.cwd();

  // Prefer script_bind when applicable
  if (config.scriptBind && tool === "exec" && command) {
    const bindable = parseBindableScript(command);
    if (bindable) {
      const abs = resolveScriptPath(bindable.scriptPath, cwd);
      const buf = readFile(abs);
      if (buf) {
        const hash = sha256Buffer(buf);
        const argsSkel = skeletonizeScriptArgs(bindable.trailingArgs);
        for (const entry of file.entries) {
          if (entry.kind !== "script_bind") continue;
          if (entry.tool !== tool) continue;
          if (entry.interpreter !== bindable.interpreter) continue;
          if (entry.script_path !== abs) continue;
          if (entry.content_sha256 !== hash) continue;
          if (entry.args_skeleton !== argsSkel) continue;
          if (!ruleOverlap(entry.matched_rule_ids, ruleIds)) continue;
          return {
            hit: true,
            kind: "script_bind",
            matchedRuleIds: ruleIds.filter((id) => entry.matched_rule_ids.includes(id)),
            entryDetail: `script=${entry.script_path} sha=${entry.content_sha256.slice(0, 12)}…`,
          };
        }
      }
    }
  }

  // Skeleton match
  const primary = pendingPrimaryText(snapshot);
  if (!primary) return { hit: false, reason: "no pending primary" };

  let skeleton: string | null;
  if (tool === "exec" && command) {
    // Bindable script forms must not match via a loose skeleton
    if (parseBindableScript(command)) {
      return { hit: false, reason: "script form requires script_bind hit" };
    }
    skeleton = skeletonizeCommand(command);
  } else {
    skeleton = skeletonizeCommand(primary) ?? primary;
  }
  if (!skeleton) return { hit: false, reason: "unsafe or empty skeleton" };

  for (const entry of file.entries) {
    if (entry.kind !== "skeleton") continue;
    if (entry.tool !== tool) continue;
    if (entry.skeleton !== skeleton) continue;
    if (!ruleOverlap(entry.matched_rule_ids, ruleIds)) continue;
    return {
      hit: true,
      kind: "skeleton",
      matchedRuleIds: ruleIds.filter((id) => entry.matched_rule_ids.includes(id)),
      entryDetail: `skeleton=${entry.skeleton}`,
    };
  }

  return { hit: false, reason: "no matching entry" };
}

export function recordAllowAlways(
  snapshot: ShadowSnapshot,
  log: Record<string, unknown> | undefined,
  config: AllowlistConfig,
  opts: { readFile?: FileReader; cwd?: string; now?: () => string } = {},
): RecordResult {
  if (!config.enabled) return { status: "skipped", reason: "allowlist disabled" };

  const ruleIds = extractMatchedRuleIds(log);
  if (ruleIds.length === 0) {
    return { status: "skipped", reason: "no matched rules" };
  }

  const tool = snapshot.pending?.tool ?? "";
  const command = pendingCommand(snapshot);
  const readFile = opts.readFile ?? defaultFileReader;
  const cwd = opts.cwd ?? process.cwd();
  const createdAt = (opts.now ?? (() => new Date().toISOString()))();

  let entry: AllowlistEntry | null = null;

  if (config.scriptBind && tool === "exec" && command) {
    const bindable = parseBindableScript(command);
    if (bindable) {
      const abs = resolveScriptPath(bindable.scriptPath, cwd);
      const buf = readFile(abs);
      if (!buf) {
        return { status: "skipped", reason: `script unreadable: ${abs}` };
      }
      entry = {
        kind: "script_bind",
        tool,
        interpreter: bindable.interpreter,
        script_path: abs,
        content_sha256: sha256Buffer(buf),
        args_skeleton: skeletonizeScriptArgs(bindable.trailingArgs),
        matched_rule_ids: ruleIds,
        created_at: createdAt,
        source: "allow-always",
      };
    } else if (isHighRiskCommand(command)) {
      return { status: "skipped", reason: "high-risk command shape" };
    }
  }

  if (!entry) {
    if (tool === "exec" && command) {
      if (isHighRiskCommand(command)) {
        return { status: "skipped", reason: "high-risk command shape" };
      }
      // Do not write a skeleton for bindable script forms that failed to hash
      if (parseBindableScript(command)) {
        return { status: "skipped", reason: "script bind preferred but unavailable" };
      }
      const skeleton = skeletonizeCommand(command);
      if (!skeleton) {
        return { status: "skipped", reason: "refused bare or empty skeleton" };
      }
      entry = {
        kind: "skeleton",
        tool,
        matched_rule_ids: ruleIds,
        skeleton,
        created_at: createdAt,
        source: "allow-always",
      };
    } else {
      const primary = pendingPrimaryText(snapshot);
      if (!primary) return { status: "skipped", reason: "no pending primary" };
      const skeleton = skeletonizeCommand(primary) ?? primary;
      entry = {
        kind: "skeleton",
        tool,
        matched_rule_ids: ruleIds,
        skeleton,
        created_at: createdAt,
        source: "allow-always",
      };
    }
  }

  const file = loadAllowlist(config.path);
  const key = entryDedupeKey(entry);
  if (file.entries.some((e) => entryDedupeKey(e) === key)) {
    return { status: "duplicate", kind: entry.kind };
  }
  file.entries.push(entry);
  saveAllowlist(config.path, file);
  return { status: "recorded", kind: entry.kind };
}
