/**
 * Plugin-local allowlist for Sentrook enforce-mode "allow-always" short-circuit.
 *
 * Two entry kinds (orthogonal):
 * - skeleton: constrained command/arg shape for general tools
 * - script_bind: interpreter + concrete local script file (path + content SHA-256)
 *   with narrow-volatile trailing args (dates / UUIDs / ints only)
 *
 * Never overrides Sentrook `block`. Never skips /scan. Never stores bare interpreters.
 * curl/wget keep scheme+host+path (query/userinfo dropped) so a trusted fetch is
 * not collapsed to ``curl <url>``. Pipes and curl|bash stay refused.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, resolve as pathResolve } from "node:path";
import { homedir } from "node:os";

import { lastPendingStep, type PlanIR } from "./planir.ts";
import { scrubSecrets } from "./sanitize.ts";

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

// Substitution and process substitution only. `;`, `&&`, `||` and `|` used to
// be here, which made *every* compound command unallowlistable — a blunt
// instrument that worked because the alternative was reasoning about what a
// compound command does. §3b's per-segment matching is that reasoning, so the
// separators come out and the things a segment split cannot make safe stay.
//
// What a segment split cannot make safe:
//   - substitution, because `ls $(curl evil)` has one segment and the shape
//     cannot say what the substitution evaluated to;
//   - a pipe into an interpreter, because `echo hi | sh` is two segments that
//     are individually harmless and jointly arbitrary code — see
//     `pipesIntoInterpreter`;
//   - a redirect, because `ls > ~/.bashrc` is one segment whose skeleton
//     differs from a recorded `ls` only by tokens the skeletonizer keeps, and
//     relying on that is relying on an accident.
const HIGH_RISK_SHELL_RE = /(?:`|\$\(|<\(|>\(|>>?|<)/;

//: Heads that turn their standard input into code. A pipe *into* one of these
//: is the shape per-segment matching cannot see: `echo hi` and `sh` are each
//: unremarkable, and `echo hi | sh` is arbitrary execution. Kept separate from
//: `INTERPRETER_RE` because that one also drives script binding, where a
//: broader list is correct.
const PIPE_SINK_INTERPRETERS = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "fish",
  "python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php",
  "eval", "source", ".", "xargs", "env",
]);

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

/** Fetch bins whose URL is the identity of the action, not a volatile. */
const FETCH_BINS = new Set(["curl", "wget"]);

/**
 * Bare builtins that execute their argument as code with no flag at all.
 *
 * `source ~/.bashrc` carries no shell metacharacter and no eval flag, so before
 * this it was neither high-risk nor refused — it could be skeletonised and
 * allowlisted, and the file it executes can change afterwards. That is the
 * AST07 update-drift shape with the approval already granted.
 */
const INLINE_EVAL_HEADS = new Set(["eval", "source", "."]);

/**
 * Inline-eval flags **bound to the interpreter that gives them meaning**,
 * mirroring `_INLINE_EVAL_FLAGS` in the Python twin.
 *
 * The previous check scanned every token against one flat flag set, so it was
 * wrong in both directions at once. It refused `ls -r`, `cp -r`, `grep -e`,
 * `du -c`, `sort -r`, `tar -c` and `uniq -c` — ordinary commands whose flags
 * merely collide with an interpreter's — making them permanently
 * un-allowlistable and quietly suppressing the host-allowlist lane that D10's
 * counterfactual measures. And it passed `python3 -m <module>`, which executes
 * arbitrary code, because `-m` was not in the flat set.
 */
const INLINE_EVAL_FLAGS_BY_HEAD: Record<string, Set<string>> = {
  python: new Set(["-c", "-m"]),
  python2: new Set(["-c", "-m"]),
  python3: new Set(["-c", "-m"]),
  node: new Set(["-e", "--eval", "-p", "--print"]),
  nodejs: new Set(["-e", "--eval", "-p", "--print"]),
  deno: new Set(["eval"]),
  bun: new Set(["-e", "--eval"]),
  perl: new Set(["-e", "-E"]),
  ruby: new Set(["-e"]),
  php: new Set(["-r"]),
  lua: new Set(["-e"]),
  bash: new Set(["-c"]),
  sh: new Set(["-c"]),
  zsh: new Set(["-c"]),
  dash: new Set(["-c"]),
  ksh: new Set(["-c"]),
  fish: new Set(["-c"]),
  osascript: new Set(["-e"]),
};

/**
 * Heads whose flags are known **not** to mean "evaluate this as code".
 *
 * Needed because the conservative fallback below still applies to any head we
 * do not recognise: for an unknown binary, an eval-looking flag might really be
 * one, and refusing costs only allowlist eligibility. This set is what stops
 * that caution from swallowing the common cases — `ls -r`, `cp -r`, `grep -e`,
 * `du -c`, `sort -r`, `tar -c`, `uniq -c` were all permanently un-allowlistable
 * before it existed.
 *
 * The failure mode of an omission here is over-refusal, never over-approval, so
 * this list is safe to extend lazily as real traffic turns up more.
 */
const NON_EVAL_FLAG_BINS = new Set([
  "ls", "cp", "mv", "rm", "ln", "mkdir", "rmdir", "touch", "stat", "file",
  "cat", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "tee", "split",
  "grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "fd", "locate",
  "du", "df", "ps", "top", "kill", "pgrep", "pkill", "uptime", "free",
  "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "xz", "zstd",
  "diff", "patch", "cmp", "md5sum", "sha256sum", "base64",
  "date", "whoami", "id", "pwd", "which", "whereis", "echo", "printf", "seq",
  "chmod", "chown", "ln", "readlink", "realpath", "dirname", "basename",
  "git", "docker", "kubectl", "npm", "pnpm", "yarn", "make", "cargo", "go",
  "jq", "yq", "xmllint", "column", "less", "more", "man", "openclaw", "gog",
]);

/**
 * Mirrors `sentrook/layers/exec_shape.py` WRAPPERS. Kept in sync by
 * `fixtures/exec_shape_golden.jsonl`, which both suites load — the plugin does
 * not derive `exec_shape` (zero runtime dependencies, so no parser), it adopts
 * the semantics only.
 */
const WRAPPER_BINS = new Set([
  "timeout",
  "time",
  "nice",
  "nohup",
  "stdbuf",
  "env",
  "command",
  "builtin",
  "noglob",
  "xargs",
  "sudo",
  "doas",
  "run0",
  "pkexec",
]);

/** Wrapper flags that consume the following token (see the Python twin). */
const WRAPPER_VALUE_FLAGS: Record<string, Set<string>> = {
  timeout: new Set(["-s", "--signal", "-k", "--kill-after"]),
  nice: new Set(["-n", "--adjustment"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
  xargs: new Set(["-n", "-P", "-I", "-d", "-s", "-a", "-E"]),
  sudo: new Set(["-u", "--user", "-g", "--group", "-p", "--prompt", "-C", "-h", "--host", "-U", "-r", "--role", "-t", "--type"]),
  doas: new Set(["-u", "-C", "-a"]),
  time: new Set(["-o", "--output", "-f", "--format"]),
};

const DURATION_RE = /^\d+(?:\.\d+)?[smhd]?$/;
const ENV_ASSIGN_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** The packer's separator. A packed excerpt is not valid shell (see §1.1). */
const PACK_SEPARATOR = " \u2026 ";

/** True when the text is a signal-packed excerpt rather than a real command. */
export function isPackedExcerpt(command: string): boolean {
  return command.includes(PACK_SEPARATOR);
}

/**
 * Command heads, mirroring `exec_shape.heads`: one per simple command, wrappers
 * stripped, basename, lowercased.
 *
 * The plugin keys its local allowlist on a skeleton while Phase 3b's allow rules
 * key on engine heads. If the two disagreed about which binary a command runs,
 * the host-allowlist lane and the allow-rule lane would be approving different
 * things under the same name — and the fatigue report's three-lane counterfactual
 * (D10) would be comparing lanes that do not mean what it thinks.
 */
export function commandHeads(command: string): string[] {
  if (!command || !command.trim() || isPackedExcerpt(command)) return [];
  const heads: string[] = [];
  for (const segment of splitSegments(command.trim())) {
    const head = segmentHead(segment);
    if (head) heads.push(head);
  }
  return heads;
}

/** Split on the separators that start a new simple command. */
function splitSegments(command: string): string[][] {
  const tokens = tokenizeArgv(command);
  const segments: string[][] = [];
  let current: string[] = [];
  for (const raw of tokens) {
    // The tokenizer keeps separators attached (`ls;`), so peel them off.
    let token = raw;
    let broke = false;
    while (token.endsWith(";") || token.endsWith("|") || token.endsWith("&")) {
      token = token.slice(0, -1);
      broke = true;
    }
    if (token === "&&" || token === "||" || token === ";" || token === "|") {
      if (current.length) segments.push(current);
      current = [];
      continue;
    }
    if (token) current.push(token);
    if (broke) {
      if (current.length) segments.push(current);
      current = [];
    }
  }
  if (current.length) segments.push(current);
  return segments;
}

/** True when this segment executes its argument as code (§1.1 `inline_eval`). */
function segmentIsInlineEval(tokens: string[]): boolean {
  const head = segmentHead(tokens);
  if (!head) return false;
  if (INLINE_EVAL_HEADS.has(head)) return true;

  const bound = INLINE_EVAL_FLAGS_BY_HEAD[head];
  if (bound) {
    return tokens.some((token) => bound.has(token) || bound.has(token.split("=")[0]));
  }
  if (NON_EVAL_FLAG_BINS.has(head)) return false;

  // Unknown binary: fall back to the blunt check. We cannot tell whether `-e`
  // means "eval" here, and the cost of being wrong in this direction is only
  // that the command cannot be added to a host allowlist.
  return tokens.some((token) => INLINE_EVAL_FLAGS.has(token));
}

/** Peel wrappers and leading env assignments off one segment. */
function segmentHead(tokens: string[]): string {
  let rest = tokens.slice();
  // Leading `VAR=value` assignments are not the head.
  while (rest.length && ENV_ASSIGN_RE.test(rest[0])) rest = rest.slice(1);
  if (!rest.length) return "";

  let guard = 0;
  while (guard++ < 8) {
    const head = basenameOf(rest[0]).toLowerCase();
    if (!WRAPPER_BINS.has(head) || rest.length < 2) return head;
    const valueFlags = WRAPPER_VALUE_FLAGS[head] ?? new Set<string>();
    let i = 1;
    while (i < rest.length && rest[i].startsWith("-") && rest[i] !== "-") {
      const flag = rest[i];
      i += 1;
      if (valueFlags.has(flag) && i < rest.length) i += 1;
    }
    if (head === "timeout" && i < rest.length && DURATION_RE.test(rest[i])) i += 1;
    // `env` and `sudo` both take KEY=VALUE arguments. Without `sudo` here,
    // `sudo LD_PRELOAD=/tmp/x.so python3 -c '…'` reports a head of `x.so`,
    // losing the real binary — the engine had the same bug. `timeout` is
    // deliberately excluded: it would exec a binary named `FOO=1` and fail,
    // so reporting that head is correct.
    if (head === "env" || head === "sudo") {
      while (i < rest.length && ENV_ASSIGN_RE.test(rest[i])) i += 1;
    }
    if (i >= rest.length) return head; // wrapper with no command after it
    rest = rest.slice(i);
  }
  return basenameOf(rest[0]).toLowerCase();
}

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

/**
 * The **review** rule ids from a scan log — never the allow families.
 *
 * An allowlist entry records "the reviews I was approved against", and an
 * allow rule is not a review: it can never be the reason a review is shown,
 * and it cannot suppress a hard one at all.
 *
 * Including them was an ordinary-looking bug with an unpleasant consequence.
 * `rulesWereAllKnown` requires every currently-matching id to have been
 * recorded, so the day an `AIRA-9NN` family started matching a command that
 * had a **hard** review, every existing entry for it stopped applying and
 * the operator was asked to approve again — although the family had changed
 * nothing about the danger and could not have waived that review. Shipping a
 * fatigue reduction would have produced a burst of fatigue.
 *
 * Detected by `action` where the log carries it, and by the `AIRA-9NN` range
 * otherwise: `action` only reached this wire model in Phase 3b, so a body
 * written earlier records ids as bare strings or without it.
 */
export function extractMatchedRuleIds(log: Record<string, unknown> | undefined): string[] {
  if (!log) return [];
  const matched = log.matched_rules;
  if (!Array.isArray(matched)) return [];
  const ids: string[] = [];
  for (const item of matched) {
    if (typeof item === "string" && item.trim()) {
      if (!ALLOW_FAMILY_ID_RE.test(item.trim())) ids.push(item.trim());
    } else if (item && typeof item === "object") {
      const record = item as Record<string, unknown>;
      const id = record.id;
      if (typeof id !== "string" || !id.trim()) continue;
      if (record.action === "allow" || record.action === "observe") continue;
      if (record.action === undefined && ALLOW_FAMILY_ID_RE.test(id.trim())) continue;
      ids.push(id.trim());
    }
  }
  return [...new Set(ids)].sort();
}

/** The `AIRA-9NN` range the allow families occupy. */
const ALLOW_FAMILY_ID_RE = /^AIRA-9\d\d$/;

function ruleOverlap(a: string[], b: string[]): boolean {
  if (a.length === 0 || b.length === 0) return false;
  const set = new Set(a);
  return b.some((id) => set.has(id));
}

/**
 * Every rule matching now was one the operator saw when they allowlisted this.
 *
 * `ruleOverlap` asks whether *any* recorded rule still matches, which is the
 * right question while the rule set is static and the wrong one the moment a
 * rule is added. An entry recorded when `cat ~/.ssh/id_rsa` matched only
 * AIRA-010 kept hitting after AIRA-083 shipped — so Phase 3a's hard credential
 * rule was silently waived on every skeleton an operator had already
 * allowlisted, by an approval given before that rule existed.
 *
 * Applied to **hard** reviews only. A hard review is one no blanket policy may
 * skip; an allowlist entry is exempt because it is a decision about one command
 * — but only about the command *as the operator saw it*. For a soft review the
 * looser overlap stays, because re-prompting on every new soft rule is noise
 * for no safety gain.
 */
function rulesWereAllKnown(recorded: string[], matchedNow: string[]): boolean {
  if (matchedNow.length === 0) return false;
  const known = new Set(recorded);
  return matchedNow.every((id) => known.has(id));
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

/**
 * Whether any `|` in the command feeds a head that executes its stdin.
 *
 * This is the hole per-segment matching opens and must therefore close in the
 * same change. `echo hi` and `sh` are each an unremarkable segment; `echo hi
 * | sh` is arbitrary code, and nothing about either half says so. The old
 * `HIGH_RISK_SHELL_RE` caught it by refusing every pipe.
 *
 * Splits on `|` at the token level rather than with a regex over the text,
 * because a `|` inside a quoted argument (`grep 'a|b' f`) is not a pipe and a
 * text-level split would refuse it.
 */
/**
 * The command with quoted content blanked out, so an argument character
 * cannot be read as shell syntax.
 *
 * `grep '<html>' page.txt` and `grep "=>" src.js` are routine, and a raw
 * regex looking for `<` or `>` calls both of them redirects — the same
 * text-versus-parse mistake that let `"git" push` past the engine's argv
 * guards, in the other direction: there it admitted something dangerous,
 * here it refuses something ordinary.
 *
 * Single-quoted spans are fully literal in shell and are blanked entirely.
 * Double-quoted spans keep `$`, `(`, `)` and a backtick, because
 * substitution still happens inside them — `echo "$(whoami)"` is a
 * substitution and must stay one.
 *
 * **An unbalanced quote returns null**, and every caller treats that as high
 * risk. Guessing at where the span ends would blank the rest of the command,
 * which is the one direction this must not fail in.
 */
export function shellSignificant(command: string): string | null {
  let out = "";
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote === null) {
      if (ch === "'" || ch === '"') {
        quote = ch;
        out += " ";
        continue;
      }
      out += ch;
      continue;
    }
    if (ch === quote) {
      quote = null;
      out += " ";
      continue;
    }
    out += quote === '"' && (ch === "$" || ch === "(" || ch === ")" || ch === "`") ? ch : " ";
  }
  return quote === null ? out : null;
}

export function pipesIntoInterpreter(command: string): boolean {
  const masked = shellSignificant(command);
  if (masked === null) return true;
  // Split on the masked text rather than on tokens: `echo hi|sh` has no
  // whitespace around the pipe, so the tokenizer yields one token `hi|sh`
  // and a token-level scan missed it entirely. A `|` inside quotes is
  // already blanked, so `grep 'a|b' f` is not a pipe here.
  const parts = masked.split("|");
  for (const part of parts.slice(1)) {
    // `|&` pipes stderr too and leaves a leading `&`; `||` leaves an empty
    // part and then the next command, which is not a pipe but does still run
    // the interpreter, so treating it the same way is the conservative
    // reading rather than a mistake.
    const first = part.replace(/^[&|]+/, "").trim().split(/\s+/)[0];
    if (!first) continue;
    if (PIPE_SINK_INTERPRETERS.has(basenameOf(first).toLowerCase())) return true;
  }
  return false;
}

export function isHighRiskCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed) return true;
  // A packed excerpt is not valid shell. It can still *tokenize* into something
  // plausible, so treating it as a real command would allowlist a skeleton built
  // from a truncation — matching later commands that merely share a prefix.
  if (isPackedExcerpt(trimmed)) return true;
  const masked = shellSignificant(trimmed);
  if (masked === null) return true; // unbalanced quote: we cannot say what this is
  if (HIGH_RISK_SHELL_RE.test(masked)) return true;
  if (pipesIntoInterpreter(trimmed)) return true;

  const tokens = tokenizeArgv(trimmed);
  if (tokens.length === 0) return true;

  // Per segment, with each flag bound to the head that gives it meaning.
  for (const segment of splitSegments(trimmed)) {
    if (segmentIsInlineEval(segment)) return true;
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

function pinHttpUrl(token: string): string | undefined {
  if (!/^https?:\/\//i.test(token)) return undefined;
  try {
    const url = new URL(token);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    return `${url.origin}${url.pathname || "/"}`;
  } catch {
    return undefined;
  }
}

function commandFingerprint(skeleton: string): string {
  return scrubSecrets(skeleton).replace(/\s+/g, " ").trim();
}

/** Skeleton used for record + match (fetch URLs pinned, secrets scrubbed). */
export function allowlistCommandSkeleton(command: string): string | null {
  const skeleton = skeletonizeCommand(command);
  if (!skeleton) return null;
  const fingerprint = commandFingerprint(skeleton);
  return fingerprint || null;
}

/** Broader volatiles for general command skeletons. */
export function skeletonizeCommand(command: string): string | null {
  if (isHighRiskCommand(command)) return null;

  const tokens = tokenizeArgv(command.trim());
  if (tokens.length === 0) return null;

  const bin = basenameOf(tokens[0]).toLowerCase();
  const pinHttpUrls = FETCH_BINS.has(bin);
  const mapRest = (token: string) => skeletonizeGeneralToken(token, { pinHttpUrls });
  // Bare dangerous binary with no further literal structure beyond volatiles
  if (BARE_DANGEROUS_BINS.has(bin) || normalizeInterpreter(tokens[0])) {
    // Interpreters / dangerous bins need remaining literal structure after skeletonize
    const rest = tokens.slice(1).map(mapRest);
    const literalRest = rest.filter(
      (t) => !t.startsWith("<") && !t.endsWith(">") && t !== "<file>",
    );
    if (literalRest.length === 0) return null;
    return [tokens[0], ...rest].join(" ");
  }

  return tokens.map((token) => skeletonizeGeneralToken(token)).join(" ");
}

function skeletonizeGeneralToken(token: string, opts: { pinHttpUrls?: boolean } = {}): string {
  if (opts.pinHttpUrls) {
    const pinned = pinHttpUrl(token);
    if (pinned) return pinned;
  }
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

function pendingCommand(plan: PlanIR): string | null {
  const step = lastPendingStep(plan);
  const args = step?.args;
  if (!args || typeof args !== "object") return null;
  const command = (args as Record<string, unknown>).command ?? (args as Record<string, unknown>).cmd;
  return typeof command === "string" ? command : null;
}

function pendingPrimaryText(plan: PlanIR): string | null {
  const step = lastPendingStep(plan);
  if (!step) return null;
  const tool = step.tool ?? "";
  const args = (step.args ?? {}) as Record<string, unknown>;
  if (tool === "exec") {
    return pendingCommand(plan);
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
  plan: PlanIR,
  log: Record<string, unknown> | undefined,
  config: AllowlistConfig,
  opts: {
    readFile?: FileReader;
    cwd?: string;
    /**
     * `review_authority` from the scan response. `hard` tightens the rule-id
     * check from "any recorded rule still matches" to "every rule matching now
     * was recorded" — see {@link rulesWereAllKnown}.
     */
    reviewAuthority?: string;
  } = {},
): MatchResult {
  if (!config.enabled) return { hit: false, reason: "allowlist disabled" };

  const ruleIds = extractMatchedRuleIds(log);
  if (ruleIds.length === 0) return { hit: false, reason: "no matched rules" };

  const file = loadAllowlist(config.path);
  if (file.entries.length === 0) return { hit: false, reason: "empty allowlist" };

  const pending = lastPendingStep(plan);
  const tool = pending?.tool ?? "";
  const command = pendingCommand(plan);
  const readFile = opts.readFile ?? defaultFileReader;
  const cwd = opts.cwd ?? process.cwd();
  const hard = opts.reviewAuthority === "hard";
  const rulesOk = (recorded: string[]): boolean =>
    hard ? rulesWereAllKnown(recorded, ruleIds) : ruleOverlap(recorded, ruleIds);

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
          if (!rulesOk(entry.matched_rule_ids)) continue;
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
  const primary = pendingPrimaryText(plan);
  if (!primary) return { hit: false, reason: "no pending primary" };

  let skeleton: string | null;
  if (tool === "exec" && command) {
    // Bindable script forms must not match via a loose skeleton
    if (parseBindableScript(command)) {
      return { hit: false, reason: "script form requires script_bind hit" };
    }
    skeleton = allowlistCommandSkeleton(command);
  } else {
    skeleton = allowlistCommandSkeleton(primary) ?? commandFingerprint(primary);
  }
  if (!skeleton) return { hit: false, reason: "unsafe or empty skeleton" };

  for (const entry of file.entries) {
    if (entry.kind !== "skeleton") continue;
    if (entry.tool !== tool) continue;
    if (entry.skeleton !== skeleton) continue;
    if (!rulesOk(entry.matched_rule_ids)) continue;
    return {
      hit: true,
      kind: "skeleton",
      matchedRuleIds: ruleIds.filter((id) => entry.matched_rule_ids.includes(id)),
      entryDetail: `skeleton=${entry.skeleton}`,
    };
  }

  // --- per-segment match, §3b -------------------------------------------
  //
  // A compound command matches when **every** top-level segment matches an
  // entry of its own. `ls -la && pwd` is a hit when `ls -la` and `pwd` were
  // each approved, which is most of what the blanket refusal of `&&` cost.
  //
  // Three things make this safe, and each is load-bearing:
  //
  //   1. `isHighRiskCommand` still refuses substitution, redirects and a pipe
  //      into an interpreter, so the segments cannot mean something the
  //      segment split cannot see.
  //   2. Rule ids are checked **strictly**, whatever the authority. Combining
  //      two approved segments is exactly the case where a rule fires that
  //      neither segment produced on its own — a sequence rule, or a
  //      whole-command path signal — and `ruleOverlap` would waive it on the
  //      strength of one id they happen to share. F50 tightened this for hard
  //      reviews; recombination needs it for soft ones too.
  //   3. Only `exec` reaches here at all.
  //
  // This is deliberately **not** "or a shipped safe family". §3b warns that a
  // safe-family match keyed on heads reintroduces F30's fail-open in the lane
  // that short-circuits the review, because `commandHeads("LD_PRELOAD=… ls")`
  // is `["ls"]`. A second implementation of the AIRA-9NN families in
  // TypeScript would be a second decision surface with no gate over it; the
  // engine already answers that question, deterministically, and its answer
  // arrives as a scan decision rather than as an allowlist waiver.
  if (tool === "exec" && command) {
    const segmentHit = matchEverySegment(command, file.entries, tool);
    if (segmentHit) {
      if (!rulesWereAllKnown(segmentHit.recordedRuleIds, ruleIds)) {
        return {
          hit: false,
          reason:
            "every segment is allowlisted, but a rule matches now that no " +
            "segment's entry recorded — the combination is not the parts",
        };
      }
      return {
        hit: true,
        kind: "skeleton",
        matchedRuleIds: ruleIds.filter((id) => segmentHit.recordedRuleIds.includes(id)),
        entryDetail: `segments=${segmentHit.skeletons.join(" ⋅ ")}`,
      };
    }
  }

  return {
    hit: false,
    reason: hard
      ? "no entry recorded with every rule that matches now (hard review)"
      : "no matching entry",
  };
}

/**
 * Every top-level segment of `command`, each matched to a skeleton entry.
 *
 * Returns null unless there are at least two segments and every one of them
 * matches. One segment is the ordinary path above and must not come through
 * here, or a single-segment miss would be retried with different rule-id
 * semantics than it was refused under.
 */
function matchEverySegment(
  command: string,
  entries: AllowlistEntry[],
  tool: string,
): { skeletons: string[]; recordedRuleIds: string[] } | null {
  if (isHighRiskCommand(command)) return null;
  const segments = splitSegments(command.trim());
  if (segments.length < 2) return null;

  const skeletons: string[] = [];
  const recorded = new Set<string>();
  for (const segment of segments) {
    const text = segment.join(" ");
    // A segment is skeletonized on its own, so an entry recorded for the
    // bare command matches it. `skeletonizeCommand` re-runs the high-risk
    // check per segment, which is why `cd` and a bare interpreter still
    // refuse here.
    const skeleton = allowlistCommandSkeleton(text);
    if (!skeleton) return null;
    const entry = entries.find(
      (e) => e.kind === "skeleton" && e.tool === tool && e.skeleton === skeleton,
    );
    if (!entry || entry.kind !== "skeleton") return null;
    skeletons.push(skeleton);
    for (const id of entry.matched_rule_ids) recorded.add(id);
  }
  return { skeletons, recordedRuleIds: [...recorded] };
}

export function recordAllowAlways(
  plan: PlanIR,
  log: Record<string, unknown> | undefined,
  config: AllowlistConfig,
  opts: { readFile?: FileReader; cwd?: string; now?: () => string } = {},
): RecordResult {
  if (!config.enabled) return { status: "skipped", reason: "allowlist disabled" };

  const ruleIds = extractMatchedRuleIds(log);
  if (ruleIds.length === 0) {
    return { status: "skipped", reason: "no matched rules" };
  }

  const pending = lastPendingStep(plan);
  const tool = pending?.tool ?? "";
  const command = pendingCommand(plan);
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
      const skeleton = allowlistCommandSkeleton(command);
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
      const primary = pendingPrimaryText(plan);
      if (!primary) return { status: "skipped", reason: "no pending primary" };
      const skeleton = allowlistCommandSkeleton(primary) ?? commandFingerprint(primary);
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
