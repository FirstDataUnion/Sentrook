/**
 * Plugin configuration: endpoints, credentials, decision policy, storage and grants.
 *
 * Every value resolves as plugin config (openclaw.json `plugins.entries.sentrook.config`), then env
 * (process env plus the state-dir `.env`), then the default.
 *
 * Endpoints default to the hosted service. A non-default scan, Rookery or identity URL must be https
 * on a firstdataunion.org host: a scan URL the agent could redirect would send every tool call
 * somewhere else. `SENTROOK_DEV_ENDPOINTS=1` (env only) lifts that for local sandboxes and dev stacks.
 * An endpoint that fails these checks is a configuration error and scans fail closed.
 *
 * The plugin config is checked here, not by OpenClaw: the manifest's `configSchema` accepts any object, because
 * OpenClaw's `doctor --fix` (which the official Docker image runs on every start) deletes the config of a plugin that
 * fails its manifest schema and disables the plugin, leaving every tool call unscanned. A setting this file cannot
 * read as written is ignored or replaced (never in a way that turns scanning off) and listed in `configProblems`,
 * which the gateway log, `openclaw sentrook verify`, `/sentrook status` and an owner notice report.
 */

import path from "node:path";

import {
  type ApprovalPolicyConfig,
  DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS,
  DEFAULT_SCHEDULED_INTENT_KINDS,
  resolveApprovalPolicyConfig,
} from "./approvalPolicy.ts";
import { resolveSetting, type SkillReviewSetting } from "./selfEdit.ts";
import { DEFAULT_ON_SCAN_ERROR, type OnScanError, resolveOnScanError } from "./scanErrorPolicy.ts";

export const DEFAULT_SCAN_URL = "https://sentrook.firstdataunion.org";
export const DEFAULT_ROOKERY_URL = "https://rookery.firstdataunion.org";
export const DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org";
export const TRUSTED_ENDPOINT_DOMAIN = "firstdataunion.org";
/** Where owners send wrong-scan reports privately, and ask for support. */
export const SUPPORT_EMAIL = "sentrook@firstdataunion.org";
/** The public issue form for a wrong scan (`.github/ISSUE_TEMPLATE/wrong_scan.yml`). */
export const WRONG_SCAN_ISSUE_URL = "https://github.com/FirstDataUnion/Sentrook/issues/new?template=wrong_scan.yml";

export const DEFAULT_REVIEW_AT = 45;
export const DEFAULT_BLOCK_AT = 80;
export const DEFAULT_SCAN_TIMEOUT_MS = 30_000;
export const DEFAULT_HISTORY_LIMIT = 20;
export const DEFAULT_INPUT_CAP_BYTES = 256 * 1024;
export const DEFAULT_HISTORY_ARGS_CAP_BYTES = 4 * 1024;
export const DEFAULT_TRAFFIC_LOG_MAX_BYTES = 50 * 1024 * 1024;

export type Mode = "enforce" | "observe";

export type Endpoint = { ok: true; url: string } | { ok: false; reason: string };

export interface Endpoints {
  scan: Endpoint;
  rookery: Endpoint;
  issuer: Endpoint;
  dev: boolean;
}

/** The grant kinds Sentrook reads; a grant of any other kind never applies. */
export const GRANT_KINDS: readonly string[] = ["destination", "file", "provider", "repo", "credential"];

export interface GrantConfig {
  kind: string;
  pattern: string;
  allows?: string[];
  scope?: "session" | "persistent";
  granted_at?: string;
  /** Sent for a session grant set by command: the session it is bound to. */
  session_ref?: string;
  /** Sent for a grant set by command with an expiry. */
  expires_at?: string;
  /** The `grant_ref` to send instead of the grant's place in the list (a cron job's delivery target). */
  ref?: string;
}

export interface PluginConfig {
  endpoints: Endpoints;
  mode: Mode;
  reviewAt: number;
  blockAt: number;
  onScanError: OnScanError;
  timeoutMs: number;
  approval: ApprovalPolicyConfig;
  stateDir: string;
  trafficLog: { enabled: boolean; path: string; maxBytes: number };
  historyLimit: number;
  inputCapBytes: number;
  historyArgsCapBytes: number;
  /**
   * Hide the calls (redacted arguments) that `/sentrook-why`, background-save notices and the dashboard show by
   * default. Anyone who can open the tab or read the owner's chat reads them.
   */
  hideToolCalls: boolean;
  packs: string[];
  trustedSenders: string[];
  trustedRoles: string[];
  /** Grants from the plugin config; a scan also sends the bindings and the grants set by command. */
  grants: GrantConfig[];
  /** Config grants that are never sent, by index in `grants`: why (`too broad`, `no session`, `unknown scope "x"`). */
  unsentGrants: Record<number, string>;
  channelBindings: string[];
  /** How OpenClaw's own background saves to skills and memory are sent (see `selfEdit.ts`). */
  skillReview: SkillReviewSetting;
  /** The configured value when it was not `allow` or `review` (read as allow). */
  skillReviewUnknown: string | null;
  /** Plugin-config settings not read as written, each with what is used instead (`configProblems`). */
  configProblems: string[];
}

type Env = NodeJS.ProcessEnv;

/** OpenClaw's own state directory: `OPENCLAW_STATE_DIR`, else `.openclaw` under `OPENCLAW_HOME` or the home directory. */
export function openclawDir(env: Env): string {
  return env.OPENCLAW_STATE_DIR?.trim() || path.join(env.OPENCLAW_HOME?.trim() || env.HOME?.trim() || "/home/node", ".openclaw");
}

/** `<state>/sentrook`: every plugin-side file lives here (the scanner's guardrail list protects it). */
export function resolveStateDir(env: Env, override?: unknown): string {
  if (typeof override === "string" && override.trim()) return override.trim();
  return path.join(openclawDir(env), "sentrook");
}

function str(raw: unknown): string | undefined {
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  return undefined;
}

function bool(raw: unknown, fallback: boolean): boolean {
  if (typeof raw === "boolean") return raw;
  if (typeof raw === "string") {
    const v = raw.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(v)) return true;
    if (["0", "false", "no", "off"].includes(v)) return false;
  }
  return fallback;
}

function num(raw: unknown, fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  const n = typeof raw === "number" ? raw : typeof raw === "string" && raw.trim() ? Number(raw) : NaN;
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

function list(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === "string" && !!v.trim());
  if (typeof raw === "string" && raw.trim()) {
    return raw.split(",").map((v) => v.trim()).filter(Boolean);
  }
  return [];
}

/** Linear-time trailing-slash trim (a `/\/+$/` regex is polynomial on backtracking engines). */
export function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") end -= 1;
  return value.slice(0, end);
}

function isTrustedHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === TRUSTED_ENDPOINT_DOMAIN || h.endsWith(`.${TRUSTED_ENDPOINT_DOMAIN}`);
}

/**
 * Rebuild an endpoint from its URL components so config text is never used as a fetch target
 * directly. Outside dev mode: https only, firstdataunion.org hosts only, no explicit port.
 */
export function parseEndpoint(raw: string, dev: boolean): Endpoint {
  let parsed: URL;
  try {
    parsed = new URL(raw.trim());
  } catch {
    // Never quote the input: a URL that fails to parse can still carry a password.
    return { ok: false, reason: "invalid URL (could not be parsed)" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, reason: `URL must be http or https (got ${parsed.protocol})` };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, reason: "URL must not include credentials" };
  }
  const host = parsed.hostname;
  if (!host || !/^[A-Za-z0-9._:\[\]-]+$/.test(host)) {
    return { ok: false, reason: "URL hostname is invalid" };
  }
  if (host === "169.254.169.254" || host === "[fd00:ec2::254]") {
    return { ok: false, reason: "URL must not target a metadata address" };
  }
  if (!dev) {
    if (parsed.protocol !== "https:") {
      return { ok: false, reason: "URL must be https (set SENTROOK_DEV_ENDPOINTS=1 for a local stack)" };
    }
    if (!isTrustedHost(host) || parsed.port) {
      return {
        ok: false,
        reason:
          `URL host ${host} is not a ${TRUSTED_ENDPOINT_DOMAIN} host ` +
          "(set SENTROOK_DEV_ENDPOINTS=1 for a local stack)",
      };
    }
  }
  return { ok: true, url: stripTrailingSlashes(parsed.origin + parsed.pathname) };
}

export function resolveEndpoints(cfg: Record<string, unknown>, env: Env): Endpoints {
  // Env only: plugin config is easier for an agent to reach than the gateway's environment.
  const dev = bool(env.SENTROOK_DEV_ENDPOINTS, false);
  const pick = (key: string, envVar: string, fallback: string) =>
    parseEndpoint(str(cfg[key]) ?? str(env[envVar]) ?? fallback, dev);
  return {
    scan: pick("scanUrl", "SENTROOK_SCAN_URL", DEFAULT_SCAN_URL),
    rookery: pick("rookeryUrl", "SENTROOK_ROOKERY_URL", DEFAULT_ROOKERY_URL),
    issuer: pick("oidcIssuer", "SENTROOK_OIDC_ISSUER", DEFAULT_OIDC_ISSUER),
    dev,
  };
}

/**
 * No scope means a standing grant. Any value other than exactly `session` or `persistent` reads as
 * `session`, so a typo never widens relief.
 */
function grantScope(raw: unknown): "session" | "persistent" {
  if (raw === undefined || raw === null) return "persistent";
  return raw === "persistent" ? "persistent" : "session";
}

/**
 * Why a config grant with this scope is never sent: a config grant names no session to bind a session
 * grant to, and an unknown scope reads as session.
 */
function unsentScope(raw: unknown): string | undefined {
  if (raw === undefined || raw === null || raw === "persistent") return undefined;
  if (raw === "session") return "no session";
  return `unknown scope ${JSON.stringify(raw) ?? String(raw)}`;
}

/**
 * A credential grant's pattern as Sentrook reads it: a name (or a prefix of three or more characters
 * and `*`), `@`, and a host (or `*.` and a domain of two or more labels), with no scheme, port or path.
 */
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
export const CREDENTIAL_PATTERN = new RegExp(
  `^(?:[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]{2,}\\*)@(?:\\*\\.)?${LABEL}(?:\\.${LABEL})+$`,
);
/**
 * Second-level labels under which a two-letter country domain is shared by many owners (`co.uk`, `ne.jp`): a wildcard
 * there, or on part of a numeric address, covers strangers, and Sentrook refuses it.
 */
export const SHARED_SECOND_LEVEL = new Set(["co", "com", "org", "net", "ac", "gov", "edu", "ne", "or", "go", "ed", "lg", "gr"]);
/**
 * Common shared-hosting and shared-registration suffixes, where anyone can get a name of their own
 * (`someone.github.io`): a wildcard on one of these, or on a domain above one (`*.amazonaws.com`), covers strangers,
 * and Sentrook refuses it. Not every such suffix: the most common ones. Sentrook's own list also has the tunnel
 * services; the plugin leaves those to it.
 */
export const SHARED_HOSTING = new Set([
  "github.io",
  "gitlab.io",
  "herokuapp.com",
  "vercel.app",
  "netlify.app",
  "pages.dev",
  "workers.dev",
  "web.app",
  "firebaseapp.com",
  "appspot.com",
  "azurewebsites.net",
  "cloudfront.net",
  "s3.amazonaws.com",
  "blob.core.windows.net",
  "onrender.com",
  "fly.dev",
  "glitch.me",
  "replit.dev",
  "repl.co",
  "blogspot.com",
  "wordpress.com",
  "myshopify.com",
  "supabase.co",
  "deno.dev",
  "uk.com",
  "us.com",
  "eu.com",
])
/**
 * Names that never resolve on the public internet (local networks, reserved for tests and examples): a destination
 * wildcard over one reaches no one else's server.
 */
export const PRIVATE_USE = new Set(["lan", "local", "internal", "localhost", "home.arpa", "test", "example", "invalid"]);
/** Characters that are never the literal part of a pattern: glob characters and separators. */
const NOT_LITERAL_CHARS = new Set("*?/~.@:#_-");

/**
 * Nothing literal is left once glob characters, `[...]` sets, separators, whitespace and `$HOME` are left out: the
 * pattern matches everything, and the scanner ignores it. One pass, in time linear in the pattern.
 */
export function nothingLiteral(pattern: string): boolean {
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i]!;
    if (c === "[") {
      const j = pattern.indexOf("]", i + 1);
      if (j < 0) return false; // a `[` that no `]` closes is literal
      i = j + 1;
    } else if (pattern.startsWith("$HOME", i)) {
      i += 5;
    } else if (NOT_LITERAL_CHARS.has(c) || /\s/.test(c)) {
      i += 1;
    } else {
      return false;
    }
  }
  return true;
}

/** `s` without the dots at its end, in time linear in `s`. */
export function trimDots(s: string): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === ".") end--;
  return s.slice(0, end);
}
const GLOB = /[*?[\]]/;
/** A chat platform in front of a channel (`discord:`, `channel:`), not a URL scheme. */
const PLATFORM_PREFIX = /^[a-z][a-z0-9_-]*:(?!\/\/)/;
/** Why a destination grant that `destinationOk` refuses is never sent. */
export const TOO_BROAD = "too broad";

/** `NAME@host` as Sentrook reads it (the host already lower-cased). */
export function credentialPatternOk(pattern: string): boolean {
  if (!CREDENTIAL_PATTERN.test(pattern)) return false;
  const host = pattern.slice(pattern.indexOf("@") + 1);
  if (!host.startsWith("*.")) return true;
  const base = host.slice(2);
  const labels = base.split(".");
  if (labels.every((l) => /^\d+$/.test(l))) return false;
  if (labels.length === 2 && SHARED_SECOND_LEVEL.has(labels[0]!) && labels[1]!.length === 2) return false;
  for (const s of SHARED_HOSTING) if (s === base || s.endsWith(`.${base}`)) return false;
  // an S3 endpoint in a region or another form (`s3.eu-west-1.amazonaws.com`)
  return !((base.startsWith("s3.") || base.startsWith("s3-")) && base.endsWith(".amazonaws.com"));
}
/**
 * `pattern` is `*.` and one domain as a credential grant's host may name it: two or more labels, not a shared country
 * second level (`*.co.uk`), a common shared-hosting suffix (`*.github.io`) or part of a numeric address. The rule is
 * `credentialPatternOk`'s, for the host alone.
 */
export function wildcardDomainOk(pattern: string): boolean {
  return pattern.startsWith("*.") && credentialPatternOk(`NAME@${trimDots(pattern.toLowerCase())}`);
}

function hostGlobOk(host: string): boolean {
  host = trimDots(host.trim().toLowerCase());
  if (!GLOB.test(host)) return true;
  return host.startsWith("*.") && (PRIVATE_USE.has(host.slice(2)) || wildcardDomainOk(host));
}

/**
 * A destination pattern Sentrook takes: something literal, and a wildcard that can reach a host or a mail domain only
 * as `*.` and one registrable domain (`wildcardDomainOk`), never over a suffix many owners share (`*.com`,
 * `*.co.uk`, `*.github.io`), or as `*.` and a name that never resolves on the public internet (`PRIVATE_USE`). A channel's name or id after a platform prefix or `#` (`discord:#ops-*`), and the name before an `@`
 * (`*@example.com`), may hold a wildcard. Sentrook ignores any other destination grant.
 */
export function destinationOk(pattern: string): boolean {
  const pat = pattern.trim().toLowerCase();
  if (nothingLiteral(pat)) return false;
  if (!GLOB.test(pat)) return true;
  const prefix = PLATFORM_PREFIX.exec(pat);
  const rest = prefix ? pat.slice(prefix[0].length) : pat;
  if (rest.startsWith("#")) return true;
  if (rest.includes("@")) return hostGlobOk(rest.slice(rest.lastIndexOf("@") + 1));
  if (prefix && !rest.includes(".")) return true; // a channel's name or id: `slack:C0B*`, `channel:ops-*`
  return hostGlobOk(rest);
}

/**
 * The config's grants, and why each one that is never sent is not (see `PluginConfig`). A destination grant Sentrook
 * would ignore as too broad (`destinationOk`) is kept in the list, so the others keep their numbers, and is never sent.
 */
export function parseConfigGrants(raw: unknown): { grants: GrantConfig[]; unsentGrants: Record<number, string> } {
  const grants: GrantConfig[] = [];
  const unsentGrants: Record<number, string> = {};
  for (const g of Array.isArray(raw) ? raw : []) {
    const [parsed] = parseGrants([g]);
    if (!parsed) continue;
    const tooBroad = parsed.kind === "destination" && !destinationOk(parsed.pattern);
    const why = tooBroad ? TOO_BROAD : unsentScope((g as Record<string, unknown>).scope);
    if (why) unsentGrants[grants.length] = why;
    grants.push(parsed);
  }
  return { grants, unsentGrants };
}

export function parseGrants(raw: unknown): GrantConfig[] {
  if (!Array.isArray(raw)) return [];
  const out: GrantConfig[] = [];
  for (const g of raw) {
    if (!g || typeof g !== "object") continue;
    const rec = g as Record<string, unknown>;
    const kind = str(rec.kind);
    const pattern = str(rec.pattern);
    if (!kind || !pattern) continue;
    out.push({
      kind,
      pattern,
      ...(Array.isArray(rec.allows) ? { allows: list(rec.allows) } : {}),
      scope: grantScope(rec.scope),
      ...(str(rec.granted_at) ? { granted_at: str(rec.granted_at) } : {}),
    });
  }
  return out;
}

export function resolveConfig(pluginConfig: Record<string, unknown> | undefined, env: Env): PluginConfig {
  const cfg = pluginConfig ?? {};
  const stateDir = resolveStateDir(env, cfg.stateDir);
  const mode = (str(cfg.mode) ?? str(env.SENTROOK_MODE))?.toLowerCase() === "observe" ? "observe" : "enforce";
  const reviewAt = num(cfg.reviewAt ?? env.SENTROOK_REVIEW_AT, DEFAULT_REVIEW_AT, 0, 100);
  const blockAt = Math.max(reviewAt, num(cfg.blockAt ?? env.SENTROOK_BLOCK_AT, DEFAULT_BLOCK_AT, 0, 101));
  const traffic = (cfg.trafficLog ?? {}) as Record<string, unknown>;
  return {
    endpoints: resolveEndpoints(cfg, env),
    mode,
    reviewAt,
    blockAt,
    onScanError: resolveOnScanError({ pluginConfig: cfg.onScanError, env }),
    timeoutMs: num(cfg.timeoutMs ?? env.SENTROOK_SCAN_TIMEOUT_MS, DEFAULT_SCAN_TIMEOUT_MS, 1000),
    approval: resolveApprovalPolicyConfig({
      pluginApproval: (cfg.approval ?? {}) as Record<string, unknown>,
      env,
    }),
    stateDir,
    trafficLog: {
      enabled: bool(traffic.enabled ?? env.SENTROOK_TRAFFIC_LOG_ENABLED, true),
      path: str(traffic.path) ?? str(env.SENTROOK_TRAFFIC_LOG) ?? path.join(stateDir, "traffic.jsonl"),
      maxBytes: num(traffic.maxBytes, DEFAULT_TRAFFIC_LOG_MAX_BYTES, 1024),
    },
    historyLimit: num(cfg.historyLimit, DEFAULT_HISTORY_LIMIT, 1, 200),
    inputCapBytes: num(cfg.inputCapBytes, DEFAULT_INPUT_CAP_BYTES, 1024),
    historyArgsCapBytes: num(cfg.historyArgsCapBytes, DEFAULT_HISTORY_ARGS_CAP_BYTES, 256),
    hideToolCalls: bool(cfg.hideToolCalls ?? env.SENTROOK_HIDE_TOOL_CALLS, false),
    packs: list(cfg.packs).length ? list(cfg.packs) : ["tier1"],
    trustedSenders: list(cfg.trustedSenders ?? env.SENTROOK_TRUSTED_SENDERS),
    trustedRoles: list(cfg.trustedRoles ?? env.SENTROOK_TRUSTED_ROLES),
    ...parseConfigGrants(cfg.grants),
    // Where a scheduled job or route is expected to deliver; sent as destination grants, so a cron
    // delivery to its usual channel is sanctioned even though the channel is not in the prompt.
    channelBindings: list(cfg.channelBindings),
    ...skillReviewOf(cfg.skillReview ?? env.SENTROOK_SKILL_REVIEW),
    configProblems: [...configProblems(pluginConfig), ...blockBelowReview(cfg.blockAt, reviewAt)],
  };
}

/** A configured block line below the review line is raised to it (`resolveConfig`), which is named. */
function blockBelowReview(raw: unknown, reviewAt: number): string[] {
  const block = num(raw, NaN, 0, 101);
  return block < reviewAt ? [`blockAt: below reviewAt (${reviewAt}); using ${reviewAt}`] : [];
}

function skillReviewOf(raw: unknown): { skillReview: SkillReviewSetting; skillReviewUnknown: string | null } {
  const { setting, unknown } = resolveSetting(raw);
  return { skillReview: setting, skillReviewUnknown: unknown };
}

// ---- settings not read as written -------------------------------------------------------------------------------

/**
 * What each plugin-config setting may hold, as the parsers above read it. Each check names a value the parser does
 * not read as written and what it uses instead. `null` counts as not set everywhere; blank text counts as not set
 * only where the parser reads it so (text, secrets, lists, `mode`): elsewhere it stops the env fallback and the
 * default is used, so it is named.
 */
type Spec =
  | { kind: "text" }
  | { kind: "secret" }
  | { kind: "flag"; fallback: boolean }
  | { kind: "number"; range: string; ok: (n: number) => boolean; fallback: number | string }
  /** `exact`: compared as written (no trimming, case kept); `blankUnset`: blank text is read as not set. */
  | {
      kind: "choice";
      values: readonly string[];
      caseless: boolean;
      effect: string;
      notText?: string;
      exact?: boolean;
      blankUnset?: boolean;
    }
  /** `commas`: a comma-separated string is read as the list too. */
  /** `none`: what is used when no item is read (else nothing). */
  | { kind: "list"; commas: boolean; item?: Spec; none?: string }
  | { kind: "object"; fields: Record<string, Spec> }
  | { kind: "grants" };

const TEXT: Spec = { kind: "text" };
const SECRET: Spec = { kind: "secret" };
const NAMES: Spec = { kind: "list", commas: true };
const between = (min: number, max: number, fallback: number | string): Spec => ({
  kind: "number",
  range: `from ${min} to ${max}`,
  ok: (n) => n >= min && n <= max,
  fallback,
});
const atLeast = (min: number, fallback: number): Spec => ({
  kind: "number",
  range: `of at least ${min}`,
  ok: (n) => n >= min,
  fallback,
});

const GRANT_FIELDS: Record<string, Spec> = {
  kind: { kind: "choice", values: GRANT_KINDS, caseless: false, exact: true, effect: "this grant never applies" },
  pattern: TEXT,
  allows: { kind: "list", commas: false },
  scope: {
    kind: "choice",
    values: ["session", "persistent"],
    caseless: false,
    exact: true,
    effect: "this grant is never sent",
    notText: "this grant is never sent",
  },
  granted_at: TEXT,
};

const SETTINGS: Record<string, Spec> = {
  scanUrl: TEXT,
  rookeryUrl: TEXT,
  oidcIssuer: TEXT,
  clientId: SECRET,
  clientSecret: SECRET,
  oidcAudience: SECRET,
  oidcScope: SECRET,
  mode: { kind: "choice", values: ["enforce", "observe"], caseless: true, blankUnset: true, effect: "read as enforce" },
  reviewAt: between(0, 100, DEFAULT_REVIEW_AT),
  blockAt: between(0, 101, `${DEFAULT_BLOCK_AT}, or reviewAt if higher`),
  onScanError: {
    kind: "choice",
    values: ["allow", "deny", "review"],
    caseless: true,
    effect: `using ${DEFAULT_ON_SCAN_ERROR}`,
    notText: `using ${DEFAULT_ON_SCAN_ERROR}`,
  },
  timeoutMs: atLeast(1000, DEFAULT_SCAN_TIMEOUT_MS),
  approval: {
    kind: "object",
    fields: {
      // Whole milliseconds: a fraction is rounded down, so below 1 would mean no wait at all.
      interactiveTimeoutMs: atLeast(1, DEFAULT_INTERACTIVE_APPROVAL_TIMEOUT_MS),
      scheduledIntentKinds: {
        kind: "list",
        commas: false,
        item: { kind: "choice", values: ["user", "cron", "subagent", "system"], caseless: false, effect: "ignored" },
        none: `using ${orList(DEFAULT_SCHEDULED_INTENT_KINDS)}`,
      },
    },
  },
  stateDir: TEXT,
  trafficLog: {
    kind: "object",
    fields: { enabled: { kind: "flag", fallback: true }, path: TEXT, maxBytes: atLeast(1024, DEFAULT_TRAFFIC_LOG_MAX_BYTES) },
  },
  historyLimit: between(1, 200, DEFAULT_HISTORY_LIMIT),
  inputCapBytes: atLeast(1024, DEFAULT_INPUT_CAP_BYTES),
  historyArgsCapBytes: atLeast(256, DEFAULT_HISTORY_ARGS_CAP_BYTES),
  hideToolCalls: { kind: "flag", fallback: false },
  // replaced by hideToolCalls; still accepted, does nothing
  dashboardShowCalls: { kind: "flag", fallback: false },
  packs: NAMES,
  trustedSenders: NAMES,
  trustedRoles: NAMES,
  grants: { kind: "grants" },
  channelBindings: NAMES,
  skillReview: { kind: "choice", values: ["allow", "review"], caseless: true, effect: "read as allow", notText: "read as allow" },
};

/** Every setting the plugin config may hold (the manifest documents exactly these). */
export const SETTING_NAMES: readonly string[] = Object.keys(SETTINGS);

/** The setting that hides calls from `/sentrook-why`, notices and the dashboard. */
export const HIDE_SETTING = "hideToolCalls";

/** Config text shown back to the owner: printable, no markup, short. */
function plain(raw: string, cap: number): string {
  const s = raw.replace(/[^\p{L}\p{N} ._\-:/@#~+,]/gu, "?");
  return s.length > cap ? `${s.slice(0, cap)}…` : s;
}

/** A value as quoted in a problem: text quoted and cut short, a list or object by its shape only. */
function shown(v: unknown): string {
  if (typeof v === "string") return `"${plain(v, 40)}"`;
  if (Array.isArray(v)) return "a list";
  if (v && typeof v === "object") return "an object";
  return plain(String(v), 40);
}

function orList(values: readonly string[]): string {
  return values.length < 2 ? values.join("") : `${values.slice(0, -1).join(", ")} or ${values.at(-1)}`;
}

/** Optimal string alignment distance: edits, with a swap of two neighbours counted as one. */
function distance(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** The known setting an unknown key most likely means: at most two edits away, and fewer than half its length. */
function closest(key: string, known: readonly string[]): string | null {
  let best: string | null = null;
  let bestD = Infinity;
  for (const k of known) {
    const dist = distance(key.toLowerCase(), k.toLowerCase());
    if (dist < bestD) [best, bestD] = [k, dist];
  }
  return best !== null && bestD <= 2 && bestD < key.length / 2 ? best : null;
}

function checkFields(obj: Record<string, unknown>, fields: Record<string, Spec>, prefix: string, out: string[]): void {
  const known = Object.keys(fields);
  for (const [key, value] of Object.entries(obj)) {
    const at = `${prefix}${plain(key, 40)}`;
    const spec = Object.hasOwn(fields, key) ? fields[key] : undefined;
    if (!spec) {
      // Never the value: an unknown key can hold anything, a misplaced secret included.
      const guess = closest(key, known);
      out.push(`${at}: not a Sentrook setting${guess ? ` (did you mean ${guess}?)` : ""}; ignored`);
      continue;
    }
    checkValue(value, spec, at, out);
  }
}

function blank(v: unknown): boolean {
  return typeof v === "string" && !v.trim();
}

function checkValue(v: unknown, spec: Spec, at: string, out: string[]): void {
  if (v === undefined || v === null) return;
  switch (spec.kind) {
    case "text":
      if (typeof v !== "string") out.push(`${at}: not text; ignored`);
      return;
    case "secret": {
      if (typeof v === "string") return;
      const ref = v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
      if (!ref) out.push(`${at}: not text or a SecretRef; ignored`);
      else if (ref.source !== "env" || typeof ref.id !== "string") out.push(`${at}: a SecretRef Sentrook cannot read (only source env, with an id); ignored`);
      return;
    }
    case "flag":
      if (typeof v === "boolean") return;
      if (typeof v === "string" && ["1", "true", "yes", "on", "0", "false", "no", "off"].includes(v.trim().toLowerCase())) return;
      out.push(`${at}: not true or false; using ${spec.fallback}`);
      return;
    case "number": {
      const n = typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v) : NaN;
      if (!Number.isFinite(n) || !spec.ok(n)) out.push(`${at}: not a number ${spec.range}; using ${spec.fallback}`);
      return;
    }
    case "choice": {
      if (typeof v !== "string") {
        out.push(`${at}: ${shown(v)} is not ${orList(spec.values)}; ${spec.notText ?? "ignored"}`);
        return;
      }
      if (spec.blankUnset && blank(v)) return;
      const s = spec.exact ? v : spec.caseless ? v.trim().toLowerCase() : v.trim();
      if (!spec.values.includes(s)) out.push(`${at}: ${shown(v)} is not ${orList(spec.values)}; ${spec.effect}`);
      return;
    }
    case "list": {
      if (spec.commas && typeof v === "string") return;
      if (!Array.isArray(v)) {
        if (!blank(v)) out.push(`${at}: not a list; ignored`);
        return;
      }
      const before = out.length;
      v.forEach((item, i) => {
        if (spec.item) checkValue(item, spec.item, `${at}[${i}]`, out);
        else if (typeof item !== "string") out.push(`${at}[${i}]: not text; ignored`);
      });
      if (spec.none && v.length && out.length - before === v.length) out.push(`${at}: no item read; ${spec.none}`);
      return;
    }
    case "object":
      if (blank(v)) return;
      if (!v || typeof v !== "object" || Array.isArray(v)) {
        out.push(`${at}: not an object; ignored`);
        return;
      }
      checkFields(v as Record<string, unknown>, spec.fields, `${at}.`, out);
      return;
    case "grants":
      if (blank(v)) return;
      if (!Array.isArray(v)) {
        out.push(`${at}: not a list; ignored`);
        return;
      }
      v.forEach((g, i) => {
        const gAt = `${at}[${i}]`;
        if (!g || typeof g !== "object" || Array.isArray(g)) {
          out.push(`${gAt}: not an object; ignored`);
          return;
        }
        const rec = g as Record<string, unknown>;
        if (!str(rec.kind) || !str(rec.pattern)) {
          out.push(`${gAt}: needs kind and pattern; ignored`);
          return;
        }
        checkFields(rec, GRANT_FIELDS, `${gAt}.`, out);
      });
      return;
  }
}

/** The plugin-config settings not read as written, each as `path: what; what is used instead`. */
export function configProblems(pluginConfig: unknown): string[] {
  if (pluginConfig === undefined || pluginConfig === null) return [];
  if (typeof pluginConfig !== "object" || Array.isArray(pluginConfig)) return ["the Sentrook config is not an object; ignored"];
  const out: string[] = [];
  checkFields(pluginConfig as Record<string, unknown>, SETTINGS, "", out);
  return out;
}

const NOTICE_LIMIT = 10;

/** The owner's notice about settings not read as written; `quietHours` is how long before it can come again. */
export function configProblemsNotice(problems: string[], quietHours = 6): string {
  const shownProblems = problems.slice(0, NOTICE_LIMIT).map((p) => `- ${p}`);
  const more = problems.length - NOTICE_LIMIT;
  return [
    "Sentrook cannot read some of its settings (plugins.entries.sentrook.config in openclaw.json). Scanning is on; " +
      "until you fix them, each is ignored or replaced as shown:",
    ...shownProblems,
    ...(more > 0 ? [`(and ${more} more)`] : []),
    "After fixing them, check with: openclaw sentrook verify",
    `While they stand, this notice comes at most once every ${quietHours} hours.`,
  ].join("\n");
}

/** One line for the log, status and verify. */
export function configProblemsSummary(problems: string[]): string {
  return problems.join("; ");
}
