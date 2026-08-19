/**
 * Configure helpers for `openclaw sentrook configure`.
 * Writes ~/.openclaw/.env (+ optional SENTROOK_DOTENV) and patches
 * plugins.entries.sentrook-openclaw. Does not restart the gateway.
 */

import { spawn } from "node:child_process";
import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fstatSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

import { parseOnScanError, type OnScanError } from "./scanErrorPolicy.ts";
import { SCAN_BASE_URL } from "./scanEndpoint.ts";

export const PLUGIN_ID = "sentrook-openclaw";

export { SCAN_BASE_URL };
export const DEFAULT_TIMEOUT_MS = 3000;
/** Contribute sanitized review feedback to the community corpus (opt-out). */
export const DEFAULT_CONTRIBUTE_CORPUS = true;
export const DEFAULT_IDENTITY_URL = "https://identity.firstdataunion.org";

export const CLIENT_ID_VAR = "SENTROOK_SCAN_CLIENT_ID";
export const CLIENT_SECRET_VAR = "SENTROOK_SCAN_CLIENT_SECRET";
export const API_KEY_VAR = "SENTROOK_SCAN_API_KEY";

export type FeedbackMode = "off" | "submit";

export interface ConfigureAnswers {
  timeoutMs: number;
  /**
   * When true, review allow-once/deny resolutions are POSTed to hosted Sentrook
   * `/feedback` for community corpus submission (Rookery). Opt-out sets false.
   */
  contributeCorpus: boolean;
  clientId?: string;
  clientSecret?: string;
  /** Optional shared API key (soak / closed beta) */
  apiKey?: string;
  /**
   * When Sentrook is unreachable or rate-limited: allow (fail-open), deny
   * (fail-closed), or review (ask, interactive only).
   */
  onScanError?: OnScanError;
}

export function feedbackModeFromContribute(contribute: boolean): FeedbackMode {
  return contribute ? "submit" : "off";
}

export interface ConfigureIo {
  log: (msg: string) => void;
  prompt: (label: string, defaultValue?: string) => Promise<string>;
  promptSecret: (label: string) => Promise<string>;
  confirm: (label: string, defaultYes?: boolean) => Promise<boolean>;
}

/**
 * OpenClaw state directory for dotenv + openclaw.json.
 *
 * Prefer OPENCLAW_STATE_DIR. OPENCLAW_HOME is the *home* root (Docker sets it to
 * /home/node), not the state dir — joining `.openclaw` matches OpenClaw docs.
 * Using HOME alone as stateDir would write credentials to an ephemeral
 * `/home/node/.env` inside the gateway while `openclaw config patch` still
 * updates the bind-mounted `~/.openclaw/openclaw.json`.
 */
export function resolveStateDir(env: NodeJS.ProcessEnv = process.env): string {
  if (env.OPENCLAW_STATE_DIR?.trim()) return env.OPENCLAW_STATE_DIR.trim();
  if (env.OPENCLAW_HOME?.trim()) {
    return path.join(env.OPENCLAW_HOME.trim(), ".openclaw");
  }
  const home = env.HOME?.trim() || "/home/node";
  return path.join(home, ".openclaw");
}

export function dotenvPath(stateDir: string): string {
  return path.join(stateDir, ".env");
}

export function openclawConfigPath(stateDir: string): string {
  return path.join(stateDir, "openclaw.json");
}

export function buildPluginEntryConfig(answers: ConfigureAnswers): Record<string, unknown> {
  // Credentials intentionally omitted from openclaw.json. Unresolved SecretRefs on an
  // enabled plugin fail-close the entire gateway; scan auth is read from
  // SENTROOK_SCAN_* in process env / ~/.openclaw/.env instead (see auth.ts).
  // mode / sanitization / url are not configurable — always enforce + scrub,
  // and the scan origin is pinned in scanEndpoint.ts.
  return {
    timeoutMs: answers.timeoutMs,
    feedback: { mode: feedbackModeFromContribute(answers.contributeCorpus) },
    onScanError: answers.onScanError ?? "allow",
  };
}

/** JSON5-ish patch body for `openclaw config patch --file`. */
export function buildConfigPatchDocument(answers: ConfigureAnswers): string {
  const entryConfig = buildPluginEntryConfig(answers);
  const configJson = JSON.stringify(entryConfig, null, 2)
    .split("\n")
    .map((line, i) => (i === 0 ? line : `          ${line}`))
    .join("\n");

  return `{
  plugins: {
    entries: {
      "${PLUGIN_ID}": {
        enabled: true,
        config: ${configJson}
      }
    }
  }
}
`;
}

function errnoCode(err: unknown): string | undefined {
  if (err && typeof err === "object" && "code" in err && typeof err.code === "string") {
    return err.code;
  }
  return undefined;
}

/** Open path once so a symlink swap cannot retarget the later read/write (TOCTOU). */
function openReadWriteSync(
  filePath: string,
  opts: { create: boolean; mode?: number },
): { fd: number; created: boolean } | null {
  try {
    return { fd: openSync(filePath, constants.O_RDWR), created: false };
  } catch (err) {
    if (errnoCode(err) !== "ENOENT") throw err;
    if (!opts.create) return null;
  }
  try {
    return {
      fd: openSync(
        filePath,
        constants.O_RDWR | constants.O_CREAT | constants.O_EXCL,
        opts.mode ?? 0o666,
      ),
      created: true,
    };
  } catch (err) {
    if (errnoCode(err) !== "EEXIST") throw err;
    return { fd: openSync(filePath, constants.O_RDWR), created: false };
  }
}

function writeAllFdSync(fd: number, text: string): void {
  const buf = Buffer.from(text, "utf8");
  ftruncateSync(fd, buf.byteLength);
  writeSync(fd, buf, 0, buf.byteLength, 0);
}

function stripTrailingNewlines(text: string): string {
  let end = text.length;
  while (end > 0 && (text[end - 1] === "\n" || text[end - 1] === "\r")) {
    end -= 1;
  }
  return text.slice(0, end);
}

export function upsertDotenvVar(dotenvFile: string, key: string, value: string): void {
  mkdirSync(path.dirname(dotenvFile), { recursive: true });
  const prefix = `${key}=`;
  const opened = openReadWriteSync(dotenvFile, { create: true, mode: 0o600 });
  if (!opened) throw new Error(`could not open ${dotenvFile}`);
  const { fd, created } = opened;
  try {
    const lines = created
      ? ["# OpenClaw gateway secrets (loaded at startup)"]
      : readFileSync(fd, "utf8").split(/\r?\n/);
    let found = false;
    const out: string[] = [];
    for (const line of lines) {
      if (line.startsWith(prefix)) {
        out.push(prefix + value);
        found = true;
      } else {
        out.push(line);
      }
    }
    if (!found) {
      if (out.length && out[out.length - 1]!.trim() !== "") out.push("");
      out.push(prefix + value);
    }
    writeAllFdSync(fd, `${stripTrailingNewlines(out.join("\n"))}\n`);
    fchmodSync(fd, 0o600);
    alignDotenvOwnerFd(fd, dotenvFile);
  } finally {
    closeSync(fd);
  }
}

function alignDotenvOwnerFd(fd: number, file: string): void {
  try {
    if (typeof process.getuid === "function" && process.getuid() !== 0) return;
    const dirStat = statSync(path.dirname(file));
    const fileStat = fstatSync(fd);
    if (dirStat.uid === fileStat.uid && dirStat.gid === fileStat.gid) return;
    fchownSync(fd, dirStat.uid, dirStat.gid);
  } catch {
    // Best-effort; SecretRef EACCES is the failure mode if this cannot run.
  }
}

/**
 * Strip terminal focus / CSI / C0 junk that raw-mode secret prompts can capture
 * when the TTY gains/loses focus during paste (`ESC[I` / `ESC[O`, etc.).
 */
export function sanitizeSecretInput(raw: string): string {
  let s = raw.replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "");
  s = s.replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, "");
  s = s.replace(/\u001b./g, "");
  s = s.replace(/[\u0000-\u001f\u007f]/g, "");
  return s.trim();
}

export function writeScanCredentials(stateDir: string, answers: ConfigureAnswers): string {
  const clientId = answers.clientId ? sanitizeSecretInput(answers.clientId) : "";
  const clientSecret = answers.clientSecret
    ? sanitizeSecretInput(answers.clientSecret)
    : "";
  const apiKey = answers.apiKey ? sanitizeSecretInput(answers.apiKey) : "";

  if (answers.clientId != null || answers.clientSecret != null) {
    if (!clientId || !clientSecret) {
      throw new Error("client_id and client_secret must be non-empty");
    }
  } else if (answers.apiKey != null) {
    if (!apiKey) {
      throw new Error("api key must be non-empty");
    }
  } else {
    throw new Error("OIDC client_id + client_secret are required (or --api-key)");
  }

  const dotenv = dotenvPath(stateDir);
  if (clientId && clientSecret) {
    upsertDotenvVar(dotenv, CLIENT_ID_VAR, clientId);
    upsertDotenvVar(dotenv, CLIENT_SECRET_VAR, clientSecret);
  } else if (apiKey) {
    upsertDotenvVar(dotenv, API_KEY_VAR, apiKey);
  }

  // Extra write target: compose project .env (Docker). Only works if the path is
  // visible inside this process (host-side configure, or a mounted OPENCLAW_DIR).
  const extra = process.env.SENTROOK_DOTENV?.trim() || process.env.OPENCLAW_COMPOSE_ENV?.trim();
  if (extra && path.resolve(extra) !== path.resolve(dotenv)) {
    if (clientId && clientSecret) {
      upsertDotenvVar(extra, CLIENT_ID_VAR, clientId);
      upsertDotenvVar(extra, CLIENT_SECRET_VAR, clientSecret);
    } else if (apiKey) {
      upsertDotenvVar(extra, API_KEY_VAR, apiKey);
    }
  }

  return dotenv;
}

async function runOpenclaw(
  bin: string,
  args: string[],
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return await new Promise((resolve) => {
    const child = spawn(bin, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer | string) => {
      stdout += String(chunk);
    });
    child.stderr?.on("data", (chunk: Buffer | string) => {
      stderr += String(chunk);
    });
    child.on("error", (err) => {
      resolve({ status: 1, stdout, stderr: err.message });
    });
    child.on("close", (status) => {
      resolve({ status, stdout, stderr });
    });
  });
}

/** TTY spinner while awaiting slow openclaw CLI work (spawnSync blocks the event loop). */
export async function withSpinner<T>(
  label: string,
  work: () => Promise<T>,
  opts: { enabled?: boolean; stream?: NodeJS.WriteStream } = {},
): Promise<T> {
  const stream = opts.stream ?? process.stderr;
  const enabled =
    opts.enabled ??
    (Boolean(stream.isTTY) && !process.env.CI && process.env.SENTROOK_NO_SPINNER !== "1");

  if (!enabled) {
    stream.write(`==> ${label}...\n`);
    return await work();
  }

  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  let i = 0;
  stream.write(`${frames[0]} ${label}`);
  const timer = setInterval(() => {
    i = (i + 1) % frames.length;
    stream.write(`\r${frames[i]} ${label}`);
  }, 80);

  try {
    const result = await work();
    clearInterval(timer);
    stream.write(`\r\x1b[K✓ ${label}\n`);
    return result;
  } catch (err) {
    clearInterval(timer);
    stream.write(`\r\x1b[K✗ ${label}\n`);
    throw err;
  }
}

export async function applyConfigPatch(
  stateDir: string,
  answers: ConfigureAnswers,
  opts: { openclawBin?: string; allowJsonFallback?: boolean } = {},
): Promise<{ method: "cli" | "json-fallback" }> {
  mkdirSync(stateDir, { recursive: true });
  const patchPath = path.join(stateDir, "sentrook-configure.patch.json5");
  writeFileSync(patchPath, buildConfigPatchDocument(answers), { encoding: "utf8" });

  const bin = opts.openclawBin || process.env.OPENCLAW_BIN || "openclaw";
  const patch = await runOpenclaw(bin, ["config", "patch", "--file", patchPath]);
  if (patch.status === 0) {
    await runOpenclaw(bin, ["config", "validate"]);
    await runOpenclaw(bin, ["plugins", "enable", PLUGIN_ID]);
    // Config patch deep-merges; strip stale SecretRef keys so missing env cannot
    // fail-close gateway startup on older installs.
    stripStalePluginConfigKeys(stateDir);
    return { method: "cli" };
  }

  if (opts.allowJsonFallback === false) {
    const detail = (patch.stderr || patch.stdout || "").trim();
    throw new Error(
      `openclaw config patch failed (exit ${patch.status ?? "?"})${detail ? `: ${detail}` : ""}`,
    );
  }

  mergeOpenclawJsonFallback(stateDir, answers);
  return { method: "json-fallback" };
}

/**
 * Remove stale plugin config keys that older configure versions wrote:
 * credential SecretRefs, removed `mode` / `sanitization` toggles, and `url`
 * (scan origin is pinned in scanEndpoint.ts).
 */
export function stripStalePluginConfigKeys(stateDir: string): boolean {
  const cfgPath = openclawConfigPath(stateDir);
  const opened = openReadWriteSync(cfgPath, { create: false });
  if (!opened) return false;
  const { fd } = opened;
  try {
    let cfg: Record<string, unknown>;
    try {
      cfg = JSON.parse(readFileSync(fd, "utf8")) as Record<string, unknown>;
    } catch (err) {
      if (err instanceof SyntaxError) return false;
      throw err;
    }
    const plugins = cfg.plugins as Record<string, unknown> | undefined;
    const entries = plugins?.entries as Record<string, unknown> | undefined;
    const entry = entries?.[PLUGIN_ID] as Record<string, unknown> | undefined;
    const config = entry?.config as Record<string, unknown> | undefined;
    if (!config) return false;

    let changed = false;
    for (const key of ["clientId", "clientSecret", "apiKey", "mode", "sanitization", "url"] as const) {
      if (key in config) {
        delete config[key];
        changed = true;
      }
    }
    if (!changed) return false;
    writeAllFdSync(fd, `${JSON.stringify(cfg, null, 2)}\n`);
    return true;
  } finally {
    closeSync(fd);
  }
}

/** @deprecated Use {@link stripStalePluginConfigKeys}. */
export function stripCredentialKeysFromPluginConfig(stateDir: string): boolean {
  return stripStalePluginConfigKeys(stateDir);
}

function mergeOpenclawJsonFallback(stateDir: string, answers: ConfigureAnswers): void {
  const cfgPath = openclawConfigPath(stateDir);
  const opened = openReadWriteSync(cfgPath, { create: true });
  if (!opened) throw new Error(`could not open ${cfgPath}`);
  const { fd, created } = opened;
  try {
    let cfg: Record<string, unknown> = {};
    if (!created) {
      try {
        cfg = JSON.parse(readFileSync(fd, "utf8")) as Record<string, unknown>;
      } catch {
        throw new Error(
          `Could not run openclaw config patch and ${cfgPath} is not strict JSON. ` +
            "Fix config manually or ensure openclaw is on PATH.",
        );
      }
    }
    const plugins = (cfg.plugins as Record<string, unknown>) ?? {};
    const entries = (plugins.entries as Record<string, unknown>) ?? {};
    const prev = entries[PLUGIN_ID] as Record<string, unknown> | undefined;
    const prevConfig =
      prev?.config && typeof prev.config === "object"
        ? { ...(prev.config as Record<string, unknown>) }
        : {};
    for (const key of ["clientId", "clientSecret", "apiKey", "mode", "sanitization", "url"] as const) {
      delete prevConfig[key];
    }
    entries[PLUGIN_ID] = {
      enabled: true,
      config: { ...prevConfig, ...buildPluginEntryConfig(answers) },
    };
    plugins.entries = entries;
    cfg.plugins = plugins;
    writeAllFdSync(fd, `${JSON.stringify(cfg, null, 2)}\n`);
  } finally {
    closeSync(fd);
  }
}

export function restartHint(dotenvWritten?: string): string {
  const dotenv = dotenvWritten || "~/.openclaw/.env";
  return [
    "Configuration written.",
    `  Credentials: ${dotenv} (OpenClaw loads this on gateway start).`,
    "  Plugin config: openclaw.json (enable + URL).",
    "",
    "Reload the gateway process (restart is enough — you do NOT need",
    "docker compose force-recreate for ~/.openclaw/.env changes):",
    "  docker compose restart openclaw-gateway",
    "  # native: openclaw gateway restart",
    "  # `openclaw-gateway` is OpenClaw's default Compose service name.",
    "  # Yours may differ (`docker compose ps`). Use the service name, not a",
    "  # `docker ps` container name like openclaw-gateway-1.",
    "",
    "Then verify:",
    "  docker compose exec openclaw-gateway openclaw sentrook verify",
    "",
    "Optional: if you prefer keeping secrets in the",
    "compose project env_file (~/openclaw/.env), also merge SENTROOK_SCAN_*",
    "there — that path needs `docker compose up -d --force-recreate` because",
    "Compose only injects env_file at container create time.",
  ].join("\n");
}

export async function createStdioIo(): Promise<ConfigureIo & { close: () => void }> {
  const rl = createInterface({ input, output });
  const io: ConfigureIo & { close: () => void } = {
    log: (msg) => console.log(msg),
    prompt: async (label, defaultValue) => {
      const suffix = defaultValue !== undefined ? ` [${defaultValue}]` : "";
      const answer = await rl.question(`${label}${suffix}: `);
      const trimmed = answer.trim();
      return trimmed || defaultValue || "";
    },
    promptSecret: async (label) => promptSecretRaw(`${label}: `),
    confirm: async (label, defaultYes = true) => {
      const hint = defaultYes ? "Y/n" : "y/N";
      const answer = (await rl.question(`${label} [${hint}]: `)).trim().toLowerCase();
      if (!answer) return defaultYes;
      return answer === "y" || answer === "yes";
    },
    close: () => rl.close(),
  };
  return io;
}

async function promptSecretRaw(label: string): Promise<string> {
  if (!input.isTTY) {
    throw new Error("secret prompt requires a TTY (or pass --client-secret / env)");
  }
  output.write(label);
  return await new Promise<string>((resolve, reject) => {
    const stdin = input;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let buf = "";
    /** Incomplete ESC / CSI sequence (focus events, bracketed paste, …). */
    let esc = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (esc) {
          esc += ch;
          if (esc.startsWith("\u001b[")) {
            const code = ch.charCodeAt(0);
            // CSI final byte is 0x40–0x7E (`ESC[I` / `ESC[O` focus, paste markers, …).
            if (code >= 0x40 && code <= 0x7e) esc = "";
            continue;
          }
          // Other ESC-prefixed controls: drop once we have the follower byte.
          if (esc.length >= 2) esc = "";
          continue;
        }
        if (ch === "\u001b") {
          esc = ch;
          continue;
        }
        if (ch === "\n" || ch === "\r" || ch === "\u0004") {
          cleanup();
          output.write("\n");
          resolve(sanitizeSecretInput(buf));
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          reject(new Error("interrupted"));
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          buf = buf.slice(0, -1);
          continue;
        }
        if (ch === "\u0015") {
          buf = "";
          continue;
        }
        // Ignore other C0 controls; keep printable secret characters only.
        if (ch.charCodeAt(0) < 0x20) continue;
        buf += ch;
      }
    };
    const cleanup = () => {
      stdin.off("data", onData);
      if (wasRaw === false) stdin.setRawMode?.(false);
    };
    stdin.on("data", onData);
  });
}

export async function collectAnswersInteractive(
  io: ConfigureIo,
  seed: Partial<ConfigureAnswers> = {},
): Promise<ConfigureAnswers> {
  io.log("==> Sentrook configure");
  io.log(`    Scan endpoint is pinned to ${SCAN_BASE_URL} (not configurable).`);

  let timeoutMs = seed.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (seed.timeoutMs === undefined) {
    if (!(await io.confirm(`Use default timeout (${DEFAULT_TIMEOUT_MS}ms)?`, true))) {
      const raw = await io.prompt("Timeout ms", String(DEFAULT_TIMEOUT_MS));
      const n = Number.parseInt(raw, 10);
      timeoutMs = Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
    }
  }

  let contributeCorpus = seed.contributeCorpus ?? DEFAULT_CONTRIBUTE_CORPUS;
  if (seed.contributeCorpus === undefined) {
    io.log("");
    io.log("==> Community corpus");
    io.log("    When you allow-once or deny a Sentrook review, a sanitized trajectory");
    io.log("    example can be submitted to the community corpus (via hosted Sentrook");
    io.log("    → Rookery). Humans still approve before anything is published.");
    io.log("    Secrets/PII are redacted; you can change this later in openclaw.json.");
    contributeCorpus = await io.confirm(
      "Contribute review feedback to the community corpus? (opt out with n)",
      true,
    );
  }

  let clientId = seed.clientId;
  let clientSecret = seed.clientSecret;
  const apiKey = seed.apiKey;

  if (!apiKey && (!clientId || !clientSecret)) {
    io.log("");
    io.log("==> Scan auth (OIDC client credentials)");
    io.log(`    Create a Sentrook scan OAuth client at:`);
    io.log(`      ${DEFAULT_IDENTITY_URL}`);
    io.log("      → Sentrook tab → grant_types=client_credentials, scope sentrook.scan");
    io.log("    Paste client_id and client_secret below (access tokens are minted at runtime).");
    clientId = sanitizeSecretInput(await io.prompt("OAuth client_id"));
    clientSecret = sanitizeSecretInput(await io.promptSecret("OAuth client_secret"));
  }

  let onScanError: OnScanError = seed.onScanError ?? "review";
  if (seed.onScanError === undefined) {
    io.log("");
    io.log("==> When Sentrook is unreachable or rate-limited");
    io.log("    allow  = continue the tool without scanning (old default)");
    io.log("    deny   = block the tool");
    io.log("    review = ask you first (recommended for hosted HTTPS)");
    const raw = await io.prompt(`onScanError [${onScanError}]`, onScanError);
    onScanError = parseOnScanError(raw, onScanError);
  }

  return { timeoutMs, contributeCorpus, clientId, clientSecret, apiKey, onScanError };
}

export function collectAnswersNonInteractive(seed: Partial<ConfigureAnswers>): ConfigureAnswers {
  const timeoutMs =
    typeof seed.timeoutMs === "number" && seed.timeoutMs > 0
      ? seed.timeoutMs
      : DEFAULT_TIMEOUT_MS;
  const contributeCorpus = seed.contributeCorpus ?? DEFAULT_CONTRIBUTE_CORPUS;
  const clientId = seed.clientId?.trim();
  const clientSecret = seed.clientSecret?.trim();
  const apiKey = seed.apiKey?.trim();
  const onScanError = seed.onScanError ?? "allow";
  if (!apiKey && (!clientId || !clientSecret)) {
    throw new Error(
      "non-interactive configure requires --client-id and --client-secret " +
        `(or env ${CLIENT_ID_VAR}/${CLIENT_SECRET_VAR}); --api-key also accepted`,
    );
  }
  return { timeoutMs, contributeCorpus, clientId, clientSecret, apiKey, onScanError };
}

export async function runConfigure(
  answers: ConfigureAnswers,
  opts: { stateDir?: string; openclawBin?: string; log?: (m: string) => void } = {},
): Promise<void> {
  const log = opts.log ?? ((m: string) => console.log(m));
  const stateDir = opts.stateDir ?? resolveStateDir();
  const dotenv = writeScanCredentials(stateDir, answers);
  log(`==> Wrote scan credentials to ${dotenv} (chmod 600)`);
  const extra = process.env.SENTROOK_DOTENV?.trim() || process.env.OPENCLAW_COMPOSE_ENV?.trim();
  if (extra) {
    log(`==> Also wrote credentials to ${extra} (SENTROOK_DOTENV / OPENCLAW_COMPOSE_ENV)`);
  }
  log("==> Updating openclaw.json (openclaw config patch can take 10–30s)…");
  const applied = await withSpinner("Patching openclaw.json + enabling plugin", () =>
    applyConfigPatch(stateDir, answers, {
      openclawBin: opts.openclawBin,
    }),
  );
  log(
    applied.method === "cli"
      ? "==> Patched openclaw.json via openclaw config patch"
      : "==> Patched openclaw.json via direct JSON merge (openclaw CLI patch unavailable)",
  );
  log(restartHint(dotenv));
}
