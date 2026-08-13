/**
 * Configure helpers for `openclaw sentrook configure`.
 * Writes ~/.openclaw/.env (+ optional SENTROOK_DOTENV) and patches
 * plugins.entries.sentrook-openclaw. Does not restart the gateway.
 */

import { spawn } from "node:child_process";
import {
  chmodSync,
  chownSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

export const PLUGIN_ID = "sentrook-openclaw";

export const DEFAULT_SCAN_URL = "https://sentrook.firstdataunion.org";
export const DEFAULT_TIMEOUT_MS = 3000;
/** Contribute sanitized review feedback to the community corpus (opt-out). */
export const DEFAULT_CONTRIBUTE_CORPUS = true;
export const DEFAULT_IDENTITY_URL = "https://identity.firstdataunion.org";

export const CLIENT_ID_VAR = "SENTROOK_SCAN_CLIENT_ID";
export const CLIENT_SECRET_VAR = "SENTROOK_SCAN_CLIENT_SECRET";
export const API_KEY_VAR = "SENTROOK_SCAN_API_KEY";

export type FeedbackMode = "off" | "submit";

export interface ConfigureAnswers {
  url: string;
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
  // mode / sanitization are not configurable — always enforce + scrub.
  return {
    url: answers.url,
    timeoutMs: answers.timeoutMs,
    feedback: { mode: feedbackModeFromContribute(answers.contributeCorpus) },
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

export function upsertDotenvVar(dotenvFile: string, key: string, value: string): void {
  mkdirSync(path.dirname(dotenvFile), { recursive: true });
  const prefix = `${key}=`;
  let lines: string[] = [];
  if (existsSync(dotenvFile)) {
    lines = readFileSync(dotenvFile, "utf8").split(/\r?\n/);
  } else {
    lines = ["# OpenClaw gateway secrets (loaded at startup)"];
  }
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
  writeFileSync(dotenvFile, `${out.join("\n").replace(/\n+$/, "")}\n`, { mode: 0o600 });
  chmodSync(dotenvFile, 0o600);
  alignDotenvOwner(dotenvFile);
}

function alignDotenvOwner(file: string): void {
  try {
    if (typeof process.getuid === "function" && process.getuid() !== 0) return;
    const dir = path.dirname(file);
    const dirStat = statSync(dir);
    const fileStat = statSync(file);
    if (dirStat.uid === fileStat.uid && dirStat.gid === fileStat.gid) return;
    chownSync(file, dirStat.uid, dirStat.gid);
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
 * credential SecretRefs, plus removed `mode` / `sanitization` toggles.
 */
export function stripStalePluginConfigKeys(stateDir: string): boolean {
  const cfgPath = openclawConfigPath(stateDir);
  if (!existsSync(cfgPath)) return false;
  let cfg: Record<string, unknown>;
  try {
    cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
  } catch {
    return false;
  }
  const plugins = cfg.plugins as Record<string, unknown> | undefined;
  const entries = plugins?.entries as Record<string, unknown> | undefined;
  const entry = entries?.[PLUGIN_ID] as Record<string, unknown> | undefined;
  const config = entry?.config as Record<string, unknown> | undefined;
  if (!config) return false;

  let changed = false;
  for (const key of ["clientId", "clientSecret", "apiKey", "mode", "sanitization"] as const) {
    if (key in config) {
      delete config[key];
      changed = true;
    }
  }
  if (!changed) return false;
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`, { encoding: "utf8" });
  return true;
}

/** @deprecated Use {@link stripStalePluginConfigKeys}. */
export function stripCredentialKeysFromPluginConfig(stateDir: string): boolean {
  return stripStalePluginConfigKeys(stateDir);
}

function mergeOpenclawJsonFallback(stateDir: string, answers: ConfigureAnswers): void {
  const cfgPath = openclawConfigPath(stateDir);
  let cfg: Record<string, unknown> = {};
  if (existsSync(cfgPath)) {
    try {
      cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
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
  for (const key of ["clientId", "clientSecret", "apiKey", "mode", "sanitization"] as const) {
    delete prevConfig[key];
  }
  entries[PLUGIN_ID] = {
    enabled: true,
    config: { ...prevConfig, ...buildPluginEntryConfig(answers) },
  };
  plugins.entries = entries;
  cfg.plugins = plugins;
  writeFileSync(cfgPath, `${JSON.stringify(cfg, null, 2)}\n`, { encoding: "utf8" });
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
    "",
    "Then verify:",
    "  docker compose exec openclaw-gateway openclaw sentrook verify",
    "",
    "Optional: if you prefer keeping secrets next to Discord keys in the",
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
  io.log("    Defaults are tuned for hosted scan at sentrook.firstdataunion.org.");

  let url = seed.url ?? DEFAULT_SCAN_URL;
  if (!seed.url) {
    if (!(await io.confirm(`Use default scan URL (${DEFAULT_SCAN_URL})?`, true))) {
      url = (await io.prompt("Scan URL", DEFAULT_SCAN_URL)).trim() || DEFAULT_SCAN_URL;
    }
  }

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

  return { url, timeoutMs, contributeCorpus, clientId, clientSecret, apiKey };
}

export function collectAnswersNonInteractive(seed: Partial<ConfigureAnswers>): ConfigureAnswers {
  const url = seed.url?.trim() || DEFAULT_SCAN_URL;
  const timeoutMs =
    typeof seed.timeoutMs === "number" && seed.timeoutMs > 0
      ? seed.timeoutMs
      : DEFAULT_TIMEOUT_MS;
  const contributeCorpus = seed.contributeCorpus ?? DEFAULT_CONTRIBUTE_CORPUS;
  const clientId = seed.clientId?.trim();
  const clientSecret = seed.clientSecret?.trim();
  const apiKey = seed.apiKey?.trim();
  if (!apiKey && (!clientId || !clientSecret)) {
    throw new Error(
      "non-interactive configure requires --client-id and --client-secret " +
        `(or env ${CLIENT_ID_VAR}/${CLIENT_SECRET_VAR}); --api-key also accepted`,
    );
  }
  return { url, timeoutMs, contributeCorpus, clientId, clientSecret, apiKey };
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
