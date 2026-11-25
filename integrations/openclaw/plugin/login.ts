/**
 * `openclaw sentrook login`: sign in in a browser and store the scan credentials, so nobody copies them by hand.
 *
 * An OAuth device sign-in (RFC 8628) against the identity service, with the public client `sentrook-plugin`. The
 * user opens the printed link on any device, signs in or creates an account, and approves. The identity service
 * then hands this install its own scan client id and secret, once. Signing in again from the same install (same
 * device id, kept in the state folder) replaces that install's credential rather than adding one.
 *
 * The two values go into OpenClaw's state-dir `.env` (mode 0600), which OpenClaw documents as the place for keys
 * and which the plugin already reads. Nothing the identity service writes is printed, and never the secret.
 */

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, closeSync } from "node:fs";
import { hostname as osHostname } from "node:os";
import path from "node:path";

import { CLIENT_ID_VAR, CLIENT_SECRET_VAR, parseDotenvText } from "./auth.ts";
import { openclawDir, resolveConfig } from "./config.ts";

export const CLIENT_ID = "sentrook-plugin";
export const SCOPE = "sentrook.scan";
export const DEVICE_NAME_MAX = 64;
export const DEVICE_ID_FILE = "device-id";
const DEFAULT_INTERVAL_S = 5;
const DEFAULT_EXPIRES_S = 600;
const DEVICE_ID = /^[0-9a-f]{32,64}$/;
const CLIENT_ID_OK = /^[A-Za-z0-9._-]{1,100}$/;
const SECRET_OK = /^[A-Za-z0-9._~+/=-]{16,256}$/;
/** A link is printed as it came, so it may hold only visible ASCII: no escape sequences, spaces or line breaks. */
const PRINTABLE_URL = /^[\x21-\x7e]{1,2048}$/;

export const EXIT_OK = 0;
export const EXIT_FAILED = 1;
export const EXIT_CANCELLED = 130;

export const RESTART_LINE = "Restart the gateway to use the new credentials: openclaw gateway restart";

/** A failure with the line to print. */
class LoginError extends Error {}

/** Thrown by `sleep` (or anything else) when the user presses Ctrl-C. */
export class Cancelled extends Error {}

export interface Saved {
  /** The text after "Credentials saved". */
  where: string;
  /** Earlier values were replaced: the running gateway still has them until it restarts. */
  replacedEarlier: boolean;
}

export interface LoginDeps {
  fetchImpl: typeof fetch;
  sleep: (seconds: number) => Promise<void>;
  now: () => number;
  out: (line: string) => void;
  hostname: () => string;
  save: (values: Record<string, string>) => Saved;
  /** The checks after saving: the report and whether all passed. */
  verify?: (values: Record<string, string>) => Promise<{ report: string; ok: boolean }>;
  timeoutMs: number;
  /** Aborted when the user presses Ctrl-C: ends a request or a wait at once, with nothing changed. */
  cancel?: AbortSignal;
}

/**
 * Plain text the identity service accepts: letters, marks, numbers, punctuation, symbols and the ASCII space;
 * anything else becomes a space; runs of spaces collapse; at most 64 characters.
 */
export function cleanDeviceName(raw: string | undefined, host: string): string {
  const kept = [...(raw ?? "")].map((c) => (c === " " || /[\p{L}\p{M}\p{N}\p{P}\p{S}]/u.test(c) ? c : " ")).join("");
  const text = [...kept.split(" ").filter(Boolean).join(" ")].slice(0, DEVICE_NAME_MAX).join("").trim();
  if (text) return text;
  return host ? cleanDeviceName(`OpenClaw on ${host}`, "") : "OpenClaw";
}

/** This install's id: created once in the state folder, reused on every later sign-in. */
export function deviceId(stateDir: string): string {
  const file = path.join(stateDir, DEVICE_ID_FILE);
  try {
    const existing = readFileSync(file, "utf8").trim();
    if (DEVICE_ID.test(existing)) return existing;
  } catch {
    // No id yet.
  }
  const id = randomBytes(16).toString("hex");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  writeFileSync(file, `${id}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return id;
}

const KEY_LINE = (key: string) => new RegExp(`^\\s*(?:export\\s+)?${key}\\s*=`);

/**
 * Write the values into OpenClaw's state-dir `.env`: lines for these keys are replaced (also `export KEY=`), every
 * other line is kept as it was, and the file is replaced in one step with mode 0600.
 */
export function saveToOpenclawDotenv(env: NodeJS.ProcessEnv, values: Record<string, string>): Saved {
  const dir = openclawDir(env);
  const file = path.join(dir, ".env");
  const lines = existsSync(file) ? readFileSync(file, "utf8").split(/\r?\n/) : [];
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  let replacedEarlier = false;
  const kept = lines.filter((line) => {
    const ours = Object.keys(values).some((key) => KEY_LINE(key).test(line));
    if (ours && !/=\s*$/.test(line)) replacedEarlier = true;
    return !ours;
  });
  const next = [...kept, ...Object.entries(values).map(([k, v]) => `${k}=${v}`)].join("\n") + "\n";
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `.env.sentrook-${process.pid}-${randomBytes(4).toString("hex")}`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeFileSync(fd, next);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
  return { where: `to ${file}`, replacedEarlier };
}

function origin(url: string): string {
  try {
    return new URL(url).origin.toLowerCase();
  } catch {
    return "";
  }
}

const outside = (issuer: string) =>
  new LoginError(`Sign-in failed: the identity service gave a sign-in address outside ${issuer}.`);

async function request(
  deps: LoginDeps,
  url: string,
  form?: Record<string, string>,
): Promise<{ status: number; body: unknown }> {
  const res = await deps.fetchImpl(url, {
    method: form ? "POST" : "GET",
    headers: form
      ? { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }
      : { accept: "application/json" },
    body: form ? new URLSearchParams(form).toString() : undefined,
    redirect: "error",
    signal: deps.cancel ? AbortSignal.any([AbortSignal.timeout(deps.timeoutMs), deps.cancel]) : AbortSignal.timeout(deps.timeoutMs),
  }).catch((err) => {
    throw deps.cancel?.aborted ? new Cancelled() : err;
  });
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // Not JSON: kept as text, never printed.
  }
  return { status: res.status, body };
}

function startLines(url: string, userCode: string, expiresIn: number): string[] {
  const minutes = Math.max(1, Math.ceil(expiresIn / 60));
  return [
    "Sign in to connect Sentrook on this machine:",
    "",
    `  ${url}`,
    "",
    `Open the link on any device, sign in or create a free FIDU account, and check the code matches: ${userCode}`,
    `Waiting for approval (the code expires in ${minutes} ${minutes === 1 ? "minute" : "minutes"}; Ctrl-C to cancel)...`,
  ];
}

function usable(body: unknown): Record<string, string> | null {
  if (!body || typeof body !== "object") return null;
  const { client_id: id, client_secret: secret } = body as Record<string, unknown>;
  if (typeof id !== "string" || !CLIENT_ID_OK.test(id)) return null;
  if (typeof secret !== "string" || !SECRET_OK.test(secret)) return null;
  return { [CLIENT_ID_VAR]: id, [CLIENT_SECRET_VAR]: secret };
}

const errorOf = (body: unknown): unknown =>
  body && typeof body === "object" ? (body as Record<string, unknown>).error : undefined;

/** The device flow up to the credentials; throws LoginError with the line to print. */
async function signIn(issuer: string, name: string, devId: string, deps: LoginDeps): Promise<Record<string, string>> {
  const discovery = await request(deps, `${issuer}/.well-known/openid-configuration`);
  const endpoint = (discovery.body as Record<string, unknown> | null)?.device_authorization_endpoint;
  if (discovery.status !== 200 || typeof endpoint !== "string" || !endpoint) {
    throw new LoginError("Sign-in failed: the identity service did not answer as expected. Try again later.");
  }
  if (origin(endpoint) !== origin(issuer)) throw outside(issuer);

  const code = await request(deps, endpoint, { client_id: CLIENT_ID, scope: SCOPE, device_name: name, device_id: devId });
  if ((code.status === 400 || code.status === 401) && errorOf(code.body) === "invalid_client") {
    throw new LoginError(
      "Sign-in failed: this identity service does not offer plugin sign-in. Set the credentials by hand instead (see the install guide).",
    );
  }
  if (code.status !== 200 || !code.body || typeof code.body !== "object") {
    throw new LoginError(`Sign-in failed: the identity service answered HTTP ${code.status}. Try again later.`);
  }
  const c = code.body as Record<string, unknown>;
  // The complete link when given, else the plain one (an empty value counts as not given).
  const url = c.verification_uri_complete || c.verification_uri;
  if (typeof c.device_code !== "string" || typeof c.user_code !== "string" || typeof url !== "string") {
    throw new LoginError("Sign-in failed: the identity service did not answer as expected. Try again later.");
  }
  if (!PRINTABLE_URL.test(url)) {
    throw new LoginError("Sign-in failed: the identity service gave a sign-in link that cannot be shown safely.");
  }
  if (origin(url) !== origin(issuer) || !/^[0-9A-Z-]{4,16}$/.test(c.user_code)) throw outside(issuer);
  let interval = Math.max(1, Number.isInteger(c.interval) ? (c.interval as number) : DEFAULT_INTERVAL_S);
  const expiresIn = Number.isInteger(c.expires_in) ? (c.expires_in as number) : DEFAULT_EXPIRES_S;
  const deadline = deps.now() + expiresIn;

  for (const line of startLines(url, c.user_code, expiresIn)) deps.out(line);

  const expired = () => new LoginError("The code expired before it was approved. Run openclaw sentrook login again.");
  const pollUrl = `${issuer}/oauth/device/sentrook-credentials`;
  while (true) {
    await deps.sleep(interval);
    if (deps.now() >= deadline) throw expired();
    let answer: { status: number; body: unknown };
    try {
      answer = await request(deps, pollUrl, { client_id: CLIENT_ID, device_code: c.device_code });
    } catch (err) {
      if (err instanceof Cancelled) throw err;
      continue; // a network blip or a timeout: ask again on the next turn
    }
    if (answer.status === 200) {
      const values = usable(answer.body);
      if (!values) {
        throw new LoginError(
          "Sign-in failed: the identity service's answer could not be used. Run openclaw sentrook login again.",
        );
      }
      return values;
    }
    const error = errorOf(answer.body);
    if (error === "authorization_pending") continue;
    if (error === "slow_down" || answer.status === 429) {
      interval += 5;
      continue;
    }
    if (error === "access_denied") throw new LoginError("Sign-in was denied in the browser. Nothing was changed.");
    if (error === "expired_token") throw expired();
    if (error === "credential_limit") {
      throw new LoginError(
        "This account already has the most Sentrook connections allowed. Remove one you no longer use at " +
          `${issuer}/dashboard#sentrook, then run openclaw sentrook login again.`,
      );
    }
    if (answer.status >= 500) continue;
    throw new LoginError(
      `Sign-in failed: the identity service refused the sign-in (HTTP ${answer.status}). Run openclaw sentrook login again.`,
    );
  }
}

/**
 * Where credentials that would win over the state-dir `.env` are set, or null. The plugin resolves the plugin
 * config first, then the process environment, then `.env`: a plain value in the config, a SecretRef naming other
 * variables, or a value in the gateway's environment that `.env` did not put there would keep the new
 * credentials from ever being used.
 */
export function credentialsSetElsewhere(
  pluginConfig: Record<string, unknown>,
  processEnv: NodeJS.ProcessEnv,
  withDotenv: NodeJS.ProcessEnv,
): string | null {
  for (const [key, envVar] of [["clientId", CLIENT_ID_VAR], ["clientSecret", CLIENT_SECRET_VAR]] as const) {
    const raw = pluginConfig[key];
    if (typeof raw === "string" && raw.trim()) return `OpenClaw's plugin config (plugins.entries.sentrook.config.${key})`;
    if (raw && typeof raw === "object") {
      const ref = raw as { source?: unknown; id?: unknown };
      if (ref.source === "env" && typeof ref.id === "string" && ref.id !== envVar) {
        return `the variable ${ref.id} (plugins.entries.sentrook.config.${key} points to it)`;
      }
    }
  }
  const dotenv = dotenvValues(withDotenv);
  for (const envVar of [CLIENT_ID_VAR, CLIENT_SECRET_VAR]) {
    const value = processEnv[envVar]?.trim();
    // OpenClaw loads `.env` into its own environment at start, so a value equal to the file's came from it.
    if (value && value !== dotenv[envVar]) return `the gateway's environment (${envVar})`;
  }
  return null;
}

function dotenvValues(env: NodeJS.ProcessEnv): Record<string, string> {
  try {
    return parseDotenvText(readFileSync(path.join(openclawDir(env), ".env"), "utf8"));
  } catch {
    return {};
  }
}

export function defaultLoginDeps(env: NodeJS.ProcessEnv): LoginDeps {
  return {
    fetchImpl: fetch,
    sleep: (s) => new Promise((resolve) => setTimeout(resolve, s * 1000)),
    now: () => performance.now() / 1000,
    out: (line) => console.log(line),
    hostname: osHostname,
    save: (values) => saveToOpenclawDotenv(env, values),
    timeoutMs: 15_000,
  };
}

/** Sign in, store the credentials, run the checks. Returns the exit code. */
export async function runLogin(
  pluginConfig: Record<string, unknown>,
  opts: {
    name?: string;
    /** The environment with OpenClaw's state-dir `.env` filled in (`envWithOpenclawDotenv`). */
    env: NodeJS.ProcessEnv;
    /** The process environment alone, to tell values that come from `.env` from values set elsewhere. */
    processEnv?: NodeJS.ProcessEnv;
    deps: LoginDeps;
  },
): Promise<number> {
  const { deps } = opts;
  const cfg = resolveConfig(pluginConfig, opts.env);
  const issuer = cfg.endpoints.issuer;
  if (!issuer.ok) {
    deps.out(`Sign-in failed: the OIDC issuer setting is not usable (${issuer.reason}).`);
    return EXIT_FAILED;
  }
  const elsewhere = credentialsSetElsewhere(pluginConfig, opts.processEnv ?? {}, opts.env);
  if (elsewhere) {
    deps.out(
      `Sentrook's credentials are already set in ${elsewhere}, which wins over the .env file this command writes. ` +
        "Remove them there first, then run openclaw sentrook login again.",
    );
    return EXIT_FAILED;
  }
  const issuerUrl = issuer.url.replace(/\/+$/, "");
  const name = cleanDeviceName(opts.name, deps.hostname());
  let values: Record<string, string>;
  try {
    values = await signIn(issuerUrl, name, deviceId(cfg.stateDir), deps);
  } catch (err) {
    if (err instanceof Cancelled || deps.cancel?.aborted) {
      deps.out("Cancelled. Nothing was changed.");
      return EXIT_CANCELLED;
    }
    if (err instanceof LoginError) {
      deps.out(err.message);
      return EXIT_FAILED;
    }
    deps.out(`Sign-in failed: could not reach the identity service (${(err as Error)?.name ?? "error"}). Try again later.`);
    return EXIT_FAILED;
  }

  let saved: Saved;
  try {
    saved = deps.save(values);
  } catch (err) {
    deps.out(
      `Signed in, but the credentials could not be written (${(err as NodeJS.ErrnoException)?.code ?? "error"}). ` +
        "Check that you run this as the user that runs the gateway, then run openclaw sentrook login again.",
    );
    return EXIT_FAILED;
  }
  deps.out(`Connected as "${name}". Credentials saved ${saved.where}.`);
  if (saved.replacedEarlier) deps.out(RESTART_LINE);
  deps.out("");
  if (!deps.verify) return EXIT_OK;
  const { report, ok } = await deps.verify(values);
  deps.out(report);
  if (!ok) {
    deps.out("Signed in, but a check above failed. Fix it, then run openclaw sentrook verify.");
    return EXIT_FAILED;
  }
  return EXIT_OK;
}
