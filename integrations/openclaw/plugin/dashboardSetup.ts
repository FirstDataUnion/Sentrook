/**
 * Dashboard first-run setup: mint against Identity with the pasted credentials,
 * then write them to state-dir `.env` (never openclaw.json) and persist
 * feedback / onScanError. A failed mint must not write, so the form stays.
 */

import {
  CLIENT_ID_VAR,
  CLIENT_SECRET_VAR,
  resolveStateDir,
  sanitizeSecretInput,
  writeScanCredentials,
} from "./configure.ts";
import {
  DEFAULT_SCAN_AUDIENCE,
  DEFAULT_SCAN_ISSUER,
  DEFAULT_SCAN_SCOPE,
  clearScanTokenCache,
  getScanAccessToken,
  hasScanCredentials,
  urlRequiresScanAuth,
  type ScanAuthConfig,
} from "./auth.ts";
import { SCAN_BASE_URL } from "./scanEndpoint.ts";
import type { OnScanError } from "./scanErrorPolicy.ts";
import type { VerifyResult } from "./verify.ts";
import { runVerify } from "./verify.ts";

export type DashboardFeedbackMode = "off" | "submit";

export type DashboardPersistResult = { persisted: boolean; error?: string };

export type DashboardSetupInput = {
  clientId: string;
  clientSecret: string;
  feedbackMode: DashboardFeedbackMode;
  onScanError: OnScanError;
};

export type DashboardSetupResult = {
  ok: boolean;
  minted: boolean;
  persisted: boolean;
  error?: string;
  dotenvPath?: string;
  restartHint?: boolean;
  checks?: VerifyResult["checks"];
};

export function dashboardSetupNeeded(
  auth: ScanAuthConfig,
  scanUrl: string = SCAN_BASE_URL,
): boolean {
  return urlRequiresScanAuth(scanUrl) && !hasScanCredentials(auth);
}

/**
 * Non-empty SENTROOK_SCAN_* already in process.env win over a new `.env` write
 * (same as OpenClaw dotenv). Scans keep using the old values until restart.
 */
export function processEnvShadowsDotenvWrite(
  written: { clientId: string; clientSecret: string },
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const envId = env[CLIENT_ID_VAR]?.trim() ?? "";
  const envSecret = env[CLIENT_SECRET_VAR]?.trim() ?? "";
  if (envId && envId !== written.clientId) return true;
  if (envSecret && envSecret !== written.clientSecret) return true;
  return false;
}

export const SETUP_RESTART_HINT =
  "This gateway process already has SENTROOK_SCAN_* in its environment, so the new .env file will not be used for scans until you restart (openclaw gateway restart / docker compose restart openclaw-gateway).";

/** Operator-facing mint failures — no HTTP status or IdP error codes. */
export function formatSetupMintError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const text = raw.toLowerCase();
  if (
    /\b401\b/.test(text) ||
    /\b403\b/.test(text) ||
    text.includes("invalid_client") ||
    text.includes("invalid_grant") ||
    text.includes("unauthorized")
  ) {
    return "Those credentials were not accepted. Check the client_id and client_secret from your FIDU Identity Sentrook tab, then try again.";
  }
  if (
    text.includes("timed out") ||
    text.includes("econnrefused") ||
    text.includes("enotfound") ||
    text.includes("eai_again") ||
    text.includes("network") ||
    text.includes("fetch failed") ||
    text.includes("discovery failed")
  ) {
    return "Could not reach FIDU Identity. Check the network and try again.";
  }
  return "Could not verify these credentials. Check the client_id and client_secret, then try again.";
}

function foldPersist(
  acc: DashboardPersistResult | undefined,
  next: DashboardPersistResult,
): DashboardPersistResult {
  if (!acc) return { persisted: next.persisted, error: next.error };
  if (acc.persisted && next.persisted) return { persisted: true };
  return { persisted: false, error: acc.error || next.error };
}

export async function applyDashboardSetup(opts: {
  input: DashboardSetupInput;
  stateDir?: string;
  setFeedbackMode: (value: DashboardFeedbackMode) => DashboardPersistResult;
  setOnScanError: (value: OnScanError) => DashboardPersistResult;
  mint?: (creds: {
    clientId: string;
    clientSecret: string;
    issuer: string;
    audience: string;
    scope: string;
  }) => Promise<void>;
  verify?: (stateDir: string) => Promise<VerifyResult>;
  env?: NodeJS.ProcessEnv;
}): Promise<DashboardSetupResult> {
  const clientId = sanitizeSecretInput(opts.input.clientId);
  const clientSecret = sanitizeSecretInput(opts.input.clientSecret);
  if (!clientId || !clientSecret) {
    return {
      ok: false,
      minted: false,
      persisted: false,
      error: "client_id and client_secret are required",
    };
  }

  const stateDir = opts.stateDir ?? resolveStateDir(opts.env);
  const env = opts.env ?? process.env;

  clearScanTokenCache();
  const mint =
    opts.mint ??
    (async (creds) => {
      await getScanAccessToken(creds);
    });
  try {
    await mint({
      clientId,
      clientSecret,
      issuer: DEFAULT_SCAN_ISSUER,
      audience: DEFAULT_SCAN_AUDIENCE,
      scope: DEFAULT_SCAN_SCOPE,
    });
  } catch (err) {
    return {
      ok: false,
      minted: false,
      persisted: false,
      error: formatSetupMintError(err),
    };
  }

  let dotenvPath: string;
  try {
    dotenvPath = writeScanCredentials(stateDir, {
      timeoutMs: 14_000,
      contributeCorpus: opts.input.feedbackMode === "submit",
      clientId,
      clientSecret,
      onScanError: opts.input.onScanError,
    });
  } catch (err) {
    return {
      ok: false,
      minted: true,
      persisted: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  const persist = foldPersist(
    undefined,
    opts.setFeedbackMode(opts.input.feedbackMode),
  );
  const persist2 = foldPersist(persist, opts.setOnScanError(opts.input.onScanError));

  const verify = opts.verify ?? ((dir) => runVerify({ stateDir: dir }));
  let checks: VerifyResult["checks"] | undefined;
  try {
    checks = (await verify(stateDir)).checks;
  } catch {
    checks = undefined;
  }

  const restartHint = processEnvShadowsDotenvWrite({ clientId, clientSecret }, env);
  return {
    ok: true,
    minted: true,
    persisted: persist2.persisted,
    error: persist2.persisted ? undefined : persist2.error,
    dotenvPath,
    restartHint,
    checks,
  };
}
