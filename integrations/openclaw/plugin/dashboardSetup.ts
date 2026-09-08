/**
 * Dashboard first-run setup: write scan credentials to state-dir `.env`
 * (never openclaw.json), persist feedback / onScanError, then mint.
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
      minted: false,
      persisted: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  const persist = foldPersist(
    undefined,
    opts.setFeedbackMode(opts.input.feedbackMode),
  );
  const persist2 = foldPersist(persist, opts.setOnScanError(opts.input.onScanError));

  clearScanTokenCache();
  const mint =
    opts.mint ??
    (async (creds) => {
      await getScanAccessToken(creds);
    });

  let minted = false;
  let mintError: string | undefined;
  try {
    await mint({
      clientId,
      clientSecret,
      issuer: DEFAULT_SCAN_ISSUER,
      audience: DEFAULT_SCAN_AUDIENCE,
      scope: DEFAULT_SCAN_SCOPE,
    });
    minted = true;
  } catch (err) {
    mintError = err instanceof Error ? err.message : String(err);
  }

  const verify = opts.verify ?? ((dir) => runVerify({ stateDir: dir }));
  let checks: VerifyResult["checks"] | undefined;
  try {
    checks = (await verify(stateDir)).checks;
  } catch {
    checks = undefined;
  }

  const restartHint = processEnvShadowsDotenvWrite({ clientId, clientSecret }, env);
  return {
    ok: minted,
    minted,
    persisted: persist2.persisted,
    error: minted
      ? persist2.persisted
        ? undefined
        : persist2.error
      : mintError || "Identity did not accept this client",
    dotenvPath,
    restartHint,
    checks,
  };
}
