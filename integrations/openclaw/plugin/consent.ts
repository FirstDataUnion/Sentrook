/**
 * Consent: what `openclaw sentrook login` prints after signing in, and the one owner notice when consent is withdrawn.
 *
 * The identity service issues scan credentials only after the owner accepts the terms and the sensitive-data step.
 * The owner can withdraw consent on the FIDU portal; the identity service then refuses this install's credentials with
 * `error_reason: consent_withdrawn` (`auth.ConsentWithdrawnError`). Each call is then handled as for any refused
 * credential (scanErrorPolicy.ts: never let through silently), and the owner gets one notice saying why, not one per
 * call. That it was sent is kept in the state folder, so a restart does not send it again; signing in again resets it.
 * The texts are shared with the Hermes plugin's tests (`integrations/fixtures/consent`).
 */

import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";

import { withFileLock } from "./store.ts";

/**
 * Printed after sign-in, one sentence per line. Keep it identical to `signed_in` in
 * `integrations/fixtures/consent/cases.json` and to `SIGNED_IN_TEXT` in the Hermes plugin's `consent.py`. The
 * `{terms}` line is left out unless the identity service names the accepted terms version.
 */
export const SIGNED_IN_TEXT: readonly string[] = [
  "Sentrook is connected to your FIDU account.",
  "{terms}",
  "Each check sends the action and its context to Sentrook, which may pass it to OpenRouter and TypeSafe to judge.",
  "Secrets are replaced with placeholders before anything leaves your machine; other personal data is sent as it is.",
  "Sentrook is a beta and does not guarantee protection.",
  "Policy and terms: {links}.",
  "To stop, run {stop} or close your FIDU account.",
];
export const TERMS_LINE = "Terms version {version} accepted.";
export const TERMS_LINE_DATED = "Terms version {version} accepted {date}.";
export const PRIVACY_URL = "https://firstdataunion.org/privacy-policy/";
/** The terms page; not published yet. While empty, the terms link is left out. */
export const TERMS_URL = "";
/** A terms version is printed only when it is short plain text, and a date only as YYYY-MM-DD. */
const TERMS_VERSION = /^[A-Za-z0-9._-]{1,40}$/;
const DATE = /^(\d{4}-\d{2}-\d{2})(?:[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/;

export const WITHDRAWN_NOTICE =
  "Sentrook consent withdrawn: scans stopped. Run {reconnect} to connect again, or switch to observe mode, or " +
  "uninstall. Observe mode: {observe}";

export const COMMANDS = {
  stop: "openclaw plugins disable sentrook && openclaw gateway restart",
  reconnect: "openclaw sentrook login",
  observe: "openclaw config set plugins.entries.sentrook.config.mode observe && openclaw gateway restart",
} as const;

export const FILE = "consent-notice.json";

export type AcceptedTerms = { version: string; date: string | null };

/** The accepted terms version and date from the identity service's credential answer, when it names a usable version. */
export function acceptedTerms(body: unknown): AcceptedTerms | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const { terms_version: version, terms_accepted_at: at } = body as Record<string, unknown>;
  if (typeof version !== "string" || !TERMS_VERSION.test(version)) return null;
  const date = typeof at === "string" ? DATE.exec(at) : null;
  return { version, date: date ? date[1]! : null };
}

export function signedInLines(terms: AcceptedTerms | null): string[] {
  const links = [PRIVACY_URL, TERMS_URL].filter(Boolean).join(" and ");
  const out: string[] = [];
  for (const line of SIGNED_IN_TEXT) {
    if (line === "{terms}") {
      if (terms) {
        out.push(
          (terms.date ? TERMS_LINE_DATED : TERMS_LINE).replace("{version}", terms.version).replace("{date}", terms.date ?? ""),
        );
      }
      continue;
    }
    out.push(line.replace("{links}", links).replace("{stop}", COMMANDS.stop));
  }
  return out;
}

export function withdrawnText(): string {
  return WITHDRAWN_NOTICE.replace("{reconnect}", COMMANDS.reconnect).replace("{observe}", COMMANDS.observe);
}

function read(file: string): Record<string, unknown> {
  try {
    const data = JSON.parse(readFileSync(file, "utf8"));
    return data && typeof data === "object" && !Array.isArray(data) ? data : {};
  } catch {
    return {};
  }
}

/**
 * Whether the withdrawal notice for `clientId` may go now: records it as sent and returns true the first time, false
 * once it was sent for these credentials. Credentials set anew (another client id) are announced again. Throws
 * `LockTimeoutError` when the file stays locked.
 */
export function claim(stateDir: string, clientId: string, now: Date): boolean {
  const file = path.join(stateDir, FILE);
  return withFileLock(file, () => {
    if (read(file).client_id === clientId) return false;
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    writeFileSync(tmp, JSON.stringify({ version: 1, client_id: clientId, sent_at: `${now.toISOString().slice(0, 19)}Z` }), {
      mode: 0o600,
    });
    renameSync(tmp, file);
    return true;
  });
}

/** Undoes `claim` after the notice could not be delivered, so the next refused scan announces it. */
export function release(stateDir: string, clientId: string): void {
  const file = path.join(stateDir, FILE);
  withFileLock(file, () => {
    if (read(file).client_id === clientId) rmSync(file, { force: true });
  });
}

/** After a sign-in: a later withdrawal is announced again. */
export function reset(stateDir: string): void {
  try {
    const file = path.join(stateDir, FILE);
    if (existsSync(file)) rmSync(file, { force: true });
  } catch {
    // nothing to reset
  }
}
