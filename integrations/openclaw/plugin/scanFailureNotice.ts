/**
 * The owner's notice when a scan failure blocks a call on an unattended run.
 *
 * Nobody is there to be asked, so the call is blocked (see scanErrorPolicy.ts); without a notice a scanner outage
 * would quietly stop scheduled jobs. The notice goes where held-call notices go and has nothing to approve: the call
 * was not held. One notice per cron job (or, for other unattended runs, per session): after one is sent, further
 * failures with the same key send none for `QUIET_MS`, so an outage gives one message per job, not one per call.
 * The texts are shared with the Hermes plugin's tests (`integrations/fixtures/hold`).
 */

import path from "node:path";

import { inert } from "./hold.ts";
import { isAuthFailure, type ScanFailure } from "./scanErrorPolicy.ts";
import { readTime, Store, withFileLock } from "./store.ts";

export const QUIET_MS = 6 * 3600_000;
const QUIET_HOURS = QUIET_MS / 3600_000;
const MAX_KEYS = 500;
const FILE = "scan-failure-notices.json";

/** Why the scan gave no answer, in words for the owner; never the failure's detail, which can carry anything. */
export function reasonOf(failure: ScanFailure): string {
  if (failure.setup === "consent_withdrawn") return "consent for Sentrook was withdrawn on the FIDU portal";
  if (isAuthFailure(failure)) return "Sentrook's endpoint or credentials are not configured correctly";
  switch (failure.kind) {
    case "network":
      return "Sentrook could not reach the scan service";
    case "timeout":
      return "the scan service did not answer in time";
    case "rate_limited":
      return "the scan service rate-limited the scan";
    default:
      return "the scan service returned an error";
  }
}

/** What the quiet period is kept by: the cron job when there is one, else the session. */
export function quietKey(jobId: string | null | undefined, sessionRef: string): string {
  return jobId ? `job:${jobId}` : `session:${sessionRef}`;
}

/** The notice; `where` is `whereText`'s, already made inert. */
export function noticeText(failure: ScanFailure, tool: string, where: string, isJob: boolean, verify: string): string {
  return [
    "Sentrook could not scan a tool call on an unattended run, so the call was blocked and did not run.",
    `Run: ${where}`,
    `Tool: ${inert(tool, 80)}`,
    `Reason: ${reasonOf(failure)}.`,
    `To check the setup: ${verify}`,
    `More scan failures in this ${isJob ? "job" : "session"} are not announced for ${QUIET_HOURS} hours.`,
  ].join("\n");
}

/**
 * Whether a notice for `key` may go now: when it may, records `now` as its send time and returns that stamp (for
 * `release`); null while the key is in its quiet period. Held under the file's lock, so two processes never both announce the same job. An unreadable file
 * starts afresh: a notice too many beats an outage nobody hears about. Throws `LockTimeoutError` when the file stays
 * locked.
 */
export function claim(stateDir: string, key: string, now: Date): string | null {
  return withFileLock(path.join(stateDir, FILE), () => {
    const store = new Store(stateDir);
    const sent: Record<string, string> = {};
    for (const [k, v] of Object.entries(store.loadScanFailureNotices())) {
      const at = readTime(v);
      if (at !== null && now.getTime() - at.getTime() < QUIET_MS) sent[k] = v as string;
    }
    if (Object.hasOwn(sent, key)) return null;
    const stamp = `${now.toISOString().slice(0, 19)}Z`;
    sent[key] = stamp;
    const keep = Object.entries(sent).sort((a, b) => a[1].localeCompare(b[1])).slice(-MAX_KEYS);
    store.saveScanFailureNotices(Object.fromEntries(keep));
    return stamp;
  });
}

/** Undoes `claim` after the notice could not be delivered, so the next failure for `key` is announced. */
export function release(stateDir: string, key: string, stamp: string): void {
  withFileLock(path.join(stateDir, FILE), () => {
    const store = new Store(stateDir);
    const sent = store.loadScanFailureNotices();
    if (sent[key] !== stamp) return;
    delete sent[key];
    store.saveScanFailureNotices(sent as Record<string, string>);
  });
}
