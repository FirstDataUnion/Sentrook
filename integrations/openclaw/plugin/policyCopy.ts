/**
 * Current-choice copy shared by the dashboard Settings hints and ``/sentrook``.
 * Keep sentences identical so GUI and chat cannot drift.
 */

import type { OnScanError } from "./scanErrorPolicy.ts";
import type { Sensitivity, SensitivityScope } from "./sessionPolicy.ts";

export type FeedbackMode = "submit" | "off";
export type AllowAllMode = "off" | "session" | "on";

export function quietRemainingPhrase(untilMs: number | null | undefined, now: number): string {
  if (untilMs == null || untilMs <= now) return "off";
  const sec = Math.max(0, Math.round((untilMs - now) / 1000));
  if (sec < 60) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m`;
  const hours = Math.floor(min / 60);
  const mins = min % 60;
  return mins ? `${hours}h ${mins}m` : `${hours}h`;
}

export function quietLeftLabel(untilMs: number | null | undefined, now: number): string {
  if (untilMs == null || untilMs <= now) return "off";
  return `${quietRemainingPhrase(untilMs, now).replace(" ", "")} left`;
}

/** Dashboard banner when gateway quiet is on. Null when off. */
export function quietActiveLine(untilMs: number | null | undefined, now: number): string | null {
  if (untilMs == null || untilMs <= now) return null;
  return `Quiet mode active, time remaining: ${quietRemainingPhrase(untilMs, now)}`;
}

export function quietHint(untilMs: number | null | undefined, now: number): string {
  if (untilMs != null && untilMs > now) {
    return `Quiet for every session (${quietLeftLabel(untilMs, now)}).`;
  }
  return "No gateway-wide quiet window.";
}

export function allowAllHint(mode: AllowAllMode): string {
  if (mode === "on") {
    return "Auto-accepting every attended review until you turn this off. Scan still runs. Blocks, scan errors, and unattended runs still stop. Open cards still need /approve. Sessions with their own attended floor are unchanged.";
  }
  return "No gateway-wide allow-all. Reviews still prompt unless quiet or a per-session allow-all is on. Off also clears every session allow-all flag.";
}

export function sessionFloorOverrideNote(scope: SensitivityScope): string {
  return scope === "unattended"
    ? "Sessions with their own unattended floor are unchanged."
    : "Sessions with their own attended floor are unchanged.";
}

export function feedbackHint(mode: FeedbackMode): string {
  return mode === "off"
    ? "No review feedback is sent."
    : "Posts sanitized allow-once and deny reviews to the community corpus.";
}

export const SETUP_SUCCESS_TOAST = "Verify successful, you're ready to go!";
export const SETUP_SUCCESS_RESTART_TOAST =
  "Verify successful. Restart the gateway so scans use the new credentials.";

export function scanErrorHint(value: OnScanError): string {
  switch (value) {
    case "deny":
      return "Block the tool call when Sentrook cannot scan. Auth failures still block.";
    case "allow":
      return "Continue without a scan when Sentrook is unreachable. Auth failures still block.";
    default:
      return "Ask on interactive runs when Sentrook cannot scan. Unattended still blocks. Auth failures still block.";
  }
}

export function sensitivityHint(scope: SensitivityScope, selected: Sensitivity): string {
  if (scope === "unattended") {
    switch (selected) {
      case "strict":
        return "Cron, heartbeat, and jobs they spawn are never auto-accepted. Unanswered cards deny when they time out. Blocks and scan errors still stop.";
      case "info":
        return "Auto-accept info reviews when nobody is watching. Warning and critical still wait (then deny if nobody answers).";
      case "warning":
        return "Auto-accept info and warning reviews on cron, heartbeat, and jobs they spawn. Critical still waits.";
      case "critical":
        return "Auto-accept every review on cron, heartbeat, and jobs they spawn, including critical. Nobody will be asked. Blocks and scan errors still stop.";
    }
  }
  switch (selected) {
    case "strict":
      return "Prompt every review while you are present. Nothing is auto-accepted.";
    case "info":
      return "Auto-accept info reviews. Warning and critical still wait for you.";
    case "warning":
      return "Auto-accept info and warning reviews. Critical still waits for you.";
    case "critical":
      return "Auto-accept every review while you are present, including critical. Blocks and scan errors still stop.";
  }
}
