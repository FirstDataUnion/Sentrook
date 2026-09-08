/**
 * Current-choice copy shared by the dashboard Settings hints and ``/sentrook``.
 * Keep sentences identical so GUI and chat cannot drift.
 */

import type { OnScanError } from "./scanErrorPolicy.ts";
import type { Sensitivity, SensitivityScope } from "./sessionPolicy.ts";

export type FeedbackMode = "submit" | "off";
export type AllowAllMode = "off" | "session" | "on";

export function quietLeftLabel(untilMs: number | null | undefined, now: number): string {
  if (untilMs == null || untilMs <= now) return "off";
  const sec = Math.max(0, Math.round((untilMs - now) / 1000));
  if (sec < 60) return `${sec}s left`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m left`;
  const hours = Math.floor(min / 60);
  const mins = min % 60;
  return mins ? `${hours}h${mins}m left` : `${hours}h left`;
}

export function quietHint(untilMs: number | null | undefined, now: number): string {
  if (untilMs != null && untilMs > now) {
    return `Quiet for every session (${quietLeftLabel(untilMs, now)}).`;
  }
  return "No gateway-wide quiet window.";
}

export function allowAllHint(mode: AllowAllMode): string {
  if (mode === "on") {
    return "Skipping reviews for every attended session until you turn this off or the gateway restarts. Cards already waiting are not resolved.";
  }
  return "No gateway-wide allow-all. Reviews still prompt unless quiet or a per-session allow-all is on. Off also clears every session allow-all flag.";
}

export function feedbackHint(mode: FeedbackMode): string {
  return mode === "off"
    ? "No review feedback is sent."
    : "Posts sanitized allow-once and deny reviews to the community corpus.";
}

export function scanErrorHint(value: OnScanError): string {
  switch (value) {
    case "deny":
      return "Block the tool call when /scan fails. Auth failures still block.";
    case "allow":
      return "Continue without a scan when Sentrook is unreachable. Auth failures still block.";
    default:
      return "Ask on interactive runs when /scan fails. Unattended still blocks. Auth failures still block.";
  }
}

export function sensitivityHint(scope: SensitivityScope, selected: Sensitivity): string {
  if (scope === "unattended") {
    switch (selected) {
      case "strict":
        return "Cron and subagent reviews are never auto-accepted. Unanswered cards deny when they time out. Blocks and scan errors still stop.";
      case "info":
        return "Auto-accept info reviews when nobody is watching. Warning and critical still wait (then deny if nobody answers).";
      case "warning":
        return "Auto-accept info and warning reviews on cron and subagent runs. Critical still waits.";
      case "critical":
        return "Auto-accept every review on cron and subagent runs, including critical. Nobody will be asked. Blocks and scan errors still stop.";
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
