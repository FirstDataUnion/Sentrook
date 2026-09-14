/**
 * Copy-friendly slash / CLI commands shown on the read-only HTTP dashboard.
 * Keep these strings identical to ``slashCommand.ts`` usage so the panel and
 * chat cannot drift.
 */

export function approveOnce(approvalId?: string): string {
  const id = approvalId?.trim();
  return id ? `/approve ${id} allow-once` : "";
}

export function approveAlways(approvalId?: string): string {
  const id = approvalId?.trim();
  return id ? `/approve ${id} allow-always` : "";
}

export function approveDeny(approvalId?: string): string {
  const id = approvalId?.trim();
  return id ? `/approve ${id} deny` : "";
}

export function pendingInspect(eventId?: string): string {
  const id = eventId?.trim();
  return id ? `/sentrook pending ${id}` : "/sentrook pending";
}

/** Copy-paste chat lines for a review card. Never emit a truncated ``plugin:…`` id. */
export function resolveChatCommands(
  approvalId?: string,
  eventId?: string,
): Array<{ label: string; cmd: string }> {
  const once = approveOnce(approvalId);
  const always = approveAlways(approvalId);
  const deny = approveDeny(approvalId);
  if (once && always && deny) {
    return [
      { label: "Allow once", cmd: once },
      { label: "Allow always", cmd: always },
      { label: "Deny", cmd: deny },
    ];
  }
  return [{ label: "Inspect in chat", cmd: pendingInspect(eventId) }];
}

export const ALLOW_ALL_OFF = "/sentrook allow-all all off";
export const ALLOW_ALL_ON = "/sentrook allow-all all on";

export function quietAll(duration: "off" | "30m" | "2h" | "8h"): string {
  return `/sentrook quiet all ${duration}`;
}

export function sessionToken(sessionKey?: string, sessionId?: string): string {
  return sessionKey?.trim() || sessionId?.trim() || "<key>";
}

export function allowAllSession(key: string, on: boolean): string {
  return `/sentrook allow-all session ${key} ${on ? "on" : "off"}`;
}

export function quietSession(key: string, duration: "30m" | "off"): string {
  return `/sentrook quiet session ${key} ${duration}`;
}

export function sensitivityCmd(
  scope: "attended" | "unattended",
  level: "strict" | "info" | "warning" | "critical",
): string {
  const base = `/sentrook sensitivity ${scope} ${level}`;
  return level === "critical" ? `${base} confirm` : base;
}

export function sensitivitySession(
  key: string,
  scope: "attended" | "unattended",
  level: "strict" | "info" | "warning" | "critical" | "default",
): string {
  const base = `/sentrook sensitivity session ${key} ${scope} ${level}`;
  return level === "critical" ? `${base} confirm` : base;
}

export function feedbackCmd(mode: "submit" | "off"): string {
  return `/sentrook feedback ${mode}`;
}

export function scanErrorCmd(mode: "review" | "deny" | "allow"): string {
  return mode === "allow" ? "/sentrook scan-error allow confirm" : `/sentrook scan-error ${mode}`;
}

export function allowlistRm(index: number): string {
  return `/sentrook allowlist rm ${index}`;
}

export function allowlistAdd(eventId?: string): string {
  const id = eventId?.trim();
  return id ? `/sentrook allowlist add ${id}` : "/sentrook allowlist add <id>";
}

export function logRetentionDays(days: number): string {
  return `/sentrook log retention ${days}d`;
}

export function logRetentionMib(mib: number): string {
  return `/sentrook log retention ${mib}MiB`;
}

export const LOG_PURGE = "/sentrook log purge confirm";
export const LOG_WIPE = "/sentrook log purge all confirm";
export const VERIFY_CLI = "openclaw sentrook verify";
export const CONFIGURE_CLI = "openclaw sentrook configure";
export const CONFIGURE_CLI_DOCKER_COMPOSE = "docker compose exec openclaw openclaw sentrook configure";
