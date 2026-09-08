/**
 * Sentrook dashboard mutations, independent of how they were requested.
 *
 * Both surfaces call these: the native Control UI page over the host's plugin
 * session-action transport, and the legacy HTTP panel. Keeping one
 * implementation means the two cannot drift on validation or persistence.
 *
 * Failures raise ``FeatureOperationError`` with a code. Session actions return
 * the code verbatim; ``httpStatusForCode`` maps it back to the status the HTTP
 * panel has always sent.
 */

import {
  listPluginApprovals,
  matchApprovalId,
  resolvePluginApproval,
  type ResolveDecision,
} from "./approvalGateway.ts";
import { loadAllowlist, saveAllowlist } from "./localAllowlist.ts";
import { purgeOperatorLog, wipeOperatorLog } from "./operatorLog.ts";
import { parseOnScanError } from "./scanErrorPolicy.ts";
import { parseQuietDuration, parseSensitivityToken } from "./sessionPolicy.ts";
import { sessionIdsOf } from "./sessionStore.ts";
import { FeatureOperationError } from "./featureOperations.ts";
import type {
  PersistResult,
  SentrookInputs,
  SetupResult,
} from "./featureContract.ts";
import type { AllowAllMode, DashboardDeps, DashboardFeedbackMode, DashboardPersistResult } from "./dashboard.ts";

export { FeatureOperationError };

/** Status the HTTP panel returns for a given operation error code. */
export function httpStatusForCode(code: string): number {
  switch (code) {
    case "NOT_FOUND":
      return 404;
    case "CONFLICT":
      return 409;
    case "UNAVAILABLE":
      return 501;
    case "OPERATION_FAILED":
      return 500;
    default:
      return 400;
  }
}

function invalid(message: string): never {
  throw new FeatureOperationError(message, "INVALID_INPUT");
}

function parseAllowAllMode(raw: unknown): AllowAllMode | undefined {
  if (raw == null) return undefined;
  if (raw === "off" || raw === "session" || raw === "on") return raw;
  return invalid("allowAllMode must be off, session, or on");
}

function parseFeedbackMode(raw: unknown): DashboardFeedbackMode | undefined {
  if (raw == null) return undefined;
  if (raw === "off" || raw === "submit") return raw;
  return invalid("feedbackMode must be submit or off");
}

function parseRetentionDays(raw: unknown): number | undefined {
  if (raw == null) return undefined;
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw < 0 || raw > 3650) {
    return invalid("maxAgeDays must be an integer from 0 to 3650 (0 = no age purge)");
  }
  return raw;
}

function parseRetentionBytes(raw: unknown): number | undefined {
  if (raw == null) return undefined;
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw < 1024 || raw > 1024 * 1024 * 1024) {
    return invalid("maxBytes must be between 1 KiB and 1 GiB");
  }
  return Math.round(raw);
}

function foldPersist(
  acc: DashboardPersistResult | undefined,
  next: DashboardPersistResult,
): DashboardPersistResult {
  if (!acc) return { persisted: next.persisted, error: next.error };
  if (acc.persisted && next.persisted) return { persisted: true };
  return { persisted: false, error: acc.error || next.error };
}

/**
 * A change can apply to the running process but fail to reach openclaw.json.
 * That is reported as success with ``persisted: false`` so the operator sees
 * the value took effect and still learns it will not survive a restart.
 */
function persistPayload(persist: DashboardPersistResult | undefined): PersistResult {
  if (!persist) return { ok: true };
  if (persist.persisted) return { ok: true, persisted: true };
  return {
    ok: true,
    persisted: false,
    error: persist.error || "Applied now, but not saved to openclaw.json.",
  };
}

export async function opResolve(
  deps: DashboardDeps,
  input: SentrookInputs["resolve"],
): Promise<{ ok: true; id: string; decision: ResolveDecision }> {
  const decision = input.decision;
  if (decision !== "allow-once" && decision !== "allow-always" && decision !== "deny") {
    invalid("decision must be allow-once, allow-always, or deny");
  }
  const id = input.toolCallId || input.eventId || "";
  const card = deps.cards.get(id);
  if (!card) throw new FeatureOperationError("No pending review for that id", "NOT_FOUND");

  const listed = await listPluginApprovals(deps.gateway);
  const approvalId = input.approvalId || matchApprovalId(listed, card.toolCallId);
  if (!approvalId) {
    throw new FeatureOperationError(
      "OpenClaw has not exposed a plugin: approval id yet. Use /approve in chat.",
      "CONFLICT",
    );
  }
  await resolvePluginApproval({
    gateway: deps.gateway,
    config: deps.config,
    approvalId,
    decision,
  });
  deps.cards.take(card.toolCallId);
  return { ok: true, id: approvalId, decision };
}

export function opPolicy(deps: DashboardDeps, input: SentrookInputs["policy"]): PersistResult {
  let persist: DashboardPersistResult | undefined;

  if (typeof input.sensitivity === "string") {
    const value = parseSensitivityToken(input.sensitivity);
    if (!value) invalid("sensitivity must be strict, info, warning, or critical");
    persist = foldPersist(persist, deps.setSensitivity(value));
  }
  if (typeof input.unattendedSensitivity === "string") {
    const value = parseSensitivityToken(input.unattendedSensitivity);
    if (!value) invalid("unattendedSensitivity must be strict, info, warning, or critical");
    persist = foldPersist(persist, deps.setUnattendedSensitivity(value));
  }
  const feedback = parseFeedbackMode(input.feedbackMode);
  if (feedback) persist = foldPersist(persist, deps.setFeedbackMode(feedback));

  if (input.onScanError != null) {
    const value = parseOnScanError(input.onScanError, deps.onScanError());
    if (typeof input.onScanError !== "string" || input.onScanError.trim().toLowerCase() !== value) {
      invalid("onScanError must be review, deny, or allow");
    }
    persist = foldPersist(persist, deps.setOnScanError(value));
  }

  const mode = parseAllowAllMode(input.allowAllMode);
  if (mode === "on") {
    deps.setAllowAll(true);
  } else if (mode === "off") {
    deps.setAllowAll(false);
    for (const st of deps.sessions.uniqueValues()) st.allowAll = false;
  } else if (mode === "session") {
    deps.setAllowAll(false);
  }

  const now = deps.now?.() ?? Date.now();
  if (typeof input.globalQuiet === "string") {
    const parsed = parseQuietDuration(input.globalQuiet, now);
    if ("error" in parsed) invalid(parsed.error);
    deps.setQuietUntilMs(parsed.untilMs);
  }

  const ids = sessionIdsOf({ sessionId: input.sessionId, sessionKey: input.sessionKey });
  if (typeof input.allowAll === "boolean" || typeof input.quiet === "string") {
    const st = deps.sessions.getOrCreate(ids, deps.sessionFactory);
    if (ids.sessionId) st.sessionId = ids.sessionId;
    if (ids.sessionKey) st.sessionKey = ids.sessionKey;
    if (typeof input.allowAll === "boolean") {
      deps.setAllowAll(false);
      st.allowAll = input.allowAll;
    }
    if (typeof input.quiet === "string") {
      const parsed = parseQuietDuration(input.quiet, now);
      if ("error" in parsed) invalid(parsed.error);
      st.quietUntilMs = parsed.untilMs;
    }
  }
  return persistPayload(persist);
}

export function opLog(deps: DashboardDeps, input: SentrookInputs["log"]): PersistResult {
  const days = parseRetentionDays(input.maxAgeDays);
  const bytes = parseRetentionBytes(input.maxBytes);
  let persist: DashboardPersistResult | undefined;
  if (typeof days === "number" || typeof bytes === "number") {
    persist = deps.setOperatorLogRetention({ maxAgeDays: days, maxBytes: bytes });
  }
  if (input.wipe === "confirm") {
    wipeOperatorLog(deps.operatorLog());
  } else if (input.purge === "confirm" || input.purge === true) {
    purgeOperatorLog(deps.operatorLog());
  }
  return persistPayload(persist);
}

export function opAllowlistRemove(
  deps: DashboardDeps,
  input: SentrookInputs["allowlist.rm"],
): { ok: true } {
  const index = typeof input.index === "number" ? input.index : Number(input.index);
  const file = loadAllowlist(deps.allowlist.path);
  if (!Number.isInteger(index) || index < 1 || index > file.entries.length) {
    invalid("invalid allowlist index");
  }
  file.entries.splice(index - 1, 1);
  try {
    saveAllowlist(deps.allowlist.path, file);
  } catch (err) {
    throw new FeatureOperationError(
      `Could not write allowlist: ${err instanceof Error ? err.message : String(err)}`,
      "OPERATION_FAILED",
    );
  }
  return { ok: true };
}

export async function opSetup(
  deps: DashboardDeps,
  input: SentrookInputs["setup"],
): Promise<SetupResult> {
  if (!deps.saveSetup) {
    throw new FeatureOperationError("Setup is not available on this gateway.", "UNAVAILABLE");
  }
  const clientId = typeof input.clientId === "string" ? input.clientId : "";
  const clientSecret = typeof input.clientSecret === "string" ? input.clientSecret : "";
  if (!clientId.trim() || !clientSecret.trim()) {
    invalid("client_id and client_secret are required");
  }
  const feedback = parseFeedbackMode(input.feedbackMode ?? "submit");
  if (input.onScanError != null) {
    const value = parseOnScanError(input.onScanError, "review");
    if (typeof input.onScanError !== "string" || input.onScanError.trim().toLowerCase() !== value) {
      invalid("onScanError must be review, deny, or allow");
    }
  }
  return deps.saveSetup({
    clientId,
    clientSecret,
    feedbackMode: feedback ?? "submit",
    onScanError: parseOnScanError(input.onScanError ?? "review", "review"),
  });
}

export async function opVerify(deps: DashboardDeps): Promise<{ ok: boolean; checks?: unknown }> {
  if (!deps.verifyConnection) {
    throw new FeatureOperationError("Verify is not available on this gateway.", "UNAVAILABLE");
  }
  const result = await deps.verifyConnection();
  return result as unknown as { ok: boolean; checks?: unknown };
}
