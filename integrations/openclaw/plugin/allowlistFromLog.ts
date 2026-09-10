/**
 * Record a local allow-always entry from an operator-log history id.
 *
 * Used by ``/sentrook allowlist add <id>``, the native dashboard, and CLI so a
 * blocked unattended review can be trusted without replaying the command in chat.
 */

import {
  recordAllowAlways,
  type AllowlistConfig,
  type RecordResult,
} from "./localAllowlist.ts";
import {
  getOperatorLogEvent,
  queryOperatorLog,
  type OperatorLogConfig,
  type OperatorLogEvent,
} from "./operatorLog.ts";
import type { Json, PlanIR } from "./planir.ts";
import type { IntentKind } from "./attendance.ts";

export type AllowlistAddResult =
  | { ok: true; status: "recorded" | "duplicate"; kind?: string; eventId: string; message: string }
  | { ok: false; message: string };

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function findScanEvent(log: OperatorLogConfig, id: string): OperatorLogEvent | undefined {
  const event = getOperatorLogEvent(log, id);
  if (!event) return undefined;
  if (event.event === "scan") return event;
  const runId = event.run_id;
  if (!runId) return undefined;
  return queryOperatorLog(log, { event: "scan" }).find((row) => row.run_id === runId);
}

export function planFromOperatorScan(event: OperatorLogEvent): PlanIR | undefined {
  const pending = asRecord(event.pending);
  if (!pending) return undefined;
  const tool = typeof pending.tool === "string" ? pending.tool : "";
  const args = asRecord(pending.args) ?? {};
  const meta = asRecord(event.metadata) ?? {};
  const intentKind =
    typeof event.intent_kind === "string" ? (event.intent_kind as IntentKind) : null;
  return {
    version: "1.0",
    run_id: event.run_id,
    intent: typeof event.intent === "string" ? event.intent : null,
    intent_kind: intentKind,
    steps: [
      {
        id: typeof pending.id === "string" ? pending.id : "s1",
        tool,
        status: "pending",
        args: args as Json,
      },
    ],
    metadata: {
      adapter: typeof meta.adapter === "string" ? meta.adapter : "openclaw",
      agent_id: typeof meta.agent_id === "string" ? meta.agent_id : null,
      session_id: typeof meta.session_id === "string" ? meta.session_id : null,
      session_key: typeof meta.session_key === "string" ? meta.session_key : null,
      hook: typeof meta.hook === "string" ? meta.hook : "before_tool_call",
      tool_call_id: typeof meta.tool_call_id === "string" ? meta.tool_call_id : null,
      step_seq: typeof meta.step_seq === "number" ? meta.step_seq : null,
      batch_size: typeof meta.batch_size === "number" ? meta.batch_size : 1,
    },
  };
}

function cwdFromArgs(args: Record<string, unknown>): string | undefined {
  for (const key of ["cwd", "workdir", "workingDirectory"]) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function formatRecorded(result: RecordResult, eventId: string): AllowlistAddResult {
  if (result.status === "recorded") {
    return {
      ok: true,
      status: "recorded",
      kind: result.kind,
      eventId,
      message: `Allowlisted this command (${result.kind ?? "entry"}). Matching later reviews skip the prompt. Re-run the job. Scan still runs; blocks still win.`,
    };
  }
  if (result.status === "duplicate") {
    return {
      ok: true,
      status: "duplicate",
      kind: result.kind,
      eventId,
      message: `Already on the allowlist (${result.kind ?? "entry"}). Matching reviews already skip the prompt.`,
    };
  }
  const reason = result.reason ?? "unknown";
  let hint = `Could not allowlist this command (${reason}).`;
  if (reason.includes("high-risk") || reason.includes("bare") || reason.includes("empty skeleton")) {
    hint +=
      " Pipes and curl|bash are not stored. A curl/wget with a URL can be, if it is not piped. Otherwise raise the unattended floor: /sentrook sensitivity unattended warning";
  } else if (reason.includes("no matched rules")) {
    hint += " Only hosted reviews with matched rules can be allowlisted.";
  } else if (reason.includes("disabled")) {
    hint += " Enable allowlist.enabled, then retry.";
  }
  return { ok: false, message: hint };
}

export function addAllowlistFromHistory(
  log: OperatorLogConfig,
  allowlist: AllowlistConfig,
  rawId: string,
): AllowlistAddResult {
  const id = rawId.trim();
  if (!id) {
    return { ok: false, message: "Usage: /sentrook allowlist add <id>   (id from /sentrook history)" };
  }
  if (!log.enabled) {
    return {
      ok: false,
      message: "Operator log is off, so history ids cannot be loaded. Enable operatorLog.enabled.",
    };
  }
  const scan = findScanEvent(log, id);
  if (!scan) {
    return {
      ok: false,
      message: `No history event ${id}. Try /sentrook history, or check SENTROOK_OPERATOR_LOG is on.`,
    };
  }
  const decision = asRecord(scan.scan)?.decision;
  if (decision === "block") {
    return {
      ok: false,
      message: "That was a hard block, not a review. The allowlist never overrides block.",
    };
  }
  if (decision !== "review") {
    return {
      ok: false,
      message: `Event ${scan.id} was ${typeof decision === "string" ? decision : "not a review"}. Only hosted reviews can be allowlisted.`,
    };
  }
  const plan = planFromOperatorScan(scan);
  if (!plan) {
    return { ok: false, message: `Event ${scan.id} has no pending command to allowlist.` };
  }
  const scanBody = asRecord(scan.scan) ?? {};
  const logPayload: Record<string, unknown> = {
    matched_rules: scanBody.matched_rules,
    winning_rule_id: scanBody.winning_rule_id,
  };
  const pendingArgs = asRecord(asRecord(scan.pending)?.args) ?? {};
  const recorded = recordAllowAlways(plan, logPayload, allowlist, {
    cwd: cwdFromArgs(pendingArgs),
  });
  return formatRecorded(recorded, scan.id);
}
