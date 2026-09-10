/**
 * Shared operation contract for the Sentrook Control UI.
 *
 * Loaded by the gateway plugin and by the native Control UI bundle, so this
 * module stays browser-safe: no ``node:`` imports and no host SDK imports.
 * Operations are dispatched over the host's plugin session-action transport
 * (``plugins.sessionAction``); queries carry ``operator.read`` and actions
 * carry ``operator.write``, matching OpenClaw's own feature-plugin mapping.
 *
 * Input schemas are enforced on the way in because callers are untrusted.
 * Outputs are not schema-checked: the payload is ours, and a strict output
 * schema turns an additive field into a runtime failure on an older host.
 */

/** Plain JSON Schema. The host validates inputs with its own validator. */
export type JsonSchema = Record<string, unknown>;

export type FeatureOperationKind = "query" | "action";

export type FeatureOperationSpec = {
  kind: FeatureOperationKind;
  description: string;
  input: JsonSchema;
};

/** Operator scope the host requires for an operation of this kind. */
export function scopeForOperation(kind: FeatureOperationKind): "operator.read" | "operator.write" {
  return kind === "query" ? "operator.read" : "operator.write";
}

const OPERATION_ID = /^[a-z][a-z0-9._-]{0,127}$/u;
const EVENT_ID = /^[a-z][a-z0-9_-]{0,127}$/u;

/**
 * Mirrors the host's own contract validation so a malformed id fails at load
 * rather than at first dispatch. Operation ids may contain dots; event ids may
 * not, because events reach clients as ``plugin.<pluginId>.<event>``.
 */
export function assertContractIds(
  operations: Record<string, unknown>,
  events: readonly string[],
): void {
  for (const id of Object.keys(operations)) {
    if (!OPERATION_ID.test(id)) throw new Error(`Invalid Sentrook operation id: ${id}`);
  }
  for (const id of events) {
    if (!EVENT_ID.test(id)) throw new Error(`Invalid Sentrook event id: ${id}`);
  }
}

export const SENTROOK_PLUGIN_ID = "sentrook-openclaw";

export const SENTROOK_EVENTS = ["reviews_changed", "policy_changed", "log_changed"] as const;

export type SentrookEvent = (typeof SENTROOK_EVENTS)[number];

const EMPTY_INPUT: JsonSchema = { type: "object", additionalProperties: false, properties: {} };

const SENSITIVITY_TOKENS = ["strict", "info", "warning", "critical", "lenient"] as const;
const SESSION_SENSITIVITY_TOKENS = [...SENSITIVITY_TOKENS, "default"] as const;

export const SENTROOK_OPERATIONS = {
  state: {
    kind: "query",
    description: "Pending reviews, timeline, sessions, allowlist, and current policy.",
    input: EMPTY_INPUT,
  },
  resolve: {
    kind: "action",
    description: "Resolve one pending Sentrook review.",
    input: {
      type: "object",
      additionalProperties: false,
      required: ["decision"],
      properties: {
        decision: { type: "string", enum: ["allow-once", "allow-always", "deny"] },
        toolCallId: { type: "string", maxLength: 512 },
        eventId: { type: "string", maxLength: 512 },
        approvalId: { type: "string", maxLength: 512 },
      },
    },
  },
  policy: {
    kind: "action",
    description: "Update review sensitivity, feedback, scan-error behaviour, and quiet windows.",
    input: {
      type: "object",
      additionalProperties: false,
      properties: {
        sensitivity: { type: "string", enum: [...SENSITIVITY_TOKENS] },
        unattendedSensitivity: { type: "string", enum: [...SENSITIVITY_TOKENS] },
        feedbackMode: { type: "string", enum: ["off", "submit"] },
        onScanError: { type: "string", enum: ["allow", "deny", "review"] },
        allowAllMode: { type: "string", enum: ["off", "session", "on"] },
        globalQuiet: { type: "string", maxLength: 64 },
        allowAll: { type: "boolean" },
        quiet: { type: "string", maxLength: 64 },
        sessionId: { type: "string", maxLength: 512 },
        sessionKey: { type: "string", maxLength: 512 },
        sessionAttendedSensitivity: { type: "string", enum: [...SESSION_SENSITIVITY_TOKENS] },
        sessionUnattendedSensitivity: { type: "string", enum: [...SESSION_SENSITIVITY_TOKENS] },
      },
    },
  },
  log: {
    kind: "action",
    description: "Change operator-log retention, or purge and wipe its contents.",
    input: {
      type: "object",
      additionalProperties: false,
      properties: {
        maxAgeDays: { type: "integer", minimum: 0, maximum: 3650 },
        maxBytes: { type: "integer", minimum: 1024, maximum: 1073741824 },
        purge: { enum: ["confirm", true] },
        wipe: { type: "string", enum: ["confirm"] },
      },
    },
  },
  "allowlist.rm": {
    kind: "action",
    description: "Remove one local allowlist entry by its 1-based index.",
    input: {
      type: "object",
      additionalProperties: false,
      required: ["index"],
      properties: { index: { type: "integer", minimum: 1 } },
    },
  },
  "allowlist.add": {
    kind: "action",
    description: "Record a local allowlist entry from an operator-log history id.",
    input: {
      type: "object",
      additionalProperties: false,
      required: ["eventId"],
      properties: { eventId: { type: "string", maxLength: 512 } },
    },
  },
  setup: {
    kind: "action",
    description: "Write Sentrook scan credentials to the state-dir .env and mint a token.",
    input: {
      type: "object",
      additionalProperties: false,
      required: ["clientId", "clientSecret"],
      properties: {
        clientId: { type: "string", minLength: 1, maxLength: 512 },
        clientSecret: { type: "string", minLength: 1, maxLength: 4096 },
        feedbackMode: { type: "string", enum: ["off", "submit"] },
        onScanError: { type: "string", enum: ["allow", "deny", "review"] },
      },
    },
  },
  verify: {
    kind: "action",
    description: "Probe Sentrook connectivity and credentials.",
    input: EMPTY_INPUT,
  },
} as const satisfies Record<string, FeatureOperationSpec>;

export type SentrookOperationName = keyof typeof SENTROOK_OPERATIONS;

assertContractIds(SENTROOK_OPERATIONS, SENTROOK_EVENTS);

/** Events that should make a client refetch ``state``. */
export const STATE_EVENTS: readonly SentrookEvent[] = SENTROOK_EVENTS;

export type Sensitivity = "strict" | "info" | "warning" | "critical";
export type FeedbackMode = "off" | "submit";
export type OnScanErrorMode = "allow" | "deny" | "review";
export type AllowAllMode = "off" | "session" | "on";
export type ResolveDecision = "allow-once" | "allow-always" | "deny";

export type ReviewScan = {
  decision: string;
  risk?: number;
  summary?: string;
  matched_rules?: string[];
  review_severity?: string;
  block_reason?: string;
};

export type PendingReview = {
  eventId: string;
  toolCallId: string;
  approvalId?: string;
  tool: string;
  command: string;
  args: Record<string, unknown>;
  scan: ReviewScan;
  sessionId?: string;
  sessionKey?: string;
  agentId?: string;
  timeoutMs: number;
  createdAtMs: number;
  intent: string | null;
  intentKind: string | null;
  priorSteps: Array<{ tool: string; command: string; resultOk?: boolean }>;
  priorOmitted: number;
};

export type TimelineNeighbor = { id: string; tool: string; command: string };

export type TimelineRow = {
  id: string;
  ts: string;
  event: string;
  decision: string;
  tool: string;
  hostTool?: string;
  command: string;
  args?: Record<string, unknown>;
  summary?: string;
  matched_rules?: string[];
  winningRule?: string;
  reviewSeverity?: string;
  excerpt?: string;
  resultOk?: boolean;
  resultTs?: string;
  resultBytes?: number;
  resultTruncated?: boolean;
  resultUrls?: string[];
  resultPaths?: string[];
  injectionMarkers?: boolean;
  sessionKey: string;
  sessionId?: string;
  agentId?: string;
  risk?: number;
  blockReason?: string;
  intent: string | null;
  intentKind: string | null;
  resolution?: string;
  resolutionTs?: string;
  resolutionSource?: string;
  errorKind?: string;
  errorDetail?: string;
  errorStatus?: number;
  unattended: boolean;
  labelSource?: string;
  skipReason?: string;
  allowlistLabel?: string;
  effect?: string;
  runId: string;
  stepSeq?: number;
  neighbors: TimelineNeighbor[];
};

export type AuditTotals = {
  scanned: number;
  allow: number;
  review: number;
  block: number;
  error: number;
};

export type SessionRow = {
  sessionId?: string;
  sessionKey?: string;
  allowAll: boolean;
  quietUntilMs: number | null;
  attendedSensitivity?: Sensitivity | null;
  unattendedSensitivity?: Sensitivity | null;
  pending: number;
  label?: string;
  agentId?: string;
};

export type AllowlistRow = {
  index: number;
  kind: string;
  tool: string;
  label: string;
  detail?: string;
  createdAt?: string;
};

export type OperatorLogSummary = {
  enabled: boolean;
  path: string;
  bytes: number;
  lines: number;
  maxAgeDays: number;
  maxBytes: number;
};

export type SentrookState = {
  pending: PendingReview[];
  history: TimelineRow[];
  audit: AuditTotals;
  sessions: SessionRow[];
  sensitivity: Sensitivity;
  unattendedSensitivity: Sensitivity;
  allowAll: boolean;
  quietUntilMs: number | null;
  feedbackMode: FeedbackMode;
  onScanError: OnScanErrorMode;
  log: OperatorLogSummary;
  allowlist: AllowlistRow[];
  resolveAvailable: boolean;
  setupNeeded: boolean;
};

export type PersistResult = { ok: true; persisted?: boolean; error?: string };

export type SetupResult = {
  ok: boolean;
  minted: boolean;
  persisted: boolean;
  error?: string;
  dotenvPath?: string;
  restartHint?: boolean;
  checks?: unknown;
};

export type SentrookInputs = {
  state: Record<string, never>;
  resolve: {
    decision: ResolveDecision;
    toolCallId?: string;
    eventId?: string;
    approvalId?: string;
  };
  policy: {
    sensitivity?: Sensitivity | "lenient";
    unattendedSensitivity?: Sensitivity | "lenient";
    feedbackMode?: FeedbackMode;
    onScanError?: OnScanErrorMode;
    allowAllMode?: AllowAllMode;
    globalQuiet?: string;
    allowAll?: boolean;
    quiet?: string;
    sessionId?: string;
    sessionKey?: string;
    sessionAttendedSensitivity?: Sensitivity | "lenient" | "default";
    sessionUnattendedSensitivity?: Sensitivity | "lenient" | "default";
  };
  log: {
    maxAgeDays?: number;
    maxBytes?: number;
    purge?: "confirm" | true;
    wipe?: "confirm";
  };
  "allowlist.rm": { index: number };
  "allowlist.add": { eventId: string };
  setup: {
    clientId: string;
    clientSecret: string;
    feedbackMode?: FeedbackMode;
    onScanError?: OnScanErrorMode;
  };
  verify: Record<string, never>;
};

export type SentrookOutputs = {
  state: SentrookState;
  resolve: { ok: true; id: string; decision: ResolveDecision };
  policy: PersistResult;
  log: PersistResult;
  "allowlist.rm": { ok: true };
  "allowlist.add": { ok: true; status: string; message: string };
  setup: SetupResult;
  verify: { ok: boolean; checks?: unknown };
};
