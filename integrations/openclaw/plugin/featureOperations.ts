/**
 * Registers the Sentrook contract on the host's plugin session-action
 * transport, and emits the change events the Control UI watches.
 *
 * The registration shape deliberately matches OpenClaw's own
 * ``defineFeaturePlugin``: one session action per operation, named for the
 * operation, scoped ``operator.read`` for queries and ``operator.write`` for
 * actions, replying with an ``{ ok, result }`` envelope. Matching it means the
 * host's typed browser client reaches these handlers unchanged, while Sentrook
 * keeps its own plugin definition, hooks, and slash command.
 */

import {
  SENTROOK_OPERATIONS,
  scopeForOperation,
  type SentrookEvent,
  type SentrookInputs,
  type SentrookOperationName,
  type SentrookOutputs,
} from "./featureContract.ts";

/** Reply envelope the host's session-action dispatch understands. */
type SessionActionResult =
  | { ok?: true; result?: unknown }
  | { ok: false; error: string; code?: string };

type SessionActionContext = {
  pluginId: string;
  actionId: string;
  sessionKey?: string;
  agentId?: string;
  payload?: unknown;
  client?: { connId?: string; scopes: string[] };
};

export type SessionActionRegistration = {
  id: string;
  description?: string;
  schema?: unknown;
  requiredScopes?: string[];
  handler: (ctx: SessionActionContext) => SessionActionResult | void | Promise<SessionActionResult | void>;
};

type GatewayEvents = {
  emit: (event: string, payload: unknown, opts?: { scope?: string }) => void;
};

/**
 * Only the surface this module touches. Both the grouped namespace and the
 * deprecated flat alias are optional so an older host fails the capability
 * probe instead of throwing at registration.
 */
export type FeatureCapableApi = {
  logger?: { warn: (msg: string) => void; info?: (msg: string) => void };
  registerSessionAction?: (action: SessionActionRegistration) => void;
  registerService?: (service: {
    id: string;
    start: (ctx: { gatewayEvents?: GatewayEvents }) => void;
    stop?: () => void;
  }) => void;
  session?: {
    controls?: {
      registerSessionAction?: (action: SessionActionRegistration) => void;
    };
  };
};

export type FeatureActionContext = {
  sessionKey?: string;
  agentId?: string;
  /** Operator scopes on the calling connection, when the host reports them. */
  scopes: readonly string[];
};

export type FeatureHandlers = {
  [K in SentrookOperationName]: (
    input: SentrookInputs[K],
    context: FeatureActionContext,
  ) => SentrookOutputs[K] | Promise<SentrookOutputs[K]>;
};

/** Thrown by a handler to reply with operator-facing copy instead of a crash. */
export class FeatureOperationError extends Error {
  readonly code: string;

  constructor(message: string, code = "INVALID_INPUT") {
    super(message);
    this.name = "FeatureOperationError";
    this.code = code;
  }
}

/**
 * Host limits from OpenClaw ``src/plugins/host-hook-json.ts``. Session-action
 * ``result`` / ``reply`` / ``details`` must pass this check or Control UI
 * shows "plugin session action result must be JSON-compatible".
 */
export const PLUGIN_JSON_VALUE_LIMITS = {
  maxDepth: 32,
  maxNodes: 4096,
  maxObjectKeys: 512,
  maxStringLength: 64 * 1024,
  maxSerializedBytes: 256 * 1024,
} as const;

function isPluginJsonValueWithinLimits(
  value: unknown,
  limits: typeof PLUGIN_JSON_VALUE_LIMITS,
  state: { depth: number; nodes: number },
): boolean {
  state.nodes += 1;
  if (state.nodes > limits.maxNodes || state.depth > limits.maxDepth) return false;
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "string") return value.length <= limits.maxStringLength;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    state.depth += 1;
    const ok = value.every((entry) => isPluginJsonValueWithinLimits(entry, limits, state));
    state.depth -= 1;
    return ok;
  }
  if (typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > limits.maxObjectKeys) return false;
  state.depth += 1;
  const ok = entries.every(
    ([key, entry]) =>
      key.length <= limits.maxStringLength && isPluginJsonValueWithinLimits(entry, limits, state),
  );
  state.depth -= 1;
  return ok;
}

/** Same guard the gateway runs on plugin session-action result fields. */
export function isPluginJsonValue(value: unknown): boolean {
  if (
    !isPluginJsonValueWithinLimits(value, PLUGIN_JSON_VALUE_LIMITS, {
      depth: 0,
      nodes: 0,
    })
  ) {
    return false;
  }
  try {
    return Buffer.byteLength(JSON.stringify(value), "utf8") <= PLUGIN_JSON_VALUE_LIMITS.maxSerializedBytes;
  } catch {
    return false;
  }
}

function jsonClone(value: unknown): unknown {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) return undefined;
  return JSON.parse(serialized) as unknown;
}

function slimHistoryRow(row: unknown): unknown {
  if (!row || typeof row !== "object" || Array.isArray(row)) return row;
  const rec = { ...(row as Record<string, unknown>) };
  delete rec.args;
  delete rec.neighbors;
  delete rec.resultUrls;
  delete rec.resultPaths;
  return rec;
}

/**
 * Dashboard ``state`` is the payload that routinely exceeds host JSON limits
 * (timeline rows plus optional ``undefined`` fields). Drop bulky columns,
 * then shorten history / pending args until the clone fits.
 */
function compactDashboardState(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const next = { ...(value as Record<string, unknown>) };
  if (Array.isArray(next.history)) {
    const slimmed = next.history.map(slimHistoryRow);
    next.history = slimmed;
    let keep = slimmed.length;
    while (keep > 0 && !isPluginJsonValue(next)) {
      keep = Math.floor(keep / 2);
      next.history = slimmed.slice(0, keep);
    }
  }
  if (!isPluginJsonValue(next) && Array.isArray(next.pending)) {
    next.pending = next.pending.map((row) => {
      if (!row || typeof row !== "object" || Array.isArray(row)) return row;
      const rec = { ...(row as Record<string, unknown>) };
      delete rec.args;
      return rec;
    });
  }
  if (!isPluginJsonValue(next) && Array.isArray(next.allowlist) && next.allowlist.length > 32) {
    next.allowlist = next.allowlist.slice(0, 32);
  }
  if (!isPluginJsonValue(next) && Array.isArray(next.sessions) && next.sessions.length > 32) {
    next.sessions = next.sessions.slice(0, 32);
  }
  return next;
}

/**
 * Make a handler return value legal for ``plugins.sessionAction``.
 * ``JSON.stringify`` drops ``undefined`` keys the host's walk rejects;
 * oversized dashboard state is compacted rather than failing the page.
 */
export function toPluginJson(value: unknown): unknown {
  let cloned: unknown;
  try {
    cloned = jsonClone(value);
  } catch {
    throw new FeatureOperationError("Operation result is not JSON-serializable", "INVALID_OUTPUT");
  }
  if (cloned === undefined) return undefined;
  if (isPluginJsonValue(cloned)) return cloned;
  const compacted = compactDashboardState(cloned);
  if (isPluginJsonValue(compacted)) return compacted;
  throw new FeatureOperationError("Operation result exceeds host JSON size limits", "INVALID_OUTPUT");
}

function sessionActionRegistrar(
  api: FeatureCapableApi,
): ((action: SessionActionRegistration) => void) | undefined {
  const grouped = api.session?.controls?.registerSessionAction;
  if (typeof grouped === "function") return grouped.bind(api.session!.controls!);
  const flat = api.registerSessionAction;
  if (typeof flat === "function") return flat.bind(api);
  return undefined;
}

/**
 * True when this host can dispatch plugin session actions, which is what the
 * native Control UI page needs. Probing the API is steadier than reading a
 * version string: every plugin API is experimental and may move again.
 */
export function supportsFeatureOperations(api: FeatureCapableApi): boolean {
  return sessionActionRegistrar(api) !== undefined;
}

export type FeatureEventEmitter = {
  emit: (event: SentrookEvent) => void;
};

/**
 * Change events carry no payload: a client refetches ``state`` when one
 * arrives. That keeps the event contract stable while the state shape grows,
 * and avoids leaking review content to ``operator.read`` subscribers beyond
 * what ``state`` already returns.
 */
export function registerFeatureEvents(api: FeatureCapableApi, pluginId: string): FeatureEventEmitter {
  let gatewayEvents: GatewayEvents | undefined;
  if (typeof api.registerService === "function") {
    api.registerService({
      id: `${pluginId}:feature-events`,
      start(ctx) {
        gatewayEvents = ctx.gatewayEvents;
      },
      stop() {
        gatewayEvents = undefined;
      },
    });
  }
  return {
    emit(event) {
      if (!gatewayEvents) return;
      try {
        gatewayEvents.emit(event, { at: Date.now() }, { scope: "operator.read" });
      } catch (err) {
        api.logger?.warn(`[sentrook-openclaw] event ${event} not delivered: ${String(err)}`);
      }
    },
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Registers every contract operation. Returns the number registered so a
 * caller can log it, or 0 when the host has no session-action transport.
 */
export function registerFeatureOperations(
  api: FeatureCapableApi,
  handlers: FeatureHandlers,
): number {
  const register = sessionActionRegistrar(api);
  if (!register) return 0;

  let count = 0;
  for (const [id, spec] of Object.entries(SENTROOK_OPERATIONS)) {
    const name = id as SentrookOperationName;
    const handler = handlers[name];
    register({
      id,
      description: spec.description,
      schema: spec.input,
      requiredScopes: [scopeForOperation(spec.kind)],
      async handler(ctx) {
        try {
          const result = await handler(asRecord(ctx.payload) as never, {
            sessionKey: ctx.sessionKey,
            agentId: ctx.agentId,
            scopes: ctx.client?.scopes ?? [],
          });
          const json = toPluginJson(result);
          return json === undefined ? { ok: true } : { ok: true, result: json };
        } catch (err) {
          if (err instanceof FeatureOperationError) {
            return { ok: false, error: err.message, code: err.code };
          }
          api.logger?.warn(`[sentrook-openclaw] operation ${id} failed: ${String(err)}`);
          return {
            ok: false,
            error: err instanceof Error ? err.message : String(err),
            code: "OPERATION_FAILED",
          };
        }
      },
    });
    count += 1;
  }
  return count;
}
