/**
 * Browser-safe client for the Sentrook contract.
 *
 * Ports the host's ``createFeatureClient`` without importing the OpenClaw SDK:
 * every call is ``plugins.sessionAction`` with ``{ pluginId, actionId, payload }``,
 * and ``watch`` refetches on named events and reconnect — it does not poll.
 */

import {
  SENTROOK_PLUGIN_ID,
  type SentrookEvent,
  type SentrookInputs,
  type SentrookOperationName,
  type SentrookOutputs,
} from "./featureContract.ts";

export type FeatureDisposer = () => void;

export type FeatureTransport = {
  readonly pluginId: string;
  readonly signal: AbortSignal;
  readonly connection: { connected: boolean };
  request: <T = unknown>(method: string, params?: Record<string, unknown>) => Promise<T>;
  onEvent: (event: string, listener: (payload: unknown) => void) => FeatureDisposer;
  subscribe: (listener: () => void) => FeatureDisposer;
};

export type FeatureRequestOptions = {
  sessionKey?: string;
  agentId?: string;
};

export type SentrookClient = {
  invoke: <K extends SentrookOperationName>(
    operation: K,
    input: SentrookInputs[K],
    options?: FeatureRequestOptions,
  ) => Promise<SentrookOutputs[K]>;
  on: (event: SentrookEvent, listener: (payload: unknown) => void) => FeatureDisposer;
  watch: (
    operation: "state",
    input: SentrookInputs["state"],
    options: FeatureRequestOptions & {
      events: readonly SentrookEvent[];
      onChange: (output: SentrookOutputs["state"]) => void;
      onError: (error: Error) => void;
    },
  ) => FeatureDisposer;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function createSentrookClient(host: FeatureTransport): SentrookClient {
  if (host.pluginId !== SENTROOK_PLUGIN_ID) {
    throw new Error("Feature contract must belong to the active browser plugin");
  }
  const invoke = async <K extends SentrookOperationName>(
    operation: K,
    input: SentrookInputs[K],
    options: FeatureRequestOptions = {},
  ): Promise<SentrookOutputs[K]> => {
    host.signal.throwIfAborted();
    const result = await host.request("plugins.sessionAction", {
      pluginId: SENTROOK_PLUGIN_ID,
      actionId: operation,
      payload: input,
      ...options,
    });
    host.signal.throwIfAborted();
    if (!isRecord(result) || result.ok !== true) {
      throw new Error(
        isRecord(result) && typeof result.error === "string"
          ? result.error
          : "Feature operation returned an invalid response",
      );
    }
    return result.result as SentrookOutputs[K];
  };
  const on = (event: SentrookEvent, listener: (payload: unknown) => void) =>
    host.onEvent(`plugin.${SENTROOK_PLUGIN_ID}.${event}`, listener);
  const watch: SentrookClient["watch"] = (_operation, input, options) => {
    let disposed = false;
    let generation = 0;
    let scheduled = false;
    let connected = host.connection.connected;
    const refresh = () => {
      generation += 1;
      if (disposed || !host.connection.connected || scheduled) return;
      scheduled = true;
      queueMicrotask(() => {
        scheduled = false;
        if (disposed || !host.connection.connected) return;
        const current = generation;
        invoke("state", input, {
          sessionKey: options.sessionKey,
          agentId: options.agentId,
        }).then(
          (output) => {
            if (!disposed && current === generation && host.connection.connected) {
              options.onChange(output);
            }
          },
          (error) => {
            if (!disposed && current === generation && host.connection.connected) {
              options.onError(error instanceof Error ? error : new Error(String(error)));
            }
          },
        );
      });
    };
    const subscriptions = options.events.map((event) => on(event, refresh));
    subscriptions.push(
      host.subscribe(() => {
        if (connected !== host.connection.connected) {
          connected = host.connection.connected;
          refresh();
        }
      }),
    );
    const dispose = () => {
      disposed = true;
      generation += 1;
      for (const unsubscribe of subscriptions) unsubscribe();
      host.signal.removeEventListener("abort", dispose);
    };
    host.signal.addEventListener("abort", dispose, { once: true });
    if (host.signal.aborted) dispose();
    else refresh();
    return dispose;
  };
  return { invoke, on, watch };
}
