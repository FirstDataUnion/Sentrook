import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { SENTROOK_PLUGIN_ID } from "./featureContract.ts";
import { createSentrookClient, type FeatureTransport } from "./featureClient.ts";

function mockHost(opts?: {
  request?: FeatureTransport["request"];
  connected?: boolean;
}): {
  host: FeatureTransport;
  requests: Array<{ method: string; params?: Record<string, unknown> }>;
  emitEvent: (event: string) => void;
  setConnected: (value: boolean) => void;
  abort: () => void;
} {
  const requests: Array<{ method: string; params?: Record<string, unknown> }> = [];
  const eventListeners = new Map<string, Array<(payload: unknown) => void>>();
  const subscribers: Array<() => void> = [];
  const ac = new AbortController();
  let connected = opts?.connected ?? true;
  const host: FeatureTransport = {
    pluginId: SENTROOK_PLUGIN_ID,
    signal: ac.signal,
    connection: {
      get connected() {
        return connected;
      },
    },
    request: async (method, params) => {
      requests.push({ method, params });
      if (opts?.request) return opts.request(method, params);
      return { ok: true, result: { pending: [] } };
    },
    onEvent: (event, listener) => {
      const list = eventListeners.get(event) ?? [];
      list.push(listener);
      eventListeners.set(event, list);
      return () => {
        const next = (eventListeners.get(event) ?? []).filter((fn) => fn !== listener);
        eventListeners.set(event, next);
      };
    },
    subscribe: (listener) => {
      subscribers.push(listener);
      return () => {
        const idx = subscribers.indexOf(listener);
        if (idx >= 0) subscribers.splice(idx, 1);
      };
    },
  };
  return {
    host,
    requests,
    emitEvent: (event) => {
      for (const listener of eventListeners.get(event) ?? []) listener({});
    },
    setConnected: (value) => {
      connected = value;
      for (const listener of subscribers) listener();
    },
    abort: () => ac.abort(),
  };
}

describe("createSentrookClient", () => {
  it("rejects a host bound to a different plugin", () => {
    const { host } = mockHost();
    assert.throws(
      () => createSentrookClient({ ...host, pluginId: "other" }),
      /active browser plugin/,
    );
  });

  it("invokes plugins.sessionAction with the contract ids", async () => {
    const { host, requests } = mockHost({
      request: async () => ({ ok: true, result: { ok: true, persisted: true } }),
    });
    const client = createSentrookClient(host);
    const out = await client.invoke("policy", { sensitivity: "warning" });
    assert.deepEqual(out, { ok: true, persisted: true });
    assert.deepEqual(requests, [
      {
        method: "plugins.sessionAction",
        params: {
          pluginId: SENTROOK_PLUGIN_ID,
          actionId: "policy",
          payload: { sensitivity: "warning" },
        },
      },
    ]);
  });

  it("surfaces the operator-facing error string from a failed envelope", async () => {
    const { host } = mockHost({
      request: async () => ({ ok: false, error: "No pending review for that id" }),
    });
    await assert.rejects(
      createSentrookClient(host).invoke("resolve", { decision: "deny", toolCallId: "x" }),
      /No pending review for that id/,
    );
  });

  it("watches state on events and reconnect, not on a timer", async () => {
    let calls = 0;
    const { host, emitEvent, setConnected } = mockHost({
      request: async () => {
        calls += 1;
        return { ok: true, result: { n: calls } };
      },
    });
    const seen: unknown[] = [];
    const errors: Error[] = [];
    const stop = createSentrookClient(host).watch("state", {}, {
      events: ["reviews_changed"],
      onChange: (output) => seen.push(output),
      onError: (error) => errors.push(error),
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(calls, 1);
    emitEvent(`plugin.${SENTROOK_PLUGIN_ID}.reviews_changed`);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(calls, 2);
    setConnected(false);
    emitEvent(`plugin.${SENTROOK_PLUGIN_ID}.reviews_changed`);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(calls, 2);
    setConnected(true);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(calls, 3);
    stop();
    emitEvent(`plugin.${SENTROOK_PLUGIN_ID}.reviews_changed`);
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(calls, 3);
    assert.equal(errors.length, 0);
    assert.equal(seen.length, 3);
  });
});
