import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  SENTROOK_EVENTS,
  SENTROOK_OPERATIONS,
  assertContractIds,
  scopeForOperation,
} from "./featureContract.ts";
import {
  FeatureOperationError,
  isPluginJsonValue,
  registerFeatureEvents,
  registerFeatureOperations,
  supportsFeatureOperations,
  toPluginJson,
  type FeatureCapableApi,
  type FeatureHandlers,
} from "./featureOperations.ts";

type Registered = {
  id: string;
  description?: string;
  schema?: unknown;
  requiredScopes?: string[];
  handler: (ctx: Record<string, unknown>) => unknown;
};

function stubHandlers(overrides: Partial<FeatureHandlers> = {}): FeatureHandlers {
  const unused = () => {
    throw new Error("not called");
  };
  return {
    state: unused,
    resolve: unused,
    policy: unused,
    log: unused,
    "allowlist.rm": unused,
    "allowlist.add": unused,
    setup: unused,
    verify: unused,
    ...overrides,
  } as FeatureHandlers;
}

function groupedApi(sink: Registered[]): FeatureCapableApi {
  return {
    session: { controls: { registerSessionAction: (action) => sink.push(action as Registered) } },
  };
}

describe("feature contract", () => {
  it("keeps operation and event ids inside the host's id grammar", () => {
    assert.doesNotThrow(() => assertContractIds(SENTROOK_OPERATIONS, SENTROOK_EVENTS));
    // Operation ids may contain dots; event ids may not.
    assert.doesNotThrow(() => assertContractIds({ "allowlist.rm": {} }, []));
    assert.throws(() => assertContractIds({}, ["reviews.changed"]), /Invalid Sentrook event id/);
    assert.throws(() => assertContractIds({ Resolve: {} }, []), /Invalid Sentrook operation id/);
  });

  it("maps queries to operator.read and actions to operator.write", () => {
    assert.equal(scopeForOperation("query"), "operator.read");
    assert.equal(scopeForOperation("action"), "operator.write");
    assert.equal(SENTROOK_OPERATIONS.state.kind, "query");
    assert.equal(SENTROOK_OPERATIONS.policy.kind, "action");
  });
});

describe("registerFeatureOperations", () => {
  it("registers one scoped session action per operation", () => {
    const sink: Registered[] = [];
    const count = registerFeatureOperations(groupedApi(sink), stubHandlers());

    assert.equal(count, Object.keys(SENTROOK_OPERATIONS).length);
    assert.deepEqual(
      sink.map((action) => action.id).sort(),
      Object.keys(SENTROOK_OPERATIONS).sort(),
    );
    const state = sink.find((action) => action.id === "state");
    assert.deepEqual(state?.requiredScopes, ["operator.read"]);
    assert.equal(state?.schema, SENTROOK_OPERATIONS.state.input);
    assert.deepEqual(
      sink.find((action) => action.id === "policy")?.requiredScopes,
      ["operator.write"],
    );
  });

  it("prefers the grouped namespace but accepts the flat alias", () => {
    const grouped: Registered[] = [];
    const flat: Registered[] = [];
    const api: FeatureCapableApi = {
      registerSessionAction: (action) => flat.push(action as Registered),
      session: { controls: { registerSessionAction: (action) => grouped.push(action as Registered) } },
    };
    registerFeatureOperations(api, stubHandlers());
    assert.equal(grouped.length, Object.keys(SENTROOK_OPERATIONS).length);
    assert.equal(flat.length, 0);

    const flatOnly: Registered[] = [];
    registerFeatureOperations(
      { registerSessionAction: (action) => flatOnly.push(action as Registered) },
      stubHandlers(),
    );
    assert.equal(flatOnly.length, Object.keys(SENTROOK_OPERATIONS).length);
  });

  it("registers nothing on a host without a session-action transport", () => {
    assert.equal(supportsFeatureOperations({}), false);
    assert.equal(registerFeatureOperations({}, stubHandlers()), 0);
    assert.equal(supportsFeatureOperations(groupedApi([])), true);
  });

  it("wraps a handler result in the host's ok envelope", async () => {
    const sink: Registered[] = [];
    registerFeatureOperations(
      groupedApi(sink),
      stubHandlers({ "allowlist.rm": () => ({ ok: true }) }),
    );
    const action = sink.find((entry) => entry.id === "allowlist.rm");
    const reply = await action?.handler({ payload: { index: 1 } });
    assert.deepEqual(reply, { ok: true, result: { ok: true } });
  });

  it("passes the calling connection's scopes and session identity through", async () => {
    const seen: unknown[] = [];
    const sink: Registered[] = [];
    registerFeatureOperations(
      groupedApi(sink),
      stubHandlers({
        state: (_input, context) => {
          seen.push(context);
          return {} as never;
        },
      }),
    );
    await sink.find((entry) => entry.id === "state")?.handler({
      payload: {},
      sessionKey: "sk",
      agentId: "agent",
      client: { scopes: ["operator.read"] },
    });
    assert.deepEqual(seen, [{ sessionKey: "sk", agentId: "agent", scopes: ["operator.read"] }]);
  });

  it("reports operator-facing errors without crashing the dispatch", async () => {
    const sink: Registered[] = [];
    registerFeatureOperations(
      groupedApi(sink),
      stubHandlers({
        resolve: () => {
          throw new FeatureOperationError("No pending review for that id", "NOT_FOUND");
        },
        policy: () => {
          throw new Error("disk on fire");
        },
      }),
    );
    const warnings: string[] = [];
    const resolve = sink.find((entry) => entry.id === "resolve");
    assert.deepEqual(await resolve?.handler({ payload: { decision: "deny" } }), {
      ok: false,
      error: "No pending review for that id",
      code: "NOT_FOUND",
    });

    const loud: Registered[] = [];
    registerFeatureOperations(
      {
        logger: { warn: (msg) => warnings.push(msg) },
        session: { controls: { registerSessionAction: (action) => loud.push(action as Registered) } },
      },
      stubHandlers({
        policy: () => {
          throw new Error("disk on fire");
        },
      }),
    );
    assert.deepEqual(await loud.find((entry) => entry.id === "policy")?.handler({ payload: {} }), {
      ok: false,
      error: "disk on fire",
      code: "OPERATION_FAILED",
    });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /operation policy failed/);
  });

  it("treats a non-object payload as an empty input", async () => {
    const seen: unknown[] = [];
    const sink: Registered[] = [];
    registerFeatureOperations(
      groupedApi(sink),
      stubHandlers({
        state: (input) => {
          seen.push(input);
          return {} as never;
        },
      }),
    );
    await sink.find((entry) => entry.id === "state")?.handler({ payload: "nope" });
    await sink.find((entry) => entry.id === "state")?.handler({});
    assert.deepEqual(seen, [{}, {}]);
  });
});

describe("toPluginJson", () => {
  it("rejects undefined the same way the host's session-action check does", () => {
    assert.equal(isPluginJsonValue({ sessionId: undefined }), false);
    assert.equal(isPluginJsonValue({ sessionId: "s1" }), true);
  });

  it("drops undefined keys so dashboard rows survive the host check", () => {
    const json = toPluginJson({
      sessionId: undefined,
      sessionKey: "agent:main:main",
      nested: { excerpt: undefined, risk: 0.4 },
      pending: [{ approvalId: undefined, tool: "exec", args: { command: "ls", unused: undefined } }],
    });
    assert.equal(isPluginJsonValue(json), true);
    assert.deepEqual(json, {
      sessionKey: "agent:main:main",
      nested: { risk: 0.4 },
      pending: [{ tool: "exec", args: { command: "ls" } }],
    });
  });

  it("turns Dates into ISO strings instead of class instances", () => {
    const json = toPluginJson({ when: new Date("2026-01-01T00:00:00.000Z") });
    assert.equal(isPluginJsonValue(json), true);
    assert.deepEqual(json, { when: "2026-01-01T00:00:00.000Z" });
  });

  it("omits a missing handler result instead of sending undefined", async () => {
    const sink: Registered[] = [];
    registerFeatureOperations(
      groupedApi(sink),
      stubHandlers({ state: () => undefined as never }),
    );
    assert.deepEqual(await sink.find((entry) => entry.id === "state")?.handler({ payload: {} }), {
      ok: true,
    });
  });

  it("compacts an oversized timeline until the host's node budget fits", () => {
    const history = Array.from({ length: 400 }, (_, i) => ({
      id: `h${i}`,
      ts: "2026-01-01T00:00:00.000Z",
      a: 1,
      b: 2,
      c: 3,
      d: 4,
      e: 5,
      f: 6,
      g: 7,
      h: 8,
      i: 9,
      j: 10,
      neighbors: [{ id: "x", tool: "exec", command: "ls" }],
      args: { command: "x".repeat(80) },
    }));
    const bloated = { pending: [], history, audit: { scanned: 400 } };
    assert.equal(isPluginJsonValue(bloated), false);
    const json = toPluginJson(bloated) as { history: unknown[] };
    assert.equal(isPluginJsonValue(json), true);
    assert.ok(json.history.length > 0);
    assert.ok(json.history.length < history.length);
    assert.equal("args" in (json.history[0] as object), false);
  });

  it("strips undefined from a live session-action envelope", async () => {
    const sink: Registered[] = [];
    registerFeatureOperations(
      groupedApi(sink),
      stubHandlers({
        state: () =>
          ({
            pending: [],
            history: [{ id: "1", sessionId: undefined, command: "ls" }],
            sessions: [{ sessionKey: "k", sessionId: undefined, allowAll: false }],
          }) as never,
      }),
    );
    const reply = (await sink.find((entry) => entry.id === "state")?.handler({ payload: {} })) as {
      ok: true;
      result: unknown;
    };
    assert.equal(reply.ok, true);
    assert.equal(isPluginJsonValue(reply.result), true);
    assert.deepEqual(reply.result, {
      pending: [],
      history: [{ id: "1", command: "ls" }],
      sessions: [{ sessionKey: "k", allowAll: false }],
    });
  });
});

describe("registerFeatureEvents", () => {
  it("emits read-scoped change events once the service has started", () => {
    const emitted: Array<{ event: string; opts?: { scope?: string } }> = [];
    let start: ((ctx: { gatewayEvents?: { emit: typeof emit } }) => void) | undefined;
    const emit = (event: string, _payload: unknown, opts?: { scope?: string }) => {
      emitted.push({ event, opts });
    };
    const events = registerFeatureEvents(
      {
        registerService: (service) => {
          start = service.start;
        },
      },
      "sentrook-openclaw",
    );

    // Before the service starts there is no transport; emitting must not throw.
    events.emit("reviews_changed");
    assert.deepEqual(emitted, []);

    start?.({ gatewayEvents: { emit } });
    events.emit("reviews_changed");
    events.emit("policy_changed");
    assert.deepEqual(
      emitted.map((entry) => entry.event),
      ["reviews_changed", "policy_changed"],
    );
    assert.deepEqual(emitted[0]?.opts, { scope: "operator.read" });
  });

  it("survives a host with no service registration", () => {
    const events = registerFeatureEvents({}, "sentrook-openclaw");
    assert.doesNotThrow(() => events.emit("log_changed"));
  });
});
