import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  applyApprovalRequested,
  joinCardApprovalIds,
  listPluginApprovals,
  matchApprovalId,
  resolvePluginApproval,
  type PluginRuntimeGateway,
} from "./approvalGateway.ts";

describe("matchApprovalId", () => {
  it("matches our plugin card by toolCallId", () => {
    const id = matchApprovalId(
      [
        {
          id: "plugin:other",
          request: { pluginId: "other", toolCallId: "t1" },
        },
        {
          id: "plugin:ours",
          request: { pluginId: "sentrook-openclaw", toolCallId: "t1" },
        },
      ],
      "t1",
    );
    assert.equal(id, "plugin:ours");
  });

  it("falls back to the first toolCallId hit when pluginId is absent", () => {
    const id = matchApprovalId(
      [{ id: "plugin:bare", request: { toolCallId: "t1" } }],
      "t1",
    );
    assert.equal(id, "plugin:bare");
  });

  it("falls back to the only Sentrook approval when toolCallId is missing", () => {
    const id = matchApprovalId(
      [{ id: "plugin:only", request: { pluginId: "sentrook-openclaw" } }],
      "unknown-call",
    );
    assert.equal(id, "plugin:only");
  });

  it("matches plugin:<toolCallId> and event ids, and approvalId aliases", () => {
    assert.equal(
      matchApprovalId([{ id: "plugin:t1", request: { pluginId: "sentrook-openclaw" } }], "t1"),
      "plugin:t1",
    );
    assert.equal(
      matchApprovalId(
        [{ id: "plugin:joined", request: { pluginId: "sentrook-openclaw", toolCallId: "evt-1" } }],
        ["t-other", "evt-1"],
      ),
      "plugin:joined",
    );
  });

  it("matches the only Sentrook item in the same session when toolCallId is absent", () => {
    const id = matchApprovalId(
      [
        {
          id: "plugin:other-session",
          request: { pluginId: "sentrook-openclaw", sessionKey: "other", toolName: "exec" },
        },
        {
          id: "plugin:same-session",
          request: { pluginId: "sentrook-openclaw", sessionKey: "main", toolName: "exec" },
        },
      ],
      "unknown-call",
      "sentrook-openclaw",
      { sessionKey: "main", toolName: "exec" },
    );
    assert.equal(id, "plugin:same-session");
  });
});

describe("listPluginApprovals", () => {
  it("returns [] when gateway is missing or list fails", async () => {
    assert.deepEqual(await listPluginApprovals(undefined), []);
    const gateway: PluginRuntimeGateway = {
      request: async () => {
        throw new Error("rejected");
      },
    };
    assert.deepEqual(await listPluginApprovals(gateway, { listOverApprovalRuntime: async () => [] }), []);
  });

  it("falls back to the approval-runtime list when plugin.approval.list is empty", async () => {
    const gateway: PluginRuntimeGateway = {
      request: async () => [],
    };
    const listed = await listPluginApprovals(gateway, {
      listOverApprovalRuntime: async () => [
        { id: "plugin:hidden", request: { pluginId: "sentrook-openclaw", toolCallId: "t1" } },
      ],
    });
    assert.equal(listed[0]?.id, "plugin:hidden");
  });

  it("falls back to the approval-runtime list when plugin.approval.list is rejected", async () => {
    const gateway: PluginRuntimeGateway = {
      request: async () => {
        throw new Error("method rejected for external plugins");
      },
    };
    const listed = await listPluginApprovals(gateway, {
      listOverApprovalRuntime: async () => [{ id: "plugin:sdk", request: { toolCallId: "t1" } }],
    });
    assert.equal(listed[0]?.id, "plugin:sdk");
  });

  it("unwraps { approvals } payloads", async () => {
    const gateway: PluginRuntimeGateway = {
      request: async () => ({
        approvals: [{ id: "plugin:a", request: { toolCallId: "t1" } }],
      }),
    };
    const listed = await listPluginApprovals(gateway);
    assert.equal(listed[0]?.id, "plugin:a");
  });

  it("unwraps nested { result: { approvals } } list payloads", async () => {
    const gateway: PluginRuntimeGateway = {
      request: async () => ({
        ok: true,
        result: { approvals: [{ id: "plugin:nested", request: { toolCallId: "t1" } }] },
      }),
    };
    const listed = await listPluginApprovals(gateway);
    assert.equal(listed[0]?.id, "plugin:nested");
  });

  it("normalizes approvalId and tool_call_id aliases", async () => {
    const gateway: PluginRuntimeGateway = {
      request: async () => ({
        payload: {
          items: [{ approvalId: "plugin:alias", tool_call_id: "t-alias", pluginId: "sentrook-openclaw" }],
        },
      }),
    };
    const listed = await listPluginApprovals(gateway);
    assert.equal(listed[0]?.id, "plugin:alias");
    assert.equal(listed[0]?.request?.toolCallId, "t-alias");
    assert.equal(matchApprovalId(listed, "t-alias"), "plugin:alias");
  });
});

describe("resolvePluginApproval", () => {
  it("resolves via gateway.request", async () => {
    const calls: Array<{ method: string; params?: unknown }> = [];
    const gateway: PluginRuntimeGateway = {
      isAvailable: async () => true,
      request: async (method, params) => {
        calls.push({ method, params });
        return { ok: true };
      },
    };
    await resolvePluginApproval({
      gateway,
      approvalId: "plugin:abc",
      decision: "allow-once",
    });
    assert.deepEqual(calls, [
      {
        method: "plugin.approval.resolve",
        params: { id: "plugin:abc", decision: "allow-once" },
      },
    ]);
  });

  it("falls back to a chat hint when RPC is rejected and the SDK is absent", async () => {
    const gateway: PluginRuntimeGateway = {
      request: async () => {
        throw new Error("method rejected for external plugins");
      },
    };
    await assert.rejects(
      () =>
        resolvePluginApproval({
          gateway,
          approvalId: "plugin:abc",
          decision: "deny",
        }),
      /Cannot resolve from this dashboard.*\/approve/,
    );
  });
});

describe("joinCardApprovalIds", () => {
  it("attaches a listed plugin: id onto the matching review card", async () => {
    const cards: Array<{
      toolCallId: string;
      eventId?: string;
      approvalId?: string;
      sessionKey?: string;
      tool?: string;
    }> = [{ toolCallId: "t1", eventId: "evt-1", sessionKey: "main", tool: "exec" }];
    const store = {
      list: () => cards,
      attachApprovalId: (toolCallId: string, approvalId: string) => {
        const card = cards.find((row) => row.toolCallId === toolCallId);
        if (card) card.approvalId = approvalId;
      },
    };
    await joinCardApprovalIds(store, undefined, {
      listOverApprovalRuntime: async () => [
        {
          id: "plugin:from-runtime",
          request: { pluginId: "sentrook-openclaw", toolCallId: "t1", sessionKey: "main" },
        },
      ],
    });
    assert.equal(cards[0]?.approvalId, "plugin:from-runtime");
  });

  it("joins plugin.approval.requested payloads that wrap the record", () => {
    const cards: Array<{
      toolCallId: string;
      eventId?: string;
      approvalId?: string;
      sessionKey?: string;
      tool?: string;
    }> = [{ toolCallId: "t1", eventId: "evt-1", sessionKey: "main", tool: "exec" }];
    const store = {
      list: () => cards,
      attachApprovalId: (toolCallId: string, approvalId: string) => {
        const card = cards.find((row) => row.toolCallId === toolCallId);
        if (card) card.approvalId = approvalId;
      },
    };
    const id = applyApprovalRequested(store, {
      payload: {
        id: "plugin:evt",
        request: { pluginId: "sentrook-openclaw", toolCallId: "t1", sessionKey: "main" },
      },
    });
    assert.equal(id, "plugin:evt");
    assert.equal(cards[0]?.approvalId, "plugin:evt");
  });
});
