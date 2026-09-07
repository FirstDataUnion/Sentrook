/**
 * Resolve OpenClaw ``plugin:`` approval ids from the dashboard.
 *
 * Prefer in-process ``api.runtime.gateway.request``. Fall back to the host
 * SDK helper when this is an external plugin and runtime RPC is rejected.
 */

export type PluginRuntimeGateway = {
  isAvailable?: () => Promise<boolean>;
  request: (
    method: string,
    params?: unknown,
    opts?: { timeoutMs?: number },
  ) => Promise<unknown>;
};

export type ApprovalListItem = {
  id: string;
  request?: {
    pluginId?: string | null;
    toolCallId?: string | null;
    toolName?: string | null;
    title?: string | null;
  };
};

export type ResolveDecision = "allow-once" | "allow-always" | "deny";

function asList(raw: unknown): ApprovalListItem[] {
  if (Array.isArray(raw)) return raw as ApprovalListItem[];
  if (raw && typeof raw === "object") {
    const rec = raw as Record<string, unknown>;
    if (Array.isArray(rec.approvals)) return rec.approvals as ApprovalListItem[];
    if (Array.isArray(rec.result)) return rec.result as ApprovalListItem[];
  }
  return [];
}

async function gatewayRequest(
  gateway: PluginRuntimeGateway | undefined,
  method: string,
  params?: unknown,
): Promise<unknown> {
  if (!gateway?.request) {
    throw new Error("gateway RPC is not available in this plugin runtime");
  }
  if (gateway.isAvailable && !(await gateway.isAvailable())) {
    throw new Error("gateway RPC is not available in this plugin runtime");
  }
  return gateway.request(method, params ?? {}, { timeoutMs: 15_000 });
}

export async function listPluginApprovals(
  gateway: PluginRuntimeGateway | undefined,
): Promise<ApprovalListItem[]> {
  if (!gateway) return [];
  try {
    return asList(await gatewayRequest(gateway, "plugin.approval.list"));
  } catch {
    return [];
  }
}

export function matchApprovalId(
  list: ApprovalListItem[],
  toolCallId: string | undefined,
  pluginId = "sentrook-openclaw",
): string | undefined {
  if (!toolCallId) return undefined;
  const hits = list.filter((item) => item.request?.toolCallId === toolCallId);
  const ours = hits.find((item) => !item.request?.pluginId || item.request.pluginId === pluginId);
  return (ours ?? hits[0])?.id;
}

export async function resolvePluginApproval(input: {
  gateway?: PluginRuntimeGateway;
  config?: unknown;
  approvalId: string;
  decision: ResolveDecision;
}): Promise<void> {
  if (input.gateway) {
    try {
      await gatewayRequest(input.gateway, "plugin.approval.resolve", {
        id: input.approvalId,
        decision: input.decision,
      });
      return;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!/rejected|not available|not found|unknown method/i.test(message)) {
        throw err;
      }
    }
  }
  const mod = await importApprovalSdk();
  const resolveOverGateway = mod?.resolveApprovalOverGateway;
  if (!resolveOverGateway) {
    throw new Error(
      "Cannot resolve from this dashboard (gateway RPC unavailable). Use /approve in chat.",
    );
  }
  await resolveOverGateway({
    cfg: input.config,
    approvalId: input.approvalId,
    decision: input.decision,
    clientDisplayName: "Sentrook dashboard",
  });
}

async function importApprovalSdk(): Promise<{
  resolveApprovalOverGateway?: (params: Record<string, unknown>) => Promise<void>;
} | null> {
  try {
    const importer = new Function("s", "return import(s)") as (
      s: string,
    ) => Promise<Record<string, unknown>>;
    return (await importer("openclaw/plugin-sdk/approval-gateway-runtime")) as {
      resolveApprovalOverGateway?: (params: Record<string, unknown>) => Promise<void>;
    };
  } catch {
    return null;
  }
}
