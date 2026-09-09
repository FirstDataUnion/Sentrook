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
    description?: string | null;
    severity?: string | null;
    timeoutMs?: number | null;
  };
};

export const SENTROOK_PLUGIN_ID = "sentrook-openclaw";

export function isSentrookApproval(
  item: ApprovalListItem,
  pluginId = SENTROOK_PLUGIN_ID,
): boolean {
  const id = item.request?.pluginId;
  return !id || id === pluginId;
}

export type ResolveDecision = "allow-once" | "allow-always" | "deny";

function nonempty(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asItem(raw: unknown): ApprovalListItem | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const rec = raw as Record<string, unknown>;
  const reqRaw = rec.request;
  const req =
    reqRaw && typeof reqRaw === "object" && !Array.isArray(reqRaw)
      ? (reqRaw as Record<string, unknown>)
      : {};
  const id = nonempty(rec.id) ?? nonempty(rec.approvalId) ?? nonempty(req.id);
  if (!id) return undefined;
  return {
    id,
    request: {
      pluginId: nonempty(req.pluginId) ?? nonempty(rec.pluginId),
      toolCallId:
        nonempty(req.toolCallId) ??
        nonempty(req.tool_call_id) ??
        nonempty(rec.toolCallId) ??
        nonempty(rec.tool_call_id),
      toolName: nonempty(req.toolName) ?? nonempty(rec.toolName),
      title: nonempty(req.title),
      description: nonempty(req.description),
      severity: nonempty(req.severity),
      timeoutMs: typeof req.timeoutMs === "number" ? req.timeoutMs : undefined,
    },
  };
}

function extractList(raw: unknown, depth = 0): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (!raw || typeof raw !== "object" || depth > 3) return [];
  const rec = raw as Record<string, unknown>;
  for (const key of ["approvals", "items", "pending"]) {
    if (Array.isArray(rec[key])) return rec[key] as unknown[];
  }
  if (Array.isArray(rec.result)) return rec.result;
  if (rec.result && typeof rec.result === "object") return extractList(rec.result, depth + 1);
  if (rec.data && typeof rec.data === "object") return extractList(rec.data, depth + 1);
  if (rec.payload && typeof rec.payload === "object") return extractList(rec.payload, depth + 1);
  return [];
}

function asList(raw: unknown): ApprovalListItem[] {
  return extractList(raw)
    .map(asItem)
    .filter((item): item is ApprovalListItem => Boolean(item));
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

function wantedIds(toolCallId: string | undefined | Array<string | undefined>): Set<string> {
  const keys = (Array.isArray(toolCallId) ? toolCallId : [toolCallId]).filter(
    (id): id is string => typeof id === "string" && id.trim().length > 0,
  );
  const wanted = new Set<string>();
  for (const raw of keys) {
    const id = raw.trim();
    wanted.add(id);
    if (!id.startsWith("plugin:")) wanted.add(`plugin:${id}`);
  }
  return wanted;
}

export function matchApprovalId(
  list: ApprovalListItem[],
  toolCallId: string | undefined | Array<string | undefined>,
  pluginId = "sentrook-openclaw",
): string | undefined {
  const wanted = wantedIds(toolCallId);
  if (wanted.size > 0) {
    const hits = list.filter((item) => {
      const call = item.request?.toolCallId;
      return (call && wanted.has(call)) || wanted.has(item.id);
    });
    const ours = hits.find((item) => !item.request?.pluginId || item.request.pluginId === pluginId);
    const hit = ours ?? hits[0];
    if (hit?.id) return hit.id;
  }
  const ours = list.filter((item) => isSentrookApproval(item, pluginId) && item.id);
  if (ours.length === 1) return ours[0]!.id;
  return undefined;
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
