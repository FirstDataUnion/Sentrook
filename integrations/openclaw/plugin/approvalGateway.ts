/**
 * Resolve OpenClaw ``plugin:`` approval ids from the dashboard.
 *
 * Prefer in-process ``api.runtime.gateway.request``. That client is
 * ``operator.write`` and is not the tool-approval requester, so
 * ``plugin.approval.list`` is often empty (visibility is requester-bound).
 * Fall back to the host's approval-runtime client — the same path
 * ``resolveApprovalOverGateway`` uses — which can see those records.
 * Fall back again to the host SDK helper when this is an external plugin
 * and runtime RPC is rejected.
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
    sessionKey?: string | null;
    agentId?: string | null;
  };
};

export const SENTROOK_PLUGIN_ID = "sentrook-openclaw";

export type ListPluginApprovalsOptions = {
  config?: unknown;
  logger?: { warn: (msg: string) => void; info?: (msg: string) => void };
  /** Test seam: skip host SDK import and return this list instead. */
  listOverApprovalRuntime?: (config?: unknown) => Promise<ApprovalListItem[]>;
};

export type ApprovalIdStore = {
  list: () => Array<{
    toolCallId: string;
    eventId?: string;
    approvalId?: string;
    sessionKey?: string;
    tool?: string;
  }>;
  attachApprovalId: (toolCallId: string, approvalId: string) => void;
};

export type MatchApprovalHints = {
  sessionKey?: string;
  toolName?: string;
};

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
      sessionKey: nonempty(req.sessionKey) ?? nonempty(rec.sessionKey),
      agentId: nonempty(req.agentId) ?? nonempty(rec.agentId),
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

async function importDynamic(specifier: string): Promise<Record<string, unknown> | null> {
  try {
    const importer = new Function("s", "return import(s)") as (
      s: string,
    ) => Promise<Record<string, unknown>>;
    return await importer(specifier);
  } catch {
    return null;
  }
}

type ApprovalRuntimeClient = {
  request: (method: string, params?: Record<string, unknown>) => Promise<unknown>;
  stop?: () => Promise<void> | void;
};

type ChannelRuntimeAdapter = {
  label: string;
  clientDisplayName: string;
  cfg: unknown;
  eventKinds?: readonly string[];
  isConfigured: () => boolean;
  shouldHandle: (request: unknown) => boolean;
  deliverRequested: (request: unknown) => Promise<unknown[]>;
  finalizeResolved: (params: unknown) => Promise<void> | void;
  finalizeExpired?: (params: unknown) => Promise<void> | void;
};

type CaptureState = {
  client: ApprovalRuntimeClient | null;
  start: Promise<ApprovalRuntimeClient | null> | null;
  onRequested?: (item: ApprovalListItem) => void;
};

const capture: CaptureState = { client: null, start: null };
let createRuntime:
  | ((adapter: ChannelRuntimeAdapter) => ApprovalRuntimeClient & { start: () => Promise<void> })
  | false
  | undefined;

async function importCreateRuntime(): Promise<
  ((adapter: ChannelRuntimeAdapter) => ApprovalRuntimeClient & { start: () => Promise<void> }) | null
> {
  if (createRuntime === false) return null;
  if (createRuntime) return createRuntime;
  const mod = await importDynamic("openclaw/plugin-sdk/infra-runtime");
  const create = mod?.createExecApprovalChannelRuntime;
  if (typeof create !== "function") {
    createRuntime = false;
    return null;
  }
  createRuntime = create as (adapter: ChannelRuntimeAdapter) => ApprovalRuntimeClient & {
    start: () => Promise<void>;
  };
  return createRuntime;
}

function pluginIdOfRequest(request: unknown): string | undefined {
  const item = asItem(request);
  return item?.request?.pluginId ?? undefined;
}

async function startApprovalRuntimeClient(opts: {
  config?: unknown;
  onRequested?: (item: ApprovalListItem) => void;
}): Promise<ApprovalRuntimeClient | null> {
  if (opts.config == null) return null;
  const create = await importCreateRuntime();
  if (!create) return null;
  const runtime = create({
    label: "sentrook-openclaw-approvals",
    clientDisplayName: "Sentrook dashboard",
    cfg: opts.config,
    eventKinds: ["plugin"],
    isConfigured: () => true,
    shouldHandle: (request) => {
      const pluginId = pluginIdOfRequest(request);
      return !pluginId || pluginId === SENTROOK_PLUGIN_ID;
    },
    deliverRequested: async (request) => {
      const item = asItem(request);
      if (item) capture.onRequested?.(item);
      return item ? [{ id: item.id }] : [];
    },
    finalizeResolved: async () => {},
    finalizeExpired: async () => {},
  });
  if (typeof (runtime as { start?: unknown }).start !== "function") return null;
  await (runtime as { start: () => Promise<void> }).start();
  return runtime;
}

/**
 * Long-lived approval-runtime client: lists requester-bound ``plugin:`` ids
 * and receives ``plugin.approval.requested`` so the dashboard can join them
 * without waiting for a click.
 */
export async function startApprovalIdCapture(opts: {
  config?: unknown;
  onRequested?: (item: ApprovalListItem) => void;
  logger?: { warn: (msg: string) => void; info?: (msg: string) => void };
}): Promise<void> {
  if (opts.onRequested) capture.onRequested = opts.onRequested;
  if (opts.config == null) return;
  if (capture.client) return;
  if (capture.start) {
    await capture.start;
    return;
  }
  capture.start = startApprovalRuntimeClient(opts)
    .then((client) => {
      capture.client = client;
      if (!client) {
        opts.logger?.warn?.(
          "[sentrook-openclaw] approval-runtime client unavailable; /approve ids join on list/resolve only",
        );
      } else {
        opts.logger?.info?.("[sentrook-openclaw] listening for plugin.approval.requested");
      }
      return client;
    })
    .catch((err) => {
      capture.client = null;
      opts.logger?.warn?.(
        `[sentrook-openclaw] approval-runtime client failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return null;
    })
    .finally(() => {
      capture.start = null;
    });
  await capture.start;
}

export async function stopApprovalIdCapture(): Promise<void> {
  const client = capture.client;
  capture.client = null;
  capture.start = null;
  capture.onRequested = undefined;
  if (client?.stop) await client.stop();
}

async function listOverApprovalRuntime(config?: unknown): Promise<ApprovalListItem[]> {
  if (capture.client) {
    return asList(await capture.client.request("plugin.approval.list", {}));
  }
  if (capture.start) {
    const client = await capture.start;
    if (client) return asList(await client.request("plugin.approval.list", {}));
  }
  const client = await startApprovalRuntimeClient({ config, onRequested: capture.onRequested });
  if (!client) return [];
  try {
    return asList(await client.request("plugin.approval.list", {}));
  } finally {
    if (!capture.client) await client.stop?.();
  }
}

export async function listPluginApprovals(
  gateway: PluginRuntimeGateway | undefined,
  opts?: ListPluginApprovalsOptions,
): Promise<ApprovalListItem[]> {
  const errors: string[] = [];
  if (gateway) {
    try {
      const listed = asList(await gatewayRequest(gateway, "plugin.approval.list"));
      if (listed.length) return listed;
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  try {
    const listed = opts?.listOverApprovalRuntime
      ? await opts.listOverApprovalRuntime(opts.config)
      : await listOverApprovalRuntime(opts?.config);
    if (listed.length) return listed;
  } catch (err) {
    errors.push(err instanceof Error ? err.message : String(err));
  }
  if (errors.length) {
    opts?.logger?.warn?.(
      `[sentrook-openclaw] plugin.approval.list did not return a /approve id (${errors.join("; ")})`,
    );
  }
  return [];
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
  pluginId = SENTROOK_PLUGIN_ID,
  hints?: MatchApprovalHints,
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
  const sessionKey = nonempty(hints?.sessionKey);
  const toolName = nonempty(hints?.toolName);
  if (sessionKey) {
    const sameSession = ours.filter((item) => item.request?.sessionKey === sessionKey);
    if (toolName) {
      const sameTool = sameSession.filter((item) => item.request?.toolName === toolName);
      if (sameTool.length === 1) return sameTool[0]!.id;
    }
    if (sameSession.length === 1) return sameSession[0]!.id;
  }
  if (ours.length === 1) return ours[0]!.id;
  return undefined;
}

export function attachListedApprovals(cards: ApprovalIdStore, listed: ApprovalListItem[]): void {
  for (const card of cards.list()) {
    if (card.approvalId) continue;
    const id = matchApprovalId(listed, [card.toolCallId, card.eventId], SENTROOK_PLUGIN_ID, {
      sessionKey: card.sessionKey,
      toolName: card.tool,
    });
    if (id) cards.attachApprovalId(card.toolCallId, id);
  }
}

/** Join a ``plugin.approval.requested`` payload onto the matching review card. */
export function applyApprovalRequested(cards: ApprovalIdStore, payload: unknown): string | undefined {
  const rec =
    payload && typeof payload === "object" && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : undefined;
  const item = asItem(payload) ?? (rec ? asItem(rec.payload) : undefined);
  if (!item || !isSentrookApproval(item)) return undefined;
  const call = item.request?.toolCallId;
  if (call) cards.attachApprovalId(call, item.id);
  attachListedApprovals(cards, [item]);
  return item.id;
}

export async function joinCardApprovalIds(
  cards: ApprovalIdStore,
  gateway?: PluginRuntimeGateway,
  opts?: ListPluginApprovalsOptions,
): Promise<ApprovalListItem[]> {
  const listed = await listPluginApprovals(gateway, opts);
  attachListedApprovals(cards, listed);
  return listed;
}

const JOIN_RETRY_MS = [120, 600];

/** Host mints ``plugin:`` after ``requireApproval`` returns; retry the join shortly after. */
export function scheduleApprovalIdJoin(
  cards: ApprovalIdStore,
  gateway?: PluginRuntimeGateway,
  opts?: ListPluginApprovalsOptions,
): void {
  for (const ms of JOIN_RETRY_MS) {
    const timer = setTimeout(() => {
      void joinCardApprovalIds(cards, gateway, opts);
    }, ms);
    timer.unref?.();
  }
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
  return (await importDynamic("openclaw/plugin-sdk/approval-gateway-runtime")) as {
    resolveApprovalOverGateway?: (params: Record<string, unknown>) => Promise<void>;
  } | null;
}
