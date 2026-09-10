/**
 * OpenClaw session-store listing for the dashboard Per session table and
 * ``/sentrook sessions``. Overlay Sentrook's allow-all / quiet / sensitivity
 * flags; do not treat DualIndexMap as the host's live session list.
 */

import type { Sensitivity } from "./sessionPolicy.ts";

export const DEFAULT_SESSION_LIST_CAP = 100;

export type HostSession = {
  sessionKey: string;
  sessionId?: string;
  updatedAtMs?: number;
  /** OpenClaw label / displayName when the store has one. */
  label?: string;
};

export type SessionListRow = {
  sessionId?: string;
  sessionKey?: string;
  allowAll: boolean;
  quietUntilMs: number | null;
  attendedSensitivity?: Sensitivity | null;
  unattendedSensitivity?: Sensitivity | null;
  pending: number;
  label?: string;
};

export type SessionStoreLister = {
  listSessionEntries?: (params?: {
    agentId?: string;
    readOnly?: boolean;
  }) => Array<{
    sessionKey?: string;
    entry?: {
      sessionId?: string;
      sessionKey?: string;
      archivedAt?: number | null;
      updatedAt?: number;
      lastInteractionAt?: number;
    };
  }>;
};

function nonempty(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function originLabel(entry: Record<string, unknown>): string | undefined {
  const origin = entry.origin;
  if (!origin || typeof origin !== "object" || Array.isArray(origin)) return undefined;
  return nonempty((origin as { label?: unknown }).label);
}

/** Prefer the same names Control UI shows: label, then displayName, then derived title. */
export function sessionLabelOf(
  rec: Record<string, unknown>,
  entry: Record<string, unknown> = {},
): string | undefined {
  return (
    nonempty(entry.label) ??
    nonempty(rec.label) ??
    nonempty(entry.displayName) ??
    nonempty(rec.displayName) ??
    nonempty(entry.derivedTitle) ??
    nonempty(rec.derivedTitle) ??
    nonempty(entry.subject) ??
    originLabel(entry)
  );
}

/** Human name when OpenClaw has one; otherwise the session key. */
export function sessionDisplayName(row: {
  sessionKey?: string;
  sessionId?: string;
  label?: string;
}): string {
  const key = nonempty(row.sessionKey);
  const named = nonempty(row.label);
  if (named && named !== key) return named;
  return key ?? nonempty(row.sessionId) ?? "—";
}

function withOptionalLabel<T extends { label?: string }>(row: T, label?: string): T {
  if (!label) return row;
  return { ...row, label };
}

function isArchived(entry: { archivedAt?: unknown } | undefined): boolean {
  return typeof entry?.archivedAt === "number" && Number.isFinite(entry.archivedAt) && entry.archivedAt > 0;
}

function callList(
  list: NonNullable<SessionStoreLister["listSessionEntries"]>,
  params: { agentId?: string },
): unknown {
  try {
    return list({ ...params, readOnly: true });
  } catch {
    return list(params);
  }
}

/** Agent ids to query. Always includes ``main``; adds ``agents.list`` / ``entries``. */
export function agentIdsFromConfig(config: unknown): string[] {
  const ids = new Set<string>();
  const add = (value: unknown) => {
    if (typeof value === "string" && value.trim()) ids.add(value.trim());
  };
  add("main");
  if (!config || typeof config !== "object") return [...ids];
  const agents = (config as { agents?: unknown }).agents;
  if (!agents || typeof agents !== "object") return [...ids];
  const rec = agents as Record<string, unknown>;
  add(rec.default);
  if (rec.defaults && typeof rec.defaults === "object") {
    add((rec.defaults as { id?: unknown }).id);
  }
  if (Array.isArray(rec.list)) {
    for (const item of rec.list) {
      if (item && typeof item === "object") add((item as { id?: unknown }).id);
      else add(item);
    }
  }
  if (rec.entries && typeof rec.entries === "object" && !Array.isArray(rec.entries)) {
    for (const key of Object.keys(rec.entries)) add(key);
  }
  return [...ids];
}

/**
 * Active (non-archived) rows from ``api.runtime.agent.session.listSessionEntries``.
 * Missing helper or a throw returns [].
 */
export function listHostSessions(
  store: SessionStoreLister | undefined,
  opts?: { agentIds?: string[] },
): HostSession[] {
  if (typeof store?.listSessionEntries !== "function") return [];
  const agentIds = (opts?.agentIds ?? []).filter((id) => id.trim());
  const calls: Array<{ agentId?: string }> = agentIds.length
    ? agentIds.map((agentId) => ({ agentId }))
    : [{}];
  const byKey = new Map<string, HostSession>();
  for (const params of calls) {
    let rows: unknown;
    try {
      rows = callList(store.listSessionEntries, params);
    } catch {
      continue;
    }
    if (!Array.isArray(rows)) continue;
    for (const raw of rows) {
      if (!raw || typeof raw !== "object") continue;
      const rec = raw as {
        sessionKey?: unknown;
        entry?: Record<string, unknown>;
      };
      const entry = rec.entry && typeof rec.entry === "object" ? rec.entry : {};
      if (isArchived(entry)) continue;
      const sessionKey = nonempty(rec.sessionKey) ?? nonempty(entry.sessionKey);
      const sessionId = nonempty(entry.sessionId);
      if (!sessionKey && !sessionId) continue;
      const updatedAtMs =
        (typeof entry.updatedAt === "number" && Number.isFinite(entry.updatedAt) && entry.updatedAt) ||
        (typeof entry.lastInteractionAt === "number" &&
          Number.isFinite(entry.lastInteractionAt) &&
          entry.lastInteractionAt) ||
        undefined;
      const key = sessionKey ?? sessionId!;
      const prev = byKey.get(key);
      if (!prev || (updatedAtMs ?? 0) >= (prev.updatedAtMs ?? 0)) {
        byKey.set(
          key,
          withOptionalLabel(
            {
              sessionKey: sessionKey ?? key,
              sessionId,
              updatedAtMs: updatedAtMs || undefined,
            },
            sessionLabelOf(rec as Record<string, unknown>, entry),
          ),
        );
      }
    }
  }
  return [...byKey.values()];
}

function liveMatchKey(sessionKey?: string, sessionId?: string): string[] {
  const keys: string[] = [];
  const k = nonempty(sessionKey);
  const id = nonempty(sessionId);
  if (k) keys.push(`k:${k}`);
  if (id) keys.push(`i:${id}`);
  return keys;
}

/**
 * Host sessions (newest first, capped) with Sentrook flags overlaid.
 * Live rows the host did not return are appended so a just-toggled
 * session does not vanish.
 */
export function mergeSessionRows(
  host: HostSession[],
  live: SessionListRow[],
  cap = DEFAULT_SESSION_LIST_CAP,
): SessionListRow[] {
  const liveByKey = new Map<string, SessionListRow>();
  for (const st of live) {
    for (const key of liveMatchKey(st.sessionKey, st.sessionId)) {
      liveByKey.set(key, st);
    }
  }

  const used = new Set<SessionListRow>();
  const fromHost: SessionListRow[] = [];
  const sorted = host
    .filter((h) => nonempty(h.sessionKey) || nonempty(h.sessionId))
    .sort((a, b) => (b.updatedAtMs ?? 0) - (a.updatedAtMs ?? 0));

  for (const h of sorted) {
    if (fromHost.length >= cap) break;
    const st =
      (h.sessionKey && liveByKey.get(`k:${h.sessionKey}`)) ||
      (h.sessionId && liveByKey.get(`i:${h.sessionId}`)) ||
      undefined;
    if (st) used.add(st);
    fromHost.push(
      withOptionalLabel(
        {
          sessionKey: nonempty(h.sessionKey) ?? st?.sessionKey,
          sessionId: nonempty(h.sessionId) ?? st?.sessionId,
          allowAll: st?.allowAll ?? false,
          quietUntilMs: st?.quietUntilMs ?? null,
          attendedSensitivity: st?.attendedSensitivity ?? null,
          unattendedSensitivity: st?.unattendedSensitivity ?? null,
          pending: st?.pending ?? 0,
        },
        nonempty(h.label) ?? nonempty(st?.label),
      ),
    );
  }

  const extras: SessionListRow[] = [];
  for (const st of live) {
    if (used.has(st)) continue;
    extras.push(
      withOptionalLabel(
        {
          sessionId: st.sessionId,
          sessionKey: st.sessionKey,
          allowAll: st.allowAll,
          quietUntilMs: st.quietUntilMs,
          attendedSensitivity: st.attendedSensitivity ?? null,
          unattendedSensitivity: st.unattendedSensitivity ?? null,
          pending: st.pending,
        },
        nonempty(st.label),
      ),
    );
  }
  return [...extras, ...fromHost];
}
