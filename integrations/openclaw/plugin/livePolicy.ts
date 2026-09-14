/**
 * Gateway-wide allow-all / quiet flags, plus per-session overlays.
 *
 * These used to live only in the plugin isolate that handled the click. The
 * scan hook often runs in another isolate of the same gateway, so a dashboard
 * toggle never reached ``before_tool_call``. The state-dir file is the same
 * sharing trick as ``sentrook-pending.json``.
 *
 * Restart no longer silently clears allow-all / quiet: turn them off when you
 * are done. Per-session sensitivity floors also live here and survive
 * ``session_end``.
 */

import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { laterQuietUntil, parseSensitivityToken, type Sensitivity } from "./sessionPolicy.ts";
import type { SessionIds } from "./sessionStore.ts";

export const LIVE_POLICY_FILE = "sentrook-live-policy.json";

export type LiveSessionFlags = {
  sessionId?: string;
  sessionKey?: string;
  allowAll: boolean;
  quietUntilMs: number | null;
  /** Null / omit = inherit the matching global floor. */
  attendedSensitivity?: Sensitivity | null;
  unattendedSensitivity?: Sensitivity | null;
};

export type LiveSessionFlagSnapshot = {
  allowAll: boolean;
  quietUntilMs: number | null;
  attendedSensitivity: Sensitivity | null;
  unattendedSensitivity: Sensitivity | null;
};

export type LivePolicySnapshot = {
  allowAll: boolean;
  quietUntilMs: number | null;
  sessions: LiveSessionFlags[];
};

type DiskDoc = {
  version: 1;
  allowAll: boolean;
  quietUntilMs: number | null;
  sessions: LiveSessionFlags[];
};

const empty = (): DiskDoc => ({
  version: 1,
  allowAll: false,
  quietUntilMs: null,
  sessions: [],
});

function idKeys(ids: SessionIds): string[] {
  return [ids.sessionId, ids.sessionKey].filter(
    (key): key is string => typeof key === "string" && key.length > 0,
  );
}

function rowMatches(row: LiveSessionFlags, ids: SessionIds): boolean {
  const keys = new Set(idKeys(ids));
  if (row.sessionId && keys.has(row.sessionId)) return true;
  if (row.sessionKey && keys.has(row.sessionKey)) return true;
  return false;
}

function diskFloor(raw: unknown): Sensitivity | null {
  return parseSensitivityToken(raw) ?? null;
}

function rowIsEmpty(row: LiveSessionFlags): boolean {
  return (
    !row.allowAll &&
    row.quietUntilMs == null &&
    row.attendedSensitivity == null &&
    row.unattendedSensitivity == null
  );
}

function pruneEmpty(sessions: LiveSessionFlags[]): LiveSessionFlags[] {
  return sessions.filter((row) => !rowIsEmpty(row));
}

function preferKeyThenRest(rows: LiveSessionFlags[], ids: SessionIds): LiveSessionFlags[] {
  const matching = rows.filter((row) => rowMatches(row, ids));
  const keyed =
    ids.sessionKey != null && ids.sessionKey.length > 0
      ? matching.filter((row) => row.sessionKey === ids.sessionKey)
      : [];
  const rest = matching.filter((row) => !keyed.includes(row));
  return [...keyed, ...rest];
}

function firstFloor(rows: LiveSessionFlags[], field: "attendedSensitivity" | "unattendedSensitivity"): Sensitivity | null {
  for (const row of rows) {
    const value = row[field];
    if (value != null) return value;
  }
  return null;
}

export class LivePolicyStore {
  private readonly persistPath?: string;

  constructor(persistPath?: string) {
    this.persistPath = persistPath;
  }

  read(): LivePolicySnapshot {
    return this.load();
  }

  writeGlobal(patch: {
    allowAll?: boolean;
    quietUntilMs?: number | null;
    clearSessionAllowAll?: boolean;
  }): void {
    const next = this.load();
    if (typeof patch.allowAll === "boolean") next.allowAll = patch.allowAll;
    if (patch.quietUntilMs !== undefined) next.quietUntilMs = patch.quietUntilMs;
    if (patch.clearSessionAllowAll) {
      for (const row of next.sessions) row.allowAll = false;
    }
    this.save(next);
  }

  writeSession(
    ids: SessionIds,
    patch: {
      allowAll?: boolean;
      quietUntilMs?: number | null;
      attendedSensitivity?: Sensitivity | null;
      unattendedSensitivity?: Sensitivity | null;
    },
  ): void {
    const keys = idKeys(ids);
    if (keys.length === 0) return;
    const next = this.load();
    let row = next.sessions.find((item) => rowMatches(item, ids));
    if (!row) {
      row = {
        sessionId: ids.sessionId,
        sessionKey: ids.sessionKey,
        allowAll: false,
        quietUntilMs: null,
      };
      next.sessions.push(row);
    } else {
      if (ids.sessionId) row.sessionId = ids.sessionId;
      if (ids.sessionKey) row.sessionKey = ids.sessionKey;
    }
    if (typeof patch.allowAll === "boolean") row.allowAll = patch.allowAll;
    if (patch.quietUntilMs !== undefined) row.quietUntilMs = patch.quietUntilMs;
    if (patch.attendedSensitivity !== undefined) {
      row.attendedSensitivity = patch.attendedSensitivity;
    }
    if (patch.unattendedSensitivity !== undefined) {
      row.unattendedSensitivity = patch.unattendedSensitivity;
    }
    next.sessions = pruneEmpty(next.sessions);
    this.save(next);
  }

  /**
   * Drop allow-all and quiet for a session. Sensitivity floors stay keyed by
   * session key so they survive ``session_end`` and restart.
   */
  clearSession(ids: SessionIds): void {
    const next = this.load();
    for (const row of next.sessions) {
      if (!rowMatches(row, ids)) continue;
      row.allowAll = false;
      row.quietUntilMs = null;
    }
    next.sessions = pruneEmpty(next.sessions);
    this.save(next);
  }

  sessionFlags(ids: SessionIds): LiveSessionFlagSnapshot {
    const snap = this.load();
    const matching = preferKeyThenRest(snap.sessions, ids);
    let allowAll = false;
    let quietUntilMs: number | null = null;
    for (const row of matching) {
      if (row.allowAll) allowAll = true;
      quietUntilMs = laterQuietUntil(quietUntilMs, row.quietUntilMs);
    }
    return {
      allowAll,
      quietUntilMs,
      attendedSensitivity: firstFloor(matching, "attendedSensitivity"),
      unattendedSensitivity: firstFloor(matching, "unattendedSensitivity"),
    };
  }

  hydrateInto<T extends LiveSessionFlags>(
    map: { getOrCreate: (ids: SessionIds, factory: () => T) => T },
    factory: () => T,
  ): void {
    for (const row of this.load().sessions) {
      const st = map.getOrCreate(
        { sessionId: row.sessionId, sessionKey: row.sessionKey },
        factory,
      );
      st.allowAll = row.allowAll;
      st.quietUntilMs = row.quietUntilMs;
      st.attendedSensitivity = row.attendedSensitivity ?? null;
      st.unattendedSensitivity = row.unattendedSensitivity ?? null;
      if (row.sessionId) st.sessionId = row.sessionId;
      if (row.sessionKey) st.sessionKey = row.sessionKey;
    }
  }

  private load(): DiskDoc {
    if (!this.persistPath) return empty();
    try {
      const parsed = JSON.parse(readFileSync(this.persistPath, "utf8")) as Partial<DiskDoc>;
      if (!parsed || typeof parsed !== "object") return empty();
      const sessions = Array.isArray(parsed.sessions)
        ? parsed.sessions.filter(
            (row): row is LiveSessionFlags =>
              Boolean(row) &&
              typeof row === "object" &&
              (typeof row.sessionId === "string" || typeof row.sessionKey === "string"),
          )
        : [];
      return {
        version: 1,
        allowAll: parsed.allowAll === true,
        quietUntilMs: typeof parsed.quietUntilMs === "number" ? parsed.quietUntilMs : null,
        sessions: sessions.map((row) => ({
          sessionId: typeof row.sessionId === "string" ? row.sessionId : undefined,
          sessionKey: typeof row.sessionKey === "string" ? row.sessionKey : undefined,
          allowAll: row.allowAll === true,
          quietUntilMs: typeof row.quietUntilMs === "number" ? row.quietUntilMs : null,
          attendedSensitivity: diskFloor(row.attendedSensitivity),
          unattendedSensitivity: diskFloor(row.unattendedSensitivity),
        })),
      };
    } catch {
      return empty();
    }
  }

  private save(doc: DiskDoc): void {
    if (!this.persistPath) return;
    const dir = dirname(this.persistPath);
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
      /* exists */
    }
    const tmp = `${this.persistPath}.${process.pid}.tmp`;
    try {
      writeFileSync(tmp, `${JSON.stringify(doc)}\n`, { encoding: "utf8", mode: 0o600 });
      try {
        chmodSync(tmp, 0o600);
      } catch {
        /* best-effort */
      }
      renameSync(tmp, this.persistPath);
      try {
        chmodSync(this.persistPath, 0o600);
      } catch {
        /* best-effort */
      }
    } catch {
      try {
        unlinkSync(tmp);
      } catch {
        /* ignore */
      }
    }
  }
}
