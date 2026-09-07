/**
 * Dual-index session maps: PlanIR ``session_id`` is the episode/transcript
 * (OpenClaw ``sessionId``); ``session_key`` is durable routing (``sessionKey``).
 *
 * ``/new`` may keep the same ``sessionKey`` (e.g. ``main``) with a new
 * ``sessionId``. Index both so slash commands that only see ``sessionKey``
 * still find the live episode, without collapsing distinct episodes into one
 * trajectory.
 */

export type SessionIds = {
  sessionId?: string;
  sessionKey?: string;
};

function nonempty(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

export function sessionIdsOf(ctx: {
  sessionId?: string;
  sessionKey?: string;
}): SessionIds {
  return {
    sessionId: nonempty(ctx.sessionId),
    sessionKey: nonempty(ctx.sessionKey),
  };
}

/** ``run_id`` prefix: episode, else routing key, else ``session``. */
export function runIdPrefix(ids: SessionIds): string {
  return ids.sessionId ?? ids.sessionKey ?? "session";
}

export class DualIndexMap<T extends object> {
  private readonly buckets = new Map<string, T>();
  private readonly owner = new WeakMap<T, string>();

  getOrCreate(ids: SessionIds, factory: () => T): T {
    const episode = ids.sessionId;
    const routing = ids.sessionKey;

    if (episode) {
      const existing = this.buckets.get(episode);
      if (existing) {
        if (routing && routing !== episode) this.buckets.set(routing, existing);
        return existing;
      }

      if (routing) {
        const aliased = this.buckets.get(routing);
        if (aliased) {
          const owner = this.owner.get(aliased);
          // Adopt state created via sessionKey only (slash before first scan).
          // Do not adopt when routing still belongs to a prior episode
          // (``/new`` without ``session_end``).
          if (!owner || owner === episode) {
            this.owner.set(aliased, episode);
            this.buckets.set(episode, aliased);
            return aliased;
          }
        }
      }

      const fresh = factory();
      this.owner.set(fresh, episode);
      this.buckets.set(episode, fresh);
      if (routing && routing !== episode) this.buckets.set(routing, fresh);
      return fresh;
    }

    const key = routing ?? "unknown";
    let st = this.buckets.get(key);
    if (!st) {
      st = factory();
      this.buckets.set(key, st);
    }
    return st;
  }

  delete(ids: SessionIds): void {
    const keys = [ids.sessionId, ids.sessionKey].filter(
      (key): key is string => typeof key === "string" && key.length > 0,
    );
    if (keys.length === 0) {
      this.buckets.delete("unknown");
      return;
    }
    const targets = new Set<T>();
    for (const key of keys) {
      const st = this.buckets.get(key);
      if (st) targets.add(st);
    }
    if (targets.size === 0) return;
    for (const [key, st] of this.buckets) {
      if (targets.has(st)) this.buckets.delete(key);
    }
  }

  /** Unique states (episode and routing aliases collapse). */
  uniqueValues(): T[] {
    const seen = new Set<T>();
    const out: T[] = [];
    for (const st of this.buckets.values()) {
      if (seen.has(st)) continue;
      seen.add(st);
      out.push(st);
    }
    return out;
  }
}
