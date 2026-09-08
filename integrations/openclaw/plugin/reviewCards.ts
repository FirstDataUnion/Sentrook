/**
 * Pending review cards for the gateway dashboard.
 *
 * Durable history stays on the operator log (scrubbed). This stash keeps the
 * live unsanitized argv until the host resolves the card. When ``persistPath``
 * is set, put/take also write ``sentrook-pending.json`` so the HTTP dashboard
 * still sees cards if the hook ran in another isolate of the same gateway.
 */

import { chmodSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const PENDING_CARDS_FILE = "sentrook-pending.json";

export type ReviewCardScan = {
  decision: string;
  risk?: number;
  summary?: string;
  matched_rules?: string[];
  review_severity?: string;
  block_reason?: string;
};

/** Executed calls in this episode before the pending review (unsanitized argv). */
export type ReviewPriorStep = {
  seq: number;
  tool: string;
  command: string;
  ok?: boolean;
  excerpt?: string;
};

export type ReviewCard = {
  eventId: string;
  toolCallId: string;
  tool: string;
  args: Record<string, unknown>;
  scan: ReviewCardScan;
  sessionId?: string;
  sessionKey?: string;
  agentId?: string;
  timeoutMs: number;
  createdAtMs: number;
  intent?: string | null;
  intentKind?: string | null;
  priorSteps?: ReviewPriorStep[];
  priorOmitted?: number;
};

export const MAX_REVIEW_PRIOR_STEPS = 40;
const PRIOR_EXCERPT = 500;

function commandFromArgs(args: Record<string, unknown> | undefined): string {
  if (!args) return "";
  if (typeof args.command === "string") return args.command;
  if (typeof args.cmd === "string") return args.cmd;
  try {
    return JSON.stringify(args);
  } catch {
    return "";
  }
}

export function snapshotReviewPrior(
  executed: Array<{
    tool: string;
    args?: Record<string, unknown>;
    resultText?: string;
    resultOk?: boolean;
  }>,
): { priorSteps: ReviewPriorStep[]; priorOmitted: number } {
  const omitted = Math.max(0, executed.length - MAX_REVIEW_PRIOR_STEPS);
  const priorSteps = executed.slice(-MAX_REVIEW_PRIOR_STEPS).map((call, i) => {
    const raw = call.resultText ?? "";
    const excerpt = raw
      ? raw.length > PRIOR_EXCERPT
        ? `${raw.slice(0, PRIOR_EXCERPT)}…`
        : raw
      : undefined;
    return {
      seq: omitted + i + 1,
      tool: call.tool,
      command: commandFromArgs(call.args),
      ...(call.resultOk === undefined ? {} : { ok: call.resultOk }),
      ...(excerpt ? { excerpt } : {}),
    };
  });
  return { priorSteps, priorOmitted: omitted };
}

type Stored = ReviewCard & { timer: ReturnType<typeof setTimeout> | null };

export type ReviewCardStoreOptions = {
  persistPath?: string;
};

function serializableCard(card: Stored): ReviewCard {
  const { timer: _timer, ...rest } = card;
  return rest;
}

function parseStoredCards(raw: string): ReviewCard[] {
  try {
    const parsed = JSON.parse(raw) as unknown;
    const rows = Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === "object" && Array.isArray((parsed as { cards?: unknown }).cards)
        ? (parsed as { cards: unknown[] }).cards
        : [];
    return rows.filter((row): row is ReviewCard => {
      if (!row || typeof row !== "object") return false;
      const rec = row as Partial<ReviewCard>;
      return typeof rec.eventId === "string" && typeof rec.toolCallId === "string" && typeof rec.tool === "string";
    });
  } catch {
    return [];
  }
}

export class ReviewCardStore {
  private readonly byToolCallId = new Map<string, Stored>();
  private readonly byEventId = new Map<string, string>();
  private readonly persistPath?: string;

  constructor(opts?: ReviewCardStoreOptions) {
    this.persistPath = opts?.persistPath;
    if (this.persistPath) this.reloadFromDisk({ startTimers: true });
  }

  put(card: Omit<ReviewCard, "createdAtMs"> & { createdAtMs?: number }): void {
    this.take(card.toolCallId, { persist: false });
    const createdAtMs = card.createdAtMs ?? Date.now();
    const stored: Stored = {
      ...card,
      createdAtMs,
      timer: this.makeTimer(card.toolCallId, card.timeoutMs),
    };
    this.byToolCallId.set(card.toolCallId, stored);
    this.byEventId.set(card.eventId, card.toolCallId);
    this.persist();
  }

  take(toolCallId: string | undefined, opts?: { persist?: boolean }): ReviewCard | undefined {
    if (!toolCallId) return undefined;
    const stored = this.byToolCallId.get(toolCallId);
    if (!stored) return undefined;
    if (stored.timer) clearTimeout(stored.timer);
    this.byToolCallId.delete(toolCallId);
    this.byEventId.delete(stored.eventId);
    const { timer: _timer, ...card } = stored;
    if (opts?.persist !== false) this.persist();
    return card;
  }

  get(id: string): ReviewCard | undefined {
    this.reloadFromDisk({ startTimers: false });
    this.dropExpiredAndPersist();
    const toolCallId = this.byEventId.get(id) ?? id;
    const stored = this.byToolCallId.get(toolCallId);
    if (!stored) return undefined;
    return serializableCard(stored);
  }

  list(): ReviewCard[] {
    this.reloadFromDisk({ startTimers: false });
    this.dropExpiredAndPersist();
    return [...this.byToolCallId.values()]
      .map(serializableCard)
      .sort((a, b) => b.createdAtMs - a.createdAtMs);
  }

  size(): number {
    this.reloadFromDisk({ startTimers: false });
    this.dropExpiredAndPersist();
    return this.byToolCallId.size;
  }

  shutdown(): void {
    for (const stored of this.byToolCallId.values()) {
      if (stored.timer) clearTimeout(stored.timer);
    }
    this.byToolCallId.clear();
    this.byEventId.clear();
    this.persist();
  }

  private makeTimer(toolCallId: string, timeoutMs: number): ReturnType<typeof setTimeout> | null {
    if (timeoutMs <= 0) return null;
    const timer = setTimeout(() => {
      this.take(toolCallId);
    }, timeoutMs);
    timer.unref?.();
    return timer;
  }

  private dropExpiredAndPersist(now = Date.now()): void {
    const before = this.byToolCallId.size;
    for (const stored of [...this.byToolCallId.values()]) {
      if (stored.timeoutMs > 0 && stored.createdAtMs + stored.timeoutMs <= now) {
        this.take(stored.toolCallId, { persist: false });
      }
    }
    if (this.byToolCallId.size !== before) this.persist();
  }

  private reloadFromDisk(opts: { startTimers: boolean }): void {
    if (!this.persistPath) return;
    let raw = "";
    try {
      raw = readFileSync(this.persistPath, "utf8");
    } catch {
      return;
    }
    const rows = parseStoredCards(raw);
    const seen = new Set(rows.map((row) => row.toolCallId));
    for (const id of [...this.byToolCallId.keys()]) {
      if (!seen.has(id)) this.take(id, { persist: false });
    }
    for (const row of rows) {
      if (this.byToolCallId.has(row.toolCallId)) continue;
      const stored: Stored = {
        ...row,
        args: row.args && typeof row.args === "object" ? row.args : {},
        scan: row.scan ?? { decision: "review" },
        timeoutMs: typeof row.timeoutMs === "number" ? row.timeoutMs : 600_000,
        createdAtMs: typeof row.createdAtMs === "number" ? row.createdAtMs : Date.now(),
        timer: opts.startTimers ? this.makeTimer(row.toolCallId, row.timeoutMs ?? 600_000) : null,
      };
      this.byToolCallId.set(row.toolCallId, stored);
      this.byEventId.set(row.eventId, row.toolCallId);
    }
  }

  private persist(): void {
    if (!this.persistPath) return;
    const cards = [...this.byToolCallId.values()].map(serializableCard);
    const dir = dirname(this.persistPath);
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
      /* exists */
    }
    const tmp = `${this.persistPath}.${process.pid}.tmp`;
    try {
      writeFileSync(tmp, `${JSON.stringify({ version: 1, cards }, null, 0)}\n`, { encoding: "utf8", mode: 0o600 });
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
