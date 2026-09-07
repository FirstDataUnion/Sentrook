/**
 * In-memory pending review cards for the gateway dashboard.
 *
 * Durable history stays on the operator log (scrubbed). This stash keeps the
 * live unsanitized argv until the host resolves the card.
 */

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

export class ReviewCardStore {
  private readonly byToolCallId = new Map<string, Stored>();
  private readonly byEventId = new Map<string, string>();

  put(card: Omit<ReviewCard, "createdAtMs"> & { createdAtMs?: number }): void {
    this.take(card.toolCallId);
    const createdAtMs = card.createdAtMs ?? Date.now();
    const stored: Stored = {
      ...card,
      createdAtMs,
      timer: (() => {
        if (card.timeoutMs <= 0) return null;
        const timer = setTimeout(() => {
          this.take(card.toolCallId);
        }, card.timeoutMs);
        timer.unref?.();
        return timer;
      })(),
    };
    this.byToolCallId.set(card.toolCallId, stored);
    this.byEventId.set(card.eventId, card.toolCallId);
  }

  take(toolCallId: string | undefined): ReviewCard | undefined {
    if (!toolCallId) return undefined;
    const stored = this.byToolCallId.get(toolCallId);
    if (!stored) return undefined;
    if (stored.timer) clearTimeout(stored.timer);
    this.byToolCallId.delete(toolCallId);
    this.byEventId.delete(stored.eventId);
    const { timer: _timer, ...card } = stored;
    return card;
  }

  get(id: string): ReviewCard | undefined {
    const toolCallId = this.byEventId.get(id) ?? id;
    const stored = this.byToolCallId.get(toolCallId);
    if (!stored) return undefined;
    const { timer: _timer, ...card } = stored;
    return card;
  }

  list(): ReviewCard[] {
    return [...this.byToolCallId.values()]
      .map(({ timer: _timer, ...card }) => card)
      .sort((a, b) => b.createdAtMs - a.createdAtMs);
  }

  size(): number {
    return this.byToolCallId.size;
  }

  shutdown(): void {
    for (const stored of this.byToolCallId.values()) {
      if (stored.timer) clearTimeout(stored.timer);
    }
    this.byToolCallId.clear();
    this.byEventId.clear();
  }
}
