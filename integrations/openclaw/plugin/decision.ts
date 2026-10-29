/**
 * From a scan response to allow / review / block, and the text a human sees.
 *
 * The plugin decides from `risk` and its local lines (review at `reviewAt`, block at `blockAt`),
 * then takes the stricter of that and the scanner's `enforced` floor. In observe mode the decision
 * is recorded but never applied.
 */

import type { ScanResponse } from "./scanClient.ts";

export type Verdict = "allow" | "review" | "block";

const RANK: Record<Verdict, number> = { allow: 0, review: 1, block: 2 };

export function decide(resp: ScanResponse, lines: { reviewAt: number; blockAt: number }): Verdict {
  const risk = resp.risk ?? 0;
  let v: Verdict = risk >= lines.blockAt ? "block" : risk >= lines.reviewAt ? "review" : "allow";
  const floor = resp.enforced;
  if (floor && RANK[floor] > RANK[v]) v = floor;
  return v;
}

export function tiersOf(resp: ScanResponse) {
  const score = (v: { score?: number | null } | undefined) => (typeof v?.score === "number" ? v.score : null);
  return {
    suspicion: score(resp.tree?.suspicion),
    consequence: score(resp.tree?.consequence),
    confidence: score(resp.tree?.confidence),
  };
}

/** Fill `{E1}` placeholders with the entity display strings the response carries. */
export function describe(resp: ScanResponse, toolName: string): string {
  const template = resp.tool_description?.template;
  if (!template) return `Runs ${toolName}`;
  const entities = resp.entities ?? {};
  return template.replace(/\{(E\d+)\}/g, (_m, id: string) => entities[id]?.display ?? id);
}

function reasonCodes(resp: ScanResponse): string[] {
  return [...new Set((resp.reasons ?? []).map((r) => r.code).filter(Boolean))];
}

function reasonText(resp: ScanResponse, max = 3): string {
  return reasonCodes(resp).slice(0, max).join(", ");
}

function clip(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, Math.max(0, n - 1))}…`;
}

/**
 * The tree's tier scores on the 0-100 scale of `risk`; empty when the response has none. A score that
 * is not a finite number is left out; the rest are held to 0-1.
 */
export function scoresLine(resp: ScanResponse): string {
  const parts = Object.entries(tiersOf(resp))
    .filter((e): e is [string, number] => e[1] !== null && Number.isFinite(e[1]))
    .map(([name, v]) => `${name} ${Math.round(Math.min(Math.max(v, 0), 1) * 100)}`);
  return parts.length ? `Scores: ${parts.join(", ")}.` : "";
}

/**
 * The description, up to 3 reason codes and `tail` within `limit`. Reason codes go first, then the
 * description is shortened; `tail` always stays.
 */
function fit(desc: string, codes: string[], tail: string, limit: number): string {
  const end = tail ? ` ${tail}` : "";
  for (let k = Math.min(3, codes.length); k >= 0; k--) {
    const why = k ? ` Why: ${codes.slice(0, k).join(", ")}.` : "";
    const text = `${desc}.${why}${end}`;
    if (text.length <= limit) return text;
  }
  return `${clip(desc, limit - end.length - 1)}.${end}`;
}

export function reviewCopy(resp: ScanResponse, toolName: string): { title: string; description: string } {
  const risk = ` (risk ${Math.round(resp.risk ?? 0)})`;
  const head = "Sentrook: review ";
  return {
    title: `${head}${clip(toolName, 80 - head.length - risk.length)}${risk}`,
    description: fit(describe(resp, toolName), reasonCodes(resp), scoresLine(resp), 256),
  };
}

export function blockReason(resp: ScanResponse, toolName: string): string {
  const risk = Math.round(resp.risk ?? 0);
  const reasons = reasonText(resp, 5);
  const floor = resp.enforced === "block" ? " (enforced)" : "";
  return clip(
    `Sentrook blocked this tool call${floor}, risk ${risk}/100: ${describe(resp, toolName)}.` +
      (reasons ? ` Reasons: ${reasons}.` : "") +
      " Do not retry it in another form; ask the user if it is needed.",
    500,
  );
}

/** A review forced by a scanner floor is critical; one from the risk line is a warning. */
export function severity(resp: ScanResponse): "warning" | "critical" {
  return resp.enforced === "review" ? "critical" : "warning";
}
