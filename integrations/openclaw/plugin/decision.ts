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

/**
 * What the agent is told about a block. It names a coarse category only, never the reason codes, the
 * risk score, the entities or the tool description: those would tell a steered agent which detector to
 * rephrase around. The human sees the detail in the review card, `why` and the traffic log.
 */
const BLOCK_CATEGORIES = {
  sensitive_data: "it reads or sends sensitive data, such as credentials or personal data",
  sends_data: "it sends data to a destination outside this machine",
  untrusted_code: "it runs or installs code from a source that is not trusted",
  concealment: "it hides what it does, or hides information from the user",
  agent_setup:
    "it changes the agent's own setup, such as its configuration, memory, plugins, skills or scheduled jobs",
  safety_controls: "it changes Sentrook's or the host's safety settings, which only the user may change",
  destructive: "it deletes or overwrites data in a way that is hard to undo",
  privileges: "it changes privileges on this machine",
  remote_account: "it makes a lasting change to an account, a payment or access rights on a remote service",
  general: "it does not look safe in the context of this session",
} as const;

export type BlockCategory = keyof typeof BLOCK_CATEGORIES;

/** Reason codes whose category differs from their domain's, or whose domain has none. */
const CATEGORY_BY_CODE: Record<string, BlockCategory> = {
  "floor.untrusted_code_execution": "untrusted_code",
  "floor.guardrail_tampering": "safety_controls",
  "selfmod.host_approvals": "safety_controls",
  "remote.delete": "destructive",
  "remote.force_push": "destructive",
  "sensitivity.session_holds_sensitive": "sensitive_data",
  "jev.sensitivity": "sensitive_data",
  "jev.self_modification": "agent_setup",
  "jev.concealment": "concealment",
  "lineage.secret_carried_to_send": "sensitive_data",
  "lineage.moved_into_destroyed_tree": "destructive",
  "lineage.listing_marks_irreplaceable": "destructive",
  "lineage.listing_marks_live_table": "destructive",
  "lineage.filter_silences_security_notices": "concealment",
};

/**
 * Domains that say what kind of harm a call does. Domains that say why a call is suspect (exposure,
 * origin, reputation, retry, trigger) or how sure the scan is (coverage, agreement) have no category.
 */
const CATEGORY_BY_DOMAIN: Record<string, BlockCategory> = {
  path: "sensitive_data",
  exfil: "sensitive_data",
  send: "sends_data",
  artefact: "sensitive_data",
  code: "untrusted_code",
  conceal: "concealment",
  selfmod: "agent_setup",
  guardrail: "safety_controls",
  destroy: "destructive",
  priv: "privileges",
  remote: "remote_account",
};

/** The category of the first reason, in contribution order, that has one; `general` when none does. */
export function blockCategory(resp: ScanResponse): BlockCategory {
  const reasons: unknown = resp.reasons;
  if (!Array.isArray(reasons)) return "general";
  for (const r of reasons) {
    const code = r && typeof r === "object" ? (r as { code?: unknown }).code : undefined;
    if (typeof code !== "string" || !code) continue;
    const domain = code.split(".", 1)[0];
    if (Object.hasOwn(CATEGORY_BY_CODE, code)) return CATEGORY_BY_CODE[code];
    if (Object.hasOwn(CATEGORY_BY_DOMAIN, domain)) return CATEGORY_BY_DOMAIN[domain];
  }
  return "general";
}

export function blockReason(resp: ScanResponse): string {
  return (
    `Sentrook security block: this tool call did not run because ${BLOCK_CATEGORIES[blockCategory(resp)]}. ` +
    "Do not retry it, rephrase it or try to reach the same result another way unless the user explicitly " +
    "tells you to. Tell the user what was blocked and why, and ask how they want to proceed."
  );
}

/** A review forced by a scanner floor is critical; one from the risk line is a warning. */
export function severity(resp: ScanResponse): "warning" | "critical" {
  return resp.enforced === "review" ? "critical" : "warning";
}
