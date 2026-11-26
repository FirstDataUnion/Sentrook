/**
 * From a scan response to allow / review / block, and what the agent is told about a block. The review card a
 * human sees is `card.ts`.
 *
 * The plugin decides from `risk` and its local lines (review at `reviewAt`, block at `blockAt`),
 * lowers that to the scanner's `ceiling` when it is `review`, then takes the stricter of that and the
 * scanner's `enforced` floor. In observe mode the decision
 * is recorded but never applied.
 */

import type { ScanResponse } from "./scanClient.ts";

export type Verdict = "allow" | "review" | "block";

const RANK: Record<Verdict, number> = { allow: 0, review: 1, block: 2 };

export function decide(resp: ScanResponse, lines: { reviewAt: number; blockAt: number }): Verdict {
  const risk = resp.risk ?? 0;
  let v: Verdict = risk >= lines.blockAt ? "block" : risk >= lines.reviewAt ? "review" : "allow";
  // the scanner's ceiling (the owner attends and nothing independent points to an attack) only lowers
  if (resp.ceiling === "review" && v === "block") v = "review";
  const floor = resp.enforced;
  if (floor && RANK[floor] > RANK[v]) v = floor;
  return v;
}

/** The scanner's reason for a ceiling on a retry of a review nobody answered: kept on an unattended run. */
export const RETRY_CAP = "cap.unanswered_retry";
/** The scanner's reason for a ceiling on code that reaches no network sink: kept on an unattended run. */
export const LOCAL_CODE_CAP = "cap.local_code";

/**
 * `resp` as an unattended run decides from it. The attended-owner ceiling is dropped: nobody can answer, so a block
 * is not lowered to a review with it. The ceilings on a retry of a review nobody answered and on code that reaches
 * no network sink are kept, so that call is held for the owner rather than blocked.
 */
export function unattendedView(resp: ScanResponse): ScanResponse {
  const codes = new Set((resp.reasons ?? []).map((r) => (r && typeof r === "object" ? r.code : undefined)));
  return codes.has(RETRY_CAP) || codes.has(LOCAL_CODE_CAP) ? resp : { ...resp, ceiling: null };
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

/**
 * What the agent is told about a block. It names a coarse category only, never the reason codes, the
 * risk score, the entities or the tool description: those would tell a steered agent which detector to
 * rephrase around. The human sees the detail in the review card, `why` and the traffic log.
 */
export const BLOCK_CATEGORIES = {
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

/**
 * A review forced by a scanner floor, or a block-level score lowered to a review (by the scanner's ceiling, or by
 * a snooze when `relaxed`), is critical; one from the review line is a warning.
 */
export function severity(resp: ScanResponse, lines: { blockAt: number }, relaxed = false): "warning" | "critical" {
  if (resp.enforced === "review" || relaxed) return "critical";
  return resp.ceiling === "review" && (resp.risk ?? 0) >= lines.blockAt ? "critical" : "warning";
}
