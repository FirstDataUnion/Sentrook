/**
 * The review card: what a person reads when Sentrook asks before a tool call.
 *
 * The title names Sentrook, the kind of question and the risk (`🪶 Sentrook security check · risk 62/100`). The
 * description has one fact per line, in this order:
 * - what the call does, from the scan's tool description (`Sends ~/notes/q3-plan.md to paste.example.net.`);
 * - why, in plain words: the first two reasons whose `text` the scanner filled, or the block category when none has;
 * - what an answer does, only where the buttons would not say it: a suggested grant, a block a snooze turned into
 *   a question, a call that would run without a scan;
 * - where to read more (`Details: /sentrook-why 3f9c2a1b`), when the traffic log is on.
 *
 * Every line is a sentence, so the terminal UI, which joins lines, still reads. The text is plain: no markdown,
 * which some surfaces render and others show as typed.
 *
 * OpenClaw refuses an approval whose title is over 80 or description over 512 characters once it has replaced
 * control and other invisible characters with visible codes, and a refused approval blocks the call. The card
 * takes those characters out first and is fitted to a description budget of 500. When it does not fit, what the
 * call does gives way first (long files and addresses are shortened in the middle, then the line is cut or
 * dropped), then the second reason, then a suggested grant's command (pointing to `why`, which lists it). The
 * title and what an answer does are kept.
 *
 * Values the agent can influence (entity displays, the tool name, scanner reason text) lose those characters, any
 * line break, and chat markup that would make a link or a mention.
 *
 * The Hermes plugin builds the same card (`card.py`); `integrations/fixtures/review-card/cases.json` holds both.
 */

import { BLOCK_CATEGORIES, blockCategory } from "./decision.ts";
import { grantCommand, type Entry } from "./grants.ts";
import type { ScanResponse } from "./scanClient.ts";

export const MARK = "🪶 Sentrook";
export const GRANT_DAYS = 30;
export const TITLE_MAX = 80;
export const DESCRIPTION_BUDGET = 500;
const CMD = (sub: string) => `/sentrook-${sub}`;
const ALWAYS = '"Always allow"';

/** Entity displays are shortened to these lengths in turn before the line about what the call does gives way. */
const ENTITY_CAPS = [60, 40, 24, 12];
/** (reasons shown, entity length) in the order tried: down to 24 characters with two reasons, then with one. */
const FIT_STEPS: [number, number][] = [[2, 60], [2, 40], [2, 24], [1, 60], [1, 40], [1, 24], [1, 12]];
/** Shortest cut of what the call does worth showing; with less room the line is dropped. */
const WHAT_MIN = 16;
const REASON_MAX = 120;
const TOOL_MAX = 40;

// What OpenClaw replaces with a visible `\u{..}` code: control, format, surrogate and separator characters, and
// spaces that do not look like spaces. Kept in step with the host's own pattern.
const ODD = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}   -   　ᅟᅠㅤﾠ]/gu;
const MARKUP = /[\[\]<>|`]/g;
const PLACEHOLDER = /\{(E\d+)\}/g;
/** Mentions that notify everyone in a chat, written without markup (Mattermost and Slack read them as typed). */
const BROADCAST = /@(everyone|here|channel|all)\b/i;

const chars = (s: string) => Array.from(s);

/** One line of plain text: odd characters become spaces, runs of spaces one space. */
export function clean(s: unknown): string {
  return String(s).replace(ODD, " ").split(" ").filter(Boolean).join(" ");
}

/** `clean`, with chat link and code markup taken out and `@` made unable to mention anyone. */
export function inert(s: unknown): string {
  return clean(String(s).replace(MARKUP, "").replaceAll("@", "＠"));
}

/** `s` shortened to `n` characters in the middle, so both ends stay readable. */
export function mid(s: string, n: number): string {
  const c = chars(s);
  if (c.length <= n) return s;
  if (n <= 1) return n === 1 ? "…" : "";
  const head = Math.ceil((n - 1) / 2);
  return c.slice(0, head).join("") + "…" + c.slice(c.length - (n - 1 - head)).join("");
}

/** `s` cut to `n` characters at the end. */
export function clip(s: string, n: number): string {
  const c = chars(s);
  return c.length <= n ? s : c.slice(0, Math.max(0, n - 1)).join("") + "…";
}

const sentence = (s: string) => (!s || /[.?!]$/.test(s) ? s : `${s}.`);

/** `risk` held to 0-100 and rounded half up, as both plugins round it; 0 when it is not a finite number. */
export function riskNumber(resp: ScanResponse): number {
  const risk: unknown = resp.risk;
  if (typeof risk !== "number" || !Number.isFinite(risk)) return 0;
  return Math.floor(Math.min(Math.max(risk, 0), 100) + 0.5);
}

/** OpenClaw counts code points, after `clean` left nothing for it to replace. */
export const measure = (text: string) => chars(text).length;

function entitiesOf(resp: ScanResponse): Record<string, string> {
  const raw: unknown = resp.entities;
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== "object") return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    const display = v && typeof v === "object" ? (v as { display?: unknown }).display : undefined;
    if (typeof display === "string") out[k] = inert(display);
  }
  return out;
}

const fill = (template: string, ents: Record<string, string>, cap: number) =>
  template.replace(PLACEHOLDER, (_m, id: string) => mid(Object.hasOwn(ents, id) ? ents[id] : id, cap));

function what(resp: ScanResponse, tool: string, ents: Record<string, string>, cap: number): string {
  const template: unknown = resp.tool_description?.template;
  if (typeof template !== "string" || !inert(template)) return `Runs ${mid(inert(tool), TOOL_MAX) || "a tool"}.`;
  return sentence(fill(inert(template), ents, cap));
}

function reasonTexts(resp: ScanResponse): string[] {
  const seen: string[] = [];
  const reasons: unknown = resp.reasons;
  for (const r of Array.isArray(reasons) ? reasons : []) {
    const text = r && typeof r === "object" ? (r as { text?: unknown }).text : undefined;
    if (typeof text === "string") {
      const t = clip(inert(text), REASON_MAX);
      if (t && !seen.includes(t)) seen.push(t);
    }
  }
  return seen;
}

const because = (texts: string[]) => `Because ${texts.join(", and ")}.`;

/** What a suggested grant allows, as `trust x` (or `trusts x` with `third`), its pattern at most `cap` long. */
function grantPhrase(grant: Entry, third: boolean, cap: number): string {
  const pattern = mid(inert(grant.pattern), cap);
  if (grant.kind === "credential") {
    const at = grant.pattern.indexOf("@");
    const what = at < 0 ? grant.pattern : `${grant.pattern.slice(0, at)} to ${grant.pattern.slice(at + 1)}`;
    return `${third ? "lets" : "let"} the agent send ${mid(inert(what), cap)}`;
  }
  if (grant.kind === "file") {
    const allows: string[] = Array.isArray(grant.allows) && grant.allows.length ? grant.allows : ["use"];
    const verbs = allows.length === 1 ? allows[0] : `${allows.slice(0, -1).join(", ")} and ${allows[allows.length - 1]}`;
    return `${third ? "lets" : "let"} the agent ${verbs} ${pattern}`;
  }
  return `${third ? "trusts" : "trust"} ${pattern}`;
}

/**
 * Whether the card may show the grant command as typed: its pattern has nothing the host would escape (which could
 * take the card over the limit), no chat markup and no mention of everyone. A command must be copied whole, so it is
 * never cleaned: the card points to `why` instead.
 */
export function commandShown(grant: Entry): boolean {
  const pattern = String(grant.pattern);
  return !(new RegExp(ODD.source, "u").test(pattern) || /[\[\]<>|`]/.test(pattern) || BROADCAST.test(pattern));
}

function answer(relaxed: boolean, hint: Entry | null, remember: boolean, whyId: string | null, short: boolean, cap: number): string[] {
  const lines: string[] = [];
  if (hint) {
    if (remember) lines.push(`${ALWAYS} also ${grantPhrase(hint, true, cap)} for ${GRANT_DAYS} days.`);
    else if (short || !commandShown(hint)) {
      // `why` lists the command, and the details line names it. Without `why` (the traffic log is off) the line is
      // left out rather than cut: a cut command would set a different grant.
      if (whyId) lines.push(`To ${grantPhrase(hint, false, cap)} for ${GRANT_DAYS} days, see Details.`);
    } else lines.push(`To allow this for ${GRANT_DAYS} days: ${grantCommand(hint, CMD)}`);
  }
  if (relaxed) lines.push("Would be blocked, but a snooze is on.");
  return lines;
}

export function header(resp: ScanResponse): string {
  const kind = resp.enforced === "review" ? "safety rule" : "security check";
  return `${MARK} ${kind} · risk ${riskNumber(resp)}/100`;
}

export interface CardOptions {
  relaxed?: boolean;
  /** The suggested grant (`grants.responseHints`), shown on the owner's own turn. */
  hint?: Entry | null;
  /** Approving always sets `hint`. */
  remember?: boolean;
  /** The scan's request id, when `why` can find it (the traffic log is on). */
  whyId?: string | null;
}

/** The description's lines, fitted to the budget. */
export function reviewLines(resp: ScanResponse, tool: string, opts: CardOptions = {}): string[] {
  const { relaxed = false, hint = null, remember = false } = opts;
  const sid = opts.whyId ? opts.whyId.slice(0, 8) : null;
  const ents = entitiesOf(resp);
  const found = reasonTexts(resp);
  const texts = found.length ? found : [BLOCK_CATEGORIES[blockCategory(resp)]];
  const details = sid ? [`Details: ${CMD("why")} ${sid}`] : [];

  const build = (cap: number, whatRoom: number | null, n: number, short: boolean, whyRoom: number | null) => {
    let w = what(resp, tool, ents, cap);
    if (whatRoom !== null) w = whatRoom >= WHAT_MIN ? clip(w, whatRoom) : "";
    let b = because(texts.slice(0, n).map((t) => fill(t, ents, Math.max(cap, 24))));
    if (whyRoom !== null) b = clip(b, whyRoom);
    return [w, b, ...answer(relaxed, hint, remember, sid, short, Math.max(cap, 24)), ...details].filter(Boolean);
  };
  const size = (lines: string[]) => measure(lines.join("\n"));
  const roomFor = (lines: string[], index: number) => {
    const rest = size([...lines.slice(0, index), ...lines.slice(index + 1)]) + 1;
    return Math.max(0, Math.min(chars(lines[index]).length, DESCRIPTION_BUDGET - rest));
  };

  // Shorten files and addresses (to a length that still reads), then keep one reason, then shorten them further,
  // then cut or drop what the call does, then point to `why` for the grant command, then cut the reason.
  for (const [n, cap] of FIT_STEPS) {
    const lines = build(cap, null, n, false, null);
    if (size(lines) <= DESCRIPTION_BUDGET) return lines;
  }
  const cap = ENTITY_CAPS[ENTITY_CAPS.length - 1];
  for (const short of [false, true]) {
    const full = build(cap, null, 1, short, null);
    const lines = build(cap, roomFor(full, 0), 1, short, null);
    if (size(lines) <= DESCRIPTION_BUDGET) return lines;
  }
  let lines = build(cap, 0, 1, true, null);
  const i = lines.findIndex((l) => l.startsWith("Because "));
  lines = build(cap, 0, 1, true, roomFor(lines, i));
  if (size(lines) <= DESCRIPTION_BUDGET) return lines;
  // Only an answer line too long to fit is left: cut the text as a whole.
  return [chars(lines.join("\n")).slice(0, DESCRIPTION_BUDGET).join("")];
}

/** The approval's title and description. */
export function reviewCard(resp: ScanResponse, tool: string, opts: CardOptions = {}): { title: string; description: string } {
  return { title: clip(header(resp), TITLE_MAX), description: reviewLines(resp, tool, opts).join("\n") };
}

// ---- a call Sentrook could not scan ----------------------------------------------------------------------

export const ERROR_TITLE = `${MARK} could not check this call`;
export const ERROR_CAUSES = {
  rate_limited: "The scan service is busy and turned this scan away for now.",
  config: "Sentrook's settings are missing or wrong. This is a setup problem, not a security finding.",
  auth: "Sentrook could not sign in to its scan service. This is a setup problem, not a security finding.",
  unreachable: "Its scan service did not answer.",
  not_signed_in: "Sentrook isn't signed in yet. Run on the gateway machine: openclaw sentrook login",
  sign_in_rejected: "Sentrook's sign-in was revoked or is wrong. Run on the gateway machine: openclaw sentrook login",
} as const;
export type ErrorCause = keyof typeof ERROR_CAUSES;
/** Why the credentials did not work, when known: none stored, or refused by the identity service. */
export type SignInProblem = "not_signed_in" | "sign_in_rejected";
export const ERROR_RUNS_UNCHECKED = "If you allow it, it runs without a security check.";

export function errorCause(kind: string, auth: boolean, setup?: SignInProblem): ErrorCause {
  if (setup) return setup;
  if (kind === "rate_limited") return "rate_limited";
  if (kind === "config") return "config";
  return auth ? "auth" : "unreachable";
}

export function errorCard(cause: ErrorCause): { title: string; description: string } {
  return { title: ERROR_TITLE, description: [ERROR_CAUSES[cause], ERROR_RUNS_UNCHECKED, `Status: ${CMD("status")}`].join("\n") };
}
