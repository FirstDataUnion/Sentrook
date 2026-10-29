/**
 * Scan history read back from the local traffic log, for `/sentrook-history` and `/sentrook-why`.
 *
 * The log is read backwards from its end and on into the rotated `<path>.1`, and reading stops once
 * enough scans are found or `READ_BUDGET_BYTES` have been read, so only the tail is read. A review
 * resolution is written after its scan, so reading backwards it comes first and is joined to its scan
 * by `request_id`. A line that does not parse (a write cut off mid-line, or one still being written)
 * is skipped.
 *
 * Only what the scanner returned is shown: risk, tier scores, reason codes and entity display strings.
 * The PlanIR as sent, with the call's arguments, and reason or failure details are never shown.
 * The Hermes plugin prints the same text for the same log.
 */

import { closeSync, fstatSync, openSync, readSync } from "node:fs";

import { tiersOf } from "./decision.ts";
import type { ScanResponse } from "./scanClient.ts";

export const HISTORY_DEFAULT = 10;
export const HISTORY_MAX = 50;
export const READ_BUDGET_BYTES = 16 * 1024 * 1024;
const CHUNK = 64 * 1024;

export const LOG_OFF = "The traffic log is off, so there is no scan history.";
export const NO_SCANS = "No scans in the traffic log yet.";

type Rec = Record<string, any>;
export type ScanWithResolution = [scan: Rec, resolution: Rec | null];

const APPROVED = new Set(["once", "session", "always", "allow-once", "allow_once", "allow-always", "allow_always"]);
const REVIEW: Record<string, string> = { deny: "denied", timeout: "timed out", cancelled: "cancelled" };
const ID = /^[0-9a-fA-F-]{4,36}$/;

function* linesBackward(file: string, budget: { left: number }): Generator<Buffer> {
  let fd: number;
  try {
    fd = openSync(file, "r");
  } catch {
    return;
  }
  try {
    let pos = fstatSync(fd).size;
    let head = Buffer.alloc(0);
    while (pos > 0 && budget.left > 0) {
      const step = Math.min(CHUNK, pos, budget.left);
      pos -= step;
      budget.left -= step;
      const chunk = Buffer.alloc(step);
      readSync(fd, chunk, 0, step, pos);
      const buf = Buffer.concat([chunk, head]);
      const parts: Buffer[] = [];
      let end = buf.length;
      for (let i = buf.length - 1; i >= 0; i--) {
        if (buf[i] === 0x0a) {
          parts.push(buf.subarray(i + 1, end));
          end = i;
        }
      }
      head = buf.subarray(0, end);
      yield* parts;
    }
    if (pos === 0) yield head;
  } finally {
    closeSync(fd);
  }
}

/** Traffic-log records, newest first, from `file` and then `<file>.1`. */
export function* recordsBackward(file: string, budget = READ_BUDGET_BYTES): Generator<Rec> {
  const left = { left: budget };
  for (const f of [file, `${file}.1`]) {
    for (const line of linesBackward(f, left)) {
      const text = line.toString("utf8");
      if (!text.trim()) continue;
      let rec: unknown;
      try {
        rec = JSON.parse(text);
      } catch {
        continue;
      }
      if (rec && typeof rec === "object" && !Array.isArray(rec)) yield rec as Rec;
    }
  }
}

/** Up to `limit` scan records, newest first, each with its review resolution (or null). */
export function recentScans(file: string, limit: number, match?: (requestId: string) => boolean): ScanWithResolution[] {
  const resolutions = new Map<string, Rec>();
  const seen = new Set<string>();
  const out: ScanWithResolution[] = [];
  for (const rec of recordsBackward(file)) {
    const rid = rec.request_id;
    if (typeof rid !== "string") continue;
    if (rec.kind === "resolution") {
      if (!resolutions.has(rid)) resolutions.set(rid, rec);
    } else if (rec.kind === "scan" && !seen.has(rid)) {
      seen.add(rid);
      if (!match || match(rid)) {
        out.push([rec, resolutions.get(rid) ?? null]);
        if (out.length >= limit) break;
      }
    }
  }
  return out;
}

/** `history [n]`: 10 when empty, at most 50; null when it is not a positive whole number. */
export function parseCount(rest: string): number | null {
  if (!rest) return HISTORY_DEFAULT;
  if (!/^[0-9]{1,6}$/.test(rest) || Number(rest) < 1) return null;
  return Math.min(Number(rest), HISTORY_MAX);
}

/** `why [request_id|last]`: a matcher on request ids (a prefix will do); null when malformed. */
export function parseRef(rest: string): ((requestId: string) => boolean) | null {
  if (rest === "" || rest.toLowerCase() === "last") return () => true;
  if (!ID.test(rest)) return null;
  const prefix = rest.toLowerCase();
  return (rid) => rid.toLowerCase().startsWith(prefix);
}

/** Lengths and cuts count code points, as Python does, so both plugins print the same text. */
function chars(s: string): string[] {
  return [...s];
}

function text(v: unknown, limit: number): string {
  const s = chars(String(v).replace(/\s+/g, " ").trim());
  return s.length <= limit ? s.join("") : `${s.slice(0, limit - 1).join("")}…`;
}

function responseOf(scan: Rec): ScanResponse | null {
  const r = scan.response;
  return r && typeof r === "object" && !Array.isArray(r) ? (r as ScanResponse) : null;
}

function risk(resp: ScanResponse | null): string {
  const v: unknown = resp?.risk;
  return typeof v === "number" && Number.isFinite(v) ? String(Math.round(v)) : "-";
}

/** The tree's tier scores on the 0-100 scale of `risk`, each held to 0-1; empty when none. */
function scores(resp: ScanResponse): string {
  return Object.entries(tiersOf(resp))
    .filter((e): e is [string, number] => e[1] !== null && Number.isFinite(e[1]))
    .map(([name, v]) => `${name} ${Math.round(Math.min(Math.max(v, 0), 1) * 100)}`)
    .join(", ");
}

function time(ts: unknown): string {
  return typeof ts === "string" && ts.length >= 19 ? `${ts.slice(0, 10)} ${ts.slice(11, 19)}` : "?";
}

/** What the plugin did with the call. */
export function actionOf(scan: Rec, resolution: Rec | null): string {
  const { verdict, decision } = scan;
  if (responseOf(scan) === null) {
    if (resolution !== null) return "review (scan error)";
    return decision === "blocked_on_error" ? "blocked (scan error)" : "allowed (scan error)";
  }
  if (scan.mode === "observe") return verdict === "review" || verdict === "block" ? `observed (would ${verdict})` : "allowed";
  if (verdict === "block") return "blocked";
  if (verdict === "review") return decision === "blocked" ? "blocked (no reviewer)" : "review";
  if (verdict === "allow") return "allowed";
  return text(decision || "?", 30);
}

/** How the review was answered; `-` when there was none. */
export function reviewOf(action: string, resolution: Rec | null): string {
  if (resolution === null) return action.startsWith("review") ? "no answer" : "-";
  const choice = String(resolution.resolution ?? "").trim().toLowerCase();
  return APPROVED.has(choice) ? "approved" : (REVIEW[choice] ?? "not approved");
}

export function formatHistory(scans: ScanWithResolution[], whyCommand: string): string {
  if (!scans.length) return NO_SCANS;
  const table: string[][] = [["id", "time (UTC)", "tool", "risk", "action", "review"]];
  for (const [scan, resolution] of scans) {
    const action = actionOf(scan, resolution);
    table.push([
      String(scan.request_id).slice(0, 8),
      time(scan.ts),
      text(scan.tool || "?", 40),
      risk(responseOf(scan)),
      action,
      reviewOf(action, resolution),
    ]);
  }
  const widths = table[0]!.map((_, i) => Math.max(...table.map((row) => chars(row[i]!).length)));
  const rows = table.map((row) =>
    row
      .map((c, i) => c + " ".repeat(widths[i]! - chars(c).length))
      .join("  ")
      .trimEnd(),
  );
  const n = scans.length;
  return [`Last ${n} scan${n === 1 ? "" : "s"}, newest first:`, ...rows, `Details: ${whyCommand} <id>`].join("\n");
}

/** E1, E2, ..., E10 in number order. */
function entityOrder(a: string, b: string): number {
  const num = (k: string) => (/^\d+$/.test(k.slice(1)) ? Number(k.slice(1)) : Number.POSITIVE_INFINITY);
  return num(a) - num(b) || (a < b ? -1 : a > b ? 1 : 0);
}

export function formatWhy(scan: Rec, resolution: Rec | null): string {
  const resp = responseOf(scan);
  const action = actionOf(scan, resolution);
  const step = scan.step;
  const lines = [
    `scan: ${scan.request_id}`,
    `time: ${time(scan.ts)} UTC`,
    `tool: ${text(scan.tool || "?", 80)}${Number.isInteger(step) ? `, step ${step}` : ""}`,
  ];
  if (resp === null) {
    const failure = scan.failure && typeof scan.failure === "object" ? scan.failure : {};
    const status = Number.isInteger(failure.status) ? `, HTTP ${failure.status}` : "";
    lines.push(`risk: - (scan failed: ${text(failure.kind || "unknown", 40)}${status})`);
  } else {
    const floor = resp.enforced;
    lines.push(`risk: ${risk(resp)}${floor === "review" || floor === "block" ? `, scanner floor: ${floor}` : ""}`);
  }
  lines.push(`action: ${action}`, `review: ${reviewOf(action, resolution)}`);
  const r: ScanResponse = resp ?? ({} as ScanResponse);
  const tierScores = scores(r);
  if (tierScores) lines.push(`scores: ${tierScores}`);
  const codes: string[] = [];
  for (const reason of Array.isArray(r.reasons) ? r.reasons : []) {
    const code: unknown = reason && typeof reason === "object" ? reason.code : undefined;
    if (typeof code === "string" && code && !codes.includes(text(code, 80))) codes.push(text(code, 80));
  }
  lines.push(`reasons: ${codes.join(", ") || "none"}`);
  const entities: Rec = r.entities && typeof r.entities === "object" ? r.entities : {};
  const shown = Object.keys(entities)
    .sort(entityOrder)
    .filter((k) => entities[k] && typeof entities[k] === "object" && typeof entities[k].display === "string")
    .map((k) => `  ${text(k, 12)} ${text(entities[k].kind || "?", 20)}: ${text(entities[k].display, 200)}`);
  lines.push(...(shown.length ? ["entities:", ...shown] : ["entities: none"]));
  return lines.join("\n");
}
