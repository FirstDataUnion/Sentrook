/**
 * A wrong-scan report: one scan from the traffic log, in a block the owner can copy and send to Sentrook.
 *
 * The summary is what `/sentrook-why` shows (without grant suggestions) plus the versions needed to look into
 * the scan: host, plugin, scanner and scan-wide versions, all read from the scan's own record. It holds no
 * PlanIR body, call arguments or conversation text, so the owner can post it in a public GitHub issue once
 * they have read it. The full record adds the scan's traffic-log lines exactly as written, so the scan can be
 * replayed; it can hold conversation text, paths and addresses, so it is only ever sent privately (to a
 * colleague, or by email to `SUPPORT_EMAIL`), never put in an issue or a link.
 *
 * The Hermes plugin builds the same summary, full record, issue link and email link for the same log
 * (fixtures/traffic-log/report).
 */

import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

import { SUPPORT_EMAIL, WRONG_SCAN_ISSUE_URL } from "./config.ts";
import { formatWhy, linesBackward, READ_BUDGET_BYTES, responseOf, text } from "./history.ts";

type Rec = Record<string, any>;

export const BEGIN = "----- BEGIN SENTROOK REPORT v1 -----";
export const END = "----- END SENTROOK REPORT v1 -----";
export const FULL_BEGIN = "----- BEGIN SENTROOK FULL RECORD v1 -----";
export const FULL_END = "----- END SENTROOK FULL RECORD v1 -----";
/** Longest issue link built; past this the entity lines are cut, then the report is left out. */
export const URL_MAX = 6000;
/** Shown above every full record. */
export const FULL_WARNING =
  "Full record: the exact request Sentrook saw. It can hold conversation text, file paths, names and " +
  "addresses. Read it and remove anything private before sharing. Send it privately (to a colleague, or " +
  `by email to ${SUPPORT_EMAIL}), never in a public issue. Email is not end-to-end encrypted; Sentrook ` +
  "keeps emailed records for up to 30 days, then deletes them.";
export const EMAIL_BODY = "Paste the Sentrook report below (the summary and the full record).\n\nGitHub issue, if you opened one:\n";
const FLAGS = new Set(["--full", "--github", "--save"]);
const ENTITY = /^ {2}\S/;
const FILE_ID = /[^0-9A-Za-z-]/g;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** `s` with any lone surrogate (a `\\ud800` escape in the log) as U+FFFD, so it encodes, as on Hermes. */
function well(s: string): string {
  return s.replace(LONE_SURROGATE, "\uFFFD");
}
const GRANTS = "grants that would allow it next time";

export interface Found {
  scan: Rec;
  resolution: Rec | null;
  /** The traffic-log lines as written, without their newline. */
  scanLine: string;
  resolutionLine: string | null;
}

/** The newest scan whose request id `match` accepts, with its resolution and both raw lines. */
export function find(file: string, match: (requestId: string) => boolean, budget = READ_BUDGET_BYTES): Found | null {
  const left = { left: budget };
  const resolutions = new Map<string, [Rec, string]>();
  for (const p of [file, `${file}.1`]) {
    for (const raw of linesBackward(p, left)) {
      const line = raw.toString("utf8");
      if (!line.trim()) continue;
      let rec: unknown;
      try {
        rec = JSON.parse(line);
      } catch {
        continue;
      }
      if (!rec || typeof rec !== "object" || Array.isArray(rec)) continue;
      const r = rec as Rec;
      const rid = r.request_id;
      if (typeof rid !== "string") continue;
      if (r.kind === "resolution") {
        if (!resolutions.has(rid)) resolutions.set(rid, [r, line]);
      } else if (r.kind === "scan" && match(rid)) {
        const res = resolutions.get(rid);
        return { scan: r, resolution: res ? res[0] : null, scanLine: line, resolutionLine: res ? res[1] : null };
      }
    }
  }
  return null;
}

function obj(v: unknown): Rec {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {};
}

/** A version value as text: strings, whole numbers and booleans; anything else is left out. */
function scalar(v: unknown): string | null {
  if (typeof v === "boolean") return v ? "true" : "false";
  // Whole numbers JavaScript holds exactly, so both plugins print the same.
  if (typeof v === "number" && Number.isInteger(v) && Math.abs(v) < 2 ** 53) return String(v);
  if (typeof v === "string" && v) return text(v, 60);
  return null;
}

function pairs(d: Rec): string {
  const out: string[] = [];
  for (const k of Object.keys(d).sort()) {
    const s = scalar(d[k]);
    if (s !== null) out.push(`${text(k, 40)} ${s}`);
  }
  return out.join(", ");
}

export function hostOf(scan: Rec): { platform: string; platform_version: string; plugin_version: string; os: string } {
  const host = obj(obj(scan.planir).host);
  const field = (key: string) => {
    const v = host[key];
    return typeof v === "string" && v.trim() ? text(v, 40) : "?";
  };
  return {
    platform: field("platform"),
    platform_version: field("platform_version"),
    plugin_version: field("plugin_version"),
    os: field("os"),
  };
}

function whyLines(scan: Rec, resolution: Rec | null): string[] {
  const lines = formatWhy(scan, resolution).split("\n");
  const at = lines.findIndex((line) => line.startsWith(GRANTS));
  return at === -1 ? lines : lines.slice(0, at);
}

function versionLines(scan: Rec): string[] {
  const h = hostOf(scan);
  const meta = obj(obj(responseOf(scan)).metadata);
  const scanner = meta.scanner_version;
  const lines = [
    `host: ${h.platform} ${h.platform_version}, plugin ${h.plugin_version}, ${h.os}`,
    `mode: ${typeof scan.mode === "string" && scan.mode ? text(scan.mode, 20) : "?"}`,
    `scanner: ${typeof scanner === "string" && scanner ? text(scanner, 60) : "?"}`,
  ];
  const versions = pairs(obj(meta.versions));
  if (versions) lines.push(`scan versions: ${versions}`);
  for (const probe of Array.isArray(meta.probes) ? meta.probes : []) {
    if (!probe || typeof probe !== "object" || typeof probe.step !== "string") continue;
    const pv = pairs(obj(probe.versions));
    if (pv) lines.push(`probe ${text(probe.step, 30)}: ${pv}`);
  }
  return lines;
}

export function summaryLines(scan: Rec, resolution: Rec | null): string[] {
  return [
    ...[...whyLines(scan, resolution), ...versionLines(scan)].map(well),
    "expected: (allow, review or block)",
    "what you were doing: (in your own words)",
  ];
}

export function summary(scan: Rec, resolution: Rec | null): string {
  return [BEGIN, ...summaryLines(scan, resolution), END].join("\n");
}

export function fullRecord(found: Found): string {
  const lines = [FULL_BEGIN, found.scanLine];
  if (found.resolutionLine !== null) lines.push(found.resolutionLine);
  lines.push(FULL_END);
  return lines.join("\n");
}

export function shortId(scan: Rec): string {
  return String(scan.request_id ?? "").slice(0, 8);
}

export function issueTitle(scan: Rec): string {
  return well(`Wrong scan: ${text(scan.tool || "?", 60)} (${shortId(scan)})`);
}

function issueUrl(scan: Rec, body: string | null): string {
  const h = hostOf(scan);
  let url = `${WRONG_SCAN_ISSUE_URL}&title=${encodeURIComponent(issueTitle(scan))}`;
  if (body !== null) url += `&report=${encodeURIComponent(body)}`;
  return `${url}&host=${encodeURIComponent(`${h.platform} ${h.platform_version}`)}&version=${encodeURIComponent(h.plugin_version)}`;
}

export type Fit = "" | "trimmed" | "blank";

/**
 * The issue form link with the summary filled in, and how it was fitted: "" (whole), "trimmed" (entity lines
 * cut from the end) or "blank" (no report: the owner pastes the summary).
 */
export function githubLink(scan: Rec, resolution: Rec | null): [string, Fit] {
  const lines = [BEGIN, ...summaryLines(scan, resolution), END];
  let url = issueUrl(scan, lines.join("\n"));
  if (url.length <= URL_MAX) return [url, ""];
  const entityAt = lines.flatMap((line, i) => (ENTITY.test(line) ? [i] : []));
  for (let cut = 1; cut <= entityAt.length; cut++) {
    const dropped = new Set(entityAt.slice(-cut));
    const kept = lines.filter((_, i) => !dropped.has(i));
    kept.splice(entityAt[entityAt.length - cut]!, 0, `  (trimmed, ${cut} more)`);
    url = issueUrl(scan, kept.join("\n"));
    if (url.length <= URL_MAX) return [url, "trimmed"];
  }
  return [issueUrl(scan, null), "blank"];
}

export function emailSubject(scan: Rec): string {
  return well(`Sentrook wrong scan ${shortId(scan)}`);
}

/** The short id as a file name part: letters, digits and dashes only, whatever the log holds. */
export function fileId(scan: Rec): string {
  return shortId(scan).replace(FILE_ID, "_") || "scan";
}

/** A mail link with a subject and a short note only: the record itself is pasted or attached, never put in the link. */
export function mailto(scan: Rec): string {
  return `mailto:${SUPPORT_EMAIL}?subject=${encodeURIComponent(emailSubject(scan))}&body=${encodeURIComponent(EMAIL_BODY)}`;
}

/** `report [request_id|last] [--full|--github|--save]`: [ref, flag]; null when malformed. */
export function parseArgs(rest: string): [string, string] | null {
  const words = rest.split(/\s+/).filter(Boolean);
  const flags = words.filter((w) => w.startsWith("-")).map((w) => w.toLowerCase());
  const refs = words.filter((w) => !w.startsWith("-"));
  if (flags.length > 1 || refs.length > 1 || flags.some((f) => !FLAGS.has(f))) return null;
  return [refs[0] ?? "", flags[0] ?? ""];
}

function stamp(now: Date): string {
  return now.toISOString().slice(0, 19).replace(/[-:]/g, "") + "Z";
}

/** Writes the summary and full record to `<stateDir>/reports/`, readable by the owner only. */
export function save(stateDir: string, found: Found, now: Date = new Date()): string {
  const folder = path.join(stateDir, "reports");
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  const file = path.join(folder, `sentrook-report-${fileId(found.scan)}-${stamp(now)}.txt`);
  const body = [summary(found.scan, found.resolution), FULL_WARNING, fullRecord(found)].join("\n\n") + "\n";
  writeFileSync(file, body, { encoding: "utf8", mode: 0o600 });
  chmodSync(file, 0o600); // an existing file keeps its mode on write
  return file;
}

/**
 * The dashboard's report panel for one scan. It never holds the full record: the dashboard is not limited to the
 * owner on every host, so the panel gives the owner's commands that print or save it instead.
 */
export function model(found: Found, cmd: (verb: string) => string): Rec {
  const [url, fitted] = githubLink(found.scan, found.resolution);
  const sid = shortId(found.scan);
  return {
    id: found.scan.request_id,
    summary: summary(found.scan, found.resolution),
    full_warning: FULL_WARNING,
    full_commands: [`${cmd("report")} ${sid} --save`, `${cmd("report")} ${sid} --full`],
    github: url,
    github_fit: fitted,
    email: SUPPORT_EMAIL,
    subject: emailSubject(found.scan),
    mailto: mailto(found.scan),
  };
}

const FIT_NOTE: Record<Fit, string> = {
  "": "The issue form opens with this summary filled in.",
  trimmed: "The issue form opens with this summary filled in, some entity lines cut to fit the link.",
  blank: "The summary is too long for a link: paste it into the issue form yourself.",
};

/** The command's reply; `cmd(verb)` is how the owner types a subcommand on this host. */
export function reply(found: Found, flag: string, cmd: (verb: string) => string, stateDir: string): string {
  const sid = shortId(found.scan);
  const body = summary(found.scan, found.resolution);
  if (flag === "--full") return [body, FULL_WARNING, fullRecord(found)].join("\n\n");
  if (flag === "--save") {
    const file = save(stateDir, found);
    return [
      `Wrote the report with its full record to ${file} (readable by you only).`,
      `Read it, remove anything private, then email it to ${SUPPORT_EMAIL} with the subject "${emailSubject(found.scan)}".`,
      "Email is not end-to-end encrypted; Sentrook keeps emailed records for up to 30 days, then deletes them.",
    ].join("\n");
  }
  if (flag === "--github") {
    const [url, fitted] = githubLink(found.scan, found.resolution);
    return [
      body,
      "",
      `${FIT_NOTE[fitted]} The issue is public: read the summary first and remove anything private.`,
      url,
      `The full record is not in the issue. To send it privately: ${cmd("report")} ${sid} --save, then email the file to ${SUPPORT_EMAIL}.`,
    ].join("\n");
  }
  return [
    body,
    "",
    "Fill in the last two lines, then send it to us:",
    `  colleagues: copy it into Discord or chat, with the full record if asked (${cmd("report")} ${sid} --full)`,
    `  public GitHub issue (summary only): ${cmd("report")} ${sid} --github`,
    `  full record, privately by email: ${cmd("report")} ${sid} --save, then email the file to ${SUPPORT_EMAIL}`,
  ].join("\n");
}
