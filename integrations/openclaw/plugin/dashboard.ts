/**
 * The read-only dashboard: a Control UI tab showing recent scans and each scan's risk tree.
 *
 * `buildModel` turns the tail of the traffic log into the JSON the page draws. It holds only what the scanner
 * returned (risk, the tier and leaf scores, floors, relief, reason codes and texts, entity display strings) plus
 * the plugin's own labels for what it did. The PlanIR as sent, the call's arguments, `reasons[].detail` and
 * failure details are never included, as with `/sentrook-why`. The Hermes plugin builds the same model for the
 * same log (fixtures/traffic-log/dashboard).
 *
 * The page is served on a Gateway route with `auth: "gateway"`. Inside the Control UI tab the browser holds a
 * short-lived grant that allows only GET and HEAD with `operator.read`, so the page cannot change anything;
 * the route refuses every other method too. Changes stay with the owner commands.
 */

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { PluginConfig } from "./config.ts";
import * as grants from "./grants.ts";
import { actionOf, HISTORY_DEFAULT, HISTORY_MAX, recentScans, responseOf, reviewOf, text } from "./history.ts";
import * as snooze from "./snooze.ts";

type Rec = Record<string, any>;

export const ROUTE = "/sentrook";
export const MODEL_VERSION = 1;

/** The leaves of each tier, in the order the page shows them; any other numeric key follows, sorted. */
export const TIERS: Array<[string, string[]]> = [
  [
    "suspicion",
    ["misalignment", "concealment", "overreach", "distrust", "request_origin", "retry_after_denial", "untrusted_origin", "exposure", "session_exposure"],
  ],
  ["consequence", ["sensitivity", "reach", "irreversibility", "self_modification"]],
  ["confidence", ["agreement", "coverage", "model_certainty"]],
];

/** Plugin marks on a scan record worth showing next to the action. */
const FLAGS = ["snoozed", "relaxed", "hold", "notice", "skill_review", "self_edit", "host_process"];

function unit(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? Math.min(Math.max(v, 0), 1) : null;
}

function finite(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function str(v: unknown, limit: number): string | null {
  return typeof v === "string" && v.trim() ? text(v, limit) : null;
}

function obj(v: unknown): Rec {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {};
}

function list(v: unknown): Rec[] {
  return Array.isArray(v) ? v.filter((x) => x && typeof x === "object" && !Array.isArray(x)) : [];
}

function tiers(tree: Rec): Rec[] {
  return TIERS.map(([name, known]) => {
    const t = obj(tree[name]);
    const extra = Object.keys(t)
      .filter((k) => k !== "score" && !known.includes(k) && typeof t[k] === "number")
      .sort();
    return {
      name,
      score: unit(t.score),
      leaves: [...known, ...extra].map((leaf) => ({ name: leaf, value: unit(t[leaf]) })),
    };
  });
}

/** E1, E2, ..., E10 in number order. */
function entityOrder(a: string, b: string): number {
  const num = (k: string) => (/^\d+$/.test(k.slice(1)) ? Number(k.slice(1)) : Number.POSITIVE_INFINITY);
  return num(a) - num(b) || (a < b ? -1 : a > b ? 1 : 0);
}

/** Which total a scan counts towards. */
export function bucketOf(scan: Rec, action: string): string {
  if (responseOf(scan) === null) return "scan_error";
  if (action.startsWith("blocked")) return "blocked";
  if (action.startsWith("review") || action.startsWith("held")) return "review";
  if (action.startsWith("observed")) return "observed";
  return "allowed";
}

export function scanModel(scan: Rec, resolution: Rec | null): Rec {
  const resp = responseOf(scan);
  const r: Rec = resp ?? {};
  const action = actionOf(scan, resolution);
  const entities = obj(r.entities);
  return {
    id: String(scan.request_id),
    ts: typeof scan.ts === "string" ? scan.ts : null,
    session: str(scan.session_ref, 80),
    tool: str(scan.tool, 80),
    step: Number.isInteger(scan.step) ? scan.step : null,
    mode: str(scan.mode, 20),
    action,
    review: reviewOf(action, resolution),
    bucket: bucketOf(scan, action),
    flags: FLAGS.filter((f) => scan[f] === true),
    failure: resp === null ? (str(obj(scan.failure).kind, 40) ?? "unknown") : null,
    risk: finite(r.risk),
    enforced: r.enforced === "review" || r.enforced === "block" ? r.enforced : null,
    ceiling: str(r.ceiling, 20),
    tiers: resp === null ? [] : tiers(obj(r.tree)),
    floors: list(r.floors_applied).map((f) => ({ floor: str(f.floor, 80), min_risk: unit(f.min_risk), subject: str(f.subject, 12) })),
    relief: list(r.relief_applied).map((f) => ({ effect: str(f.effect, 80), grant_ref: str(f.grant_ref, 40), subject: str(f.subject, 12) })),
    reasons: list(r.reasons)
      .filter((x) => typeof x.code === "string" && x.code)
      .map((x) => ({ code: text(x.code, 80), signal: str(x.signal, 60), subject: str(x.subject, 12), text: str(x.text, 200) })),
    entities: Object.keys(entities)
      .sort(entityOrder)
      .filter((k) => typeof obj(entities[k]).display === "string")
      .map((k) => ({ id: text(k, 12), kind: str(entities[k].kind, 20), display: text(entities[k].display, 200) })),
  };
}

/** The scans part of the model; both plugins build the same JSON for the same log. */
export function scansModel(file: string, enabled: boolean, limit: number): Rec {
  const scans = enabled ? recentScans(file, limit).map(([s, res]) => scanModel(s, res)) : [];
  const totals: Record<string, number> = { blocked: 0, review: 0, observed: 0, allowed: 0, scan_error: 0 };
  for (const s of scans) totals[s.bucket] = (totals[s.bucket] ?? 0) + 1;
  return { version: MODEL_VERSION, log: enabled ? "on" : "off", limit, scans, totals };
}

/** `?n=` from the page's limit links: the history default when absent or malformed, at most the history max. */
export function limitOf(raw: string | null): number {
  if (!raw || !/^[0-9]{1,4}$/.test(raw) || Number(raw) < 1) return HISTORY_DEFAULT;
  return Math.min(Number(raw), HISTORY_MAX);
}

const CMD: grants.Cmd = (sub) => `/sentrook-${sub}`;

export function buildModel(cfg: PluginConfig, limit: number, now: Date = new Date()): Rec {
  const model = scansModel(cfg.trafficLog.path, cfg.trafficLog.enabled, limit);
  let grantsText: string;
  let snoozeText: string;
  try {
    grantsText = grants.formatGrants(cfg, grants.load(cfg.stateDir), now, CMD, null);
  } catch {
    grantsText = "Grants could not be read.";
  }
  try {
    snoozeText = snooze.statusLine(snooze.load(cfg.stateDir), now);
  } catch {
    snoozeText = "Snooze state could not be read.";
  }
  return {
    ...model,
    host: "openclaw",
    lines: { review_at: cfg.reviewAt, block_at: cfg.blockAt },
    mode: cfg.mode,
    state: { grants: grantsText, snooze: snoozeText },
    commands: { history: "/sentrook-history", why: "/sentrook-why <id>", grants: "/sentrook-grants", snooze: "/sentrook-snooze" },
  };
}

let viewSource: string | null = null;

/** The browser script, shared byte for byte with the Hermes plugin's dashboard bundle. */
export function viewScript(): string {
  if (viewSource !== null) return viewSource;
  const here = path.dirname(fileURLToPath(import.meta.url));
  // Next to index.ts when run from source; one level up from dist/index.js when bundled.
  for (const dir of [here, path.dirname(here)]) {
    try {
      viewSource = readFileSync(path.join(dir, "dashboardView.js"), "utf8");
      return viewSource;
    } catch {
      // Try the next place.
    }
  }
  viewSource = "document.body.textContent = 'The Sentrook dashboard script is missing from this install.';";
  return viewSource;
}

/** JSON safe inside a `<script>` element: no `<`, `>` or `&`, and no line separators. */
export function scriptJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export function renderPage(model: unknown, nonce: string, script: string = viewScript()): string {
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Sentrook</title></head>",
    '<body><div id="sentrook-root"></div>',
    `<script type="application/json" id="sentrook-model">${scriptJson(model)}</script>`,
    `<script nonce="${nonce}">${script.replace(/<\/script/gi, "<\\/script")}</script>`,
    "</body></html>",
  ].join("\n");
}

interface Req {
  method?: string;
  url?: string;
}
interface Res {
  statusCode: number;
  setHeader: (name: string, value: string) => void;
  end: (body?: string) => void;
}

function send(res: Res, status: number, type: string, body: string, head: boolean, extra: Record<string, string> = {}): true {
  res.statusCode = status;
  res.setHeader("Content-Type", type);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(head ? undefined : body);
  return true;
}

/**
 * The route handler: GET or HEAD of `/sentrook` (or `/sentrook/`) draws the page; nothing else is served. A path
 * that only shares the prefix (`/sentrook-x`) is not ours and is left to the Gateway (false).
 */
export function handleRequest(req: Req, res: Res, loadConfig: () => PluginConfig, now: () => Date = () => new Date()): boolean {
  const pathname = new URL(req.url ?? ROUTE, "http://gateway.invalid").pathname;
  if (pathname !== ROUTE && !pathname.startsWith(`${ROUTE}/`)) return false;
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    return send(res, 405, "text/plain; charset=utf-8", "The Sentrook dashboard is read-only.", false, { Allow: "GET, HEAD" });
  }
  const head = method === "HEAD";
  const url = new URL(req.url ?? ROUTE, "http://gateway.invalid");
  if (url.pathname !== ROUTE && url.pathname !== `${ROUTE}/`) {
    return send(res, 404, "text/plain; charset=utf-8", "Not found.", head);
  }
  let model: unknown;
  try {
    model = buildModel(loadConfig(), limitOf(url.searchParams.get("n")), now());
  } catch {
    return send(res, 500, "text/plain; charset=utf-8", "The Sentrook dashboard could not read its state.", head);
  }
  const nonce = randomBytes(16).toString("base64");
  return send(res, 200, "text/html; charset=utf-8", renderPage(model, nonce), head, {
    "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`,
  });
}

/** The Control UI tab: the Gateway draws the route in a sandboxed frame. */
export const TAB = {
  surface: "tab",
  id: "sentrook",
  label: "Sentrook",
  description: "Recent Sentrook scans and their risk scores (read-only).",
  icon: "shield",
  group: "control",
  path: ROUTE,
  requiredScopes: ["operator.read"],
} as const;
