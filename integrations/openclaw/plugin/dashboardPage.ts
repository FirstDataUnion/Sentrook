import {
  escapeHtml,
  highlightCommandHtml,
  operatorSummary,
  dashboardFingerprint,
  ruleMeanings,
  commandSignals,
} from "./dashboardPresent.ts";
import {
  SENSITIVITY_BUTTONS,
  parseSensitivity,
  sensitivityFloorHighlight,
  type Sensitivity,
  type SensitivityScope,
} from "./sessionPolicy.ts";
import {
  allowAllHint,
  feedbackHint,
  quietHint,
  quietLeftLabel,
  scanErrorHint,
  sensitivityHint,
} from "./policyCopy.ts";
import { ACCESS_QUERY, DASHBOARD_TAB_PREFIX } from "./dashboardAuth.ts";
import { DEFAULT_OIDC_ISSUER } from "./scanEndpoint.ts";

export type DashboardViewState = {
  pending: Array<{
    eventId: string;
    toolCallId: string;
    approvalId?: string;
    tool: string;
    command: string;
    args?: Record<string, unknown>;
    scan: {
      decision: string;
      risk?: number;
      summary?: string;
      matched_rules?: string[];
      review_severity?: string;
      block_reason?: string;
    };
    sessionId?: string;
    sessionKey?: string;
    agentId?: string;
    timeoutMs?: number;
    createdAtMs: number;
    intent?: string | null;
    intentKind?: string | null;
    priorSteps?: Array<{
      seq: number;
      tool: string;
      command: string;
      ok?: boolean;
      excerpt?: string;
    }>;
    priorOmitted?: number;
  }>;
  history: Array<{
    id: string;
    ts: string;
    event: string;
    decision: string;
    tool: string;
    command: string;
    summary?: string | null;
    matched_rules?: string[];
    winningRule?: string;
    reviewSeverity?: string;
    excerpt?: string;
    resultOk?: boolean;
    resultTs?: string;
    resultBytes?: number;
    resultTruncated?: boolean;
    resultUrls?: string[];
    resultPaths?: string[];
    injectionMarkers?: boolean;
    sessionKey?: string;
    sessionId?: string;
    agentId?: string;
    risk?: number;
    blockReason?: string | null;
    intent?: string | null;
    intentKind?: string | null;
    resolution?: string;
    resolutionTs?: string;
    resolutionSource?: string;
    errorKind?: string | null;
    errorDetail?: string | null;
    errorStatus?: number | null;
    unattended?: boolean;
    labelSource?: string;
    skipReason?: string;
    allowlistLabel?: string;
    hostTool?: string;
    effect?: string;
    runId?: string;
    neighbors?: Array<{ id: string; tool: string; command: string }>;
    args?: Record<string, unknown>;
  }>;
  audit?: {
    scanned: number;
    allow: number;
    review: number;
    block: number;
    error: number;
  };
  sessions: Array<{
    sessionId?: string;
    sessionKey?: string;
    allowAll: boolean;
    quietUntilMs: number | null;
    pending: number;
  }>;
  sensitivity: string;
  unattendedSensitivity?: string;
  allowAll?: boolean;
  quietUntilMs?: number | null;
  feedbackMode?: string;
  onScanError?: string;
  log: {
    enabled: boolean;
    path: string;
    bytes: number;
    lines: number;
    maxAgeDays: number;
    maxBytes: number;
  };
  allowlist: Array<{
    index: number;
    kind: string;
    label: string;
    tool?: string;
    detail?: string;
    createdAt?: string;
  }>;
  resolveAvailable: boolean;
  setupNeeded?: boolean;
};

type Severity = "info" | "warning" | "critical";

const SEV_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

export { escapeHtml } from "./dashboardPresent.ts";

export function severityOf(raw: string | undefined): Severity {
  const value = (raw ?? "").trim().toLowerCase();
  if (value === "critical" || value === "warning" || value === "info") return value;
  return "warning";
}

function fmtAge(fromMs: number, now: number): string {
  const sec = Math.max(0, Math.round((now - fromMs) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  return `${Math.round(min / 60)}h ago`;
}

function fmtRemain(createdAtMs: number, timeoutMs: number, now: number): string {
  const left = createdAtMs + timeoutMs - now;
  if (left <= 0) return "timed out";
  const sec = Math.round(left / 1000);
  if (sec < 60) return `${sec}s left`;
  const min = Math.floor(sec / 60);
  return `${min}m ${sec % 60}s left`;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function formatCommand(command: string): string {
  const trimmed = command.trim();
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      return command;
    }
  }
  return command;
}

/** One-line identity for a collapsed timeline card — URL/path when that is the args. */
function glanceCommand(command: string): string {
  const trimmed = command.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      if (typeof obj.url === "string" && obj.url.trim()) return obj.url.trim();
      if (typeof obj.action === "string" && typeof obj.path === "string" && obj.path.trim()) {
        return `${obj.action} ${obj.path}`;
      }
    } catch {
      /* fall through to the raw command */
    }
  }
  return clipText(trimmed, 160);
}

function extraArgsJson(args: Record<string, unknown> | undefined, command: string): string | null {
  if (!args) return null;
  const rest: Record<string, unknown> = { ...args };
  if (typeof rest.command === "string" && rest.command === command) delete rest.command;
  if (typeof rest.cmd === "string" && rest.cmd === command) delete rest.cmd;
  if (Object.keys(rest).length === 0) return null;
  return prettyJson(rest);
}

function riskScore(risk: number | undefined): { pct: number; label: string } | null {
  if (typeof risk !== "number" || !Number.isFinite(risk)) return null;
  const pct = Math.min(100, Math.max(0, risk <= 1 ? Math.round(risk * 100) : Math.round(risk)));
  return { pct, label: String(pct) };
}

function commandExcerpt(command: string, max = 64): string {
  const oneLine = command.replace(/\s+/g, " ").trim();
  return oneLine.length <= max ? oneLine : `${oneLine.slice(0, max - 1)}…`;
}

/** OpenClaw Control UI plugin-tab cookies authorize GET/HEAD only (CSRF). */
export const GATEWAY_TAB_WRITE_HINT =
  "Control UI plugin-tab cookies are GET-only, so this change was not saved. Use /sentrook in chat, or open /sentrook with gateway auth in a full browser tab.";

export const GATEWAY_TAB_READ_HINT =
  "This Control UI tab can show the dashboard but cannot save settings or resolve reviews. Use /sentrook in chat, or open /sentrook with gateway auth in a full browser tab.";

function errorField(value: unknown, fallback = ""): string {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (value && typeof value === "object") {
    const msg = (value as { message?: unknown }).message;
    if (typeof msg === "string" && msg.trim()) return msg.trim();
  }
  return fallback;
}

/** Operator copy for a plugin HTTP JSON error (gateway 401 bodies are `{ error: { message, type } }`). */
export function formatHttpError(data: unknown, status: number, statusText = ""): string {
  const rec = data && typeof data === "object" ? (data as Record<string, unknown>) : null;
  if (status === 401 || status === 403) {
    if (typeof rec?.error === "string" && rec.error.trim()) return rec.error.trim();
    return GATEWAY_TAB_WRITE_HINT;
  }
  const fromError = errorField(rec?.error);
  if (fromError) return fromError;
  const fromMessage = errorField(rec?.message);
  if (fromMessage) return fromMessage;
  return statusText.trim() || `HTTP ${status}`;
}

const DASHBOARD_CSS = `
:root {
  color-scheme: dark;
  --bg: #081627;
  --elev: #0b1e33;
  --card: #0f2740;
  --inset: #061018;
  --line: #1a3a58;
  --fg: #f0f4f8;
  --muted: #94a3b8;
  --faint: #6b7c90;
  --accent: #2ba9d2;
  --accent-dim: rgba(43, 169, 210, 0.14);
  --info: #2ba9d2;
  --info-bg: rgba(43, 169, 210, 0.1);
  --info-line: #1a6f8e;
  --warning: #e6b84d;
  --warning-bg: rgba(230, 184, 77, 0.12);
  --warning-line: #a37d22;
  --critical: #ff5d67;
  --critical-bg: rgba(255, 93, 103, 0.14);
  --critical-line: #ff5d67;
  --ok: #7dba7d;
  --deny: #e07a5f;
  --focus: #2ba9d2;
  --url: #f472b6;
  --radius: 10px;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; background: var(--bg); color: var(--fg); overflow: hidden; color-scheme: dark; }
body {
  font: 14px/1.5 "Avenir Next", "Segoe UI", ui-sans-serif, system-ui, sans-serif;
  display: flex; flex-direction: column;
}
body > :not(.page) { flex-shrink: 0; }
code, pre, kbd {
  font-family: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
}
a { color: var(--accent); }
button, .btn {
  font: inherit; color: var(--fg); background: var(--elev); border: 1px solid var(--line);
  border-radius: var(--radius); padding: 0.45rem 0.8rem; cursor: pointer;
}
button:hover, .btn:hover { border-color: var(--accent); background: #123049; }
button:focus-visible, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.top {
  display: flex; flex-wrap: wrap; gap: 0.85rem 1.5rem; align-items: center;
  padding: 0.85rem 1.5rem; border-bottom: 1px solid var(--line); background: var(--elev);
  z-index: 20;
}
.brand { display: flex; align-items: center; min-width: auto; }
h1 {
  font-size: 0.98rem; font-weight: 700; letter-spacing: 0.24em; margin: 0;
  text-transform: uppercase; line-height: 1;
}
.ver {
  margin-left: auto;
  color: var(--muted);
  font-size: 0.72rem;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.04em;
  white-space: nowrap;
}
.meta { margin-left: auto; display: flex; align-items: center; gap: 1rem; }
.tabs { display: flex; flex-wrap: wrap; gap: 0.1rem; flex: 1; align-self: stretch; }
.tabs a {
  color: var(--muted); text-decoration: none; padding: 0.55rem 0.85rem 0.45rem;
  display: inline-flex; align-items: center; gap: 0.4rem; font-weight: 600;
  font-size: 0.82rem; letter-spacing: 0.06em; text-transform: uppercase;
  border-bottom: 2px solid transparent; margin-bottom: -1px;
}
.tabs a:hover { color: var(--fg); }
.tabs a[aria-current="page"] { color: var(--fg); border-bottom-color: var(--accent); }
.count {
  font-size: 0.68rem; font-weight: 700; letter-spacing: 0; text-transform: none;
  background: var(--accent-dim); color: var(--accent);
  border-radius: 999px; min-width: 1.2rem; padding: 0.05rem 0.38rem; text-align: center;
}
.count.warn { background: var(--warning-bg); color: var(--warning); }
.count.critical { background: var(--critical-bg); color: var(--critical); }
#flash:empty { display: none; }
#flash:not(:empty) {
  position: fixed; left: 50%; top: 0.85rem; transform: translate(-50%, 0);
  z-index: 80; width: min(36rem, calc(100vw - 2rem));
  padding: 1rem 1.15rem; border-radius: 10px;
  border: 1px solid var(--line); background: var(--card); color: var(--fg);
  font-size: 0.95rem; line-height: 1.45; text-align: center;
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.55);
  cursor: pointer;
}
#flash.flash-error { border-color: var(--critical); background: #4a1822; color: #ffc1c5; }
#flash.flash-ok { border-color: var(--accent); background: #0d3a4d; color: var(--fg); }
#confirm[hidden] { display: none !important; }
#confirm {
  position: fixed; inset: 0; z-index: 90; display: flex; align-items: flex-start;
  justify-content: center; padding: 12vh 1rem 1rem; background: rgba(0, 0, 0, 0.45);
}
#confirm .confirm-card {
  width: min(36rem, 100%); padding: 1.1rem 1.2rem 1rem; border-radius: 10px;
  border: 1px solid var(--warning-line); background: var(--card); color: var(--fg);
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.55);
}
#confirm .confirm-card p { margin: 0 0 0.9rem; font-size: 0.95rem; line-height: 1.45; }
#confirm .confirm-actions { display: flex; gap: 0.5rem; justify-content: flex-end; }
.iframe-note, .iframe-note-url { display: none; }
body.in-frame .iframe-note {
  display: block; margin: 0; padding: 0.65rem 1.5rem 0.35rem;
  border-bottom: 0; background: var(--warning-bg);
  color: var(--fg); font-size: 0.86rem; line-height: 1.45;
}
body.in-frame .iframe-note-url {
  display: block; margin: 0; padding: 0 1.5rem 0.65rem; border: 0;
  border-bottom: 1px solid var(--warning-line); background: var(--warning-bg);
  width: 100%; box-sizing: border-box; font: inherit; font-size: 0.78rem;
  color: var(--muted); letter-spacing: 0;
}
.iframe-note code { font-size: 0.86em; }
.page {
  width: 100%;
  max-width: 110rem;
  margin: 0 auto;
  padding: 2rem clamp(1.25rem, 3vw, 2.5rem) 5rem;
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  -webkit-overflow-scrolling: touch;
}
.panel[hidden] { display: none !important; }
.section-head { margin: 0 0 1.35rem; }
.section-head h2 {
  margin: 0 0 0.35rem; font-size: 1.35rem; font-weight: 650; letter-spacing: -0.02em;
}
.section-head p { margin: 0; color: var(--muted); font-size: 0.95rem; line-height: 1.45; }
.jump {
  list-style: none; margin: 0 0 1.25rem; padding: 0; display: flex; flex-direction: column; gap: 0.4rem;
}
.jump a {
  display: flex; gap: 0.7rem; align-items: baseline; text-decoration: none; color: var(--fg);
  background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); padding: 0.65rem 0.9rem;
}
.jump a:hover { border-color: var(--accent); }
.jump .tag { font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; }
.jump .ex { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; }
.jump .tag.sev-info { color: var(--info); }
.jump .tag.sev-warning { color: var(--warning); }
.jump .tag.sev-critical { color: var(--critical); }
.empty {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 3.25rem 1.75rem; text-align: center;
}
.empty-kicker {
  margin: 0; color: var(--accent); font-size: 0.78rem; font-weight: 550;
}
.empty h2 { margin: 0.4rem 0 0.5rem; font-size: 1.5rem; font-weight: 650; letter-spacing: -0.02em; }
.empty p { margin: 0 auto; max-width: 32rem; color: var(--muted); }
.setup {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 1.75rem 1.5rem; max-width: 38rem; text-align: left;
}
.setup .empty-kicker { margin: 0; }
.setup h2 { margin: 0.4rem 0 0.75rem; font-size: 1.5rem; font-weight: 650; letter-spacing: -0.02em; }
.setup .setup-copy { margin: 0 0 0.85rem; color: var(--muted); font-size: 0.95rem; line-height: 1.55; }
.setup .setup-copy a { color: var(--accent); }
.setup .lead { margin: 0 0 0.5rem; color: var(--muted); font-size: 0.9rem; line-height: 1.5; }
.setup-fields { display: flex; flex-direction: column; gap: 0.85rem; margin-top: 1.15rem; }
.setup .field input { width: 100%; max-width: 100%; }
.setup-actions { margin-top: 1.15rem; }
.verify-result { margin-top: 0.85rem; padding: 0.7rem 0.85rem; background: var(--inset); border-radius: 8px; }
.verify-result ul { margin: 0; padding: 0; list-style: none; }
.verify-result li { margin: 0.35rem 0 0; font-size: 0.88rem; line-height: 1.45; color: var(--muted); }
.verify-result li:first-child { margin-top: 0; }
.verify-result li.ok { color: var(--ok); }
.verify-result li.fail { color: var(--critical); }
.review {
  background: var(--card); border: 1px solid var(--line); border-left-width: 4px;
  border-radius: var(--radius); margin: 0 0 1.5rem; overflow: hidden;
}
.review.sev-info { border-left-color: var(--info); }
.review.sev-warning { border-left-color: var(--warning); }
.review.sev-critical { border-left-color: var(--critical); box-shadow: 0 0 0 1px rgba(255, 93, 103, 0.16); }
.hero {
  display: grid; grid-template-columns: 1fr auto; gap: 1.25rem; align-items: end;
  padding: 1.4rem 1.5rem 1.1rem;
}
.review.sev-info .hero { background: var(--info-bg); }
.review.sev-warning .hero { background: var(--warning-bg); }
.review.sev-critical .hero { background: var(--critical-bg); }
.sev-kicker, .risk-kicker {
  margin: 0; font-size: 0.78rem; font-weight: 550; color: var(--muted);
}
.sev-label {
  margin: 0.2rem 0 0; font-size: 1.85rem; font-weight: 750; letter-spacing: 0.06em; text-transform: uppercase; line-height: 1.1;
}
.sev-info .sev-label { color: var(--info); }
.sev-warning .sev-label { color: var(--warning); }
.sev-critical .sev-label { color: var(--critical); }
.hero-risk { text-align: right; min-width: 7.5rem; }
.risk-row { display: flex; align-items: baseline; justify-content: flex-end; gap: 0.25rem; }
.risk-num { font-size: 2.5rem; font-weight: 750; font-variant-numeric: tabular-nums; line-height: 1; }
.risk-scale { color: var(--muted); font-size: 0.85rem; }
.risk-bar { margin-top: 0.4rem; height: 5px; background: var(--inset); border-radius: 99px; overflow: hidden; }
.risk-bar > i { display: block; height: 100%; border-radius: inherit; }
.sev-info .risk-bar > i { background: var(--info); }
.sev-warning .risk-bar > i { background: var(--warning); }
.sev-critical .risk-bar > i { background: var(--critical); }
.risk-missing { color: var(--faint); font-size: 0.9rem; padding-top: 1.2rem; }
.summary { margin: 0; padding: 0.15rem 1.5rem 0; font-size: 1.08rem; line-height: 1.5; }
.intent {
  margin: 0.7rem 1.5rem 0; padding: 0.7rem 0.9rem; background: var(--inset);
  border-radius: 8px; color: var(--fg); font-size: 0.95rem; line-height: 1.45;
}
.intent-label { display: block; color: var(--faint); font-size: 0.72rem; margin-bottom: 0.25rem; }
.kind {
  display: inline-block; margin-left: 0.45rem; padding: 0.05rem 0.45rem; border-radius: 99px;
  font-size: 0.68rem; font-weight: 650; letter-spacing: 0.06em; text-transform: uppercase;
  background: var(--accent-dim); color: var(--accent); vertical-align: middle;
}
.kind-cron { background: var(--warning-bg); color: var(--warning); }
.kind-subagent { background: var(--info-bg); color: var(--info); }
.kind-system { background: rgba(148, 163, 184, 0.16); color: var(--muted); }
.facts {
  display: flex; flex-wrap: wrap; gap: 0.45rem 1.15rem; margin: 0; padding: 0.95rem 1.5rem 0;
}
.facts div { min-width: auto; }
.facts dt { margin: 0; font-size: 0.72rem; color: var(--faint); }
.facts dd { margin: 0.1rem 0 0; font-weight: 550; word-break: break-all; }
.facts a { color: var(--fg); text-decoration: none; border-bottom: 1px solid var(--line); }
.facts a:hover { color: var(--accent); border-bottom-color: var(--accent); }
.block { padding: 1rem 1.5rem 0; }
.block-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin-bottom: 0.4rem; }
.block h3, .more summary {
  margin: 0; font-size: 0.82rem; font-weight: 600; color: var(--muted);
}
pre.command {
  margin: 0; white-space: pre-wrap; word-break: break-word; background: var(--inset);
  border: 1px solid var(--line); border-radius: 8px; padding: 0.9rem 1rem; font-size: 0.92rem; line-height: 1.45;
}
pre.command mark.hl, pre.lead mark.hl { padding: 0.05em 0.12em; border-radius: 2px; font-weight: 650; }
pre.command mark.hl-url, pre.lead mark.hl-url {
  background: var(--url); color: var(--bg);
}
pre.command mark.hl-path, pre.lead mark.hl-path { background: rgba(230, 184, 77, 0.28); color: #ffe7a8; }
pre.command mark.hl-destroy, pre.lead mark.hl-destroy { background: rgba(255, 93, 103, 0.32); color: #ffd0d3; }
pre.command mark.hl-pipe, pre.lead mark.hl-pipe { background: rgba(255, 93, 103, 0.22); color: #ffd0d3; }
.chips { display: flex; flex-wrap: wrap; gap: 0.4rem; list-style: none; margin: 0.35rem 0 0; padding: 0; }
.chips li {
  background: var(--inset); border: 1px solid var(--line); border-radius: 99px; padding: 0.22rem 0.7rem;
  font-size: 0.82rem;
}
.hint { color: var(--muted); font-size: 0.85rem; }
.spine, .spine-older {
  list-style: none;
}
.spine li::marker, .spine-older li::marker { content: none; }
.spine {
  position: relative;
  margin: 1.15rem 1.5rem 0;
  padding: 0 0 0.15rem 2.35rem;
}
.spine::before {
  content: ""; position: absolute; left: 9px; top: 0.45rem; bottom: 1.6rem;
  width: 2px; background: var(--line); border-radius: 2px;
}
.spine-step { position: relative; margin: 0 0 0.55rem; }
.spine-step::before {
  content: ""; position: absolute; left: -2.2rem; top: 0.42rem;
  width: 10px; height: 10px; border-radius: 50%;
  background: var(--card); border: 2px solid var(--muted);
}
.spine-past { color: var(--muted); }
.spine-past .spine-head { margin-bottom: 0.2rem; }
.spine-past .command {
  max-height: 2.55em; overflow: clip; padding: 0.28rem 0.5rem;
  font-size: 0.78rem; line-height: 1.35; color: var(--fg);
}
.spine-fold::before {
  width: 8px; height: 8px; top: 0.5rem; background: var(--line); border-color: var(--line);
}
.spine-fold details { margin: 0; }
.spine-fold summary {
  cursor: pointer; color: var(--faint); font-size: 0.8rem; font-weight: 550;
}
.spine-older {
  list-style: none; margin: 0.45rem 0 0.15rem; padding: 0;
}
.spine-older .spine-step { margin: 0 0 0.4rem; }
.spine-older .spine-step::before { display: none; }
.spine-now {
  background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
  padding: 1rem 1.1rem 1.1rem; margin-bottom: 0;
  box-shadow: 0 10px 28px rgba(0, 0, 0, 0.22);
}
.spine-now::before {
  top: 1.2rem; width: 12px; height: 12px; left: -2.28rem;
}
.review.sev-info .spine-now { border-color: var(--info-line); }
.review.sev-warning .spine-now { border-color: var(--warning-line); }
.review.sev-critical .spine-now { border-color: var(--critical-line); }
.review.sev-info .spine-now::before { border-color: var(--info); background: var(--info); box-shadow: 0 0 0 4px var(--info-bg); }
.review.sev-warning .spine-now::before { border-color: var(--warning); background: var(--warning); box-shadow: 0 0 0 4px var(--warning-bg); }
.review.sev-critical .spine-now::before { border-color: var(--critical); background: var(--critical); box-shadow: 0 0 0 4px var(--critical-bg); }
.spine-head { display: flex; flex-wrap: wrap; gap: 0.35rem 0.55rem; align-items: baseline; margin-bottom: 0.4rem; }
.spine-n { color: var(--faint); font-size: 0.75rem; font-variant-numeric: tabular-nums; min-width: 1.1rem; }
.spine-tool { font-size: 0.8rem; }
.spine-now .spine-tool { font-size: 0.9rem; font-weight: 650; }
.spine-ok { color: var(--ok); font-size: 0.72rem; font-weight: 600; }
.spine-fail { color: var(--critical); font-size: 0.72rem; font-weight: 600; }
.spine-now-kicker { color: var(--fg); font-size: 0.88rem; font-weight: 650; margin-right: auto; }
.spine-now .command { font-size: 0.98rem; padding: 0.95rem 1.05rem; }
.spine-out-fold { margin: 0.2rem 0 0; }
.spine-out-fold summary { cursor: pointer; color: var(--faint); font-size: 0.72rem; }
.spine-out {
  margin: 0.3rem 0 0; max-height: 4.4rem; overflow: auto; color: var(--muted);
  background: var(--inset); padding: 0.35rem 0.45rem; border-radius: 6px; font-size: 0.75rem;
}
.decide {
  position: sticky; bottom: 0; display: flex; flex-wrap: wrap; gap: 0.55rem; align-items: center;
  margin-top: 1.2rem; padding: 1rem 1.5rem 1.15rem; background: #0b1e33f5; border-top: 1px solid var(--line);
  backdrop-filter: blur(12px);
}
.btn-once {
  background: var(--accent); border-color: var(--accent); color: #081627; font-weight: 700;
  padding: 0.65rem 1.15rem; letter-spacing: 0.02em; border-radius: 8px;
}
.btn-once:hover { background: #48c0e4; border-color: #48c0e4; }
.btn-always { color: var(--muted); border-radius: 8px; }
.btn-deny {
  background: transparent; border-color: var(--critical-line); color: var(--critical); font-weight: 650;
  margin-left: auto; padding: 0.65rem 1.1rem; border-radius: 8px;
}
.btn-deny:hover { background: var(--critical-bg); }
.legend { width: 100%; margin: 0.25rem 0 0; color: var(--muted); font-size: 0.82rem; line-height: 1.45; }
.fallback { margin: 0.25rem 0 0; color: var(--faint); font-size: 0.8rem; }
.more { padding: 0.85rem 1.5rem 1.25rem; }
.more pre { white-space: pre-wrap; word-break: break-word; background: var(--inset); padding: 0.7rem; border-radius: 8px; font-size: 0.8rem; }
.more dl { display: grid; grid-template-columns: 8rem 1fr; gap: 0.25rem 0.8rem; margin: 0.6rem 0; }
.more dt { color: var(--faint); }
.more dd { margin: 0; word-break: break-all; }
.filters { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0 0 1rem; }
.filters button {
  border-radius: 99px; padding: 0.28rem 0.75rem; font-size: 0.82rem; background: transparent;
}
.filters button[aria-pressed="true"] {
  background: var(--accent-dim); border-color: var(--accent); color: var(--fg);
}
.stream { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.65rem; }
.stream-item {
  background: var(--card); border: 1px solid var(--line); border-left-width: 3px;
  border-radius: var(--radius); padding: 0.85rem 1rem;
}
.stream-item[data-tone="allow"] { border-left-color: var(--ok); }
.stream-item[data-tone="review"] { border-left-color: var(--warning); }
.stream-item[data-tone="block"] { border-left-color: var(--critical); }
.stream-item[data-tone="error"] { border-left-color: var(--faint); }
.stream-head {
  display: flex; flex-wrap: wrap; gap: 0.35rem 0.7rem; align-items: baseline;
  margin: 0.45rem 0 0;
}
.pill {
  font-size: 0.72rem; font-weight: 650; text-transform: uppercase; letter-spacing: 0.04em;
}
.pill-allow { color: var(--ok); }
.pill-review { color: var(--warning); }
.pill-block { color: var(--critical); }
.pill-error { color: var(--muted); }
.stream-when, .stream-session { color: var(--faint); font-size: 0.8rem; font-variant-numeric: tabular-nums; }
.stream-item { padding: 0; }
.stream-item > summary {
  list-style: none; cursor: pointer; padding: 0.85rem 1rem 0.9rem;
}
.stream-item > summary::-webkit-details-marker { display: none; }
.stream-item > summary:focus-visible {
  outline: 2px solid var(--accent); outline-offset: -2px;
}
.stream-lead {
  display: flex; align-items: flex-start; gap: 0.55rem; max-width: 100%;
}
.stream-lead::after {
  content: ""; width: 0.4rem; height: 0.4rem; margin-top: 0.45rem; flex: 0 0 auto;
  border-right: 2px solid var(--faint); border-bottom: 2px solid var(--faint);
  transform: rotate(-45deg); opacity: 0.7;
}
.stream-item[open] .stream-lead::after { transform: rotate(45deg); margin-top: 0.35rem; }
pre.stream-title {
  margin: 0; padding: 0; border: 0; background: none; min-width: 0;
  font-size: 0.95rem; line-height: 1.4; font-weight: 550;
  max-height: 2.8em; overflow: clip; white-space: pre-wrap; word-break: break-word;
}
pre.stream-title mark.hl, .signals mark.hl, .extracts mark.hl { padding: 0.05em 0.12em; border-radius: 2px; font-weight: 650; }
pre.stream-title mark.hl-url, .signals mark.hl-url, .extracts mark.hl-url { background: var(--url); color: var(--bg); }
pre.stream-title mark.hl-path, .signals mark.hl-path, .extracts mark.hl-path { background: rgba(230, 184, 77, 0.28); color: #ffe7a8; }
pre.stream-title mark.hl-destroy, .signals mark.hl-destroy { background: rgba(255, 93, 103, 0.32); color: #ffd0d3; }
pre.stream-title mark.hl-pipe, .signals mark.hl-pipe { background: rgba(255, 93, 103, 0.22); color: #ffd0d3; }
.stream-why {
  margin: 0.4rem 0 0; color: var(--muted); font-size: 0.82rem; line-height: 1.4;
}
.stream-body { padding: 0 1rem 1rem; border-top: 1px solid var(--line); }
.stream-body .command { margin-top: 0.75rem; max-height: none; overflow: visible; }
.stream-body .command[hidden] { display: none !important; }
.stream-body .intent { margin: 0.7rem 0 0; }
.stream-toolbar {
  display: flex; flex-wrap: wrap; gap: 0.5rem 0.85rem; align-items: center;
  margin: 0.75rem 0 0;
}
.stream-toolbar a { color: var(--muted); font-size: 0.82rem; text-decoration: none; border-bottom: 1px solid var(--line); }
.stream-toolbar a:hover { color: var(--accent); border-bottom-color: var(--accent); }
.beats { display: flex; flex-direction: column; gap: 0.65rem; margin-top: 0.85rem; }
.beat {
  background: var(--inset); border: 1px solid var(--line); border-radius: 8px;
  padding: 0.7rem 0.85rem;
}
.beat > h3 {
  margin: 0 0 0.45rem; font-size: 0.72rem; font-weight: 650; color: var(--faint);
  letter-spacing: 0.04em; text-transform: uppercase;
}
.beat-facts { display: flex; flex-wrap: wrap; gap: 0.4rem 1.05rem; margin: 0; padding: 0; }
.beat-facts > div { min-width: auto; }
.beat-facts dt { margin: 0; font-size: 0.68rem; color: var(--faint); }
.beat-facts dd { margin: 0.08rem 0 0; font-weight: 550; }
.signals, .extracts, .neighbors {
  list-style: none; margin: 0.5rem 0 0; padding: 0; display: flex; flex-direction: column; gap: 0.28rem;
}
.signals li, .extracts li { font-size: 0.82rem; line-height: 1.4; word-break: break-word; }
.extracts { flex-direction: row; flex-wrap: wrap; gap: 0.35rem; }
.extracts li {
  background: var(--card); border: 1px solid var(--line); border-radius: 6px;
  padding: 0.12rem 0.45rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem;
}
.neighbors a {
  color: var(--fg); text-decoration: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem; border-bottom: 1px solid transparent;
}
.neighbors a:hover { color: var(--accent); border-bottom-color: var(--accent); }
.inject-flag { color: var(--warning); font-size: 0.82rem; margin: 0.4rem 0 0; }
.stream-meta { display: flex; flex-wrap: wrap; gap: 0.35rem 0.75rem; margin: 0.65rem 0 0; }
.audit-stats {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(7.2rem, 1fr));
  gap: 0.5rem; margin: 0 0 1.15rem;
}
.audit-stat {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 0.65rem 0.8rem;
}
.audit-stat .n { display: block; font-size: 1.45rem; font-weight: 750; font-variant-numeric: tabular-nums; line-height: 1.1; }
.audit-stat .k { color: var(--faint); font-size: 0.72rem; }
.audit-stat[data-tone="allow"] .n { color: var(--ok); }
.audit-stat[data-tone="review"] .n { color: var(--warning); }
.audit-stat[data-tone="block"] .n { color: var(--critical); }
.audit-stat[data-tone="error"] .n { color: var(--muted); }
.tl-toolbar {
  display: flex; flex-wrap: wrap; gap: 0.65rem 1rem; align-items: center;
  margin: 0 0 0.85rem;
}
.tl-search {
  flex: 1 1 16rem; min-width: 12rem; max-width: 28rem;
  font: inherit; color: var(--fg); background: var(--inset);
  border: 1px solid var(--line); border-radius: 99px; padding: 0.45rem 0.95rem;
}
.tl-search:focus { outline: 2px solid var(--accent); outline-offset: 2px; }
.tl-group { margin: 0 0 1.35rem; }
.tl-group > h3 {
  margin: 0 0 0.55rem; font-size: 0.82rem; font-weight: 650; color: var(--muted);
  letter-spacing: 0.02em;
}
.res-pill { color: var(--fg); background: var(--inset); border-radius: 99px; padding: 0.05rem 0.45rem; font-size: 0.68rem; font-weight: 600; text-transform: none; letter-spacing: 0; }
.stream .command { padding: 0.55rem 0.7rem; font-size: 0.84rem; }
.table-wrap { overflow: auto; border: 1px solid var(--line); border-radius: var(--radius); background: var(--card); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--line); }
th { font-size: 0.72rem; color: var(--faint); font-weight: 650; }
tr:last-child td { border-bottom: 0; }
.sess-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.55rem; }
.sess-row {
  display: flex; flex-wrap: wrap; gap: 0.65rem 1rem;
  align-items: flex-start; justify-content: space-between;
  background: var(--inset); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 0.75rem 0.9rem;
}
.sess-id { flex: 1 1 14rem; min-width: 0; }
.sess-key {
  display: block;
  overflow-wrap: anywhere;
  word-break: break-all;
  font-size: 0.82rem;
}
.sess-meta { display: block; margin-top: 0.22rem; color: var(--faint); font-size: 0.78rem; }
.sess-meta code { font-size: inherit; overflow-wrap: anywhere; word-break: break-all; }
.sess-actions { flex: 0 1 auto; display: flex; flex-wrap: wrap; gap: 0.4rem; }
.sess-more { margin: 0.45rem 0 0; }
.sess-more > summary {
  cursor: pointer; list-style: none; color: var(--accent);
  font-size: 0.88rem; font-weight: 550; padding: 0.4rem 0.1rem;
}
.sess-more > summary::-webkit-details-marker { display: none; }
.sess-more > summary::before { content: "▸ "; color: var(--faint); }
.sess-more[open] > summary::before { content: "▾ "; }
.sess-more-open { display: none; }
.sess-more[open] > summary .sess-more-closed { display: none; }
.sess-more[open] > summary .sess-more-open { display: inline; }
.sess-more .sess-list { margin-top: 0.55rem; }
pre.lead { max-height: none; overflow: visible; margin: 0.2rem 0; background: var(--inset); padding: 0.5rem 0.6rem; border-radius: 8px; }
.row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; margin-top: 0.8rem; }
.allow-kinds {
  display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin: 0;
  padding: 0.85rem 1rem 1rem;
}
.kind-card {
  background: var(--inset); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 0.95rem 1.05rem;
}
.kind-card h3 {
  margin: 0 0 0.4rem; font-size: 0.78rem; font-weight: 650; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--accent);
}
.kind-card p { margin: 0; color: var(--muted); font-size: 0.88rem; line-height: 1.45; }
.help-fold {
  margin: 0 0 1.1rem;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: var(--radius);
}
.help-fold > summary {
  cursor: pointer;
  list-style: none;
  padding: 0.7rem 1rem;
  color: var(--muted);
  font-size: 0.88rem;
  font-weight: 550;
}
.help-fold > summary::-webkit-details-marker { display: none; }
.help-fold > summary::before { content: "▸ "; color: var(--faint); }
.help-fold[open] > summary::before { content: "▾ "; }
.help-fold[open] > summary { border-bottom: 1px solid var(--line); color: var(--fg); }
.allow-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.55rem; }
.allow-list li {
  display: flex; gap: 0.85rem; align-items: flex-start; justify-content: space-between;
  background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); padding: 0.85rem 1rem;
}
.allow-main { min-width: 0; }
.allow-kind {
  display: inline-block; margin: 0 0 0.3rem; padding: 0.05rem 0.45rem; border-radius: 99px;
  font-size: 0.68rem; font-weight: 650; letter-spacing: 0.05em; text-transform: uppercase;
  background: var(--accent-dim); color: var(--accent);
}
.allow-label { margin: 0; font-size: 0.92rem; word-break: break-word; }
.allow-meta { margin: 0.28rem 0 0; color: var(--faint); font-size: 0.78rem; }
.allow-list code { font-size: 0.85rem; }
.log-meta { color: var(--muted); }
.settings { display: flex; flex-direction: column; gap: 1rem; max-width: 72rem; }
.set-card {
  background: var(--card); border: 1px solid var(--line); border-radius: var(--radius);
  padding: 1.15rem 1.25rem;
}
.set-card h3 { margin: 0 0 0.35rem; font-size: 1.02rem; font-weight: 650; }
.set-card .lead { margin: 0 0 0.9rem; color: var(--muted); font-size: 0.9rem; line-height: 1.5; }
.set-card .lead:last-child { margin-bottom: 0; }
.seg { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.seg button[aria-pressed="true"] {
  background: var(--accent-dim); border-color: var(--accent); color: var(--fg);
}
.seg button:disabled {
  opacity: 0.5; cursor: not-allowed;
}
.seg button:disabled:hover {
  border-color: var(--line); background: var(--elev);
}
.seg button:disabled[aria-pressed="true"]:hover {
  background: var(--accent-dim); border-color: var(--accent);
}
.seg button:disabled[aria-pressed="true"] {
  background: var(--accent-dim); border-color: var(--accent);
}
.seg-floor { gap: 0.45rem; }
.seg-floor button {
  min-width: 5.4rem;
  font-weight: 650;
  letter-spacing: 0.02em;
}
.seg-floor button.floor-strict { color: var(--ok); border-color: rgba(125, 186, 125, 0.45); }
.seg-floor button.floor-info { color: #d4de6a; border-color: rgba(212, 222, 106, 0.4); }
.seg-floor button.floor-warning { color: var(--warning); border-color: rgba(230, 184, 77, 0.45); }
.seg-floor button.floor-critical { color: var(--critical); border-color: rgba(255, 93, 103, 0.45); }
.seg-floor button.floor-strict:hover { background: rgba(125, 186, 125, 0.12); border-color: var(--ok); }
.seg-floor button.floor-info:hover { background: rgba(212, 222, 106, 0.12); border-color: #d4de6a; }
.seg-floor button.floor-warning:hover { background: var(--warning-bg); border-color: var(--warning); }
.seg-floor button.floor-critical:hover { background: var(--critical-bg); border-color: var(--critical); }
.seg-floor button.floor-covered {
  opacity: 0.95;
}
.seg-floor button.floor-strict.floor-on,
.seg-floor button.floor-strict.floor-covered {
  background: rgba(125, 186, 125, 0.22); border-color: var(--ok); color: #d7efd7;
}
.seg-floor button.floor-info.floor-on,
.seg-floor button.floor-info.floor-covered {
  background: rgba(212, 222, 106, 0.2); border-color: #d4de6a; color: #eef3b5;
}
.seg-floor button.floor-warning.floor-on,
.seg-floor button.floor-warning.floor-covered {
  background: var(--warning-bg); border-color: var(--warning); color: #f3d98a;
}
.seg-floor button.floor-critical.floor-on,
.seg-floor button.floor-critical.floor-covered {
  background: var(--critical-bg); border-color: var(--critical); color: #ffc1c5;
}
.seg-floor button.floor-on { box-shadow: inset 0 0 0 1px currentColor; font-weight: 750; }
.floor-hint {
  margin: 0.8rem 0 0; padding: 0.7rem 0.85rem;
  background: var(--inset); border: 1px solid var(--line); border-radius: 8px;
  color: var(--muted); font-size: 0.88rem; line-height: 1.5;
}
.floor-hint.floor-strict { border-left: 3px solid var(--ok); }
.floor-hint.floor-info { border-left: 3px solid #d4de6a; }
.floor-hint.floor-warning { border-left: 3px solid var(--warning); }
.floor-hint.floor-critical { border-left: 3px solid var(--critical); }
.set-fields { display: flex; flex-wrap: wrap; gap: 0.85rem 1.1rem; align-items: end; }
.field { display: flex; flex-direction: column; gap: 0.28rem; }
.field span { font-size: 0.72rem; color: var(--faint); font-weight: 650; }
.field input {
  width: 7.5rem; font: inherit; color: var(--fg); background: var(--inset);
  border: 1px solid var(--line); border-radius: 8px; padding: 0.35rem 0.55rem;
}
.set-warn { color: var(--warning); }
.set-danger { color: var(--critical); }
#set-sessions { scroll-margin-top: 0.75rem; }
@media (max-width: 720px) {
  .hero { grid-template-columns: 1fr; }
  .hero-risk { text-align: left; }
  .risk-row { justify-content: flex-start; }
  .btn-deny { margin-left: 0; }
  .allow-kinds { grid-template-columns: 1fr; }
}
`;

const DASHBOARD_JS = `
(function () {
  try {
    if (window.parent !== window) document.body.classList.add("in-frame");
  } catch {
    document.body.classList.add("in-frame");
  }
  const panelUrl = document.querySelector("[data-panel-url]");
  if (panelUrl instanceof HTMLInputElement) {
    panelUrl.value = location.href;
    panelUrl.addEventListener("focus", () => panelUrl.select());
    panelUrl.addEventListener("click", () => panelUrl.select());
  }
  const TABS = ["reviews", "timeline", "allowlist", "settings"];
  const TAB_ALIAS = { sessions: "settings", log: "settings", configure: "settings", "set-sessions": "settings" };
  const SCROLL_STORE = "sentrook-page-scroll";
  const FLASH_STORE = "sentrook-flash";
  const GATEWAY_TAB_WRITE_HINT = ${JSON.stringify(GATEWAY_TAB_WRITE_HINT)};
  let flashTimer;

  function flashNode() {
    return document.getElementById("flash");
  }

  function applyFlash(text, kind) {
    const el = flashNode();
    if (!el) return;
    el.textContent = text || "";
    el.className = kind === "error" ? "flash-error" : kind === "ok" ? "flash-ok" : "";
    if (flashTimer) clearTimeout(flashTimer);
    if (!text) return;
    flashTimer = setTimeout(() => {
      el.textContent = "";
      el.className = "";
    }, kind === "error" ? 14000 : 5000);
  }

  function flash(m, kind) {
    applyFlash(String(m || ""), kind);
  }

  function restoreFlash() {
    try {
      const raw = sessionStorage.getItem(FLASH_STORE);
      if (!raw) return;
      sessionStorage.removeItem(FLASH_STORE);
      const saved = JSON.parse(raw);
      if (saved && saved.text) applyFlash(saved.text, saved.kind);
    } catch {
      /* ignore bad store */
    }
  }

  function pageEl() {
    const page = document.querySelector(".page");
    return page instanceof HTMLElement ? page : null;
  }

  let savedScroll = null;

  function savePageScroll() {
    const page = pageEl();
    if (!page) return;
    savedScroll = { hash: location.hash, top: page.scrollTop };
    try {
      sessionStorage.setItem(SCROLL_STORE, JSON.stringify(savedScroll));
    } catch {
      /* private mode / iframe */
    }
  }

  function restorePageScroll() {
    let saved = savedScroll;
    savedScroll = null;
    try {
      const raw = sessionStorage.getItem(SCROLL_STORE);
      if (raw) {
        sessionStorage.removeItem(SCROLL_STORE);
        if (!saved) saved = JSON.parse(raw);
      }
    } catch {
      /* ignore bad store */
    }
    if (!saved || saved.hash !== location.hash) return false;
    if (location.hash === "#set-sessions") return false;
    const page = pageEl();
    const top = Number(saved.top);
    if (page && Number.isFinite(top)) {
      page.scrollTop = top;
      return true;
    }
    return false;
  }

  function errorField(value, fallback) {
    if (typeof value === "string" && value.trim()) return value.trim();
    if (value && typeof value === "object" && typeof value.message === "string" && value.message.trim()) {
      return value.message.trim();
    }
    return fallback || "";
  }

  function errorFromResponse(data, res) {
    if (res.status === 401 || res.status === 403) {
      if (data && typeof data.error === "string" && data.error.trim()) return data.error.trim();
      return GATEWAY_TAB_WRITE_HINT;
    }
    return errorField(data && data.error, errorField(data && data.message, res.statusText || ("HTTP " + res.status)));
  }

  function escText(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function reloadAfter(data) {
    if (data && data.persisted === false) {
      applyFlash(errorField(data.error, "Applied now, but not saved to openclaw.json."), "error");
    } else {
      applyFlash("Saved", "ok");
    }
  }

  function setPressed(clicked, selector) {
    if (!(clicked instanceof HTMLElement)) return;
    const group = clicked.closest("[role='group']") || clicked.parentElement || document;
    group.querySelectorAll(selector).forEach((btn) => {
      btn.setAttribute("aria-pressed", btn === clicked ? "true" : "false");
    });
  }

  function resolveTab(id) {
    return TAB_ALIAS[id] || id;
  }

  function scrollPageTo(el) {
    const page = document.querySelector(".page");
    if (!(el instanceof HTMLElement)) return;
    if (page instanceof HTMLElement) {
      const br = el.getBoundingClientRect();
      const pr = page.getBoundingClientRect();
      page.scrollTop += br.top - pr.top - 24;
    } else {
      el.scrollIntoView({ block: "start" });
    }
  }

  function showTab(rawId, opts) {
    const id = resolveTab(rawId);
    if (!TABS.includes(id)) return;
    document.querySelectorAll("[data-panel]").forEach((p) => {
      p.hidden = p.getAttribute("data-panel") !== id;
    });
    document.querySelectorAll("[data-tab]").forEach((t) => {
      t.setAttribute("aria-current", t.getAttribute("data-tab") === id ? "page" : "false");
    });
    const url = new URL(location.href);
    if (id !== "timeline") {
      url.searchParams.delete("session");
      url.searchParams.delete("decision");
      url.searchParams.delete("q");
      url.searchParams.delete("view");
    }
    url.hash = id;
    history.replaceState(null, "", url);
    if (id === "timeline") applyTimelineFilters();
    const page = document.querySelector(".page");
    if (page instanceof HTMLElement && !opts?.keepScroll) {
      page.scrollTop = 0;
    }
  }

  function timelineItems(panel) {
    return [...panel.querySelectorAll("[data-tl-item]")].filter((el) => el instanceof HTMLElement);
  }

  function writeTimelineUrl(panel) {
    const url = new URL(location.href);
    const session = panel.getAttribute("data-filter-session") || "";
    const decision = panel.getAttribute("data-filter-decision") || "";
    const q = (panel.getAttribute("data-filter-q") || "").trim();
    const view = panel.getAttribute("data-filter-view") || "stream";
    if (session) url.searchParams.set("session", session); else url.searchParams.delete("session");
    if (decision) url.searchParams.set("decision", decision); else url.searchParams.delete("decision");
    if (q) url.searchParams.set("q", q); else url.searchParams.delete("q");
    if (view === "session") url.searchParams.set("view", "session"); else url.searchParams.delete("view");
    url.hash = "timeline";
    history.replaceState(null, "", url);
  }

  function syncTimelineFromUrl(panel) {
    const url = new URL(location.href);
    const session = url.searchParams.get("session") || panel.getAttribute("data-filter-session") || "";
    const decision = url.searchParams.get("decision") || panel.getAttribute("data-filter-decision") || "";
    const q = url.searchParams.get("q") ?? panel.getAttribute("data-filter-q") ?? "";
    const view = url.searchParams.get("view") === "session" || panel.getAttribute("data-filter-view") === "session"
      ? "session" : "stream";
    panel.setAttribute("data-filter-session", session);
    panel.setAttribute("data-filter-decision", decision);
    panel.setAttribute("data-filter-q", q);
    panel.setAttribute("data-filter-view", view);
    const search = panel.querySelector("[data-tl-search]");
    if (search instanceof HTMLInputElement && search.value !== q) search.value = q;
  }

  function applyTimelineLayout(panel) {
    const view = panel.getAttribute("data-filter-view") || "stream";
    const list = panel.querySelector("[data-tl-list]");
    const grouped = panel.querySelector("[data-tl-grouped]");
    if (!(list instanceof HTMLElement) || !(grouped instanceof HTMLElement)) return;
    const items = timelineItems(panel).sort((a, b) => Number(a.getAttribute("data-i")) - Number(b.getAttribute("data-i")));
    if (view !== "session") {
      items.forEach((el) => list.appendChild(el));
      grouped.replaceChildren();
      grouped.hidden = true;
      list.hidden = false;
      return;
    }
    const order = [];
    const map = new Map();
    for (const el of items) {
      const key = el.getAttribute("data-session") || "No session";
      if (!map.has(key)) {
        map.set(key, []);
        order.push(key);
      }
      map.get(key).push(el);
    }
    grouped.replaceChildren();
    for (const key of order) {
      const sec = document.createElement("section");
      sec.className = "tl-group";
      const h = document.createElement("h3");
      h.textContent = key;
      const ol = document.createElement("div");
      ol.className = "stream";
      const els = map.get(key) || [];
      for (const el of els) ol.appendChild(el);
      sec.appendChild(h);
      sec.appendChild(ol);
      sec.hidden = !els.some((el) => !el.hidden);
      grouped.appendChild(sec);
    }
    list.hidden = true;
    grouped.hidden = false;
  }

  function applyTimelineFilters() {
    const panel = document.querySelector('[data-panel="timeline"]');
    if (!(panel instanceof HTMLElement)) return;
    syncTimelineFromUrl(panel);
    const decision = panel.getAttribute("data-filter-decision") || "";
    const session = panel.getAttribute("data-filter-session") || "";
    const q = (panel.getAttribute("data-filter-q") || "").trim().toLowerCase();
    const view = panel.getAttribute("data-filter-view") || "stream";
    let visible = 0;
    const items = timelineItems(panel);
    items.forEach((el) => {
      const okD = !decision || el.getAttribute("data-tone") === decision;
      const okS = !session || el.getAttribute("data-session") === session;
      const blob = (el.getAttribute("data-tl-blob") || "").toLowerCase();
      const okQ = !q || blob.includes(q);
      el.hidden = !(okD && okS && okQ);
      if (!el.hidden) visible += 1;
    });
    applyTimelineLayout(panel);
    panel.querySelectorAll("[data-tl-decision]").forEach((b) => {
      b.setAttribute("aria-pressed", b.getAttribute("data-tl-decision") === decision ? "true" : "false");
    });
    panel.querySelectorAll("[data-tl-session-filter]").forEach((b) => {
      b.setAttribute("aria-pressed", (b.getAttribute("data-tl-session-filter") || "") === session ? "true" : "false");
    });
    panel.querySelectorAll("[data-tl-view]").forEach((b) => {
      b.setAttribute("aria-pressed", b.getAttribute("data-tl-view") === view ? "true" : "false");
    });
    const empty = panel.querySelector("[data-tl-empty]");
    if (empty instanceof HTMLElement) empty.hidden = visible > 0;
    const count = panel.querySelector("[data-tl-count]");
    if (count instanceof HTMLElement) {
      count.textContent = items.length
        ? (visible === items.length
          ? "Newest " + items.length + " scans"
          : "Showing " + visible + " of " + items.length + " newest")
        : "";
    }
  }

  function openTimelineSession(key) {
    const url = new URL(location.href);
    if (key) url.searchParams.set("session", key);
    else url.searchParams.delete("session");
    url.searchParams.delete("q");
    url.hash = "timeline";
    const panel = document.querySelector('[data-panel="timeline"]');
    if (panel instanceof HTMLElement) {
      panel.setAttribute("data-filter-session", key || "");
      panel.setAttribute("data-filter-decision", "");
      panel.setAttribute("data-filter-q", "");
      const search = panel.querySelector("[data-tl-search]");
      if (search instanceof HTMLInputElement) search.value = "";
    }
    history.replaceState(null, "", url);
    showTab("timeline");
  }

  function fmtAge(fromMs) {
    const sec = Math.max(0, Math.round((Date.now() - fromMs) / 1000));
    if (sec < 60) return sec + "s ago";
    const min = Math.round(sec / 60);
    if (min < 60) return min + "m ago";
    return Math.round(min / 60) + "h ago";
  }
  function fmtRemain(created, timeout) {
    const left = created + timeout - Date.now();
    if (left <= 0) return "timed out";
    const sec = Math.round(left / 1000);
    if (sec < 60) return sec + "s left";
    const min = Math.floor(sec / 60);
    return min + "m " + (sec % 60) + "s left";
  }
  function tickClocks() {
    document.querySelectorAll("article.review[data-created]").forEach((el) => {
      const created = Number(el.getAttribute("data-created"));
      const timeout = Number(el.getAttribute("data-timeout") || "0");
      const age = el.querySelector(".age");
      const remain = el.querySelector(".remain");
      if (age) age.textContent = fmtAge(created);
      if (remain && timeout) remain.textContent = fmtRemain(created, timeout);
    });
  }

  let ACCESS = (document.body.getAttribute("data-access") || new URLSearchParams(location.search).get(${JSON.stringify(ACCESS_QUERY)}) || "").trim();
  const TAB_PREFIX = ${JSON.stringify(DASHBOARD_TAB_PREFIX)};

  function apiUrl() {
    return ACCESS ? TAB_PREFIX + encodeURIComponent(ACCESS) : "/sentrook";
  }

  async function post(srk, body) {
    const res = await fetch(apiUrl(), {
      method: "POST",
      credentials: "omit",
      headers: { "content-type": "text/plain" },
      body: JSON.stringify({ _srk: srk, _tok: ACCESS, ...(body || {}) }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(errorFromResponse(data, res));
    return data;
  }

  async function postAndReload(path, body) {
    await reloadAfter(await post(path, body));
  }

  function askConfirm(message) {
    return new Promise((resolve) => {
      const box = document.getElementById("confirm");
      const msg = document.getElementById("confirm-msg");
      if (!(box instanceof HTMLElement) || !(msg instanceof HTMLElement)) {
        resolve(true);
        return;
      }
      msg.textContent = message;
      box.hidden = false;
      const done = (ok) => {
        box.hidden = true;
        box.removeEventListener("click", onClick, true);
        resolve(ok);
      };
      function onClick(e) {
        const el = e.target;
        if (!(el instanceof HTMLElement)) return;
        if (el.closest("[data-confirm-ok]")) { e.preventDefault(); e.stopPropagation(); done(true); }
        else if (el.closest("[data-confirm-cancel]")) { e.preventDefault(); e.stopPropagation(); done(false); }
      }
      box.addEventListener("click", onClick, true);
    });
  }

  async function resolveCard(btn, decision) {
    const card = btn.closest("article.review");
    if (decision === "allow-always" && card && card.getAttribute("data-severity") === "critical") {
      if (!(await askConfirm("Allow always on a critical review? Only confirm if you trust this pattern."))) return;
    }
    await post("resolve", { toolCallId: btn.getAttribute("data-tool"), decision: decision });
    card?.remove();
    applyFlash("Resolved " + decision, "ok");
  }

  document.addEventListener("click", async (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.id === "flash") {
      applyFlash("", "");
      return;
    }
    if (t.closest("#confirm")) return;
    try {
      const tab = t.closest("[data-tab]");
      if (tab instanceof HTMLElement && tab.dataset.tab) {
        e.preventDefault();
        showTab(tab.dataset.tab);
        return;
      }
      const openSess = t.closest("[data-tl-open-session]");
      if (openSess instanceof HTMLElement) {
        e.preventDefault();
        openTimelineSession(openSess.getAttribute("data-tl-open-session") || "");
        return;
      }
      if (t.dataset.tlDecision != null) {
        const panel = document.querySelector('[data-panel="timeline"]');
        if (panel instanceof HTMLElement) {
          panel.setAttribute("data-filter-decision", t.dataset.tlDecision);
          writeTimelineUrl(panel);
          applyTimelineFilters();
        }
        return;
      }
      if (t.dataset.tlView != null) {
        const panel = document.querySelector('[data-panel="timeline"]');
        if (panel instanceof HTMLElement) {
          panel.setAttribute("data-filter-view", t.dataset.tlView);
          writeTimelineUrl(panel);
          applyTimelineFilters();
        }
        return;
      }
      if (t.dataset.tlSessionFilter != null) {
        const key = t.dataset.tlSessionFilter;
        const panel = document.querySelector('[data-panel="timeline"]');
        if (panel instanceof HTMLElement) panel.setAttribute("data-filter-session", key);
        if (panel instanceof HTMLElement) writeTimelineUrl(panel);
        applyTimelineFilters();
        return;
      }
      if (t.dataset.copyTarget) {
        const src = document.getElementById(t.dataset.copyTarget);
        const text = src ? src.textContent || "" : "";
        await navigator.clipboard.writeText(text);
        const prev = t.textContent;
        t.textContent = "Copied";
        setTimeout(() => { t.textContent = prev; }, 1200);
        return;
      }
      if (t.dataset.act && t.dataset.tool) {
        await resolveCard(t, t.dataset.act);
      } else if (t.closest("[data-allow-mode]")) {
        const modeBtn = t.closest("[data-allow-mode]");
        const mode = modeBtn instanceof HTMLElement ? modeBtn.dataset.allowMode : "";
        if (mode !== "off" && mode !== "on") return;
        await postAndReload("policy", { allowAllMode: mode });
        setPressed(modeBtn, "[data-allow-mode]");
      } else if (t.dataset.quietGlobal) {
        await postAndReload("policy", { globalQuiet: t.dataset.quietGlobal });
        setPressed(t, "[data-quiet-global]");
      } else if (t.dataset.policy) {
        await postAndReload("policy", {
          sessionId: t.dataset.sid, sessionKey: t.dataset.skey,
          allowAll: t.dataset.policy === "allow-all" ? t.dataset.on === "1" : undefined,
          quiet: t.dataset.policy === "quiet" ? (t.dataset.on === "1" ? "30m" : "off") : undefined,
        });
      } else if (t.dataset.sens) {
        const scope = t.dataset.sensScope === "unattended" ? "unattended" : "attended";
        if (t.dataset.sens === "critical") {
          const msg = scope === "unattended"
            ? "Auto-approve every review on cron and subagent runs, including critical? Nobody will be asked. Blocks and scan errors still stop. This persists in openclaw.json."
            : "Auto-approve every review, including critical ones? Blocks, scan errors, and the unattended floor are separate. This persists in openclaw.json (unlike allow-all).";
          if (!(await askConfirm(msg))) return;
        }
        const body = scope === "unattended"
          ? { unattendedSensitivity: t.dataset.sens }
          : { sensitivity: t.dataset.sens };
        await postAndReload("policy", body);
        setPressed(t, t.dataset.sensScope === "unattended" ? "[data-sens-scope='unattended']" : "[data-sens]:not([data-sens-scope='unattended'])");
      } else if (t.dataset.feedback) {
        await postAndReload("policy", { feedbackMode: t.dataset.feedback });
        setPressed(t, "[data-feedback]");
      } else if (t.dataset.scanError) {
        if (t.dataset.scanError === "allow") {
          if (!(await askConfirm("Continue tool calls without scanning when Sentrook is unreachable? Auth failures still block."))) return;
        }
        await postAndReload("policy", { onScanError: t.dataset.scanError });
        setPressed(t, "[data-scan-error]");
      } else if (t.dataset.log === "save") {
        const daysEl = document.querySelector("[data-log-days]");
        const mibEl = document.querySelector("[data-log-mib]");
        const maxAgeDays = daysEl instanceof HTMLInputElement ? Number(daysEl.value) : undefined;
        const mib = mibEl instanceof HTMLInputElement ? Number(mibEl.value) : undefined;
        await postAndReload("log", {
          maxAgeDays,
          maxBytes: Number.isFinite(mib) ? Math.round(mib * 1024 * 1024) : undefined,
        });
      } else if (t.dataset.log === "purge") {
        if (!(await askConfirm("Drop operator-log lines older than the retention window? This cannot be undone."))) return;
        await postAndReload("log", { purge: "confirm" });
      } else if (t.dataset.log === "wipe") {
        if (!(await askConfirm("Delete the entire local operator log, including the rotated copy? Timeline will go empty. This cannot be undone."))) return;
        await postAndReload("log", { wipe: "confirm" });
      } else if (t.dataset.allowRm) {
        const row = t.closest("li");
        await post("allowlist/rm", { index: Number(t.dataset.allowRm) });
        row?.remove();
        applyFlash("Removed from allowlist", "ok");
      } else if (t.dataset.setupFeedback) {
        const group = t.closest("[data-setup-feedback-group]");
        if (group) {
          group.querySelectorAll("[data-setup-feedback]").forEach((btn) => {
            btn.setAttribute("aria-pressed", btn === t ? "true" : "false");
          });
        }
      } else if (t.dataset.setupScanError) {
        if (t.dataset.setupScanError === "allow") {
          if (!(await askConfirm("Continue tool calls without scanning when Sentrook is unreachable? Auth failures still block."))) return;
        }
        const group = t.closest("[data-setup-scan-error-group]");
        if (group) {
          group.querySelectorAll("[data-setup-scan-error]").forEach((btn) => {
            btn.setAttribute("aria-pressed", btn === t ? "true" : "false");
          });
        }
      } else if (t.dataset.setupSave) {
        const idEl = document.querySelector("[data-setup-client-id]");
        const secretEl = document.querySelector("[data-setup-client-secret]");
        const feedbackBtn = document.querySelector("[data-setup-feedback][aria-pressed='true']");
        const scanBtn = document.querySelector("[data-setup-scan-error][aria-pressed='true']");
        const clientId = idEl instanceof HTMLInputElement ? idEl.value : "";
        const clientSecret = secretEl instanceof HTMLInputElement ? secretEl.value : "";
        const data = await post("setup", {
          clientId,
          clientSecret,
          feedbackMode: feedbackBtn instanceof HTMLElement ? feedbackBtn.dataset.setupFeedback : "submit",
          onScanError: scanBtn instanceof HTMLElement ? scanBtn.dataset.setupScanError : "review",
        });
        const panel = document.querySelector('[data-panel="reviews"]');
        if (panel instanceof HTMLElement) {
          panel.innerHTML = "<div class='section-head'><h2>Identity saved</h2><p>Reload Control UI, or paste this panel URL in a normal browser tab, to load reviews.</p></div>";
        }
        applyFlash(
          data.restartHint
            ? "Identity accepted this client. Restart the gateway so scans pick up the new credentials."
            : "Identity accepted this client. Tool calls can scan without a restart in the usual case.",
          "ok",
        );
      } else if (t.dataset.verify) {
        const box = document.querySelector("[data-verify-result]");
        const data = await post("verify", {});
        if (box instanceof HTMLElement) {
          const checks = Array.isArray(data.checks) ? data.checks : [];
          box.hidden = false;
          box.innerHTML = "<ul>" + checks.map((c) => {
            const name = escText(c && c.name);
            const detail = escText(c && c.detail);
            return "<li class='" + (c && c.ok ? "ok" : "fail") + "'>" + (c && c.ok ? "Pass" : "Fail") + " · " + name + " — " + detail + "</li>";
          }).join("") + "</ul>";
        }
        if (data.ok) flash("Connection checks passed.", "ok");
        else flash("Connection checks failed. See the list below.", "error");
      }
    } catch (err) {
      flash(String(err.message || err), "error");
    }
  });

  document.addEventListener("input", (e) => {
    const t = e.target;
    if (!(t instanceof HTMLInputElement)) return;
    const panel = document.querySelector('[data-panel="timeline"]');
    if (!(panel instanceof HTMLElement)) return;
    if (t.dataset.tlSearch != null) {
      panel.setAttribute("data-filter-q", t.value);
      writeTimelineUrl(panel);
      applyTimelineFilters();
    }
  });

  function openHashTarget() {
    const id = location.hash.replace("#", "");
    if (!id || TABS.includes(id) || id === "sessions" || id === "log" || id === "configure" || id === "set-sessions") return;
    const el = document.getElementById(id);
    if (el instanceof HTMLDetailsElement) {
      showTab("timeline");
      el.open = true;
      persistOpenDetails();
      const page = document.querySelector(".page");
      if (page instanceof HTMLElement) {
        const br = el.getBoundingClientRect();
        const pr = page.getBoundingClientRect();
        page.scrollTop += br.top - pr.top - 24;
      } else {
        el.scrollIntoView({ block: "start" });
      }
      return;
    }
    el?.scrollIntoView({ block: "start" });
  }

  window.addEventListener("hashchange", () => {
    const id = location.hash.replace("#", "");
    if (TABS.includes(resolveTab(id))) showTab(id);
    else openHashTarget();
  });
  const initial = location.hash.replace("#", "");
  const keepScroll = (() => {
    try {
      const raw = sessionStorage.getItem(SCROLL_STORE);
      if (!raw) return false;
      const saved = JSON.parse(raw);
      return Boolean(saved && saved.hash === location.hash && location.hash !== "#set-sessions");
    } catch {
      return false;
    }
  })();
  if (TABS.includes(resolveTab(initial))) showTab(initial, { keepScroll });
  else if (!initial) showTab("reviews");
  else if (initial.startsWith("tl-")) showTab("timeline", { keepScroll });
  else document.getElementById(initial)?.scrollIntoView({ block: "start" });
  applyTimelineFilters();
  restoreOpenDetails();
  openHashTarget();
  restorePageScroll();
  restoreFlash();
  tickClocks();
  setInterval(tickClocks, 1000);

  const OPEN_STORE = "sentrook-open-details";

  function detailsOpenKey(el) {
    if (el.id) return el.id;
    const root = el.closest("[id]");
    const summary = el.querySelector(":scope > summary");
    const label = (summary ? summary.textContent : "").trim().replace(/\s+/g, " ").slice(0, 100);
    return (root && root.id ? root.id : "anon") + "::" + label;
  }

  function persistOpenDetails() {
    try {
      const keys = [...document.querySelectorAll("details[open]")].map(detailsOpenKey);
      sessionStorage.setItem(OPEN_STORE, JSON.stringify(keys));
    } catch {
      /* private mode / iframe */
    }
  }

  function restoreOpenDetails() {
    try {
      const raw = sessionStorage.getItem(OPEN_STORE);
      if (!raw) return;
      const keys = JSON.parse(raw);
      if (!Array.isArray(keys)) return;
      const want = new Set(keys);
      document.querySelectorAll("details").forEach((el) => {
        if (el instanceof HTMLDetailsElement && want.has(detailsOpenKey(el))) el.open = true;
      });
    } catch {
      /* ignore bad store */
    }
  }

  document.addEventListener("toggle", (e) => {
    if (e.target instanceof HTMLDetailsElement) persistOpenDetails();
  }, true);
  window.addEventListener("beforeunload", () => {
    persistOpenDetails();
    savePageScroll();
  });

  window.addEventListener("keydown", (e) => {
    const reloadKey = e.key === "F5" || ((e.metaKey || e.ctrlKey) && (e.key === "r" || e.key === "R"));
    if (!reloadKey) return;
    e.preventDefault();
    e.stopPropagation();
  }, true);
})();
`;

function clipText(value: string, max: number): string {
  const one = value.replace(/\s+/g, " ").trim();
  return one.length <= max ? one : `${one.slice(0, max - 1)}…`;
}

function intentKindChip(kind: string | null | undefined): string {
  const k = (kind ?? "").trim().toLowerCase();
  if (!k || k === "user") return "";
  const label = k === "cron" ? "Cron" : k === "subagent" ? "Subagent" : k === "system" ? "System" : k;
  return ` <span class="kind kind-${escapeHtml(k)}">${escapeHtml(label)}</span>`;
}

function decisionTone(decision: string): "allow" | "review" | "block" | "error" {
  if (decision.startsWith("error")) return "error";
  if (decision === "block") return "block";
  if (decision === "review") return "review";
  return "allow";
}

function decisionLabel(decision: string): { pill: string; detail: string } {
  if (decision.startsWith("error:")) {
    const kind = decision.slice("error:".length).replace(/_/g, " ").trim();
    const detail = kind ? kind.charAt(0).toUpperCase() + kind.slice(1) : "";
    return { pill: "error", detail };
  }
  return { pill: decision, detail: "" };
}

function resolutionLabel(raw: string | undefined): string {
  if (!raw) return "";
  switch (raw) {
    case "allow-once":
      return "Allowed once";
    case "allow-always":
      return "Allowed always";
    case "deny":
      return "Denied";
    case "timeout":
      return "Timed out (denied)";
    case "allow-all-skip":
      return "Skipped (allow-all)";
    case "quiet-skip":
      return "Skipped (quiet)";
    case "lenient-skip":
      return "Skipped (lenient)";
    case "allowlist-hit":
      return "Allowlisted";
    case "cancelled":
      return "Cancelled";
    default:
      return raw.replace(/-/g, " ");
  }
}

const MONTH_SHORT = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function sameCalendarDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

function fmtClock(d: Date, withSeconds: boolean): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return withSeconds ? `${hm}:${pad(d.getSeconds())}` : hm;
}

function fmtWhen(iso: string, now: number): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const d = new Date(t);
  const n = new Date(now);
  if (sameCalendarDay(d, n)) return fmtClock(d, true);
  const yest = new Date(now);
  yest.setDate(yest.getDate() - 1);
  if (sameCalendarDay(d, yest)) return `Yesterday ${fmtClock(d, false)}`;
  const day = `${d.getDate()} ${MONTH_SHORT[d.getMonth()]}`;
  const year = d.getFullYear() !== n.getFullYear() ? ` ${d.getFullYear()}` : "";
  return `${day}${year} ${fmtClock(d, false)}`;
}

function resultGlance(row: DashboardViewState["history"][number]): string {
  if (row.resultOk === true) return `<span class="spine-ok">ok</span>`;
  if (row.resultOk === false) return `<span class="spine-fail">failed</span>`;
  if (decisionTone(row.decision) === "block") return `<span class="stream-when">not run</span>`;
  return "";
}

function glanceWhy(
  tone: "allow" | "review" | "block" | "error",
  summary: string,
  meanings: string[],
): string {
  if (tone === "allow") return "";
  const text = summary || meanings[0] || "";
  if (!text) return "";
  return `<p class="stream-why">${escapeHtml(clipText(text, 140))}</p>`;
}

function sourceLabel(raw: string | undefined): string {
  switch ((raw ?? "").trim().toLowerCase()) {
    case "allowlist":
      return "Allowlist";
    case "quiet":
      return "Quiet";
    case "lenient":
      return "Lenient";
    case "allow-all":
      return "Allow-all";
    case "timeout":
      return "Timeout";
    case "human":
      return "You";
    case "scanner":
      return "Scanner";
    default:
      return raw ? raw.replace(/-/g, " ") : "";
  }
}

function resolvedBy(row: DashboardViewState["history"][number]): string {
  if (row.resolutionSource) return sourceLabel(row.resolutionSource);
  switch (row.resolution) {
    case "allow-once":
    case "allow-always":
    case "deny":
    case "cancelled":
      return "You";
    case "timeout":
      return "Timeout";
    case "allowlist-hit":
      return "Allowlist";
    case "quiet-skip":
      return "Quiet";
    case "lenient-skip":
      return "Lenient";
    case "allow-all-skip":
      return "Allow-all";
    default:
      return sourceLabel(row.labelSource);
  }
}

function fmtSpan(fromIso: string, toIso: string): string {
  const a = Date.parse(fromIso);
  const b = Date.parse(toIso);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return "";
  const sec = Math.round((b - a) / 1000);
  if (sec < 1) return "immediately";
  if (sec < 60) return `${sec}s later`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m later`;
  return `${Math.round(min / 60)}h later`;
}

function fact(label: string, value: string): string {
  if (!value) return "";
  return `<div><dt>${escapeHtml(label)}</dt><dd>${value}</dd></div>`;
}

function extraArgsForRow(args: Record<string, unknown> | undefined, command: string): string | null {
  const extra = extraArgsJson(args, command);
  if (!extra) return null;
  const compactExtra = extra.replace(/\s+/g, "");
  const compactCmd = formatCommand(command).replace(/\s+/g, "");
  if (compactExtra === compactCmd) return null;
  return extra;
}

function renderTimelineBeats(row: DashboardViewState["history"][number]): string {
  const tone = decisionTone(row.decision);
  const meanings = ruleMeanings(row.matched_rules, row.winningRule);
  const summary = operatorSummary(row.summary ?? undefined);
  const signals = commandSignals(row.command);
  const sev =
    row.reviewSeverity ||
    (tone === "block" ? "critical" : tone === "review" ? "warning" : tone === "error" ? "warning" : "info");
  const risk = riskScore(row.risk);
  const skip = sourceLabel(row.skipReason || (row.resolution === "allowlist-hit" ? "allowlist" : row.labelSource));
  const scannedAs =
    row.hostTool && row.hostTool !== row.tool
      ? `${escapeHtml(row.hostTool)} → ${escapeHtml(row.tool)}`
      : "";
  const errBits = [
    row.errorKind ? escapeHtml(row.errorKind) : "",
    row.errorStatus != null ? `HTTP ${row.errorStatus}` : "",
    row.errorDetail ? escapeHtml(row.errorDetail) : "",
  ]
    .filter(Boolean)
    .join(" · ");
  const signalList = signals.length
    ? `<ul class="signals">${signals
        .map(
          (sig) =>
            `<li><span class="stream-when">${escapeHtml(sig.title)}</span> ${highlightCommandHtml(sig.text)}</li>`,
        )
        .join("")}</ul>`
    : "";
  const policy =
    meanings.length > 0
      ? `<ul class="chips">${meanings.map((label) => `<li>${escapeHtml(label)}</li>`).join("")}</ul>`
      : "";
  const whyText =
    row.blockReason && operatorSummary(row.blockReason) !== summary
      ? operatorSummary(row.blockReason)
      : summary;
  const scanFacts = [
    fact("Severity", escapeHtml(sev)),
    risk ? fact("Risk", `${risk.label} / 100`) : "",
    scannedAs ? fact("Tool", scannedAs) : "",
    skip ? fact("Source", escapeHtml(skip)) : "",
    errBits ? fact("Error", errBits) : "",
  ]
    .filter(Boolean)
    .join("");
  const scanBeat = `<section class="beat">
      <h3>Scan</h3>
      ${scanFacts ? `<dl class="beat-facts">${scanFacts}</dl>` : ""}
      ${policy}
      ${signalList}
      ${whyText && whyText !== meanings[0] ? `<p class="hint" style="margin:0.45rem 0 0">${escapeHtml(whyText)}</p>` : ""}
    </section>`;

  const resolved = resolutionLabel(row.resolution);
  const implicit =
    !resolved && tone === "block" ? "Blocked" : !resolved && tone === "error" ? "Scan failed" : "";
  const outcome = resolved || implicit;
  const by = resolvedBy(row);
  const wait = row.resolutionTs ? fmtSpan(row.ts, row.resolutionTs) : "";
  const allowHit = row.allowlistLabel ? `<code>${escapeHtml(row.allowlistLabel)}</code>` : "";
  const decisionFacts = [
    outcome ? fact("Outcome", escapeHtml(outcome)) : "",
    by ? fact("By", escapeHtml(by)) : "",
    wait ? fact("Waited", escapeHtml(wait)) : "",
    allowHit ? fact("Allowlist", allowHit) : "",
  ]
    .filter(Boolean)
    .join("");
  const decisionEmpty = !decisionFacts
    ? `<p class="hint" style="margin:0">No extra decision — ${tone === "allow" ? "scanner allowed this call" : "nothing recorded"}.</p>`
    : "";
  const decisionBeat = `<section class="beat">
      <h3>Decision</h3>
      ${decisionFacts ? `<dl class="beat-facts">${decisionFacts}</dl>` : decisionEmpty}
    </section>`;

  const ran =
    row.resultOk === true
      ? `<span class="spine-ok">ok</span>`
      : row.resultOk === false
        ? `<span class="spine-fail">failed</span>`
        : tone === "block" || row.effect === "never_ran" || row.effect === "blocked"
          ? `<span class="stream-when">not run</span>`
          : "";
  const duration = row.resultTs ? fmtSpan(row.ts, row.resultTs) : "";
  const size =
    row.resultBytes != null
      ? `${escapeHtml(fmtBytes(row.resultBytes))}${row.resultTruncated ? " · truncated" : ""}`
      : row.resultTruncated
        ? "truncated"
        : "";
  const urls = (row.resultUrls ?? [])
    .map((url) => `<li>${highlightCommandHtml(url)}</li>`)
    .join("");
  const paths = (row.resultPaths ?? [])
    .map((path) => `<li>${highlightCommandHtml(path)}</li>`)
    .join("");
  const resultFacts = [
    ran ? fact("Tool", ran) : "",
    duration ? fact("Returned", escapeHtml(duration)) : "",
    size ? fact("Size", size) : "",
  ]
    .filter(Boolean)
    .join("");
  const output = row.excerpt
    ? `<pre class="spine-out" style="max-height:8rem;margin-top:0.5rem">${escapeHtml(clipText(row.excerpt, 800))}</pre>`
    : !ran || ran.includes("not run")
      ? `<p class="hint" style="margin:0.45rem 0 0">Not run.</p>`
      : `<p class="hint" style="margin:0.45rem 0 0">No output logged.</p>`;
  const extracts =
    urls || paths
      ? `${urls ? `<p class="hint" style="margin:0.45rem 0 0.2rem">URLs in output</p><ul class="extracts">${urls}</ul>` : ""}
         ${paths ? `<p class="hint" style="margin:0.45rem 0 0.2rem">Paths in output</p><ul class="extracts">${paths}</ul>` : ""}`
      : "";
  const resultBeat = `<section class="beat">
      <h3>Result</h3>
      ${resultFacts ? `<dl class="beat-facts">${resultFacts}</dl>` : ""}
      ${row.injectionMarkers ? `<p class="inject-flag">Output looked like a prompt injection</p>` : ""}
      ${output}
      ${extracts}
    </section>`;

  const neighborItems = (row.neighbors ?? [])
    .map(
      (n) =>
        `<li><a href="#tl-${escapeHtml(n.id)}"><code>${escapeHtml(n.tool)}</code> ${escapeHtml(clipText(n.command, 72))}</a></li>`,
    )
    .join("");
  const neighbors = neighborItems
    ? `<section class="beat"><h3>Earlier in this run</h3><ul class="neighbors">${neighborItems}</ul></section>`
    : "";

  return `<div class="beats">${scanBeat}${decisionBeat}${resultBeat}${neighbors}</div>`;
}

function resolveAudit(state: DashboardViewState): { scanned: number; allow: number; review: number; block: number; error: number; showing: number } {
  if (state.audit) return { ...state.audit, showing: state.history.length };
  const counts = { scanned: 0, allow: 0, review: 0, block: 0, error: 0 };
  for (const row of state.history) {
    counts.scanned += 1;
    counts[decisionTone(row.decision)] += 1;
  }
  return { ...counts, showing: state.history.length };
}

function searchBlob(row: DashboardViewState["history"][number], meanings: string[], summary: string): string {
  return [
    row.decision,
    row.resolution,
    row.tool,
    row.command,
    row.sessionKey,
    summary,
    row.intent,
    row.allowlistLabel,
    row.hostTool,
    ...(row.resultUrls ?? []),
    ...(row.resultPaths ?? []),
    ...meanings,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function renderTimelineItem(
  row: DashboardViewState["history"][number],
  index: number,
  now: number,
): string {
  const meanings = ruleMeanings(row.matched_rules, row.winningRule);
  const summary = operatorSummary(row.summary ?? undefined);
  const tone = decisionTone(row.decision);
  const session = row.sessionKey || "";
  const cmdId = `tl-cmd-${escapeHtml(row.id)}`;
  const resolved = resolutionLabel(row.resolution);
  const title = highlightCommandHtml(glanceCommand(row.command));
  const fullCmd = formatCommand(row.command);
  const full = highlightCommandHtml(fullCmd);
  const glance = glanceCommand(row.command);
  const showCommand = fullCmd.replace(/\s+/g, " ").trim() !== glance.replace(/\s+/g, " ").trim();
  const extraArgs = extraArgsForRow(row.args, row.command);
  const kind = intentKindChip(row.intentKind);
  const intent = row.intent?.trim()
    ? `<p class="intent"><span class="intent-label">Started as${kind}</span>${escapeHtml(row.intent)}</p>`
    : "";
  const risk =
    typeof row.risk === "number" && tone !== "allow"
      ? `<span class="stream-when">Risk ${Math.round(row.risk * 100)}</span>`
      : "";
  const when = fmtWhen(row.ts, now);
  const whenTitle = Number.isFinite(Date.parse(row.ts))
    ? new Date(row.ts).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" })
    : row.ts;
  const blob = escapeHtml(searchBlob(row, meanings, summary));
  const { pill, detail } = decisionLabel(row.decision);
  return `<details class="stream-item" id="tl-${escapeHtml(row.id)}" data-tl-item data-tone="${tone}" data-session="${escapeHtml(session)}" data-decision="${escapeHtml(row.decision)}" data-i="${index}" data-ts="${escapeHtml(row.ts)}" data-tl-blob="${blob}">
      <summary>
        <div class="stream-lead">
          <pre class="stream-title">${title}</pre>
        </div>
        <div class="stream-head">
          <span class="pill pill-${tone}">${escapeHtml(pill)}</span>
          ${resolved ? `<span class="res-pill">${escapeHtml(resolved)}</span>` : detail ? `<span class="res-pill">${escapeHtml(detail)}</span>` : ""}
          <code>${escapeHtml(row.tool)}</code>
          <time class="stream-when" datetime="${escapeHtml(row.ts)}" title="${escapeHtml(whenTitle)}">${escapeHtml(when)}</time>
          ${session ? `<span class="stream-session">${escapeHtml(session)}</span>` : ""}
          ${resultGlance(row)}
          ${row.unattended ? `<span class="kind kind-cron">Unattended</span>` : ""}
          ${risk}
        </div>
        ${glanceWhy(tone, summary, meanings)}
      </summary>
      <div class="stream-body">
        <div class="stream-toolbar">
          <button type="button" data-copy-target="${cmdId}">Copy command</button>
          <a href="#tl-${escapeHtml(row.id)}">Link</a>
        </div>
        ${intent}
        <pre class="command" id="${cmdId}" ${showCommand ? "" : "hidden"}>${full}</pre>
        ${
          extraArgs
            ? `<div class="block" style="padding:0.75rem 0 0"><h3>Arguments</h3><pre class="spine-out">${escapeHtml(extraArgs)}</pre></div>`
            : ""
        }
        ${renderTimelineBeats(row)}
      </div>
    </details>`;
}

function renderTimeline(state: DashboardViewState, now: number): string {
  const audit = resolveAudit(state);
  const sessionKeys = [
    ...new Set(state.history.map((row) => row.sessionKey).filter((k): k is string => Boolean(k))),
  ];
  const items = state.history.map((row, i) => renderTimelineItem(row, i, now)).join("\n");
  const sessionFilters = sessionKeys
    .map(
      (key) =>
        `<button type="button" data-tl-session-filter="${escapeHtml(key)}" aria-pressed="false">${escapeHtml(key)}</button>`,
    )
    .join("");
  const loaded = state.history.length;
  return `<div class="section-head">
        <h2>Timeline</h2>
        <p>Newest scans from the local operator log (up to 100). Open a session from a review to filter.</p>
      </div>
      <div class="audit-stats" aria-label="Counts for the loaded scans">
        <div class="audit-stat" data-stat="scanned"><span class="n">${audit.scanned}</span><span class="k">Scanned</span></div>
        <div class="audit-stat" data-tone="allow" data-stat="allow"><span class="n">${audit.allow}</span><span class="k">Allowed</span></div>
        <div class="audit-stat" data-tone="review" data-stat="review"><span class="n">${audit.review}</span><span class="k">Reviewed</span></div>
        <div class="audit-stat" data-tone="block" data-stat="block"><span class="n">${audit.block}</span><span class="k">Blocked</span></div>
        <div class="audit-stat" data-tone="error" data-stat="error"><span class="n">${audit.error}</span><span class="k">Errors</span></div>
      </div>
      <div class="tl-toolbar">
        <input type="search" class="tl-search" data-tl-search placeholder="Search commands, sessions, summaries" aria-label="Search timeline">
        <div class="filters" role="toolbar" aria-label="Layout">
          <button type="button" data-tl-view="stream" aria-pressed="true">Stream</button>
          <button type="button" data-tl-view="session" aria-pressed="false">By session</button>
        </div>
      </div>
      <div class="filters" role="toolbar" aria-label="Decision filter">
        <button type="button" data-tl-decision="" aria-pressed="true">All</button>
        <button type="button" data-tl-decision="allow" aria-pressed="false">Allow</button>
        <button type="button" data-tl-decision="review" aria-pressed="false">Review</button>
        <button type="button" data-tl-decision="block" aria-pressed="false">Block</button>
        <button type="button" data-tl-decision="error" aria-pressed="false">Error</button>
      </div>
      ${
        sessionKeys.length
          ? `<div class="filters" role="toolbar" aria-label="Session filter">
        <button type="button" data-tl-session-filter="" aria-pressed="true">All sessions</button>
        ${sessionFilters}
      </div>`
          : ""
      }
      <p class="hint" data-tl-count>${loaded ? `Newest ${loaded} scans` : ""}</p>
      <div class="stream" data-tl-list>
        ${items}
      </div>
      <div data-tl-grouped hidden></div>
      <p class="hint" data-tl-empty ${items ? "hidden" : ""}>No events in this log yet.</p>`;
}

const SPINE_VISIBLE = 2;

function renderPastStep(step: NonNullable<DashboardViewState["pending"][number]["priorSteps"]>[number]): string {
  const status =
    step.ok === false
      ? `<span class="spine-fail">failed</span>`
      : step.ok
        ? `<span class="spine-ok">ok</span>`
        : "";
  const excerpt = step.excerpt
    ? `<details class="spine-out-fold"><summary>output</summary><pre class="spine-out">${escapeHtml(clipText(step.excerpt, 220))}</pre></details>`
    : "";
  const compact = clipText(step.command, 180);
  return `<li class="spine-step spine-past">
      <div class="spine-head">
        <code class="spine-tool">${escapeHtml(step.tool)}</code>
        ${status}
        <span class="spine-n">#${step.seq}</span>
      </div>
      <pre class="command" title="${escapeHtml(step.command)}">${highlightCommandHtml(compact)}</pre>
      ${excerpt}
    </li>`;
}

function renderSpine(card: DashboardViewState["pending"][number], command: string, cmdId: string): string {
  const all = card.priorSteps ?? [];
  const hidden = all.length > SPINE_VISIBLE ? all.slice(0, all.length - SPINE_VISIBLE) : [];
  const visible = all.slice(-SPINE_VISIBLE);
  const omittedNote = card.priorOmitted ? ` · ${card.priorOmitted} more not in this snapshot` : "";
  const fold = hidden.length
    ? `<li class="spine-step spine-fold">
        <details>
          <summary>Show ${hidden.length} earlier call${hidden.length === 1 ? "" : "s"}${omittedNote}</summary>
          <ol class="spine-older">${hidden.map(renderPastStep).join("")}</ol>
        </details>
      </li>`
    : card.priorOmitted
      ? `<li class="spine-step spine-fold"><p class="hint">${card.priorOmitted} earlier calls in this episode are outside this snapshot.</p></li>`
      : "";
  return `<ol class="spine">
      ${fold}
      ${visible.map(renderPastStep).join("")}
      <li class="spine-step spine-now">
        <div class="spine-head">
          <span class="spine-now-kicker">Waiting on this call</span>
          <code class="spine-tool">${escapeHtml(card.tool)}</code>
          <button type="button" data-copy-target="${escapeHtml(cmdId)}">Copy</button>
        </div>
        <pre class="command" id="${escapeHtml(cmdId)}">${highlightCommandHtml(command)}</pre>
      </li>
    </ol>`;
}

function renderReviewCard(
  card: DashboardViewState["pending"][number],
  opts: { resolveAvailable: boolean; now: number },
): string {
  const sev = severityOf(card.scan.review_severity ?? card.scan.decision);
  const risk = riskScore(card.scan.risk);
  const command = formatCommand(card.command);
  const cmdId = `cmd-${card.eventId}`;
  const argsJson = extraArgsJson(card.args, card.command);
  const meanings = ruleMeanings(card.scan.matched_rules);
  const headline = operatorSummary(card.scan.summary) || meanings[0] || "";
      const approveCmd = `/approve ${card.approvalId ?? "plugin:…"}`;
  const canResolve = opts.resolveAvailable && Boolean(card.approvalId);
  const remain =
    card.timeoutMs && card.timeoutMs > 0 ? fmtRemain(card.createdAtMs, card.timeoutMs, opts.now) : null;
  const sessionLabel = card.sessionKey?.trim() || "—";
  const sessionLink = card.sessionKey?.trim()
    ? `<a href="#timeline" data-tl-open-session="${escapeHtml(card.sessionKey)}">${escapeHtml(sessionLabel)}</a>`
    : escapeHtml(sessionLabel);
  const showAgent = Boolean(card.agentId && card.agentId !== card.sessionKey);
  const intent = card.intent?.trim();
  const intentBlock = intent
    ? `<p class="intent"><span class="intent-label">Started as${intentKindChip(card.intentKind)}</span>${escapeHtml(clipText(intent, 280))}</p>`
    : intentKindChip(card.intentKind)
      ? `<p class="intent"><span class="intent-label">Turn</span>${intentKindChip(card.intentKind).trim()}</p>`
      : "";
  const actions = canResolve
    ? `<div class="decide">
        <button type="button" class="btn-once" data-act="allow-once" data-tool="${escapeHtml(card.toolCallId)}">Allow once</button>
        <button type="button" class="btn-always" data-act="allow-always" data-tool="${escapeHtml(card.toolCallId)}">Allow always</button>
        <button type="button" class="btn-deny" data-act="deny" data-tool="${escapeHtml(card.toolCallId)}">Deny</button>
        <p class="legend">Once = this call. Always = local allowlist (skipped for high-risk shapes). Deny = veto; the claw moves on.</p>
        <p class="fallback">If allow/deny fails, use <code>${escapeHtml(approveCmd)}</code> in chat.</p>
      </div>`
    : `<div class="decide">
        <p class="legend">Once = this call. Always = local allowlist (skipped for high-risk shapes). Deny = veto; the claw moves on.</p>
        <p class="fallback">Approve via <code>${escapeHtml(approveCmd)}</code> in chat if these buttons fail.</p>
      </div>`;

  return `<article class="review sev-${sev}" id="${escapeHtml(card.eventId)}"
      data-severity="${sev}" data-created="${card.createdAtMs}" data-timeout="${card.timeoutMs ?? 0}">
    <div class="hero">
      <div>
        <p class="sev-kicker">${escapeHtml(card.scan.decision || "review")}</p>
        <h2 class="sev-label">${escapeHtml(sev)}</h2>
          </div>
      <div class="hero-risk">
        ${
          risk
            ? `<p class="risk-kicker">Risk</p>
               <div class="risk-row"><span class="risk-num">${risk.label}</span><span class="risk-scale">/ 100</span></div>
               <div class="risk-bar" aria-hidden="true"><i style="width:${risk.pct}%"></i></div>`
            : `<p class="risk-missing">No risk score</p>`
        }
      </div>
    </div>
    ${headline ? `<p class="summary">${escapeHtml(headline)}</p>` : ""}
    ${intentBlock}
    <dl class="facts">
      <div><dt>Tool</dt><dd>${escapeHtml(card.tool)}</dd></div>
      <div><dt>Waiting</dt><dd class="age">${escapeHtml(fmtAge(card.createdAtMs, opts.now))}</dd></div>
      ${remain ? `<div><dt>Timeout</dt><dd class="remain">${escapeHtml(remain)}</dd></div>` : ""}
      <div><dt>Session</dt><dd>${sessionLink}</dd></div>
      ${showAgent ? `<div><dt>Agent</dt><dd>${escapeHtml(card.agentId ?? "")}</dd></div>` : ""}
    </dl>
    <div class="block">
      <h3>Why this was flagged</h3>
      ${
        meanings.length
          ? `<ul class="chips">${meanings.map((label) => `<li>${escapeHtml(label)}</li>`).join("")}</ul>`
          : `<p class="hint">No extra policy labels.</p>`
      }
    </div>
    ${
      card.scan.block_reason
        ? `<div class="block"><h3>Block reason</h3><p>${escapeHtml(card.scan.block_reason)}</p></div>`
        : ""
    }
    ${renderSpine(card, command, cmdId)}
    ${actions}
    <details class="more">
      <summary>IDs, full arguments, chat fallback</summary>
      <dl>
        <dt>Event</dt><dd><code>${escapeHtml(card.eventId)}</code></dd>
        <dt>Tool call</dt><dd><code>${escapeHtml(card.toolCallId)}</code></dd>
        <dt>Approval</dt><dd><code>${escapeHtml(card.approvalId ?? "not minted yet")}</code></dd>
        <dt>Session key</dt><dd><code>${escapeHtml(card.sessionKey ?? "—")}</code></dd>
        <dt>Session id</dt><dd><code>${escapeHtml(card.sessionId ?? "—")}</code></dd>
      </dl>
      ${
        argsJson
          ? `<h3>Tool arguments</h3><pre>${escapeHtml(argsJson)}</pre>`
          : `<p class="hint">No extra tool arguments beyond the command.</p>`
      }
      <p class="hint">Chat fallback: <code>${escapeHtml(approveCmd)}</code></p>
    </details>
      </article>`;
}

function allowAllModeOf(state: DashboardViewState): "off" | "session" | "on" {
  if (state.allowAll) return "on";
  if (state.sessions.some((s) => s.allowAll)) return "session";
  return "off";
}

function segBtn(pressed: boolean, attrs: string, label: string): string {
  return `<button type="button" aria-pressed="${pressed ? "true" : "false"}" ${attrs}>${label}</button>`;
}

function choiceHint(text: string): string {
  return `<p class="floor-hint">${escapeHtml(text)}</p>`;
}

const FLOOR_LABEL: Record<Sensitivity, string> = {
  strict: "Strict",
  info: "Info",
  warning: "Warning",
  critical: "Critical",
};

function renderSensitivityFloor(scope: SensitivityScope, raw: string | undefined): string {
  const selected = parseSensitivity(raw, "strict");
  const buttons = SENSITIVITY_BUTTONS.map((level) => {
    const mark = sensitivityFloorHighlight(selected, level);
    const pressed = mark === "on";
    const cls = [`floor-${level}`, mark === "off" ? "" : `floor-${mark}`].filter(Boolean).join(" ");
    return segBtn(
      pressed,
      `class="${cls}" data-sens="${level}" data-sens-scope="${scope}"`,
      FLOOR_LABEL[level],
    );
  }).join("\n          ");
  return `<div class="seg seg-floor" role="group" aria-label="${scope} review sensitivity">
          ${buttons}
        </div>
        <p class="floor-hint floor-${selected}">${escapeHtml(sensitivityHint(scope, selected))}</p>`;
}

function renderAllowlist(state: DashboardViewState): string {
  const entries = state.allowlist
    .map((entry) => {
      const kind = entry.kind === "script_bind" ? "script bind" : "skeleton";
      const meta = [
        entry.tool,
        entry.detail ? `args ${entry.detail}` : "",
        entry.createdAt ? entry.createdAt.slice(0, 10) : "",
      ]
        .filter(Boolean)
        .join(" · ");
      return `<li>
        <div class="allow-main">
          <span class="allow-kind">${escapeHtml(kind)}</span>
          <p class="allow-label"><code>${escapeHtml(entry.label)}</code></p>
          ${meta ? `<p class="allow-meta">${escapeHtml(meta)}</p>` : ""}
        </div>
        <button type="button" data-allow-rm="${entry.index}">Remove</button>
      </li>`;
    })
    .join("\n");
  return `<div class="section-head">
      <h2>Allowlist</h2>
      <p>Local short-circuit after a <strong>review</strong>. Matching calls skip the prompt; they still go to /scan. Blocks always win.</p>
    </div>
    <details class="help-fold" id="allow-help">
      <summary>How skeleton and script-bind matchers work</summary>
      <div class="allow-kinds">
        <article class="kind-card">
          <h3>Skeleton</h3>
          <p>Same tool and argument shape. Volatile bits (dates, UUIDs, integers) may change. Typical for <code>git status --short</code> or <code>rg -n TODO src/</code>. A new flag or a different binary is a different skeleton.</p>
        </article>
        <article class="kind-card">
          <h3>Script bind</h3>
          <p>A specific local script: interpreter + path + content hash, plus a narrow args skeleton. Editing the file breaks the bind. For <code>python3 tools/report.py</code>, not inline <code>-c</code> / <code>curl | bash</code>.</p>
        </article>
      </div>
    </details>
    ${
      entries
        ? `<ul class="allow-list">${entries}</ul>`
        : `<div class="empty"><h2>No entries yet</h2><p>Choose Allow every time on a review to store a skeleton or script bind here.</p></div>`
    }`;
}

const SESSION_PREVIEW_LIMIT = 5;

function renderSessionRow(
  s: DashboardViewState["sessions"][number],
  now: number,
): string {
  const quietOn = Boolean(s.quietUntilMs && s.quietUntilMs > now);
  const sessionQuiet = quietOn ? quietLeftLabel(s.quietUntilMs, now) : "off";
  const key = s.sessionKey?.trim() || "—";
  const id = s.sessionId?.trim() || "";
  const showId = Boolean(id && id !== key);
  const pending = s.pending === 1 ? "1 pending" : `${s.pending} pending`;
  return `<li class="sess-row">
        <div class="sess-id">
          <code class="sess-key">${escapeHtml(key)}</code>
          <span class="sess-meta">${showId ? `<code>${escapeHtml(id)}</code> · ` : ""}${pending}</span>
        </div>
        <div class="sess-actions seg">
          ${segBtn(s.allowAll, `data-policy="allow-all" data-on="${s.allowAll ? "0" : "1"}" data-sid="${escapeHtml(s.sessionId ?? "")}" data-skey="${escapeHtml(s.sessionKey ?? "")}"`, s.allowAll ? "Allow-all on" : "Allow-all off")}
          ${segBtn(quietOn, `data-policy="quiet" data-on="${quietOn ? "0" : "1"}" data-sid="${escapeHtml(s.sessionId ?? "")}" data-skey="${escapeHtml(s.sessionKey ?? "")}"`, quietOn ? `Quiet ${sessionQuiet}` : "Quiet 30m")}
        </div>
      </li>`;
}

function renderSessionList(sessions: DashboardViewState["sessions"], now: number): string {
  if (!sessions.length) {
    return `<p class="hint">No sessions in the OpenClaw store.</p>`;
  }
  const head = sessions.slice(0, SESSION_PREVIEW_LIMIT);
  const rest = sessions.slice(SESSION_PREVIEW_LIMIT);
  const headList = `<ul class="sess-list">${head.map((s) => renderSessionRow(s, now)).join("\n")}</ul>`;
  if (!rest.length) return headList;
  const n = rest.length;
  return `${headList}
        <details class="sess-more" id="sess-more">
          <summary><span class="sess-more-closed">Show ${n} more session${n === 1 ? "" : "s"}</span><span class="sess-more-open">Show fewer</span></summary>
          <ul class="sess-list">${rest.map((s) => renderSessionRow(s, now)).join("\n")}</ul>
        </details>`;
}

function renderSettings(state: DashboardViewState, now: number): string {
  const mode = allowAllModeOf(state);
  const quietOn = Boolean(state.quietUntilMs && state.quietUntilMs > now);
  const quietChoice = quietHint(state.quietUntilMs, now);
  const feedback = state.feedbackMode === "off" ? "off" : "submit";
  const scanErr = state.onScanError === "allow" || state.onScanError === "deny" ? state.onScanError : "review";
  const mib = Math.max(1, Math.round(state.log.maxBytes / (1024 * 1024)));

  return `<div class="section-head">
      <h2>Settings</h2>
      <p>Runtime skips live in memory (cleared on gateway restart). Sensitivity, feedback, scan-error policy, and log retention write to <code>openclaw.json</code> when the gateway can save them.</p>
    </div>
    <div class="settings">
      <section class="set-card">
        <h3>Attended tool review sensitivity</h3>
        <p class="lead">Auto-accept reviews at or below the selected severity while you are present. Each step includes every lower level. Blocks and scan errors still stop. Unlike allow-all, this persists across restarts.</p>
        ${renderSensitivityFloor("attended", state.sensitivity)}
      </section>
      <section class="set-card">
        <h3>Unattended tool review sensitivity</h3>
        <p class="lead">The same floor for cron and subagent runs, when nobody is watching. Default is strict. Allow-all and quiet do not apply here.</p>
        ${renderSensitivityFloor("unattended", state.unattendedSensitivity)}
      </section>
      <section class="set-card">
        <h3>Allow-all</h3>
        <p class="lead">Skip future <strong>reviews</strong> without resolving cards already waiting. Never skips block or scan errors. Unattended runs use the unattended sensitivity above, not this switch. Per session Allow-all/Quiet controls can be set in the Per session section below.</p>
        <div class="seg">
          ${segBtn(mode !== "on", `data-allow-mode="off"`, "Off")}
          ${segBtn(mode === "on", `data-allow-mode="on"`, "On for all")}
        </div>
        ${choiceHint(allowAllHint(mode))}
      </section>
      <section class="set-card">
        <h3>Quiet</h3>
        <p class="lead">Same skip as allow-all, with a TTL (max 8 hours). This row is gateway-wide. Per session Allow-all/Quiet controls can be set in the Per session section below. Unattended runs use the unattended sensitivity above.</p>
        <div class="seg">
          ${segBtn(!quietOn, `data-quiet-global="off"`, "Off")}
          ${segBtn(false, `data-quiet-global="30m"`, "30m")}
          ${segBtn(false, `data-quiet-global="2h"`, "2h")}
          ${segBtn(false, `data-quiet-global="8h"`, "8h")}
        </div>
        ${choiceHint(quietChoice)}
      </section>
      <section class="set-card" id="set-sessions">
        <h3>Per session</h3>
        <p class="lead">OpenClaw sessions from the same store as Control UI. Allow-all and quiet flags are Sentrook’s and stay in memory (cleared on restart / session end). Extra quiet windows work even if global quiet is off.</p>
        ${renderSessionList(state.sessions, now)}
        ${
          mode === "on"
            ? choiceHint("Global allow-all is on — session allow-all flags are ignored until you switch off.")
            : ""
        }
      </section>
      <section class="set-card">
        <h3>Plugin config</h3>
        <p class="lead">Writes <code>plugins.entries.sentrook-openclaw.config</code>. Environment variables still win after a restart. Scan origin and credentials stay out of this page.</p>
        <p class="lead">Submit feedback</p>
        <div class="seg">
          ${segBtn(feedback === "submit", `data-feedback="submit"`, "submit")}
          ${segBtn(feedback === "off", `data-feedback="off"`, "off")}
        </div>
        ${choiceHint(feedbackHint(feedback))}
        <p class="lead" style="margin-top:1rem">When /scan fails</p>
        <div class="seg">
          ${segBtn(scanErr === "review", `data-scan-error="review"`, "review")}
          ${segBtn(scanErr === "deny", `data-scan-error="deny"`, "deny")}
          ${segBtn(scanErr === "allow", `data-scan-error="allow" class="set-warn"`, "allow")}
        </div>
        ${choiceHint(scanErrorHint(scanErr))}
        ${
          state.setupNeeded
            ? `<p class="lead" style="margin-top:1rem">Save credentials on Reviews first, then you can test the connection here.</p>`
            : `<p class="lead" style="margin-top:1rem">Connection</p>
        <p class="lead">Mint a token against FIDU Identity and ping hosted /health. Same checks as <code>openclaw sentrook verify</code>.</p>
        <button type="button" data-verify="1">Test connection</button>
        <div class="verify-result" data-verify-result hidden></div>`
        }
      </section>
      <section class="set-card">
        <h3>Operator log</h3>
        <p class="lead">Local JSONL on this host. Never uploaded. Timeline reads from here.</p>
        <p class="log-meta"><code>${escapeHtml(state.log.path)}</code><br>
          ${state.log.lines} lines · ${fmtBytes(state.log.bytes)} · ${state.log.enabled ? "on" : "off"}</p>
        <div class="set-fields" style="margin-top:0.85rem">
          <label class="field"><span>Keep (days)</span>
            <input type="number" min="0" max="3650" step="1" data-log-days value="${state.log.maxAgeDays}">
          </label>
          <label class="field"><span>Rotate at (MiB)</span>
            <input type="number" min="1" max="1024" step="1" data-log-mib value="${mib}">
          </label>
          <button type="button" data-log="save">Save</button>
        </div>
        <div class="row">
          <button type="button" data-log="purge">Drop lines older than retention</button>
          <button type="button" class="set-danger" data-log="wipe">Delete entire log</button>
        </div>
      </section>
    </div>`;
}

function renderSetup(state: DashboardViewState): string {
  const identity = DEFAULT_OIDC_ISSUER;
  const scanErr =
    state.onScanError === "allow" || state.onScanError === "deny" ? state.onScanError : "review";
  return `<div class="setup">
      <p class="empty-kicker">First-run setup</p>
      <h2>Connect hosted Sentrook</h2>
      <p class="setup-copy">To use hosted Sentrook you need a free FIDU membership with a Sentrook OAuth client.</p>
      <p class="setup-copy">Visit <a href="${escapeHtml(identity)}" target="_blank" rel="noopener noreferrer">${escapeHtml(identity)}</a> — log in or create an account (free membership is all that's required). Use the Identity environment that matches this Sentrook build (prod Identity for prod Sentrook).</p>
      <p class="setup-copy">On your dashboard, open the Sentrook tab, click Create Credentials, then paste the client_id and client_secret below.</p>
      <div class="setup-fields">
        <label class="field"><span>OAuth client_id</span>
          <input type="text" autocomplete="off" spellcheck="false" data-setup-client-id>
        </label>
        <label class="field"><span>OAuth client_secret</span>
          <input type="password" autocomplete="new-password" spellcheck="false" data-setup-client-secret>
        </label>
      </div>
      <p class="lead" style="margin-top:1.15rem">Submit feedback</p>
      <div class="seg" data-setup-feedback-group role="group" aria-label="Feedback">
        ${segBtn(true, `data-setup-feedback="submit"`, "submit")}
        ${segBtn(false, `data-setup-feedback="off"`, "off")}
      </div>
      ${choiceHint(feedbackHint("submit"))}
      <p class="lead" style="margin-top:1rem">When /scan fails</p>
      <div class="seg" data-setup-scan-error-group role="group" aria-label="When scan fails">
        ${segBtn(scanErr === "review", `data-setup-scan-error="review"`, "review")}
        ${segBtn(scanErr === "deny", `data-setup-scan-error="deny"`, "deny")}
        ${segBtn(scanErr === "allow", `data-setup-scan-error="allow" class="set-warn"`, "allow")}
      </div>
      ${choiceHint(scanErrorHint(scanErr))}
      <div class="setup-actions">
        <button type="button" data-setup-save="1">Save and test</button>
      </div>
    </div>`;
}

function renderReviews(state: DashboardViewState, now: number): string {
  const pending = state.pending.slice().sort((a, b) => {
    const rank =
      (SEV_RANK[severityOf(a.scan.review_severity ?? a.scan.decision)] ?? 9) -
      (SEV_RANK[severityOf(b.scan.review_severity ?? b.scan.decision)] ?? 9);
    return rank || b.createdAtMs - a.createdAtMs;
  });
  if (!pending.length) {
    return `<div class="empty">
      <p class="empty-kicker">Reviews</p>
      <h2>All clear</h2>
      <p>Nothing waiting. When a review is needed, the full command and scan details land here — no channel character limit.</p>
    </div>`;
  }
  const jump =
    pending.length > 1
      ? `<ol class="jump">${pending
          .map((card) => {
            const sev = severityOf(card.scan.review_severity ?? card.scan.decision);
            return `<li><a href="#${escapeHtml(card.eventId)}"><span class="tag sev-${sev}">${escapeHtml(sev)}</span>
              <span>${escapeHtml(card.tool)}</span>
              <span class="ex">${escapeHtml(commandExcerpt(card.command))}</span></a></li>`;
          })
          .join("")}</ol>
        <p class="hint" style="margin:-0.4rem 0 1rem">Critical first. ${pending.length} waiting — uncommon, but all are shown in full below.</p>`
      : "";
  const cards = pending
    .map((card) =>
      renderReviewCard(card, {
        resolveAvailable: state.resolveAvailable,
        now,
      }),
    )
    .join("\n");
  return `${jump}${cards}`;
}

export function renderDashboardPage(
  state: DashboardViewState,
  now: number = Date.now(),
  access: string = "",
  version: string = "",
): string {
  const pendingCount = state.pending.length;
  const worst = state.pending.reduce<Severity | null>((acc, card) => {
    const sev = severityOf(card.scan.review_severity ?? card.scan.decision);
    if (!acc) return sev;
    return SEV_RANK[sev] < SEV_RANK[acc] ? sev : acc;
  }, null);
  const countClass = worst === "critical" ? "critical" : pendingCount ? "warn" : "";
  const title = pendingCount
    ? `Sentrook · ${pendingCount} review${pendingCount === 1 ? "" : "s"}`
    : "Sentrook";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${escapeHtml(title)}</title>
  <style>${DASHBOARD_CSS}</style>
</head>
<body data-pending="${escapeHtml(dashboardFingerprint(state))}" data-access="${escapeHtml(access)}">
  <header class="top">
    <div class="brand">
    <h1>Sentrook</h1>
    </div>
    <nav class="tabs" aria-label="Dashboard sections">
      <a href="#reviews" data-tab="reviews" aria-current="page">Reviews${
        pendingCount
          ? ` <span class="count ${countClass}">${pendingCount}</span>`
          : ""
      }</a>
      <a href="#timeline" data-tab="timeline">Timeline</a>
      <a href="#allowlist" data-tab="allowlist">Allowlist</a>
      <a href="#settings" data-tab="settings">Settings</a>
    </nav>
    ${version ? `<p class="ver" title="Plugin version">${escapeHtml(version)}</p>` : ""}
  </header>
  <p class="iframe-note">This Control UI tab is sandboxed. Switching away can freeze it — reload Control UI if it goes blank. Select the URL below and paste it in a normal browser tab (clipboard is often blocked here). Settings also work via <code>/sentrook</code> in chat.</p>
  <input class="iframe-note-url" data-panel-url readonly spellcheck="false" />
  <div id="flash" role="status" aria-live="assertive"></div>
  <div id="confirm" hidden>
    <div class="confirm-card">
      <p id="confirm-msg"></p>
      <div class="confirm-actions">
        <button type="button" data-confirm-cancel>Cancel</button>
        <button type="button" data-confirm-ok>Confirm</button>
      </div>
    </div>
  </div>
  <div class="page">
    <section class="panel" data-panel="reviews">
      ${
        state.setupNeeded
          ? renderSetup(state)
          : `<div class="section-head">
        <h2>Pending reviews</h2>
        <p>Full local command and scan detail — not bound by chat card limits.</p>
      </div>
      ${renderReviews(state, now)}`
      }
    </section>
    <section class="panel" data-panel="timeline" hidden>
      ${renderTimeline(state, now)}
    </section>
    <section class="panel" data-panel="allowlist" hidden>
      ${renderAllowlist(state)}
    </section>
    <section class="panel" data-panel="settings" hidden>
      ${renderSettings(state, now)}
    </section>
  </div>
  <script>${DASHBOARD_JS}</script>
</body>
</html>`;
}
