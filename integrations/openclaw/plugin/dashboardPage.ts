/**
 * Iframe operator dashboard: page shell, CSS, and client JS.
 *
 * HTML fragments live in ``dashboardPanels.ts`` so the native Control UI can
 * reuse them without pulling iframe CSS/JS or dashboardAuth.
 */

import { dashboardFingerprint, escapeHtml } from "./dashboardPresent.ts";
import {
  type DashboardPanelOpts,
  type DashboardViewState,
  renderAllowlist,
  renderReviewsPanel,
  renderSettings,
  renderTimeline,
  severityOf,
} from "./dashboardPanels.ts";
import {
  READ_ONLY_TAB_TITLE,
  hostUiSupport,
  readOnlyTabMessage,
  resolveHostVersion,
} from "./hostVersion.ts";

export type { DashboardViewState } from "./dashboardPanels.ts";
export { escapeHtml } from "./dashboardPresent.ts";
export { severityOf } from "./dashboardPanels.ts";

type Severity = "info" | "warning" | "critical";

const SEV_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

export const GATEWAY_TAB_WRITE_HINT =
  "Control UI plugin-tab cookies are GET-only, so this change was not saved. Use the native Sentrook page (OpenClaw 2026.9.2+ with Labs \u2192 Custom plugin UI), /sentrook in chat, or the sentrook CLI.";

export const GATEWAY_TAB_READ_HINT =
  "This panel is read-only. Use the native Sentrook page (OpenClaw 2026.9.2+ with Labs \u2192 Custom plugin UI), /sentrook in chat, or the sentrook CLI.";

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
#flash.flash-ok { border-color: var(--ok); background: rgba(125, 186, 125, 0.18); color: #d4f0d4; }
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
.iframe-note {
  display: block; margin: 0; padding: 0.65rem 1.5rem 0.75rem;
  border-bottom: 1px solid var(--warning-line); background: var(--warning-bg);
  color: var(--fg); font-size: 0.86rem; line-height: 1.45;
}
.iframe-note-title { display: block; font-weight: 700; margin: 0 0 0.25rem; }
.iframe-note p { margin: 0; }
.iframe-note code { font-size: 0.86em; }
.slash-cmds {
  list-style: none; margin: 0.55rem 0 0; padding: 0;
  display: flex; flex-direction: column; gap: 0.35rem;
}
.slash-cmds li {
  display: flex; flex-wrap: wrap; gap: 0.35rem 0.7rem; align-items: baseline;
  color: var(--muted); font-size: 0.86rem;
}
.slash-cmd, .slash-cmds code {
  display: inline-block; max-width: 100%; background: var(--inset); border: 1px solid var(--line);
  border-radius: 6px; padding: 0.18rem 0.45rem; color: var(--fg); font-size: 0.82rem;
  user-select: all; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-all;
}
.current { margin: 0 0 0.45rem; color: var(--fg); font-size: 0.9rem; }
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
.kind-cron, .kind-heartbeat { background: var(--warning-bg); color: var(--warning); }
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
  display: flex; flex-wrap: wrap; gap: 0.55rem; align-items: center;
  margin: 0.9rem 0 0; padding: 1rem 1.5rem 0.35rem;
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
.sess-name {
  display: block;
  font-size: 0.95rem;
  font-weight: 650;
  overflow-wrap: anywhere;
}
.sess-meta { display: block; margin-top: 0.22rem; color: var(--faint); font-size: 0.78rem; }
.sess-meta code { font-size: inherit; overflow-wrap: anywhere; word-break: break-all; }
.sess-actions { flex: 0 1 auto; display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: flex-end; }
.sess-sens {
  display: flex; flex-direction: column; gap: 0.12rem; min-width: 8.2rem;
}
.sess-sens span { font-size: 0.72rem; color: var(--faint); font-weight: 650; }
.sess-sens select {
  font: inherit; font-size: 0.82rem; color: var(--fg); background: var(--card);
  border: 1px solid var(--line); border-radius: 8px; padding: 0.28rem 0.4rem;
}
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
.set-card-quiet { border-color: rgba(230, 184, 77, 0.55); }
.quiet-status {
  margin: 0 0 0.85rem; padding: 0.75rem 0.95rem;
  border-radius: var(--radius);
  border: 1px solid var(--warning);
  background: var(--warning-bg);
  color: var(--warning);
  font-size: 1.05rem; font-weight: 650; line-height: 1.35;
}
.quiet-status [data-quiet-until] { font-variant-numeric: tabular-nums; }
.sess-actions button.quiet-on[aria-pressed="true"] {
  border-color: var(--warning); background: var(--warning-bg); color: var(--warning);
}
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
  const TABS = ["reviews", "timeline", "allowlist", "settings"];
  const TAB_ALIAS = { sessions: "settings", log: "settings", configure: "settings", "set-sessions": "settings" };
  const SCROLL_STORE = "sentrook-page-scroll";
  const FLASH_STORE = "sentrook-flash";
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
    document.querySelectorAll("[data-quiet-until]").forEach((el) => {
      const until = Number(el.getAttribute("data-quiet-until"));
      if (!Number.isFinite(until)) return;
      const sec = Math.max(0, Math.round((until - Date.now()) / 1000));
      let phrase = "off";
      if (sec < 60) phrase = sec + "s";
      else {
        const min = Math.round(sec / 60);
        if (min < 60) phrase = min + "m";
        else {
          const hours = Math.floor(min / 60);
          const mins = min % 60;
          phrase = mins ? hours + "h " + mins + "m" : hours + "h";
        }
      }
      el.textContent = phrase;
    });
  }

  document.addEventListener("click", async (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.id === "flash") {
      applyFlash("", "");
      return;
    }
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
  const panels: DashboardPanelOpts = { now, interactive: false };
  const hostVersion = resolveHostVersion();
  const banner = readOnlyTabMessage(hostUiSupport(hostVersion), hostVersion);

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
  <div class="iframe-note" role="status">
    <strong class="iframe-note-title">${escapeHtml(READ_ONLY_TAB_TITLE)}</strong>
    <p>${escapeHtml(banner)}</p>
  </div>
  <div id="flash" role="status" aria-live="assertive"></div>
  <div class="page">
    <section class="panel" data-panel="reviews">
      ${renderReviewsPanel(state, panels)}
    </section>
    <section class="panel" data-panel="timeline" hidden>
      ${renderTimeline(state, panels)}
    </section>
    <section class="panel" data-panel="allowlist" hidden>
      ${renderAllowlist(state, panels)}
    </section>
    <section class="panel" data-panel="settings" hidden>
      ${renderSettings(state, panels)}
    </section>
  </div>
  <script>${DASHBOARD_JS}</script>
</body>
</html>`;
}
