/**
 * Native Control UI view for Sentrook.
 *
 * Browser-safe: no ``node:`` imports. Panel HTML comes from ``dashboardPanels.ts``
 * so the layout matches the iframe operator dashboard. Class names match the
 * scoped stylesheet in ``control-ui.css``.
 */

import { escapeHtml } from "./dashboardPresent.ts";
import {
  renderAllowlist,
  renderReviewsPanel,
  renderSettings,
  renderTimeline,
  severityOf,
  type DashboardPanelOpts,
} from "./dashboardPanels.ts";
import type { SentrookState } from "./featureContract.ts";

export type NativeTab = "reviews" | "timeline" | "allowlist" | "settings";

export type NativeViewOpts = {
  tab: NativeTab;
  canWrite: boolean;
  connected: boolean;
  now: number;
  version?: string;
  flash?: { text: string; kind: "ok" | "error" } | null;
};

const SEV_RANK: Record<string, number> = { critical: 0, warning: 1, info: 2 };

function statusLine(opts: NativeViewOpts): string {
  if (!opts.connected) return "offline";
  return opts.canWrite ? "connected" : "read-only";
}

function versionMark(opts: NativeViewOpts): string {
  const version = opts.version?.trim();
  const status = statusLine(opts);
  if (!version) return `<p class="ver">${escapeHtml(status)}</p>`;
  return `<p class="ver" title="${escapeHtml(`Plugin version · ${status}`)}">${escapeHtml(version)}</p>`;
}

export function renderNativePage(state: SentrookState, opts: NativeViewOpts): string {
  const pendingCount = state.pending.length;
  const worst = state.pending.reduce<string | null>((acc, card) => {
    const sev = severityOf(card.scan.review_severity ?? card.scan.decision);
    if (!acc) return sev;
    return (SEV_RANK[sev] ?? 9) < (SEV_RANK[acc] ?? 9) ? sev : acc;
  }, null);
  const countClass = worst === "critical" ? "critical" : pendingCount ? "warn" : "";
  const flash = opts.flash
    ? `<div id="flash" class="flash-${opts.flash.kind}" role="status">${escapeHtml(opts.flash.text)}</div>`
    : `<div id="flash" role="status" aria-live="assertive"></div>`;
  const tab = (id: NativeTab, label: string, extra = "") =>
    `<a href="#${id}" data-tab="${id}"${opts.tab === id ? ` aria-current="page"` : ""}>${label}${extra}</a>`;
  const panels: DashboardPanelOpts = { now: opts.now, interactive: opts.canWrite };
  return `<header class="top">
      <div class="brand"><h1>Sentrook</h1></div>
      <nav class="tabs" aria-label="Dashboard sections">
        ${tab("reviews", "Reviews", pendingCount ? ` <span class="count ${countClass}">${pendingCount}</span>` : "")}
        ${tab("timeline", "Timeline")}
        ${tab("allowlist", "Allowlist")}
        ${tab("settings", "Settings")}
      </nav>
      ${versionMark(opts)}
    </header>
    ${flash}
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
      <section class="panel" data-panel="reviews"${opts.tab === "reviews" ? "" : " hidden"}>
        ${renderReviewsPanel(state, panels)}
      </section>
      <section class="panel" data-panel="timeline"${opts.tab === "timeline" ? "" : " hidden"}>
        ${renderTimeline(state, panels)}
      </section>
      <section class="panel" data-panel="allowlist"${opts.tab === "allowlist" ? "" : " hidden"}>
        ${renderAllowlist(state, panels)}
      </section>
      <section class="panel" data-panel="settings"${opts.tab === "settings" ? "" : " hidden"}>
        ${renderSettings(state, panels)}
      </section>
    </div>`;
}
