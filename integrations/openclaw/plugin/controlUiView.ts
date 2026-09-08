/**
 * Native Control UI view for Sentrook.
 *
 * Browser-safe: no ``node:`` imports. The HTML class names match the scoped
 * stylesheet in ``control-ui.css`` (copied from the operator dashboard).
 */

import { escapeHtml, highlightCommandHtml, operatorSummary, ruleMeanings } from "./dashboardPresent.ts";
import {
  allowAllHint,
  feedbackHint,
  quietHint,
  scanErrorHint,
  sensitivityHint,
} from "./policyCopy.ts";
import { SENSITIVITY_BUTTONS, type Sensitivity } from "./sessionPolicy.ts";
import { DEFAULT_OIDC_ISSUER } from "./scanEndpoint.ts";
import type { PendingReview, SentrookState } from "./featureContract.ts";

export type NativeTab = "reviews" | "timeline" | "allowlist" | "settings";

export type NativeViewOpts = {
  tab: NativeTab;
  canWrite: boolean;
  connected: boolean;
  now: number;
  flash?: { text: string; kind: "ok" | "error" } | null;
};

const SEV_RANK: Record<string, number> = { critical: 0, warning: 1, info: 2 };

function severityOf(raw: string | undefined): "info" | "warning" | "critical" {
  const value = (raw ?? "").trim().toLowerCase();
  if (value === "critical" || value === "warning" || value === "info") return value;
  return "warning";
}

function clip(text: string, max: number): string {
  const t = text.trim();
  return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

function fmtAge(fromMs: number, now: number): string {
  const sec = Math.max(0, Math.round((now - fromMs) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  return `${Math.round(min / 60)}h ago`;
}

function pressed(on: boolean): string {
  return on ? ` aria-pressed="true"` : ` aria-pressed="false"`;
}

function seg(on: boolean, attrs: string, label: string): string {
  return `<button type="button" class="seg-btn"${pressed(on)} ${attrs}>${escapeHtml(label)}</button>`;
}

function writeDisabled(canWrite: boolean): string {
  return canWrite ? "" : " disabled";
}

function renderSetup(state: SentrookState, canWrite: boolean): string {
  const scanErr = state.onScanError;
  return `<div class="setup">
    <p class="empty-kicker">First-run setup</p>
    <h2>Connect hosted Sentrook</h2>
    <p class="setup-copy">Create a Sentrook OAuth client at
      <a href="${escapeHtml(DEFAULT_OIDC_ISSUER)}" target="_blank" rel="noopener noreferrer">${escapeHtml(DEFAULT_OIDC_ISSUER)}</a>,
      then paste the client id and secret. This writes <code>~/.openclaw/.env</code>, never plugin JSON.</p>
    <div class="setup-fields">
      <label class="field"><span>OAuth client_id</span>
        <input type="text" autocomplete="off" spellcheck="false" data-setup-client-id ${writeDisabled(canWrite)}>
      </label>
      <label class="field"><span>OAuth client_secret</span>
        <input type="password" autocomplete="new-password" spellcheck="false" data-setup-client-secret ${writeDisabled(canWrite)}>
      </label>
    </div>
    <p class="lead" style="margin-top:1.15rem">Submit feedback</p>
    <div class="seg" role="group" aria-label="Feedback">
      ${seg(true, `data-setup-feedback="submit"`, "submit")}
      ${seg(false, `data-setup-feedback="off"`, "off")}
    </div>
    <p class="lead" style="margin-top:1rem">When /scan fails</p>
    <div class="seg" role="group" aria-label="When scan fails">
      ${seg(scanErr === "review", `data-setup-scan-error="review"`, "review")}
      ${seg(scanErr === "deny", `data-setup-scan-error="deny"`, "deny")}
      ${seg(scanErr === "allow", `data-setup-scan-error="allow" class="set-warn"`, "allow")}
    </div>
    <div class="setup-actions">
      <button type="button" data-setup-save="1"${writeDisabled(canWrite)}>Save and test</button>
    </div>
  </div>`;
}

function renderReviewCard(card: PendingReview, opts: { canWrite: boolean; now: number }): string {
  const sev = severityOf(card.scan.review_severity ?? card.scan.decision);
  const meanings = ruleMeanings(card.scan.matched_rules, undefined);
  const summary = operatorSummary(card.scan.summary);
  const id = card.toolCallId || card.eventId;
  return `<article class="review" data-id="${escapeHtml(id)}" data-approval="${escapeHtml(card.approvalId ?? "")}">
    <div class="review-head">
      <span class="tag sev-${sev}">${escapeHtml(sev)}</span>
      <strong>${escapeHtml(card.tool)}</strong>
      <span class="muted">${escapeHtml(fmtAge(card.createdAtMs, opts.now))}</span>
      ${card.sessionKey ? `<span class="muted">${escapeHtml(card.sessionKey)}</span>` : ""}
    </div>
    <pre class="cmd">${highlightCommandHtml(card.command || JSON.stringify(card.args ?? {}))}</pre>
    ${summary ? `<p class="summary">${escapeHtml(summary)}</p>` : ""}
    ${meanings.length ? `<p class="meanings">${meanings.map((m) => escapeHtml(m)).join(" · ")}</p>` : ""}
    <div class="review-actions">
      <button type="button" data-resolve="allow-once" data-id="${escapeHtml(id)}"${writeDisabled(opts.canWrite)}>Allow once</button>
      <button type="button" data-resolve="allow-always" data-id="${escapeHtml(id)}"${writeDisabled(opts.canWrite)}>Allow always</button>
      <button type="button" class="btn-deny" data-resolve="deny" data-id="${escapeHtml(id)}"${writeDisabled(opts.canWrite)}>Deny</button>
    </div>
  </article>`;
}

function renderReviews(state: SentrookState, opts: NativeViewOpts): string {
  if (state.setupNeeded) return renderSetup(state, opts.canWrite);
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
      <p>Nothing waiting. New reviews appear here as soon as a scan asks for a human.</p>
    </div>`;
  }
  return `<div class="section-head">
      <h2>Pending reviews</h2>
      <p>Allow / deny uses OpenClaw <code>plugin.approval.resolve</code> so the waiting tool continues.</p>
    </div>
    ${pending.map((card) => renderReviewCard(card, opts)).join("\n")}`;
}

function renderTimeline(state: SentrookState): string {
  if (!state.history.length) {
    return `<div class="empty"><p class="empty-kicker">Timeline</p><h2>No scans yet</h2></div>`;
  }
  const rows = state.history.slice(0, 100).map((row) => {
    const sev = severityOf(row.reviewSeverity ?? row.decision);
    return `<tr>
      <td>${escapeHtml(row.ts.slice(11, 19) || row.ts)}</td>
      <td><span class="tag sev-${sev}">${escapeHtml(row.decision)}</span></td>
      <td>${escapeHtml(row.tool)}</td>
      <td class="ex">${escapeHtml(clip(row.command || "", 120))}</td>
      <td>${escapeHtml(row.sessionKey || "")}</td>
    </tr>`;
  });
  const audit = state.audit;
  return `<div class="section-head">
      <h2>Timeline</h2>
      <p>${audit ? `${audit.scanned} scanned · ${audit.allow} allow · ${audit.review} review · ${audit.block} block · ${audit.error} error` : "Newest 100 scans."}</p>
    </div>
    <div class="table-wrap"><table class="tl">
      <thead><tr><th>Time</th><th>Decision</th><th>Tool</th><th>Command</th><th>Session</th></tr></thead>
      <tbody>${rows.join("")}</tbody>
    </table></div>`;
}

function renderAllowlist(state: SentrookState, canWrite: boolean): string {
  if (!state.allowlist.length) {
    return `<div class="empty"><p class="empty-kicker">Allowlist</p><h2>No local skips</h2>
      <p>Allow-always records a matcher here. Remove one to start reviewing that shape again.</p></div>`;
  }
  const rows = state.allowlist.map(
    (entry) => `<tr>
      <td>${entry.index}</td>
      <td>${escapeHtml(entry.kind)}</td>
      <td>${escapeHtml(entry.tool)}</td>
      <td>${escapeHtml(entry.label)}${entry.detail ? `<div class="muted">${escapeHtml(entry.detail)}</div>` : ""}</td>
      <td><button type="button" class="set-danger" data-allowlist-rm="${entry.index}"${writeDisabled(canWrite)}>Remove</button></td>
    </tr>`,
  );
  return `<div class="section-head"><h2>Allowlist</h2>
      <p>Local short-circuit after allow-always. Does not override a Sentrook block.</p></div>
    <div class="table-wrap"><table class="tl">
      <thead><tr><th>#</th><th>Kind</th><th>Tool</th><th>Matcher</th><th></th></tr></thead>
      <tbody>${rows.join("")}</tbody>
    </table></div>`;
}

function asSensitivity(value: string): Sensitivity {
  if (value === "info" || value === "warning" || value === "critical") return value;
  return "strict";
}

function renderSettings(state: SentrookState, opts: NativeViewOpts): string {
  const can = opts.canWrite;
  const att = asSensitivity(state.sensitivity);
  const una = asSensitivity(state.unattendedSensitivity);
  const allowMode = state.allowAll ? "on" : "off";
  return `<div class="section-head"><h2>Settings</h2>
      <p>${can ? "Changes save through the signed-in operator session." : "This connection cannot write. Use an operator.write / admin session, or /sentrook in chat."}</p>
    </div>
    <section class="set-block">
      <p class="lead">Allow-all (attended)</p>
      <div class="seg" role="group">
        ${seg(allowMode === "off", `data-policy-allowall="off"`, "off")}
        ${seg(allowMode === "on", `data-policy-allowall="on"`, "on")}
      </div>
      <p class="hint">${escapeHtml(allowAllHint(allowMode))}</p>
      <p class="lead">Quiet</p>
      <p class="hint">${escapeHtml(quietHint(state.quietUntilMs, opts.now))}</p>
      <div class="row">
        <input data-quiet-value placeholder="30m" ${writeDisabled(can)}>
        <button type="button" data-quiet-set="1"${writeDisabled(can)}>Set quiet</button>
        <button type="button" data-quiet-set="off"${writeDisabled(can)}>Clear</button>
      </div>
    </section>
    <section class="set-block">
      <p class="lead">Attended sensitivity</p>
      <div class="seg" role="group">
        ${SENSITIVITY_BUTTONS.map((token) => seg(att === token, `data-policy-sensitivity="${token}"`, token)).join("")}
      </div>
      <p class="hint">${escapeHtml(sensitivityHint("attended", att))}</p>
      <p class="lead">Unattended sensitivity</p>
      <div class="seg" role="group">
        ${SENSITIVITY_BUTTONS.map((token) => seg(una === token, `data-policy-unattended="${token}"`, token)).join("")}
      </div>
      <p class="hint">${escapeHtml(sensitivityHint("unattended", una))}</p>
    </section>
    <section class="set-block">
      <p class="lead">Feedback</p>
      <div class="seg" role="group">
        ${seg(state.feedbackMode === "submit", `data-policy-feedback="submit"`, "submit")}
        ${seg(state.feedbackMode === "off", `data-policy-feedback="off"`, "off")}
      </div>
      <p class="hint">${escapeHtml(feedbackHint(state.feedbackMode === "off" ? "off" : "submit"))}</p>
      <p class="lead">When /scan fails</p>
      <div class="seg" role="group">
        ${seg(state.onScanError === "review", `data-policy-scan-error="review"`, "review")}
        ${seg(state.onScanError === "deny", `data-policy-scan-error="deny"`, "deny")}
        ${seg(state.onScanError === "allow", `data-policy-scan-error="allow" class="set-warn"`, "allow")}
      </div>
      <p class="hint">${escapeHtml(scanErrorHint(state.onScanError))}</p>
    </section>
    <section class="set-block">
      <p class="lead">Operator log</p>
      <p class="hint">${escapeHtml(state.log.path)} · ${state.log.lines} lines</p>
      <div class="row">
        <label class="field"><span>Retention days</span>
          <input type="number" min="0" max="3650" data-log-days value="${state.log.maxAgeDays}" ${writeDisabled(can)}>
        </label>
        <button type="button" data-log="retention"${writeDisabled(can)}>Save retention</button>
        <button type="button" data-log="purge"${writeDisabled(can)}>Purge aged lines</button>
        <button type="button" class="set-danger" data-log="wipe"${writeDisabled(can)}>Delete log</button>
      </div>
    </section>
    <section class="set-block">
      <p class="lead">Connection</p>
      <button type="button" data-verify="1"${writeDisabled(can)}>Test connection</button>
    </section>`;
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
  return `<header class="top">
      <div class="brand"><h1>Sentrook</h1></div>
      <nav class="tabs" aria-label="Dashboard sections">
        ${tab("reviews", "Reviews", pendingCount ? ` <span class="count ${countClass}">${pendingCount}</span>` : "")}
        ${tab("timeline", "Timeline")}
        ${tab("allowlist", "Allowlist")}
        ${tab("settings", "Settings")}
      </nav>
      <p class="ver">${opts.connected ? (opts.canWrite ? "beta" : "read-only") : "offline"}</p>
    </header>
    <p class="beta-note">Native dashboard is beta — needs OpenClaw 2026.9.2+ with Settings → Labs → Custom plugin UI. Writes use your signed-in operator session, not the iframe cookie.</p>
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
        ${renderReviews(state, opts)}
      </section>
      <section class="panel" data-panel="timeline"${opts.tab === "timeline" ? "" : " hidden"}>
        ${renderTimeline(state)}
      </section>
      <section class="panel" data-panel="allowlist"${opts.tab === "allowlist" ? "" : " hidden"}>
        ${renderAllowlist(state, opts.canWrite)}
      </section>
      <section class="panel" data-panel="settings"${opts.tab === "settings" ? "" : " hidden"}>
        ${renderSettings(state, opts)}
      </section>
    </div>`;
}
