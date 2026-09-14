/**
 * Browser-safe HTML fragments for the operator dashboard panels.
 *
 * Shared by the iframe page (``dashboardPage.ts``) and the native Control UI
 * (``controlUiView.ts``). No ``node:`` imports, no dashboardAuth, and no
 * page-level CSS/JS — those stay in the iframe shell.
 *
 * ``SentrookState`` is assignable: pending ``priorSteps[].resultOk`` is mapped
 * to ``ok`` when rendering the spine.
 */

import {
  escapeHtml,
  highlightCommandHtml,
  operatorSummary,
  ruleMeanings,
  commandSignals,
} from "./dashboardPresent.ts";
import {
  SENSITIVITY_BUTTONS,
  parseSensitivity,
  sensitivityFloorHighlight,
  sessionFloorLabel,
  type Sensitivity,
  type SensitivityScope,
} from "./sessionPolicy.ts";
import {
  allowAllHint,
  feedbackHint,
  quietActiveLine,
  quietHint,
  quietLeftLabel,
  quietRemainingPhrase,
  scanErrorHint,
  sensitivityHint,
} from "./policyCopy.ts";
import { DEFAULT_OIDC_ISSUER } from "./scanEndpoint.ts";
import { sessionDisplayName } from "./hostSessions.ts";
import {
  ALLOW_ALL_OFF,
  ALLOW_ALL_ON,
  CONFIGURE_CLI,
  CONFIGURE_CLI_DOCKER_COMPOSE,
  LOG_PURGE,
  LOG_WIPE,
  VERIFY_CLI,
  allowlistRm,
  allowlistAdd,
  approveAlways,
  approveDeny,
  approveOnce,
  feedbackCmd,
  logRetentionDays,
  logRetentionMib,
  pendingInspect,
  quietAll,
  quietSession,
  resolveChatCommands,
  scanErrorCmd,
  sensitivityCmd,
  sensitivitySession,
  sessionToken,
} from "./dashboardSlashHints.ts";

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
      seq?: number;
      tool: string;
      command: string;
      ok?: boolean;
      resultOk?: boolean;
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
    attendedSensitivity?: Sensitivity | null;
    unattendedSensitivity?: Sensitivity | null;
    pending: number;
    label?: string;
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

export type DashboardPanelOpts = {
  now: number;
  /**
   * Native page: true (mutation buttons). HTTP / iframe: false (slash and
   * ``/approve`` substitutes; this surface cannot save).
   */
  interactive?: boolean;
};

type Severity = "info" | "warning" | "critical";

const SEV_RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

export { escapeHtml } from "./dashboardPresent.ts";

function interactiveOf(opts?: { interactive?: boolean }): boolean {
  return opts?.interactive !== false;
}

function disableAttr(interactive: boolean): string {
  return interactive ? "" : " disabled";
}

function slashCode(cmd: string): string {
  return `<code class="slash-cmd">${escapeHtml(cmd)}</code>`;
}

function slashList(rows: Array<{ label: string; cmd: string }>): string {
  return `<ul class="slash-cmds">${rows
    .map((row) => `<li><span>${escapeHtml(row.label)}</span> ${slashCode(row.cmd)}</li>`)
    .join("")}</ul>`;
}

function currentValue(label: string): string {
  return `<p class="current">Now: <strong>${escapeHtml(label)}</strong></p>`;
}

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

function clipText(value: string, max: number): string {
  const one = value.replace(/\s+/g, " ").trim();
  return one.length <= max ? one : `${one.slice(0, max - 1)}…`;
}

function intentKindChip(kind: string | null | undefined): string {
  const k = (kind ?? "").trim().toLowerCase();
  if (!k || k === "user") return "";
  const label =
    k === "cron"
      ? "Cron"
      : k === "heartbeat"
        ? "Heartbeat"
        : k === "subagent"
          ? "Subagent"
          : k === "system"
            ? "System"
            : k;
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
    case "session-skip":
      return "Skipped (session)";
    case "allowlist-hit":
      return "Allowlisted";
    case "unattended-block":
      return "No cron review card";
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
    case "session":
      return "Session";
    case "allow-all":
      return "Allow-all";
    case "timeout":
      return "Timeout";
    case "host":
      return "Host";
    case "unattended":
      return "Unattended";
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
      return "You";
    case "cancelled":
      return sourceLabel(row.resolutionSource || row.labelSource || "host");
    case "timeout":
      return "Timeout";
    case "allowlist-hit":
      return "Allowlist";
    case "quiet-skip":
      return "Quiet";
    case "lenient-skip":
      return "Lenient";
    case "session-skip":
      return "Session";
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
  interactive: boolean,
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
          ${
            row.decision === "review"
              ? interactive
                ? `<button type="button" data-allowlist-add="${escapeHtml(row.id)}">Allowlist this command</button>`
                : slashList([{ label: "Allowlist this command", cmd: allowlistAdd(row.id) }])
              : ""
          }
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

export function renderTimeline(state: DashboardViewState, opts: DashboardPanelOpts): string {
  const now = opts.now;
  const audit = resolveAudit(state);
  const sessionKeys = [
    ...new Set(state.history.map((row) => row.sessionKey).filter((k): k is string => Boolean(k))),
  ];
  const items = state.history.map((row, i) => renderTimelineItem(row, i, now, interactiveOf(opts))).join("\n");
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

type PriorStep = NonNullable<DashboardViewState["pending"][number]["priorSteps"]>[number];

function normalizePriorStep(step: PriorStep, index: number): {
  seq: number;
  tool: string;
  command: string;
  ok?: boolean;
  excerpt?: string;
} {
  return {
    seq: step.seq ?? index + 1,
    tool: step.tool,
    command: step.command,
    ok: step.ok ?? step.resultOk,
    excerpt: step.excerpt,
  };
}

function renderPastStep(step: ReturnType<typeof normalizePriorStep>): string {
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
  const all = (card.priorSteps ?? []).map(normalizePriorStep);
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
  opts: { resolveAvailable: boolean; now: number; interactive?: boolean },
): string {
  const sev = severityOf(card.scan.review_severity ?? card.scan.decision);
  const risk = riskScore(card.scan.risk);
  const command = formatCommand(card.command);
  const cmdId = `cmd-${card.eventId}`;
  const argsJson = extraArgsJson(card.args, card.command);
  const meanings = ruleMeanings(card.scan.matched_rules);
  const headline = operatorSummary(card.scan.summary) || meanings[0] || "";
  const interactive = interactiveOf(opts);
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
  const legend =
    `<p class="legend">Once = this call. Always = local allowlist (not pipes or curl|bash). Deny = veto; the claw moves on.</p>`;
  const chatCommands = resolveChatCommands(card.approvalId, card.eventId);
  const missingIdHint =
    `<p class="hint">No copyable <code>/approve</code> id yet. Use Allow/Deny on the native Sentrook page, or the approval card OpenClaw posted in chat. Inspect: ${slashCode(pendingInspect(card.eventId))}</p>`;
  const actions = !interactive
    ? `<div class="decide">
        ${legend}
        ${slashList(chatCommands)}
        ${card.approvalId ? "" : missingIdHint}
      </div>`
    : `<div class="decide">
        <button type="button" class="btn-once" data-act="allow-once" data-tool="${escapeHtml(card.toolCallId)}">Allow once</button>
        <button type="button" class="btn-always" data-act="allow-always" data-tool="${escapeHtml(card.toolCallId)}">Allow always</button>
        <button type="button" class="btn-deny" data-act="deny" data-tool="${escapeHtml(card.toolCallId)}">Deny</button>
        ${legend}
        ${
          card.approvalId
            ? `<p class="fallback">If allow/deny fails, paste one of these in chat:</p>${slashList(chatCommands)}`
            : `<p class="fallback">If allow/deny fails, use the approval card OpenClaw posted in chat. There is no copyable <code>/approve</code> id yet.</p>
               <p class="hint">Inspect: ${slashCode(pendingInspect(card.eventId))}</p>`
        }
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
    ${actions}
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
      <p class="hint">Chat: ${
        card.approvalId
          ? `${slashCode(approveOnce(card.approvalId))} · ${slashCode(approveAlways(card.approvalId))} · ${slashCode(approveDeny(card.approvalId))}`
          : slashCode(pendingInspect(card.eventId))
      }</p>
    </details>
      </article>`;
}

function allowAllModeOf(state: DashboardViewState): "off" | "session" | "on" {
  if (state.allowAll) return "on";
  if (state.sessions.some((s) => s.allowAll)) return "session";
  return "off";
}

function segBtn(pressed: boolean, attrs: string, label: string, interactive = true): string {
  return `<button type="button" aria-pressed="${pressed ? "true" : "false"}" ${attrs}${disableAttr(interactive)}>${label}</button>`;
}

function choiceHint(text: string, extraClass = ""): string {
  const cls = extraClass ? `floor-hint ${extraClass}` : "floor-hint";
  return `<p class="${cls}">${escapeHtml(text)}</p>`;
}

const FLOOR_LABEL: Record<Sensitivity, string> = {
  strict: "Strict",
  info: "Info",
  warning: "Warning",
  critical: "Critical",
};

function renderSensitivityFloor(
  scope: SensitivityScope,
  raw: string | undefined,
  interactive = true,
): string {
  const selected = parseSensitivity(raw, "strict");
  const hint = `<p class="floor-hint floor-${selected}">${escapeHtml(sensitivityHint(scope, selected))}</p>`;
  if (!interactive) {
    return `${currentValue(FLOOR_LABEL[selected])}
        ${hint}
        ${slashList(
          SENSITIVITY_BUTTONS.map((level) => ({
            label: FLOOR_LABEL[level],
            cmd: sensitivityCmd(scope, level),
          })),
        )}`;
  }
  const buttons = SENSITIVITY_BUTTONS.map((level) => {
    const mark = sensitivityFloorHighlight(selected, level);
    const pressed = mark === "on";
    const cls = [`floor-${level}`, mark === "off" ? "" : `floor-${mark}`].filter(Boolean).join(" ");
    return segBtn(
      pressed,
      `class="${cls}" data-sens="${level}" data-sens-scope="${scope}"`,
      FLOOR_LABEL[level],
      interactive,
    );
  }).join("\n          ");
  return `<div class="seg seg-floor" role="group" aria-label="${scope} review sensitivity">
          ${buttons}
        </div>
        ${hint}`;
}

export function renderAllowlist(state: DashboardViewState, opts: DashboardPanelOpts = { now: 0 }): string {
  const interactive = interactiveOf(opts);
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
        ${
          interactive
            ? `<button type="button" data-allow-rm="${entry.index}">Remove</button>`
            : slashList([{ label: "Remove", cmd: allowlistRm(entry.index) }])
        }
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
          <p>Same tool and argument shape. Volatile bits (dates, UUIDs, integers) may change. Typical for <code>git status --short</code> or <code>rg -n TODO src/</code>. <code>curl</code>/<code>wget</code> keep the host and path so a trusted fetch is not every URL. A new flag or a different binary is a different skeleton. Pipes and <code>curl | bash</code> are not stored.</p>
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
        : `<div class="empty"><h2>No entries yet</h2><p>Choose Allow always on a review, or <code>/sentrook allowlist add &lt;id&gt;</code> from a history event.</p></div>`
    }`;
}

const SESSION_PREVIEW_LIMIT = 5;

const SESSION_FLOOR_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "default", label: "Default (global)" },
  { value: "strict", label: "Strict" },
  { value: "info", label: "Info" },
  { value: "warning", label: "Warning" },
  { value: "critical", label: "Critical" },
];

function sessionSensSelect(
  scope: SensitivityScope,
  current: Sensitivity | null | undefined,
  sid: string,
  skey: string,
): string {
  const selected = sessionFloorLabel(current);
  const options = SESSION_FLOOR_OPTIONS.map(
    (opt) =>
      `<option value="${opt.value}"${opt.value === selected ? " selected" : ""}>${escapeHtml(opt.label)}</option>`,
  ).join("");
  const caption = scope === "attended" ? "Attended" : "Unattended";
  return `<label class="sess-sens">
            <span>${caption}</span>
            <select data-session-sens="${scope}" data-current="${escapeHtml(selected)}" data-sid="${escapeHtml(sid)}" data-skey="${escapeHtml(skey)}">${options}</select>
          </label>`;
}

function renderSessionRow(
  s: DashboardViewState["sessions"][number],
  now: number,
  interactive: boolean,
): string {
  const quietOn = Boolean(s.quietUntilMs && s.quietUntilMs > now);
  const sessionQuiet = quietOn ? quietLeftLabel(s.quietUntilMs, now) : "off";
  const key = s.sessionKey?.trim() || "—";
  const id = s.sessionId?.trim() || "";
  const named = sessionDisplayName(s);
  const showName = named !== key;
  const showId = Boolean(id && id !== key);
  const pending = s.pending === 1 ? "1 pending" : `${s.pending} pending`;
  const token = sessionToken(s.sessionKey, s.sessionId);
  const attended = sessionFloorLabel(s.attendedSensitivity);
  const unattended = sessionFloorLabel(s.unattendedSensitivity);
  const actions = interactive
    ? `<div class="sess-actions">
          ${sessionSensSelect("attended", s.attendedSensitivity, s.sessionId ?? "", s.sessionKey ?? "")}
          ${sessionSensSelect("unattended", s.unattendedSensitivity, s.sessionId ?? "", s.sessionKey ?? "")}
          ${segBtn(quietOn, `data-policy="quiet" data-on="${quietOn ? "0" : "1"}" data-sid="${escapeHtml(s.sessionId ?? "")}" data-skey="${escapeHtml(s.sessionKey ?? "")}"${quietOn ? ` class="quiet-on"` : ""}`, quietOn ? `Quiet ${sessionQuiet}` : "Quiet 30m")}
        </div>`
    : `<div class="sess-actions">
          ${currentValue(`attended ${attended} · unattended ${unattended} · quiet ${sessionQuiet}`)}
          ${slashList([
            { label: "Attended default", cmd: sensitivitySession(token, "attended", "default") },
            { label: "Attended warning", cmd: sensitivitySession(token, "attended", "warning") },
            { label: "Unattended warning", cmd: sensitivitySession(token, "unattended", "warning") },
            { label: "Quiet 30m", cmd: quietSession(token, "30m") },
            { label: "Quiet off", cmd: quietSession(token, "off") },
          ])}
        </div>`;
  const metaBits = [
    showName ? `<code>${escapeHtml(key)}</code>` : "",
    showId ? `<code>${escapeHtml(id)}</code>` : "",
    pending,
  ].filter(Boolean);
  return `<li class="sess-row">
        <div class="sess-id">
          ${showName ? `<span class="sess-name">${escapeHtml(named)}</span>` : `<code class="sess-key">${escapeHtml(key)}</code>`}
          <span class="sess-meta">${metaBits.join(" · ")}</span>
        </div>
        ${actions}
      </li>`;
}

function renderSessionList(
  sessions: DashboardViewState["sessions"],
  now: number,
  interactive: boolean,
): string {
  if (!sessions.length) {
    return `<p class="hint">No sessions in the OpenClaw store.</p>`;
  }
  const head = sessions.slice(0, SESSION_PREVIEW_LIMIT);
  const rest = sessions.slice(SESSION_PREVIEW_LIMIT);
  const headList = `<ul class="sess-list">${head.map((s) => renderSessionRow(s, now, interactive)).join("\n")}</ul>`;
  if (!rest.length) return headList;
  const n = rest.length;
  return `${headList}
        <details class="sess-more" id="sess-more">
          <summary><span class="sess-more-closed">Show ${n} more session${n === 1 ? "" : "s"}</span><span class="sess-more-open">Show fewer</span></summary>
          <ul class="sess-list">${rest.map((s) => renderSessionRow(s, now, interactive)).join("\n")}</ul>
        </details>`;
}

export function renderSettings(state: DashboardViewState, opts: DashboardPanelOpts): string {
  const now = opts.now;
  const interactive = interactiveOf(opts);
  const mode = allowAllModeOf(state);
  const quietOn = Boolean(state.quietUntilMs && state.quietUntilMs > now);
  const quietChoice = quietHint(state.quietUntilMs, now);
  const quietLine = quietActiveLine(state.quietUntilMs, now);
  const quietBanner = quietLine
    ? `<p class="quiet-status" role="status">Quiet mode active, time remaining: <span data-quiet-until="${state.quietUntilMs ?? ""}">${escapeHtml(quietRemainingPhrase(state.quietUntilMs, now))}</span></p>`
    : "";
  const feedback = state.feedbackMode === "off" ? "off" : "submit";
  const scanErr = state.onScanError === "allow" || state.onScanError === "deny" ? state.onScanError : "review";
  const mib = Math.max(1, Math.round(state.log.maxBytes / (1024 * 1024)));
  const allowAllNow = mode === "on" ? "On for all" : "Off";
  const intro = interactive
    ? "Allow-all and quiet are stored on this host so every plugin isolate sees them. Sensitivity, feedback, scan-error policy, and log retention write to <code>openclaw.json</code> when the gateway can save them."
    : "This panel cannot save changes to state. To change these settings, copy a command into any OpenClaw chat, or open the native Sentrook page. Allow-all and quiet are stored on this host. Sensitivity, feedback, scan-error, and log retention persist in <code>openclaw.json</code> when those commands run.";

  const allowAllControls = interactive
    ? `<div class="seg">
          ${segBtn(mode !== "on", `data-allow-mode="off"`, "Off")}
          ${segBtn(mode === "on", `data-allow-mode="on" class="set-warn"`, "On for all")}
        </div>`
    : `${currentValue(allowAllNow)}
        ${slashList([
          { label: "Allow-all off", cmd: ALLOW_ALL_OFF },
          { label: "Allow-all on for all", cmd: ALLOW_ALL_ON },
        ])}`;

  const quietControls = interactive
    ? `<div class="seg">
          ${segBtn(!quietOn, `data-quiet-global="off"`, "Off")}
          ${segBtn(false, `data-quiet-global="30m"`, "30m")}
          ${segBtn(false, `data-quiet-global="2h"`, "2h")}
          ${segBtn(false, `data-quiet-global="8h"`, "8h")}
        </div>`
    : `${currentValue(quietOn ? quietLeftLabel(state.quietUntilMs, now) : "Off")}
        ${slashList([
          { label: "Quiet off", cmd: quietAll("off") },
          { label: "Quiet 30m", cmd: quietAll("30m") },
          { label: "Quiet 2h", cmd: quietAll("2h") },
          { label: "Quiet 8h", cmd: quietAll("8h") },
        ])}`;

  const feedbackControls = interactive
    ? `<div class="seg">
          ${segBtn(feedback === "submit", `data-feedback="submit"`, "submit")}
          ${segBtn(feedback === "off", `data-feedback="off"`, "off")}
        </div>`
    : `${currentValue(feedback)}
        ${slashList([
          { label: "Submit", cmd: feedbackCmd("submit") },
          { label: "Off", cmd: feedbackCmd("off") },
        ])}`;

  const scanErrorControls = interactive
    ? `<div class="seg">
          ${segBtn(scanErr === "review", `data-scan-error="review"`, "review")}
          ${segBtn(scanErr === "deny", `data-scan-error="deny"`, "deny")}
          ${segBtn(scanErr === "allow", `data-scan-error="allow" class="set-warn"`, "allow")}
        </div>`
    : `${currentValue(scanErr)}
        ${slashList([
          { label: "Review", cmd: scanErrorCmd("review") },
          { label: "Deny", cmd: scanErrorCmd("deny") },
          { label: "Allow", cmd: scanErrorCmd("allow") },
        ])}`;

  const verifyBlock = state.setupNeeded
    ? interactive
      ? `<p class="lead" style="margin-top:1rem">Save credentials on Reviews first, then you can test the connection here.</p>`
      : `<p class="lead" style="margin-top:1rem">Connection</p>
        ${slashList([{ label: "First-run setup", cmd: CONFIGURE_CLI }])}`
    : interactive
      ? `<p class="lead" style="margin-top:1rem">Connection</p>
        <p class="lead">Mint a token against FIDU Identity and ping hosted /health. Same checks as <code>openclaw sentrook verify</code>.</p>
        <button type="button" data-verify="1">Test connection</button>
        <div class="verify-result" data-verify-result hidden></div>`
      : `<p class="lead" style="margin-top:1rem">Connection</p>
        <p class="lead">Mint a token against FIDU Identity and ping hosted /health.</p>
        ${slashList([{ label: "Test connection", cmd: VERIFY_CLI }])}`;

  const logControls = interactive
    ? `<div class="set-fields" style="margin-top:0.85rem">
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
        </div>`
    : `${currentValue(`${state.log.maxAgeDays} days · ${mib} MiB`)}
        ${slashList([
          { label: "Keep days", cmd: logRetentionDays(state.log.maxAgeDays) },
          { label: "Rotate at MiB", cmd: logRetentionMib(mib) },
          { label: "Log purge", cmd: LOG_PURGE },
          { label: "Log wipe", cmd: LOG_WIPE },
        ])}`;

  return `<div class="section-head">
      <h2>Settings</h2>
      <p>${intro}</p>
    </div>
    <div class="settings">
      <section class="set-card">
        <h3>Attended tool review sensitivity</h3>
        <p class="lead">Auto-accept reviews at or below the selected severity while you are present. Each step includes every lower level. Blocks and scan errors still stop. Writes to <code>openclaw.json</code>. A per-session attended floor overrides this, allow-all, and quiet for that session.</p>
        ${renderSensitivityFloor("attended", state.sensitivity, interactive)}
      </section>
      <section class="set-card">
        <h3>Unattended tool review sensitivity</h3>
        <p class="lead">The same floor for cron, heartbeat, and jobs they spawn. Subagents of a chat session stay on the attended floor. Default is strict. Allow-all and quiet do not apply here. A per-session unattended floor overrides this.</p>
        ${renderSensitivityFloor("unattended", state.unattendedSensitivity, interactive)}
      </section>
      <section class="set-card">
        <h3>Allow-all</h3>
        <p class="lead">Auto-accept every future <strong>attended review</strong> — soft and hard. Scan still runs. Does not override a <strong>block</strong> or a scan error. Unattended runs use the unattended sensitivity above, not this switch. Sessions with their own attended floor ignore this. Per session Quiet can be set in the Per session section below.</p>
        ${allowAllControls}
        ${choiceHint(allowAllHint(mode))}
      </section>
      <section class="set-card${quietOn ? " set-card-quiet" : ""}">
        <h3>Quiet</h3>
        <p class="lead">Same skip as allow-all, with a TTL (max 8 hours). This row is gateway-wide. Sessions with their own attended floor ignore quiet. Per session Quiet can be set in the Per session section below. Unattended runs use the unattended sensitivity above.</p>
        ${quietBanner}
        ${quietControls}
        ${choiceHint(quietChoice, quietOn ? "floor-warning" : "")}
      </section>
      <section class="set-card" id="set-sessions">
        <h3>Per session</h3>
        <p class="lead">OpenClaw sessions from the same store as Control UI. Attended and unattended floors stick by session key across restart and session end; Default inherits the matching global floor. A set attended floor overrides global attended, allow-all, and quiet. Quiet still applies only while attended is Default, and still clears when the session ends.</p>
        ${renderSessionList(state.sessions, now, interactive)}
        ${
          mode === "on"
            ? choiceHint("Global allow-all is on. Sessions with their own attended floor ignore it; leftover session allow-all flags on Default sessions are ignored until you switch off.")
            : ""
        }
      </section>
      <section class="set-card">
        <h3>Plugin config</h3>
        <p class="lead">${interactive ? "Writes <code>plugins.entries.sentrook-openclaw.config</code>. Environment variables still win after a restart. Scan origin and credentials stay out of this page." : "Shown values are current policy. Change them with the commands below, or on the native Sentrook page. Scan origin and credentials stay out of this page."}</p>
        <p class="lead">Submit feedback</p>
        ${feedbackControls}
        ${choiceHint(feedbackHint(feedback))}
        <p class="lead" style="margin-top:1rem">When /scan fails</p>
        ${scanErrorControls}
        ${choiceHint(scanErrorHint(scanErr))}
        ${verifyBlock}
      </section>
      <section class="set-card">
        <h3>Operator log</h3>
        <p class="lead">Local JSONL on this host. Never uploaded. Timeline reads from here.</p>
        <p class="log-meta"><code>${escapeHtml(state.log.path)}</code><br>
          ${state.log.lines} lines · ${fmtBytes(state.log.bytes)} · ${state.log.enabled ? "on" : "off"}</p>
        ${logControls}
      </section>
    </div>`;
}

export function renderSetup(state: DashboardViewState, opts: DashboardPanelOpts = { now: 0 }): string {
  const interactive = interactiveOf(opts);
  const identity = DEFAULT_OIDC_ISSUER;
  const scanErr =
    state.onScanError === "allow" || state.onScanError === "deny" ? state.onScanError : "review";
  if (!interactive) {
    return `<div class="setup">
      <p class="empty-kicker">First-run setup</p>
      <h2>Connect hosted Sentrook</h2>
      <p class="setup-copy">To use hosted Sentrook you need a free FIDU membership with a Sentrook OAuth client.</p>
      <p class="setup-copy">Visit <a href="${escapeHtml(identity)}" target="_blank" rel="noopener noreferrer">${escapeHtml(identity)}</a> — log in or create an account (free membership is all that's required).</p>
      <p class="setup-copy">Create credentials on the Sentrook tab of your Identity dashboard, then run the command below in a terminal/CLI. This panel cannot write scan credentials.</p>
      ${slashList([{ label: "First-run setup", cmd: CONFIGURE_CLI }])}
      ${slashList([{ label: "Docker compose users", cmd: CONFIGURE_CLI_DOCKER_COMPOSE }])}
    </div>`;
  }
  return `<div class="setup">
      <p class="empty-kicker">First-run setup</p>
      <h2>Connect hosted Sentrook</h2>
      <p class="setup-copy">To use hosted Sentrook you need a free FIDU membership with a Sentrook OAuth client.</p>
      <p class="setup-copy">Visit <a href="${escapeHtml(identity)}" target="_blank" rel="noopener noreferrer">${escapeHtml(identity)}</a> — log in or create an account (free membership is all that's required).</p>
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

export function renderReviews(state: DashboardViewState, opts: DashboardPanelOpts): string {
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
        now: opts.now,
        interactive: opts.interactive,
      }),
    )
    .join("\n");
  return `${jump}${cards}`;
}

export function renderReviewsPanel(state: DashboardViewState, opts: DashboardPanelOpts): string {
  if (state.setupNeeded) return renderSetup(state, opts);
  return `<div class="section-head">
        <h2>Pending reviews</h2>
        <p>Full local command and scan detail — not bound by chat card limits.</p>
      </div>
      ${renderReviews(state, opts)}`;
}

