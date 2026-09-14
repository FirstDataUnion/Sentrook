/**
 * Operator-facing presentation for the /sentrook dashboard: dangerous-span
 * highlighting, AIRA-id → meaning labels, and scan-summary cleanup.
 *
 * Highlighting follows the same signals review-card copy and the corpus care
 * about: outbound URLs, credential/SSH/config paths, rm -rf, pipe-to-shell.
 * Rule ids never appear in the HTML — operators see the meaning, not AIRA-010.
 */

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export type HighlightKind = "url" | "path" | "destroy" | "pipe";

export type HighlightSpan = {
  start: number;
  end: number;
  kind: HighlightKind;
};

const KIND_TITLE: Record<HighlightKind, string> = {
  url: "Outbound URL",
  path: "Sensitive path",
  destroy: "Destructive command",
  pipe: "Pipe to shell",
};

const KIND_RANK: Record<HighlightKind, number> = {
  destroy: 0,
  path: 1,
  pipe: 2,
  url: 3,
};

const URL_RE = /https?:\/\/[^\s"'<>\\]+/gi;

/** Linear needle scan — do not use `[~/\w.-]*marker` (CodeQL js/polynomial-redos). */
const SECRET_PATH_MARKERS: ReadonlyArray<{
  needle: string;
  afterSlash: "none" | "optional" | "required";
  extraDotSuffix: boolean;
}> = [
  { needle: "openclaw-agent.sqlite", afterSlash: "none", extraDotSuffix: false },
  { needle: "auth-profiles.json", afterSlash: "none", extraDotSuffix: false },
  { needle: "database.sqlite", afterSlash: "none", extraDotSuffix: false },
  { needle: "openclaw.json", afterSlash: "none", extraDotSuffix: false },
  { needle: "openclaw-auth-intake", afterSlash: "required", extraDotSuffix: false },
  { needle: ".ssh", afterSlash: "optional", extraDotSuffix: false },
  { needle: "/.env", afterSlash: "none", extraDotSuffix: true },
  { needle: "credentials", afterSlash: "optional", extraDotSuffix: false },
  { needle: "id_rsa", afterSlash: "none", extraDotSuffix: false },
  { needle: "id_ed25519", afterSlash: "none", extraDotSuffix: false },
  { needle: "authorized_keys", afterSlash: "none", extraDotSuffix: false },
  { needle: "known_hosts", afterSlash: "none", extraDotSuffix: false },
  { needle: "/etc/shadow", afterSlash: "none", extraDotSuffix: false },
  { needle: "/etc/passwd", afterSlash: "none", extraDotSuffix: false },
  { needle: "/etc/sudoers", afterSlash: "none", extraDotSuffix: false },
  { needle: "/etc/", afterSlash: "required", extraDotSuffix: false },
  { needle: ".openclaw", afterSlash: "optional", extraDotSuffix: false },
];

/**
 * Short operator labels from corpus rule intent. Unknown ids are dropped —
 * never fall back to showing AIRA-010.
 */
export const RULE_MEANING: Record<string, string> = {
  "AIRA-001": "Fetch then risky exec",
  "AIRA-002": "Fetch then write",
  "AIRA-010": "High-risk shell",
  "AIRA-020": "Pipe to shell",
  "AIRA-030": "Write to /etc",
  "AIRA-031": "Fetch then sensitive write",
  "AIRA-032": "SSH / credential path",
  "AIRA-040": "Search then write",
  "AIRA-050": "Standing instructions",
  "AIRA-051": "Fetch then memory write",
  "AIRA-052": "Credential read then outbound",
  "AIRA-053": "Credential read then message",
  "AIRA-054": "Supply-chain install",
  "AIRA-055": "Obfuscated remote shell",
  "AIRA-056": "Search then memory write",
  "AIRA-057": "Read then memory write",
  "AIRA-058": "Fetch then exec",
  "AIRA-060": "Skill doc then SSH exfil",
  "AIRA-062": "Hook shell exfil",
  "AIRA-063": "Ingest then exfil message",
  "AIRA-064": "Read then exec",
  "AIRA-065": "Poisoned ingest",
  "AIRA-066": "Skill scope mismatch",
  "AIRA-067": "Credential path + outbound upload",
  "AIRA-068": "Secret-shaped message",
  "AIRA-069": "Subagent credential exfil",
  "AIRA-071": "Ingest then memory exfil",
};

const DESTROY_VERBS = ["rm", "rmdir", "unlink", "shred"] as const;
const PIPE_SHELLS = ["bash", "sh", "zsh", "dash"] as const;

function isPathPrefixChar(ch: string): boolean {
  const code = ch.charCodeAt(0);
  if (code === 126 || code === 47 || code === 46 || code === 45 || code === 95) return true;
  if (code >= 48 && code <= 57) return true;
  if (code >= 65 && code <= 90) return true;
  if (code >= 97 && code <= 122) return true;
  return false;
}

function consumeUnquotedTail(text: string, start: number): number {
  let i = start;
  while (i < text.length) {
    const ch = text[i] ?? "";
    if (!ch || ch === '"' || ch === "'" || ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      break;
    }
    i += 1;
  }
  return i;
}

function stripUrlTrailingPunct(raw: string): string {
  let end = raw.length;
  while (end > 0) {
    const code = raw.charCodeAt(end - 1);
    if (code !== 41 && code !== 46 && code !== 44 && code !== 59 && code !== 93) break;
    end -= 1;
  }
  return raw.slice(0, end);
}

function isWordStart(text: string, index: number): boolean {
  if (index <= 0) return true;
  const prev = text[index - 1] ?? "";
  return /[^A-Za-z0-9_]/.test(prev);
}

function addSpan(spans: HighlightSpan[], start: number, end: number, kind: HighlightKind): void {
  if (end <= start) return;
  spans.push({ start, end, kind });
}

function findUrlSpans(text: string): HighlightSpan[] {
  const spans: HighlightSpan[] = [];
  URL_RE.lastIndex = 0;
  for (const match of text.matchAll(URL_RE)) {
    const raw = match[0] ?? "";
    const url = stripUrlTrailingPunct(raw);
    const start = match.index ?? 0;
    addSpan(spans, start, start + url.length, "url");
  }
  return spans;
}

function findPathSpans(text: string): HighlightSpan[] {
  const spans: HighlightSpan[] = [];
  const lower = text.toLowerCase();
  for (const marker of SECRET_PATH_MARKERS) {
    let from = 0;
    while (from < lower.length) {
      const idx = lower.indexOf(marker.needle, from);
      if (idx < 0) break;
      let start = idx;
      while (start > 0 && isPathPrefixChar(text[start - 1] ?? "")) start -= 1;
      let end = idx + marker.needle.length;
      if (marker.afterSlash !== "none" && text[end] === "/") {
        const tailEnd = consumeUnquotedTail(text, end + 1);
        if (marker.afterSlash === "optional" || tailEnd > end + 1) end = tailEnd;
      } else if (marker.extraDotSuffix && text[end] === ".") {
        end = consumeUnquotedTail(text, end + 1);
      }
      addSpan(spans, start, end, "path");
      from = idx + marker.needle.length;
    }
  }
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "@") continue;
    const next = text[i + 1] ?? "";
    if (next !== "~" && next !== "/" && next !== ".") continue;
    const end = consumeUnquotedTail(text, i + 1);
    addSpan(spans, i, end, "path");
  }
  return spans;
}

function findDestroySpans(text: string): HighlightSpan[] {
  const spans: HighlightSpan[] = [];
  const lower = text.toLowerCase();
  for (const verb of DESTROY_VERBS) {
    let from = 0;
    while (from < lower.length) {
      const idx = lower.indexOf(verb, from);
      if (idx < 0) break;
      const after = idx + verb.length;
      if (!isWordStart(text, idx) || /[A-Za-z0-9_]/.test(text[after] ?? "")) {
        from = after;
        continue;
      }
      let i = after;
      while (text[i] === " " || text[i] === "\t") i += 1;
      while (text[i] === "-") {
        i = consumeUnquotedTail(text, i);
        while (text[i] === " " || text[i] === "\t") i += 1;
      }
      if (text[i] && text[i] !== "\n") i = consumeUnquotedTail(text, i);
      addSpan(spans, idx, Math.max(i, after), "destroy");
      from = after;
    }
  }
  return spans;
}

function findPipeSpans(text: string): HighlightSpan[] {
  const spans: HighlightSpan[] = [];
  const lower = text.toLowerCase();
  let from = 0;
  while (from < text.length) {
    const idx = text.indexOf("|", from);
    if (idx < 0) break;
    let i = idx + 1;
    while (text[i] === " " || text[i] === "\t") i += 1;
    const rest = lower.slice(i);
    const shell = PIPE_SHELLS.find((name) => rest.startsWith(name) && !/[a-z0-9_]/.test(rest[name.length] ?? " "));
    if (shell) addSpan(spans, idx, i + shell.length, "pipe");
    from = idx + 1;
  }
  return spans;
}

export function findDangerousSpans(text: string): HighlightSpan[] {
  return mergeSpans([
    ...findUrlSpans(text),
    ...findPathSpans(text),
    ...findDestroySpans(text),
    ...findPipeSpans(text),
  ]);
}

function mergeSpans(spans: HighlightSpan[]): HighlightSpan[] {
  const sorted = spans.slice().sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    const rank = KIND_RANK[a.kind] - KIND_RANK[b.kind];
    if (rank !== 0) return rank;
    return b.end - a.end;
  });
  const out: HighlightSpan[] = [];
  let cursor = -1;
  for (const span of sorted) {
    if (span.start < cursor) continue;
    out.push(span);
    cursor = span.end;
  }
  return out;
}

export function highlightCommandHtml(command: string): string {
  const spans = findDangerousSpans(command);
  let html = "";
  let i = 0;
  for (const span of spans) {
    html += escapeHtml(command.slice(i, span.start));
    html += `<mark class="hl hl-${span.kind}" title="${escapeHtml(KIND_TITLE[span.kind])}">${escapeHtml(command.slice(span.start, span.end))}</mark>`;
    i = span.end;
  }
  html += escapeHtml(command.slice(i));
  return html;
}

export function ruleMeanings(ids: string[] | undefined, winningId?: string | null): string[] {
  const raw = [...(ids ?? [])];
  if (winningId) {
    const needle = winningId.trim().toUpperCase();
    const i = raw.findIndex((id) => id.trim().toUpperCase() === needle);
    if (i > 0) {
      const [win] = raw.splice(i, 1);
      if (win) raw.unshift(win);
    }
  }
  const seen = new Set<string>();
  const labels: string[] = [];
  for (const id of raw) {
    const label = RULE_MEANING[id.trim().toUpperCase()];
    if (!label || seen.has(label)) continue;
    seen.add(label);
    labels.push(label);
  }
  return labels;
}

export function commandSignals(command: string): Array<{ kind: HighlightKind; text: string; title: string }> {
  return findDangerousSpans(command).map((span) => ({
    kind: span.kind,
    text: command.slice(span.start, span.end),
    title: KIND_TITLE[span.kind],
  }));
}

export function operatorSummary(summary: string | undefined): string {
  if (!summary) return "";
  return summary
    .replace(/^(Review triggered by|Blocked by)\s+AIRA-\d+\s*:?\s*/i, "")
    .replace(/\bAIRA-\d+\b/g, "")
    .replace(/\s{2,}/g, " ")
    .replace(/^[:\-–—]\s*/, "")
    .trim();
}

export function pendingFingerprint(
  pending: Array<{ eventId: string; toolCallId?: string }>,
): string {
  return pending
    .map((card) => `${card.eventId}:${card.toolCallId ?? ""}`)
    .sort()
    .join("|");
}

/** Same formula the dashboard poll uses — reload only when this changes. */
export function dashboardFingerprint(state: {
  pending: Array<{ eventId: string; toolCallId?: string }>;
  history?: Array<{
    id?: string;
    resolution?: string;
    resultOk?: boolean;
    decision?: string;
  }>;
  setupNeeded?: boolean;
}): string {
  const pending = pendingFingerprint(state.pending);
  const hist = (state.history ?? [])
    .map((row) => {
      const ok = row.resultOk === true ? "1" : row.resultOk === false ? "0" : "";
      return `${row.id ?? ""}:${row.resolution ?? ""}:${ok}:${row.decision ?? ""}`;
    })
    .join("|");
  return `${pending}#${hist}#${state.setupNeeded ? "1" : "0"}`;
}
