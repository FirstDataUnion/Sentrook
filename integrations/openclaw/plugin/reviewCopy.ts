/**
 * Operator-facing exec review copy for OpenClaw requireApproval.
 *
 * OpenClaw maps ``title`` → Command (80 chars) and ``description`` → Shell
 * Preview (256). Cards are rebuilt from local pending args so hosted PlanIR
 * truncation cannot hide the action. Secrets are still scrubbed because
 * Discord/Telegram forward the same strings.
 *
 * Title ladder (structural, not product-specific): destination, sensitive
 * operand, packed argv, then an honest miss. Never a rule id.
 */

import { stringifyArgValue } from "./planir.ts";
import { packSignalExcerpt, scrubSecrets } from "./sanitize.ts";

export const REVIEW_TITLE_MAX = 80;
export const REVIEW_DESCRIPTION_MAX = 256;

const TRUNCATED_TOKEN = "[TRUNCATED]";
const MIN_COMMAND_CHARS = 16;
const PAYLOAD_COLLAPSE_MIN = 48;
const PAYLOAD_PREVIEW = 40;

const EXEC_COMMAND_KEYS = ["command", "cmd", "shell", "script", "line"] as const;
const BODY_FLAGS = new Set([
  "-d",
  "--data",
  "--data-raw",
  "--data-binary",
  "--data-urlencode",
  "--data-ascii",
  "-F",
  "--form",
  "-m",
  "--message",
  "--content",
  "--body",
  "--json",
  "--payload",
]);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);
const PRIMARY_VERBS = [
  "curl",
  "wget",
  "python3",
  "python",
  "openclaw",
  "gog",
  "ntn",
  "npx",
  "bash",
  "sh",
] as const;

const URL_RE = /https?:\/\/[^\s"'<>\\]+/gi;
const UPLOAD_RE =
  /(?:-F|--form|--upload-file|--data-binary?|-d)\s+[^\s]*@([^\s"']+)|(?:-F|--form)\s+["']?[^=\s]+=@([^\s"']+)/gi;
const HTTP_VERB_RE = /\b(?:curl|wget|urllib|requests)\b/i;

// Linear token scan — do not use `[~/\w.-]*marker` (CodeQL js/polynomial-redos).
const SECRET_PATH_MARKERS: ReadonlyArray<{
  needle: string;
  afterSlash: "none" | "optional" | "required";
  extraDotSuffix: boolean;
}> = [
  { needle: "openclaw-agent.sqlite", afterSlash: "none", extraDotSuffix: false },
  { needle: "auth-profiles.json", afterSlash: "none", extraDotSuffix: false },
  { needle: "database.sqlite", afterSlash: "none", extraDotSuffix: false },
  { needle: ".ssh", afterSlash: "required", extraDotSuffix: false },
  { needle: "/.env", afterSlash: "none", extraDotSuffix: true },
  { needle: "credentials", afterSlash: "optional", extraDotSuffix: false },
];

export function pendingDisplayCommand(
  args: Record<string, unknown> | undefined,
): string | undefined {
  if (!args) return undefined;
  for (const key of EXEC_COMMAND_KEYS) {
    if (!(key in args)) continue;
    const text = stringifyArgValue(args[key]).trim();
    if (text && text !== TRUNCATED_TOKEN) return text;
  }
  return undefined;
}

export function isPolicyHeadline(title: string): boolean {
  return title.trim().toLowerCase().startsWith("sentrook review:");
}

export function honestMissTitle(tool: string): string {
  if (tool === "exec") return "exec: no command preview";
  return clip(`${tool}: no preview`, REVIEW_TITLE_MAX);
}

function clip(text: string, limit: number): string {
  const trimmed = text.trim();
  if (trimmed.length <= limit) return trimmed;
  if (limit <= 3) return trimmed.slice(0, limit);
  return `${trimmed.slice(0, limit - 3)}...`;
}

function collapseWs(text: string): string {
  return text.trim().replace(/\s+/g, " ");
}

function redactWebhookUrls(text: string): string {
  return text.replace(URL_RE, (raw) => {
    const url = raw.replace(/[).,;\]]+$/, "");
    const trailing = raw.slice(url.length);
    if (!isWebhookUrl(url)) return raw;
    const host = hostFromUrl(url) || "host";
    return `https://${host}/[redacted-webhook]${trailing}`;
  });
}

function displayScrub(text: string): string {
  return scrubSecrets(redactWebhookUrls(text));
}

function commandUrls(command: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  URL_RE.lastIndex = 0;
  for (const match of command.matchAll(URL_RE)) {
    const url = (match[0] ?? "").replace(/[).,;\]]+$/, "");
    const key = url.toLowerCase();
    if (!url || seen.has(key)) continue;
    seen.add(key);
    found.push(url);
  }
  return found;
}

function hostFromUrl(url: string): string | undefined {
  try {
    const host = new URL(url).hostname;
    return host || undefined;
  } catch {
    return undefined;
  }
}

function isLoopbackHost(host: string | undefined): boolean {
  if (!host) return false;
  const lower = host.toLowerCase().split("%")[0] ?? host;
  return LOOPBACK_HOSTS.has(lower) || lower.endsWith(".localhost");
}

function isWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();
    const host = parsed.hostname.toLowerCase();
    if (host.startsWith("hooks.")) return true;
    return path.includes("/webhook") || path.includes("/hooks/");
  } catch {
    const lower = url.toLowerCase();
    return lower.includes("/webhook") || lower.includes("/hooks/");
  }
}

function looksLikeUrlOrPath(text: string): boolean {
  const stripped = text.trim();
  if (!stripped) return false;
  if (stripped.startsWith("@") || stripped.startsWith("/") || stripped.startsWith("~")) {
    return true;
  }
  return /^https?:\/\//i.test(stripped);
}

function isSecretPathPrefixChar(ch: string): boolean {
  // Same class as the old `[~/\w.-]` prefix, one character at a time.
  const code = ch.charCodeAt(0);
  if (code === 126 || code === 47 || code === 46 || code === 45 || code === 95) {
    return true; // ~ / . - _
  }
  if (code >= 48 && code <= 57) return true; // 0-9
  if (code >= 65 && code <= 90) return true; // A-Z
  if (code >= 97 && code <= 122) return true; // a-z
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

function firstSecretPath(text: string): string | undefined {
  const lower = text.toLowerCase();
  let bestStart = -1;
  let bestEnd = -1;
  for (const marker of SECRET_PATH_MARKERS) {
    const idx = lower.indexOf(marker.needle);
    if (idx < 0) continue;
    let start = idx;
    while (start > 0 && isSecretPathPrefixChar(text[start - 1] ?? "")) {
      start -= 1;
    }
    let end = idx + marker.needle.length;
    if (marker.afterSlash !== "none" && text[end] === "/") {
      const tailEnd = consumeUnquotedTail(text, end + 1);
      if (marker.afterSlash === "optional" || tailEnd > end + 1) {
        end = tailEnd;
      }
    } else if (marker.extraDotSuffix && text[end] === ".") {
      end = consumeUnquotedTail(text, end + 1);
    }
    if (bestStart < 0 || start < bestStart) {
      bestStart = start;
      bestEnd = end;
    }
  }
  if (bestStart < 0) return undefined;
  return text.slice(bestStart, bestEnd);
}

function firstUploadPath(text: string): string | undefined {
  UPLOAD_RE.lastIndex = 0;
  const match = UPLOAD_RE.exec(text);
  const path = match?.[1] || match?.[2];
  if (!path || path === "-" || path === "/dev/stdin") return undefined;
  return path.replace(/;type=[^;"'\s]+/gi, "");
}

function shortenPath(path: string, maxLen: number): string {
  const trimmed = path.trim();
  if (trimmed.length <= maxLen) return trimmed;
  return `…${trimmed.slice(-(maxLen - 1))}`;
}

function pathLeaf(path: string): string {
  let end = path.length;
  while (end > 0 && path.charCodeAt(end - 1) === 47) {
    end -= 1;
  }
  const trimmed = path.slice(0, end);
  const slash = trimmed.lastIndexOf("/");
  return slash === -1 ? trimmed : trimmed.slice(slash + 1) || trimmed;
}

function primaryExecVerb(command: string): string {
  const collapsed = collapseWs(command);
  for (const candidate of PRIMARY_VERBS) {
    const re = new RegExp(`(?:^|[\\s;|&]|\\$\\()${candidate}\\b`, "i");
    if (re.test(collapsed)) return candidate;
  }
  const raw = collapsed.split(" ", 1)[0] || "cmd";
  return raw.includes("/") ? (raw.split("/").pop() ?? raw) : raw;
}

function payloadStub(body: string, quote: string): string {
  const stripped = body.trim();
  let preview = "…";
  try {
    const data: unknown = JSON.parse(stripped);
    if (data && typeof data === "object" && !Array.isArray(data)) {
      preview = "{…}";
      const record = data as Record<string, unknown>;
      for (const key of ["content", "text", "body", "message", "caption"]) {
        const value = record[key];
        if (typeof value === "string" && value.trim()) {
          let shown = collapseWs(value).split(quote).join("");
          if (shown.length > PAYLOAD_PREVIEW) {
            shown = `${shown.slice(0, PAYLOAD_PREVIEW - 1)}…`;
          }
          preview = `{${key}: ${shown}}`;
          break;
        }
      }
    } else if (Array.isArray(data)) {
      preview = "[…]";
    }
  } catch {
    /* not JSON */
  }
  return `${quote}${preview}${quote}`;
}

function shouldCollapsePayload(previousToken: string, body: string): boolean {
  if (body.length < PAYLOAD_COLLAPSE_MIN) return false;
  if (looksLikeUrlOrPath(body)) return false;
  const flag = previousToken.split("=", 1)[0]?.toLowerCase() ?? "";
  if (BODY_FLAGS.has(flag)) return true;
  const stripped = body.trim();
  return stripped.startsWith("{") || stripped.startsWith("[");
}

/** Replace long quoted JSON/message bodies; keep URLs and paths. Linear scan. */
export function collapseLongPayloads(command: string): string {
  let out = "";
  let i = 0;
  let prevToken = "";
  let token = "";

  const flushToken = () => {
    if (token) {
      prevToken = token;
      token = "";
    }
  };

  while (i < command.length) {
    const ch = command[i] ?? "";
    if (ch === "'" || ch === '"') {
      const quote = ch;
      i += 1;
      let body = "";
      while (i < command.length) {
        const cur = command[i] ?? "";
        if (cur === "\\" && i + 1 < command.length) {
          body += cur + (command[i + 1] ?? "");
          i += 2;
          continue;
        }
        if (cur === quote) {
          i += 1;
          break;
        }
        body += cur;
        i += 1;
      }
      out += shouldCollapsePayload(prevToken, body)
        ? payloadStub(body, quote)
        : `${quote}${body}${quote}`;
      prevToken = "";
      token = "";
      continue;
    }
    if (/\s/.test(ch) || ";|&".includes(ch)) {
      flushToken();
      out += ch;
      i += 1;
      continue;
    }
    token += ch;
    out += ch;
    i += 1;
  }
  return out;
}

export function structuralIntent(command: string, tool = "exec"): string | undefined {
  const url = commandUrls(command)[0];
  const upload = firstUploadPath(command);
  const secret = firstSecretPath(command);
  if (url) {
    const host = hostFromUrl(url);
    if (isWebhookUrl(url)) return "post a webhook message";
    if (isLoopbackHost(host)) return "call a local service";
    if (upload) return host ? `upload a file to ${host}` : "upload a file";
    if (HTTP_VERB_RE.test(command)) {
      return host ? `send an outbound HTTP request to ${host}` : "send an outbound HTTP request";
    }
    return host ? `contact ${host}` : undefined;
  }
  if (upload) return "upload a file";
  if (secret) return "access a sensitive path";
  if (tool === "exec") return undefined;
  return undefined;
}

export function buildCommandTitle(command: string): string {
  const url = commandUrls(command)[0];
  const secret = firstUploadPath(command) ?? firstSecretPath(command);
  const collapsed = collapseLongPayloads(collapseWs(displayScrub(command)));
  const verb = primaryExecVerb(collapsed);

  if (url && secret) {
    const host = hostFromUrl(url) || url;
    const leaf = pathLeaf(secret);
    if (isLoopbackHost(host)) return clip(`local: ${leaf}`, REVIEW_TITLE_MAX);
    return clip(`${leaf} → ${host}`, REVIEW_TITLE_MAX);
  }
  if (url) {
    const host = hostFromUrl(url) || url;
    if (isWebhookUrl(url)) return clip(`webhook → ${host}`, REVIEW_TITLE_MAX);
    if (isLoopbackHost(host)) return clip(`local → ${host}`, REVIEW_TITLE_MAX);
    return clip(`${verb} → ${host}`, REVIEW_TITLE_MAX);
  }
  if (secret) {
    return clip(`${verb} ${shortenPath(secret, 40)}`, REVIEW_TITLE_MAX);
  }
  return clip(packSignalExcerpt(collapsed, REVIEW_TITLE_MAX), REVIEW_TITLE_MAX);
}

export function buildCommandDescription(command: string, tool = "exec"): string {
  const collapsed = collapseLongPayloads(displayScrub(command));
  const intent = structuralIntent(command, tool);
  if (intent) {
    const intentLine = `Likely: ${intent}`;
    const budget = Math.max(
      MIN_COMMAND_CHARS,
      REVIEW_DESCRIPTION_MAX - intentLine.length - 1,
    );
    const excerpt = packSignalExcerpt(collapsed, budget);
    const body = `${intentLine}\n${excerpt}`;
    if (body.length <= REVIEW_DESCRIPTION_MAX) return body;
    return clip(intentLine, REVIEW_DESCRIPTION_MAX);
  }
  return clip(packSignalExcerpt(collapsed, REVIEW_DESCRIPTION_MAX), REVIEW_DESCRIPTION_MAX);
}

export function buildApprovalCard(input: {
  command?: string;
  tool?: string;
  path?: string;
}): { title: string; description: string; commandFound: boolean } {
  const tool = input.tool ?? "exec";
  const usable = input.command?.trim();
  if (usable && usable !== TRUNCATED_TOKEN) {
    return {
      title: buildCommandTitle(usable),
      description: buildCommandDescription(usable, tool),
      commandFound: true,
    };
  }
  if (input.path?.trim()) {
    const leaf = shortenPath(input.path.trim(), 48);
    return {
      title: clip(`${tool}: ${leaf}`, REVIEW_TITLE_MAX),
      description: clip(`\`${tool}\` \`${leaf}\``, REVIEW_DESCRIPTION_MAX),
      commandFound: false,
    };
  }
  const miss = honestMissTitle(tool);
  return {
    title: miss,
    description: clip(`${tool}: command was not available to summarise`, REVIEW_DESCRIPTION_MAX),
    commandFound: false,
  };
}

/**
 * Build OpenClaw title/description from local pending args when available.
 *
 * Local argv always wins. Sidecar copy is kept only when there is no local
 * command *and* the sidecar title is not a policy headline.
 */
export function overlayApprovalCopy(input: {
  scanTitle?: string;
  scanDescription?: string;
  fallbackTitle: string;
  fallbackDescription: string;
  pendingTool: string;
  pendingArgs?: Record<string, unknown>;
}): { title: string; description: string } {
  const localCommand = pendingDisplayCommand(input.pendingArgs);
  if (localCommand) {
    const card = buildApprovalCard({ command: localCommand, tool: input.pendingTool });
    return { title: card.title, description: card.description };
  }

  const titleIn = input.scanTitle?.trim() || input.fallbackTitle;
  const descriptionIn = input.scanDescription?.trim() || input.fallbackDescription;
  const title = isPolicyHeadline(titleIn)
    ? honestMissTitle(input.pendingTool)
    : clip(titleIn, REVIEW_TITLE_MAX);
  return {
    title,
    description: clip(descriptionIn, REVIEW_DESCRIPTION_MAX),
  };
}
