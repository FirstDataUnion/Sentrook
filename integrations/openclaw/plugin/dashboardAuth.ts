/**
 * Plugin-managed dashboard auth for ``/sentrook``.
 *
 * Control UI gateway-auth tabs use a 5-minute GET-only cookie the iframe
 * cannot remint. Like Avatar / diffs / clawg-ui, this route is ``auth: "plugin"``
 * plus a process token on the Control UI tab path (hello is operator.admin-only).
 * That token is the credential: it does not expire until the gateway restarts,
 * and a custom header is not sent by cross-site forms, so a separate CSRF
 * session is not used.
 *
 * The Control UI tab is a sandboxed iframe (``Origin: null``). Fetches from
 * that page are cross-origin, so API responses allow that opaque origin (and
 * same-host) and OPTIONS is answered without the token. Arbitrary sites are
 * not reflected. POSTs use ``text/plain`` JSON so a custom-header preflight
 * is not required if the gateway never forwards OPTIONS.
 *
 * Control UI remounts plugin tabs by pathname (query is stripped). The tab
 * path is therefore ``/sentrook/tab/<token>``. Mutations POST that exact
 * pathname with ``_srk`` / ``_tok`` so a Control UI remount/proxy that only
 * allows the descriptor path cannot 401 nested ``/api`` URLs. GET still accepts a leftover ``sentrook_access`` cookie for
 * a remount of bare ``/sentrook``; the page does not mint one. POST still
 * requires the query, header, or path token so a cookie is not a CSRF
 * stand-in. The host 401s GET fetches to this path (document navigation
 * still works; POST ``_tok`` still works). The page therefore does not poll
 * or refetch HTML. ``location.reload()`` drops allow-scripts; Cmd/Ctrl+R
 * and F5 are intercepted so the iframe is not navigated. Control UI
 * remounts can still strip ``allow-scripts``. The banner shows the panel
 * URL as selectable text (clipboard is often blocked in that sandbox).
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

export const ACCESS_HEADER = "x-sentrook-access";
export const ACCESS_QUERY = "access";
export const ACCESS_COOKIE = "sentrook_access";
export const DASHBOARD_PATH = "/sentrook";
export const DASHBOARD_TAB_PREFIX = `${DASHBOARD_PATH}/tab/`;
export const DASHBOARD_API_PATH = "/sentrook/api";
export const ACCESS_MISSING = "Open this panel from the Control UI Sentrook tab.";

const TOKEN_BYTES = 24;
const TAB_PATH_PREFIXES = [DASHBOARD_TAB_PREFIX, "/tab/"] as const;
const TAB_TOKEN_RESERVED = new Set(["api", "state", "policy", "log", "setup", "verify", "allowlist", "tab"]);

export function createDashboardAccessToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

export function dashboardTabPath(accessToken: string): string {
  return `${DASHBOARD_TAB_PREFIX}${encodeURIComponent(accessToken)}`;
}

function tabTokenAndRest(pathname: string): { token: string; rest: string } | undefined {
  for (const prefix of TAB_PATH_PREFIXES) {
    if (!pathname.startsWith(prefix)) continue;
    const after = pathname.slice(prefix.length);
    const slash = after.indexOf("/");
    const raw = slash < 0 ? after : after.slice(0, slash);
    if (!raw) return undefined;
    let token: string;
    try {
      token = decodeURIComponent(raw).trim();
    } catch {
      return undefined;
    }
    if (!token || TAB_TOKEN_RESERVED.has(token.toLowerCase())) return undefined;
    return { token, rest: slash < 0 ? "" : after.slice(slash) };
  }
  return undefined;
}

export function tabAccessFromPathname(pathname: string): string | undefined {
  return tabTokenAndRest(pathname)?.token;
}

/** ``/sentrook/tab/<token>`` (and prefix-stripped ``/tab/<token>``) plus optional ``/api/…``. */
export function dashboardRestFromPathname(pathname: string): { rest: string; handled: true } | undefined {
  const parsed = tabTokenAndRest(pathname);
  if (!parsed) return undefined;
  return { rest: parsed.rest, handled: true };
}

export function accessCookieFromHeader(cookieHeader: string | undefined): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() !== ACCESS_COOKIE) continue;
    const raw = part.slice(idx + 1).trim();
    if (!raw) return undefined;
    try {
      return decodeURIComponent(raw).trim() || undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function accessFromRequest(
  req: IncomingMessage,
  opts?: { allowCookie?: boolean },
): string | undefined {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const query = url.searchParams.get(ACCESS_QUERY)?.trim();
  if (query) return query;
  const raw = req.headers[ACCESS_HEADER];
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  if (Array.isArray(raw) && raw[0]?.trim()) return raw[0].trim();
  const pathTok = tabAccessFromPathname(url.pathname);
  if (pathTok) return pathTok;
  if (opts?.allowCookie) {
    return accessCookieFromHeader(singleHeader(req.headers.cookie));
  }
  return undefined;
}

export function accessTokensEqual(expected: string, provided: string | undefined): boolean {
  if (!provided) return false;
  const left = Buffer.from(expected);
  const right = Buffer.from(provided);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || undefined;
  }
  if (Array.isArray(value) && value[0]) {
    const trimmed = value[0].trim();
    return trimmed || undefined;
  }
  return undefined;
}

/** Echo ``null`` (sandboxed tab) or the same host as this request. Never reflect other sites. */
export function dashboardCorsAllowOrigin(
  origin: string | undefined,
  host: string | undefined,
): string | undefined {
  if (!origin) return undefined;
  if (origin === "null") return "null";
  if (!host) return undefined;
  try {
    const url = new URL(origin);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    if (url.host !== host) return undefined;
    return origin;
  } catch {
    return undefined;
  }
}

export function applyDashboardCors(req: IncomingMessage, res: ServerResponse): void {
  const allowed = dashboardCorsAllowOrigin(
    singleHeader(req.headers.origin),
    singleHeader(req.headers.host),
  );
  if (!allowed) return;
  res.setHeader("access-control-allow-origin", allowed);
  res.setHeader("access-control-allow-credentials", "true");
  res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
  res.setHeader("access-control-allow-headers", `${ACCESS_HEADER}, content-type, accept`);
  res.setHeader("access-control-max-age", "600");
  res.setHeader("vary", "origin");
}
