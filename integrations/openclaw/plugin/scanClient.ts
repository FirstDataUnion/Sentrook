/**
 * POST /scan transport. Token mint happens outside the scan deadline (a cold identity lookup must
 * not eat the scan budget); one 429 is retried when `Retry-After` fits in the deadline.
 */

import { getScanAccessToken, type OidcCredentials } from "./auth.ts";
import { parseRetryAfterSeconds, scanAuthErrorToFailure, type ScanFailure } from "./scanErrorPolicy.ts";

export interface ScanResponse {
  response_version: string;
  request_id?: string;
  status: "ok" | "degraded" | "error";
  risk: number | null;
  enforced: "block" | "review" | null;
  tree?: {
    suspicion?: { score?: number | null };
    consequence?: { score?: number | null };
    confidence?: { score?: number | null };
  };
  floors_applied?: Array<Record<string, unknown>>;
  relief_applied?: Array<Record<string, unknown>>;
  reasons?: Array<{ code: string; signal?: string; subject?: string | null; detail?: unknown }>;
  tool_description?: { category?: string; template?: string } | null;
  entities?: Record<string, { kind?: string; display?: string }>;
  action_fingerprint?: string | null;
  state?: string | null;
  error?: { code?: string; message?: string } | null;
  metadata?: Record<string, unknown>;
}

export interface ScanOk {
  ok: true;
  response: ScanResponse;
  latencyMs: number;
}

/** A body is usable when it is Response 2.0 with a numeric risk and a non-error status. */
export function parseScanResponse(body: unknown, httpStatus: number): ScanResponse | ScanFailure {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, kind: "http", status: httpStatus, detail: "scan response is not an object" };
  }
  const doc = body as ScanResponse;
  if (doc.response_version !== "2.0") {
    return { ok: false, kind: "http", status: httpStatus, detail: `unexpected response_version ${String(doc.response_version)}` };
  }
  if (doc.status === "error" || typeof doc.risk !== "number" || !Number.isFinite(doc.risk)) {
    const code = doc.error?.code ?? "no_score";
    const msg = doc.error?.message ?? "scan returned no usable score";
    return { ok: false, kind: "scan_error", status: httpStatus, detail: `${code}: ${msg}`.slice(0, 200) };
  }
  if (doc.enforced !== null && doc.enforced !== undefined && doc.enforced !== "block" && doc.enforced !== "review") {
    return { ok: false, kind: "http", status: httpStatus, detail: `unknown enforced value ${String(doc.enforced)}` };
  }
  return { ...doc, enforced: doc.enforced ?? null };
}

function isFailure(v: unknown): v is ScanFailure {
  return typeof v === "object" && v !== null && (v as ScanFailure).ok === false;
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new Error("aborted"));
    const t = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new Error("aborted"));
      },
      { once: true },
    );
  });
}

export async function postScan(opts: {
  scanUrl: string;
  oidc: OidcCredentials | null;
  body: string;
  timeoutMs: number;
  fetchImpl?: typeof fetch;
}): Promise<ScanOk | ScanFailure> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (!opts.oidc) {
    return {
      ok: false,
      kind: "config",
      detail: "no scan credentials (set SENTROOK_SCAN_CLIENT_ID and SENTROOK_SCAN_CLIENT_SECRET)",
    };
  }
  try {
    headers.authorization = `Bearer ${await getScanAccessToken(opts.oidc, fetchImpl)}`;
  } catch (err) {
    return scanAuthErrorToFailure(err);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
  const started = performance.now();
  let retried = false;
  try {
    while (true) {
      const res = await fetchImpl(`${opts.scanUrl}/scan`, {
        method: "POST",
        headers,
        body: opts.body,
        signal: controller.signal,
        redirect: "error",
      });
      // 422 carries the Response 2.0 error shape (preparation failed).
      if (res.ok || res.status === 422) {
        let raw: unknown;
        try {
          raw = await res.json();
        } catch (err) {
          return { ok: false, kind: "http", status: res.status, detail: `invalid scan JSON: ${String(err)}`.slice(0, 200) };
        }
        const parsed = parseScanResponse(raw, res.status);
        if (isFailure(parsed)) return parsed;
        return { ok: true, response: parsed, latencyMs: Math.round(performance.now() - started) };
      }
      const detail = (await res.text().catch(() => "")).slice(0, 200);
      if (res.status === 429) {
        const retryAfterSec = parseRetryAfterSeconds(res.headers.get("retry-after")) ?? 1;
        const waitMs = Math.ceil(retryAfterSec * 1000);
        if (!retried && started + opts.timeoutMs - performance.now() > waitMs + 50) {
          retried = true;
          await sleep(waitMs, controller.signal);
          continue;
        }
        return { ok: false, kind: "rate_limited", status: 429, retryAfterSec, detail: detail || "rate limited" };
      }
      return { ok: false, kind: "http", status: res.status, detail: detail || `HTTP ${res.status}` };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const aborted = controller.signal.aborted || msg.toLowerCase().includes("abort");
    return { ok: false, kind: aborted ? "timeout" : "network", detail: msg.slice(0, 200) };
  } finally {
    clearTimeout(timer);
  }
}
