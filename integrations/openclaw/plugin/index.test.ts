import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import { resolveApprovalPolicyConfig } from "./approvalPolicy.ts";
import { clearScanTokenCache } from "./auth.ts";
import {
  buildScanTiming,
  computeTransportMs,
  extractEngineMs,
  parseScanResponse,
  postScan,
  resolveScanTimeoutMs,
  translateScanResponse,
  type ScanResponse,
} from "./index.ts";
import { buildPlanirSnapshot, type PlanIR } from "./planir.ts";
import { recordAllowAlways } from "./localAllowlist.ts";
import { SCAN_BASE_URL } from "./scanEndpoint.ts";

const noopLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

function plan(overrides: {
  executed?: Array<{ tool: string; args: Record<string, unknown> }>;
  pending?: { tool: string; args: Record<string, unknown> };
  intent?: string;
  intentKind?: PlanIR["intent_kind"];
  sessionId?: string;
  toolCallId?: string;
} = {}): PlanIR {
  return buildPlanirSnapshot({
    executed: overrides.executed ?? [],
    pending: overrides.pending ?? { tool: "exec", args: { command: "ls /tmp" } },
    runId: `${overrides.sessionId ?? "sess-1"}:run_1`,
    intent: overrides.intent ?? "check my email",
    intentKind: overrides.intentKind ?? "user",
    sessionId: overrides.sessionId ?? "sess-1",
    toolCallId: overrides.toolCallId,
  });
}

function ctx(overrides: Record<string, unknown> = {}) {
  return {
    plan: plan(),
    url: SCAN_BASE_URL,
    auth: { apiKey: null, oidc: null },
    feedbackMode: "off" as const,
    approval: resolveApprovalPolicyConfig({}),
    allowlist: { enabled: false, path: "/tmp/unused-sentrook-allowlist.json", scriptBind: true },
    logger: noopLogger,
    ...overrides,
  };
}

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  clearScanTokenCache();
});

describe("scan timing helpers", () => {
  it("defaults to 60000ms", () => {
    assert.equal(resolveScanTimeoutMs(undefined, {}), 60_000);
  });

  it("prefers explicit config and env timeout overrides", () => {
    assert.equal(resolveScanTimeoutMs(5000, {}), 5000);
    assert.equal(
      resolveScanTimeoutMs(undefined, {
        SENTROOK_SCAN_TIMEOUT_MS: "4000",
      }),
      4000,
    );
  });

  it("prefers timing.engine_ms over log.total_ms", () => {
    const scan: ScanResponse = {
      block: false,
      decision: "allow",
      timing: { engine_ms: 42, request_ms: 44 },
      log: { total_ms: 99 },
    };
    assert.equal(extractEngineMs(scan), 42);
    const timing = buildScanTiming(scan, 50);
    assert.equal(timing.pluginE2eMs, 50);
    assert.equal(timing.requestMs, 44);
    assert.equal(timing.transportMs, 8);
    assert.equal(timing.sanitizeEnabled, false);
    assert.equal(timing.sanitizeMs, 0);
  });

  it("falls back to log.total_ms when timing is missing", () => {
    const scan: ScanResponse = {
      block: false,
      decision: "allow",
      log: { total_ms: 120 },
    };
    assert.equal(extractEngineMs(scan), 120);
    assert.equal(computeTransportMs(125, 120), 5);
  });
});

describe("postScan timing", () => {
  it("measures plugin round-trip time for enforce scans", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          block: false,
          decision: "allow",
          timing: { engine_ms: 10, request_ms: 12 },
          log: { total_ms: 10 },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    const result = await postScan(SCAN_BASE_URL, 1500, plan({ toolCallId: "exec:abc" }), null, );
    assert.ok(result);
    assert.equal(result.scan.decision, "allow");
    assert.ok(result.timing.pluginE2eMs >= 0);
    assert.equal(result.timing.engineMs, 10);
    assert.equal(result.timing.requestMs, 12);
    assert.equal(result.timing.transportMs, Math.max(0, result.timing.pluginE2eMs - 10));
    assert.equal(result.timing.sanitizeEnabled, true);
    assert.ok(result.timing.sanitizeMs >= 0);
  });

  it("sanitizes PlanIR body when sanitization is enabled", async () => {
    let postedBody = "";
    globalThis.fetch = (async (_url, init) => {
      postedBody = String(init?.body ?? "");
      return new Response(
        JSON.stringify({
          block: false,
          decision: "allow",
          timing: { engine_ms: 1, request_ms: 2 },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const result = await postScan(
      SCAN_BASE_URL,
      1500,
      plan({
        pending: {
          tool: "exec",
          args: { command: "echo hi", api_key: "super-secret" },
        },
      }),
      null,
    );
    assert.ok(result);
    assert.equal(result.timing.sanitizeEnabled, true);
    assert.ok(result.timing.sanitizeMs >= 0);
    const body = JSON.parse(postedBody) as {
      steps: Array<{ args: { api_key: string } }>;
    };
    const pendingStep = body.steps.find((s) => s.args.api_key !== undefined);
    assert.equal(pendingStep?.args.api_key, "[REDACTED]");
    assert.ok(!postedBody.includes("super-secret"));
  });
});

describe("postScan failure logging", () => {
  it("warns with HTTP status and body snippet on non-OK", async () => {
    const warns: string[] = [];
    const logger = {
      info: () => {},
      warn: (m: string) => warns.push(m),
      error: () => {},
    };
    const body = "x".repeat(250);
    globalThis.fetch = (async () =>
      new Response(body, { status: 401 })) as typeof fetch;

    const result = await postScan(
      "https://scan.test",
      1500,
      plan(),
      { apiKey: "k", oidc: null },
      logger,
    );
    assert.equal(result.ok, false);
    if (result.ok !== false) throw new Error("expected failure");
    assert.equal(result.kind, "http");
    assert.equal(result.status, 401);
    assert.equal(warns.length, 1);
    assert.match(warns[0]!, /scan HTTP 401:/);
    assert.ok(!warns[0]!.includes("failing open"));
    assert.ok(!warns[0]!.includes(body));
    assert.ok(warns[0]!.includes("x".repeat(200)));
  });

  it("treats invalid JSON 200 as a scan failure", async () => {
    const warns: string[] = [];
    const logger = {
      info: () => {},
      warn: (m: string) => warns.push(m),
      error: () => {},
    };
    globalThis.fetch = (async () =>
      new Response("not-json", { status: 200 })) as typeof fetch;
    const result = await postScan("https://scan.test", 1500, plan(), { apiKey: "k", oidc: null }, logger);
    assert.equal(result.ok, false);
    if (result.ok !== false) throw new Error("expected failure");
    assert.equal(result.kind, "http");
    assert.match(result.detail, /invalid scan JSON/);
    assert.ok(warns.some((w) => /invalid JSON/.test(w)));
  });

  it("treats unknown decision 200 as a scan failure", async () => {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ block: false, decision: "maybe" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;
    const result = await postScan("https://scan.test", 1500, plan(), { apiKey: "k", oidc: null });
    assert.equal(result.ok, false);
    if (result.ok !== false) throw new Error("expected failure");
    assert.match(result.detail, /unknown scan decision/);
  });

  it("retries once on 429 when Retry-After fits in the timeout", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      if (calls === 1) {
        return new Response("slow down", {
          status: 429,
          headers: { "Retry-After": "0" },
        });
      }
      return new Response(JSON.stringify({ block: false, decision: "allow" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const result = await postScan("https://scan.test", 1500, plan(), null);
    assert.equal(calls, 2);
    assert.ok(!("ok" in result && (result as { ok?: false }).ok === false));
    assert.equal((result as { scan: { decision: string } }).scan.decision, "allow");
  });

  it("returns rate_limited when 429 Retry-After does not fit", async () => {
    const warns: string[] = [];
    const logger = {
      info: () => {},
      warn: (m: string) => warns.push(m),
      error: () => {},
    };
    globalThis.fetch = (async () =>
      new Response("slow", {
        status: 429,
        headers: { "Retry-After": "30" },
      })) as typeof fetch;

    const result = await postScan("https://scan.test", 200, plan(), null, logger);
    assert.equal(result.ok, false);
    if (result.ok !== false) throw new Error("expected failure");
    assert.equal(result.kind, "rate_limited");
    assert.match(warns[0] || "", /HTTP 429: rate limited; Retry-After=30/);
  });

  it("warns scan timed out when the request is aborted", async () => {
    const warns: string[] = [];
    const logger = {
      info: () => {},
      warn: (m: string) => warns.push(m),
      error: () => {},
    };
    globalThis.fetch = ((_url, init) =>
      new Promise((_resolve, reject) => {
        const signal = init?.signal;
        if (!signal) {
          reject(new Error("missing abort signal"));
          return;
        }
        if (signal.aborted) {
          reject(new Error("aborted"));
          return;
        }
        signal.addEventListener("abort", () => reject(new Error("aborted")));
      })) as typeof fetch;

    const result = await postScan("https://scan.test", 20, plan(), null, logger);
    assert.equal(result.ok, false);
    if (result.ok !== false) throw new Error("expected failure");
    assert.equal(result.kind, "timeout");
    assert.match(warns[0] || "", /scan timed out:/);
    assert.ok(!warns[0]!.includes("failing open"));
  });

  it("warns scan failed on network errors", async () => {
    const warns: string[] = [];
    const logger = {
      info: () => {},
      warn: (m: string) => warns.push(m),
      error: () => {},
    };
    globalThis.fetch = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;

    const result = await postScan("https://scan.test", 1500, plan(), null, logger);
    assert.equal(result.ok, false);
    if (result.ok !== false) throw new Error("expected failure");
    assert.equal(result.kind, "network");
    assert.match(warns[0] || "", /scan failed: ECONNREFUSED/);
    assert.ok(!warns[0]!.includes("failing open"));
  });

  it("maps OIDC mint 401 to scan auth failure without POSTing /scan", async () => {
    const warns: string[] = [];
    const logger = {
      info: () => {},
      warn: (m: string) => warns.push(m),
      error: () => {},
    };
    const urls: string[] = [];
    globalThis.fetch = (async (input) => {
      const url = String(input);
      urls.push(url);
      if (url.includes("openid-configuration")) {
        return new Response(JSON.stringify({ token_endpoint: "https://identity.test/oauth/token" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("/oauth/token")) {
        return new Response(JSON.stringify({ error: "invalid_client" }), { status: 401 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;

    const result = await postScan(
      "https://scan.test",
      1500,
      plan(),
      {
        apiKey: null,
        oidc: {
          clientId: "c",
          clientSecret: "s",
          issuer: "https://identity.test",
          audience: "sentrook",
          scope: "sentrook.scan",
        },
      },
      logger,
    );
    assert.equal(result.ok, false);
    if (result.ok !== false) throw new Error("expected failure");
    assert.equal(result.kind, "http");
    assert.equal(result.status, 401);
    assert.ok(warns.some((w) => /scan auth failed/.test(w)));
    assert.ok(!urls.some((u) => u.includes("/scan")));
  });

  it("does not spend the scan timeout on OIDC mint", async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const access = `aaa.${Buffer.from(JSON.stringify({ exp })).toString("base64url")}.bbb`;
    globalThis.fetch = (async (input) => {
      const url = String(input);
      if (url.includes("openid-configuration")) {
        await new Promise((r) => setTimeout(r, 80));
        return new Response(JSON.stringify({ token_endpoint: "https://identity.test/oauth/token" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("/oauth/token")) {
        return new Response(JSON.stringify({ access_token: access, expires_in: 3600 }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("/scan")) {
        return new Response(JSON.stringify({ decision: "allow", block: false }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }) as typeof fetch;

    const result = await postScan(
      "https://scan.test",
      20,
      plan(),
      {
        apiKey: null,
        oidc: {
          clientId: "c",
          clientSecret: "s",
          issuer: "https://identity.test",
          audience: "sentrook",
          scope: "sentrook.scan",
        },
      },
    );
    assert.ok(!("ok" in result && (result as { ok?: false }).ok === false));
    assert.equal((result as { scan: { decision: string } }).scan.decision, "allow");
  });
});

describe("translateScanResponse — block mapping", () => {
  it("maps a block decision to an OpenClaw veto with the sidecar reason", () => {
    const scan: ScanResponse = {
      block: true,
      decision: "block",
      block_reason: "AIRA-001: fetched payload piped to shell",
    };
    const result = translateScanResponse(scan, ctx());
    assert.ok(result);
    assert.equal(result.block, true);
    assert.equal(result.blockReason, "AIRA-001: fetched payload piped to shell");
    assert.equal(result.requireApproval, undefined);
  });

  it("blocks on decision=block even when block flag is false (defence in depth)", () => {
    const scan: ScanResponse = {
      block: false,
      decision: "block",
      summary: "Block triggered by AIRA-001",
    };
    const result = translateScanResponse(scan, ctx());
    assert.ok(result);
    assert.equal(result.block, true);
    assert.equal(result.blockReason, "Block triggered by AIRA-001");
  });

  it("falls back to a generic reason when the sidecar sends none", () => {
    const scan: ScanResponse = { block: true, decision: "block" };
    const result = translateScanResponse(scan, ctx());
    assert.ok(result?.blockReason);
    assert.match(result.blockReason!, /Sentrook blocked/);
  });
});

describe("translateScanResponse — review mapping", () => {
  it("maps review to requireApproval with sidecar copy and severity", () => {
    const scan: ScanResponse = {
      block: false,
      decision: "review",
      review_title: "Sentrook review: exec",
      review_description: "read → exec chain flagged",
      review_severity: "critical",
    };
    const result = translateScanResponse(
      scan,
      ctx({ pendingArgs: { command: "ls /tmp" } }),
    );
    assert.ok(result?.requireApproval);
    const approval = result.requireApproval!;
    assert.equal(approval.title, "ls /tmp");
    assert.ok(approval.description.includes("ls /tmp"));
    assert.equal(approval.severity, "critical");
    assert.deepEqual(approval.allowedDecisions, [
      "allow-once",
      "allow-always",
      "deny",
    ]);
  });

  it("overlays local exec command when sidecar copy is [TRUNCATED]", () => {
    const command = `python3 wiki.py get Self:Today ${"padding ".repeat(80)}`;
    const scan: ScanResponse = {
      block: false,
      decision: "review",
      review_title: "[TRUNCATED]",
      review_description: "Likely: run a shell command\nrun: `[TRUNCATED]`\n(010)",
      review_severity: "warning",
    };
    const result = translateScanResponse(scan, ctx({ pendingArgs: { command } }));
    const approval = result?.requireApproval;
    assert.ok(approval);
    assert.notEqual(approval.title, "[TRUNCATED]");
    assert.ok(!approval.description.includes("[TRUNCATED]"));
    assert.ok(approval.description.includes("wiki.py") || approval.title.includes("wiki.py"));
    assert.ok(!approval.description.includes("(010)"));
  });

  it("uses fallback title/description/severity when copy is missing", () => {
    const scan: ScanResponse = {
      block: false,
      decision: "review",
      summary: "Review triggered by AIRA-064",
    };
    const result = translateScanResponse(scan, ctx());
    const approval = result?.requireApproval;
    assert.ok(approval);
    assert.equal(approval.title, "exec: no command preview");
    assert.equal(approval.description, "Review triggered by AIRA-064");
    assert.equal(approval.severity, "warning");
  });

  it("applies interactive deny timing for user intents", () => {
    const scan: ScanResponse = { block: false, decision: "review" };
    const result = translateScanResponse(scan, ctx());
    const approval = result?.requireApproval;
    assert.ok(approval);
    assert.equal(approval.timeoutBehavior, "deny");
  });

  it("applies scheduled deny timing for cron intents", () => {
    const scan: ScanResponse = { block: false, decision: "review" };
    const result = translateScanResponse(
      scan,
      ctx({
        plan: plan({
          intent: "[cron:abc] Daily Brief",
          intentKind: "cron",
        }),
      }),
    );
    const approval = result?.requireApproval;
    assert.ok(approval);
    assert.equal(approval.timeoutBehavior, "deny");
  });
});

describe("translateScanResponse — allow mapping", () => {
  it("returns undefined so the tool call proceeds untouched", () => {
    const scan: ScanResponse = { block: false, decision: "allow" };
    assert.equal(translateScanResponse(scan, ctx()), undefined);
  });
});

describe("parseScanResponse", () => {
  it("normalizes decision case", () => {
    const parsed = parseScanResponse({ decision: "BLOCK", block: true });
    assert.equal("ok" in parsed && parsed.ok === false, false);
    if ("ok" in parsed && parsed.ok === false) throw new Error("expected scan");
    assert.equal(parsed.decision, "block");
  });

  it("treats block flag without decision as block", () => {
    const parsed = parseScanResponse({ block: true });
    if ("ok" in parsed && parsed.ok === false) throw new Error("expected scan");
    assert.equal(parsed.decision, "block");
  });

  it("fails closed on unknown or missing decision", () => {
    const unknown = parseScanResponse({ decision: "maybe", block: false });
    assert.equal("ok" in unknown && unknown.ok === false, true);
    if (!("ok" in unknown) || unknown.ok !== false) throw new Error("expected failure");
    assert.equal(unknown.kind, "http");
    assert.match(unknown.detail, /unknown/);

    const missing = parseScanResponse({ block: false });
    assert.equal("ok" in missing && missing.ok === false, true);
    if (!("ok" in missing) || missing.ok !== false) throw new Error("expected failure");
    assert.match(missing.detail, /missing/);
  });

  it("fails closed on a non-object body", () => {
    const parsed = parseScanResponse(["allow"]);
    assert.equal("ok" in parsed && parsed.ok === false, true);
  });
});

describe("translateScanResponse — resolution feedback", () => {
  function captureFeedback(): { calls: Array<{ url: string; body: any }> } {
    const calls: Array<{ url: string; body: any }> = [];
    globalThis.fetch = ((url: any, init?: any) => {
      calls.push({ url: String(url), body: JSON.parse(init?.body ?? "{}") });
      return Promise.resolve(new Response("{}", { status: 200 }));
    }) as typeof fetch;
    return { calls };
  }

  it("posts feedback on allow-always even when feedback mode is off", async () => {
    const { calls } = captureFeedback();
    const scan: ScanResponse = { block: false, decision: "review" };
    const result = translateScanResponse(scan, ctx());
    await result!.requireApproval!.onResolution!("allow-always");
    assert.equal(calls.length, 1);
    assert.match(calls[0].url, /\/feedback$/);
    assert.equal(calls[0].body.resolution, "allow-always");
  });

  it("warns when feedback response is skipped", async () => {
    const warns: string[] = [];
    globalThis.fetch = ((url: any, init?: any) => {
      return Promise.resolve(
        new Response(JSON.stringify({ status: "skipped", reason: "feedback disabled" }), {
          status: 200,
        }),
      );
    }) as typeof fetch;
    const scan: ScanResponse = { block: false, decision: "review" };
    const result = translateScanResponse(
      scan,
      ctx({
        feedbackMode: "submit",
        logger: {
          info: () => {},
          warn: (msg: string) => warns.push(msg),
          error: () => {},
        },
      }),
    );
    await result!.requireApproval!.onResolution!("allow-once");
    assert.equal(warns.length, 1);
    assert.match(warns[0], /feedback not submitted/);
    assert.match(warns[0], /feedback disabled/);
  });

  it("posts deny feedback when feedback mode is submit", async () => {
    const { calls } = captureFeedback();
    const scan: ScanResponse = { block: false, decision: "review" };
    const result = translateScanResponse(scan, ctx({ feedbackMode: "submit" }));
    await result!.requireApproval!.onResolution!("deny");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.resolution, "deny");
  });

  it("sanitizes feedback plan when sanitization is enabled", async () => {
    const { calls } = captureFeedback();
    const scan: ScanResponse = { block: false, decision: "review" };
    const snap = plan({
      pending: {
        tool: "exec",
        args: { command: "echo hi", api_key: "super-secret" },
      },
    });
    const result = translateScanResponse(
      scan,
      ctx({
        plan: snap,
        feedbackMode: "submit",
      }),
    );
    await result!.requireApproval!.onResolution!("deny");
    assert.equal(calls.length, 1);
    const pendingStep = (calls[0].body.plan as PlanIR).steps.find(
      (s) => (s.args as { api_key?: string }).api_key !== undefined,
    );
    assert.equal((pendingStep?.args as { api_key: string }).api_key, "[REDACTED]");
    assert.ok(!JSON.stringify(calls[0].body).includes("super-secret"));
  });
});

describe("translateScanResponse — local allowlist", () => {
  const allowlistDirs: string[] = [];
  afterEach(() => {
    while (allowlistDirs.length) {
      const dir = allowlistDirs.pop();
      if (dir) rmSync(dir, { recursive: true, force: true });
    }
  });

  function allowlistCtx(command: string) {
    const dir = mkdtempSync(join(tmpdir(), "sentrook-idx-allow-"));
    allowlistDirs.push(dir);
    const path = join(dir, "sentrook-allowlist.json");
    const allowlist = { enabled: true, path, scriptBind: true };
    const snap = plan({
      pending: { tool: "exec", args: { command } },
    });
    const log = { matched_rules: [{ id: "AIRA-010" }] };
    return { dir, allowlist, snap, log };
  }

  it("skips requireApproval on allowlist hit", () => {
    const warns: string[] = [];
    const { allowlist, snap, log } = allowlistCtx("rg -n TODO src/");
    recordAllowAlways(snap, log, allowlist);
    const result = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({
        plan: snap,
        allowlist,
        logger: { ...noopLogger, warn: (m) => warns.push(m) },
      }),
    );
    assert.equal(result, undefined);
    assert.ok(warns.some((m) => /local allowlist hit \(skeleton\)/.test(m)));
    assert.ok(warns.some((m) => /rules=AIRA-010/.test(m)));
    assert.ok(warns.some((m) => /skeleton=rg -n TODO src\//.test(m)));
  });

  it("never short-circuits block decisions", () => {
    const { allowlist, snap, log } = allowlistCtx("rg -n TODO src/");
    recordAllowAlways(snap, log, allowlist);
    const result = translateScanResponse(
      { block: true, decision: "block", log },
      ctx({ plan: snap, allowlist }),
    );
    assert.equal(result?.block, true);
  });

  it("records allowlist on allow-always and still posts feedback", async () => {
    const { calls } = (() => {
      const calls: Array<{ url: string; body: any }> = [];
      globalThis.fetch = ((url: any, init?: any) => {
        calls.push({ url: String(url), body: JSON.parse(init?.body ?? "{}") });
        return Promise.resolve(new Response("{}", { status: 200 }));
      }) as typeof fetch;
      return { calls };
    })();

    const { dir, allowlist, snap, log } = allowlistCtx(
      "rg -n hello src/",
    );
    const result = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({ plan: snap, allowlist }),
    );
    assert.ok(result?.requireApproval);
    await result!.requireApproval!.onResolution!("allow-always");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.resolution, "allow-always");

    const again = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({ plan: snap, allowlist }),
    );
    assert.equal(again, undefined);
    assert.ok(dir);
  });

  it("records script_bind for python helpers", async () => {
    const { calls } = (() => {
      const calls: Array<{ url: string; body: any }> = [];
      globalThis.fetch = ((url: any, init?: any) => {
        calls.push({ url: String(url), body: JSON.parse(init?.body ?? "{}") });
        return Promise.resolve(new Response("{}", { status: 200 }));
      }) as typeof fetch;
      return { calls };
    })();

    const { dir, allowlist, log } = allowlistCtx("placeholder");
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print(1)\n", "utf8");
    const snap = plan({
      pending: {
        tool: "exec",
        args: { command: `python3 ${scriptPath} --date 2026-07-17` },
      },
    });
    const result = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({ plan: snap, allowlist }),
    );
    await result!.requireApproval!.onResolution!("allow-always");
    assert.equal(calls.length, 1);

    const hit = translateScanResponse(
      {
        block: false,
        decision: "review",
        log,
      },
      ctx({
        plan: plan({
          pending: {
            tool: "exec",
            args: { command: `python3 ${scriptPath} --date 2026-07-20` },
          },
        }),
        allowlist,
      }),
    );
    assert.equal(hit, undefined);
  });

  it("allow-once does not record and still prompts next time", async () => {
    const { calls } = (() => {
      const calls: Array<{ url: string; body: any }> = [];
      globalThis.fetch = ((url: any, init?: any) => {
        calls.push({ url: String(url), body: JSON.parse(init?.body ?? "{}") });
        return Promise.resolve(new Response("{}", { status: 200 }));
      }) as typeof fetch;
      return { calls };
    })();

    const { allowlist, snap, log } = allowlistCtx("rg -n once src/");
    const result = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({ plan: snap, allowlist, feedbackMode: "submit" }),
    );
    await result!.requireApproval!.onResolution!("allow-once");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.resolution, "allow-once");

    const again = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({ plan: snap, allowlist }),
    );
    assert.ok(again?.requireApproval);
  });

  it("high-risk allow-always posts feedback but does not short-circuit later", async () => {
    const { calls } = (() => {
      const calls: Array<{ url: string; body: any }> = [];
      globalThis.fetch = ((url: any, init?: any) => {
        calls.push({ url: String(url), body: JSON.parse(init?.body ?? "{}") });
        return Promise.resolve(new Response("{}", { status: 200 }));
      }) as typeof fetch;
      return { calls };
    })();

    const { allowlist, snap, log } = allowlistCtx("python3 -c 'print(1)'");
    const result = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({ plan: snap, allowlist }),
    );
    await result!.requireApproval!.onResolution!("allow-always");
    assert.equal(calls.length, 1);

    const again = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({ plan: snap, allowlist }),
    );
    assert.ok(again?.requireApproval);
  });

  it("disabled allowlist still posts allow-always feedback", async () => {
    const { calls } = (() => {
      const calls: Array<{ url: string; body: any }> = [];
      globalThis.fetch = ((url: any, init?: any) => {
        calls.push({ url: String(url), body: JSON.parse(init?.body ?? "{}") });
        return Promise.resolve(new Response("{}", { status: 200 }));
      }) as typeof fetch;
      return { calls };
    })();

    const { allowlist, snap, log } = allowlistCtx("rg -n TODO src/");
    const result = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({
        plan: snap,
        allowlist: { ...allowlist, enabled: false },
      }),
    );
    await result!.requireApproval!.onResolution!("allow-always");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.resolution, "allow-always");
  });

  it("script URL arg change still requires approval after script_bind", async () => {
    const { dir, allowlist, log } = allowlistCtx("placeholder");
    const scriptPath = join(dir, "helper.py");
    writeFileSync(scriptPath, "print(1)\n", "utf8");
    const snap = plan({
      pending: {
        tool: "exec",
        args: { command: `python3 ${scriptPath} --url https://safe.example` },
      },
    });
    recordAllowAlways(snap, log, allowlist);

    const miss = translateScanResponse(
      { block: false, decision: "review", log },
      ctx({
        plan: plan({
          pending: {
            tool: "exec",
            args: { command: `python3 ${scriptPath} --url https://evil.example` },
          },
        }),
        allowlist,
      }),
    );
    assert.ok(miss?.requireApproval);
  });
});
