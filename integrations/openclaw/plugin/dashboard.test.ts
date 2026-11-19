import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Script } from "node:vm";
import { afterEach, beforeEach, test } from "node:test";

import { resolveConfig } from "./config.ts";
import { buildModel, handleRequest, limitOf, renderPage, ROUTE, scansModel, scriptJson, TAB, viewScript } from "./dashboard.ts";
import plugin from "./index.ts";

/** Shared with the Hermes plugin's tests: both plugins build the same model for the same log. */
const FIXTURES = fileURLToPath(new URL("../../fixtures/traffic-log/", import.meta.url));
const DASH = path.join(FIXTURES, "dashboard");
/** Strings that appear only in call arguments, reason and floor details, descriptions and failure details. */
const RAW = "RAW-ARG-MARKER";
const HERMES_VIEW = fileURLToPath(new URL("../../hermes/plugin/dashboard/view.js", import.meta.url));

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_TRAFFIC_LOG", "SENTROOK_TRAFFIC_LOG_ENABLED"];
const savedEnv: Record<string, string | undefined> = {};
let stateDir = "";
let logFile = "";

beforeEach(() => {
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  for (const k of ENV_KEYS) delete process.env[k];
  process.env.OPENCLAW_STATE_DIR = mkdtempSync(path.join(tmpdir(), "sentrook-dashboard-"));
  stateDir = path.join(process.env.OPENCLAW_STATE_DIR, "sentrook");
  logFile = path.join(stateDir, "traffic.jsonl");
  mkdirSync(stateDir, { recursive: true });
  copyFileSync(path.join(DASH, "traffic.jsonl"), logFile);
});
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

const cfg = () => resolveConfig({}, process.env);

type Captured = { status: number; headers: Record<string, string>; body: string | undefined };
function call(method: string, url: string, load = cfg): Captured {
  const out: Captured = { status: 0, headers: {}, body: undefined };
  handleRequest(
    { method, url },
    {
      set statusCode(v: number) {
        out.status = v;
      },
      get statusCode() {
        return out.status;
      },
      setHeader: (k: string, v: string) => {
        out.headers[k.toLowerCase()] = v;
      },
      end: (body?: string) => {
        out.body = body;
      },
    },
    load,
  );
  return out;
}

function embeddedModel(html: string): any {
  const m = /<script type="application\/json" id="sentrook-model">([\s\S]*?)<\/script>/.exec(html);
  assert.ok(m, "the page embeds the model");
  return JSON.parse(m[1]!);
}

test("the scans model matches the shared fixture the Hermes plugin also builds", () => {
  const expected = JSON.parse(readFileSync(path.join(DASH, "model.json"), "utf8"));
  assert.deepStrictEqual(scansModel(logFile, true, 50), expected);
});

test("the model never carries arguments, PlanIR, reason or floor details, descriptions or failure details", () => {
  for (const file of [logFile, path.join(FIXTURES, "traffic.jsonl"), path.join(FIXTURES, "edge", "traffic.jsonl")]) {
    const json = JSON.stringify(scansModel(file, true, 50));
    assert.ok(!json.includes(RAW), file);
    assert.ok(!json.includes("planir"), file);
    assert.ok(!json.includes('"detail"'), file);
  }
});

test("the risk tree keeps every leaf, unassessed leaves as null, and unknown numeric leaves after the known ones", () => {
  const scan = scansModel(logFile, true, 50).scans[0];
  const suspicion = scan.tiers.find((t: any) => t.name === "suspicion");
  assert.equal(suspicion.score, 0.91);
  assert.deepStrictEqual(
    suspicion.leaves.map((l: any) => l.name),
    ["misalignment", "concealment", "overreach", "distrust", "request_origin", "retry_after_denial", "untrusted_origin", "exposure", "session_exposure", "future_leaf"],
  );
  assert.equal(suspicion.leaves.find((l: any) => l.name === "concealment").value, null);
  assert.deepStrictEqual(scan.floors, [{ floor: "credential_exfiltration", min_risk: 0.85, subject: "E2" }]);
  assert.deepStrictEqual(
    scan.reasons.map((r: any) => r.signal),
    [null, "suspicion.distrust", "suspicion.exposure", "consequence.sensitivity", "confidence.agreement", "suspicion.not_a_leaf"],
  );
  // An entity with no display string is left out; E10 sorts after E2.
  assert.deepStrictEqual(scan.entities.map((e: any) => e.id), ["E1", "E2", "E10"]);
});

test("a failed scan has no tiers and only the failure kind", () => {
  const failed = scansModel(logFile, true, 50).scans.at(-1);
  assert.equal(failed.failure, "timeout");
  assert.equal(failed.risk, null);
  assert.deepStrictEqual(failed.tiers, []);
  assert.equal(failed.bucket, "scan_error");
});

test("the log off gives an empty model", () => {
  const m = scansModel(logFile, false, 10);
  assert.equal(m.log, "off");
  assert.deepStrictEqual(m.scans, []);
});

test("the page limit: default 10, at most 50", () => {
  assert.equal(limitOf(null), 10);
  assert.equal(limitOf("abc"), 10);
  assert.equal(limitOf("0"), 10);
  assert.equal(limitOf("25"), 25);
  assert.equal(limitOf("999"), 50);
});

test("buildModel adds the review and block lines, mode, grants and snooze text", () => {
  const m = buildModel(cfg(), 10);
  assert.deepStrictEqual(m.lines, { review_at: 45, block_at: 80 });
  assert.equal(m.mode, "enforce");
  assert.equal(typeof m.state.grants, "string");
  assert.equal(typeof m.state.snooze, "string");
  assert.equal(m.commands.grants, "/sentrook-grants");
});

test("GET draws the page with the model embedded, a nonce CSP and no raw markup from the log", () => {
  const res = call("GET", `${ROUTE}?n=25`);
  assert.equal(res.status, 200);
  assert.match(res.headers["content-type"]!, /^text\/html/);
  assert.equal(res.headers["cache-control"], "no-store");
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  const nonce = /script-src 'nonce-([^']+)'/.exec(res.headers["content-security-policy"]!)?.[1];
  assert.ok(nonce);
  assert.ok(res.body!.includes(`<script nonce="${nonce}">`));
  assert.ok(!res.body!.includes(RAW));
  // The entity display string with a script tag stays inside the JSON, escaped.
  assert.ok(!res.body!.includes("<script>alert(1)"));
  const model = embeddedModel(res.body!);
  assert.equal(model.limit, 25);
  assert.equal(model.scans[0].entities[0].display, "<script>alert(1)</script>evil.example");
  assert.equal(call("GET", `${ROUTE}/`).status, 200);
});

test("HEAD sends the headers and no body", () => {
  const res = call("HEAD", ROUTE);
  assert.equal(res.status, 200);
  assert.equal(res.body, undefined);
});

test("every other method is refused: the dashboard is read-only", () => {
  for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
    const res = call(method, ROUTE);
    assert.equal(res.status, 405, method);
    assert.equal(res.headers.allow, "GET, HEAD");
  }
});

test("other paths under the route are not served", () => {
  assert.equal(call("GET", `${ROUTE}/api/resolve`).status, 404);
  assert.equal(call("GET", `${ROUTE}/../etc/passwd`).status, 404);
});

test("a config that cannot be read gives a 500 without details", () => {
  const res = call("GET", ROUTE, () => {
    throw new Error(`${RAW} secret`);
  });
  assert.equal(res.status, 500);
  assert.ok(!res.body!.includes(RAW));
});

test("scriptJson cannot close the script element", () => {
  const s = scriptJson({ a: "</script><b>&\u2028" });
  assert.ok(!/[<>&\u2028]/.test(s));
  assert.deepStrictEqual(JSON.parse(s), { a: "</script><b>&\u2028" });
});

test("renderPage escapes a closing script tag in the view source", () => {
  assert.ok(!renderPage({ scans: [] }, "n").includes("</script></script>"));
});

test("the view script parses, and the Hermes plugin ships the same file byte for byte", () => {
  const src = viewScript();
  assert.doesNotThrow(() => new Script(src));
  assert.equal(src, readFileSync(HERMES_VIEW, "utf8"));
});

function registered(extra: Record<string, unknown>) {
  const routes: any[] = [];
  const tabs: any[] = [];
  const api: any = {
    pluginConfig: {},
    registrationMode: "full",
    logger: { info() {}, warn() {}, error() {} },
    on() {},
    registerHttpRoute: (r: any) => routes.push(r),
    ...extra,
  };
  plugin.register(api);
  return { routes, tabs, api };
}

test("register adds the route behind gateway auth and the tab through session.controls", () => {
  const tabs: any[] = [];
  const flat: any[] = [];
  const { routes } = registered({
    session: { controls: { registerControlUiDescriptor: (d: any) => tabs.push(d) } },
    registerControlUiDescriptor: (d: any) => flat.push(d),
  });
  assert.equal(routes.length, 1);
  assert.equal(routes[0].path, "/sentrook");
  assert.equal(routes[0].auth, "gateway");
  assert.equal(routes[0].match, "prefix");
  assert.deepStrictEqual(tabs, [{ ...TAB, requiredScopes: ["operator.read"] }]);
  assert.deepStrictEqual(flat, []);
  // The registered handler serves this install's log.
  const out: Captured = { status: 0, headers: {}, body: undefined };
  routes[0].handler(
    { method: "GET", url: "/sentrook" },
    { statusCode: 0, setHeader: () => {}, end: (b?: string) => (out.body = b) },
  );
  assert.equal(embeddedModel(out.body!).scans.length, 6);
});

test("register falls back to the flat tab method on hosts without session.controls", () => {
  const flat: any[] = [];
  registered({ registerControlUiDescriptor: (d: any) => flat.push(d) });
  assert.equal(flat.length, 1);
  assert.equal(flat[0].path, "/sentrook");
});

test("a host without HTTP routes still loads the plugin", () => {
  const api: any = { pluginConfig: {}, registrationMode: "full", logger: { info() {}, warn() {}, error() {} }, on() {} };
  assert.doesNotThrow(() => plugin.register(api));
});
