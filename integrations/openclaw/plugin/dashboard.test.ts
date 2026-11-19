import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Script } from "node:vm";
import { afterEach, beforeEach, test } from "node:test";

import { resolveConfig } from "./config.ts";
import { buildModel, COMMANDS, handleRequest, limitOf, pendingOf, renderPage, ROUTE, scanModel, scansModel, scriptJson, TAB, viewScript } from "./dashboard.ts";
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

test("the scans model matches the shared fixtures the Hermes plugin also builds", () => {
  for (const [log, expected] of [
    [logFile, "model.json"],
    [path.join(FIXTURES, "traffic.jsonl"), "model-history.json"],
    [path.join(FIXTURES, "edge", "traffic.jsonl"), "model-edge.json"],
  ]) {
    assert.deepStrictEqual(scansModel(log!, true, 50), JSON.parse(readFileSync(path.join(DASH, expected!), "utf8")), expected);
  }
});

test("a step reads as a whole number only", () => {
  for (const [raw, step] of [[3, 3], [3.0, 3], [3.5, null], [true, null], ["3", null]] as const) {
    assert.equal(scanModel({ request_id: "x", step: raw }, null).step, step);
  }
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

test("pending: open prompts inside the answer window and live holds, matching the shared fixture", () => {
  const holdsDir = mkdtempSync(path.join(tmpdir(), "sentrook-holds-"));
  copyFileSync(path.join(DASH, "holds.json"), path.join(holdsDir, "holds.json"));
  const model = scansModel(path.join(FIXTURES, "traffic.jsonl"), true, 50);
  const now = new Date("2026-10-29T09:47:00Z");
  const got = pendingOf(model, holdsDir, now, 300_000);
  assert.deepStrictEqual(got, JSON.parse(readFileSync(path.join(DASH, "pending.json"), "utf8")));
  assert.ok(!JSON.stringify(got).includes(RAW), "a hold's notice is never shown");
  // Past the answer window the prompt has timed out: no longer pending.
  assert.deepStrictEqual(pendingOf(model, holdsDir, new Date("2026-10-29T09:51:00Z"), 300_000).reviews, []);
  // A prompt that was answered is never pending.
  assert.ok(model.scans.filter((s: any) => s.review !== "no answer").every((s: any) => !s.open_review));
});

test("pending: an unreadable holds file says so and shows none", () => {
  const holdsDir = mkdtempSync(path.join(tmpdir(), "sentrook-holds-"));
  writeFileSync(path.join(holdsDir, "holds.json"), "not json");
  const got = pendingOf({ scans: [] }, holdsDir, new Date(), 300_000);
  assert.deepStrictEqual(got.holds, []);
  assert.equal(got.holds_readable, false);
});

test("buildModel adds the review and block lines, mode, grants and snooze text", () => {
  const m = buildModel(cfg(), 10);
  assert.deepStrictEqual(m.lines, { review_at: 45, block_at: 80 });
  assert.equal(m.mode, "enforce");
  assert.equal(typeof m.state.grants, "string");
  assert.equal(typeof m.state.snooze, "string");
  assert.deepStrictEqual(m.commands, COMMANDS);
  assert.equal(m.commands.prefix, "/sentrook-");
  assert.equal(m.pending.review_window_s, 300);
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

test("a path that only shares the prefix is left to the Gateway", () => {
  let touched = false;
  const handled = handleRequest(
    { method: "GET", url: "/sentrook-other" },
    { statusCode: 0, setHeader: () => (touched = true), end: () => (touched = true) },
    cfg,
  );
  assert.equal(handled, false);
  assert.equal(touched, false);
});

test("other paths under the route are not served", () => {
  assert.equal(call("GET", `${ROUTE}/api/resolve`).status, 404);
  // Normalised to /etc/passwd: not under the route, so not answered here.
  assert.equal(call("GET", `${ROUTE}/../etc/passwd`).status, 0);
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

// --- The view, drawn into a minimal DOM: what the page shows for the fixture model.

class FakeNode {
  tag: string;
  children: FakeNode[] = [];
  attrs: Record<string, string> = {};
  className = "";
  id = "";
  listeners: Record<string, Array<() => void>> = {};
  private ownText: string | null = null;
  ownerDocument: any;
  constructor(tag: string, doc: any) {
    this.tag = tag;
    this.ownerDocument = doc;
  }
  set textContent(v: string) {
    this.ownText = v;
    this.children = [];
  }
  get textContent(): string {
    return this.ownText ?? this.children.map((c) => c.textContent).join("");
  }
  get firstChild() {
    return this.children[0] ?? null;
  }
  appendChild(n: FakeNode) {
    this.ownText = this.ownText === null ? null : this.ownText;
    this.children.push(n);
    return n;
  }
  removeChild(n: FakeNode) {
    this.children = this.children.filter((c) => c !== n);
    return n;
  }
  setAttribute(k: string, v: string) {
    this.attrs[k] = v;
  }
  getAttribute(k: string) {
    return this.attrs[k] ?? null;
  }
  addEventListener(type: string, fn: () => void) {
    (this.listeners[type] ??= []).push(fn);
  }
  click() {
    for (const fn of this.listeners.click ?? []) fn();
  }
  all(): FakeNode[] {
    return [this, ...this.children.flatMap((c) => c.all())];
  }
  byClass(cls: string): FakeNode[] {
    return this.all().filter((n) => n.className.split(" ").includes(cls));
  }
}

function drawView(model: unknown): FakeNode {
  const doc: any = { documentElement: null, head: null };
  const make = (tag: string) => new FakeNode(tag, doc);
  doc.createElement = make;
  doc.createTextNode = (t: string) => {
    const n = make("#text");
    n.textContent = t;
    return n;
  };
  doc.documentElement = make("html");
  doc.head = make("head");
  const root = make("div");
  const data = make("script");
  data.textContent = JSON.stringify(model);
  doc.getElementById = (id: string) =>
    id === "sentrook-root" ? root : id === "sentrook-model" ? data : doc.head.children.find((c: FakeNode) => c.id === id) ?? null;
  const window: any = { location: { search: "" } };
  new Script(viewScript()).runInNewContext({ document: doc, window, setTimeout: () => 0, navigator: {} });
  return root;
}

function viewModel(): any {
  return { ...scansModel(logFile, true, 50), lines: { review_at: 45, block_at: 80 }, mode: "enforce", state: { grants: "g", snooze: "s" }, commands: {} };
}

test("the view draws the newest scan's risk tree: tiers, leaves, badges and reasons under their leaf", () => {
  const root = drawView(viewModel());
  const detail = root.byClass("srk-detail");
  assert.equal(detail.length, 1, "the newest scan opens on first draw");
  const text = detail[0]!.textContent;
  assert.match(text, /Floor: credential_exfiltration ≥ 85/);
  assert.match(text, /Scanner requires: block/);
  const tiers = detail[0]!.byClass("srk-tier");
  assert.deepStrictEqual(tiers.map((t) => t.byClass("srk-tier-name")[0]!.textContent), ["Suspicion", "Consequence", "Confidence"]);
  // Every leaf shows its number as text, or "not assessed".
  const leaves = detail[0]!.byClass("srk-leaf");
  assert.equal(leaves.length, 9 + 1 + 4 + 3);
  for (const leaf of leaves) assert.match(leaf.byClass("srk-leaf-val")[0]!.textContent, /^(\d+|not assessed)$/);
  const concealment = leaves.find((l) => l.textContent.startsWith("Concealment"))!;
  assert.ok(concealment.className.includes("srk-na"));
  // A reason sits under the leaf its signal names, with entity names filled in as text.
  const distrust = leaves.find((l) => l.textContent.startsWith("Distrust"))!;
  assert.match(distrust.textContent, /distrust\.unknown_destination.*sends data to <script>alert\(1\)<\/script>evil\.example/);
  const other = text.slice(text.indexOf("Other reasons"));
  assert.match(other, /floor\.credential_exfiltration/);
  assert.match(other, /future\.thing/);
});

test("the view shows relief and the ceiling, and a failed scan without scores", () => {
  const root = drawView(viewModel());
  const rows = root.byClass("srk-row");
  rows.find((r) => r.textContent.includes("38"))!.click();
  const relief = root.byClass("srk-detail").find((d) => d.textContent.includes("Relief"))!;
  assert.match(relief.textContent, /Relief: distrust\+untrusted_origin \(grant g-3\)/);
  assert.match(relief.textContent, /At most: review/);
  rows.at(-1)!.click();
  const failed = root.byClass("srk-detail").find((d) => d.textContent.includes("The scan failed"))!;
  assert.match(failed.textContent, /The scan failed \(timeout\)/);
  assert.equal(failed.byClass("srk-tier").length, 0);
});

test("signals start collapsed; every tier, signal and value carries a hover hint", () => {
  const root = drawView(viewModel());
  const detail = root.byClass("srk-detail")[0]!;
  const signals = detail.byClass("srk-signals");
  assert.equal(signals.length, 3);
  for (const d of signals) assert.equal(d.getAttribute("open"), null, "collapsed by default");
  for (const tier of detail.byClass("srk-tier")) {
    assert.ok(tier.byClass("srk-tier-name")[0]!.getAttribute("title"));
    assert.ok(tier.byClass("srk-tier-score")[0]!.getAttribute("title"));
  }
  for (const leaf of detail.byClass("srk-leaf")) {
    const label = leaf.byClass("srk-leaf-top")[0]!.children[0]!;
    assert.ok((label.getAttribute("title") ?? "").length > 20, `${label.textContent} has a hint`);
    assert.ok(leaf.byClass("srk-leaf-val")[0]!.getAttribute("title"));
  }
  for (const chip of detail.byClass("srk-chip")) assert.ok(chip.getAttribute("title"), chip.textContent);
  for (const dt of detail.all().filter((n) => n.tag === "dt")) assert.ok(dt.getAttribute("title"), dt.textContent);
});

test("the timeline has one cell per scan, oldest first, and opens a scan on click", () => {
  const model = viewModel();
  const root = drawView(model);
  const cells = root.byClass("srk-tl-cell");
  assert.equal(cells.length, model.scans.length);
  assert.match(cells[0]!.getAttribute("title")!, /web_fetch/);
  assert.match(cells.at(-1)!.getAttribute("title")!, /terminal · risk 86 · blocked/);
  assert.equal(root.byClass("srk-detail").length, 1);
  cells[0]!.click();
  assert.equal(root.byClass("srk-detail").length, 2);
  // No count chips above the list any more: counts live in the timeline legend.
  assert.equal(root.byClass("srk-head")[0]!.byClass("srk-chip").length, 0);
});

test("pending items sit at the top with the commands to answer them", () => {
  const model: any = viewModel();
  const review = model.scans.find((s: any) => s.bucket === "review");
  model.pending = JSON.parse(readFileSync(path.join(DASH, "pending.json"), "utf8"));
  model.pending.reviews = [review.id];
  model.commands = COMMANDS;
  const root = drawView(model);
  assert.equal(root.children[1]!.className, "srk-pending", "right under the header");
  const text = root.byClass("srk-pending")[0]!.textContent;
  assert.match(text, /Waiting for you \(4\)/);
  assert.match(text, /\/approve <approval id> deny/);
  assert.match(text, new RegExp(`/sentrook-why ${review.id.slice(0, 8)}`));
  assert.match(text, /\/sentrook-approve h-2c2c2c/);
  assert.match(text, /destination channel:1234567890/);
  assert.match(text, /There is no suggested grant/);
  // The open prompt carries the same breakdown as an opened scan, without repeating its why command.
  const panel = root.byClass("srk-pending")[0]!;
  const details = panel.byClass("srk-detail");
  assert.equal(details.length, 1, "the review's scan is in the list; the holds' scans are not");
  assert.equal(details[0]!.byClass("srk-tier").length, 3);
  assert.equal(details[0]!.byClass("srk-meter").length, 1);
  assert.match(panel.textContent, /Its scan is older than the scans shown here; \/sentrook-why h-2c2c2c shows it/);
  // A hold whose scan is in the list shows its breakdown too.
  model.pending.holds[0].request_id = model.scans[0].id;
  assert.equal(drawView(model).byClass("srk-pending")[0]!.byClass("srk-detail").length, 2);
  // Nothing pending: no panel.
  assert.equal(drawView(viewModel()).byClass("srk-pending").length, 0);
});

test("grants and snooze sections explain the commands, in this host's command form", () => {
  const model: any = { ...viewModel(), commands: { prefix: "/sentrook " } };
  const root = drawView(model);
  const sections = root.byClass("srk-howto");
  assert.equal(sections.length, 2);
  assert.equal(sections[0]!.getAttribute("open"), null);
  assert.match(sections[0]!.textContent, /\/sentrook grant destination api\.example\.com --persistent --expires 30d/);
  assert.match(sections[1]!.textContent, /\/sentrook snooze 2h --all/);
});

test("the view never writes markup: no innerHTML, outerHTML, insertAdjacentHTML or document.write", () => {
  assert.doesNotMatch(viewScript(), /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
});

test("the view copes with a model missing its lines, totals and state", () => {
  assert.doesNotThrow(() => drawView({ log: "on", limit: 10, scans: [] }));
});
