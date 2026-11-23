import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Script } from "node:vm";
import { afterEach, beforeEach, test } from "node:test";

import { resolveConfig } from "./config.ts";
import {
  budgetFor,
  buildModel,
  CALL_TOTAL_MAX,
  callOf,
  COMMANDS,
  handleRequest,
  limitOf,
  pendingOf,
  queryOf,
  queryScans,
  renderPage,
  ROUTE,
  scanModel,
  scansModel,
  scriptJson,
  TAB,
  viewScript,
} from "./dashboard.ts";
import plugin from "./index.ts";
import * as report from "./report.ts";

/** Shared with the Hermes plugin's tests: both plugins build the same model for the same log. */
const FIXTURES = fileURLToPath(new URL("../../fixtures/traffic-log/", import.meta.url));
const DASH = path.join(FIXTURES, "dashboard");
/** Strings that appear only in call arguments, reason and floor details, descriptions and failure details. */
const RAW = "RAW-ARG-MARKER";
const HERMES_VIEW = fileURLToPath(new URL("../../hermes/plugin/dashboard/view.js", import.meta.url));
const BRAND_MARK = fileURLToPath(new URL("../../../brand/sentrook-mark.svg", import.meta.url));
const SVG_NS = "http://www.w3.org/2000/svg";

const ENV_KEYS = ["OPENCLAW_STATE_DIR", "SENTROOK_TRAFFIC_LOG", "SENTROOK_TRAFFIC_LOG_ENABLED", "SENTROOK_DASHBOARD_SHOW_CALLS"];
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
async function call(method: string, url: string, load = cfg): Promise<Captured> {
  const out: Captured = { status: 0, headers: {}, body: undefined };
  await handleRequest(
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

test("background saves count where they ended: drafts under review, a lost draft under blocked, a let-through save flagged", () => {
  const scan = (decision: string, extra: Record<string, unknown> = {}) => ({
    request_id: `r-${decision}`,
    mode: "enforce",
    verdict: "review",
    decision,
    background_save: { kind: "background_review", store: "skills" },
    response: { risk: 55, status: "ok" },
    ...extra,
  });
  const rows: Array<[Record<string, unknown>, Record<string, unknown> | null, string, string]> = [
    [scan("drafted"), null, "sent to drafts (self-edit)", "review"],
    [scan("drafted"), { resolution: "draft_saved" }, "drafted (self-edit)", "review"],
    [scan("drafted"), { resolution: "draft_failed" }, "not saved (draft refused, self-edit)", "blocked"],
    [scan("draft_failed"), null, "not saved (draft refused, self-edit)", "blocked"],
    [scan("drafted"), { resolution: "draft_ignored" }, "saved live (draft ignored, self-edit)", "allowed"],
    [scan("held"), null, "held (self-edit)", "review"],
    [scan("allowed", { lenient: true }), null, "allowed (let through, self-edit)", "allowed"],
  ];
  for (const [s, res, action, bucket] of rows) {
    const m = scanModel(s, res);
    assert.equal(m.action, action);
    assert.equal(m.bucket, bucket, action);
  }
  assert.deepEqual(scanModel(scan("allowed", { lenient: true }), null).flags, ["lenient"]);
  assert.deepEqual(scanModel(scan("drafted"), null).flags, []);
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

test("pending: open prompts inside the answer window and live holds with their scans, matching the shared fixture", async () => {
  const holdsDir = mkdtempSync(path.join(tmpdir(), "sentrook-holds-"));
  copyFileSync(path.join(DASH, "holds.json"), path.join(holdsDir, "holds.json"));
  const log = path.join(FIXTURES, "traffic.jsonl");
  const got = await pendingOf(log, true, holdsDir, new Date("2026-10-29T09:47:00Z"), 300_000);
  assert.deepStrictEqual(got, JSON.parse(readFileSync(path.join(DASH, "pending.json"), "utf8")));
  assert.ok(!JSON.stringify(got).includes(RAW), "a hold's notice and the scans' raw content are never shown");
  // Past the answer window the prompt has timed out: no longer pending.
  assert.deepStrictEqual((await pendingOf(log, true, holdsDir, new Date("2026-10-29T09:51:00Z"), 300_000)).reviews, []);
  // With the log off, holds still show, without scans.
  const off = await pendingOf(log, false, holdsDir, new Date("2026-10-29T09:47:00Z"), 300_000);
  assert.deepStrictEqual(off.reviews, []);
  assert.ok(off.holds.every((h: any) => h.scan === null));
});

test("pending: an unreadable holds file says so and shows none", async () => {
  const holdsDir = mkdtempSync(path.join(tmpdir(), "sentrook-holds-"));
  writeFileSync(path.join(holdsDir, "holds.json"), "not json");
  const got = await pendingOf(logFile, true, holdsDir, new Date(), 300_000);
  assert.deepStrictEqual(got.holds, []);
  assert.equal(got.holds_readable, false);
});

test("query: every shared case gives the same page as the Hermes plugin", async () => {
  const logs: Record<string, string> = {
    dashboard: logFile,
    history: path.join(FIXTURES, "traffic.jsonl"),
    edge: path.join(FIXTURES, "edge", "traffic.jsonl"),
  };
  for (const c of JSON.parse(readFileSync(path.join(DASH, "query-cases.json"), "utf8"))) {
    const r = await queryScans(logs[c.log]!, queryOf(new URLSearchParams(c.params)));
    assert.deepStrictEqual({ ids: r.scans.map((s: any) => s.id), page: r.page, query: r.query }, { ids: c.ids, page: c.page, query: c.query }, c.name);
  }
});

test("query: the read stops at the budget and says so", async () => {
  const r = await queryScans(logFile, queryOf(new URLSearchParams("tool=nothing-matches")), 1024);
  assert.equal(r.page.budget_hit, true);
  assert.equal(r.page.read_bytes, 1024);
  assert.deepStrictEqual(r.scans, []);
});

test("query: the read budget covers the whole log at its configured size, within 16 to 256 MB", () => {
  const MB = 1024 * 1024;
  assert.equal(budgetFor(50 * MB), 101 * MB);
  assert.equal(budgetFor(1 * MB), 16 * MB);
  assert.equal(budgetFor(1024 * MB), 256 * MB);
});

test("buildModel adds the review and block lines, mode, grants and snooze text", async () => {
  const m = await buildModel(cfg(), queryOf(new URLSearchParams("n=10")));
  assert.deepStrictEqual(m.lines, { review_at: 45, block_at: 80 });
  assert.equal(m.mode, "enforce");
  assert.equal(typeof m.state.grants, "string");
  assert.equal(typeof m.state.snooze, "string");
  assert.deepStrictEqual(m.commands, COMMANDS);
  assert.equal(m.commands.prefix, "/sentrook-");
  assert.equal(m.pending.review_window_s, 300);
  assert.equal(m.scans.length, 6);
  assert.equal(m.page.reached_start, true);
  assert.equal(m.query.limit, 10);
});

test("GET draws the page with the model embedded, a nonce CSP and no raw markup from the log", async () => {
  const res = await call("GET", `${ROUTE}?n=25`);
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
  assert.equal((await call("GET", `${ROUTE}?tool=web&outcome=review`)).body!.includes('"ids"'), false);
  assert.deepStrictEqual(embeddedModel((await call("GET", `${ROUTE}?tool=web&outcome=review`)).body!).scans.map((s: any) => s.tool), ["web_fetch"]);
  assert.equal(model.scans[0].entities[0].display, "<script>alert(1)</script>evil.example");
  assert.equal((await call("GET", `${ROUTE}/`)).status, 200);
});

test("HEAD sends the headers and no body", async () => {
  const res = await call("HEAD", ROUTE);
  assert.equal(res.status, 200);
  assert.equal(res.body, undefined);
});

test("every other method is refused: the dashboard is read-only", async () => {
  for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
    const res = await call(method, ROUTE);
    assert.equal(res.status, 405, method);
    assert.equal(res.headers.allow, "GET, HEAD");
  }
});

test("a path that only shares the prefix is left to the Gateway", async () => {
  let touched = false;
  const handled = await handleRequest(
    { method: "GET", url: "/sentrook-other" },
    { statusCode: 0, setHeader: () => (touched = true), end: () => (touched = true) },
    cfg,
  );
  assert.equal(handled, false);
  assert.equal(touched, false);
});

test("other paths under the route are not served", async () => {
  assert.equal((await call("GET", `${ROUTE}/api/resolve`)).status, 404);
  // Normalised to /etc/passwd: not under the route, so not answered here.
  assert.equal((await call("GET", `${ROUTE}/../etc/passwd`)).status, 0);
});

test("a config that cannot be read gives a 500 without details", async () => {
  const res = await call("GET", ROUTE, () => {
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

test("the header shows the Sentrook mark before the heading: the master logo's path, in the text colour, hidden from screen readers", () => {
  const head = drawView(viewModel()).byClass("srk-head")[0]!;
  const marks = head.all().filter((n) => n.tag === "svg");
  assert.equal(marks.length, 1, "one mark in the header");
  const mark = marks[0]!;
  assert.equal(head.children[0], mark, "the mark comes first, before the heading");
  assert.equal(head.children[1]!.tag, "h1");
  assert.equal(mark.namespaceURI, SVG_NS, "made as an SVG element, not HTML");
  assert.equal(mark.attrs.viewBox, "0 0 512 512");
  assert.equal(mark.attrs["aria-hidden"], "true", "the heading already says Sentrook");
  assert.equal(mark.attrs.focusable, "false");
  assert.equal(mark.children.length, 1);
  const pathNode = mark.children[0]!;
  assert.equal(pathNode.tag, "path");
  assert.equal(pathNode.namespaceURI, SVG_NS);
  assert.equal(pathNode.attrs.fill, "currentColor", "follows the host's text colour in every theme");
  const master = /\sd="([^"]+)"/.exec(readFileSync(BRAND_MARK, "utf8"))?.[1];
  assert.ok(master, "brand/sentrook-mark.svg has path data");
  assert.equal(pathNode.attrs.d, master, "the view carries the master logo's path; copy it again after editing the master");
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

test("register adds the route behind gateway auth and the tab through session.controls", async () => {
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
  await routes[0].handler(
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
  namespaceURI: string | null = null;
  listeners: Record<string, Array<(e?: any) => void>> = {};
  private ownText: string | null = null;
  ownerDocument: any;
  parentNode: FakeNode | null = null;
  style: Record<string, string> = {};
  offsetWidth = 120;
  offsetHeight = 30;
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
    n.parentNode = this;
    return n;
  }
  removeChild(n: FakeNode) {
    this.children = this.children.filter((c) => c !== n);
    n.parentNode = null;
    return n;
  }
  setAttribute(k: string, v: string) {
    this.attrs[k] = v;
  }
  removeAttribute(k: string) {
    delete this.attrs[k];
  }
  contains(n: FakeNode | null): boolean {
    for (let c = n; c; c = c.parentNode) if (c === this) return true;
    return false;
  }
  /** Only the selectors the view uses: a tag list, or one `[attr]`. */
  private matches(sel: string): boolean {
    const attr = /^\[([\w-]+)\]$/.exec(sel);
    return attr ? this.attrs[attr[1]!] !== undefined : sel.split(",").includes(this.tag);
  }
  closest(sel: string): FakeNode | null {
    for (let c: FakeNode | null = this; c; c = c.parentNode) if (c.matches(sel)) return c;
    return null;
  }
  querySelectorAll(sel: string): FakeNode[] {
    return this.all().slice(1).filter((n) => n.matches(sel));
  }
  getBoundingClientRect() {
    return { left: 100, top: 200, right: 160, bottom: 220, width: 60, height: 20 };
  }
  private typed: string | null = null;
  /** As the DOM has it: an input's value starts from its attribute; a select's is its selected option's. */
  get value(): string {
    if (this.tag === "select") {
      const opt = this.children.find((c) => c.attrs.selected !== undefined) ?? this.children[0];
      return opt?.attrs.value ?? "";
    }
    return this.typed ?? this.attrs.value ?? "";
  }
  set value(v: string) {
    this.typed = v;
  }
  getAttribute(k: string) {
    return this.attrs[k] ?? null;
  }
  addEventListener(type: string, fn: (e?: any) => void) {
    (this.listeners[type] ??= []).push(fn);
  }
  click() {
    for (const fn of this.listeners.click ?? []) fn();
  }
  /** Calls this node's listeners for `type`, then each ancestor's, as a bubbling event would. */
  fire(type: string, extra: Record<string, unknown> = {}) {
    const e = { type, target: this, ...extra };
    for (let c: FakeNode | null = this; c; c = c.parentNode) for (const fn of c.listeners[type] ?? []) fn(e);
  }
  all(): FakeNode[] {
    return [this, ...this.children.flatMap((c) => c.all())];
  }
  byClass(cls: string): FakeNode[] {
    return this.all().filter((n) => n.className.split(" ").includes(cls));
  }
}

function drawView(model: unknown): FakeNode {
  return drawViewWith(model).root;
}

function drawViewWith(model: unknown): { root: FakeNode; window: any; doc: any; tick: () => void; redraw: () => void } {
  const doc: any = { documentElement: null, head: null, listeners: {} as Record<string, Array<(e: any) => void>> };
  doc.addEventListener = (type: string, fn: (e: any) => void) => (doc.listeners[type] ??= []).push(fn);
  doc.removeEventListener = (type: string, fn: (e: any) => void) => {
    doc.listeners[type] = (doc.listeners[type] ?? []).filter((f: unknown) => f !== fn);
  };
  const make = (tag: string) => new FakeNode(tag, doc);
  doc.createElement = make;
  doc.createElementNS = (ns: string, tag: string) => {
    const n = make(tag);
    n.namespaceURI = ns;
    return n;
  };
  doc.createTextNode = (t: string) => {
    const n = make("#text");
    n.textContent = t;
    return n;
  };
  doc.documentElement = make("html");
  doc.documentElement.clientWidth = 800;
  doc.head = make("head");
  const root = make("div");
  const data = make("script");
  data.textContent = JSON.stringify(model);
  doc.getElementById = (id: string) =>
    id === "sentrook-root" ? root : id === "sentrook-model" ? data : doc.head.children.find((c: FakeNode) => c.id === id) ?? null;
  const window: any = { location: { search: "" }, innerHeight: 600 };
  doc.defaultView = window;
  const timers = new Map<number, () => void>();
  let next = 1;
  const setTimeout = (fn: () => void) => {
    timers.set(next, fn);
    return next++;
  };
  const clearTimeout = (id: number) => timers.delete(id);
  const run = () => new Script(viewScript()).runInNewContext({ document: doc, window, setTimeout, clearTimeout, navigator: {}, encodeURIComponent });
  run();
  /** Runs the timers due so far. */
  const tick = () => {
    const due = [...timers.values()];
    timers.clear();
    due.forEach((fn) => fn());
  };
  return { root, window, doc, tick, redraw: run };
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

test("relief from a cron job's own delivery target names the job, not a grant", () => {
  const model = viewModel();
  const scan = model.scans.find((s: any) => s.relief.length);
  scan.relief[0].grant_ref = "cron_delivery:j_2ec7326addd8";
  const root = drawView(model);
  root.byClass("srk-row").find((r) => r.textContent.includes("38"))!.click();
  const relief = root.byClass("srk-detail").find((d) => d.textContent.includes("Relief"))!;
  assert.match(relief.textContent, /Relief: distrust\+untrusted_origin \(a cron job's delivery target\)/);
  assert.doesNotMatch(relief.textContent, /\(grant /);
});

test("signals start collapsed; every tier, signal and value carries a hover hint", () => {
  const root = drawView(viewModel());
  const detail = root.byClass("srk-detail")[0]!;
  const signals = detail.byClass("srk-signals");
  assert.equal(signals.length, 3);
  for (const d of signals) assert.equal(d.getAttribute("open"), null, "collapsed by default");
  for (const tier of detail.byClass("srk-tier")) {
    assert.ok(tier.byClass("srk-tier-name")[0]!.getAttribute("data-srk-hint"));
    assert.ok(tier.byClass("srk-tier-score")[0]!.getAttribute("data-srk-hint"));
  }
  for (const leaf of detail.byClass("srk-leaf")) {
    const label = leaf.byClass("srk-leaf-top")[0]!.children[0]!;
    assert.ok((label.getAttribute("data-srk-hint") ?? "").length > 20, `${label.textContent} has a hint`);
    assert.ok(leaf.byClass("srk-leaf-val")[0]!.getAttribute("data-srk-hint"));
  }
  for (const chip of detail.byClass("srk-chip")) assert.ok(chip.getAttribute("data-srk-hint"), chip.textContent);
  for (const dt of detail.all().filter((n) => n.tag === "dt")) assert.ok(dt.getAttribute("data-srk-hint"), dt.textContent);
});

test("hints are drawn by the page: no title attributes, one hidden tooltip, hinted labels take focus", () => {
  const { root } = drawViewWith(viewModel());
  const all = root.all();
  assert.deepStrictEqual(all.filter((n) => n.getAttribute("title") !== null).map((n) => n.textContent), [], "no browser title tooltips");
  const tips = root.byClass("srk-tip");
  assert.equal(tips.length, 1);
  assert.equal(tips[0]!.getAttribute("role"), "tooltip");
  assert.notEqual(tips[0]!.getAttribute("hidden"), null, "hidden until asked for");
  const hinted = all.filter((n) => n.getAttribute("data-srk-hint"));
  assert.ok(hinted.length > 40, `${hinted.length} hinted elements`);
  const controls = ["a", "button", "input", "select", "textarea", "summary", "label"];
  for (const n of hinted) {
    const inControl = n.closest(controls.join(",")) !== null;
    assert.equal(n.getAttribute("tabindex") === "0", !inControl, `${n.tag} "${n.textContent.slice(0, 30)}" focusable only outside a control`);
  }
});

test("a hint shows on focus, hover and tap, as text, and hides on blur, Escape and a click elsewhere", () => {
  const { root, doc, tick } = drawViewWith(viewModel());
  const tip = root.byClass("srk-tip")[0]!;
  const name = root.byClass("srk-tier-name")[0]!;
  const hint = name.getAttribute("data-srk-hint")!;
  assert.ok(hint.length > 20);

  name.fire("focusin");
  assert.equal(tip.getAttribute("hidden"), null);
  assert.equal(tip.textContent, hint);
  assert.equal(name.getAttribute("aria-describedby"), "srk-tip");
  assert.match(tip.style.top!, /^-?\d+px$/);
  name.fire("focusout");
  assert.notEqual(tip.getAttribute("hidden"), null);
  assert.equal(name.getAttribute("aria-describedby"), null);

  // Hover waits a moment, then shows.
  const score = root.byClass("srk-tier-score")[0]!;
  score.fire("mouseover");
  assert.notEqual(tip.getAttribute("hidden"), null, "not straight away");
  tick();
  assert.equal(tip.textContent, score.getAttribute("data-srk-hint"));
  for (const fn of doc.listeners.keydown) fn({ key: "Escape" });
  assert.notEqual(tip.getAttribute("hidden"), null);

  // A tap on a label shows it; a tap on a control (the scan row) does not.
  name.fire("click");
  assert.equal(tip.getAttribute("hidden"), null);
  for (const fn of doc.listeners.click) fn({ target: doc.documentElement });
  assert.notEqual(tip.getAttribute("hidden"), null);
  const riskInRow = root.byClass("srk-row")[0]!.byClass("srk-risk")[0]!;
  riskInRow.fire("click");
  assert.notEqual(tip.getAttribute("hidden"), null);
});

test("a redraw into the same root: one tooltip, no hover left waiting for an old element, listeners kept once", () => {
  const { root, doc, tick, redraw } = drawViewWith(viewModel());
  const clicks = doc.listeners.click.length;
  const oldScore = root.byClass("srk-tier-score")[0]!;
  oldScore.fire("mouseover");
  redraw();
  tick();
  const tips = root.byClass("srk-tip");
  assert.equal(tips.length, 1);
  assert.notEqual(tips[0]!.getAttribute("hidden"), null, "the old hover never shows");
  assert.equal(doc.listeners.click.length, clicks, "no second set of page-wide listeners");
  const name = root.byClass("srk-tier-name")[0]!;
  name.fire("focusin");
  assert.equal(tips[0]!.textContent, name.getAttribute("data-srk-hint"));
});

test("a root that has left the page drops its page-wide listeners", () => {
  const { root, doc } = drawViewWith(viewModel());
  (root as any).isConnected = false;
  for (const fn of [...doc.listeners.keydown]) fn({ key: "Escape" });
  assert.equal(doc.listeners.keydown.length, 0);
  assert.equal(doc.listeners.click.length, 0);
});

test("hint text goes in as text: markup in a hint is not parsed", () => {
  const model = viewModel();
  model.scans[0].tool = "<img src=x onerror=alert(1)>";
  const { root } = drawViewWith(model);
  // A timeline cell's hint names the scan's tool, which comes from the log.
  const cell = root.byClass("srk-tl-cell").at(-1)!;
  cell.fire("focusin");
  const tip = root.byClass("srk-tip")[0]!;
  assert.match(tip.textContent, /^<img src=x onerror=alert\(1\)> · risk/);
  assert.equal(tip.children.length, 0, "set as text, no child nodes");
});

test("the timeline has one cell per scan, oldest first, and opens a scan on click", () => {
  const model = viewModel();
  const root = drawView(model);
  const cells = root.byClass("srk-tl-cell");
  assert.equal(cells.length, model.scans.length);
  assert.match(cells[0]!.getAttribute("data-srk-hint")!, /web_fetch/);
  assert.match(cells.at(-1)!.getAttribute("data-srk-hint")!, /terminal · risk 86 · blocked/);
  assert.equal(root.byClass("srk-detail").length, 1);
  cells[0]!.click();
  assert.equal(root.byClass("srk-detail").length, 2);
  // No count chips above the list any more: counts live in the timeline legend.
  assert.equal(root.byClass("srk-head")[0]!.byClass("srk-chip").length, 0);
});

test("pending items sit at the top with the commands to answer them and their full breakdown", () => {
  const model: any = viewModel();
  model.pending = JSON.parse(readFileSync(path.join(DASH, "pending.json"), "utf8"));
  model.commands = COMMANDS;
  const root = drawView(model);
  assert.equal(root.children[1]!.className, "srk-pending-section", "right under the header");
  const section = root.byClass("srk-pending-section")[0]!;
  const text = section.textContent;
  assert.match(text, /^Waiting for you4/);
  // Each waiting item has its own box.
  assert.equal(section.byClass("srk-pending-item").length, 4);
  // History follows as its own section.
  assert.equal(root.children[2]!.textContent, "History6");
  assert.match(text, /\/approve <approval id> deny/);
  assert.match(text, /\/sentrook-why 8888a1b2/);
  assert.match(text, /\/sentrook-approve h-2c2c2c/);
  assert.match(text, /destination channel:1234567890/);
  assert.match(text, /There is no suggested grant/);
  // The open prompt and the hold whose scan is still in the log carry the full breakdown, without repeating why.
  const details = section.byClass("srk-detail");
  assert.equal(details.length, 2);
  for (const d of details) {
    assert.equal(d.byClass("srk-tier").length, 3);
    assert.equal(d.byClass("srk-meter").length, 1);
    assert.equal(d.byClass("srk-cmd").length, 0);
  }
  assert.match(text, /Its scan is no longer in the traffic log; \/sentrook-why h-3d3d3d shows it/);
  // Nothing pending: no section, and History comes first.
  const quiet = drawView(viewModel());
  assert.equal(quiet.byClass("srk-pending-section").length, 0);
  assert.equal(quiet.children[1]!.textContent, "History6");
});

test("search: the form shows the query, the status says how far the log was read, Older pages on", () => {
  const model: any = {
    ...viewModel(),
    limit: 2,
    scans: viewModel().scans.slice(0, 2),
    query: { limit: 2, before: null, from: "2026-11-19T09:00:00.000Z", to: null, tool: "web", outcome: "review", min_risk: 40, session: null },
    page: { more: true, next: "d5d5d5d5-0000-4000-8000-000000000005", read_bytes: 3 * 1024 * 1024, budget_hit: false, cursor_lost: false, reached_start: false },
  };
  const { root, window } = drawViewWith(model);
  // No <form>: OpenClaw's sandboxed tab frame blocks form submission.
  assert.equal(root.all().filter((n) => n.tag === "form").length, 0);
  const form = root.byClass("srk-search")[0]!;
  const inputs = form.all().filter((n) => n.tag === "input");
  assert.equal(inputs[0]!.attrs.value, "web");
  assert.match(root.byClass("srk-status")[0]!.textContent, /Showing 2 matching scans, newest first\. Read 3\.0 MB of the log\./);
  const older = root.byClass("srk-pager")[0]!.all().find((n) => n.tag === "button" && n.textContent === "Older →")!;
  older.click();
  const qs = new URLSearchParams(window.location.search.slice(1));
  assert.equal(qs.get("before"), "d5d5d5d5-0000-4000-8000-000000000005");
  assert.equal(qs.get("tool"), "web");
  assert.equal(qs.get("outcome"), "review");
  assert.equal(qs.get("risk"), "40");
  assert.equal(qs.get("from"), "2026-11-19T09:00:00.000Z");
  assert.equal(qs.get("n"), "2");
  // Search navigates with the form's values and starts again from the newest.
  model.page.more = false;
  const fresh = drawViewWith(model);
  fresh.root.byClass("srk-search")[0]!.all().find((n) => n.tag === "button" && n.textContent === "Search")!.click();
  const sq = new URLSearchParams(fresh.window.location.search.slice(1));
  assert.equal(sq.get("tool"), "web");
  assert.equal(sq.get("before"), null);
  // A page that continued from a cursor offers the way back to the newest.
  model.query.before = "d5d5d5d5-0000-4000-8000-000000000005";
  const back = drawViewWith(model).root.byClass("srk-pager")[0]!.all().find((n) => n.tag === "button" && n.textContent === "← Newest");
  assert.ok(back);
});

test("search: the read limit, a lost cursor and an empty result each say so", () => {
  const base: any = { ...viewModel(), query: { limit: 10, before: "abcd1234", tool: "x" } };
  const hit = drawView({ ...base, scans: [], page: { read_bytes: 1, budget_hit: true, cursor_lost: false } });
  assert.match(hit.byClass("srk-status")[0]!.textContent, /Stopped after the read limit/);
  assert.match(hit.byClass("srk-empty")[0]!.textContent, /No scans match this search/);
  const lost = drawView({ ...base, scans: [], page: { read_bytes: 1, budget_hit: false, cursor_lost: true } });
  assert.match(lost.byClass("srk-status")[0]!.textContent, /no longer in the log/);
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

const REPORT_FIXTURES = path.join(FIXTURES, "report");

test("report: buildModel adds the asked-for scan's report panel only when asked, and says when it is gone", async () => {
  copyFileSync(path.join(REPORT_FIXTURES, "traffic.jsonl"), logFile);
  const plain = await buildModel(cfg(), queryOf(new URLSearchParams("n=10")));
  assert.equal("report" in plain, false);
  const m = await buildModel(cfg(), queryOf(new URLSearchParams("n=10")), new Date(), "aaaa1b2c");
  const found = report.find(logFile, (id) => id.startsWith("aaaa1b2c"))!;
  assert.deepStrictEqual(m.report, report.model(found, (v) => `/sentrook-${v}`));
  assert.deepStrictEqual(m.report.full_commands, ["/sentrook-report aaaa1b2c --save", "/sentrook-report aaaa1b2c --full"]);
  assert.ok(!/PLANIR-BODY-MARKER|PRIVATE-PATH-MARKER/.test(JSON.stringify(m)));
  assert.equal(m.report.summary, readFileSync(path.join(REPORT_FIXTURES, "summary-aaaa1b2c.txt"), "utf8").trimEnd());
  for (const ref of ["abcdef12", "last", "../etc"]) {
    assert.deepStrictEqual((await buildModel(cfg(), queryOf(new URLSearchParams("")), new Date(), ref)).report, { id: ref, missing: true }, ref);
  }
});

test("report: GET with report= embeds the panel, never the full record", async () => {
  copyFileSync(path.join(REPORT_FIXTURES, "traffic.jsonl"), logFile);
  const body = (await call("GET", `${ROUTE}?n=10&report=aaaa1b2c`)).body!;
  const model = embeddedModel(body);
  assert.equal(model.report.id, "aaaa1b2c-0000-4000-8000-00000000000a");
  assert.ok(!body.includes("PLANIR-BODY-MARKER") && !body.includes("PRIVATE-PATH-MARKER"));
  assert.equal("report" in embeddedModel((await call("GET", `${ROUTE}?n=10`)).body!), false);
});

test("report: every scan offers a report button that keeps the search and adds the scan id", () => {
  const model: any = { ...viewModel(), query: { limit: 10, tool: "web", min_risk: 40 } };
  const { root, window } = drawViewWith(model);
  const buttons = root.all().filter((n) => n.tag === "button" && n.textContent === "Report this scan…");
  assert.ok(buttons.length >= 1);
  buttons[0]!.click();
  const qs = new URLSearchParams(window.location.search.slice(1));
  assert.equal(qs.get("report"), model.scans[0].id);
  assert.equal(qs.get("tool"), "web");
  assert.equal(qs.get("risk"), "40");
});

test("report: the panel shows the summary, the GitHub and email links, the full record behind a warning, and Close", () => {
  copyFileSync(path.join(REPORT_FIXTURES, "traffic.jsonl"), logFile);
  const found = report.find(logFile, (id) => id.startsWith("aaaa1b2c"))!;
  const panel = report.model(found, (v) => `/sentrook-${v}`);
  const { root, window } = drawViewWith({ ...viewModel(), query: { limit: 10, tool: "web" }, report: panel });
  const box = root.byClass("srk-report")[0]!;
  assert.equal(root.children.indexOf(box), 1); // right under the header
  const areas = box.all().filter((n) => n.tag === "textarea");
  assert.deepStrictEqual(areas.map((a) => a.textContent), [panel.summary]);
  assert.equal(areas[0]!.attrs.readonly, "readonly");
  const links = box.all().filter((n) => n.tag === "a");
  assert.deepStrictEqual(links.map((a) => a.attrs.href), [panel.github, panel.mailto]);
  assert.equal(links[0]!.attrs.target, "_blank");
  assert.match(links[0]!.attrs.rel!, /noopener/);
  // The full record sits in a collapsed section after the warning.
  const details = box.all().find((n) => n.tag === "details")!;
  assert.equal(details.attrs.open, undefined);
  assert.ok(details.textContent.includes(panel.full_warning));
  const codes = details.all().filter((n) => n.tag === "code").map((n) => n.textContent);
  assert.deepStrictEqual(codes, ["/sentrook-report aaaa1b2c --save", "/sentrook-report aaaa1b2c --full"]);
  assert.equal(root.all().filter((n) => n.tag === "form").length, 0);
  // Copy falls back without a clipboard (the test window has none), and Close keeps the search.
  box.all().find((n) => n.tag === "button" && n.textContent === "Copy report")!.click();
  box.all().find((n) => n.tag === "button" && n.textContent === "Close")!.click();
  const qs = new URLSearchParams(window.location.search.slice(1));
  assert.equal(qs.get("report"), null);
  assert.equal(qs.get("tool"), "web");
});

test("report: a scan no longer in the log says so", () => {
  const root = drawView({ ...viewModel(), report: { id: "abcdef12", missing: true } });
  const box = root.byClass("srk-report")[0]!;
  assert.match(box.textContent, /not in the recent traffic log/);
  assert.equal(box.all().filter((n) => n.tag === "textarea").length, 0);
});

// ---- Showing the call (dashboardShowCalls, off by default) ----

const CALLS_LOG = path.join(DASH, "calls.jsonl");
/** Strings in the calls fixture that sit outside the pending call's tool and arguments. */
const NOT_THE_CALL = ["REQUEST-TEXT-MARKER", "HISTORY-MARKER", "NARRATION-MARKER", "SIBLING-MARKER", "DETAIL-MARKER", "planir"];

function useCallsLog() {
  copyFileSync(CALLS_LOG, logFile);
}

test("callOf bounds each call as the shared fixture has it (the Hermes plugin builds the same)", () => {
  const got = readFileSync(CALLS_LOG, "utf8").trim().split("\n").map((l) => callOf(JSON.parse(l)));
  assert.deepStrictEqual(got, JSON.parse(readFileSync(path.join(DASH, "calls.json"), "utf8")));
  // Cuts count code points; the whole call has one budget; nesting, lists and keys are capped; no PlanIR, no call.
  assert.match(got[3]!.arguments.content, /^x{8000}… \(1000 more characters\)$/);
  const sizes = Object.values(got[4]!.arguments as Record<string, string>).map((v) => [...v.split("…")[0]!].length);
  assert.equal(sizes.reduce((a, b) => a + b, 0), CALL_TOTAL_MAX);
  assert.equal(got[7]!.arguments.deep.a.b.c.d.e.f.g, "… (nested too deep)");
  assert.equal(got[6]!.arguments.items.length, 101);
  assert.equal(got[10]!.arguments && Object.keys(got[10]!.arguments).length, 0);
  assert.equal(got[11], null);
  // Numbers as JavaScript reads them: past 2^53 a double, past the double range null; long keys cut.
  assert.deepStrictEqual(Object.values(got[12]!.arguments).slice(0, 4), [null, 2 ** 60, 2 ** 53, -(2 ** 60)]);
  assert.equal(Object.keys(got[12]!.arguments)[4], "k".repeat(200) + "…");
  assert.equal(got[2]!.arguments.background, false);
});

test("the setting is off by default; config or env turns it on", () => {
  assert.equal(resolveConfig({}, {}).dashboardShowCalls, false);
  assert.equal(resolveConfig({ dashboardShowCalls: true }, {}).dashboardShowCalls, true);
  assert.equal(resolveConfig({}, { SENTROOK_DASHBOARD_SHOW_CALLS: "1" }).dashboardShowCalls, true);
  assert.equal(resolveConfig({ dashboardShowCalls: false }, { SENTROOK_DASHBOARD_SHOW_CALLS: "1" }).dashboardShowCalls, false);
});

test("must stay silent: with the setting off, neither the model nor the page holds any part of a call", async () => {
  useCallsLog();
  const m = await buildModel(cfg(), queryOf(new URLSearchParams("n=50")));
  assert.equal(m.show_calls, false);
  assert.equal(m.scans.length, 13);
  for (const s of m.scans) assert.ok(!("call" in s));
  const page = (await call("GET", ROUTE + "?n=50")).body!;
  for (const marker of [...NOT_THE_CALL, "notes/todo.md", "git status", "#général"]) assert.ok(!page.includes(marker), marker);
});

test("must fire: with the setting on, each scan carries its call and nothing else from the PlanIR", async () => {
  useCallsLog();
  const on = () => resolveConfig({ dashboardShowCalls: true }, process.env);
  const m = await buildModel(on(), queryOf(new URLSearchParams("n=50")));
  assert.equal(m.show_calls, true);
  const byTool = (t: string) => m.scans.filter((s: any) => s.tool === t);
  assert.deepStrictEqual(byTool("edit").at(-1).call, {
    tool: "edit",
    arguments: { path: "notes/todo.md", old_string: "- [ ] ship\n", new_string: "- [x] ship\n- [ ] <script>alert(1)</script>\n" },
  });
  assert.equal(byTool("web_fetch")[0].call, null, "a record without a PlanIR");
  const json = JSON.stringify(m);
  for (const marker of NOT_THE_CALL) assert.ok(!json.includes(marker), marker);
  const page = (await call("GET", ROUTE + "?n=50", on)).body!;
  assert.ok(page.includes("notes/todo.md"));
  assert.ok(!page.includes("<script>alert(1)"), "the call is embedded as JSON, never as markup");
});

test("the view: with calls off, Show the call says how to turn it on; with calls on, it draws the arguments as text", async () => {
  useCallsLog();
  const off = drawView(await buildModel(cfg(), queryOf(new URLSearchParams("n=50"))));
  const section = off.byClass("srk-call")[0]!;
  assert.equal(section.tag, "details");
  assert.equal(section.getAttribute("open"), null, "collapsed");
  assert.match(section.textContent, /openclaw config set plugins\.entries\.sentrook\.config\.dashboardShowCalls true/);
  assert.match(section.textContent, /\/sentrook-report ca110013 --save/);

  const model = await buildModel(resolveConfig({ dashboardShowCalls: true }, process.env), queryOf(new URLSearchParams("n=50&tool=edit")));
  const root = drawView(model);
  const opened = root.byClass("srk-scan")[0]!;
  const text = opened.byClass("srk-call")[0]!.textContent;
  assert.match(text, /^Show the call/);
  assert.match(text, /edits/);
  // An edit's before and after text sit side by side; markup in them is text.
  root.byClass("srk-row").at(-1)!.click();
  const edit = root.byClass("srk-call-edit").find((e) => e.textContent.includes("<script>"))!;
  assert.deepStrictEqual(edit.byClass("srk-call-text").map((n) => n.textContent), ["- [ ] ship\n", "- [x] ship\n- [ ] <script>alert(1)</script>\n"]);
  assert.ok(!edit.all().some((n) => n.tag === "script"));
  assert.match(edit.textContent, /Before \(old_string\)[\s\S]*After \(new_string\)/);
});

test("the view: a pending item's breakdown has no Show the call section while calls are off", () => {
  const model = viewModel();
  model.pending = JSON.parse(readFileSync(path.join(DASH, "pending.json"), "utf8"));
  const root = drawView(model);
  const items = root.byClass("srk-pending-item");
  assert.ok(items.length, "the pending panel draws");
  for (const item of items) assert.equal(item.byClass("srk-call").length, 0);
});
