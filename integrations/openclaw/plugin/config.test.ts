import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { configProblemsNotice, DEFAULT_SCAN_URL, GRANT_KINDS, parseEndpoint, resolveConfig, SETTING_NAMES } from "./config.ts";
import { KINDS } from "./grants.ts";
import { runVerify } from "./verify.ts";

test("endpoints default to the hosted service", () => {
  const cfg = resolveConfig({}, { HOME: "/home/u" });
  assert.deepEqual(cfg.endpoints.scan, { ok: true, url: DEFAULT_SCAN_URL });
  assert.equal(cfg.endpoints.dev, false);
  assert.equal(cfg.stateDir, "/home/u/.openclaw/sentrook");
  assert.equal(cfg.trafficLog.path, "/home/u/.openclaw/sentrook/traffic.jsonl");
});

test("a firstdataunion.org dev instance is accepted without the dev switch", () => {
  const cfg = resolveConfig(
    {},
    {
      SENTROOK_SCAN_URL: "https://dev.sentrook.firstdataunion.org/",
      SENTROOK_OIDC_ISSUER: "https://dev.identity.firstdataunion.org",
      SENTROOK_ROOKERY_URL: "https://dev.rookery.firstdataunion.org",
    },
  );
  assert.deepEqual(cfg.endpoints.scan, { ok: true, url: "https://dev.sentrook.firstdataunion.org" });
  assert.equal(cfg.endpoints.issuer.ok, true);
  assert.equal(cfg.endpoints.rookery.ok, true);
});

test("other hosts, http and explicit ports need the dev switch", () => {
  for (const url of [
    "https://sentrook.example.com",
    "https://evilfirstdataunion.org",
    "https://firstdataunion.org.evil.example",
    "http://sentrook.firstdataunion.org",
    "https://sentrook.firstdataunion.org:8443",
    "http://sentrook:8080",
  ]) {
    assert.equal(parseEndpoint(url, false).ok, false, url);
  }
  assert.deepEqual(parseEndpoint("http://sentrook:8080/", true), { ok: true, url: "http://sentrook:8080" });
});

test("credentials and metadata addresses are refused even in dev mode", () => {
  assert.equal(parseEndpoint("https://user:pw@sentrook.firstdataunion.org", true).ok, false);
  assert.equal(parseEndpoint("http://169.254.169.254/", true).ok, false);
  assert.equal(parseEndpoint("file:///etc/passwd", true).ok, false);
});

test("a URL that cannot be parsed is refused without quoting it", () => {
  for (const dev of [false, true]) {
    assert.deepEqual(parseEndpoint("https://u:pw-91c7e2@scan.test:99999", dev), {
      ok: false,
      reason: "invalid URL (could not be parsed)",
    });
  }
});

test("the dev switch is read from env, never plugin config", () => {
  const cfg = resolveConfig({ scanUrl: "http://sentrook:8080", devEndpoints: true }, {});
  assert.equal(cfg.endpoints.scan.ok, false);
  const dev = resolveConfig({ scanUrl: "http://sentrook:8080" }, { SENTROOK_DEV_ENDPOINTS: "1" });
  assert.equal(dev.endpoints.scan.ok, true);
});

test("decision policy defaults and overrides", () => {
  const d = resolveConfig({}, {});
  assert.equal(d.mode, "enforce");
  assert.equal(d.reviewAt, 45);
  assert.equal(d.blockAt, 80);
  assert.equal(d.onScanError, "review");
  const o = resolveConfig({ reviewAt: 50 }, { SENTROOK_MODE: "observe", SENTROOK_BLOCK_AT: "30" });
  assert.equal(o.mode, "observe");
  assert.equal(o.reviewAt, 50);
  assert.equal(o.blockAt, 50, "block line never sits below the review line");
});

test("grants and channel bindings", () => {
  const cfg = resolveConfig(
    {
      grants: [{ kind: "destination", pattern: "*.mycorp.example" }, { kind: "file" }],
      channelBindings: ["#ops-alerts"],
    },
    {},
  );
  assert.deepEqual(cfg.grants, [{ kind: "destination", pattern: "*.mycorp.example", scope: "persistent" }]);
  assert.deepEqual(cfg.channelBindings, ["#ops-alerts"]);
});

// ---- settings Sentrook cannot read as written --------------------------------------------------------------------
// OpenClaw disables a plugin whose config fails its manifest schema, so the manifest accepts any object and the
// plugin reports what it cannot read instead: every such setting is ignored or replaced, and named.

const problemsOf = (pluginConfig: unknown) => resolveConfig(pluginConfig as Record<string, unknown>, {}).configProblems;

test("a misspelt setting is named, with the setting it probably means, and ignored", () => {
  assert.deepEqual(problemsOf({ modee: "observe" }), ["modee: not a Sentrook setting (did you mean mode?); ignored"]);
  assert.deepEqual(problemsOf({ blockAtt: 60 }), ["blockAtt: not a Sentrook setting (did you mean blockAt?); ignored"]);
  assert.deepEqual(problemsOf({ trafficLog: { enabeld: false } }), [
    "trafficLog.enabeld: not a Sentrook setting (did you mean enabled?); ignored",
  ]);
  assert.deepEqual(problemsOf({ grants: [{ kind: "destination", pattern: "a.example", scpoe: "session" }] }), [
    "grants[0].scpoe: not a Sentrook setting (did you mean scope?); ignored",
  ]);
  assert.deepEqual(problemsOf({ somethingElse: 1 }), ["somethingElse: not a Sentrook setting; ignored"]);
  assert.equal(resolveConfig({ modee: "observe" }, {}).mode, "enforce", "the misspelt key changes nothing");
});

test("a value Sentrook cannot read is named with what is used instead", () => {
  assert.deepEqual(problemsOf({ mode: "observ" }), ['mode: "observ" is not enforce or observe; read as enforce']);
  assert.deepEqual(problemsOf({ onScanError: "block" }), ['onScanError: "block" is not allow, deny or review; using review']);
  assert.deepEqual(problemsOf({ skillReview: "reveiw" }), ['skillReview: "reveiw" is not allow or review; read as allow']);
  assert.deepEqual(problemsOf({ grants: [{ kind: "destination", pattern: "a.example", scope: "persistant" }] }), [
    'grants[0].scope: "persistant" is not session or persistent; this grant is never sent',
  ]);
  assert.deepEqual(problemsOf({ reviewAt: "abc" }), ["reviewAt: not a number from 0 to 100; using 45"]);
  assert.deepEqual(problemsOf({ reviewAt: 150 }), ["reviewAt: not a number from 0 to 100; using 45"]);
  assert.deepEqual(problemsOf({ blockAt: -1 }), ["blockAt: not a number from 0 to 101; using 80, or reviewAt if higher"]);
  assert.deepEqual(problemsOf({ timeoutMs: 10 }), ["timeoutMs: not a number of at least 1000; using 30000"]);
  assert.deepEqual(problemsOf({ historyLimit: 0 }), ["historyLimit: not a number from 1 to 200; using 20"]);
  assert.deepEqual(problemsOf({ dashboardShowCalls: "maybe" }), ["dashboardShowCalls: not true or false; using false"]);
  assert.deepEqual(problemsOf({ trafficLog: { enabled: "sometimes", maxBytes: 5 } }), [
    "trafficLog.enabled: not true or false; using true",
    "trafficLog.maxBytes: not a number of at least 1024; using 52428800",
  ]);
  assert.deepEqual(problemsOf({ approval: { interactiveTimeoutMs: 0, scheduledIntentKinds: ["cron", "crn"] } }), [
    "approval.interactiveTimeoutMs: not a number of at least 1; using 300000",
    'approval.scheduledIntentKinds[1]: "crn" is not user, cron, subagent or system; ignored',
  ]);
});

test("values that look set but are read differently are named", () => {
  // A block line below the review line is raised to it.
  assert.deepEqual(problemsOf({ reviewAt: 90, blockAt: 50 }), ["blockAt: below reviewAt (90); using 90"]);
  assert.equal(resolveConfig({ reviewAt: 90, blockAt: 50 }, {}).blockAt, 90);
  assert.deepEqual(problemsOf({ reviewAt: 90, blockAt: "abc" }), ["blockAt: not a number from 0 to 101; using 80, or reviewAt if higher"]);
  // A grant kind Sentrook does not know never applies; scope is compared exactly as written.
  assert.deepEqual(problemsOf({ grants: [{ kind: "destinaton", pattern: "a.example" }] }), [
    'grants[0].kind: "destinaton" is not destination, file, provider, repo or credential; this grant never applies',
  ]);
  assert.deepEqual(problemsOf({ grants: [{ kind: "destination", pattern: "a.example", scope: " persistent" }] }), [
    'grants[0].scope: " persistent" is not session or persistent; this grant is never sent',
  ]);
  assert.deepEqual(problemsOf({ grants: [{ kind: "destination", pattern: "a.example", scope: "" }] }), [
    'grants[0].scope: "" is not session or persistent; this grant is never sent',
  ]);
  // Blank text where the parser then ignores the environment and uses the default.
  assert.deepEqual(problemsOf({ reviewAt: "" }), ["reviewAt: not a number from 0 to 100; using 45"]);
  assert.deepEqual(problemsOf({ onScanError: "" }), ['onScanError: "" is not allow, deny or review; using review']);
  assert.deepEqual(problemsOf({ skillReview: "  " }), ['skillReview: "  " is not allow or review; read as allow']);
  assert.deepEqual(problemsOf({ dashboardShowCalls: "" }), ["dashboardShowCalls: not true or false; using false"]);
  // A fraction of a millisecond is rounded down to no wait.
  assert.deepEqual(problemsOf({ approval: { interactiveTimeoutMs: 0.5 } }), [
    "approval.interactiveTimeoutMs: not a number of at least 1; using 300000",
  ]);
  // No unattended kind read: the default list is used.
  assert.deepEqual(problemsOf({ approval: { scheduledIntentKinds: ["crn"] } }), [
    'approval.scheduledIntentKinds[0]: "crn" is not user, cron, subagent or system; ignored',
    "approval.scheduledIntentKinds: no item read; using cron or subagent",
  ]);
  // A SecretRef the plugin cannot resolve.
  assert.deepEqual(problemsOf({ clientSecret: { source: "file", id: "x" } }), [
    "clientSecret: a SecretRef Sentrook cannot read (only source env, with an id); ignored",
  ]);
});

test("the settings check knows the same grant kinds as the grant command", () => {
  assert.deepEqual([...GRANT_KINDS], KINDS);
});

test("blank text the parser reads as not set stays silent", () => {
  assert.deepEqual(problemsOf({ mode: "", scanUrl: "  ", clientId: "", stateDir: "", packs: "", trustedSenders: "" }), []);
  assert.deepEqual(problemsOf({ reviewAt: 90, blockAt: 95 }), []);
  assert.deepEqual(problemsOf({ reviewAt: 50, blockAt: 50 }), []);
});

test("a setting of the wrong shape is named and ignored", () => {
  assert.deepEqual(problemsOf({ trafficLog: "off" }), ["trafficLog: not an object; ignored"]);
  assert.deepEqual(problemsOf({ approval: [] }), ["approval: not an object; ignored"]);
  assert.deepEqual(problemsOf({ stateDir: 5 }), ["stateDir: not text; ignored"]);
  assert.deepEqual(problemsOf({ scanUrl: { url: "x" } }), ["scanUrl: not text; ignored"]);
  assert.deepEqual(problemsOf({ clientSecret: 5 }), ["clientSecret: not text or a SecretRef; ignored"]);
  assert.deepEqual(problemsOf({ packs: 5 }), ["packs: not a list; ignored"]);
  assert.deepEqual(problemsOf({ trustedSenders: ["alice", 3] }), ["trustedSenders[1]: not text; ignored"]);
  assert.deepEqual(problemsOf({ grants: { kind: "destination" } }), ["grants: not a list; ignored"]);
  assert.deepEqual(problemsOf({ grants: ["a.example", { kind: "destination" }] }), [
    "grants[0]: not an object; ignored",
    "grants[1]: needs kind and pattern; ignored",
  ]);
  assert.deepEqual(problemsOf({ grants: [{ kind: "destination", pattern: "a.example", allows: "x" }] }), [
    "grants[0].allows: not a list; ignored",
  ]);
  assert.deepEqual(problemsOf(["mode", "observe"]), ["the Sentrook config is not an object; ignored"]);
});

test("settings Sentrook reads as written stay silent", () => {
  assert.deepEqual(problemsOf({}), []);
  assert.deepEqual(problemsOf(undefined), []);
  const full = {
    scanUrl: "https://sentrook.firstdataunion.org",
    rookeryUrl: "https://rookery.firstdataunion.org",
    oidcIssuer: "https://identity.firstdataunion.org",
    clientId: { source: "env", provider: "default", id: "SENTROOK_SCAN_CLIENT_ID" },
    clientSecret: { source: "env", provider: "default", id: "SENTROOK_SCAN_CLIENT_SECRET" },
    oidcAudience: "sentrook",
    oidcScope: "sentrook.scan",
    mode: "observe",
    reviewAt: 40,
    blockAt: 90,
    onScanError: "deny",
    timeoutMs: 20000,
    approval: { interactiveTimeoutMs: 60000, scheduledIntentKinds: ["cron", "system"] },
    stateDir: "/var/lib/sentrook",
    trafficLog: { enabled: false, path: "/tmp/t.jsonl", maxBytes: 4096 },
    historyLimit: 10,
    inputCapBytes: 2048,
    historyArgsCapBytes: 512,
    dashboardShowCalls: true,
    packs: ["tier1"],
    trustedSenders: ["alice"],
    trustedRoles: ["admin"],
    grants: [
      { kind: "destination", pattern: "*.mycorp.example", allows: ["send"], granted_at: "2026-11-01T00:00:00Z" },
      { kind: "file", pattern: "~/notes/", scope: "persistent" },
      { kind: "destination", pattern: "b.example", scope: "session" },
    ],
    channelBindings: ["#ops-alerts"],
    skillReview: "review",
  };
  assert.deepEqual(problemsOf(full), []);
  // Forms the parser reads as meant: a number or a flag as text, a case variant, a comma list, a plain secret.
  assert.deepEqual(
    problemsOf({
      mode: "Observe",
      reviewAt: "45",
      dashboardShowCalls: "true",
      onScanError: "DENY",
      packs: "tier1,tier2",
      clientId: "plain-id",
      grants: [{ kind: "destination", pattern: "a.example", scope: null }],
    }),
    [],
  );
});

test("a problem never quotes the value of an unknown setting, and keeps quoted values short and printable", () => {
  const [p] = problemsOf({ clientSecrett: "s3cr3t-value-6f1d" });
  assert.equal(p, "clientSecrett: not a Sentrook setting (did you mean clientSecret?); ignored");
  const [long] = problemsOf({ mode: `observe\u0007${"x".repeat(200)}` });
  assert.ok(!long.includes("\u0007"));
  assert.ok(long.length < 120, long);
});

test("the owner notice lists the problems and says scanning is on", () => {
  const text = configProblemsNotice(["modee: not a Sentrook setting (did you mean mode?); ignored"]);
  assert.match(text, /^Sentrook cannot read some of its settings/);
  assert.match(text, /Scanning is on/);
  assert.match(text, /^- modee: not a Sentrook setting \(did you mean mode\?\); ignored$/m);
  assert.match(text, /openclaw sentrook verify/);
  const many = configProblemsNotice(Array.from({ length: 14 }, (_, i) => `k${i}: not a Sentrook setting; ignored`));
  assert.match(many, /^- k9: /m);
  assert.doesNotMatch(many, /^- k10: /m);
  assert.match(many, /and 4 more/);
});

test("verify fails on settings Sentrook cannot read and passes on a clean config", async () => {
  const offline = { scanUrl: "http://scan.invalid" };
  const bad = (await runVerify({ ...offline, modee: "observe" }, { env: {} })).find((c) => c.name === "settings");
  assert.deepEqual(bad, { name: "settings", ok: false, detail: "modee: not a Sentrook setting (did you mean mode?); ignored" });
  const clean = (await runVerify(offline, { env: {} })).find((c) => c.name === "settings");
  assert.deepEqual(clean, { name: "settings", ok: true, detail: "all read as written" });
});

// The manifest accepts any object: OpenClaw's `doctor --fix` deletes and disables the config of a plugin whose
// config fails the manifest schema, which would leave every tool call unscanned.
test("the manifest schema rejects nothing, and documents exactly the settings Sentrook reads", () => {
  const manifest = JSON.parse(readFileSync(new URL("./openclaw.plugin.json", import.meta.url), "utf8"));
  const schema = manifest.configSchema;
  assert.equal(schema.type, "object");
  assert.equal(schema.additionalProperties, true);
  const constraints = ["type", "enum", "minimum", "maximum", "required", "items", "additionalProperties", "const", "pattern"];
  for (const [key, prop] of Object.entries(schema.properties as Record<string, Record<string, unknown>>)) {
    for (const c of constraints) assert.ok(!(c in prop), `${key} has no ${c}`);
    assert.equal(typeof prop.description, "string", `${key} is described`);
  }
  assert.deepEqual(Object.keys(schema.properties).sort(), [...SETTING_NAMES].sort());
});
