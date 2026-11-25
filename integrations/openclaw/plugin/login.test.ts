// `openclaw sentrook login`: the shared golden cases (integrations/fixtures/login), the device id, and the `.env`.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { loginFromCli } from "./cli.ts";
import {
  Cancelled,
  cleanDeviceName,
  credentialsSetElsewhere,
  DEVICE_ID_FILE,
  deviceId,
  EXIT_CANCELLED,
  RESTART_LINE,
  runLogin,
  saveToOpenclawDotenv,
  type LoginDeps,
} from "./login.ts";

const FIXTURE = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/login/cases.json", import.meta.url)), "utf8"),
);
const ISSUER: string = FIXTURE.issuer;

function fakeIdentity(c: any) {
  const discovery = c.discovery ?? FIXTURE.discovery;
  const polls = [...c.polls];
  const requests: string[] = [];
  const codeForms: Record<string, string>[] = [];
  const pollForms: Record<string, string>[] = [];
  const json = (status: number, body: unknown) =>
    new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
  const fetchImpl = (async (input: string, init?: RequestInit) => {
    const form = Object.fromEntries(new URLSearchParams(String(init?.body ?? "")));
    if (input === `${ISSUER}/.well-known/openid-configuration`) {
      requests.push("discovery");
      return json(200, discovery);
    }
    if (input === discovery.device_authorization_endpoint) {
      requests.push("code");
      codeForms.push(form);
      return json(c.code_status ?? 200, c.code_response ?? FIXTURE.code_response);
    }
    if (input === FIXTURE.credentials_endpoint) {
      requests.push("poll");
      pollForms.push(form);
      const answer = polls.shift();
      if (answer.network_error) throw new TypeError("fetch failed");
      return json(answer.status, answer.body);
    }
    throw new Error(`unexpected request to ${input}`);
  }) as typeof fetch;
  return { fetchImpl, requests, codeForms, pollForms };
}

function stateDir(): string {
  const dir = path.join(mkdtempSync(path.join(tmpdir(), "sentrook-login-")), "sentrook");
  deviceId(dir); // creates the folder
  writeFileSync(path.join(dir, DEVICE_ID_FILE), `${FIXTURE.device_id}\n`);
  return dir;
}

function expectedOutput(c: any, where: string): string[] {
  const lines: string[] = [];
  for (const line of c.expect.output as string[]) {
    if (line === "{start}") lines.push(...FIXTURE.start_output);
    else if (line === "{restart}") continue; // first sign-in into an empty .env: no restart needed
    else if (line === "{verify}") lines.push(FIXTURE.verify_report);
    else lines.push(line.replaceAll("{cmd}", "openclaw").replaceAll("{where}", where));
  }
  return lines;
}

for (const c of FIXTURE.cases) {
  test(`login golden: ${c.name}`, async () => {
    const identity = fakeIdentity(c);
    let t = 0;
    const sleeps: number[] = [];
    const out: string[] = [];
    const saved: Record<string, string>[] = [];
    const deps: LoginDeps = {
      fetchImpl: identity.fetchImpl,
      sleep: async (s) => {
        sleeps.push(s);
        t += s;
      },
      now: () => t,
      out: (l) => out.push(l),
      hostname: () => "unused",
      save: (v) => {
        saved.push({ ...v });
        return { where: "to /state/.env", replacedEarlier: false };
      },
      verify: async () => ({ report: FIXTURE.verify_report, ok: c.verify_ok ?? true }),
      timeoutMs: 1000,
    };
    const code = await runLogin({ stateDir: stateDir() }, { name: c.name_arg, env: {}, deps });

    assert.equal(code, c.expect.exit);
    assert.deepEqual(sleeps, c.expect.sleeps);
    assert.deepEqual(identity.requests, c.expect.requests);
    if (identity.requests.includes("code")) {
      assert.deepEqual(identity.codeForms, [c.code_request ?? FIXTURE.code_request]);
    }
    const deviceCode = (c.code_response ?? FIXTURE.code_response).device_code;
    for (const form of identity.pollForms) assert.deepEqual(form, { client_id: "sentrook-plugin", device_code: deviceCode });
    assert.deepEqual(saved, c.expect.saved ? [c.expect.saved] : []);
    assert.deepEqual(out, expectedOutput(c, "to /state/.env"));
    const secret = c.expect.saved?.SENTROOK_SCAN_CLIENT_SECRET;
    if (secret) assert.ok(out.every((l) => !l.includes(secret)), "the secret is never printed");
  });
}

test("the device id is created once and kept", () => {
  const dir = path.join(mkdtempSync(path.join(tmpdir(), "sentrook-id-")), "state", "sentrook");
  const first = deviceId(dir);
  assert.match(first, /^[0-9a-f]{32}$/);
  assert.equal(statSync(path.join(dir, DEVICE_ID_FILE)).mode & 0o777, 0o600);
  assert.equal(deviceId(dir), first);
  writeFileSync(path.join(dir, DEVICE_ID_FILE), "not hex\n");
  assert.notEqual(deviceId(dir), "not hex");
});

test("the default device name names the host", () => {
  assert.equal(cleanDeviceName(undefined, "vps-1"), "OpenClaw on vps-1");
  assert.equal(cleanDeviceName("   ", ""), "OpenClaw");
});

test(".env: our two lines are replaced, everything else is kept, mode 0600", () => {
  const home = mkdtempSync(path.join(tmpdir(), "sentrook-env-"));
  const file = path.join(home, ".env");
  writeFileSync(
    file,
    "# my keys\nOPENAI_API_KEY=sk-x\nexport SENTROOK_SCAN_CLIENT_ID=old-id\nSENTROOK_SCAN_CLIENT_SECRET=old-secret\nOTHER=1",
    { mode: 0o644 },
  );
  const saved = saveToOpenclawDotenv(
    { OPENCLAW_STATE_DIR: home },
    { SENTROOK_SCAN_CLIENT_ID: "new-id", SENTROOK_SCAN_CLIENT_SECRET: "new-secret-0123456789" },
  );
  assert.equal(saved.where, `to ${file}`);
  assert.equal(saved.replacedEarlier, true);
  assert.equal(
    readFileSync(file, "utf8"),
    "# my keys\nOPENAI_API_KEY=sk-x\nOTHER=1\nSENTROOK_SCAN_CLIENT_ID=new-id\nSENTROOK_SCAN_CLIENT_SECRET=new-secret-0123456789\n",
  );
  assert.equal(statSync(file).mode & 0o777, 0o600);
});

test(".env: a new file is created and asks for no restart", () => {
  const home = path.join(mkdtempSync(path.join(tmpdir(), "sentrook-env-")), "fresh");
  const saved = saveToOpenclawDotenv({ OPENCLAW_STATE_DIR: home }, { SENTROOK_SCAN_CLIENT_ID: "id", SENTROOK_SCAN_CLIENT_SECRET: "s" });
  assert.equal(saved.replacedEarlier, false);
  assert.equal(readFileSync(path.join(home, ".env"), "utf8"), "SENTROOK_SCAN_CLIENT_ID=id\nSENTROOK_SCAN_CLIENT_SECRET=s\n");
  assert.equal(statSync(path.join(home, ".env")).mode & 0o777, 0o600);
});

test("replacing earlier credentials prints the restart line", async () => {
  const c = FIXTURE.cases[0];
  const identity = fakeIdentity(c);
  const out: string[] = [];
  const code = await runLogin(
    { stateDir: stateDir() },
    {
      name: "test box",
      env: {},
      deps: {
        fetchImpl: identity.fetchImpl,
        sleep: async () => {},
        now: () => 0,
        out: (l) => out.push(l),
        hostname: () => "x",
        save: () => ({ where: "to /state/.env", replacedEarlier: true }),
        timeoutMs: 1000,
      },
    },
  );
  assert.equal(code, 0);
  assert.ok(out.includes(RESTART_LINE));
});

test("Ctrl-C changes nothing", async () => {
  const identity = fakeIdentity({ polls: [] });
  const out: string[] = [];
  const saved: unknown[] = [];
  const code = await runLogin(
    { stateDir: stateDir() },
    {
      name: "box",
      env: {},
      deps: {
        fetchImpl: identity.fetchImpl,
        sleep: async () => {
          throw new Cancelled();
        },
        now: () => 0,
        out: (l) => out.push(l),
        hostname: () => "x",
        save: (v) => {
          saved.push(v);
          return { where: "x", replacedEarlier: false };
        },
        timeoutMs: 1000,
      },
    },
  );
  assert.equal(code, EXIT_CANCELLED);
  assert.equal(out.at(-1), "Cancelled. Nothing was changed.");
  assert.deepEqual(saved, []);
});

test("credentials set where they would win over .env are named, and nothing starts", async () => {
  const home = mkdtempSync(path.join(tmpdir(), "sentrook-else-"));
  writeFileSync(path.join(home, ".env"), "SENTROOK_SCAN_CLIENT_ID=from-file\nSENTROOK_SCAN_CLIENT_SECRET=file-secret\n");
  const env = { OPENCLAW_STATE_DIR: home };
  const fromFile = { ...env, SENTROOK_SCAN_CLIENT_ID: "from-file", SENTROOK_SCAN_CLIENT_SECRET: "file-secret" };
  // Values OpenClaw loaded from .env, or none at all: login can replace them.
  assert.equal(credentialsSetElsewhere({}, fromFile, env), null);
  assert.equal(credentialsSetElsewhere({}, env, env), null);
  assert.equal(
    credentialsSetElsewhere({ clientId: { source: "env", provider: "default", id: "SENTROOK_SCAN_CLIENT_ID" } }, env, env),
    null,
  );
  // Values from somewhere else win, so a sign-in would change nothing.
  assert.match(
    credentialsSetElsewhere({}, { ...env, SENTROOK_SCAN_CLIENT_ID: "docker-e" }, env)!,
    /gateway's environment \(SENTROOK_SCAN_CLIENT_ID\)/,
  );
  assert.match(credentialsSetElsewhere({ clientSecret: "plain" }, env, env)!, /plugin config/);
  assert.match(credentialsSetElsewhere({ clientId: { source: "env", id: "OTHER_VAR" } }, env, env)!, /OTHER_VAR/);

  const out: string[] = [];
  const code = await runLogin(
    { clientSecret: "plain", stateDir: stateDir() },
    {
      env,
      deps: {
        fetchImpl: (async () => {
          throw new Error("no request when the sign-in could not take effect");
        }) as typeof fetch,
        sleep: async () => {},
        now: () => 0,
        out: (l) => out.push(l),
        hostname: () => "x",
        save: () => {
          throw new Error("never saved");
        },
        timeoutMs: 1000,
      },
    },
  );
  assert.equal(code, 1);
  assert.match(out[0], /^Sentrook's credentials are already set in OpenClaw's plugin config/);
});

test("a .env that cannot be written is reported, not thrown", async () => {
  const identity = fakeIdentity(FIXTURE.cases[0]);
  const out: string[] = [];
  const code = await runLogin(
    { stateDir: stateDir() },
    {
      name: "test box",
      env: {},
      deps: {
        fetchImpl: identity.fetchImpl,
        sleep: async () => {},
        now: () => 0,
        out: (l) => out.push(l),
        hostname: () => "x",
        save: () => {
          throw Object.assign(new Error("denied"), { code: "EACCES" });
        },
        timeoutMs: 1000,
      },
    },
  );
  assert.equal(code, 1);
  assert.match(out.at(-1)!, /^Signed in, but the credentials could not be written \(EACCES\)/);
  assert.ok(!out.some((l) => l.startsWith("Connected")));
});

test("Ctrl-C during a request ends the sign-in at once, with nothing changed", async () => {
  const saved: unknown[] = [];
  const out: string[] = [];
  const pending = (async (_url: string, init?: RequestInit) =>
    new Promise<Response>((_, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      setTimeout(() => process.emit("SIGINT"), 10);
    })) as typeof fetch;
  const code = await loginFromCli({ stateDir: stateDir() }, () => undefined, "box", {
    fetchImpl: pending,
    out: (l) => out.push(l),
    save: (v) => {
      saved.push(v);
      return { where: "x", replacedEarlier: false };
    },
  });
  assert.equal(code, EXIT_CANCELLED);
  assert.deepEqual(out, ["Cancelled. Nothing was changed."]);
  assert.deepEqual(saved, []);
  assert.equal(process.listenerCount("SIGINT"), 0, "the handler is removed afterwards");
});
