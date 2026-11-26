// Consent: the text printed after sign-in, the identity service's withdrawal answer, and verify. The owner notice
// end to end is in hold.test.ts. The texts are shared with the Hermes plugin's tests (integrations/fixtures/consent).

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { clearScanTokenCache, ConsentWithdrawnError, consentWithdrawn, getScanAccessToken } from "./auth.ts";
import * as consent from "./consent.ts";
import { DEVICE_ID_FILE, deviceId, runLogin, type LoginDeps } from "./login.ts";
import { scanAuthErrorToFailure } from "./scanErrorPolicy.ts";
import { runVerify } from "./verify.ts";

const FIXTURE = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/consent/cases.json", import.meta.url)), "utf8"),
);
const RENDERED = FIXTURE.rendered.openclaw;
const TOKEN_ERROR = FIXTURE.token_error;

test("the texts match the shared cases", () => {
  assert.deepEqual([...consent.SIGNED_IN_TEXT], FIXTURE.signed_in);
  assert.equal(consent.WITHDRAWN_NOTICE, FIXTURE.withdrawn_notice);
  assert.equal(consent.TERMS_LINE, FIXTURE.terms_line);
  assert.equal(consent.TERMS_LINE_DATED, FIXTURE.terms_line_dated);
  assert.equal(consent.PRIVACY_URL, FIXTURE.privacy_url);
  assert.equal(consent.TERMS_URL, FIXTURE.terms_url);
  assert.deepEqual({ ...consent.COMMANDS }, FIXTURE.hosts.openclaw);
  assert.deepEqual(consent.signedInLines(null), RENDERED.signed_in);
  assert.deepEqual(consent.signedInLines(consent.acceptedTerms(FIXTURE.dated_case)), RENDERED.signed_in_dated);
  assert.equal(consent.withdrawnText(), RENDERED.withdrawn_notice);
});

test("the stop command stops every scan", () => {
  assert.match(consent.COMMANDS.stop, /^openclaw plugins disable sentrook/);
  assert.match(consent.signedInLines(null).at(-1)!, /^To stop, run openclaw plugins disable sentrook/);
});

test("accepted terms are read only when plain", () => {
  assert.deepEqual(consent.acceptedTerms({ terms_version: "v3.1" }), { version: "v3.1", date: null });
  assert.deepEqual(consent.acceptedTerms({ terms_version: "1", terms_accepted_at: "2026-11-26" }), { version: "1", date: "2026-11-26" });
  assert.deepEqual(consent.acceptedTerms({ terms_version: "1", terms_accepted_at: "soon\u001b[2J" }), { version: "1", date: null });
  for (const raw of [null, 3, "", "1\u001b[2J", "a b", "x".repeat(41)]) {
    assert.equal(consent.acceptedTerms({ terms_version: raw }), null);
  }
  assert.equal(consent.acceptedTerms("not an object"), null);
  assert.equal(consent.signedInLines({ version: "2", date: null })[1], "Terms version 2 accepted.");
});

test("the withdrawal answer is told from other refusals", async () => {
  assert.ok(consentWithdrawn(TOKEN_ERROR.status, JSON.stringify(TOKEN_ERROR.body)));
  assert.ok(!consentWithdrawn(401, JSON.stringify({ error: "invalid_client" })));
  assert.ok(!consentWithdrawn(200, JSON.stringify(TOKEN_ERROR.body)));
  assert.ok(!consentWithdrawn(401, "consent_withdrawn"));

  const fetchImpl = (async (input: string) => {
    if (String(input).endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify({ token_endpoint: "http://idp.test/oauth/token" }), { status: 200 });
    }
    return new Response(JSON.stringify(TOKEN_ERROR.body), { status: TOKEN_ERROR.status });
  }) as typeof fetch;
  clearScanTokenCache();
  const oidc = { clientId: "c", clientSecret: "s", issuer: "http://idp.test", audience: "sentrook", scope: "sentrook.scan" };
  const err = await getScanAccessToken(oidc, fetchImpl).catch((e) => e);
  assert.ok(err instanceof ConsentWithdrawnError);
  const failure = scanAuthErrorToFailure(err);
  assert.deepEqual([failure.kind, failure.status, failure.setup], ["http", 401, "consent_withdrawn"]);
  const other = scanAuthErrorToFailure(new Error('client_credentials token mint failed: HTTP 401: {"error":"invalid_client"}'));
  assert.equal(other.setup, "sign_in_rejected");

  const checks = await runVerify(
    { scanUrl: "", oidcIssuer: "http://idp.test" },
    {
      env: {
        OPENCLAW_STATE_DIR: mkdtempSync(path.join(tmpdir(), "sentrook-consent-")),
        SENTROOK_DEV_ENDPOINTS: "1",
        SENTROOK_SCAN_CLIENT_ID: "c",
        SENTROOK_SCAN_CLIENT_SECRET: "s",
      },
      fetchImpl,
      hostConfig: {},
    },
  );
  const mint = checks.find((c) => c.name === "token mint");
  assert.deepEqual(mint && { ok: mint.ok, detail: mint.detail }, {
    ok: false,
    detail: "consent for Sentrook was withdrawn on the FIDU portal; run openclaw sentrook login to reconnect",
  });
});

test("signing in resets the consent notice and prints what is sent", async () => {
  const dir = path.join(mkdtempSync(path.join(tmpdir(), "sentrook-consent-")), "sentrook");
  deviceId(dir);
  assert.ok(consent.claim(dir, "old-client", new Date()));
  assert.ok(existsSync(path.join(dir, consent.FILE)));
  assert.ok(existsSync(path.join(dir, DEVICE_ID_FILE)));
  const issuer = "https://identity.firstdataunion.org";
  const fetchImpl = (async (input: string) => {
    const url = String(input);
    const body = url.endsWith("openid-configuration")
      ? { device_authorization_endpoint: `${issuer}/oauth/device/code` }
      : url.endsWith("/device/code")
        ? { device_code: "dc", user_code: "ABCD-1234", verification_uri: `${issuer}/oauth/device`, expires_in: 600, interval: 5 }
        : { client_id: "sentrook-scan-1", client_secret: "not-a-real-secret-zzzzzzzzzzzzzzzz", terms_version: "1" };
    return new Response(JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
  const out: string[] = [];
  const deps: LoginDeps = {
    fetchImpl,
    sleep: async () => undefined,
    now: () => 0,
    out: (l) => out.push(l),
    hostname: () => "box",
    save: () => ({ where: "to /state/.env", replacedEarlier: false }),
    timeoutMs: 1000,
  };
  const code = await runLogin({ stateDir: dir }, { name: "box", env: {}, deps });
  assert.equal(code, 0);
  assert.ok(!existsSync(path.join(dir, consent.FILE)));
  assert.ok(out.includes("Terms version 1 accepted."));
  assert.equal(out.at(-2), RENDERED.signed_in.at(-1));
});
