// Fail closed, and say how to fix it: what the agent and the owner are told when Sentrook is not signed in.

import assert from "node:assert/strict";
import { test } from "node:test";

import { errorCard } from "./card.ts";
import { scanAuthErrorToFailure, scanErrorCopy, scanErrorToHookResult, type ScanFailure } from "./scanErrorPolicy.ts";

const notSignedIn: ScanFailure = { ok: false, kind: "config", detail: "not signed in", setup: "not_signed_in" };

test("unattended: the block reason tells the agent the owner must run the login", () => {
  for (const onScanError of ["allow", "deny", "review"] as const) {
    const r = scanErrorToHookResult(notSignedIn, { onScanError, unattended: true } as any);
    assert.equal(r?.block, true, onScanError);
    assert.equal(
      r!.blockReason,
      "Sentrook is not signed in on this machine, so this tool call was not scanned or run. This is a setup problem, " +
        "not a security finding. Tell the owner to run `openclaw sentrook login` in a terminal on the gateway machine. " +
        "Do not try to run it yourself or work around this.",
    );
  }
});

test("attended: the owner's card names the login", () => {
  assert.deepEqual(scanErrorCopy(notSignedIn), errorCard("not_signed_in"));
  assert.match(errorCard("not_signed_in").description, /openclaw sentrook login/);
});

test("revoked credentials say to sign in again; other auth failures keep their text", () => {
  const rejected = scanAuthErrorToFailure(
    new Error('client_credentials token mint failed: HTTP 401: {"error":"invalid_client","error_description":"invalid client credentials"}'),
  );
  assert.equal(rejected.setup, "sign_in_rejected");
  assert.deepEqual(scanErrorCopy(rejected), errorCard("sign_in_rejected"));
  const r = scanErrorToHookResult(rejected, { onScanError: "allow", unattended: false } as any);
  assert.equal(
    r!.blockReason,
    "Sentrook's sign-in was revoked or is wrong, so this tool call was not scanned or run. This is a setup problem, " +
      "not a security finding. Tell the owner to run `openclaw sentrook login` again in a terminal on the gateway " +
      "machine. Do not try to run it yourself or work around this.",
  );

  const other = scanAuthErrorToFailure(new Error("client_credentials token mint failed: HTTP 403: nope"));
  assert.equal(other.setup, undefined);
  assert.deepEqual(scanErrorCopy(other), errorCard("auth"));
});
