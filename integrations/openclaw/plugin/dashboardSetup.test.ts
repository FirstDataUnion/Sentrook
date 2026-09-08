import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";

import { CLIENT_ID_VAR, CLIENT_SECRET_VAR, dotenvPath } from "./configure.ts";
import {
  applyDashboardSetup,
  dashboardSetupNeeded,
  processEnvShadowsDotenvWrite,
} from "./dashboardSetup.ts";
import type { ScanAuthConfig } from "./auth.ts";

const tempDirs: string[] = [];
const extraEnvKeys = ["SENTROOK_DOTENV", "OPENCLAW_COMPOSE_ENV"] as const;
const savedExtra: Partial<Record<(typeof extraEnvKeys)[number], string | undefined>> = {};
for (const key of extraEnvKeys) savedExtra[key] = process.env[key];

afterEach(() => {
  while (tempDirs.length) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
  for (const key of extraEnvKeys) {
    const value = savedExtra[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

function tempState(): string {
  delete process.env.SENTROOK_DOTENV;
  delete process.env.OPENCLAW_COMPOSE_ENV;
  const dir = mkdtempSync(path.join(tmpdir(), "sentrook-setup-"));
  tempDirs.push(dir);
  return dir;
}

describe("dashboardSetupNeeded", () => {
  it("is true for HTTPS scan with neither OIDC nor API key", () => {
    const auth: ScanAuthConfig = { apiKey: null, oidc: null };
    assert.equal(dashboardSetupNeeded(auth, "https://sentrook.example"), true);
  });

  it("is false once an OIDC pair is present", () => {
    const auth: ScanAuthConfig = {
      apiKey: null,
      oidc: {
        clientId: "id",
        clientSecret: "sec",
        issuer: "https://identity.example",
        audience: "sentrook",
        scope: "sentrook.scan",
      },
    };
    assert.equal(dashboardSetupNeeded(auth, "https://sentrook.example"), false);
  });

  it("is false for HTTP scan URLs even without credentials", () => {
    const auth: ScanAuthConfig = { apiKey: null, oidc: null };
    assert.equal(dashboardSetupNeeded(auth, "http://127.0.0.1:8080"), false);
  });
});

describe("processEnvShadowsDotenvWrite", () => {
  it("is false when process env has no scan credentials", () => {
    assert.equal(
      processEnvShadowsDotenvWrite(
        { clientId: "new-id", clientSecret: "new-sec" },
        {},
      ),
      false,
    );
  });

  it("is true when process env already holds a different client id", () => {
    assert.equal(
      processEnvShadowsDotenvWrite(
        { clientId: "new-id", clientSecret: "new-sec" },
        { [CLIENT_ID_VAR]: "old-id", [CLIENT_SECRET_VAR]: "old-sec" },
      ),
      true,
    );
  });

  it("is false when process env matches the values just written", () => {
    assert.equal(
      processEnvShadowsDotenvWrite(
        { clientId: "id", clientSecret: "sec" },
        { [CLIENT_ID_VAR]: "id", [CLIENT_SECRET_VAR]: "sec" },
      ),
      false,
    );
  });
});

describe("applyDashboardSetup", () => {
  it("writes dotenv, omits secrets from the result, and mints", async () => {
    const dir = tempState();
    let feedback = "off" as "off" | "submit";
    let onScanError = "review" as "allow" | "deny" | "review";
    let mintedWith: { clientId: string; clientSecret: string } | undefined;
    const result = await applyDashboardSetup({
      input: {
        clientId: "  cid  ",
        clientSecret: "csec",
        feedbackMode: "submit",
        onScanError: "review",
      },
      stateDir: dir,
      setFeedbackMode: (value) => {
        feedback = value;
        return { persisted: true };
      },
      setOnScanError: (value) => {
        onScanError = value;
        return { persisted: true };
      },
      mint: async (creds) => {
        mintedWith = { clientId: creds.clientId, clientSecret: creds.clientSecret };
      },
      verify: async () => ({
        ok: true,
        url: "https://sentrook.example",
        checks: [{ name: "OIDC token mint", ok: true, detail: "ok" }],
      }),
      env: { OPENCLAW_STATE_DIR: dir },
    });
    assert.equal(result.ok, true);
    assert.equal(result.minted, true);
    assert.equal(result.persisted, true);
    assert.equal(result.restartHint, false);
    assert.equal(feedback, "submit");
    assert.equal(onScanError, "review");
    assert.equal(mintedWith?.clientId, "cid");
    assert.equal(mintedWith?.clientSecret, "csec");
    const dumped = JSON.stringify(result);
    assert.doesNotMatch(dumped, /csec/);
    const dotenv = readFileSync(dotenvPath(dir), "utf8");
    assert.match(dotenv, new RegExp(`${CLIENT_ID_VAR}=cid`));
    assert.match(dotenv, new RegExp(`${CLIENT_SECRET_VAR}=csec`));
  });

  it("returns ok false on mint failure after writing dotenv", async () => {
    const dir = tempState();
    const result = await applyDashboardSetup({
      input: {
        clientId: "cid",
        clientSecret: "bad-secret",
        feedbackMode: "off",
        onScanError: "deny",
      },
      stateDir: dir,
      setFeedbackMode: () => ({ persisted: true }),
      setOnScanError: () => ({ persisted: true }),
      mint: async () => {
        throw new Error("client_credentials token mint failed: HTTP 401: invalid_client");
      },
      verify: async () => ({
        ok: false,
        url: "https://sentrook.example",
        checks: [{ name: "OIDC token mint", ok: false, detail: "invalid_client" }],
      }),
      env: { OPENCLAW_STATE_DIR: dir },
    });
    assert.equal(result.ok, false);
    assert.equal(result.minted, false);
    assert.match(result.error ?? "", /invalid_client/);
    assert.doesNotMatch(JSON.stringify(result), /bad-secret/);
    const dotenv = readFileSync(dotenvPath(dir), "utf8");
    assert.match(dotenv, /SENTROOK_SCAN_CLIENT_ID=cid/);
  });

  it("rejects empty credentials without writing", async () => {
    const dir = tempState();
    const result = await applyDashboardSetup({
      input: {
        clientId: "   ",
        clientSecret: "",
        feedbackMode: "submit",
        onScanError: "review",
      },
      stateDir: dir,
      setFeedbackMode: () => {
        throw new Error("should not persist");
      },
      setOnScanError: () => {
        throw new Error("should not persist");
      },
      env: { OPENCLAW_STATE_DIR: dir },
    });
    assert.equal(result.ok, false);
    assert.equal(result.minted, false);
    assert.match(result.error ?? "", /required/);
  });

  it("sets restartHint when process env would hide the dotenv write", async () => {
    const dir = tempState();
    const result = await applyDashboardSetup({
      input: {
        clientId: "new-id",
        clientSecret: "new-sec",
        feedbackMode: "submit",
        onScanError: "review",
      },
      stateDir: dir,
      setFeedbackMode: () => ({ persisted: true }),
      setOnScanError: () => ({ persisted: true }),
      mint: async () => {},
      verify: async () => ({ ok: true, url: "https://sentrook.example", checks: [] }),
      env: {
        OPENCLAW_STATE_DIR: dir,
        [CLIENT_ID_VAR]: "compose-id",
        [CLIENT_SECRET_VAR]: "compose-sec",
      },
    });
    assert.equal(result.ok, true);
    assert.equal(result.restartHint, true);
  });
});
