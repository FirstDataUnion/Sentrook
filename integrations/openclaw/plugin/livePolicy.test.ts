import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";

import { DualIndexMap } from "./sessionStore.ts";
import { LivePolicyStore, LIVE_POLICY_FILE } from "./livePolicy.ts";

const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) {
    const dir = dirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function store() {
  const dir = mkdtempSync(join(tmpdir(), "sentrook-live-"));
  dirs.push(dir);
  return { path: join(dir, LIVE_POLICY_FILE), dir };
}

describe("LivePolicyStore", () => {
  it("shares gateway allow-all across two stores on the same file", () => {
    const { path } = store();
    const dashboard = new LivePolicyStore(path);
    const hook = new LivePolicyStore(path);
    dashboard.writeGlobal({ allowAll: true });
    assert.equal(hook.read().allowAll, true);
    hook.writeGlobal({ allowAll: false, clearSessionAllowAll: true });
    assert.equal(dashboard.read().allowAll, false);
  });

  it("keeps a session flag written by one isolate when the other isolate writes global", () => {
    const { path } = store();
    const a = new LivePolicyStore(path);
    const b = new LivePolicyStore(path);
    a.writeSession({ sessionKey: "main", sessionId: "uuid-1" }, { allowAll: true });
    b.writeGlobal({ allowAll: true });
    const flags = a.sessionFlags({ sessionKey: "main", sessionId: "uuid-1" });
    assert.equal(flags.allowAll, true);
    assert.equal(b.read().allowAll, true);
  });

  it("hydrates DualIndexMap session rows from disk", () => {
    const { path } = store();
    const writer = new LivePolicyStore(path);
    writer.writeSession({ sessionKey: "ops" }, { allowAll: true, quietUntilMs: 9_000 });
    const reader = new LivePolicyStore(path);
    const map = new DualIndexMap<{
      sessionId?: string;
      sessionKey?: string;
      allowAll: boolean;
      quietUntilMs: number | null;
    }>();
    reader.hydrateInto(map, () => ({ allowAll: false, quietUntilMs: null }));
    const st = map.getOrCreate({ sessionKey: "ops" }, () => ({ allowAll: false, quietUntilMs: null }));
    assert.equal(st.allowAll, true);
    assert.equal(st.quietUntilMs, 9_000);
  });

  it("shares session floors across isolates and keeps them after session_end", () => {
    const { path } = store();
    const writer = new LivePolicyStore(path);
    writer.writeSession(
      { sessionKey: "cron:nightly", sessionId: "old-id" },
      { attendedSensitivity: "warning", unattendedSensitivity: "info" },
    );
    const reader = new LivePolicyStore(path);
    const flags = reader.sessionFlags({ sessionKey: "cron:nightly", sessionId: "old-id" });
    assert.equal(flags.attendedSensitivity, "warning");
    assert.equal(flags.unattendedSensitivity, "info");
    reader.clearSession({ sessionKey: "cron:nightly", sessionId: "old-id" });
    const afterEnd = writer.sessionFlags({ sessionKey: "cron:nightly", sessionId: "new-id" });
    assert.equal(afterEnd.allowAll, false);
    assert.equal(afterEnd.quietUntilMs, null);
    assert.equal(afterEnd.attendedSensitivity, "warning");
    assert.equal(afterEnd.unattendedSensitivity, "info");
    writer.writeSession({ sessionKey: "cron:nightly" }, { attendedSensitivity: null, unattendedSensitivity: null });
    assert.equal(writer.sessionFlags({ sessionKey: "cron:nightly" }).attendedSensitivity, null);
    assert.equal(writer.read().sessions.length, 0);
  });
});
