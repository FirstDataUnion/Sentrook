import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DualIndexMap,
  runIdPrefix,
  sessionIdsOf,
} from "./sessionStore.ts";

type State = { label: string };

function empty(): State {
  return { label: "fresh" };
}

describe("sessionIdsOf", () => {
  it("treats sessionId as episode and sessionKey as routing", () => {
    assert.deepEqual(
      sessionIdsOf({ sessionId: "uuid-1", sessionKey: "main" }),
      { sessionId: "uuid-1", sessionKey: "main" },
    );
  });

  it("trims blanks to undefined", () => {
    assert.deepEqual(sessionIdsOf({ sessionId: "  ", sessionKey: "" }), {
      sessionId: undefined,
      sessionKey: undefined,
    });
  });
});

describe("runIdPrefix", () => {
  it("prefers episode over routing key", () => {
    assert.equal(runIdPrefix({ sessionId: "uuid-1", sessionKey: "main" }), "uuid-1");
    assert.equal(runIdPrefix({ sessionKey: "main" }), "main");
    assert.equal(runIdPrefix({}), "session");
  });
});

describe("DualIndexMap", () => {
  it("aliases sessionKey onto the live episode so slash-only lookups share state", () => {
    const map = new DualIndexMap<State>();
    const a = map.getOrCreate({ sessionId: "uuid-1", sessionKey: "main" }, empty);
    a.label = "episode-1";
    const viaKey = map.getOrCreate({ sessionKey: "main" }, empty);
    assert.equal(viaKey, a);
    assert.equal(viaKey.label, "episode-1");
  });

  it("does not collapse /new into the previous episode's trajectory", () => {
    const map = new DualIndexMap<State>();
    const old = map.getOrCreate({ sessionId: "uuid-1", sessionKey: "main" }, empty);
    old.label = "old";
    const next = map.getOrCreate({ sessionId: "uuid-2", sessionKey: "main" }, empty);
    assert.notEqual(next, old);
    assert.equal(next.label, "fresh");
    const viaKey = map.getOrCreate({ sessionKey: "main" }, empty);
    assert.equal(viaKey, next);
  });

  it("adopts sessionKey-only state onto the first episode id", () => {
    const map = new DualIndexMap<State>();
    const slash = map.getOrCreate({ sessionKey: "main" }, empty);
    slash.label = "allow-all";
    const firstScan = map.getOrCreate({ sessionId: "uuid-1", sessionKey: "main" }, empty);
    assert.equal(firstScan, slash);
    assert.equal(firstScan.label, "allow-all");
  });

  it("session_end deletes both episode and routing aliases", () => {
    const map = new DualIndexMap<State>();
    const st = map.getOrCreate({ sessionId: "uuid-1", sessionKey: "main" }, empty);
    st.label = "gone";
    map.delete({ sessionId: "uuid-1", sessionKey: "main" });
    const next = map.getOrCreate({ sessionId: "uuid-1", sessionKey: "main" }, empty);
    assert.notEqual(next, st);
    assert.equal(next.label, "fresh");
  });
});
