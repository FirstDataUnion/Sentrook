import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  agentIdsFromConfig,
  listHostSessions,
  mergeSessionRows,
  type HostSession,
  type SessionListRow,
} from "./hostSessions.ts";

const live = (overrides: Partial<SessionListRow> = {}): SessionListRow => ({
  allowAll: false,
  quietUntilMs: null,
  pending: 0,
  ...overrides,
});

describe("agentIdsFromConfig", () => {
  it("always includes main", () => {
    assert.deepEqual(agentIdsFromConfig(undefined), ["main"]);
  });

  it("adds agents.list ids", () => {
    const ids = agentIdsFromConfig({
      agents: { list: [{ id: "ops" }, { id: "main" }] },
    });
    assert.deepEqual(ids.sort(), ["main", "ops"]);
  });

  it("adds agents.entries keys", () => {
    const ids = agentIdsFromConfig({
      agents: { entries: { research: {}, main: {} } },
    });
    assert.ok(ids.includes("research"));
    assert.ok(ids.includes("main"));
  });
});

describe("listHostSessions", () => {
  it("returns [] when the helper is missing", () => {
    assert.deepEqual(listHostSessions(undefined), []);
    assert.deepEqual(listHostSessions({}), []);
  });

  it("skips archived rows and maps sessionId from the entry", () => {
    const rows = listHostSessions({
      listSessionEntries: () => [
        {
          sessionKey: "main",
          entry: { sessionId: "uuid-1", updatedAt: 100 },
        },
        {
          sessionKey: "old",
          entry: { sessionId: "uuid-old", archivedAt: 99, updatedAt: 200 },
        },
      ],
    });
    assert.deepEqual(rows, [{ sessionKey: "main", sessionId: "uuid-1", updatedAtMs: 100 }]);
  });

  it("swallows a throwing helper", () => {
    assert.deepEqual(
      listHostSessions({
        listSessionEntries: () => {
          throw new Error("no store");
        },
      }),
      [],
    );
  });

  it("retries without readOnly when the host rejects that flag", () => {
    const rows = listHostSessions({
      listSessionEntries: (params) => {
        if (params?.readOnly) throw new Error("unknown readOnly");
        return [{ sessionKey: "discord:ops", entry: { sessionId: "d1" } }];
      },
    });
    assert.equal(rows[0]?.sessionKey, "discord:ops");
    assert.equal(rows[0]?.sessionId, "d1");
  });
});

describe("mergeSessionRows", () => {
  it("lists host sessions with default-off flags when Sentrook has never seen them", () => {
    const host: HostSession[] = [
      { sessionKey: "main", sessionId: "uuid-1", updatedAtMs: 2 },
      { sessionKey: "discord:ops", sessionId: "d1", updatedAtMs: 1 },
    ];
    const rows = mergeSessionRows(host, []);
    assert.equal(rows.length, 2);
    assert.equal(rows[0]?.sessionKey, "main");
    assert.equal(rows[0]?.allowAll, false);
    assert.equal(rows[1]?.sessionKey, "discord:ops");
  });

  it("overlays in-memory allow-all onto the matching host key", () => {
    const rows = mergeSessionRows(
      [{ sessionKey: "main", sessionId: "uuid-1", updatedAtMs: 1 }],
      [live({ sessionKey: "main", sessionId: "uuid-1", allowAll: true, pending: 2 })],
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0]?.allowAll, true);
    assert.equal(rows[0]?.pending, 2);
  });

  it("keeps a live-only row the host list omitted", () => {
    const rows = mergeSessionRows(
      [{ sessionKey: "main", sessionId: "uuid-1", updatedAtMs: 1 }],
      [live({ sessionKey: "slash-only", sessionId: "s1", allowAll: true })],
    );
    assert.equal(rows[0]?.sessionKey, "slash-only");
    assert.equal(rows[0]?.allowAll, true);
    assert.equal(rows[1]?.sessionKey, "main");
  });

  it("caps host rows at 100 newest and still appends extras", () => {
    const host: HostSession[] = Array.from({ length: 120 }, (_, i) => ({
      sessionKey: `s${i}`,
      sessionId: `id-${i}`,
      updatedAtMs: i,
    }));
    const rows = mergeSessionRows(host, [live({ sessionKey: "flagged", allowAll: true })]);
    assert.equal(rows[0]?.sessionKey, "flagged");
    assert.equal(rows.length, 101);
    assert.ok(rows.some((r) => r.sessionKey === "s119"));
    assert.ok(!rows.some((r) => r.sessionKey === "s0"));
  });
});
