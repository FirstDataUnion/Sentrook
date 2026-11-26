import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { DESCRIPTION_BUDGET, errorCard, MARK, RELAXED_NOTE, reviewCard, STRONG_NOTE, TITLE_MAX } from "./card.ts";
import { scanErrorCopy } from "./scanErrorPolicy.ts";

const FIXTURE = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../fixtures/review-card/cases.json", import.meta.url)), "utf8"),
) as {
  budgets: { openclaw_title: number; openclaw_description: number };
  cases: { name: string; response: any; tool: string; relaxed: boolean; strong?: boolean; hint: any; remember: boolean; why_id: string | null; openclaw: { title: string; description: string } }[];
  errors: { name: string; cause: "rate_limited" | "config" | "auth" | "unreachable" | "not_signed_in" | "sign_in_rejected" | "consent_withdrawn"; openclaw: { title: string; description: string } }[];
};

// What OpenClaw replaces with a visible code before it checks the limits (its exec-approval text sanitizer).
const HOST_ESCAPES = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}   -   　ᅟᅠㅤﾠ]/u;
const codePoints = (s: string) => Array.from(s).length;

test("the card is the agreed text, case by case", () => {
  for (const c of FIXTURE.cases) {
    const card = reviewCard(c.response, c.tool, { relaxed: c.relaxed, strong: c.strong ?? false, hint: c.hint, remember: c.remember, whyId: c.why_id });
    assert.deepEqual(card, c.openclaw, c.name);
  }
});

test("the scan-error card is the agreed text, and each failure gets its cause", () => {
  for (const e of FIXTURE.errors) assert.deepEqual(errorCard(e.cause), e.openclaw, e.name);
  const copy = (kind: any, status?: number) => scanErrorCopy({ ok: false, kind, detail: "x", status });
  assert.deepEqual(copy("rate_limited"), errorCard("rate_limited"));
  assert.deepEqual(copy("config"), errorCard("config"));
  assert.deepEqual(copy("http", 403), errorCard("auth"));
  for (const [kind, status] of [["network"], ["timeout"], ["http", 503], ["scan_error"]] as [any, number?][]) {
    assert.deepEqual(copy(kind, status), errorCard("unreachable"));
  }
});

test("whatever the scan sends, OpenClaw never refuses the card", () => {
  // A seeded generator, so a failure can be replayed.
  let seed = 7;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
  const pick = <T>(xs: T[]) => xs[Math.floor(rnd() * xs.length)];
  const alphabet = Array.from("abc&<>\"'é🪶😀\n\t‍ ‮/.-_@[]`" + "x".repeat(20));
  const word = (n: number) => Array.from({ length: Math.floor(rnd() * (n + 1)) }, () => pick(alphabet)).join("");
  for (let i = 0; i < 400; i++) {
    const entities = Object.fromEntries([1, 2, 3].map((k) => [`E${k}`, { display: word(400) }]));
    const reasons = Array.from({ length: 4 }, () => ({ code: "a.b", text: `{E${1 + Math.floor(rnd() * 4)}} ${word(200)}` }));
    const resp: any = {
      risk: rnd() * 100,
      enforced: pick([null, "review"]),
      tool_description: pick([null, { template: `Sends {E1} to {E2} via {E3} ${word(80)}` }]),
      entities,
      reasons: pick([[], reasons]),
    };
    const hint = pick<any>([
      null,
      { kind: "destination", pattern: "h".repeat(1 + Math.floor(rnd() * 300)) },
      { kind: "file", pattern: "/p".repeat(1 + Math.floor(rnd() * 150)), allows: ["read", "write"] },
      // letters the host escapes, markup and mentions: a command the card must not show as typed
      { kind: "destination", pattern: "x" + "\u3164\u115f\uffa0".repeat(1 + Math.floor(rnd() * 120)) },
      { kind: "file", pattern: "/t/<@1>`[x]|@everyone".repeat(1 + Math.floor(rnd() * 20)), allows: ["read"] },
    ]);
    const relaxed = rnd() < 0.3;
    const strong = rnd() < 0.5;
    const remember = rnd() < 0.5;
    const card = reviewCard(resp, word(300) || "t", { relaxed, strong, hint, remember, whyId: pick([null, "3f9c2a1b-77aa"]) });
    // a snooze's note is never cut, and the strong one comes only with a relaxed block
    const lines = card.description.split("\n");
    if (relaxed) assert.ok(lines.includes(strong ? STRONG_NOTE : RELAXED_NOTE), card.description);
    else assert.ok(!lines.includes(STRONG_NOTE) && !lines.includes(RELAXED_NOTE), card.description);
    assert.ok(card.title.startsWith(MARK));
    assert.ok(codePoints(card.title) <= Math.min(TITLE_MAX, FIXTURE.budgets.openclaw_title), card.title);
    assert.ok(codePoints(card.description) <= Math.min(DESCRIPTION_BUDGET, FIXTURE.budgets.openclaw_description), card.description);
    assert.ok(!HOST_ESCAPES.test(card.title), card.title);
    assert.ok(!card.description.split("\n").some((line) => HOST_ESCAPES.test(line)), card.description);
  }
});

test("the card carries no redacted data", () => {
  const secret = `ghp_${"A".repeat(36)}`;
  const resp: any = {
    risk: 90,
    tree: { suspicion: { score: 0.9, note: secret }, extra: { score: secret } },
    tool_description: { template: "Sends {E2} to {E1}" },
    reasons: [{ code: "exfil.exec_egress", subject: secret, detail: { value: secret }, signal: secret, text: "it sends sensitive data to {E1}" }],
    entities: { E1: { kind: "host", display: "cl0ud-sync.io" }, E2: { kind: "path", display: "~/x" }, E3: { display: secret } },
  };
  const card = reviewCard(resp, "exec", { whyId: "3f9c2a1b" });
  assert.ok(!card.title.includes(secret) && !card.description.includes(secret));
  assert.deepEqual(card.description.split("\n").slice(0, 2), ["Sends ~/x to cl0ud-sync.io.", "Because it sends sensitive data to cl0ud-sync.io."]);
});

