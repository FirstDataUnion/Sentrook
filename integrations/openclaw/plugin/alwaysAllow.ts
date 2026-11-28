/**
 * What "Always allow" on a review of an MCP tool call lets through later: that tool on that server.
 *
 * Without a suggested grant, "Always allow" would set nothing a later call could be matched by, so the card offered
 * only "Allow once" and every call of an MCP write tool (another page, other text) asked again. On the owner's own
 * turn, a review of an MCP tool call now also offers "Always allow", and the answer is kept here, in
 * `<state dir>/always-allows.json`, as a standing allowance for that tool on that server: the tool, the server's
 * identity as the scan names the provider (its address, or the package it runs; a server the host config does not
 * describe has none, and keeps nothing), and every party the review named other than a path (a host, a recipient, a
 * channel: a call that sends somewhere else asks again). The path a call names is left out: an update tool names
 * another page on every call. A later review is let through when it scores at most `MARGIN` points above the answer
 * and below the block line, carries no warning the answered review lacked (a rising consequence trend is not one),
 * the scanner neither enforced it nor applied a floor, and the scan is complete. Each answer is kept on its own, for
 * `MAX_AGE_MS` from that answer.
 *
 * Where "Always allow" sets the review's suggested grant, nothing is kept here: the grant goes to the scanner.
 *
 * The same rule as the Hermes plugin's Always answer (`always_allow`), with the same key: both read the shared
 * fixture `integrations/fixtures/always-allow/cases.json`. The match key is an HMAC under the install's salt; each
 * entry also keeps the tool, the server's name and identity, for the owner's `grants` list and `revoke <id>`.
 */

import { createHmac, randomBytes } from "node:crypto";
import path from "node:path";

import { eligible, parties, riskOf, warnings } from "./passes.ts";
import type { ScanResponse } from "./scanClient.ts";
import { readTime, Store, withFileLock } from "./store.ts";

type Entry = Record<string, any>;

const DAY_MS = 24 * 3600_000;
/** How long one answer lets later calls through (as long as a grant "Always allow" sets). */
export const MAX_AGE_MS = 30 * DAY_MS;
/** How many points above the answered risk an allowance still covers (never at or above the block line). */
export const MARGIN = 10;
/** Warnings that do not ask again under an allowance: the session's consequence trend, bounded by `MARGIN`. */
export const ALLOWANCE_NOTES = new Set(["escalation.consequence_rising"]);
const MAX_ENTRIES = 200;
const MAX_ANSWERS = 5;
/** Party kinds left out of the key: what an MCP tool writes, which differs on every call. */
const UNKEYED_KINDS = new Set(["path"]);
export const FILE = "always-allows.json";
const ID = /^aa-[0-9a-f]{6}$/;

const file = (stateDir: string) => path.join(stateDir, FILE);
const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

/** `[name, identity]` of the MCP server a call's provider names; null for any other provider, or one with no identity. */
export function serverOf(provider: unknown): [string, string] | null {
  const p = provider as Entry | null;
  if (!p || typeof p !== "object" || p.kind !== "mcp") return null;
  if (typeof p.identity !== "string" || !p.identity.trim()) return null;
  return [typeof p.name === "string" && p.name ? p.name : p.identity, p.identity];
}

/** The allowance key of a call of `tool` on the MCP server `provider` names; null when it is not one. */
export function keyOf(tool: string, provider: unknown, resp: ScanResponse | Entry, secret: string): string | null {
  const server = serverOf(provider);
  if (server === null || !tool) return null;
  const named = parties(resp).filter(([k]) => !UNKEYED_KINDS.has(k));
  const material = [tool, server[1], ...named.map(([k, d]) => `${k}\t${d}`)].join("\n");
  return createHmac("sha256", `sentrook always allow v1|${secret}`).update(material).digest("hex").slice(0, 24);
}

/** Whether an answer at `risk` with the warnings `seen` covers this scan (the block line is checked apart). */
export function fits(risk: unknown, seen: unknown, resp: ScanResponse | Entry): boolean {
  const now = riskOf(resp);
  if (now === null || typeof risk !== "number" || !Number.isFinite(risk)) return false;
  const had = new Set(Array.isArray(seen) ? seen.map(String) : []);
  return now <= risk + MARGIN && warnings(resp).every((w) => had.has(w) || ALLOWANCE_NOTES.has(w));
}

export function load(stateDir: string): Entry | null {
  return new Store(stateDir).loadAlwaysAllows();
}

function liveAnswers(e: Entry, now: Date): Entry[] {
  return (Array.isArray(e.answers) ? e.answers : []).filter((a: Entry) => {
    const at = a && typeof a === "object" ? readTime(a.at) : null;
    return at !== null && now.getTime() - at.getTime() <= MAX_AGE_MS;
  });
}

/** Entries with at least one answer still in force. */
export function live(data: Entry | null, now: Date): Entry[] {
  const all = data && Array.isArray(data.allows) ? data.allows : [];
  return all.filter((e: Entry) => e && typeof e === "object" && liveAnswers(e, now).length > 0);
}

/** `[entry, answer]` that lets this review through, or null. Never at or above `blockAt`. */
export function covering(
  data: Entry | null,
  key: string | null,
  resp: ScanResponse | Entry,
  now: Date,
  blockAt: number,
): [Entry, Entry] | null {
  const risk = riskOf(resp);
  if (key === null || !eligible(resp) || risk === null || risk >= blockAt) return null;
  for (const e of live(data, now)) {
    if (e.key !== key) continue;
    for (const a of liveAnswers(e, now)) if (fits(a.risk, a.warnings, resp)) return [e, a];
  }
  return null;
}

/** Keep the allowance an answer gave; the entry, or null when the file cannot be read. */
export function add(
  stateDir: string,
  b: { key: string; tool: string; server: string; identity: string; risk: number; seen: string[]; requestId: string; now: Date },
): Entry | null {
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadAlwaysAllows();
    if (data === null) return null;
    const kept = live(data, b.now);
    let entry = kept.find((e) => e.key === b.key) ?? null;
    if (entry === null) {
      const taken = new Set(kept.map((e) => e.id));
      let id = `aa-${randomBytes(3).toString("hex")}`;
      while (taken.has(id)) id = `aa-${randomBytes(3).toString("hex")}`;
      entry = { id, key: b.key, tool: b.tool, server: b.server, identity: b.identity };
    } else {
      kept.splice(kept.indexOf(entry), 1);
    }
    const answers = liveAnswers(entry, b.now).filter((a) => a.request_id !== b.requestId);
    answers.push({ risk: b.risk, warnings: [...new Set(b.seen)].sort(), request_id: b.requestId, at: iso(b.now) });
    entry.answers = answers.slice(-MAX_ANSWERS);
    entry.set_at = iso(b.now);
    kept.push(entry);
    data.allows = kept.slice(-MAX_ENTRIES);
    store.saveAlwaysAllows(data);
    return entry;
  });
}

function clean(s: unknown, cap = 120): string {
  const text = String(s ?? "").split(/\s+/).filter(Boolean).join(" ");
  return [...text].length <= cap ? text : [...text].slice(0, cap - 1).join("") + "…";
}

/** `{reply, change}` when `id` names an allowance kept here; null when it names none (or the file cannot be read). */
export function revoke(
  stateDir: string,
  id: string,
  now: Date,
  beforeWrite: () => void = () => {},
): { reply: string; change: Entry } | null {
  if (!ID.test(id)) return null;
  return withFileLock(file(stateDir), () => {
    const store = new Store(stateDir);
    const data = store.loadAlwaysAllows();
    if (data === null) return null;
    const kept = live(data, now);
    const found = kept.find((e) => e.id === id);
    if (!found) return null;
    data.allows = kept.filter((e) => e !== found);
    beforeWrite();
    store.saveAlwaysAllows(data);
    return {
      reply: `Revoked ${id}: Always for ${clean(found.tool)} on ${clean(found.server)}.`,
      change: { op: "revoke_always", entry: { id: found.id, tool: found.tool, server: found.server } },
    };
  });
}

/** The `grants` listing's lines for these allowances; none when there are none. */
export function formatLines(stateDir: string, now: Date, cmd: (s: string) => string): string[] {
  const entries = live(load(stateDir), now);
  if (!entries.length) return [];
  const lines = ["Always answers (an MCP tool on its server, at a similar risk):"];
  for (const e of entries) {
    const last = Math.max(...liveAnswers(e, now).map((a) => readTime(a.at)!.getTime()));
    const until = new Date(last + MAX_AGE_MS).toISOString().slice(0, 16).replace("T", " ");
    lines.push(`  ${e.id}  ${clean(e.tool)} on ${clean(e.server)} (${clean(e.identity)}); expires ${until} UTC`);
  }
  lines.push(`Remove one with ${cmd("revoke")} <id>.`);
  return lines;
}
