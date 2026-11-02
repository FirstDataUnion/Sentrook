/**
 * Grants and channel bindings set by command, kept in `<state>/sentrook/grants.json`.
 *
 * Grants and channel bindings in the plugin config stay where they are: the commands list them as
 * read-only and never change them. A scan sends config grants, config bindings, then the file's live
 * grants and bindings, in that order, so adding by command never renumbers a config grant.
 *
 * A grant set by command has the PlanIR grant fields (kind, pattern, scope, allows, granted_at) plus
 * an id, who set it (`set_by`: the owner basis, channel and hashed sender) and an optional
 * `expires_at`. Scope is `session` unless the owner asks for `persistent`; any other value is refused.
 *
 * A session grant is bound to one session: the one the command was sent from, or the one `--session`
 * names (a `session_ref` as `history` shows it). It stores that `session_ref`, the same hash a scan of
 * the session sends, and is sent only on scans of that session: not in cron jobs, subagents or other
 * chats. A session grant with no session (the command line without `--session`) is refused, and one
 * stored without a session is never sent. Persistent grants and the plugin config's grants are sent on
 * every scan. An expired grant is not sent, and is dropped from the file on the next change. Patterns are passed
 * on as typed: Sentrook itself refuses patterns too broad to relieve on.
 *
 * Every change is written to the traffic log as a `grants` record (none when the owner has turned the
 * traffic log off). The Hermes plugin keeps the same file format and prints the same text.
 */

import { randomBytes } from "node:crypto";
import path from "node:path";

import { type GrantConfig, parseGrants, type PluginConfig } from "./config.ts";
import { type GrantsFile, readTime, Store } from "./store.ts";

export const KINDS = ["destination", "file", "provider"];
export const ALLOWS = ["read", "write", "edit", "delete", "exec"];
export const SCOPES = ["session", "persistent"];
const SESSION_REF = /^s_[0-9a-f]{12}$/;
export const MAX_PATTERN = 256;
const MAX_EXPIRY_MS = 365 * 24 * 3600_000;
const UNIT_MS: Record<string, number> = { m: 60_000, h: 3600_000, d: 24 * 3600_000 };

/** (subcommand) -> the command as the owner types it, e.g. "/sentrook-bind". */
export type Cmd = (sub: string) => string;

export type Entry = Record<string, any>;

/** A change to write to the traffic log, with the reply. */
export interface Change {
  op: "grant" | "revoke" | "bind_add" | "bind_remove";
  entry: Entry;
}

export interface ChangeResult {
  reply: string;
  change: Change | null;
}

export function load(stateDir: string): GrantsFile | null {
  return new Store(stateDir).loadGrants();
}

const iso = (d: Date) => `${d.toISOString().slice(0, 19)}Z`;
const show = (d: Date) => `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;

const NOT_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]|[^\P{Zs} ]/u;

function printable(s: string): boolean {
  return !NOT_PRINTABLE.test(s);
}

function clean(s: unknown, cap = 200): string {
  return Array.from(String(s), (c) => (printable(c) ? c : "?"))
    .slice(0, cap)
    .join("");
}

/** Past its expiry. An expiry that cannot be read counts as past, so it never widens relief. */
export function expired(entry: Entry, now: Date): boolean {
  if (!("expires_at" in entry)) return false;
  const at = readTime(entry.expires_at);
  return at === null || at.getTime() <= now.getTime();
}

/** [stored entry, PlanIR grant] for each usable entry, expired ones included. */
function fileGrants(data: GrantsFile | null): Array<[Entry, GrantConfig]> {
  const out: Array<[Entry, GrantConfig]> = [];
  for (const raw of data?.grants ?? []) {
    const [parsed] = parseGrants([raw]);
    if (parsed) out.push([raw as Entry, parsed]);
  }
  return out;
}

function fileBindings(data: GrantsFile | null): Entry[] {
  return (data?.bindings ?? []).filter(
    (b): b is Entry => !!b && typeof b === "object" && typeof (b as Entry).pattern === "string" && !!(b as Entry).pattern.trim(),
  );
}

/** The session a session grant set by command is bound to; null when it has none. */
function bound(raw: Entry): string | null {
  return typeof raw.session_ref === "string" && raw.session_ref ? raw.session_ref : null;
}

/**
 * Every grant a scan of the session `sessionRef` may send: config grants, config bindings, then live
 * file entries (a session grant only in its own session).
 */
export function effective(cfg: PluginConfig, data: GrantsFile | null, now: Date, sessionRef: string): GrantConfig[] {
  const out: GrantConfig[] = cfg.grants.map((g) => ({ ...g }));
  for (const pattern of cfg.channelBindings) out.push({ kind: "destination", pattern, scope: "persistent" });
  for (const [raw, g] of fileGrants(data)) {
    if (!expired(raw, now) && (g.scope !== "session" || bound(raw) === sessionRef)) out.push(g);
  }
  for (const b of fileBindings(data)) {
    const g: GrantConfig = { kind: "destination", pattern: b.pattern.trim(), scope: "persistent" };
    if (typeof b.granted_at === "string" && b.granted_at.trim()) g.granted_at = b.granted_at.trim();
    out.push(g);
  }
  return out;
}

// ---- listing -----------------------------------------------------------------------------------------

function setBy(entry: Entry): string[] {
  const at = readTime(entry.granted_at);
  const by = entry.set_by && typeof entry.set_by === "object" ? entry.set_by : {};
  const basis = (Array.isArray(by.basis) ? by.basis : []).filter((b: unknown): b is string => typeof b === "string");
  const text = `set${at ? ` ${show(at)}` : ""}${basis.length ? ` (${basis.join("+")})` : ""}`;
  return text !== "set" ? [clean(text)] : [];
}

function table(header: string[], rows: string[][], cap = 40): string[] {
  const all = [header, ...rows];
  const widths = header.slice(0, -1).map((_, i) => Math.min(cap, Math.max(...all.map((r) => r[i]!.length))));
  return all.map((r) => [...widths.map((w, i) => r[i]!.padEnd(w)), r.at(-1)!].join("  ").trimEnd());
}

function sessionOf(raw: Entry, ref: string | null): string {
  const b = bound(raw);
  if (b === null) return "no session, never sent";
  return b === ref ? "this session" : `session ${b}`;
}

/** The grants in force, as seen from the session `ref` (null: no current session). */
export function formatGrants(cfg: PluginConfig, data: GrantsFile | null, now: Date, cmd: Cmd, ref: string | null = null): string {
  const rows: string[][] = cfg.grants.map((g, i) => [
    `cfg-${i + 1}`,
    g.kind,
    g.scope ?? "persistent",
    g.pattern,
    [...(g.allows?.length ? [`allows ${g.allows.join(",")}`] : []), "config, read-only"].join("; "),
  ]);
  const file = fileGrants(data);
  for (const [raw, g] of file) {
    const details = g.scope === "session" ? [sessionOf(raw, ref)] : [];
    if (g.allows?.length) details.push(`allows ${g.allows.join(",")}`);
    if ("expires_at" in raw) {
      const at = readTime(raw.expires_at);
      details.push(`${expired(raw, now) ? "expired" : "expires"} ${at ? show(at) : "?"}`);
    }
    rows.push([String(raw.id || "-"), g.kind, g.scope ?? "session", g.pattern, [...details, ...setBy(raw)].join("; ")]);
  }
  const lines = [`Grants: ${cfg.grants.length} in config, ${file.length} by command`];
  if (data === null) lines.push("The grants file could not be read, so no grants set by command apply.");
  if (rows.length) lines.push(...table(["id", "kind", "scope", "pattern", "details"], rows.map((r) => r.map((c) => clean(c)))));
  lines.push(
    `Channel bindings: ${cfg.channelBindings.length} in config, ${fileBindings(data).length} by command; see ${cmd("bind")} list`,
  );
  return lines.join("\n");
}

export function formatBindings(cfg: PluginConfig, data: GrantsFile | null): string {
  const rows = [
    ...cfg.channelBindings.map((p) => [p, "config, read-only"]),
    ...fileBindings(data).map((b) => [b.pattern.trim(), setBy(b).join("; ")]),
  ];
  const lines = [`Channel bindings: ${cfg.channelBindings.length} in config, ${fileBindings(data).length} by command`];
  if (data === null) lines.push("The grants file could not be read, so no bindings set by command apply.");
  if (rows.length) lines.push(...table(["channel", "details"], rows.map((r) => r.map((c) => clean(c)))));
  return lines.join("\n");
}

/** The `grants:` and `channel bindings:` lines of status. */
export function counts(cfg: PluginConfig, data: GrantsFile | null): [string, string] {
  return [
    `${cfg.grants.length} in config, ${fileGrants(data).length} by command`,
    `${cfg.channelBindings.length} in config, ${fileBindings(data).length} by command`,
  ];
}

// ---- changes -----------------------------------------------------------------------------------------

export function grantUsage(cmd: Cmd): string {
  return (
    `usage: ${cmd("grant")} <kind> <pattern> [--persistent | --scope session|persistent] ` +
    "[--session <ref>] [--allows read,write] [--expires 12h]\n" +
    "kind is destination, file or provider; --allows is for file grants; scope defaults to " +
    "session: this session only, or the one --session names (a ref from " +
    `${cmd("history")}); cron jobs, subagents and other chats need --persistent`
  );
}

function noSession(cmd: Cmd): string {
  return (
    "There is no current session here, so a session grant cannot be bound to one; " +
    `give --session <ref> (from ${cmd("history")}) or --persistent (with --expires to end it).`
  );
}

interface ParsedGrant {
  kind: string;
  pattern: string;
  scope: string;
  session_ref?: string | null;
  allows?: string[];
  expiresInMs?: number;
}

/** The grant typed after `grant`, or the reason it is refused ("" for a plain usage error). */
export function parseGrant(rest: string, cmd: Cmd): ParsedGrant | string {
  const tokens = rest.split(/\s+/).filter(Boolean);
  const pos: string[] = [];
  const opts: Record<string, string> = {};
  for (let i = 0; i < tokens.length; ) {
    const tok = tokens[i++]!;
    if (!tok.startsWith("--")) {
      pos.push(tok);
      continue;
    }
    const eq = tok.indexOf("=");
    const name = eq < 0 ? tok.slice(2) : tok.slice(2, eq);
    let value = eq < 0 ? undefined : tok.slice(eq + 1);
    if (name === "persistent" && eq < 0) {
      opts.scope = "persistent";
      continue;
    }
    if (!["scope", "session", "allows", "expires"].includes(name)) return `Unknown option --${clean(name, 40)}.`;
    if (value === undefined) {
      if (i >= tokens.length) return `--${name} needs a value.`;
      value = tokens[i++]!;
    }
    opts[name] = value;
  }
  if (pos.length !== 2) return "";
  const kind = pos[0]!.toLowerCase();
  const pattern = pos[1]!;
  if (!KINDS.includes(kind)) return `Unknown grant kind "${clean(pos[0], 40)}": use destination, file or provider.`;
  if (pattern.length > MAX_PATTERN || !printable(pattern)) {
    return `The pattern must be at most ${MAX_PATTERN} printable characters.`;
  }
  const scope = opts.scope ?? "session";
  if (!SCOPES.includes(scope)) return `Unknown scope "${clean(scope, 40)}": use session or persistent.`;
  const grant: ParsedGrant = { kind, pattern, scope };
  if (opts.session !== undefined) {
    if (scope !== "session") return "--session applies to session grants only.";
    if (!SESSION_REF.test(opts.session)) {
      return `Unknown session "${clean(opts.session, 40)}": use a session ref (s_ and 12 hex digits) from ${cmd("history")}.`;
    }
    grant.session_ref = opts.session;
  }
  if (opts.allows !== undefined) {
    if (kind !== "file") return "--allows applies to file grants only.";
    const allows = opts.allows.split(",").map((a) => a.trim()).filter(Boolean);
    if (!allows.length) return "--allows needs a value.";
    for (const a of allows) {
      if (!ALLOWS.includes(a)) return `Unknown allows value "${clean(a, 40)}": use read, write, edit, delete or exec.`;
    }
    grant.allows = [...new Set(allows)];
  }
  if (opts.expires !== undefined) {
    const m = /^(\d{1,6})([mhd])$/.exec(opts.expires);
    const span = m ? Number(m[1]) * UNIT_MS[m[2]!]! : NaN;
    if (!(span >= UNIT_MS.m! && span <= MAX_EXPIRY_MS)) {
      return `Unknown expiry "${clean(opts.expires, 40)}": use a number with m, h or d, from 1m to 365d.`;
    }
    grant.expiresInMs = span;
  }
  return grant;
}

/**
 * Read the file, apply `fn`, and write it back (after `beforeWrite`) if it made a change. A write
 * also drops expired grants; `fn` still sees them, so revoking one works.
 */
function change(stateDir: string, now: Date, fn: (data: GrantsFile) => ChangeResult, beforeWrite: () => void): ChangeResult {
  const store = new Store(stateDir);
  const data = store.loadGrants();
  if (data === null) {
    return {
      reply: `The grants file ${path.join(stateDir, "grants.json")} could not be read; fix or remove it first.`,
      change: null,
    };
  }
  const result = fn(data);
  if (result.change) {
    data.grants = data.grants.filter((g) => !(g && typeof g === "object" && expired(g as Entry, now)));
    beforeWrite();
    store.saveGrants(data);
  }
  return result;
}

/** `grant ...` from the session `ref` (null: no current session). */
export function addGrant(
  stateDir: string,
  rest: string,
  ref: string | null,
  by: Entry,
  now: Date,
  cmd: Cmd,
  beforeWrite: () => void,
): ChangeResult {
  const parsed = parseGrant(rest, cmd);
  if (typeof parsed === "string") {
    const usage = grantUsage(cmd);
    return { reply: parsed ? `${parsed}\n${usage}` : usage, change: null };
  }
  if (parsed.scope === "session") {
    parsed.session_ref ??= ref;
    if (parsed.session_ref === null) return { reply: noSession(cmd), change: null };
  }
  return change(
    stateDir,
    now,
    (data) => {
      const taken = new Set(data.grants.map((g) => (g as Entry)?.id));
      let id = `gr-${randomBytes(3).toString("hex")}`;
      while (taken.has(id)) id = `gr-${randomBytes(3).toString("hex")}`;
      const { expiresInMs, ...grant } = parsed;
      const entry: Entry = { id, ...grant, granted_at: iso(now) };
      const expires = expiresInMs === undefined ? null : new Date(now.getTime() + expiresInMs);
      if (expires) entry.expires_at = iso(expires);
      entry.set_by = by;
      data.grants.push(entry);
      const where =
        entry.scope !== "session" ? entry.scope : entry.session_ref === ref ? "this session only" : `session ${entry.session_ref} only`;
      const details = [where, ...(entry.allows ? [`allows ${entry.allows.join(",")}`] : [])];
      if (expires) details.push(`expires ${show(expires)}`);
      const note = entry.scope === "session" ? " Cron jobs, subagents and other chats need a --persistent grant (add --expires to end it)." : "";
      return {
        reply: `Granted ${id}: ${entry.kind} ${entry.pattern} (${details.join(", ")}).${note}`,
        change: { op: "grant", entry },
      };
    },
    beforeWrite,
  );
}

export function revoke(stateDir: string, cfg: PluginConfig, rest: string, now: Date, cmd: Cmd, beforeWrite: () => void): ChangeResult {
  const words = rest.split(/\s+/).filter(Boolean);
  if (words.length !== 1) return { reply: `usage: ${cmd("revoke")} <id>, with an id from ${cmd("grants")}`, change: null };
  const id = words[0]!;
  const m = /^cfg-(\d+)$/.exec(id);
  if (m && Number(m[1]) >= 1 && Number(m[1]) <= cfg.grants.length) {
    return { reply: `${id} is set in the plugin config; remove it there.`, change: null };
  }
  return change(
    stateDir,
    now,
    (data) => {
      const i = data.grants.findIndex((g) => (g as Entry)?.id === id);
      if (i < 0) return { reply: `No grant ${clean(id, 40)}; see ${cmd("grants")}.`, change: null };
      const [entry] = data.grants.splice(i, 1) as Entry[];
      return { reply: `Revoked ${id}: ${clean(entry!.kind)} ${clean(entry!.pattern)}.`, change: { op: "revoke", entry: entry! } };
    },
    beforeWrite,
  );
}

export function bind(
  stateDir: string,
  cfg: PluginConfig,
  rest: string,
  by: Entry,
  now: Date,
  cmd: Cmd,
  beforeWrite: () => void,
): ChangeResult {
  const words = rest.split(/\s+/).filter(Boolean);
  const op = (words[0] ?? "list").toLowerCase();
  if (op === "list" && words.length <= 1) return { reply: formatBindings(cfg, load(stateDir)), change: null };
  if ((op !== "add" && op !== "remove") || words.length !== 2) {
    return { reply: `usage: ${cmd("bind")} add|remove <channel>, or ${cmd("bind")} list`, change: null };
  }
  const channel = words[1]!;
  if (channel.length > MAX_PATTERN || !printable(channel)) {
    return { reply: `The channel must be at most ${MAX_PATTERN} printable characters.`, change: null };
  }
  if (cfg.channelBindings.includes(channel)) {
    return {
      reply: op === "add" ? `${channel} is already bound in the plugin config.` : `${channel} is bound in the plugin config; remove it there.`,
      change: null,
    };
  }
  return change(
    stateDir,
    now,
    (data) => {
      const found = data.bindings.findIndex((b) => (b as Entry)?.pattern === channel);
      if (op === "add") {
        if (found >= 0) return { reply: `${channel} is already bound.`, change: null };
        const entry: Entry = { pattern: channel, granted_at: iso(now), set_by: by };
        data.bindings.push(entry);
        return { reply: `Channel binding added: ${channel}.`, change: { op: "bind_add", entry } };
      }
      if (found < 0) return { reply: `${channel} is not bound.`, change: null };
      const [entry] = data.bindings.splice(found, 1) as Entry[];
      return { reply: `Channel binding removed: ${channel}.`, change: { op: "bind_remove", entry: entry! } };
    },
    beforeWrite,
  );
}
