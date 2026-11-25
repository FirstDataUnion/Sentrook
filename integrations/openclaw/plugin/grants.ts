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
 * A `credential` grant (`NAME@host`: a key's environment name, or `PREFIX*`, and the host it is meant
 * for, or `*.example.com`) is `persistent` unless the owner asks for `session`: a key's home rarely
 * changes. Its pattern is checked here as Sentrook reads it, so a typo is refused at once rather than
 * relieving nothing.
 *
 * A session grant is bound to one session: the one the command was sent from, or the one `--session`
 * names (a `session_ref` as `history` shows it). It stores that `session_ref`, the same hash a scan of
 * the session sends, and is sent only on scans of that session: not in cron jobs, subagents or other
 * chats. A session grant with no session (the command line without `--session`) is refused, and one
 * stored without a session is never sent. Persistent grants are sent on every scan. A config grant has
 * no session to be bound to, so one with scope session, or with an unknown scope (read as session), is
 * never sent either; the listing, status, verify and the startup log name it. A scan sends a session
 * grant with its `session_ref` and a grant with an expiry with its `expires_at`, and Sentrook checks
 * both. An expired grant is not sent, and is dropped from the file on the next change. Patterns are
 * passed on as typed: Sentrook itself refuses patterns too broad to relieve on.
 *
 * Every change is written to the traffic log as a `grants` record (none when the owner has turned the
 * traffic log off). The Hermes plugin keeps the same file format and prints the same text.
 */

import { randomBytes } from "node:crypto";
import path from "node:path";

import { type GrantConfig, parseGrants, type PluginConfig } from "./config.ts";
import { bindingProblem, HOST_TASK_KINDS } from "./planir.ts";
import { type GrantsFile, readTime, Store, withFileLock } from "./store.ts";

export const KINDS = ["destination", "file", "provider", "repo", "credential"];
/**
 * A credential grant's pattern as Sentrook reads it: a name (or a prefix of three or more characters
 * and `*`), `@`, and a host (or `*.` and a domain of two or more labels), with no scheme, port or path.
 */
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
export const CREDENTIAL_PATTERN = new RegExp(
  `^(?:[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]{2,}\\*)@(?:\\*\\.)?${LABEL}(?:\\.${LABEL})+$`,
);
/**
 * Second-level labels under which a two-letter country domain is shared by many owners (`co.uk`): a wildcard there,
 * or on part of a numeric address, covers strangers, and Sentrook refuses it.
 */
export const SHARED_SECOND_LEVEL = new Set(["co", "com", "org", "net", "ac", "gov", "edu"]);

/** `NAME@host` as Sentrook reads it (the host already lower-cased). */
export function credentialPatternOk(pattern: string): boolean {
  if (!CREDENTIAL_PATTERN.test(pattern)) return false;
  const host = pattern.slice(pattern.indexOf("@") + 1);
  if (!host.startsWith("*.")) return true;
  const labels = host.slice(2).split(".");
  if (labels.every((l) => /^\d+$/.test(l))) return false;
  return !(labels.length === 2 && SHARED_SECOND_LEVEL.has(labels[0]!) && labels[1]!.length === 2);
}
/**
 * `pattern` is `*.` and one domain as a credential grant's host may name it: two or more labels, not a shared country
 * second level (`*.co.uk`) or part of a numeric address. The rule is `credentialPatternOk`'s, for the host alone.
 */
export function wildcardDomainOk(pattern: string): boolean {
  return pattern.startsWith("*.") && credentialPatternOk(`NAME@${pattern.toLowerCase().replace(/\.+$/, "")}`);
}
export const ALLOWS = ["read", "write", "edit", "delete", "exec"];
export const SCOPES = ["session", "persistent"];
export const SESSION_REF = /^s_[0-9a-f]{12}$/;
export const MAX_PATTERN = 256;
export const MAX_EXPIRY_MS = 365 * 24 * 3600_000;
const UNIT_MS: Record<string, number> = { m: 60_000, h: 3600_000, d: 24 * 3600_000 };

/** (subcommand) -> the command as the owner types it, e.g. "/sentrook-bind". */
export type Cmd = (sub: string) => string;

export type Entry = Record<string, any>;

/** A change to write to the traffic log, with the reply. */
export interface Change {
  op: "grant" | "revoke" | "bind_add" | "bind_remove";
  entry: Entry;
  /** Set when an approval found the grant its hold already set, and wrote nothing. */
  existing?: boolean;
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

export function printable(s: string): boolean {
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
export function fileGrants(data: GrantsFile | null): Array<[Entry, GrantConfig]> {
  const out: Array<[Entry, GrantConfig]> = [];
  for (const raw of data?.grants ?? []) {
    const [parsed] = parseGrants([raw]);
    if (parsed) out.push([raw as Entry, parsed]);
  }
  return out;
}

export function fileBindings(data: GrantsFile | null): Entry[] {
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
  const out: GrantConfig[] = cfg.grants.filter((g) => g.scope === "persistent").map((g) => ({ ...g }));
  for (const pattern of cfg.channelBindings) out.push({ kind: "destination", pattern, scope: "persistent" });
  for (const [raw, g] of fileGrants(data)) {
    if (expired(raw, now) || (g.scope === "session" && bound(raw) !== sessionRef)) continue;
    if (g.scope === "session") g.session_ref = sessionRef;
    const at = readTime(raw.expires_at);
    if (at !== null) g.expires_at = iso(at);
    out.push(g);
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
    [
      ...(g.allows?.length ? [`allows ${g.allows.join(",")}`] : []),
      "config, read-only",
      ...(i in cfg.unsentGrants ? [`${cfg.unsentGrants[i]}, never sent`] : []),
    ].join("; "),
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

/** A binding's details, with why it can never apply when it cannot. */
function withProblem(pattern: string, details: string[]): string {
  const problem = bindingProblem(pattern);
  return [...details, ...(problem ? [problem] : [])].join("; ");
}

export function formatBindings(cfg: PluginConfig, data: GrantsFile | null): string {
  const rows = [
    ...cfg.channelBindings.map((p) => [p, withProblem(p, ["config, read-only"])]),
    ...fileBindings(data).map((b) => [b.pattern.trim(), withProblem(b.pattern, setBy(b))]),
  ];
  const lines = [`Channel bindings: ${cfg.channelBindings.length} in config, ${fileBindings(data).length} by command`];
  if (data === null) lines.push("The grants file could not be read, so no bindings set by command apply.");
  if (rows.length) lines.push(...table(["channel", "details"], rows.map((r) => r.map((c) => clean(c)))));
  return lines.join("\n");
}

/** The config bindings that can never apply and why, e.g. `ab (too short, never sent)`; "" when none. */
export function bindingProblemsSummary(cfg: PluginConfig): string {
  return cfg.channelBindings
    .flatMap((p) => {
      const why = bindingProblem(p);
      return why ? [`${clean(p, 60)} (${why})`] : [];
    })
    .join(", ");
}

/** The config grants that are never sent and why, e.g. `cfg-2 (no session)`; "" when none. */
export function unsentSummary(cfg: PluginConfig): string {
  return Object.entries(cfg.unsentGrants)
    .map(([i, why]) => `cfg-${Number(i) + 1} (${clean(why, 60)})`)
    .join(", ");
}

/** The `grants:` and `channel bindings:` lines of status. */
export function counts(cfg: PluginConfig, data: GrantsFile | null): [string, string] {
  const unsent = Object.keys(cfg.unsentGrants).length;
  return [
    `${cfg.grants.length} in config${unsent ? ` (${unsent} never sent)` : ""}, ${fileGrants(data).length} by command`,
    `${cfg.channelBindings.length} in config, ${fileBindings(data).length} by command`,
  ];
}

// ---- changes -----------------------------------------------------------------------------------------

export function grantUsage(cmd: Cmd): string {
  return (
    `usage: ${cmd("grant")} <kind> <pattern> [--persistent | --scope session|persistent] ` +
    "[--session <ref>] [--allows read,write] [--expires 12h]\n" +
    "kind is destination, file, provider, repo (github.com/<owner>/<repo>) or credential " +
    "(NAME@host: the key and the host it is meant for); --allows is for file grants; scope defaults to " +
    "session: this session only, or the one --session names (a ref from " +
    `${cmd("history")}); cron jobs, subagents and other chats need --persistent. ` +
    "A credential grant is persistent unless --scope session is given"
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
  let pattern = pos[1]!;
  if (!KINDS.includes(kind)) {
    return `Unknown grant kind "${clean(pos[0], 40)}": use destination, file, provider, repo or credential.`;
  }
  if (pattern.length > MAX_PATTERN || !printable(pattern)) {
    return `The pattern must be at most ${MAX_PATTERN} printable characters.`;
  }
  if (kind === "credential") {
    const at = pattern.indexOf("@");
    if (at >= 0) pattern = `${pattern.slice(0, at)}@${pattern.slice(at + 1).toLowerCase().replace(/\.+$/, "")}`;
    if (!credentialPatternOk(pattern)) {
      return (
        `"${clean(pos[1], 80)}" is not a credential pattern: use NAME@host, such as ` +
        "MY_SERVICE_TOKEN@api.myservice.example (NAME may end in * after three or more characters, " +
        "host may be *.example.com)."
      );
    }
  }
  // a credential grant is persistent unless the owner asks for a session (naming one with --session asks too)
  const scope = opts.scope ?? (kind === "credential" && opts.session === undefined ? "persistent" : "session");
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
  // The gateway (an approved hold) and the command line can change the file at the same time.
  return withFileLock(path.join(stateDir, "grants.json"), () => changeLocked(stateDir, now, fn, beforeWrite));
}

function changeLocked(stateDir: string, now: Date, fn: (data: GrantsFile) => ChangeResult, beforeWrite: () => void): ChangeResult {
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

/**
 * A suggested grant as the owner could have typed it: run through `parseGrant` with the same rules as
 * `grant <kind> <pattern> --persistent [--allows ...]`, so a suggestion can never set more than the command could.
 * Kind, pattern and allows only; the scope is always persistent and the expiry is the hold's. Null when it is not
 * one the command would accept.
 */
export function hintGrant(hint: unknown): Entry | null {
  if (!hint || typeof hint !== "object" || Array.isArray(hint)) return null;
  const { kind, pattern, allows } = hint as Entry;
  if (typeof kind !== "string" || typeof pattern !== "string") return null;
  const words = [kind, pattern.trim(), "--persistent"];
  if (allows !== undefined && allows !== null) {
    // Each one known verb, exactly: no spaces, commas or anything the command line would split.
    if (!Array.isArray(allows) || !allows.every((a) => typeof a === "string" && ALLOWS.includes(a))) return null;
    words.push("--allows", allows.join(","));
  }
  // One word each, as typed: a kind or pattern with spaces could not have been typed either.
  if (words.slice(0, 2).some((w) => !w || /\s/u.test(w))) return null;
  const parsed = parseGrant(words.join(" "), (sub) => sub);
  if (typeof parsed === "string") return null;
  return { kind: parsed.kind, pattern: parsed.pattern, ...(parsed.allows ? { allows: parsed.allows } : {}) };
}

/** Days a suggested grant lasts when the owner sets it (by command, by approving a held call, or by approving a review always). */
export const HINT_DAYS = 30;
/** Sender bases that put a message in a room others can write to. */
const SHARED_BASIS = new Set(["group_chat", "host_open_access"]);
/** Sender bases that say nothing about how the relation was derived. */
const NO_BASIS = new Set(["none", "unknown"]);

/**
 * The scan response's suggested grants (`grant_hints`) that the grant command would accept, as `hintGrant` returns
 * them, in the scanner's order. With `reviewAt`, only those whose own risk (the call's risk with the grant applied)
 * is below this plugin's review line.
 */
export function responseHints(resp: unknown, reviewAt?: number): Entry[] {
  const raw = resp && typeof resp === "object" ? (resp as Entry).grant_hints : undefined;
  const out: Entry[] = [];
  for (const h of Array.isArray(raw) ? raw.slice(0, 3) : []) {
    if (!h || typeof h !== "object" || Array.isArray(h)) continue;
    if (reviewAt !== undefined && !(typeof h.risk === "number" && h.risk < reviewAt)) continue;
    const grant = hintGrant(h);
    if (grant && !out.some((g) => JSON.stringify(g) === JSON.stringify(grant))) out.push(grant);
  }
  return out;
}

/** The command that sets `grant` (from `hintGrant`) as the owner types it: persistent, ending in 30 days. */
export function grantCommand(grant: Entry, cmd: Cmd): string {
  const words = [cmd("grant"), grant.kind, grant.pattern, "--persistent", "--expires", `${HINT_DAYS}d`];
  if (Array.isArray(grant.allows) && grant.allows.length) words.push("--allows", grant.allows.join(","));
  return clean(words.join(" "), 400);
}

export { HOST_TASK_KINDS };
/** The line `/sentrook-why <hold id>` adds under a suggestion from a host task run. */
export const HOLD_CONTEXT = "this suggestion comes from a {kind} run, not your own message: {where}";

/**
 * The owner's own turn: the sender is the owner, or the host started a scheduled or heartbeat run with no sender
 * behind it (`unknown`). A suggested grant is shown, kept on a hold and set only then: on anyone else's turn (a
 * non-owner sender, a sub-agent, a hook), whoever sent it chose what the call acts on. On a host task run a
 * suggestion reaches the owner only through a held call they approve.
 */
export function ownerSender(planir: Entry): boolean {
  const relation = planir?.trigger?.sender?.relation;
  return relation === "owner" || (HOST_TASK_KINDS.has(planir?.trigger?.kind) && relation === "unknown");
}

/**
 * Approving a review always may set its suggested grant: the call came from the owner's own message on the main
 * agent, outside a group chat or a host open to anyone, in a chat the plugin could tell apart. Whoever answers a review elsewhere is not known to be the
 * owner, so there the prompt only shows the command.
 */
export function mayRemember(planir: Entry): boolean {
  const trig = planir?.trigger && typeof planir.trigger === "object" ? planir.trigger : {};
  const sender = trig.sender && typeof trig.sender === "object" ? trig.sender : {};
  const basis: unknown[] = Array.isArray(sender.basis) ? sender.basis : [];
  return (
    trig.kind === "message" &&
    sender.relation === "owner" &&
    planir?.session?.agent_role === "main" &&
    !basis.some((b) => typeof b === "string" && SHARED_BASIS.has(b)) &&
    // a basis that says how the plugin knows: `none` alone is a chat whose kind it could not tell, maybe a room
    basis.some((b) => typeof b === "string" && !NO_BASIS.has(b)) &&
    (planir?.self_edit ?? null) === null
  );
}

/** `destination discord:#ops`, with `(allows read)` for a file grant that limits them. */
export function describeGrant(grant: Entry): string {
  const allows = grant.allows ? ` (allows ${grant.allows.join(",")})` : "";
  return clean(`${grant.kind} ${grant.pattern}${allows}`, 300);
}

/**
 * Adds `grant` (from `hintGrant`) as a persistent grant ending `spanMs` from now, for an approved hold (`source`
 * `from_hold`, `holdId` its id) or a review approved always (`from_review`, the scan's request id). The reply names
 * the new grant's id; no change when the file could not be read.
 */
export function addSuggested(
  stateDir: string,
  grant: Entry,
  by: Entry,
  now: Date,
  spanMs: number,
  holdId: string,
  beforeWrite: () => void,
  source: "from_hold" | "from_review" = "from_hold",
): ChangeResult {
  return change(
    stateDir,
    now,
    (data) => {
      // Once per hold or review: an approval retried after a failed save finds its grant.
      const prior = data.grants.find((g) => g && typeof g === "object" && (g as Entry)[source] === holdId && !expired(g as Entry, now)) as
        | Entry
        | undefined;
      if (prior) {
        const at = readTime(prior.expires_at);
        return {
          reply: `Granted ${prior.id}: ${describeGrant(prior)} (persistent, expires ${at ? show(at) : "?"}).`,
          change: { op: "grant", entry: prior, existing: true },
        };
      }
      const taken = new Set(data.grants.map((g) => (g as Entry)?.id));
      let id = `gr-${randomBytes(3).toString("hex")}`;
      while (taken.has(id)) id = `gr-${randomBytes(3).toString("hex")}`;
      const expires = new Date(now.getTime() + spanMs);
      const entry: Entry = {
        id,
        ...grant,
        scope: "persistent",
        granted_at: iso(now),
        expires_at: iso(expires),
        set_by: by,
        [source]: holdId,
      };
      data.grants.push(entry);
      return {
        reply: `Granted ${id}: ${describeGrant(entry)} (persistent, expires ${show(expires)}).`,
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
        const problem = bindingProblem(channel);
        return { reply: `Channel binding added: ${channel}${problem ? ` (${problem}).` : "."}`, change: { op: "bind_add", entry } };
      }
      if (found < 0) return { reply: `${channel} is not bound.`, change: null };
      const [entry] = data.bindings.splice(found, 1) as Entry[];
      return { reply: `Channel binding removed: ${channel}.`, change: { op: "bind_remove", entry: entry! } };
    },
    beforeWrite,
  );
}
