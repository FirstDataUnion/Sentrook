/**
 * File-backed plugin state under `<state>/sentrook/`, so episodes survive gateway restarts.
 *
 * - `sessions/<sid>.json`: step counter, input sequence, state token, history, input buffer
 * - `runs/<runId>.json`: run context joined from agent hooks (trigger, request, sender facts)
 * - `assistant/<sessionKey>.json`: the latest assistant message (narration and sibling calls)
 * - `subagents.json`: child session key → parent session key
 * - `grants.json`: grants and channel bindings set by command (see `grants.ts`)
 * - `snooze.json`: snoozes set by command (see `snooze.ts`)
 * - `selfedit/<runId>.json`: the conversation a self-editing run read (see `conversation.ts`), kept for at most
 *   `SELF_EDIT_KEEP_DAYS` days and the latest `SELF_EDIT_KEEP_RUNS` runs
 * - `salt`: per-install key for placeholder refs and hashed ids
 *
 * Writes are atomic (temp file then rename). Read-modify-write of a session goes through
 * `withSession`, which serialises callers per session in this process.
 */

import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  linkSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import path from "node:path";

/** A lock file older than this is left over from a process that died holding it, and is taken over. */
export const LOCK_STALE_MS = 30_000;
/** How long to wait for another process's lock before giving up. Short: the gateway waits on it. */
export const LOCK_WAIT_MS = 1_000;
const LOCK_SLEEP = new Int32Array(new SharedArrayBuffer(4));

/** Another process held a state file's lock for longer than `LOCK_WAIT_MS`. */
export class LockTimeoutError extends Error {}

function readToken(file: string): string | null {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

/**
 * Removes a lock judged stale, only if it is still the one judged (`seen`): it is renamed aside first, which only
 * one process can do, and a lock that turns out to be someone's fresh one is put back.
 */
function takeOver(lock: string, seen: string): void {
  const aside = `${lock}.stale.${process.pid}.${randomBytes(4).toString("hex")}`;
  try {
    renameSync(lock, aside);
  } catch {
    return; // someone else took it over or released it
  }
  if (readToken(aside) !== seen) {
    try {
      linkSync(aside, lock); // a fresh lock moved by mistake: put it back, unless another is there now
    } catch {
      // the path is taken again; the lock that was moved is lost to its owner's release check
    }
  }
  rmSync(aside, { force: true });
}

/**
 * Runs `fn` holding `<file>.lock`, so a read-modify-write of `file` is safe across processes (the gateway and the
 * `openclaw sentrook` command line) as well as within one. The lock is a file created exclusively that holds a
 * token unique to this holder. One older than `LOCK_STALE_MS` is from a process that died holding it: it is
 * renamed aside (only one waiter can) and checked before it is removed. A holder removes the lock only while it
 * still holds its own token. Throws `LockTimeoutError` when another process holds it for longer than
 * `LOCK_WAIT_MS`. The write inside stays atomic (temp file, then rename).
 */
export function withFileLock<T>(file: string, fn: () => T): T {
  const lock = `${file}.lock`;
  const token = `${process.pid}:${randomBytes(8).toString("hex")}\n`;
  mkdirSync(path.dirname(lock), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(lock, "wx", 0o600);
      try {
        writeSync(fd, token);
      } finally {
        closeSync(fd);
      }
      break;
    } catch (err: any) {
      if (err?.code !== "EEXIST") throw err;
    }
    const before = readToken(lock);
    let age = 0;
    try {
      age = Date.now() - statSync(lock).mtimeMs;
    } catch {
      continue; // released between the two calls
    }
    if (before !== null && age > LOCK_STALE_MS && readToken(lock) === before) {
      takeOver(lock, before);
      continue;
    }
    if (Date.now() > deadline) throw new LockTimeoutError(`${lock} is held by another process`);
    Atomics.wait(LOCK_SLEEP, 0, 0, 5);
  }
  try {
    return fn();
  } finally {
    if (readToken(lock) === token) rmSync(lock, { force: true });
  }
}

export interface Provider {
  kind: string;
  name: string | null;
  identity: string | null;
  transport: string | null;
}

export interface HistoryEntry {
  step: number;
  turn: number;
  call_id: string;
  tool: string;
  tool_kind: string;
  provider: Provider;
  arguments: Record<string, unknown>;
  result: { status: "ok" | "error"; size_bytes: number } | null;
  action_fingerprint: string | null;
  risk: number | null;
  tiers: { suspicion: number | null; consequence: number | null; confidence: number | null } | null;
  request_id: string;
  decision: string;
  /** Plugin-only bookkeeping, stripped before sending. */
  _host_call_id?: string;
}

export interface BufferedInput {
  input_seq: number;
  kind: "tool_result";
  call_id: string;
  tool: string;
  tool_kind: string;
  provider: Provider;
  status: "ok" | "error";
  content_type: string;
  content: string | null;
  size_bytes: number;
  truncated: boolean;
}

export interface Session {
  nextStep: number;
  inputSeq: number;
  token: string | null;
  runs: string[];
  seenCallIds: string[];
  history: HistoryEntry[];
  buffer: BufferedInput[];
}

export type RunContext = Record<string, any>;

export interface GrantsFile {
  version?: number;
  grants: unknown[];
  bindings: unknown[];
  [key: string]: unknown;
}

export interface SnoozeFile {
  version?: number;
  snoozes: unknown[];
  [key: string]: unknown;
}

export interface HoldsFile {
  version?: number;
  holds: unknown[];
  [key: string]: unknown;
}

/** Where the owner gets notices: a direct message on one channel, as `/sentrook-notify here` recorded it. */
export interface NotifyTarget {
  channel: string;
  to: string;
  accountId?: string;
  threadId?: string | number;
  set_at: string;
  set_by: Record<string, unknown>;
}

/** The only time form read back from `grants.json` and `snooze.json`; both plugins accept exactly this. */
const ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:Z|[+-](\d{2}):(\d{2}))?$/;

const daysIn = (y: number, mo: number) =>
  mo === 2 ? (y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28) : [4, 6, 9, 11].includes(mo) ? 30 : 31;

/**
 * A time from a state file: ISO with a `T`, no offset meaning UTC; anything else is unreadable. A field
 * out of range (`24:00`, `12:30:60`, `02-30`, year 0, offset `+24:00`) is unreadable too, as it is to
 * the Hermes plugin, rather than rolled forward into a later time; so is a time whose UTC year is not
 * 1-9999. Only ASCII spaces, tabs and line breaks around it are ignored.
 */
export function readTime(raw: unknown): Date | null {
  const text = typeof raw === "string" ? raw.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "") : "";
  const m = ISO.exec(text);
  if (!m) return null;
  const [y, mo, d, h, mi, s, oh, om] = m.slice(1).map((v) => Number(v ?? 0)) as number[];
  if (
    y! < 1 ||
    mo! < 1 ||
    mo! > 12 ||
    d! < 1 ||
    d! > daysIn(y!, mo!) ||
    h! > 23 ||
    mi! > 59 ||
    s! > 59 ||
    oh! > 23 ||
    om! > 59
  ) {
    return null;
  }
  const at = new Date(/(?:Z|[+-]\d{2}:\d{2})$/.test(text) ? text : `${text}Z`);
  const year = at.getUTCFullYear();
  return Number.isNaN(year) || year < 1 || year > 9999 ? null : at;
}

/** Retention of the self-edit conversation logs. */
export const SELF_EDIT_KEEP_DAYS = 7;
export const SELF_EDIT_KEEP_RUNS = 100;

const fileKey = (s: string) => s.replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 120);

export class Store {
  readonly dir: string;
  private locks = new Map<string, Promise<unknown>>();
  private saltCache: string | null = null;

  constructor(dir: string) {
    this.dir = dir;
  }

  private readJson<T>(file: string, fallback: T): T {
    try {
      return JSON.parse(readFileSync(file, "utf8")) as T;
    } catch {
      return fallback;
    }
  }

  private writeJson(file: string, value: unknown): void {
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    writeFileSync(tmp, JSON.stringify(value), { mode: 0o600 });
    renameSync(tmp, file);
  }

  salt(): string {
    if (this.saltCache) return this.saltCache;
    const file = path.join(this.dir, "salt");
    if (existsSync(file)) {
      const v = readFileSync(file, "utf8").trim();
      if (v) return (this.saltCache = v);
    }
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const v = randomBytes(32).toString("hex");
    writeFileSync(file, v, { mode: 0o600 });
    try {
      chmodSync(file, 0o600);
    } catch {
      // best effort
    }
    return (this.saltCache = v);
  }

  private sessionFile(sid: string) {
    return path.join(this.dir, "sessions", `${fileKey(sid)}.json`);
  }

  loadSession(sid: string): Session {
    return this.readJson<Session>(this.sessionFile(sid), {
      nextStep: 1,
      inputSeq: 0,
      token: null,
      runs: [],
      seenCallIds: [],
      history: [],
      buffer: [],
    });
  }

  saveSession(sid: string, s: Session, historyKeep: number): void {
    if (s.history.length > historyKeep) s.history = s.history.slice(-historyKeep);
    if (s.seenCallIds.length > 2000) s.seenCallIds = s.seenCallIds.slice(-2000);
    if (s.runs.length > 2000) s.runs = s.runs.slice(-2000);
    this.writeJson(this.sessionFile(sid), s);
  }

  /** Run `fn` with exclusive access to the session (per process); the callback saves explicitly. */
  async withSession<T>(sid: string, fn: () => Promise<T> | T): Promise<T> {
    const prev = this.locks.get(sid) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const chained = prev.then(() => gate);
    this.locks.set(sid, chained);
    await prev.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
      if (this.locks.get(sid) === chained) this.locks.delete(sid);
    }
  }

  mergeRun(runId: string | undefined, patch: RunContext): void {
    if (!runId) return;
    const file = path.join(this.dir, "runs", `${fileKey(runId)}.json`);
    const cur = this.readJson<RunContext>(file, { runId });
    for (const [k, v] of Object.entries(patch)) if (v !== undefined && v !== null && v !== "") cur[k] = v;
    this.writeJson(file, cur);
  }

  loadRun(runId: string | undefined): RunContext {
    return runId ? this.readJson<RunContext>(path.join(this.dir, "runs", `${fileKey(runId)}.json`), {}) : {};
  }

  saveAssistant(sessionKey: string, value: unknown): void {
    this.writeJson(path.join(this.dir, "assistant", `${fileKey(sessionKey)}.json`), value);
  }

  loadAssistant(sessionKey: string | undefined): any {
    return sessionKey ? this.readJson<any>(path.join(this.dir, "assistant", `${fileKey(sessionKey)}.json`), null) : null;
  }

  /**
   * `grants.json`, empty when absent; null when it exists but cannot be read, so a change never
   * overwrites entries it could not see.
   */
  loadGrants(): GrantsFile | null {
    const file = path.join(this.dir, "grants.json");
    if (!existsSync(file)) return { version: 1, grants: [], bindings: [] };
    const data = this.readJson<unknown>(file, null);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    const g = data as Record<string, unknown>;
    // A key that is present must hold a list (null included): otherwise it is unreadable.
    if (!Object.hasOwn(g, "grants")) g.grants = [];
    if (!Object.hasOwn(g, "bindings")) g.bindings = [];
    return Array.isArray(g.grants) && Array.isArray(g.bindings) ? (g as GrantsFile) : null;
  }

  saveGrants(value: GrantsFile): void {
    this.writeJson(path.join(this.dir, "grants.json"), value);
  }

  /** `snooze.json`, empty when absent; null when it exists but cannot be read. */
  loadSnooze(): SnoozeFile | null {
    const file = path.join(this.dir, "snooze.json");
    if (!existsSync(file)) return { version: 1, snoozes: [] };
    const data = this.readJson<unknown>(file, null);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    const s = data as Record<string, unknown>;
    if (!Object.hasOwn(s, "snoozes")) s.snoozes = [];
    return Array.isArray(s.snoozes) ? (s as SnoozeFile) : null;
  }

  saveSnooze(value: SnoozeFile): void {
    this.writeJson(path.join(this.dir, "snooze.json"), value);
  }

  /** `holds.json`, empty when absent; null when it exists but cannot be read. */
  loadHolds(): HoldsFile | null {
    const file = path.join(this.dir, "holds.json");
    if (!existsSync(file)) return { version: 1, holds: [] };
    const data = this.readJson<unknown>(file, null);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    const h = data as Record<string, unknown>;
    if (!Object.hasOwn(h, "holds")) h.holds = [];
    return Array.isArray(h.holds) ? (h as HoldsFile) : null;
  }

  saveHolds(value: HoldsFile): void {
    this.writeJson(path.join(this.dir, "holds.json"), value);
  }

  /** The owner's notice target from `notify.json`; null when none is set or the file cannot be read. */
  loadNotify(): NotifyTarget | null {
    const data = this.readJson<any>(path.join(this.dir, "notify.json"), null);
    const t = data && typeof data === "object" ? data.target : null;
    return t && typeof t.channel === "string" && t.channel && typeof t.to === "string" && t.to ? (t as NotifyTarget) : null;
  }

  saveNotify(target: NotifyTarget | null): void {
    this.writeJson(path.join(this.dir, "notify.json"), { version: 1, target });
  }

  private selfEditFile(runId: string) {
    return path.join(this.dir, "selfedit", `${fileKey(runId)}.json`);
  }

  /** The conversation a self-editing run read; empty when none was kept. */
  loadConversation(runId: string | undefined): any[] {
    if (!runId) return [];
    const v = this.readJson<unknown>(this.selfEditFile(runId), []);
    return Array.isArray(v) ? v : [];
  }

  /** Replaces the run's conversation with `change(current)`, then drops logs past the retention limits. */
  updateConversation(runId: string, change: (entries: any[]) => any[], now = Date.now()): void {
    this.writeJson(this.selfEditFile(runId), change(this.loadConversation(runId)));
    this.pruneConversations(now);
  }

  /** Drops conversation logs past the retention limits (on every write, and at startup). */
  pruneConversations(now = Date.now()): void {
    const dir = path.join(this.dir, "selfedit");
    let files: Array<{ file: string; mtime: number }>;
    try {
      files = readdirSync(dir)
        .filter((f) => f.endsWith(".json"))
        .map((f) => ({ file: path.join(dir, f), mtime: statSync(path.join(dir, f)).mtimeMs }));
    } catch {
      return;
    }
    files.sort((a, b) => b.mtime - a.mtime);
    const cutoff = now - SELF_EDIT_KEEP_DAYS * 86_400_000;
    files.forEach((f, i) => {
      if (i >= SELF_EDIT_KEEP_RUNS || f.mtime < cutoff) rmSync(f.file, { force: true });
    });
  }

  /** Deletes every kept conversation; true when there were any. */
  deleteConversations(): boolean {
    const dir = path.join(this.dir, "selfedit");
    if (!existsSync(dir)) return false;
    rmSync(dir, { recursive: true, force: true });
    return true;
  }

  setParent(child: string, parent: string): void {
    const file = path.join(this.dir, "subagents.json");
    const m = this.readJson<Record<string, string>>(file, {});
    m[child] = parent;
    this.writeJson(file, m);
  }

  parents(): Record<string, string> {
    return this.readJson<Record<string, string>>(path.join(this.dir, "subagents.json"), {});
  }
}
