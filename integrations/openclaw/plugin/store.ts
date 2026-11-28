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
  existsSync,
  linkSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

/** How long to wait for another process's lock before giving up. Short: the gateway waits on it. */
export const LOCK_WAIT_MS = 1_000;

/** Another process held a state file's lock for longer than `LOCK_WAIT_MS`. */
export class LockTimeoutError extends Error {}

/**
 * Runs `fn` holding an exclusive lock for `file`, so a read-modify-write of it is safe across processes (the gateway
 * and the `openclaw sentrook` command line) as well as within one. The lock is an exclusive transaction on a small
 * SQLite file beside it (`<file>.lockdb`, through Node's own `node:sqlite`, which OpenClaw itself uses): SQLite
 * takes the operating system's file lock, and the system releases it when its process dies, so a crashed holder
 * leaves nothing to take over and no two processes ever hold it at once. Throws `LockTimeoutError` when another
 * process holds it for longer than `LOCK_WAIT_MS`. The write inside stays atomic (temp file, then rename).
 */
export function withFileLock<T>(file: string, fn: () => T): T {
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(`${file}.lockdb`, { timeout: LOCK_WAIT_MS });
  try {
    try {
      db.exec("BEGIN EXCLUSIVE");
    } catch (err: any) {
      if (/locked|busy/i.test(String(err?.message ?? err))) throw new LockTimeoutError(`${file} is locked by another process`);
      throw err;
    }
    try {
      return fn();
    } finally {
      db.exec("ROLLBACK");
    }
  } finally {
    db.close();
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
  /** Plugin-only: the skill a background patch sent to the drafts changes; stripped before sending. */
  _patch_skill?: string;
}

export interface BufferedInput {
  /** The folder grant whose manifest vouched for this read (`folders.attest`): sent as `trusted_by`, never as is. */
  _trusted_grant?: string;
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
  /** Actions this session's owner was asked about with a snooze's strong warning (snooze.noteAsked). */
  snoozeAsked?: string[];
}

export type RunContext = Record<string, any>;

/**
 * A cron run as the plugin keeps it for a session: the job OpenClaw's run metadata named and the cron run's own agent
 * run id (its run key and start are read from it as the run's own calls read them). `via`: `cron` on the run's own
 * session, `subagent` on a sub-agent's session that took it from its parent at spawn.
 */
export interface JobRunLink {
  job_id: string;
  run_id: string;
  via: "cron" | "subagent";
}

/** The session links `jobruns.json` keeps, newest last. */
const JOB_RUN_LINKS = 500;
/** Group rooms whose server `servers.json` keeps (trust.ts), newest last. */
const SERVER_ROOMS = 1000;

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

export interface TrustFile {
  version?: number;
  trusted_chats: unknown[];
  trusted_senders: unknown[];
  [key: string]: unknown;
}

export interface ProposalsFile {
  version: number;
  proposals: unknown[];
  [k: string]: unknown;
}

export interface HoldsFile {
  version?: number;
  holds: unknown[];
  [key: string]: unknown;
}

export interface PassesFile {
  version?: number;
  passes: unknown[];
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

/**
 * One queue per session in this process, shared by every `Store` of the same directory: a scan holds it for the whole
 * scan, and an answer to a held call takes it to set the held call's history (hold.ts), so neither overwrites the
 * other's copy of the session.
 */
const SESSION_LOCKS = new Map<string, Promise<unknown>>();

export class Store {
  readonly dir: string;
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

  /**
   * The per-install salt, created on first use. Every process sharing the state dir (the gateway and the
   * `openclaw sentrook` command line) must get the same one, so a new salt is written whole to a temp file and
   * hard-linked into place: the link fails with `EEXIST` when another process got there first, and that
   * process's salt is read instead. No one ever reads a half-written salt. Two cases fall back to renaming
   * the temp file into place while holding the file's cross-process lock (`withFileLock`): an empty salt file
   * (which older versions could leave after a crash), and a filesystem without hard links. Under the lock the
   * first process to get it writes the salt and the rest read it.
   */
  salt(): string {
    if (this.saltCache) return this.saltCache;
    const file = path.join(this.dir, "salt");
    const existing = this.readSalt(file);
    if (existing) return (this.saltCache = existing);
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    try {
      writeFileSync(tmp, randomBytes(32).toString("hex"), { mode: 0o600 });
      try {
        chmodSync(tmp, 0o600);
      } catch {
        // best effort
      }
      try {
        linkSync(tmp, file);
      } catch (err: any) {
        if (err?.code !== "EEXIST" || !this.readSalt(file)) {
          withFileLock(file, () => {
            if (!this.readSalt(file)) renameSync(tmp, file);
          });
        }
      }
    } finally {
      rmSync(tmp, { force: true });
    }
    const v = this.readSalt(file);
    if (!v) throw new Error(`could not create ${file}`);
    return (this.saltCache = v);
  }

  private readSalt(file: string): string {
    try {
      return readFileSync(file, "utf8").trim();
    } catch (err: any) {
      if (err?.code === "ENOENT") return "";
      throw err;
    }
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
    const key = `${this.dir}\u0000${sid}`;
    const prev = SESSION_LOCKS.get(key) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const chained = prev.then(() => gate);
    SESSION_LOCKS.set(key, chained);
    await prev.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
      if (SESSION_LOCKS.get(key) === chained) SESSION_LOCKS.delete(key);
    }
  }

  mergeRun(runId: string | undefined, patch: RunContext): void {
    if (!runId) return;
    const file = path.join(this.dir, "runs", `${fileKey(runId)}.json`);
    const cur = this.readJson<RunContext>(file, { runId });
    // When the plugin first heard of the run: its first hook, before any of its tool calls.
    if (typeof cur.seenAtMs !== "number") cur.seenAtMs = Date.now();
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

  /**
   * `trust.json`, the trusted chats and users the owner set by command (trust.ts), empty when absent; null when it
   * exists but cannot be read.
   */
  loadTrust(): TrustFile | null {
    const file = path.join(this.dir, "trust.json");
    if (!existsSync(file)) return { version: 1, trusted_chats: [], trusted_senders: [] };
    const data = this.readJson<unknown>(file, null);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    const t = data as Record<string, unknown>;
    for (const k of ["trusted_chats", "trusted_senders"]) {
      if (!Object.hasOwn(t, k)) t[k] = [];
      if (!Array.isArray(t[k])) return null;
    }
    return t as TrustFile;
  }

  saveTrust(value: TrustFile): void {
    this.writeJson(path.join(this.dir, "trust.json"), value);
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

  /** `passes.json` (passes.ts), empty when absent; null when it exists but cannot be read. */
  loadPasses(): PassesFile | null {
    const file = path.join(this.dir, "passes.json");
    if (!existsSync(file)) return { version: 1, passes: [] };
    const data = this.readJson<unknown>(file, null);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    const p = data as Record<string, unknown>;
    if (!Object.hasOwn(p, "passes")) p.passes = [];
    return Array.isArray(p.passes) ? (p as PassesFile) : null;
  }

  savePasses(value: PassesFile): void {
    this.writeJson(path.join(this.dir, "passes.json"), value);
  }

  /** `always-allows.json` (alwaysAllow.ts), empty when absent; null when it exists but cannot be read. */
  loadAlwaysAllows(): Record<string, any> | null {
    const file = path.join(this.dir, "always-allows.json");
    if (!existsSync(file)) return { version: 1, allows: [] };
    const data = this.readJson<unknown>(file, null);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    const a = data as Record<string, unknown>;
    if (!Object.hasOwn(a, "allows")) a.allows = [];
    return Array.isArray(a.allows) ? (a as Record<string, any>) : null;
  }

  saveAlwaysAllows(value: Record<string, any>): void {
    this.writeJson(path.join(this.dir, "always-allows.json"), value);
  }

  /** `proposals.json` (the agent's setup proposals), empty when absent; null when it cannot be read. */
  loadProposals(): ProposalsFile | null {
    const file = path.join(this.dir, "proposals.json");
    if (!existsSync(file)) return { version: 1, proposals: [] };
    const data = this.readJson<unknown>(file, null);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    const p = data as Record<string, unknown>;
    if (!Object.hasOwn(p, "proposals")) p.proposals = [];
    return Array.isArray(p.proposals) ? (p as ProposalsFile) : null;
  }

  saveProposals(value: ProposalsFile): void {
    this.writeJson(path.join(this.dir, "proposals.json"), value);
  }

  /** `setup.json`: the setup screen last shown, its code and items; empty when absent or unreadable. */
  loadSetup(): Record<string, any> {
    const data = this.readJson<unknown>(path.join(this.dir, "setup.json"), null);
    return data && typeof data === "object" && !Array.isArray(data) ? (data as Record<string, any>) : {};
  }

  saveSetup(value: unknown): void {
    this.writeJson(path.join(this.dir, "setup.json"), value);
  }

  /** When each job or session last had a scan-failure notice (`scan-failure-notices.json`); empty when unreadable. */
  loadScanFailureNotices(): Record<string, unknown> {
    const data = this.readJson<any>(path.join(this.dir, "scan-failure-notices.json"), null);
    const sent = data && typeof data === "object" ? data.sent : null;
    return sent && typeof sent === "object" && !Array.isArray(sent) ? sent : {};
  }

  saveScanFailureNotices(sent: Record<string, string>): void {
    this.writeJson(path.join(this.dir, "scan-failure-notices.json"), { version: 1, sent });
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

  /**
   * The plugin's own agent tools another plugin's tool of the same name ran in place of, and when
   * (`foreign-tools.json`, by tool name). A `report-tool.json` from an earlier beta still counts for the setup report.
   */
  loadForeignTools(): Record<string, string> {
    const data = this.readJson<any>(path.join(this.dir, "foreign-tools.json"), null);
    const tools = data && typeof data === "object" && data.tools && typeof data.tools === "object" ? data.tools : {};
    const out = Object.fromEntries(Object.entries(tools).filter((e): e is [string, string] => typeof e[1] === "string"));
    const old = this.readJson<any>(path.join(this.dir, "report-tool.json"), null);
    if (old && typeof old === "object" && typeof old.foreign_at === "string") out.sentrook_setup_report ??= old.foreign_at;
    return out;
  }

  saveForeignTool(tool: string, at: Date): void {
    const tools = { ...this.loadForeignTools(), [tool]: at.toISOString() };
    this.writeJson(path.join(this.dir, "foreign-tools.json"), { version: 1, tools });
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

  /**
   * Keeps the server OpenClaw named for a group room (`platform:room id` -> a Discord guild id) and when one was last
   * seen, for trusted servers (trust.ts). A room's server never changes; the oldest rooms go past `SERVER_ROOMS`.
   */
  noteServer(room: string, server: string, now = new Date()): void {
    const file = path.join(this.dir, "servers.json");
    withFileLock(file, () => {
      const cur = this.readJson<Record<string, any>>(file, {});
      const rooms: Record<string, string> =
        cur.rooms && typeof cur.rooms === "object" && !Array.isArray(cur.rooms) ? cur.rooms : {};
      const seen = `${now.toISOString().slice(0, 19)}Z`;
      if (rooms[room] === server && typeof cur.seen_at === "string" && cur.seen_at.slice(0, 13) === seen.slice(0, 13)) return;
      delete rooms[room];
      rooms[room] = server;
      const keys = Object.keys(rooms);
      for (const k of keys.slice(0, Math.max(0, keys.length - SERVER_ROOMS))) delete rooms[k];
      this.writeJson(file, { version: 1, rooms, seen_at: seen });
    });
  }

  /** The server OpenClaw named for a group room (`noteServer`), or null. */
  serverOf(room: string): string | null {
    const cur = this.readJson<Record<string, any>>(path.join(this.dir, "servers.json"), {});
    const rooms = cur.rooms && typeof cur.rooms === "object" && !Array.isArray(cur.rooms) ? cur.rooms : {};
    const v = Object.hasOwn(rooms, room) ? rooms[room] : null;
    return typeof v === "string" && v ? v : null;
  }

  /** When OpenClaw last named a room's server (`noteServer`), or null when it never has. */
  serverSeenAt(): string | null {
    const cur = this.readJson<Record<string, any>>(path.join(this.dir, "servers.json"), {});
    return typeof cur.seen_at === "string" ? cur.seen_at : null;
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

  /**
   * The cron run a session serves now, or the one a sub-agent's session belongs to (`JobRunLink`), by session key;
   * null when none.
   */
  jobRunOf(sessionKey: unknown): JobRunLink | null {
    if (typeof sessionKey !== "string" || !sessionKey) return null;
    const m = this.readJson<Record<string, JobRunLink>>(path.join(this.dir, "jobruns.json"), {});
    const rec = Object.hasOwn(m, sessionKey) ? m[sessionKey] : undefined;
    return rec && typeof rec === "object" && typeof rec.job_id === "string" && rec.job_id && typeof rec.run_id === "string" && rec.run_id
      ? rec
      : null;
  }

  /** Sets (or with null, drops) a session's cron run link; the oldest go past `JOB_RUN_LINKS`. */
  setJobRun(sessionKey: string, link: JobRunLink | null): void {
    const file = path.join(this.dir, "jobruns.json");
    withFileLock(file, () => {
      const m = this.readJson<Record<string, JobRunLink>>(file, {});
      if (link === null && !Object.hasOwn(m, sessionKey)) return;
      delete m[sessionKey];
      if (link) m[sessionKey] = link;
      const keys = Object.keys(m);
      for (const k of keys.slice(0, Math.max(0, keys.length - JOB_RUN_LINKS))) delete m[k];
      this.writeJson(file, m);
    });
  }
}
