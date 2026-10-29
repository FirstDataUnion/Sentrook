/**
 * File-backed plugin state under `<state>/sentrook/`, so episodes survive gateway restarts.
 *
 * - `sessions/<sid>.json`: step counter, input sequence, state token, history, input buffer
 * - `runs/<runId>.json`: run context joined from agent hooks (trigger, request, sender facts)
 * - `assistant/<sessionKey>.json`: the latest assistant message (narration and sibling calls)
 * - `subagents.json`: child session key → parent session key
 * - `grants.json`: grants and channel bindings set by command (see `grants.ts`)
 * - `salt`: per-install key for placeholder refs and hashed ids
 *
 * Writes are atomic (temp file then rename). Read-modify-write of a session goes through
 * `withSession`, which serialises callers per session in this process.
 */

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

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
    const g = data as GrantsFile;
    g.grants ??= [];
    g.bindings ??= [];
    return Array.isArray(g.grants) && Array.isArray(g.bindings) ? g : null;
  }

  saveGrants(value: GrantsFile): void {
    this.writeJson(path.join(this.dir, "grants.json"), value);
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
