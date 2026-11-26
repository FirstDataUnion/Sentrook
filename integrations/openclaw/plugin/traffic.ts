/**
 * Local traffic log: one JSON line per scan (the redacted PlanIR as sent and the response or
 * failure) and one per review resolution, joined by `request_id`. Collected from day one so beta
 * traffic can be studied; nothing here is sent anywhere by the plugin.
 *
 * The file is created 0600 and rotated to `<path>.1` past `maxBytes`. A write cut off mid-line (a
 * crash, a full disk) leaves the file without a final newline; the next record then starts with one,
 * so it lands on its own line.
 *
 * Records are kept for 30 days. A write prunes the log and its rotated file (at most once an hour per
 * process and log): a file holding only older records is deleted, and one that straddles the boundary
 * is rewritten without them, atomically. A line's age is the `ts` it starts with (a cut-off line keeps
 * its `ts` when the cut came after it); a line without one goes with the dated line before it (or, at
 * the top of the file, the first dated line after it). A file with no dated line is left alone. Most of
 * the time the first line is inside the window and only the start of each file is read.
 */

import {
  closeSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import path from "node:path";

/** Records older than this are deleted from the log and its rotated file. */
export const RETENTION_MS = 30 * 24 * 3600 * 1000;
/** A process prunes a given log at most this often (its first write always prunes). */
export const PRUNE_INTERVAL_MS = 3600 * 1000;
/** How much of a file is read to see whether its first record is still inside the window. */
const HEAD_BYTES = 64 * 1024;

const TS = /^\{"ts":\s*"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})"/;
const NL = 0x0a;

const lastPrune = new Map<string, number>();
let retentionMs = RETENTION_MS;

/** For tests that replay a fixture log recorded on a fixed date: keep every record whatever today's date is. */
export function keepAllRecordsForTests(on: boolean): void {
  retentionMs = on ? Number.POSITIVE_INFINITY : RETENTION_MS;
}

export class TrafficLog {
  private readonly file: string;
  private readonly maxBytes: number;
  private readonly enabled: boolean;
  private readonly onError: (msg: string) => void;
  private readonly now: () => Date;

  constructor(
    file: string,
    maxBytes: number,
    enabled: boolean,
    onError: (msg: string) => void = () => undefined,
    now: () => Date = () => new Date(),
  ) {
    this.file = file;
    this.maxBytes = maxBytes;
    this.enabled = enabled;
    this.onError = onError;
    this.now = now;
  }

  write(record: Record<string, unknown>): void {
    if (!this.enabled) return;
    const now = this.now();
    try {
      mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
      try {
        if (statSync(this.file).size > this.maxBytes) renameSync(this.file, `${this.file}.1`);
      } catch {
        // no file yet
      }
      this.maybePrune(now.getTime());
      const fd = openSync(this.file, "a+", 0o600);
      try {
        const lead = torn(fd) ? "\n" : "";
        const buf = Buffer.from(`${lead}${JSON.stringify({ ts: now.toISOString(), ...record })}\n`);
        // Like appendFileSync: keep writing after a short write, so a full disk ends in an error.
        for (let off = 0; off < buf.length; ) off += writeSync(fd, buf, off);
      } finally {
        closeSync(fd);
      }
    } catch (err) {
      this.onError(`traffic log write failed: ${String(err)}`);
    }
  }

  private maybePrune(now: number): void {
    const last = lastPrune.get(this.file);
    if (last !== undefined && now - last >= 0 && now - last < PRUNE_INTERVAL_MS) return;
    lastPrune.set(this.file, now);
    prune(this.file, now - retentionMs, this.onError);
  }
}

/** Drop the records older than `cutoff` (epoch ms) from the log at `file` and its rotated file. */
export function prune(file: string, cutoff: number, onError: (msg: string) => void = () => undefined): void {
  for (const target of [file, `${file}.1`]) {
    try {
      pruneFile(target, cutoff);
    } catch (err) {
      onError(`traffic log prune failed for ${target}: ${String(err)}`);
    }
  }
}

function pruneFile(file: string, cutoff: number): void {
  let fd: number;
  try {
    fd = openSync(file, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  let data: Buffer;
  try {
    const head = Buffer.alloc(HEAD_BYTES);
    const n = readSync(fd, head, 0, HEAD_BYTES, 0);
    for (const line of splitLines(head.subarray(0, n))) {
      const ts = lineTs(line);
      if (ts === undefined) continue;
      if (ts >= cutoff) return; // the first record is inside the window
      break;
    }
    data = readFileSync(fd); // the whole file: the read above did not move the file position
  } finally {
    closeSync(fd);
  }
  const keep = kept(data, cutoff);
  if (keep === undefined || keep.equals(data)) return;
  const tmp = `${file}.prune.tmp`;
  try {
    const out = openSync(tmp, "w", 0o600);
    let written = 0;
    try {
      for (let off = 0; off < keep.length; ) off += writeSync(out, keep, off);
      // Another process may have appended since the read: carry its bytes over.
      const extra = readFileSync(file).subarray(data.length);
      for (let off = 0; off < extra.length; ) off += writeSync(out, extra, off);
      written = keep.length + extra.length;
    } finally {
      closeSync(out);
    }
    if (written === 0) {
      unlinkSync(file);
      unlinkSync(tmp);
    } else {
      renameSync(tmp, file);
    }
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // already gone
    }
    throw err;
  }
}

/** Split on "\n": every element but the last ended with a newline; the last is empty or a cut-off line. */
function splitLines(buf: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  let start = 0;
  for (let i = buf.indexOf(NL); i !== -1; i = buf.indexOf(NL, start)) {
    parts.push(buf.subarray(start, i));
    start = i + 1;
  }
  parts.push(buf.subarray(start));
  return parts;
}

/** The bytes of `data` without its lines older than `cutoff`; undefined when no line is dated. */
function kept(data: Buffer, cutoff: number): Buffer | undefined {
  const parts = splitLines(data);
  const stamps = parts.map(lineTs);
  let current = stamps.find((t) => t !== undefined);
  if (current === undefined) return undefined;
  const out: Buffer[] = [];
  parts.forEach((part, i) => {
    current = stamps[i] ?? current;
    if ((current as number) >= cutoff) {
      out.push(part);
      if (i < parts.length - 1) out.push(Buffer.from([NL]));
    }
  });
  return Buffer.concat(out);
}

function lineTs(line: Buffer): number | undefined {
  const m = TS.exec(line.subarray(0, 64).toString("latin1"));
  if (!m) return undefined;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  const frac = m[7] ? Number(`0.${m[7]}`) : 0;
  const zone = m[8];
  const offset =
    zone === "Z" ? 0 : (zone[0] === "+" ? 1 : -1) * (Number(zone.slice(1, 3)) * 3600 + Number(zone.slice(4, 6)) * 60);
  return Date.UTC(y, mo - 1, d, h, mi, s) + frac * 1000 - offset * 1000;
}

/** True when the file is non-empty and does not end with a newline. */
function torn(fd: number): boolean {
  const size = fstatSync(fd).size;
  if (size === 0) return false;
  const last = Buffer.alloc(1);
  readSync(fd, last, 0, 1, size - 1);
  return last[0] !== NL;
}
