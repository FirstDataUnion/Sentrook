/**
 * Local traffic log: one JSON line per scan (the redacted PlanIR as sent and the response or
 * failure) and one per review resolution, joined by `request_id`. Collected from day one so beta
 * traffic can be studied; nothing here is sent anywhere by the plugin.
 *
 * The file is created 0600 and rotated to `<path>.1` past `maxBytes`. A write cut off mid-line (a
 * crash, a full disk) leaves the file without a final newline; the next record then starts with one,
 * so it lands on its own line.
 */

import { closeSync, fstatSync, mkdirSync, openSync, readSync, renameSync, statSync, writeSync } from "node:fs";
import path from "node:path";

export class TrafficLog {
  private readonly file: string;
  private readonly maxBytes: number;
  private readonly enabled: boolean;
  private readonly onError: (msg: string) => void;

  constructor(file: string, maxBytes: number, enabled: boolean, onError: (msg: string) => void = () => undefined) {
    this.file = file;
    this.maxBytes = maxBytes;
    this.enabled = enabled;
    this.onError = onError;
  }

  write(record: Record<string, unknown>): void {
    if (!this.enabled) return;
    try {
      mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
      try {
        if (statSync(this.file).size > this.maxBytes) renameSync(this.file, `${this.file}.1`);
      } catch {
        // no file yet
      }
      const fd = openSync(this.file, "a+", 0o600);
      try {
        const lead = torn(fd) ? "\n" : "";
        const buf = Buffer.from(`${lead}${JSON.stringify({ ts: new Date().toISOString(), ...record })}\n`);
        // Like appendFileSync: keep writing after a short write, so a full disk ends in an error.
        for (let off = 0; off < buf.length; ) off += writeSync(fd, buf, off);
      } finally {
        closeSync(fd);
      }
    } catch (err) {
      this.onError(`traffic log write failed: ${String(err)}`);
    }
  }
}

/** True when the file is non-empty and does not end with a newline. */
function torn(fd: number): boolean {
  const size = fstatSync(fd).size;
  if (size === 0) return false;
  const last = Buffer.alloc(1);
  readSync(fd, last, 0, 1, size - 1);
  return last[0] !== 0x0a;
}
