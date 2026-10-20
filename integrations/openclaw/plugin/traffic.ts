/**
 * Local traffic log: one JSON line per scan (the redacted PlanIR as sent and the response or
 * failure) and one per review resolution, joined by `request_id`. Collected from day one so beta
 * traffic can be studied; nothing here is sent anywhere by the plugin.
 *
 * The file is created 0600 and rotated to `<path>.1` past `maxBytes`.
 */

import { appendFileSync, mkdirSync, renameSync, statSync } from "node:fs";
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
      appendFileSync(this.file, `${JSON.stringify({ ts: new Date().toISOString(), ...record })}\n`, { mode: 0o600 });
    } catch (err) {
      this.onError(`traffic log write failed: ${String(err)}`);
    }
  }
}
