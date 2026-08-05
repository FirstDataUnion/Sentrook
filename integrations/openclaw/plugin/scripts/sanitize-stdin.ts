/**
 * Read a sentrook.shadow.snapshot/v1 JSON document from stdin; write
 * `{ "snapshot": ..., "sanitizeMs": ... }` to stdout.
 *
 * Used by Sentrook pytest parity tests so scanner fixtures exercise the real
 * OpenClaw plugin sanitize implementation (not a Python reimplementation).
 */

import { sanitizeSnapshot } from "../sanitize.ts";

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) {
  chunks.push(chunk as Buffer);
}

const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const result = sanitizeSnapshot(input);
process.stdout.write(JSON.stringify(result));
