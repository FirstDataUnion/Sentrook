/**
 * Read a PlanIR 1.0 JSON document from stdin; write
 * `{ "plan": ..., "sanitizeMs": ... }` to stdout.
 *
 * Used by Sentrook pytest parity tests so scanner fixtures exercise the real
 * OpenClaw plugin sanitize implementation (not a Python reimplementation).
 */

import { sanitizePlanir } from "../sanitize.ts";

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) {
  chunks.push(chunk as Buffer);
}

const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
const result = sanitizePlanir(input);
process.stdout.write(JSON.stringify(result));
