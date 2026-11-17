// The OpenClaw compatibility check's seam probe: a test-only plugin, installed next to Sentrook, that records
// the shape of the host fields Sentrook reads but OpenClaw does not document as a contract. Sentrook reads them
// defensively, so a field OpenClaw moves would only make it quietly less accurate; here it fails the check.
//
// Each observation is one JSON line in $COMPAT_PROBE_OUT. container_check.sh judges them (the `seams` step).
// COMPAT_PROBE_EXTRA (comma-separated paths on the plugin api) adds fields to require, for the self-test.

import { appendFileSync } from "node:fs";

const OUT = process.env.COMPAT_PROBE_OUT || "/tmp/sentrook-compat-probe.jsonl";

/** Fields on the plugin api Sentrook uses (index.ts, cli.ts). */
const API_FIELDS = [
  "on",
  "registerAgentToolResultMiddleware",
  "registerCli",
  "registerCommand",
  "runtime.version",
  "runtime.config.current",
];

function record(entry) {
  try {
    appendFileSync(OUT, JSON.stringify(entry) + "\n");
  } catch {
    // The check reports a missing record.
  }
}

function shape(v) {
  return v === null ? "null" : Array.isArray(v) ? "array" : typeof v;
}

/** The shape at a dotted path, "throws" when a getter on the way throws (the runtime does outside full mode). */
function shapeAt(root, path) {
  try {
    let v = root;
    for (const key of path.split(".")) v = v?.[key];
    return shape(v);
  } catch {
    return "throws";
  }
}

export default {
  id: "sentrook-compat-probe",
  name: "Sentrook compatibility probe",

  register(api) {
    const mode = api.registrationMode ?? "full";
    const extra = (process.env.COMPAT_PROBE_EXTRA || "").split(",").map((s) => s.trim()).filter(Boolean);
    const fields = {};
    for (const path of [...API_FIELDS, ...extra]) fields[path] = shapeAt(api, path);
    let version;
    let current;
    try {
      version = api.runtime?.version;
    } catch {
      version = undefined;
    }
    try {
      current = shape(api.runtime?.config?.current?.());
    } catch {
      current = "throws";
    }
    record({ at: "register", mode, fields, extra, version: typeof version === "string" ? version : null, current });
    // As Sentrook does: hooks in every mode but cli-metadata.
    if (mode === "cli-metadata") return;

    api.on("before_prompt_build", (event) => {
      const messages = Array.isArray(event?.messages) ? event.messages : [];
      const users = messages.filter((m) => m?.role === "user");
      record({
        at: "before_prompt_build",
        messages: shape(event?.messages),
        users: users.length,
        ownerMarked: users.filter((m) => m?.__openclaw?.senderIsOwner === true).length,
        markerShapes: users.map((m) => shape(m?.__openclaw?.senderIsOwner)),
      });
    });

    // As Sentrook registers its tool-result middleware (index.ts): a host that rejects it would only cap results.
    try {
      api.registerAgentToolResultMiddleware(
        (event) => {
          record({ at: "tool_result_middleware", toolCallId: shape(event?.toolCallId), result: shape(event?.result) });
          return undefined;
        },
        { runtimes: ["openclaw"] },
      );
      record({ at: "middleware_registered", mode, ok: true });
    } catch (err) {
      record({ at: "middleware_registered", mode, ok: false, error: String(err).slice(0, 200) });
    }

    api.on("before_tool_call", (event, ctx) => {
      record({
        at: "before_tool_call",
        toolName: shape(event?.toolName),
        params: shape(event?.params),
        runId: shape(event?.runId ?? ctx?.runId),
        toolCallId: shape(event?.toolCallId),
        session: shape(ctx?.sessionId || ctx?.sessionKey),
      });
    });
  },
};
