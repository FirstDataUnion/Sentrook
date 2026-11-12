/**
 * OpenClaw writers that save memory in host code, with no tool call, so no plugin hook (and no scan) sees them:
 * dreaming and the session-memory hook. `openclaw sentrook verify` names the ones that are on, with the setting that
 * turns each off. Each state is read from the host config the way OpenClaw reads it; where the config leaves it open
 * (or cannot be read) the state is null and verify says nothing rather than guess.
 */

export type WriterState = "on" | "off" | null;

function record(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/** OpenClaw's own reading of a boolean setting: true/false, or the strings "true"/"false" in any case. */
function parseBoolean(v: unknown): boolean | undefined {
  if (typeof v === "boolean") return v;
  if (typeof v !== "string") return undefined;
  const s = v.trim().toLowerCase();
  return s === "true" ? true : s === "false" ? false : undefined;
}

const MEMORY_CORE = "memory-core";

/**
 * Dreaming, memory-core's nightly sweep: on unless `plugins.entries.memory-core.config.dreaming.enabled` is false.
 * Off when memory-core cannot load (plugins off, memory-core disabled or denied, memory slot `none`). Unknown when
 * another plugin holds the memory slot, an allowlist leaves memory-core out, or the cron scheduler is off.
 */
export function dreamingState(hostConfig: unknown): WriterState {
  const cfg = record(hostConfig);
  if (!cfg) return null;
  if (cfg.plugins !== undefined && !record(cfg.plugins)) return null;
  const plugins = record(cfg.plugins) ?? {};
  if (plugins.enabled === false) return "off";
  const slot = record(plugins.slots)?.memory;
  if (typeof slot === "string" && slot.trim()) {
    const id = slot.trim().toLowerCase();
    if (id === "none") return "off";
    if (id !== MEMORY_CORE) return null;
  }
  if (Array.isArray(plugins.deny) && plugins.deny.includes(MEMORY_CORE)) return "off";
  const entry = record(record(plugins.entries)?.[MEMORY_CORE]);
  if (entry?.enabled === false) return "off";
  if (parseBoolean(record(record(entry?.config)?.dreaming)?.enabled) === false) return "off";
  if (Array.isArray(plugins.allow) && plugins.allow.length > 0 && !plugins.allow.includes(MEMORY_CORE)) return null;
  if (record(cfg.cron)?.enabled === false) return null;
  return "on";
}

const SESSION_MEMORY = "session-memory";

/**
 * The bundled session-memory hook, by OpenClaw's selection of internal hooks: off with `hooks.internal.enabled`
 * false or an entry with `enabled: false`; on with an entry that is not disabled, or with open discovery (the master
 * switch true and no named entries, or a load directory). Named entries without it form an allowlist that leaves it
 * out. Hook packs installed with `openclaw hooks install` are not in the config, so a selection they could widen is
 * not claimed either way: a bare config counts as off, as OpenClaw treats it.
 */
export function sessionMemoryHookState(hostConfig: unknown): WriterState {
  const cfg = record(hostConfig);
  if (!cfg) return null;
  if (cfg.hooks !== undefined && !record(cfg.hooks)) return null;
  const internalRaw = record(cfg.hooks)?.internal;
  if (internalRaw !== undefined && !record(internalRaw)) return null;
  const internal = record(internalRaw) ?? {};
  if (internal.enabled === false) return "off";
  const entries = record(internal.entries) ?? {};
  const entry = entries[SESSION_MEMORY];
  if (entry !== undefined) return record(entry)?.enabled === false ? "off" : "on";
  const extraDirs = record(internal.load)?.extraDirs;
  const open =
    (Array.isArray(extraDirs) && extraDirs.some((d) => typeof d === "string" && d.trim().length > 0)) ||
    (internal.enabled === true && Object.keys(entries).every((k) => !k.trim()));
  return open ? "on" : "off";
}

export interface WriterCheck {
  name: string;
  ok: true;
  detail: string;
}

/** The verify lines: dreaming first (its output reaches every later session's system prompt), then the hook. */
export function memoryWriterChecks(hostConfig: unknown): WriterCheck[] {
  const checks: WriterCheck[] = [];
  if (dreamingState(hostConfig) === "on") {
    checks.push({
      name: "dreaming",
      ok: true,
      detail:
        "on, and not scanned: it promotes notes into MEMORY.md, which every later session reads as trusted, and " +
        "notes from fetched pages can reach it. If the agent fetches untrusted content, turn it off: " +
        "openclaw config set plugins.entries.memory-core.config.dreaming.enabled false",
    });
  }
  if (sessionMemoryHookState(hostConfig) === "on") {
    checks.push({
      name: "session-memory hook",
      ok: true,
      detail:
        "on, and not scanned: it saves recent messages to memory/ on /new, /reset and automatic resets. " +
        "To turn it off: openclaw hooks disable session-memory",
    });
  }
  return checks;
}
