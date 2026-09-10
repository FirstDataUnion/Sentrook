/**
 * CLI helpers for `openclaw sentrook allowlist path|list|add|clear`.
 */

import { existsSync, readFileSync, unlinkSync } from "node:fs";

import {
  openclawConfigPath,
  resolveStateDir,
  PLUGIN_ID,
} from "./configure.ts";
import {
  type AllowlistEntry,
  loadAllowlist,
  resolveAllowlistConfig,
  saveAllowlist,
} from "./localAllowlist.ts";
import { addAllowlistFromHistory } from "./allowlistFromLog.ts";
import { resolveOperatorLogConfig } from "./operatorLog.ts";
import { ruleMeanings } from "./dashboardPresent.ts";

export interface AllowlistCliOptions {
  path?: string;
  stateDir?: string;
  yes?: boolean;
}

function readPluginAllowlistConfig(
  stateDir: string,
): Record<string, unknown> | undefined {
  const cfgPath = openclawConfigPath(stateDir);
  if (!existsSync(cfgPath)) return undefined;
  try {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as {
      plugins?: {
        entries?: Record<string, { config?: Record<string, unknown> }>;
      };
    };
    const pluginCfg = cfg.plugins?.entries?.[PLUGIN_ID]?.config;
    return pluginCfg && typeof pluginCfg === "object" ? pluginCfg : undefined;
  } catch {
    return undefined;
  }
}

/** Resolve the allowlist file path the same way the live plugin does. */
export function resolveAllowlistCliPath(opts: AllowlistCliOptions = {}): string {
  if (opts.path?.trim()) {
    return resolveAllowlistConfig({ allowlist: { path: opts.path.trim() } }, process.env)
      .path;
  }
  const stateDir = opts.stateDir?.trim() || resolveStateDir();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    OPENCLAW_STATE_DIR: stateDir,
  };
  const pluginCfg = readPluginAllowlistConfig(stateDir);
  return resolveAllowlistConfig(pluginCfg, env).path;
}

export function formatAllowlistEntry(entry: AllowlistEntry, index: number): string {
  const meanings = ruleMeanings(entry.matched_rule_ids);
  const kind = entry.kind === "skeleton" ? "command" : entry.kind === "script_bind" ? "script" : entry.kind;
  const why = meanings.length ? `  ${meanings.join("; ")}` : "";
  const lines = [
    `[${index}] ${kind}  tool=${entry.tool}${why}`,
    `    created   ${entry.created_at}`,
  ];
  if (entry.kind === "skeleton") {
    lines.push(`    match     ${entry.skeleton}`);
  } else {
    lines.push(`    interpreter  ${entry.interpreter}`);
    lines.push(`    file         ${entry.script_path}`);
    lines.push(`    sha256       ${entry.content_sha256.slice(0, 12)}…`);
    lines.push(`    args         ${entry.args_skeleton || "(none)"}`);
  }
  return lines.join("\n");
}

export function formatAllowlistList(path: string): string {
  const file = loadAllowlist(path);
  if (!existsSync(path) || file.entries.length === 0) {
    return `Allowlist\n  ${path}\n  empty — no allow-always entries\n  Add one: /sentrook allowlist add <id>   (id from /sentrook history)`;
  }
  const body = file.entries
    .map((entry, i) => formatAllowlistEntry(entry, i + 1))
    .join("\n\n");
  const count = `${file.entries.length} entr${file.entries.length === 1 ? "y" : "ies"}`;
  return `Allowlist\n  ${path}\n  ${count}\n\n${body}`;
}

export function clearAllowlistFile(path: string): { cleared: number; path: string } {
  const before = loadAllowlist(path).entries.length;
  if (existsSync(path)) {
    // Prefer rewriting to empty versioned file so path stays stable / discoverable.
    saveAllowlist(path, { version: 1, entries: [] });
  }
  return { cleared: before, path };
}

export function runAllowlistPath(opts: AllowlistCliOptions = {}): string {
  return resolveAllowlistCliPath(opts);
}

export function runAllowlistList(opts: AllowlistCliOptions = {}): string {
  return formatAllowlistList(resolveAllowlistCliPath(opts));
}

export function runAllowlistClear(opts: AllowlistCliOptions = {}): string {
  if (!opts.yes) {
    throw new Error(
      "Refusing to clear without --yes (non-interactive safety). Re-run with --yes.",
    );
  }
  const path = resolveAllowlistCliPath(opts);
  const { cleared } = clearAllowlistFile(path);
  if (cleared === 0 && !existsSync(path)) {
    return `Allowlist already empty (no file at ${path})`;
  }
  return `Cleared ${cleared} entr${cleared === 1 ? "y" : "ies"} from ${path}`;
}

export function runAllowlistAdd(id: string, opts: AllowlistCliOptions = {}) {
  const path = resolveAllowlistCliPath(opts);
  const stateDir = opts.stateDir?.trim() || resolveStateDir();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    OPENCLAW_STATE_DIR: stateDir,
  };
  const pluginCfg = readPluginAllowlistConfig(stateDir);
  const allowlist = resolveAllowlistConfig(
    { ...(pluginCfg ?? {}), allowlist: { ...(asAllowlist(pluginCfg?.allowlist)), path } },
    env,
  );
  const log = resolveOperatorLogConfig(env, pluginCfg);
  return addAllowlistFromHistory(log, allowlist, id);
}

function asAllowlist(raw: unknown): Record<string, unknown> {
  return raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
}

/** Unused helper kept for tests that want hard-delete semantics. */
export function deleteAllowlistFile(path: string): void {
  if (existsSync(path)) unlinkSync(path);
}
