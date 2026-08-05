/**
 * CLI helpers for `openclaw sentrook allowlist path|list|clear`.
 */

import { existsSync, unlinkSync } from "node:fs";

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
import { readFileSync } from "node:fs";

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
  const rules = entry.matched_rule_ids.join(", ") || "(none)";
  const lines = [
    `[${index}] ${entry.kind}  tool=${entry.tool}  rules=${rules}`,
    `    created: ${entry.created_at}`,
  ];
  if (entry.kind === "skeleton") {
    lines.push(`    skeleton: ${entry.skeleton}`);
  } else {
    lines.push(`    interpreter: ${entry.interpreter}`);
    lines.push(`    script: ${entry.script_path}`);
    lines.push(`    sha256: ${entry.content_sha256.slice(0, 12)}…`);
    lines.push(
      `    args: ${entry.args_skeleton || "(none)"}`,
    );
  }
  return lines.join("\n");
}

export function formatAllowlistList(path: string): string {
  const file = loadAllowlist(path);
  const header = `Allowlist: ${path}`;
  if (!existsSync(path) || file.entries.length === 0) {
    return `${header}\n(empty — no allow-always entries)`;
  }
  const body = file.entries
    .map((entry, i) => formatAllowlistEntry(entry, i + 1))
    .join("\n\n");
  return `${header}\n${file.entries.length} entr${file.entries.length === 1 ? "y" : "ies"}\n\n${body}`;
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

/** Unused helper kept for tests that want hard-delete semantics. */
export function deleteAllowlistFile(path: string): void {
  if (existsSync(path)) unlinkSync(path);
}
