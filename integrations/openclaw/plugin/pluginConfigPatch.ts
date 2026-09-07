/**
 * Best-effort merge into ``plugins.entries.sentrook-openclaw.config``.
 * Used by slash commands that persist sensitivity / log retention.
 * Does not spawn ``openclaw config patch`` (too slow for a chat reply).
 */

import { closeSync, readFileSync } from "node:fs";

import {
  openReadWriteSync,
  openclawConfigPath,
  PLUGIN_ID,
  resolveStateDir,
  writeAllFdSync,
} from "./configure.ts";

export type PluginConfigPatchResult =
  | { ok: true; path: string }
  | { ok: false; error: string };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function mergeOneLevel(
  current: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const next = { ...current };
  for (const [key, value] of Object.entries(patch)) {
    if (isPlainObject(value) && isPlainObject(next[key])) {
      next[key] = { ...(next[key] as Record<string, unknown>), ...value };
    } else {
      next[key] = value;
    }
  }
  return next;
}

export function patchSentrookPluginConfig(
  patch: Record<string, unknown>,
  env: NodeJS.ProcessEnv = process.env,
): PluginConfigPatchResult {
  const stateDir = resolveStateDir(env);
  const cfgPath = openclawConfigPath(stateDir);
  const opened = openReadWriteSync(cfgPath, { create: false });
  if (!opened) {
    return {
      ok: false,
      error: `openclaw.json was not found at ${cfgPath}. Setting applies until gateway restart.`,
    };
  }
  const { fd } = opened;
  try {
    let cfg: Record<string, unknown>;
    try {
      cfg = JSON.parse(readFileSync(fd, "utf8")) as Record<string, unknown>;
    } catch {
      return {
        ok: false,
        error: `${cfgPath} is not strict JSON, so the setting was not saved (live until restart).`,
      };
    }
    const plugins = isPlainObject(cfg.plugins) ? cfg.plugins : {};
    const entries = isPlainObject(plugins.entries) ? plugins.entries : {};
    const prev = isPlainObject(entries[PLUGIN_ID]) ? entries[PLUGIN_ID] : {};
    const prevConfig = isPlainObject(prev.config) ? prev.config : {};
    entries[PLUGIN_ID] = {
      ...prev,
      enabled: prev.enabled !== false,
      config: mergeOneLevel(prevConfig, patch),
    };
    plugins.entries = entries;
    cfg.plugins = plugins;
    writeAllFdSync(fd, `${JSON.stringify(cfg, null, 2)}\n`);
    return { ok: true, path: cfgPath };
  } catch (err) {
    return {
      ok: false,
      error: `Could not write ${cfgPath}: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    closeSync(fd);
  }
}
