/**
 * Best-effort OpenClaw host version, used to pick the dashboard's copy.
 *
 * The plugin runs inside the gateway process, so this mirrors the host's own
 * ``resolveRuntimeServiceVersion``: ``OPENCLAW_VERSION`` first, then the
 * resolved ``openclaw`` package, then the service/npm fallbacks. Importing the
 * host SDK to read its exported VERSION would couple the plugin to one host
 * build, which is the opposite of what the tiering is for.
 *
 * Detection is advisory only. An unknown version names both upgrade paths
 * rather than guessing, and nothing here gates a security decision: the native
 * page is authorized by operator scopes, not by this string.
 */

import { createRequire } from "node:module";

/** First OpenClaw release shipping native Control UI plugin pages (#134943). */
export const NATIVE_UI_MIN_VERSION = "2026.9.2";

function nonEmpty(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const lower = trimmed.toLowerCase();
  if (lower === "undefined" || lower === "null" || trimmed === "0.0.0") return undefined;
  return trimmed;
}

function versionFromResolvedPackage(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    const parsed = require("openclaw/package.json") as { name?: string; version?: string };
    if (parsed?.name !== "openclaw") return undefined;
    return nonEmpty(parsed.version);
  } catch {
    return undefined;
  }
}

export function resolveHostVersion(
  env: NodeJS.ProcessEnv = process.env,
  readPackage: () => string | undefined = versionFromResolvedPackage,
): string | undefined {
  return (
    nonEmpty(env.OPENCLAW_VERSION) ??
    readPackage() ??
    nonEmpty(env.OPENCLAW_SERVICE_VERSION) ??
    nonEmpty(env.npm_package_version)
  );
}

/**
 * Compares dotted numeric versions such as ``2026.9.2``. Any pre-release
 * suffix is dropped first, so ``2026.9.2-beta.1`` compares equal to the
 * release: a beta of the version that added the API still has the API.
 */
export function compareVersions(left: string, right: string): number {
  const parts = (value: string): number[] =>
    value
      .split("-")[0]!
      .split(".")
      .map((part) => Number.parseInt(part, 10));
  const a = parts(left);
  const b = parts(right);
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (!Number.isFinite(x) || !Number.isFinite(y)) return Number.NaN;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export type HostUiSupport = "native" | "legacy" | "unknown";

/**
 * ``unknown`` when the version cannot be read or parsed. Callers show copy that
 * names both conditions rather than asserting the wrong one.
 */
export function hostUiSupport(version: string | undefined): HostUiSupport {
  if (!version) return "unknown";
  const cmp = compareVersions(version, NATIVE_UI_MIN_VERSION);
  if (Number.isNaN(cmp)) return "unknown";
  return cmp >= 0 ? "native" : "legacy";
}

export const READ_ONLY_TAB_TITLE = "This panel is read-only";

/** True when Settings → Labs → Custom plugin UI is on. */
export function customPluginUiEnabled(config: unknown): boolean {
  if (!config || typeof config !== "object" || Array.isArray(config)) return false;
  const gateway = (config as { gateway?: unknown }).gateway;
  if (!gateway || typeof gateway !== "object" || Array.isArray(gateway)) return false;
  const controlUi = (gateway as { controlUi?: unknown }).controlUi;
  if (!controlUi || typeof controlUi !== "object" || Array.isArray(controlUi)) return false;
  const experimental = (controlUi as { experimental?: unknown }).experimental;
  if (!experimental || typeof experimental !== "object" || Array.isArray(experimental)) return false;
  return (experimental as { customPlugins?: unknown }).customPlugins === true;
}

/** Native plugin pages are blocked on plain LAN HTTP. */
export const NATIVE_PAGE_ORIGIN_HINT =
  "The native page needs HTTPS or loopback (http://127.0.0.1), not plain LAN HTTP.";

/**
 * Copy for the iframe tab and the standalone ``/sentrook`` page. Neither can
 * save: the host's frame grant is GET/HEAD with ``operator.read``, and this
 * HTML is the same read-only view in a normal browser tab.
 */
export function readOnlyTabMessage(support: HostUiSupport, version?: string): string {
  const chat = "You can still change everything with /sentrook in chat or the sentrook CLI.";
  const thisPage = "This /sentrook page cannot save.";
  const openNative =
    "then open Control UI and choose Sentrook in the sidebar — not this /sentrook page, and not Sentrook (read-only).";
  if (support === "native") {
    return (
      `${thisPage} OpenClaw ${version ?? NATIVE_UI_MIN_VERSION} can run the full Sentrook dashboard. ` +
      `Enable Settings \u2192 Labs \u2192 Custom plugin UI, restart the gateway, ${openNative} ` +
      `${NATIVE_PAGE_ORIGIN_HINT} ${chat}`
    );
  }
  if (support === "legacy") {
    return (
      `${thisPage} This gateway runs OpenClaw ${version}. The editable dashboard needs ${NATIVE_UI_MIN_VERSION} ` +
      `or later, then Settings \u2192 Labs \u2192 Custom plugin UI. ${NATIVE_PAGE_ORIGIN_HINT} ${chat}`
    );
  }
  return (
    `${thisPage} The editable dashboard needs OpenClaw ${NATIVE_UI_MIN_VERSION} or later with ` +
    `Settings \u2192 Labs \u2192 Custom plugin UI enabled. ${NATIVE_PAGE_ORIGIN_HINT} ${chat}`
  );
}
