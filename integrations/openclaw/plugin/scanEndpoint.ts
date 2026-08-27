/**
 * Scan / feedback / latency base URL + matching Identity issuer.
 *
 * Pinned in code so a compromised agent cannot retarget the scanner via
 * openclaw.json or SENTROOK_SCAN_URL. Runtime config and env are ignored.
 *
 * Self-hosted / *dev* forks: change SCAN_BASE_URL and DEFAULT_OIDC_ISSUER
 * together, rebuild, and publish your plugin.
 */
export const SCAN_BASE_URL = "https://sentrook.firstdataunion.org";
export const DEFAULT_OIDC_ISSUER = "https://identity.firstdataunion.org";
