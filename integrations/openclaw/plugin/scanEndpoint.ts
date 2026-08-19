/**
 * Scan / feedback / latency base URL.
 *
 * Pinned in code so a compromised agent cannot retarget the scanner via
 * openclaw.json or SENTROOK_SCAN_URL. Runtime config and env are ignored.
 *
 * Self-hosted forks: change SCAN_BASE_URL to your Sentrook origin, rebuild,
 * and publish your plugin.
 */
export const SCAN_BASE_URL = "https://sentrook.firstdataunion.org";
