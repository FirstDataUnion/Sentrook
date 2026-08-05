#!/usr/bin/env bash
# Remove the Sentrook OpenClaw plugin (config + managed install). Does not restart the gateway.
#
# Usage:
#   OPENCLAW_DIR=~/openclaw ./uninstall-plugin.sh
#   PURGE=1 OPENCLAW_DIR=~/openclaw ./uninstall-plugin.sh   # also drop .env scan keys + stale patches
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/sentrook-scan-auth.sh
source "${SCRIPT_DIR}/lib/sentrook-scan-auth.sh"
openclaw_common_init "${SCRIPT_DIR}"

require_openclaw_dir

PLUGIN_ID="sentrook-shadow"
OPENCLAW_CONFIG="${OPENCLAW_CONFIG:-${OPENCLAW_STATE_DIR}/openclaw.json}"
PURGE="${PURGE:-0}"
LEGACY_PLUGIN_HOST_DIR="${OPENCLAW_STATE_DIR}/sentrook-shadow-plugin"

remove_plugin_config_via_gateway() {
  local patch_file remove_path openclaw_home
  patch_file="$(mktemp)"
  trap 'rm -f "${patch_file}"' RETURN
  openclaw_home="$(gateway_openclaw_home)"
  remove_path="${openclaw_home}/sentrook-shadow.remove.patch.json5"

  cat > "${patch_file}" <<EOF
{
  plugins: {
    entries: {
      "${PLUGIN_ID}": null
    }
  }
}
EOF

  echo "==> Removing plugin config entry from openclaw.json"
  gateway_write_file "${remove_path}" "${patch_file}"
  if gateway_run_openclaw config patch --file "${remove_path}"; then
    gateway_run_openclaw config validate || true
    gateway_exec_root rm -f "${remove_path}" 2>/dev/null || true
    return 0
  fi
  echo "warning: config patch removal failed — try manual edit of ${OPENCLAW_CONFIG}" >&2
  return 1
}

remove_plugin_config_on_host() {
  if [[ ! -f "${OPENCLAW_CONFIG}" ]]; then
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "warning: python3 not available — inspect ${OPENCLAW_CONFIG} for plugins.entries.${PLUGIN_ID}" >&2
    return 1
  fi
  python3 - "${OPENCLAW_CONFIG}" "${PLUGIN_ID}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
plugin_id = sys.argv[2]
raw = path.read_text(encoding="utf-8")
try:
    cfg = json.loads(raw)
except json.JSONDecodeError:
    print(f"warning: {path} is not strict JSON — remove plugins.entries.{plugin_id} manually", file=sys.stderr)
    raise SystemExit(1)

plugins = cfg.setdefault("plugins", {})
entries = plugins.setdefault("entries", {})
if plugin_id not in entries:
    print(f"    no plugins.entries.{plugin_id} in {path}")
    raise SystemExit(0)

del entries[plugin_id]
if not entries:
    plugins.pop("entries", None)
path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
print(f"    removed plugins.entries.{plugin_id} from {path}")
PY
}

purge_scan_credentials() {
  local dotenv
  dotenv="$(openclaw_dotenv_path)"
  [[ -f "${dotenv}" ]] || return 0
  echo "==> Purging Sentrook scan credentials from ${dotenv}"
  python3 - "${dotenv}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
drop = {
    "SENTROOK_SCAN_API_KEY",
    "SENTROOK_SCAN_CLIENT_ID",
    "SENTROOK_SCAN_CLIENT_SECRET",
}
lines = path.read_text(encoding="utf-8").splitlines()
kept = [ln for ln in lines if not any(ln.startswith(f"{k}=") for k in drop)]
path.write_text("\n".join(kept).rstrip() + ("\n" if kept else ""), encoding="utf-8")
path.chmod(0o600)
PY
}

echo "==> Sentrook plugin uninstall"
echo "    OPENCLAW_DIR=${OPENCLAW_DIR}"
if [[ "${PURGE}" == "1" ]]; then
  echo "    PURGE=1 (also remove scan credentials from .env)"
fi

gateway_healthy=0
if compose_base_only ps --status running --format '{{.Service}}' 2>/dev/null \
  | grep -qx "${OPENCLAW_GATEWAY_SERVICE}"; then
  gateway_healthy=1
fi

if (( gateway_healthy )); then
  echo "==> Uninstalling plugin via openclaw CLI"
  if [[ -t 0 && -t 1 ]]; then
    compose_base_only exec "${OPENCLAW_GATEWAY_SERVICE}" \
      openclaw plugins uninstall "${PLUGIN_ID}" || true
  else
    printf 'y\n' | compose_base_only exec -T "${OPENCLAW_GATEWAY_SERVICE}" \
      openclaw plugins uninstall "${PLUGIN_ID}" || true
  fi
  remove_plugin_config_via_gateway || remove_plugin_config_on_host || true
else
  echo "==> Gateway not running — removing config on host if present"
  remove_plugin_config_on_host || true
fi

# Legacy rsync install path (pre–GitHub Packages)
if [[ -d "${LEGACY_PLUGIN_HOST_DIR}" ]]; then
  echo "==> Removing legacy linked plugin tree at ${LEGACY_PLUGIN_HOST_DIR}"
  rm -rf "${LEGACY_PLUGIN_HOST_DIR}"
fi

if [[ "${PURGE}" == "1" ]]; then
  purge_scan_credentials
  rm -f "${OPENCLAW_STATE_DIR}/sentrook-shadow.patch.json5" \
    "${OPENCLAW_STATE_DIR}/sentrook-install.env" 2>/dev/null || true
fi

echo "==> Uninstall complete"
gateway_restart_hint
echo "    (uninstall does not restart the gateway for you)"
