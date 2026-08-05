#!/usr/bin/env bash
# Write shared Sentrook scan API key to ~/.openclaw/.env.
#
# Prefer sentrook-scan-oidc.sh (per-user OIDC). Kept for closed-beta / soak hosts only.
#
# Usage:
#   ./sentrook-scan-key.sh
#   SENTROOK_SCAN_API_KEY=... ./sentrook-scan-key.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/sentrook-scan-auth.sh
source "${SCRIPT_DIR}/lib/sentrook-scan-auth.sh"
openclaw_common_init "${SCRIPT_DIR}"

for arg in "$@"; do
  case "${arg}" in
    -h|--help)
      echo "Usage: $(basename "$0")"
      echo "  Shared API key path. Prefer ./sentrook-scan-oidc.sh."
      echo "  Writes SENTROOK_SCAN_API_KEY to ${OPENCLAW_STATE_DIR}/.env (chmod 600)."
      exit 0
      ;;
    --refresh-plugin)
      echo "error: --refresh-plugin was removed with the rsync installer." >&2
      echo "    Prefer OIDC: ./sentrook-scan-oidc.sh then README configure steps." >&2
      exit 2
      ;;
    *)
      echo "error: unknown argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

prompt_secret() {
  local label="$1"
  local answer
  read -r -s -p "${label}: " answer
  echo >&2
  printf '%s' "${answer}"
}

if [[ -z "${SENTROOK_SCAN_API_KEY:-}" ]]; then
  echo "warning: shared API key is optional — prefer sentrook-scan-oidc.sh" >&2
  SENTROOK_SCAN_API_KEY="$(prompt_secret "Sentrook scan API key")"
fi
if [[ -z "${SENTROOK_SCAN_API_KEY}" ]]; then
  echo "error: empty API key" >&2
  exit 1
fi

write_sentrook_scan_api_key_to_dotenv "${SENTROOK_SCAN_API_KEY}"
echo "==> Wrote ${SENTROOK_SCAN_API_KEY_VAR} to $(openclaw_dotenv_path) (chmod 600)"
echo "==> Next: configure plugin entries (see README.md), then restart the gateway."
gateway_restart_hint
