#!/usr/bin/env bash
# Write per-user Sentrook scan OIDC client credentials to ~/.openclaw/.env (SecretRef backing store).
#
# Preferred auth path for hosted scan. Create credentials in the FIDU ID dashboard (Sentrook tab).
# Config patching moves to `openclaw sentrook configure` (plugin CLI) — this script only stores secrets.
#
# Usage:
#   ./sentrook-scan-oidc.sh
#   SENTROOK_SCAN_CLIENT_ID=... SENTROOK_SCAN_CLIENT_SECRET=... ./sentrook-scan-oidc.sh
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
      echo "  Writes SENTROOK_SCAN_CLIENT_ID and SENTROOK_SCAN_CLIENT_SECRET to"
      echo "  ${OPENCLAW_STATE_DIR}/.env (chmod 600)."
      echo "  Create credentials in the FIDU ID dashboard → Sentrook tab."
      echo "  Then configure the plugin (see README.md) and restart the gateway."
      exit 0
      ;;
    --refresh-plugin)
      echo "error: --refresh-plugin was removed with the rsync installer." >&2
      echo "    Write credentials with this script, then follow README configure steps" >&2
      echo "    (or run: openclaw sentrook configure — once the plugin CLI ships)." >&2
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

prompt_value() {
  local label="$1"
  local answer
  read -r -p "${label}: " answer
  printf '%s' "${answer}"
}

if [[ -z "${SENTROOK_SCAN_CLIENT_ID:-}" ]]; then
  echo "Create credentials on the FIDU ID dashboard → Sentrook tab, then paste below." >&2
  SENTROOK_SCAN_CLIENT_ID="$(prompt_value "Sentrook scan OAuth client_id")"
fi
if [[ -z "${SENTROOK_SCAN_CLIENT_SECRET:-}" ]]; then
  SENTROOK_SCAN_CLIENT_SECRET="$(prompt_secret "Sentrook scan OAuth client_secret")"
fi
if [[ -z "${SENTROOK_SCAN_CLIENT_ID}" || -z "${SENTROOK_SCAN_CLIENT_SECRET}" ]]; then
  echo "error: empty client_id or client_secret" >&2
  exit 1
fi

write_sentrook_scan_oidc_to_dotenv "${SENTROOK_SCAN_CLIENT_ID}" "${SENTROOK_SCAN_CLIENT_SECRET}"
echo "==> Wrote ${SENTROOK_SCAN_CLIENT_ID_VAR} + ${SENTROOK_SCAN_CLIENT_SECRET_VAR} to $(openclaw_dotenv_path) (chmod 600)"
echo "    Access tokens are minted at runtime (not stored). Never put JWTs in .env."
echo "==> Next: configure plugin entries (see README.md), then restart the gateway."
gateway_restart_hint
