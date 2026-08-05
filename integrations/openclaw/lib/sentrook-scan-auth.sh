#!/usr/bin/env bash
# Scan auth helpers — SecretRef backing store in ~/.openclaw/.env
# Prefer OIDC client credentials (SENTROOK_SCAN_CLIENT_*); legacy API key still supported.
set -euo pipefail

SENTROOK_SCAN_API_KEY_VAR="${SENTROOK_SCAN_API_KEY_VAR:-SENTROOK_SCAN_API_KEY}"
SENTROOK_SCAN_CLIENT_ID_VAR="${SENTROOK_SCAN_CLIENT_ID_VAR:-SENTROOK_SCAN_CLIENT_ID}"
SENTROOK_SCAN_CLIENT_SECRET_VAR="${SENTROOK_SCAN_CLIENT_SECRET_VAR:-SENTROOK_SCAN_CLIENT_SECRET}"

openclaw_dotenv_path() {
  echo "${OPENCLAW_DOTENV:-${OPENCLAW_STATE_DIR:-${HOME}/.openclaw}/.env}"
}

_sentrook_dotenv_get() {
  local var="$1"
  local dotenv line
  dotenv="$(openclaw_dotenv_path)"
  [[ -f "${dotenv}" ]] || return 1
  line="$(grep -E "^${var}=" "${dotenv}" 2>/dev/null | tail -1 || true)"
  [[ -n "${line}" ]] || return 1
  printf '%s' "${line#*=}"
}

_sentrook_write_dotenv_var() {
  local var="$1"
  local value="$2"
  local dotenv
  dotenv="$(openclaw_dotenv_path)"
  mkdir -p "$(dirname "${dotenv}")"
  umask 077
  if [[ ! -f "${dotenv}" ]]; then
    printf '%s\n' "# OpenClaw gateway secrets (loaded at startup)" > "${dotenv}"
    chmod 600 "${dotenv}"
  fi
  python3 - "${dotenv}" "${var}" "${value}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
var = sys.argv[2]
value = sys.argv[3]
prefix = f"{var}="
lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
out: list[str] = []
found = False
for line in lines:
    if line.startswith(prefix):
        out.append(prefix + value)
        found = True
    else:
        out.append(line)
if not found:
    if out and out[-1].strip():
        out.append("")
    out.append(prefix + value)
path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
path.chmod(0o600)
PY
  _sentrook_align_dotenv_owner "${dotenv}"
}

sentrook_scan_api_key_from_dotenv() {
  _sentrook_dotenv_get "${SENTROOK_SCAN_API_KEY_VAR}"
}

sentrook_scan_api_key_configured() {
  local key
  if [[ -n "${SENTROOK_SCAN_API_KEY:-}" ]]; then
    return 0
  fi
  key="$(sentrook_scan_api_key_from_dotenv 2>/dev/null || true)"
  [[ -n "${key}" ]]
}

sentrook_scan_client_id_from_dotenv() {
  _sentrook_dotenv_get "${SENTROOK_SCAN_CLIENT_ID_VAR}"
}

sentrook_scan_client_secret_from_dotenv() {
  _sentrook_dotenv_get "${SENTROOK_SCAN_CLIENT_SECRET_VAR}"
}

sentrook_scan_oidc_configured() {
  local cid csec
  cid="${SENTROOK_SCAN_CLIENT_ID:-}"
  csec="${SENTROOK_SCAN_CLIENT_SECRET:-}"
  if [[ -z "${cid}" ]]; then
    cid="$(sentrook_scan_client_id_from_dotenv 2>/dev/null || true)"
  fi
  if [[ -z "${csec}" ]]; then
    csec="$(sentrook_scan_client_secret_from_dotenv 2>/dev/null || true)"
  fi
  [[ -n "${cid}" && -n "${csec}" ]]
}

sentrook_scan_auth_configured() {
  sentrook_scan_oidc_configured || sentrook_scan_api_key_configured
}

sentrook_scan_url_requires_api_key() {
  local url="${1:-${SIDECAR_URL:-}}"
  [[ "${url}" == https://* ]]
}

sentrook_scan_url_requires_auth() {
  sentrook_scan_url_requires_api_key "$@"
}

_sentrook_stat_owner() {
  # Print "uid:gid" for a path, portable across GNU (Linux) and BSD (macOS) stat.
  stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1" 2>/dev/null || true
}

_sentrook_align_dotenv_owner() {
  # The gateway container bind-mounts the state dir and runs as its owner uid.
  # A root-owned 600 .env inside a uid-1000 state dir is unreadable in-container
  # (EACCES on secret resolution), so match the file owner to the parent dir.
  local file="$1" dir dir_owner file_owner
  dir="$(dirname "${file}")"
  [[ -e "${dir}" && -e "${file}" ]] || return 0
  [[ "$(id -u)" == "0" ]] || return 0
  dir_owner="$(_sentrook_stat_owner "${dir}")"
  file_owner="$(_sentrook_stat_owner "${file}")"
  [[ -n "${dir_owner}" && "${dir_owner}" != "${file_owner}" ]] || return 0
  chown "${dir_owner}" "${file}" 2>/dev/null || true
}

write_sentrook_scan_api_key_to_dotenv() {
  _sentrook_write_dotenv_var "${SENTROOK_SCAN_API_KEY_VAR}" "$1"
}

write_sentrook_scan_oidc_to_dotenv() {
  local client_id="$1"
  local client_secret="$2"
  _sentrook_write_dotenv_var "${SENTROOK_SCAN_CLIENT_ID_VAR}" "${client_id}"
  _sentrook_write_dotenv_var "${SENTROOK_SCAN_CLIENT_SECRET_VAR}" "${client_secret}"
}

ensure_sentrook_scan_api_key_materialized() {
  # Export SENTROOK_SCAN_API_KEY from the shell, or read ~/.openclaw/.env into the file.
  if [[ -n "${SENTROOK_SCAN_API_KEY:-}" ]]; then
    write_sentrook_scan_api_key_to_dotenv "${SENTROOK_SCAN_API_KEY}"
    return 0
  fi
  if sentrook_scan_api_key_configured; then
    return 0
  fi
  return 1
}

ensure_sentrook_scan_oidc_materialized() {
  local cid="${SENTROOK_SCAN_CLIENT_ID:-}"
  local csec="${SENTROOK_SCAN_CLIENT_SECRET:-}"
  if [[ -z "${cid}" ]]; then
    cid="$(sentrook_scan_client_id_from_dotenv 2>/dev/null || true)"
  fi
  if [[ -z "${csec}" ]]; then
    csec="$(sentrook_scan_client_secret_from_dotenv 2>/dev/null || true)"
  fi
  if [[ -z "${cid}" || -z "${csec}" ]]; then
    return 1
  fi
  write_sentrook_scan_oidc_to_dotenv "${cid}" "${csec}"
  export SENTROOK_SCAN_CLIENT_ID="${cid}"
  export SENTROOK_SCAN_CLIENT_SECRET="${csec}"
  return 0
}
