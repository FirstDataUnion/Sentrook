#!/usr/bin/env bash
# Shared helpers for OpenClaw + Sentrook (online hosted scan).
# Gateway exec/config only — no sidecar compose or rsync install.
set -euo pipefail

openclaw_common_init() {
  local script_dir="$1"
  OPENCLAW_LIB_DIR="$(cd "${script_dir}/lib" && pwd)"
  OPENCLAW_INTEGRATION_DIR="$(cd "${script_dir}" && pwd)"
  SENTROOK_REPO="${SENTROOK_REPO:-$(cd "${OPENCLAW_INTEGRATION_DIR}/../.." && pwd)}"
  OPENCLAW_DIR="${OPENCLAW_DIR:-$(pwd)}"
  # Official OpenClaw compose *service* name (not the docker ps container name).
  OPENCLAW_GATEWAY_SERVICE="${OPENCLAW_GATEWAY_SERVICE:-openclaw-gateway}"
  OPENCLAW_STATE_DIR="${OPENCLAW_STATE_DIR:-${HOME}/.openclaw}"
  SENTROOK_SCAN_URL="${SENTROOK_SCAN_URL:-${SIDECAR_URL:-https://sentrook.firstdataunion.org}}"
  SIDECAR_URL="${SENTROOK_SCAN_URL}"
}

docker_compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "error: install docker compose (plugin) or docker-compose" >&2
    exit 1
  fi
}

require_openclaw_dir() {
  if [[ ! -f "${OPENCLAW_DIR}/docker-compose.yml" ]]; then
    echo "error: OPENCLAW_DIR must contain docker-compose.yml (got: ${OPENCLAW_DIR})" >&2
    exit 1
  fi
}

# Base OpenClaw compose only — never merge Sentrook overlays into gateway ops.
compose_base_only() {
  (
    cd "${OPENCLAW_DIR}" &&
    unset COMPOSE_FILE &&
    docker_compose "$@"
  )
}

gateway_exec() {
  compose_base_only exec -T "${OPENCLAW_GATEWAY_SERVICE}" "$@"
}

# Run the openclaw CLI inside the gateway. Prefer a real TTY for interactive commands.
gateway_run_openclaw() {
  local rc=0
  if [[ -t 0 && -t 1 ]]; then
    compose_base_only exec "${OPENCLAW_GATEWAY_SERVICE}" openclaw "$@" || rc=$?
  else
    compose_base_only exec -T "${OPENCLAW_GATEWAY_SERVICE}" openclaw "$@" || rc=$?
  fi
  if (( rc != 0 )); then
    echo "error: openclaw $* failed (exit ${rc})" >&2
    echo "hint: cd ${OPENCLAW_DIR} && docker compose exec ${OPENCLAW_GATEWAY_SERVICE} openclaw $*" >&2
  fi
  return "${rc}"
}

gateway_exec_root() {
  compose_base_only exec -T -u root "${OPENCLAW_GATEWAY_SERVICE}" "$@"
}

gateway_openclaw_home() {
  gateway_exec sh -c 'printf %s "${OPENCLAW_HOME:-/home/node/.openclaw}"'
}

gateway_write_file() {
  local container_path="$1"
  local host_file="$2"
  local parent
  parent="$(dirname "${container_path}")"
  gateway_exec mkdir -p "${parent}"
  gateway_exec_root rm -f "${container_path}" 2>/dev/null || true
  gateway_exec tee "${container_path}" > /dev/null < "${host_file}"
}

gateway_restart_hint() {
  cat <<EOF
Restart the gateway when ready (from your OpenClaw compose project):
  cd ${OPENCLAW_DIR} && docker compose restart ${OPENCLAW_GATEWAY_SERVICE}
  # Compose service name (often openclaw-gateway). Override OPENCLAW_GATEWAY_SERVICE if yours differs.
EOF
}
