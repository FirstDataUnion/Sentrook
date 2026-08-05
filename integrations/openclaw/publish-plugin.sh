#!/usr/bin/env bash
# Publish @firstdataunion/sentrook-shadow to GitHub Packages.
#
# Prerequisites:
#   - gh auth login (or NODE_AUTH_TOKEN / GITHUB_TOKEN with write:packages + repo read)
#   - Package linked to github.com/FirstDataUnion/Sentrook (first publish creates it)
#
# Usage:
#   ./publish-plugin.sh              # test + publish
#   ./publish-plugin.sh --dry-run    # test + npm pack only
#   DRY_RUN=1 ./publish-plugin.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${SCRIPT_DIR}/plugin"
DRY_RUN="${DRY_RUN:-0}"

for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--dry-run]"
      echo "  Publishes integrations/openclaw/plugin to GitHub Packages."
      exit 0
      ;;
    *)
      echo "error: unknown argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "${PLUGIN_DIR}/package.json" || ! -f "${PLUGIN_DIR}/openclaw.plugin.json" ]]; then
  echo "error: plugin package incomplete under ${PLUGIN_DIR}" >&2
  exit 1
fi

name="$(node -p "require('${PLUGIN_DIR}/package.json').name")"
version="$(node -p "require('${PLUGIN_DIR}/package.json').version")"
registry="$(node -p "require('${PLUGIN_DIR}/package.json').publishConfig?.registry || ''")"

if [[ "${name}" != @firstdataunion/* ]]; then
  echo "error: expected scoped name @firstdataunion/... (got ${name})" >&2
  exit 1
fi
if [[ "${registry}" != "https://npm.pkg.github.com" ]]; then
  echo "error: publishConfig.registry must be https://npm.pkg.github.com (got ${registry})" >&2
  exit 1
fi

# Prefer explicit NODE_AUTH_TOKEN; fall back to gh / GITHUB_TOKEN for publish.
if [[ -z "${NODE_AUTH_TOKEN:-}" ]]; then
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    export NODE_AUTH_TOKEN="${GITHUB_TOKEN}"
  elif command -v gh >/dev/null 2>&1; then
    if token="$(gh auth token 2>/dev/null)" && [[ -n "${token}" ]]; then
      export NODE_AUTH_TOKEN="${token}"
    fi
  fi
fi

if [[ -z "${NODE_AUTH_TOKEN:-}" && "${DRY_RUN}" != "1" ]]; then
  echo "error: set NODE_AUTH_TOKEN (or GITHUB_TOKEN / gh auth login) with write:packages" >&2
  echo "    example: NODE_AUTH_TOKEN=\$(gh auth token) $0" >&2
  exit 1
fi

echo "==> Plugin package"
echo "    name=${name}"
echo "    version=${version}"
echo "    registry=${registry}"

echo "==> Tests"
(
  cd "${PLUGIN_DIR}"
  npm test
)

echo "==> Build (compiled runtime for npm installs)"
(
  cd "${PLUGIN_DIR}"
  npm run build
)
if [[ ! -f "${PLUGIN_DIR}/dist/index.js" ]]; then
  echo "error: build did not produce ${PLUGIN_DIR}/dist/index.js" >&2
  exit 1
fi

echo "==> Pack check (runtime files only)"
(
  cd "${PLUGIN_DIR}"
  npm pack --dry-run
)

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "==> Dry run complete (not published)"
  echo "    Install preview: openclaw plugins install npm:${name}@${version} --pin --force"
  exit 0
fi

# npm does not send NODE_AUTH_TOKEN to GitHub Packages unless an .npmrc maps the
# registry to that token. Write a throwaway userconfig (never committed / packed).
npmrc="$(mktemp)"
trap 'rm -f "${npmrc}"' EXIT
cat > "${npmrc}" <<EOF
@firstdataunion:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
always-auth=true
EOF

echo "==> Publishing to GitHub Packages"
(
  cd "${PLUGIN_DIR}"
  npm publish --userconfig "${npmrc}"
)

echo "==> Published ${name}@${version}"
echo
echo "Colleague install:"
echo "  # ~/.npmrc — see integrations/openclaw/.npmrc.example"
echo "  openclaw plugins install npm:${name}@${version} --pin --force"
echo "  openclaw sentrook configure"
echo "  docker compose restart openclaw-gateway"
