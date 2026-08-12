#!/usr/bin/env bash
# Test, pack, and optionally publish @firstdataunion/sentrook-openclaw to public npmjs.
#
# Preferred publish path is Sentrook Actions `release-plugin.yml` (OIDC + Environment
# `release-npm`). This script is for local dry-run and the one-off bootstrap publish.
#
# Usage:
#   ./publish-plugin.sh --dry-run              # tests + npm pack (default-safe)
#   ./publish-plugin.sh --dry-run --tag next
#   ./publish-plugin.sh --publish              # npm publish (requires npm login)
#   ./publish-plugin.sh --publish --tag latest
#   DRY_RUN=1 ./publish-plugin.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${SCRIPT_DIR}/plugin"
DRY_RUN="${DRY_RUN:-1}"
TAG=""
NPMJS_REGISTRY="https://registry.npmjs.org"

usage() {
  echo "Usage: $(basename "$0") [--dry-run|--publish] [--tag next|latest]"
  echo "  Tests + packs integrations/openclaw/plugin; publishes to npmjs only with --publish."
}

for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=1 ;;
    --publish) DRY_RUN=0 ;;
    --tag=next|--tag=latest) TAG="${arg#--tag=}" ;;
    --tag)
      echo "error: use --tag=next or --tag=latest" >&2
      exit 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: ${arg}" >&2
      usage >&2
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
access="$(node -p "require('${PLUGIN_DIR}/package.json').publishConfig?.access || ''")"

if [[ "${name}" != @firstdataunion/* ]]; then
  echo "error: expected scoped name @firstdataunion/... (got ${name})" >&2
  exit 1
fi
if [[ "${registry}" != "${NPMJS_REGISTRY}" ]]; then
  echo "error: publishConfig.registry must be ${NPMJS_REGISTRY} (got ${registry})" >&2
  exit 1
fi
if [[ "${access}" != "public" ]]; then
  echo "error: publishConfig.access must be public (got ${access})" >&2
  exit 1
fi

is_prerelease=0
if [[ "${version}" == *-* ]]; then
  is_prerelease=1
fi

if [[ -z "${TAG}" ]]; then
  if [[ "${is_prerelease}" == "1" ]]; then
    TAG=next
  else
    TAG=latest
  fi
fi

if [[ "${TAG}" == "latest" && "${is_prerelease}" == "1" ]]; then
  echo "error: --tag=latest refuses prerelease version ${version}" >&2
  exit 1
fi
if [[ "${TAG}" == "next" && "${is_prerelease}" != "1" ]]; then
  echo "error: --tag=next requires a prerelease version (got ${version})" >&2
  echo "    bump package.json to x.y.z-rc.N first" >&2
  exit 1
fi

echo "==> Plugin package"
echo "    name=${name}"
echo "    version=${version}"
echo "    registry=${registry}"
echo "    access=${access}"
echo "    tag=${TAG}"

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
  if [[ "${TAG}" == "next" ]]; then
    echo "    Soak tag:        openclaw plugins install npm:${name}@next --pin --force"
  fi
  exit 0
fi

echo "==> Publishing to npmjs (tag=${TAG})"
echo "    Prefer GitHub Actions release-plugin.yml (OIDC). Local publish needs npm login."
(
  cd "${PLUGIN_DIR}"
  npm publish --access public --tag "${TAG}"
)

echo "==> Published ${name}@${version} (dist-tag ${TAG})"
echo
echo "Install:"
if [[ "${TAG}" == "next" ]]; then
  echo "  openclaw plugins install npm:${name}@next --pin --force"
else
  echo "  openclaw plugins install npm:${name}@${version} --pin --force"
fi
echo "  openclaw sentrook configure"
echo "  docker compose restart openclaw-gateway"
