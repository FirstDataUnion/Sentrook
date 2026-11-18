#!/usr/bin/env bash
# The OpenClaw compatibility check against one OpenClaw image:
#
#   integrations/openclaw/compat/run.sh <image> [plugin dir] [out dir]
#   e.g. integrations/openclaw/compat/run.sh ghcr.io/openclaw/openclaw:2026.11.5
#
# Packs the plugin as npm publishes it (`npm run pack:check`, then `npm pack`), runs container_check.sh in the
# image (validator, credentials, install, load, doctor, verify, status, an agent turn against the mock services,
# the seam probe), then compares what OpenClaw's own checks report with warnings-baseline.txt. Exit 1 when any
# step fails. Needs Docker, Node 22.6+ and python3. COMPAT_CLIENT_SECRET and COMPAT_PROBE_EXTRA are passed
# through (see container_check.sh).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
image=${1:?usage: run.sh <image> [plugin dir] [out dir]}
plugin=${2:-$root/integrations/openclaw/plugin}
out=${3:-$(mktemp -d)}
mkdir -p "$out"
: >"$out/steps.tsv"
rm -f "${out:?}/validate.json"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# The package as the release workflow publishes it, from a copy so the source tree is left alone.
mkdir -p "$stage/src" "$stage/pkg"
(cd "$plugin" && tar --exclude node_modules --exclude dist -cf - .) | tar -xf - -C "$stage/src"
# The plugin is an npm workspace of the repository root, so its build tools are in the root's node_modules.
ln -s "$root/node_modules" "$stage/src/node_modules"
if { [ -x "$root/node_modules/.bin/esbuild" ] || (cd "$root" && npm ci --no-audit --no-fund); } >"$out/pack.log" 2>&1 &&
  (cd "$stage/src" && npm run --silent pack:check && npm pack --silent --pack-destination "$stage/pkg") \
    >>"$out/pack.log" 2>&1 && mv "$stage/pkg"/*.tgz "$stage/pkg/sentrook.tgz" 2>>"$out/pack.log"; then
  printf 'pack\tok\t%s\n' "npm run pack:check and npm pack" >>"$out/steps.tsv"
else
  printf 'pack\tFAIL\t%s\n' "npm ci, npm run pack:check or npm pack failed (see pack.log)" >>"$out/steps.tsv"
fi
chmod -R a+rX "$stage"
chmod a+rwx "$out"
chmod a+rw "$out/steps.tsv"

echo "== $image"
status=0
if [ -f "$stage/pkg/sentrook.tgz" ]; then
  docker run --rm --init --user node \
    -e COMPAT_CLIENT_SECRET="${COMPAT_CLIENT_SECRET:-}" -e COMPAT_PROBE_EXTRA="${COMPAT_PROBE_EXTRA:-}" \
    -v "$stage/pkg:/pkg:ro" -v "$here:/compat:ro" -v "$root/integrations/compat:/shared:ro" -v "$out:/out" \
    --entrypoint bash "$image" /compat/container_check.sh || status=1
else
  status=1
fi

# OpenClaw reports some contract breaks (an unknown hook name, a hook it blocks) only as diagnostics; any report
# not in the baseline fails.
if warnings=$(python3 "$root/integrations/compat/compat.py" warnings --host openclaw "$out/validate.json"); then
  printf 'warnings\tok\t%s\n' "$(grep -v '^note:' <<<"$warnings" | sed 's/^ok *//' | head -1)" >>"$out/steps.tsv"
else
  status=1
  printf 'warnings\tFAIL\t%s\n' "$(grep '^FAIL' <<<"$warnings" | sed 's/^FAIL *//' | paste -sd ';' -)" >>"$out/steps.tsv"
fi
echo "$warnings"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### OpenClaw compatibility: \`$image\`"
    echo
    echo "| step | result | detail |"
    echo "| --- | --- | --- |"
    awk -F'\t' '{ gsub(/\|/, "\\|", $3); printf "| %s | %s | %s |\n", $1, $2, $3 }' "$out/steps.tsv"
    echo
  } >>"$GITHUB_STEP_SUMMARY"
fi
echo "results in $out"
exit "$status"
