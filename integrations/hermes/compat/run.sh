#!/usr/bin/env bash
# The Hermes compatibility check against one Hermes image:
#
#   integrations/hermes/compat/run.sh <image> [plugin dir] [out dir]
#   e.g. integrations/hermes/compat/run.sh nousresearch/hermes-agent:v0.23.2
#
# Copies the plugin as a user gets it (no tests), runs container_check.sh in the image (validator,
# install, credentials, verify, status, one agent turn against the mock services), then compares the
# validator's warnings with warnings-baseline.txt. Exit 1 when any step fails. Needs Docker and python3.
# COMPAT_CLIENT_SECRET is passed through (see container_check.sh).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
image=${1:?usage: run.sh <image> [plugin dir] [out dir]}
plugin=${2:-$root/integrations/hermes/plugin}
out=${3:-$(mktemp -d)}
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# The same tree the release workflow publishes: tests and caches left out.
mkdir -p "$stage/sentrook"
(cd "$plugin" && tar --exclude tests --exclude __pycache__ --exclude '*.py[cod]' --exclude .pytest_cache -cf - .) |
  tar -xf - -C "$stage/sentrook"
chmod -R a+rX "$stage"
chmod a+rwx "$out"

echo "== $image"
status=0
docker run --rm --init --user hermes \
  -e COMPAT_CLIENT_SECRET="${COMPAT_CLIENT_SECRET:-}" \
  -v "$stage/sentrook:/plugin:ro" -v "$here:/compat:ro" -v "$root/integrations/compat:/shared:ro" -v "$out:/out" \
  --entrypoint bash "$image" /compat/container_check.sh || status=1

# The validator reports some contract breaks (a declared hook never registered, a private import) only
# as warnings; any warning not in the baseline fails.
if warnings=$(python3 "$root/integrations/compat/compat.py" warnings --host hermes "$out/validate.json"); then
  printf 'warnings\tok\t%s\n' "$(grep -v '^note:' <<<"$warnings" | sed 's/^ok *//' | head -1)" >>"$out/steps.tsv"
else
  status=1
  printf 'warnings\tFAIL\t%s\n' "$(grep '^FAIL' <<<"$warnings" | sed 's/^FAIL *//' | paste -sd ';' -)" >>"$out/steps.tsv"
fi
echo "$warnings"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Hermes compatibility: \`$image\`"
    echo
    echo "| step | result | detail |"
    echo "| --- | --- | --- |"
    awk -F'\t' '{ gsub(/\|/, "\\|", $3); printf "| %s | %s | %s |\n", $1, $2, $3 }' "$out/steps.tsv"
    echo
  } >>"$GITHUB_STEP_SUMMARY"
fi
echo "results in $out"
exit "$status"
