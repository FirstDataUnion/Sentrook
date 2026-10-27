#!/usr/bin/env bash
# Runs when the agent tries to finish. Exit 2 sends stderr back to the agent.
cd "$(git rev-parse --show-toplevel)" || exit 0
changed=$(git status --porcelain | cut -c4-)
[ -z "$changed" ] && exit 0

fail=0
run() { echo "== $*" >&2; "$@" >&2 || fail=1; }

if echo "$changed" | grep -qE '^(sentrook/|schema/|pyproject.toml|uv.lock)'; then
  run make lint; run make test; run make schema-check
fi
plugins=0
echo "$changed" | grep -q '^integrations/openclaw/' && { run make plugin-test; plugins=1; }
echo "$changed" | grep -q '^integrations/hermes/'   && { run make hermes-plugin-test; plugins=1; }
[ "$plugins" = 1 ] && run make plugin-planir-check

[ "$fail" = 0 ] || { echo "Checks failed. Fix before finishing." >&2; exit 2; }
