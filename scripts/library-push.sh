#!/usr/bin/env bash
# Push missing repo corpus examples to Rookery (repo dev tool).
# Runs in the sentrook project env so PyYAML and sentrook imports resolve.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec uv run --directory "$ROOT/sentrook" python "$ROOT/scripts/library_push.py" "$@"
