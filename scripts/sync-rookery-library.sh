#!/usr/bin/env bash
# Sync Rookery SoT (rules/, corpus/, eval/) into this Sentrook checkout as a
# gitignored local mirror for full TestNest runs.
#
# Usage:
#   make sync-library
#   ROOKERY_ROOT=/path/to/FIDU-Rookery ./scripts/sync-rookery-library.sh
#
# Destination paths must remain untracked (see .gitignore). CI should consume
# Rookery's committed tree directly — this mirror is for local DX only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROOKERY_ROOT="${ROOKERY_ROOT:-$ROOT/../FIDU-Rookery}"

die() {
  echo "sync-rookery-library: $*" >&2
  exit 1
}

[[ -d "$ROOKERY_ROOT" ]] || die "Rookery root not found: $ROOKERY_ROOT (set ROOKERY_ROOT)"

for dir in rules corpus eval; do
  [[ -d "$ROOKERY_ROOT/$dir" ]] || die "missing $ROOKERY_ROOT/$dir"
done

command -v rsync >/dev/null 2>&1 || die "rsync is required"

cd "$ROOT"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for dir in rules corpus eval; do
    if git ls-files --error-unmatch "$dir" >/dev/null 2>&1; then
      die "$dir/ is tracked by git — refuse to overwrite. Remove it from the index first."
    fi
    # Also refuse if any tracked file lives under the path (partial tracking).
    if [[ -n "$(git ls-files "$dir" 2>/dev/null || true)" ]]; then
      die "$dir/ has tracked files — refuse to overwrite. Untrack them first."
    fi
  done
fi

for dir in rules corpus eval; do
  mkdir -p "$ROOT/$dir"
  rsync -a --delete "$ROOKERY_ROOT/$dir/" "$ROOT/$dir/"
done

REF="unknown"
if git -C "$ROOKERY_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  REF="$(git -C "$ROOKERY_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  BRANCH="$(git -C "$ROOKERY_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  echo "Synced rules/ corpus/ eval/ from $ROOKERY_ROOT ($BRANCH @ $REF)"
else
  echo "Synced rules/ corpus/ eval/ from $ROOKERY_ROOT"
fi
