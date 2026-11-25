#!/usr/bin/env bash
# Proves the compatibility check fails when it should: each case breaks the plugin or its setup in one way and
# expects run.sh to fail at a named step with a named message.
#
#   integrations/openclaw/compat/selftest.sh <image>
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
image=${1:?usage: selftest.sh <image>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

copy_plugin() { # dest
  mkdir -p "$1"
  (cd "$root/integrations/openclaw/plugin" && tar --exclude node_modules --exclude dist -cf - .) | tar -xf - -C "$1"
}

failed_at() { # out step -> the detail of that step's failure
  awk -F'\t' -v s="$2" '$1 == s && $2 == "FAIL" { print $3 }' "$1/steps.tsv" 2>/dev/null
}

expect_fail() { # case step pattern plugin-dir [env...]
  local name=$1 step=$2 pattern=$3 plugin=$4
  shift 4
  local out="$work/out-$name"
  if env "$@" "$here/run.sh" "$image" "$plugin" "$out" >"$work/$name.log" 2>&1; then
    echo "FAIL $name: the check passed"
    failures=1
  elif failed_at "$out" "$step" | grep -qiE "$pattern"; then
    echo "ok   $name: $(failed_at "$out" "$step" | cut -c1-160)"
  else
    echo "FAIL $name: failed, but not at $step with /$pattern/:"
    sed 's/^/     /' "$out/steps.tsv" 2>/dev/null || tail -20 "$work/$name.log"
    failures=1
  fi
}

# A hook name OpenClaw does not know (OpenClaw ignores it and reports it only as a diagnostic).
copy_plugin "$work/unknown-hook"
python3 - "$work/unknown-hook/index.ts" <<'PY'
import sys
p = sys.argv[1]
text = open(p).read()
anchor = "    // ---- the scan ---"
assert anchor in text
hook = '    api.on("compat_no_such_hook", () => undefined);\n\n'
open(p, "w").write(text.replace(anchor, hook + anchor, 1))
PY
expect_fail unknown-hook warnings 'unknown typed hook "compat_no_such_hook"' "$work/unknown-hook"

# verify must fail when the identity service refuses the token mint.
expect_fail token-mint verify "token mint" "$root/integrations/openclaw/plugin" COMPAT_CLIENT_SECRET=wrong-secret

# A host field the plugin reads that this OpenClaw does not have.
expect_fail missing-field seams "api.runtime.compatNoSuchField is missing" "$root/integrations/openclaw/plugin" \
  COMPAT_PROBE_EXTRA=runtime.compatNoSuchField

# A manifest schema that rejects a setting: OpenClaw's doctor --fix then disables the plugin.
copy_plugin "$work/strict-schema"
python3 - "$work/strict-schema/openclaw.plugin.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m["configSchema"]["additionalProperties"] = False
json.dump(m, open(p, "w"), indent=2)
PY
expect_fail strict-schema settings-doctor "disabled the plugin" "$work/strict-schema"

exit "$failures"
