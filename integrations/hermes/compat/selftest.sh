#!/usr/bin/env bash
# Proves the compatibility check fails when it should: each case breaks the plugin or its setup in
# one way and expects run.sh to fail at a named step with a named message.
#
#   integrations/hermes/compat/selftest.sh <image>
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
image=${1:?usage: selftest.sh <image>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

copy_plugin() { # dest
  mkdir -p "$1"
  (cd "$root/integrations/hermes/plugin" && tar --exclude tests --exclude __pycache__ -cf - .) | tar -xf - -C "$1"
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

# A hook declared in provides_hooks that register() never registers (Hermes reports it as a warning).
copy_plugin "$work/undeclared-hook"
python3 - "$work/undeclared-hook/plugin.yaml" <<'PY'
import sys
p = sys.argv[1]
text = open(p).read()
assert "  - post_approval_response\n" in text
open(p, "w").write(text.replace("  - post_approval_response\n", "  - post_approval_response\n  - on_session_start\n", 1))
PY
expect_fail undeclared-hook warnings "provides_hooks declares on_session_start" "$work/undeclared-hook"

# A config_schema entry with a type Hermes does not know.
copy_plugin "$work/unknown-config-type"
python3 - "$work/unknown-config-type/plugin.yaml" <<'PY'
import sys
p = sys.argv[1]
text = open(p).read()
old = "  scan_url:\n    type: str\n"
assert old in text
open(p, "w").write(text.replace(old, "  scan_url:\n    type: colour\n", 1))
PY
expect_fail unknown-config-type validate "config schema" "$work/unknown-config-type"

# A Hermes whose background-review memory gate is not on the plugin's list of verified builds.
copy_plugin "$work/unverified-gate"
python3 - "$work/unverified-gate/staging.py" <<'PY'
import re, sys
p = sys.argv[1]
text = open(p).read()
new = re.sub(r'\n    "[0-9a-f]{64}": "[^"]*",', "", text)
assert new != text
open(p, "w").write(new)
PY
expect_fail unverified-gate "memory gate" "not verified" "$work/unverified-gate"

# A Hermes platform the plugin classifies neither as attended nor as not attended.
copy_plugin "$work/unclassified-platform"
python3 - "$work/unclassified-platform/intent.py" <<'PY2'
import sys
p = sys.argv[1]
text = open(p).read()
assert '        "teams",\n' in text
open(p, "w").write(text.replace('        "teams",\n', "", 1))
PY2
expect_fail unclassified-platform platforms "unclassified teams" "$work/unclassified-platform"

# verify must fail when the identity service refuses the token mint.
expect_fail token-mint verify "token mint" "$root/integrations/hermes/plugin" COMPAT_CLIENT_SECRET=wrong-secret

exit "$failures"
