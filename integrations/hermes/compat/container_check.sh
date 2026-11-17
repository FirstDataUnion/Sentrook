#!/usr/bin/env bash
# Runs inside a nousresearch/hermes-agent image as the `hermes` user; started by run.sh.
#
#   /plugin   the plugin as a user would get it (no tests), read-only
#   /compat   this directory, read-only
#   /out      results: steps.tsv (step, ok|FAIL, detail), validate.json, the logs of each step
#
# Steps: the catalog validator, install from a git URL with --enable, the scan credentials set through
# Hermes, `hermes sentrook verify` and `status` against the mock identity service and scanner, then one
# real agent turn (`hermes chat`, model served by the mock) in which Sentrook must block one terminal
# call and allow the next. Every step runs even after a failure; the exit code is 1 when any failed.
#
# Synthetic credentials only. COMPAT_CLIENT_SECRET overrides the secret given to Hermes (the mock
# accepts only compat-secret), which is how the self-test makes the token mint fail.
set -uo pipefail

export HOME=/opt/data
OUT=/out
MOCK_PORT=8790
MOCK="http://127.0.0.1:${MOCK_PORT}"
CLIENT_ID=compat-client
CLIENT_SECRET=compat-secret
BLOCKED_FILE=/tmp/sentrook-compat-blocked
ALLOWED_FILE=/tmp/sentrook-compat-allowed
STEP_TIMEOUT=${COMPAT_STEP_TIMEOUT:-240}

: >"$OUT/steps.tsv"
failed=0

record() { # step ok|FAIL detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/steps.tsv"
  printf '%-4s %s: %s\n' "$2" "$1" "$3"
  [ "$2" = ok ] || failed=1
}

# The step's command output goes to $OUT/<step>.log; Hermes's container banner lines are dropped.
run() { # step cmd...
  local step=$1
  shift
  timeout "$STEP_TIMEOUT" "$@" </dev/null >"$OUT/$step.log" 2>&1
}

hermes_version=$(hermes --version 2>/dev/null | head -1)
record "hermes version" ok "${hermes_version:-unknown}"

# A git repository, as the catalog and `hermes plugins install` fetch plugins.
src=/tmp/sentrook-src
cp -r /plugin "$src"
git -C "$src" init -q
git -C "$src" -c user.name=compat -c user.email=compat@example.invalid add -A
git -C "$src" -c user.name=compat -c user.email=compat@example.invalid commit -qm plugin

# 1. Catalog validator.
run validate hermes plugins validate --install-deps --json "$src"
validate_rc=$?
# The JSON is the last top-level object in the output; anything before it is Hermes chatter.
python3 - "$OUT/validate.log" "$OUT/validate.json" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
doc, start = None, text.find("{")
while start != -1:
    try:
        obj, end = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        start = text.find("{", start + 1)
        continue
    if isinstance(obj, dict) and "checks" in obj:
        doc = obj
    start = text.find("{", start + end)
json.dump(doc, open(sys.argv[2], "w"), indent=2)
PY
validator_detail=$(python3 - "$OUT/validate.json" "$validate_rc" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if not isinstance(doc, dict):
    print(f"FAIL\tno JSON report (exit {sys.argv[2]})")
else:
    bad = [f"{c.get('name')}: {c.get('detail')}" for c in doc.get("checks", []) if not c.get("ok")]
    ok = doc.get("ok") is True and not bad and sys.argv[2] == "0"
    n = len(doc.get("checks", []))
    print(("ok\t" if ok else "FAIL\t") + ("; ".join(bad) if bad else f"{n} checks pass (exit {sys.argv[2]})"))
PY
)
record validate "${validator_detail%%$'\t'*}" "${validator_detail#*$'\t'}"

# 2. Install from a git URL, enabled.
if run install hermes plugins install "file://$src" --enable; then
  if hermes plugins list 2>/dev/null | grep -E '^\W*sentrook\W' | grep -q enabled; then
    record install ok "installed and enabled"
  else
    record install FAIL "install exited 0 but sentrook is not listed as enabled"
  fi
else
  record install FAIL "hermes plugins install exited $? (see install.log)"
fi

# 3. Scan credentials, through Hermes.
if run credentials sh -c "hermes config set SENTROOK_SCAN_CLIENT_ID '$CLIENT_ID' && \
    hermes config set SENTROOK_SCAN_CLIENT_SECRET '${COMPAT_CLIENT_SECRET:-$CLIENT_SECRET}'"; then
  record credentials ok "set with hermes config set"
else
  record credentials FAIL "hermes config set failed (see credentials.log)"
fi

# The mock identity service, scanner and model.
python3 /compat/mock_services.py --port "$MOCK_PORT" --log "$OUT/mock.jsonl" \
  --client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET" &
for _ in $(seq 50); do
  python3 -c "import urllib.request; urllib.request.urlopen('$MOCK/healthz', timeout=1)" 2>/dev/null && break
  sleep 0.2
done
export SENTROOK_DEV_ENDPOINTS=1 SENTROOK_SCAN_URL="$MOCK" SENTROOK_ROOKERY_URL="$MOCK" SENTROOK_OIDC_ISSUER="$MOCK"

# 4. verify: endpoints, credentials, scanner health, token mint.
if run verify hermes sentrook verify; then
  record verify ok "all checks pass"
else
  rc=$?
  record verify FAIL "exit $rc: $(grep '^FAIL' "$OUT/verify.log" | tr '\n' ';' | cut -c1-300)"
fi

# 5. status.
if run status hermes sentrook status && grep -q '^credentials: present' "$OUT/status.log"; then
  record status ok "$(grep -m1 '^Sentrook plugin' "$OUT/status.log")"
else
  record status FAIL "status failed or does not report the credentials (see status.log)"
fi

# 6. One agent turn through the real agent loop: the model asks for two terminal calls; Sentrook's
# pre_tool_call must block the first and allow the second.
if ! run turn-config sh -c "hermes config set model.provider custom && \
  hermes config set model.base_url '$MOCK/v1' && hermes config set model.default compat-mock && \
  hermes config set OPENAI_API_KEY compat-model-key"; then
  record turn-config FAIL "could not point Hermes at the mock model (see turn-config.log)"
fi
rm -f "$BLOCKED_FILE" "$ALLOWED_FILE"
(cd /tmp && run turn hermes chat -q "Run the compatibility steps." --oneshot -Q -t terminal --max-turns 6)
turn_rc=$?
turn_detail=$(python3 - "$OUT/mock.jsonl" "$BLOCKED_FILE" "$ALLOWED_FILE" "$turn_rc" "$OUT/turn.log" <<'PY'
import json, os, sys
log, blocked, allowed, rc, turn_log = sys.argv[1:6]
scans = []
if os.path.exists(log):
    for line in open(log):
        e = json.loads(line)
        if e.get("path") == "/scan":
            scans.append(e)
problems = []
if rc != "0":
    problems.append(f"hermes chat exited {rc}")
if "compat turn done" not in open(turn_log, errors="replace").read():
    problems.append("the agent did not finish the turn")
if len(scans) < 2:
    problems.append(f"{len(scans)} scans sent, expected one per terminal call (2)")
if any(not s.get("authed") for s in scans):
    problems.append("a scan was sent without a bearer token")
if not any(s.get("enforced") == "block" and s.get("tool") == "terminal" for s in scans):
    problems.append("no terminal call was scanned and blocked")
if os.path.exists(blocked):
    problems.append("the blocked terminal call ran")
if not os.path.exists(allowed):
    problems.append("the allowed terminal call did not run")
print(("FAIL\t" + "; ".join(problems)) if problems else f"ok\t{len(scans)} scans; block held, allow ran")
PY
)
record turn "${turn_detail%%$'\t'*}" "${turn_detail#*$'\t'}"

exit "$failed"
