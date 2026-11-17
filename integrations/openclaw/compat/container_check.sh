#!/usr/bin/env bash
# Runs inside a ghcr.io/openclaw/openclaw image as the `node` user; started by run.sh.
#
#   /pkg      sentrook.tgz, the plugin packed as npm publishes it, read-only
#   /compat   this directory, read-only
#   /shared   integrations/compat (the mock services), read-only
#   /out      results: steps.tsv (step, ok|FAIL, detail; run.sh wrote the pack step), validate.json (what
#             OpenClaw's own checks report, for the baseline), the logs of each step, mock.jsonl, probe.jsonl
#
# Steps, as the install guide has a user do them: OpenClaw's plugin validator on the package, the scan
# credentials in the state-dir .env with SecretRefs to them, conversation access, install from the archive with
# --force --accept-capabilities, enable, then `openclaw plugins doctor` and `inspect --runtime`, `openclaw
# sentrook verify` and `status` against the mock identity service and scanner, and two real agent turns
# (`openclaw agent --local`, model served by the mock) in one session: in the first Sentrook must block one exec
# call and allow the next; the second only gives the seam probe a conversation with history. Every step runs
# even after a failure; the exit code is 1 when any failed.
#
# Synthetic credentials only. COMPAT_CLIENT_SECRET overrides the secret given to OpenClaw (the mock accepts only
# compat-secret), which is how the self-test makes the token mint fail. COMPAT_PROBE_EXTRA is passed to the
# probe (see probe/index.js).
set -uo pipefail

export HOME=/home/node
OUT=/out
STATE="$HOME/.openclaw"
MOCK_PORT=8790
MOCK="http://127.0.0.1:${MOCK_PORT}"
CLIENT_ID=compat-client
CLIENT_SECRET=compat-secret
BLOCKED_FILE=/tmp/sentrook-compat-blocked
ALLOWED_FILE=/tmp/sentrook-compat-allowed
STEP_TIMEOUT=${COMPAT_STEP_TIMEOUT:-240}
export COMPAT_PROBE_OUT="$OUT/probe.jsonl"

failed=0
# The files are owned by `node` inside the image; on a Linux host that is a different user, and run.sh appends
# the warnings step to steps.tsv after the container exits.
trap 'chmod -R a+rwX "$OUT" 2>/dev/null' EXIT

record() { # step ok|FAIL detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/steps.tsv"
  printf '%-4s %s: %s\n' "$2" "$1" "$3"
  [ "$2" = ok ] || failed=1
}

run() { # step cmd... ; output to $OUT/<step>.log
  local step=$1
  shift
  timeout "$STEP_TIMEOUT" "$@" </dev/null >"$OUT/$step.log" 2>&1
}

# The last JSON object in a log that has the given key; OpenClaw prints log lines around its JSON.
json_from() { # log key out
  python3 - "$@" <<'PY'
import json, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
doc, start = None, text.find("{")
while start != -1:
    try:
        obj, end = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        start = text.find("{", start + 1)
        continue
    if isinstance(obj, dict) and sys.argv[2] in obj:
        doc = obj
    start = text.find("{", start + end)
json.dump(doc, open(sys.argv[3], "w"), indent=2)
PY
}

openclaw_version=$(openclaw --version 2>/dev/null | head -1)
record "openclaw version" ok "${openclaw_version:-unknown}"

# 1. OpenClaw's plugin validator, on the package as published. Its errors go to the baseline comparison.
pkg=/tmp/sentrook-pkg
mkdir -p "$pkg" && tar -xzf /pkg/sentrook.tgz -C "$pkg"
run validate openclaw plugins validate --root "$pkg/package" --json
validate_rc=$?
json_from "$OUT/validate.log" valid "$OUT/plugin-validate.json"
detail=$(python3 - "$OUT/plugin-validate.json" "$validate_rc" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
if not isinstance(doc, dict):
    print(f"FAIL\tno JSON report (exit {sys.argv[2]})")
else:
    errors = doc.get("errors") or []
    print(f"ok\tvalid={doc.get('valid')}, {len(errors)} errors (compared with the baseline)")
PY
)
record validate "${detail%%$'\t'*}" "${detail#*$'\t'}"

# 2. Credentials (guide step 2) and conversation access (step 3), before installing.
mkdir -p "$STATE"
printf 'SENTROOK_SCAN_CLIENT_ID=%s\nSENTROOK_SCAN_CLIENT_SECRET=%s\n' \
  "$CLIENT_ID" "${COMPAT_CLIENT_SECRET:-$CLIENT_SECRET}" >>"$STATE/.env"
chmod 600 "$STATE/.env"
if run credentials sh -c '
    openclaw config set plugins.entries.sentrook.config.clientId --ref-provider default --ref-source env --ref-id SENTROOK_SCAN_CLIENT_ID &&
    openclaw config set plugins.entries.sentrook.config.clientSecret --ref-provider default --ref-source env --ref-id SENTROOK_SCAN_CLIENT_SECRET &&
    openclaw config set plugins.entries.sentrook.hooks.allowConversationAccess true &&
    openclaw config set plugins.entries.sentrook-compat-probe.hooks.allowConversationAccess true'; then
  record credentials ok "in .env, SecretRefs and conversation access set with openclaw config set"
else
  record credentials FAIL "openclaw config set failed (see credentials.log)"
fi

# 3. Install from the archive, as the guide's npm install does, and enable.
if run install sh -c 'openclaw plugins install /pkg/sentrook.tgz --force --accept-capabilities &&
    openclaw plugins enable sentrook'; then
  if grep -q 'Installed plugin: sentrook' "$OUT/install.log"; then
    record install ok "installed and enabled"
  else
    record install FAIL "install exited 0 without 'Installed plugin: sentrook' (see install.log)"
  fi
else
  record install FAIL "openclaw plugins install or enable exited non-zero (see install.log)"
fi

# The seam probe, installed next to Sentrook.
cp -r /compat/probe /tmp/sentrook-compat-probe
if ! run probe-install sh -c 'openclaw plugins install /tmp/sentrook-compat-probe --force --accept-capabilities &&
    openclaw plugins enable sentrook-compat-probe'; then
  record probe-install FAIL "could not install the seam probe (see probe-install.log)"
fi

# 4. Loaded, with its hooks and commands.
run inspect openclaw plugins inspect sentrook --runtime --json
json_from "$OUT/inspect.log" plugin "$OUT/inspect.json"
detail=$(python3 - "$OUT/inspect.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
p = (doc or {}).get("plugin") or {}
problems = []
if p.get("status") != "loaded":
    problems.append(f"status {p.get('status')!r}: {p.get('error') or ''}".strip())
if not p.get("enabled"):
    problems.append("not enabled")
if not p.get("hookCount"):
    problems.append("no hooks registered")
if "sentrook" not in (p.get("commands") or []):
    problems.append("the /sentrook command is not registered")
print(("FAIL\t" + "; ".join(problems)) if problems else
      f"ok\t{p.get('version')} loaded, {p.get('hookCount')} hooks, {len(p.get('commands') or [])} commands")
PY
)
record load "${detail%%$'\t'*}" "${detail#*$'\t'}"

# 5. OpenClaw's diagnostics for the plugin (an unknown or blocked hook shows only here). With the validator's
# errors they make validate.json, which run.sh compares with the baseline.
run doctor openclaw plugins doctor --json
json_from "$OUT/doctor.log" diagnostics "$OUT/doctor.json"
detail=$(python3 - "$OUT/doctor.json" "$OUT/plugin-validate.json" "$OUT/validate.json" <<'PY'
import json, sys
doctor = json.load(open(sys.argv[1]))
validate = json.load(open(sys.argv[2]))
warnings = [f"validate: {e}" for e in ((validate or {}).get("errors") or [])]
if isinstance(doctor, dict):
    for e in doctor.get("pluginErrors") or []:
        if e.get("pluginId") == "sentrook":
            warnings.append(f"doctor error: {e.get('message') or e.get('error')}")
    for d in doctor.get("diagnostics") or []:
        if d.get("pluginId") == "sentrook":
            warnings.append(f"doctor {d.get('level')}: {d.get('message')}")
    for c in doctor.get("compatibility") or []:
        if c.get("pluginId") == "sentrook":
            warnings.append(f"doctor {c.get('severity')} {c.get('code')}: {c.get('message')}")
json.dump({"warnings": warnings}, open(sys.argv[3], "w"), indent=2)
if not isinstance(doctor, dict):
    print("FAIL\tno JSON report from openclaw plugins doctor")
else:
    print(f"ok\t{len(warnings)} reports for sentrook (compared with the baseline)")
PY
)
record doctor "${detail%%$'\t'*}" "${detail#*$'\t'}"

# The mock identity service, scanner and model.
python3 /shared/mock_services.py --port "$MOCK_PORT" --log "$OUT/mock.jsonl" \
  --client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET" --tool exec &
for _ in $(seq 50); do
  python3 -c "import urllib.request; urllib.request.urlopen('$MOCK/healthz', timeout=1)" 2>/dev/null && break
  sleep 0.2
done
export SENTROOK_DEV_ENDPOINTS=1 SENTROOK_SCAN_URL="$MOCK" SENTROOK_ROOKERY_URL="$MOCK" SENTROOK_OIDC_ISSUER="$MOCK"

# 6. verify: endpoints, credentials, scanner health, token mint.
if run verify openclaw sentrook verify; then
  record verify ok "all checks pass"
else
  rc=$?
  record verify FAIL "exit $rc: $(grep '^FAIL' "$OUT/verify.log" | tr '\n' ';' | cut -c1-300)"
fi

# 7. status.
if run status openclaw sentrook status && grep -q '^Sentrook plugin' "$OUT/status.log"; then
  record status ok "$(grep -m1 '^Sentrook plugin' "$OUT/status.log")"
else
  record status FAIL "status failed (see status.log)"
fi

# 8. One agent turn through the real agent loop: the model asks for two exec calls; Sentrook's before_tool_call
# must block the first and allow the second.
if ! run turn-config sh -c "
  openclaw config set models.providers.compat '{\"baseUrl\":\"$MOCK/v1\",\"apiKey\":\"compat-model-key\",\"api\":\"openai-completions\",\"models\":[{\"id\":\"compat-mock\",\"name\":\"compat mock\",\"reasoning\":false,\"input\":[\"text\"],\"contextWindow\":32000,\"maxTokens\":2048}]}' --strict-json &&
  openclaw config set agents.defaults.model.primary compat/compat-mock &&
  openclaw config set tools.exec.security full && openclaw config set tools.exec.ask off"; then
  record turn-config FAIL "could not point OpenClaw at the mock model (see turn-config.log)"
fi
rm -f "$BLOCKED_FILE" "$ALLOWED_FILE"
(cd /tmp && run turn openclaw agent --local --agent main --session-id sentrook-compat -m "Run the compatibility steps.")
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
    problems.append(f"openclaw agent exited {rc}")
if "compat turn done" not in open(turn_log, errors="replace").read():
    problems.append("the agent did not finish the turn")
if len(scans) < 2:
    problems.append(f"{len(scans)} scans sent, expected one per exec call (2)")
if any(not s.get("authed") for s in scans):
    problems.append("a scan was sent without a bearer token")
if not any(s.get("enforced") == "block" and s.get("tool") == "exec" for s in scans):
    problems.append("no exec call was scanned and blocked")
if os.path.exists(blocked):
    problems.append("the blocked exec call ran")
if not os.path.exists(allowed):
    problems.append("the allowed exec call did not run")
print(("FAIL\t" + "; ".join(problems)) if problems else f"ok\t{len(scans)} scans; block held, allow ran")
PY
)
record turn "${turn_detail%%$'\t'*}" "${turn_detail#*$'\t'}"

# 9. The host fields Sentrook reads without a documented contract. A second turn in the same session gives
# before_prompt_build a history with the owner's message in it.
(cd /tmp && run turn-2 openclaw agent --local --agent main --session-id sentrook-compat -m "Thanks.")
detail=$(python3 /compat/seams.py "$COMPAT_PROBE_OUT")
record seams "${detail%%$'\t'*}" "${detail#*$'\t'}"

exit "$failed"
