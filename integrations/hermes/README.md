# Sentrook × Hermes Agent

Thin Python plugin that scans tool calls against **hosted** Sentrook
(`https://sentrook.firstdataunion.org`) and maps allow / review / block onto
Hermes `pre_tool_call` directives (`approve` + `rule_key` for human review).

> **Status:** Phase 3 — scan loop live-validated; `hermes sentrook verify`, unit
> tests, and CI are in place. Community index / compose helpers remain deferred.

## Requirements

- Hermes Agent **≥ 0.18.2** (approve + `rule_key` + gateway Discord notify proven)
- Network reachability to hosted Sentrook
- Scan credentials in `~/.hermes/.env` (OIDC client or API key)

## Install (dev / until community index)

From a clone of this monorepo:

```bash
hermes plugins install FirstDataUnion/Sentrook/integrations/hermes/plugin --enable
# or symlink for local iteration:
#   ln -s /path/to/FIDU-Sentrook/integrations/hermes/plugin ~/.hermes/plugins/sentrook
#   hermes plugins enable sentrook
```

Then restart the gateway (or open a new CLI session) so hooks load.

```bash
hermes sentrook configure --client-id ... --client-secret ...
hermes sentrook verify
```

`verify` checks install path, `provides_hooks`, `plugins.enabled` /
`plugins.entries`, scan credentials, `GET /health`, and (when OIDC is
configured) a real client_credentials mint. Passing verify means the host is
**ready to cover** after a gateway restart — it cannot prove the live scan path
alone. Confirm with a tool call and `sentrook:` lines in
`~/.hermes/logs/agent.log`.

Flags: `--skip-health`, `--skip-mint` (offline / CI-friendly local checks).

Docker: install via `docker exec` into the container that mounts
`~/.hermes:/opt/data` — plugins live on the volume, not in the immutable image.

## Behaviour

| Scan decision | Hermes directive |
|---|---|
| allow | no directive |
| block | `{"action":"block","message":...}` |
| review | `{"action":"approve","message":...,"rule_key":"sentrook:<kind>:<digest>"}` |

On each `pre_tool_call` the plugin:

1. Builds PlanIR 1.0 from session trajectory + pending tool (`adapter: hermes`).
2. Sanitizes PlanIR (secret/PII scrub, session hash) before egress.
3. `POST`s to hosted `/scan` with OIDC or API-key auth from `~/.hermes/.env`.
4. Maps the decision to a Hermes directive; stashes pending state by `rule_key`
   for feedback join on `post_approval_response`.

### Host tool names → PlanIR (coverage-critical)

Hosted rules and L1 early-exit key on **shared PlanIR tool names** (the
OpenClaw vocabulary today), not on each host’s raw tool id. Hermes’s shell tool
is `terminal`; the corpus expects `exec`. The plugin **must** canonicalize
before egress (`terminal` → `exec`, including args aliases like `cmd` →
`command`).

A missed mapping fails **open and quietly**: `/scan` returns allow with
“No matching rules. Early exit at Layer 1.” — verify/health still look fine,
but shell/exfil coverage is effectively off. Live incident (2026-08-25): exfil
`curl … -d @~/.hermes/.env` was allowed until the mapping landed; afterward the
same shape hit AIRA rules and **blocked**.

When adding support for another Hermes tool, add an explicit PlanIR alias + a
regression test that asserts the emitted `steps[].tool` (do not teach the
corpus host-specific names unless product deliberately expands the vocabulary).

Unattended (`HERMES_CRON_SESSION`, `platform=cron|subagent`, subagent child
sessions, YOLO / `approvals.mode: off`, or non-TTY CLI without a chat
platform): **block** on review and on scan-error-when-`on_scan_error=review`
— do not escalate. Under YOLO Hermes would otherwise auto-approve plugin
`approve` directives, so Sentrook treats that as unattended and blocks
instead. Discord / Telegram / other gateway chat platforms are **attended**
even when the gateway process has no TTY. Platform comes from Hermes
`gateway.session_context.get_session_env("HERMES_SESSION_PLATFORM")` (task-local
ContextVar) — not from process `os.environ`, which the gateway no longer uses
for concurrent messaging. `subagent_start` marks `child_session_id` so child
tool calls stay unattended even when the parent ContextVar is still Discord.

`on_scan_error` default is **review** (interactive only). Set `allow` or `deny`
in plugin settings or `SENTROOK_ON_SCAN_ERROR`. **401/403 always deny.**

Approval card copy: scrubbed local command excerpt in `message` (Hermes shows
`<tool> (plugin approval rule)` as the title).

Feedback join: match `post_approval_response.pattern_key` after stripping
`plugin_rule:`; `tool_call_id` is empty on the gateway path. Best-effort
`POST /feedback` when `feedback_mode=submit` (default). Hosted **dev** may
return `skipped` / feedback disabled — that is expected; do not enable Rookery
feedback on shared hosts just to watch traffic. Wire shape is covered by
mocked unit tests (`test_feedback_wire.py`).

Session cleanup: `on_session_finalize` / `on_session_reset` only —
**not** `on_session_end` (fires every turn).

## Configuration

Plugin settings (`plugin.yaml` / `plugins.entries.sentrook.settings`):

| Setting | Default | Env override |
|---|---|---|
| `scan_base_url` | `https://sentrook.firstdataunion.org` | `SENTROOK_SCAN_BASE_URL` |
| `timeout_ms` | `60000` | `SENTROOK_SCAN_TIMEOUT_MS` |
| `on_scan_error` | `review` | `SENTROOK_ON_SCAN_ERROR` |
| `feedback_mode` | `submit` | `SENTROOK_FEEDBACK_MODE` |

Credentials (not in settings JSON): `SENTROOK_SCAN_CLIENT_ID` +
`SENTROOK_SCAN_CLIENT_SECRET` (preferred) or `SENTROOK_SCAN_API_KEY` in
`~/.hermes/.env`.

## Layout

```text
integrations/hermes/
  README.md
  plugin/
    plugin.yaml
    __init__.py          # register(ctx) + hooks + scan loop
    verify.py            # hermes sentrook verify checks
    planir.py            # PlanIR builder (terminal ≈ exec)
    sanitize.py          # egress scrub (OpenClaw parity)
    auth.py              # OIDC + API key (~/.hermes/.env)
    scan_client.py       # POST /scan, /feedback, /latency
    scan_error_policy.py
    review_copy.py
    rule_key.py
    intent.py
    approval_map.py
    config.py
    cli.py
    scan_endpoint.py
    tests/
```

OpenClaw twin: `integrations/openclaw/`. Sanitize golden fixtures are shared
from `integrations/openclaw/plugin/fixtures/sanitize/`.

Run plugin unit tests from the repo root:

```bash
make hermes-plugin-test
# or: PYTHONPATH=integrations/hermes python -m pytest integrations/hermes/plugin/tests -q
```

## Hermes vs OpenClaw differences

- **Gate:** Hermes `approve` + `rule_key`; no `requireApproval` card API.
- **Allowlist:** omitted — Hermes native once/session/always via `rule_key`.
- **Unattended review:** Hermes always **blocks** immediately; OpenClaw uses
  scheduled timeout policy.
- **Scan error default:** Hermes **review**; OpenClaw historically **allow**.
- **Session cleanup:** Hermes `on_session_finalize` / `on_session_reset`; OpenClaw
  `session_end`.
- **Tool naming:** Hermes `terminal` maps to OpenClaw `exec` for PlanIR args.

## Live validation status

Validated on Hermes **≥ 0.18.2** against **dev** hosted Sentrook (Discord
gateway + CLI). See the Notion page *Hermes Agent Plugin (Beta)* for the full
checklist.

**Proven:** install/rsync plugin, OIDC scan, `terminal`→`exec`, Discord attended
escalate (`get_session_env` platform), review → approve card (Once / Session /
Always / Deny), cron/subagent/YOLO / `approvals.mode: off` block without hang,
Always Allow `plugin_rule:sentrook:…` persistence across gateway restart.

### Deferred

- Second `pre_tool_call` plugin ordering (Hermes first-directive-wins).
- Parallel tool batches (N tools → N scans) load check.
- Community plugin index / compose helper suite.
- Always Allow **behavioral** retest on Discord after restart (config
  persistence already proven).
