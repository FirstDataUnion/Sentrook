# Sentrook × Hermes Agent

Thin Python plugin that scans tool calls against **hosted** Sentrook
(`https://sentrook.firstdataunion.org`) and maps allow / review / block onto
Hermes `pre_tool_call` directives (`approve` + `rule_key` for human review).

> **Status:** Phase 3 — scan loop live-validated; `hermes sentrook verify`, unit
> tests, and CI are in place. Public install via a **release-synced mirror repo**
> + community index remains to be wired (see Packaging below).

## Requirements

- Hermes Agent **≥ 0.18.2** (approve + `rule_key` + gateway Discord notify proven)
- Network reachability to hosted Sentrook
- Scan credentials in `~/.hermes/.env` (OIDC client or API key)

## Install

**Public (planned):** `hermes plugins install sentrook --enable` via the Hermes
community index, resolving to the release mirror
[`FirstDataUnion/Sentrook-hermes`](https://github.com/FirstDataUnion/Sentrook-hermes)
(plugin at root). Until the first promote + index entry land, use the monorepo
path below.

**Dev / beta (this monorepo is source of truth):**

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
OpenClaw vocabulary today), not on each host’s raw tool id. A missed mapping
fails **open and quietly**: `/scan` returns allow with “No matching rules.
Early exit at Layer 1.” — verify/health still look fine, but coverage for that
tool is effectively off.

Live incident (2026-08-25): Hermes `terminal` was emitted as `terminal` while
the corpus expects `exec`; an exfil `curl … -d @~/.hermes/.env` was **allowed**
until `terminal` → `exec` landed, then the same shape **blocked**.

Current Hermes → PlanIR mappings (`TOOL_NAME_ALIASES` / conditional logic in `planir.py`):

| Hermes tool | PlanIR tool | Arg notes |
|---|---|---|
| `terminal` | `exec` | `command` (aliases: `cmd`, `shell`, `script`, `line`, `code`) |
| `execute_code` | `exec` | `code` → `command` (Python sandbox still scanned as exec text) |
| `process` (`action`=`write`\|`submit`) | `exec` | `data` → `command` (stdin inject after background terminal) |
| `write_file` | `write` | `path` + `content` already canonical |
| `patch` | `edit` | `path` / `old_string` / `new_string` / V4A `patch` flattened into `content` |
| `send_message` | `message` | Unified multi-platform send → `text`; `target`/`channel` retained (not matched by YAIRA) |
| Host send twins (`yb_send_dm`, Feishu comment add/reply, …) | `message` | Same sink; body keys → `text` |
| `read_file` | `read` | trajectory / ingest shape |
| `web_extract` | `web_fetch` | URL fetch twin |

Passed through unchanged (no OpenClaw twin or lower priority today): `process`
(list/poll/log/wait/kill/close), `search_files`, `browser_*`, `computer_use`,
`delegate_task`, `mcp__*`, Home Assistant / kanban / desktop UI tools, etc.
Those still appear in PlanIR under Hermes names — Rookery rules that only key
on OpenClaw vocabulary will **not** match them until aliases or corpus
expansions land. See `ROOKERY-HERMES-TOOL-COVERAGE.md`.

When adding support for another Hermes tool, add an explicit
`TOOL_NAME_ALIASES` entry (or conditional branch) + a regression test that
asserts the emitted `steps[].tool` (do not teach the corpus host-specific
names unless product deliberately expands the vocabulary).

### Multi-plugin coexistence (Hermes host limitation)

Hermes runs **all** `pre_tool_call` hooks, then picks the **first** valid
`block` / `approve` directive. User plugins load in **alphabetical directory
name** order (`sorted(iterdir)`); there is **no priority API** (unlike OpenClaw
`priority: 10`).

Live Case A/B (2026-08-26): with only Sentrook enabled, review cards work.
With a second plugin whose directory sorts **before** `sentrook` and returns
`approve`/`block`, **only that plugin’s directive is applied** — Sentrook still
scans (and logs), but its directive is discarded. Operators who install other
security / approval plugins should ensure Sentrook’s directory name sorts
first (e.g. keep the install dir `sentrook`, not `zzz-sentrook`) or accept that
another plugin can shadow coverage. This is a Hermes platform constraint, not
something Sentrook can override.
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
in plugin settings or `SENTROOK_ON_SCAN_ERROR`. Applies to timeouts, transport
errors, 5xx, exhausted 429s, and **401/403 auth failures**. Auth never
fail-opens: `allow` still **blocks** on 401/403 so a misconfigured client
cannot silently skip scans. Interactive `review` escalates with a
configuration-error card (not a policy deny); unattended `review` blocks
with an agent-facing message that names the config/connectivity cause.

Approval card copy: Hermes only lets plugins set `approve.message` (Reason).
The host hardcodes Requested command to `<tool> (plugin approval rule)`, so
we pack OpenClaw-style body into Reason: hosted `Likely:` when present, then a
signal-aware scrubbed command excerpt (head/signals/tail for long argv), then
an allow/deny hint if space remains. Budget **300** (Discord Reason clip);
rule ids are omitted. Secrets are scrubbed before display.

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
| `timeout_ms` | `60000` | `SENTROOK_SCAN_TIMEOUT_MS` |
| `on_scan_error` | `review` | `SENTROOK_ON_SCAN_ERROR` |
| `feedback_mode` | `submit` | `SENTROOK_FEEDBACK_MODE` |

Scan origin is **pinned** in `scan_endpoint.py` (`https://sentrook.firstdataunion.org`)
— not configurable via settings/env/wizard (same threat model as OpenClaw).

Credentials (not in settings JSON): `SENTROOK_SCAN_CLIENT_ID` +
`SENTROOK_SCAN_CLIENT_SECRET` in `~/.hermes/.env` (OIDC only via configure).
Configure also writes `SENTROOK_OIDC_ISSUER` to match the plugin build's
pinned Identity env (`DEFAULT_OIDC_ISSUER` beside `SCAN_BASE_URL` in
`scan_endpoint.py` — *dev* Identity when scanning *dev* Sentrook).

`hermes sentrook configure` runs an interactive wizard (OpenClaw-style help
text) or `--non-interactive` with `--client-id` / `--client-secret`. Create
credentials on the same Identity host the plugin defaults to.

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
- **Auth failures (401/403):** both honor `on_scan_error` / `onScanError` for
  interactive `review` (never fail-open on `allow`).
- **Session cleanup:** Hermes `on_session_finalize` / `on_session_reset`; OpenClaw
  `session_end`.
- **Tool naming:** Hermes host tools map onto OpenClaw PlanIR names via
  `TOOL_NAME_ALIASES` (`terminal`/`execute_code` → `exec`, `write_file` →
  `write`, `patch` → `edit`, …).
- **Multi-plugin gate:** Hermes first-directive-wins (alpha dir order); OpenClaw
  supports explicit hook priority.

## Live validation status

Validated on Hermes **≥ 0.18.2** (live Discord/CLI path exercised against
**dev** hosted Sentrook during beta). Plugin builds now pin **production**
`SCAN_BASE_URL` / `DEFAULT_OIDC_ISSUER` in `scan_endpoint.py`. See the Notion
page *Hermes Agent Plugin (Beta)* for the full checklist.

**Proven:** install/rsync plugin, OIDC scan, `terminal`→`exec`, Discord attended
escalate (`get_session_env` platform), review → approve card (Once / Session /
Always / Deny), cron/subagent/YOLO / `approvals.mode: off` block without hang,
Always Allow `plugin_rule:sentrook:…` persistence across gateway restart,
scan-error `review` on auth failure, multi-plugin Case A (Sentrook first) /
Case B (earlier plugin shadows Sentrook — documented limitation).

## Packaging / release (locked)

| Layer | Role |
|---|---|
| `integrations/hermes/plugin/` (this repo) | Source of truth — develop, test, VPS iterate |
| [`FirstDataUnion/Sentrook-hermes`](https://github.com/FirstDataUnion/Sentrook-hermes) | Install-only mirror — plugin at **repo root** |
| `hermes-plugin-index` | Bare name `sentrook` → mirror + pinned release SHA (`subdir` null) |

Mirror is **not** continuous sync from `main`. Promote only when releasing via
gated workflow [`.github/workflows/release-hermes-plugin.yml`](../../.github/workflows/release-hermes-plugin.yml)
(Environment `release-hermes`, secret `MIRROR_GITHUB_TOKEN`) — same idea as
OpenClaw’s `release-plugin.yml` → npm.

**Mirror lockdown (current):** **public** install mirror; issues/projects/wiki/discussions
off; Actions disabled on the mirror; README/CONTRIBUTING/SECURITY/PR template +
issue contact links redirect to upstream. Branch ruleset on `main` and tag
ruleset on `hermes-plugin-v*` block deletion/force-push and restrict updates to
org-admin bypass (used by gated CI). Prefer a **fine-grained PAT** (Contents
write on `Sentrook-hermes` only) over enabling org-wide deploy keys.

**Before first promote:** create that PAT →
`gh secret set MIRROR_GITHUB_TOKEN --repo FirstDataUnion/Sentrook --env release-hermes`.

**Promote:** Actions → `release-hermes-plugin` → approve `release-hermes` →
optional dry_run first. Then bump the community index pin to the new mirror
tag/SHA.

### Deferred

- Broader PlanIR aliases (`process` write/submit done; remaining `browser_*`,
  `mcp__*`, … as corpus needs).
- Engine YAIRA gaps (track in Sentrook issues / coverage brief §6):
  `pending_tool` pipe OR, `args_match` key alternates, `mcp__*` prefix match.
- First promote + community index entry (mirror public + rulesets + workflow exist; needs `MIRROR_GITHUB_TOKEN`).
- Compose helper suite.