# Sentrook × Hermes Agent

Thin Python plugin that scans every `pre_tool_call` against **hosted** Sentrook
(`https://sentrook.firstdataunion.org`) and maps allow / review / block onto
Hermes native approvals (`approve` + `rule_key`).

For the bigger picture (layers, privacy, community contribution) see the root
[README — How it works](../../README.md#how-it-works).

## Requirements

- **Hermes Agent ≥ 0.18.2** (plugin `approve` + `rule_key` + gateway chat
  approvals). The plugin declares `manifest_version: 1` so
  `hermes plugins install` works on that floor.
- Network reachability to `https://sentrook.firstdataunion.org`
- A free [FIDU account](https://firstdataunion.org) — `hermes sentrook configure`
  walks you through creating an OAuth client for the scan API

## Install

Package source:
[`FirstDataUnion/Sentrook-hermes`](https://github.com/FirstDataUnion/Sentrook-hermes)
(public install mirror; plugin at repo root).

```bash
# 1. Install and enable
hermes plugins install FirstDataUnion/Sentrook-hermes --enable

# 2. Interactive setup (OIDC credentials + defaults)
hermes sentrook configure

# 3. Restart the gateway (or open a new CLI session) so hooks load
#    native: hermes gateway restart

# 4. Sanity-check install, hooks, credentials, health, and OIDC mint
hermes sentrook verify

# 5. Ask the agent to run a tool, then confirm sentrook: lines in
#    ~/.hermes/logs/agent.log (verify does not replace an end-to-end tool call)
```

Docker: run the same `hermes plugins install` / `configure` / `verify` commands
via `docker exec` into the container that mounts `~/.hermes:/opt/data`. Plugins
live on that volume, not in the immutable image.

### Updates

Re-run install with `--force` (or remove + install) against
`FirstDataUnion/Sentrook-hermes`, then restart the gateway. Prefer a tagged
release when pinning a host.

> Community index bare-name install (`hermes plugins install sentrook`) is
> deferred until the plugin is listed in the Hermes plugin index.

## Configure

```bash
hermes sentrook configure
# or non-interactive:
hermes sentrook configure --non-interactive --client-id … --client-secret …
```

Writes `SENTROOK_SCAN_CLIENT_ID`, `SENTROOK_SCAN_CLIENT_SECRET`, and
`SENTROOK_OIDC_ISSUER` into `~/.hermes/.env`, and plugin settings into
`config.yaml`. Create credentials on the same Identity host the plugin pins
(production: `https://identity.firstdataunion.org`).

Scan origin is **pinned** in code to `https://sentrook.firstdataunion.org` — not
configurable via settings, env, or the wizard (same threat model as OpenClaw).

Missing credentials: the plugin warns at register. Tool calls still hit `/scan`,
get HTTP 401, and follow the auth-failure path (never fail-open).

### Settings

| Setting | Default | Env override |
|---|---|---|
| `timeout_ms` | `60000` | `SENTROOK_SCAN_TIMEOUT_MS` |
| `on_scan_error` | `review` | `SENTROOK_ON_SCAN_ERROR` |
| `feedback_mode` | `submit` | `SENTROOK_FEEDBACK_MODE` |

- **`timeout_ms`:** wait for `POST /scan` (default 60000). This does **not**
  include OIDC mint: discovery and token mint each have a **30s** cap, then
  `/scan` gets the full `timeout_ms`.
- **`on_scan_error`:** `allow` \| `deny` \| `review` when `/scan` times out,
  cannot connect, returns 5xx, is rate-limited, auth fails (401/403), or a
  200 body has invalid JSON / a missing or unknown `decision`.
  Auth never fail-opens: `allow` still **blocks** on 401/403.
  Unexpected plugin errors always **block**.
- **`feedback_mode`:** `submit` posts sanitized review resolutions to hosted
  `/feedback` for the community corpus; `off` disables that.

## How it behaves

| Scan decision | Hermes result |
|---|---|
| allow | continue (no directive) |
| block | tool call vetoed with a message |
| review | Hermes approval card (Once / Session / Always / Deny) |

On each tool call the plugin builds a scrubbed PlanIR trajectory, `POST`s
`/scan`, and applies the decision. Review **Reason** text includes a likely
intent line and a secret-scrubbed command excerpt (Hermes shows a synthetic
“Requested command” label for plugin rules; the real command is in Reason).

### Messaging channels

If you talk to Hermes over Discord / Telegram / Slack, ensure approval prompts
are delivered on that channel. Sentrook `review` becomes a Hermes plugin
approval; without channel delivery you can sit blocked on a prompt you never
see.

### Unattended sessions

Cron, subagents, YOLO / `approvals.mode: off`, and non-interactive CLI without
a chat platform **block** on review (and on scan-error-when-`review`) instead
of escalating — so headless runs never hang waiting for a human.

### Other security plugins

Hermes applies the **first** `block` / `approve` from `pre_tool_call` hooks
(plugins load in alphabetical directory order). Keep the install directory
named `sentrook` (not e.g. `zzz-sentrook`) if another approval plugin is also
enabled, or that other plugin can shadow Sentrook’s decision.

## Verify

```bash
hermes sentrook verify
# offline / CI-friendly:
hermes sentrook verify --skip-health --skip-mint
```

Checks install path, declared hooks, enablement, credentials, `GET /health`,
and (when OIDC is configured) a real client_credentials mint. Passing verify
means the host is ready to cover after a gateway restart — confirm with a real
tool call and log lines.

## Uninstall

```bash
hermes plugins uninstall sentrook
# Docker: run the same via docker exec, then restart the gateway
```

Then optionally remove `SENTROOK_SCAN_*` / `SENTROOK_OIDC_ISSUER` lines from
`~/.hermes/.env` and the `plugins.entries.sentrook` block in `config.yaml`.

## Privacy (plugin side)

The plugin **always** scrubs PlanIR before `POST /scan` and `/feedback`.
Pattern scrubbing catches credentials and common PII shapes; it is not a full
guarantee that no personal detail remains in free-form text.

On the hosted scan path, the execution plan is evaluated in memory and is not
stored as PlanIR. Opt-in review feedback is a separate path (derived intent,
matched-step slice, human-gated community corpus) — see the root
[README — Privacy and community contribution](../../README.md#privacy-and-community-contribution).

## Hermes vs OpenClaw (operators)

| | Hermes | OpenClaw |
|---|---|---|
| Install | `hermes plugins install FirstDataUnion/Sentrook-hermes` | `openclaw plugins install npm:@firstdataunion/sentrook-openclaw --force` |
| Gate | native Once / Session / Always / Deny | `requireApproval` cards |
| “Allow always” | Hermes approval store via `rule_key` | host + optional local allowlist |
| Unattended review | block immediately | 10 min wait, then deny |
| Scan error default | `review` | `review` |
| Scan timeout | `60000` | `14000` |

## Maintainers

Source of truth: `integrations/hermes/plugin/` in this monorepo. Public installs
are promoted to [`FirstDataUnion/Sentrook-hermes`](https://github.com/FirstDataUnion/Sentrook-hermes)
via `.github/workflows/release-hermes-plugin.yml` (Environment `release-hermes`).

```bash
make hermes-plugin-test
```

That target includes a publish-surface check (`plugin.yaml` version +
`provides_hooks` vs the tree promoted to the install mirror). It does not
load a live Hermes gateway — after a promote, install on a real instance and
exercise a tool call.

Release notes: [`plugin/CHANGELOG.md`](plugin/CHANGELOG.md).

PlanIR host→corpus tool aliases live in `plugin/planir.py`
(`TOOL_NAME_ALIASES`) and `plugin/tests/test_planir.py`.
