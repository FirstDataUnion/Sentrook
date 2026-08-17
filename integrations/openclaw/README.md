# Sentrook OpenClaw integration

Thin TypeScript plugin that scans every `before_tool_call` against **hosted**
Sentrook (`https://sentrook.firstdataunion.org`).

## How it works

On each `before_tool_call`, the plugin builds a short **PlanIR** trajectory
(recent tool calls in the session plus the pending action) and `POST`s it to
`/scan`. The pending step is the tool under review.

The plugin waits for the decision and maps **allow** / **review** / **block** to
OpenClaw continue / approval UI / veto.

PlanIR is always scrubbed before egress (not configurable). Optional review
feedback can `POST /feedback` with a sanitized resolution for the community
corpus (human-gated publish).

For the bigger picture (layers, privacy, community contribution) see the root
[README — How it works](../../README.md#how-it-works).

## Install

Requires **OpenClaw ≥ 2026.6.0** (`before_tool_call` + `requireApproval`; feature
landed in 2026.3.28, tested from 2026.6.0).

Package: [`@firstdataunion/sentrook-openclaw`](https://www.npmjs.com/package/@firstdataunion/sentrook-openclaw)
on public npmjs — no `.npmrc` or GitHub token.

```bash
# 1. Install (tracks npm latest — see Updates below)
openclaw plugins install npm:@firstdataunion/sentrook-openclaw

# 2. Configure (OIDC + defaults)
openclaw sentrook configure

# 3. Restart gateway (reload ~/.openclaw/.env + plugin config)
# 4. Verify (includes a live client_credentials mint against FIDU Identity)
openclaw sentrook verify

# 5. Ask the agent to run a tool, then confirm [sentrook-openclaw] scan lines
#    in the gateway logs (verify does not replace an end-to-end tool call)
```

Docker Compose (typical VPS layout):

```bash
cd ~/openclaw
docker compose exec openclaw-gateway \
  openclaw plugins install npm:@firstdataunion/sentrook-openclaw
docker compose exec openclaw-gateway openclaw sentrook configure
docker compose restart openclaw-gateway
docker compose exec openclaw-gateway openclaw sentrook verify
# Then exercise a tool call and:
docker compose logs -f openclaw-gateway 2>&1 | grep --line-buffered sentrook-openclaw
```

### Updates

```bash
openclaw plugins update @firstdataunion/sentrook-openclaw
# or: openclaw plugins update --all
# then restart the gateway
```

OpenClaw does not auto-update plugins on restart. Prefer staying on `latest`
unless you deliberately pin a version for a frozen host.

## Configure

### Wizard (preferred)

```bash
openclaw sentrook configure
```

Interactive flow:

1. Accept defaults for scan URL / timeout (or override)
2. Community corpus: contribute sanitized allow-once/deny reviews by default
   (opt out with `n`, or later `feedback.mode: "off"` / `--contribute-corpus false`)
3. Paste FIDU ID OAuth `client_id` + `client_secret` (link printed in the wizard)
4. Writes credentials + patches `plugins.entries.sentrook-openclaw`
5. Prints reload instructions — **does not restart the gateway**

PlanIR is always scrubbed (not prompted).

### Non-interactive

For CI / scripted hosts (skips the wizard):

```bash
openclaw sentrook configure --non-interactive \
  --client-id "$SENTROOK_SCAN_CLIENT_ID" \
  --client-secret "$SENTROOK_SCAN_CLIENT_SECRET"
# optional: --url --timeout-ms --contribute-corpus false
```

Then restart the gateway and run `openclaw sentrook verify`.

### CLI reference

| Command | Purpose |
|---------|---------|
| `openclaw sentrook configure` | Credentials + plugin entry (interactive or `--non-interactive`) |
| `openclaw sentrook verify` | Confirm plugin config, credentials, and scan connectivity |
| `openclaw sentrook allowlist list\|path\|clear --yes` | Inspect / wipe local allow-always store |

## Configuration

Configure does **not** restart the gateway — do that yourself after the first
setup or after credential changes.

### What configure writes

| Location | Contents |
|----------|----------|
| `~/.openclaw/.env` | `SENTROOK_SCAN_CLIENT_ID` / `SENTROOK_SCAN_CLIENT_SECRET`. Prefer this over compose `env_file` so a normal **restart** reloads secrets |
| `~/.openclaw/openclaw.json` → `plugins.entries.sentrook-openclaw` | `enabled`, `url`, `timeoutMs`, `feedback`, and related plugin settings. **No** credentials in this file |

### Plugin settings

Useful knobs under `plugins.entries.sentrook-openclaw.config`:

| Setting | Default | Role |
|---------|---------|------|
| `url` | `https://sentrook.firstdataunion.org` (set by configure) | Scan service base URL |
| `timeoutMs` | `3000` | Bounds the `/scan` wait. On timeout or transport error the plugin follows `onScanError` — see [Timeouts](#timeouts) |
| `onScanError` | `allow` | `allow` (continue without scanning), `deny` (block the tool), or `review` (ask, interactive). Env: `SENTROOK_ON_SCAN_ERROR`. Hosted configure recommends `review`. |
| `feedback.mode` | `submit` (wizard default) | `submit` posts sanitized allow-once / deny reviews for the community corpus (human-gated publish). Opt out: wizard prompt, `--contribute-corpus false`, or `feedback.mode: "off"` |
| `allowlist.enabled` | `true` | Local short-circuit for “allow every time” — see [Allow every time](#allow-every-time-local-allowlist) |
| `allowlist.path` | `~/.openclaw/sentrook-allowlist.json` | Override store path |
| `approval.interactiveTimeoutMs` | `300000` (5 min) | Review timeout for interactive sessions (deny on timeout) |
| `approval.scheduledTimeoutMs` | `1800000` (30 min) | Review timeout for unattended cron / subagent runs |
| `approval.scheduledTimeoutBehavior` | `deny` | What happens when an unattended review times out (`deny` or `allow`) |

PlanIR is always scrubbed before egress. Decisions are always enforced (allow /
review / block) — there is no observe-only or sanitization-off toggle.

### Timeouts

Two different options:

1. **`timeoutMs` (scan)** — how long to wait for hosted `/scan`. If the request
   times out, cannot connect, returns 5xx, or is still rate-limited after one
   `Retry-After` retry, the plugin applies **`onScanError`**:
   - `allow` — continue the tool without scanning (legacy fail-open; default
     when the key is missing so existing installs do not change behaviour)
   - `deny` — block the tool
   - `review` — interactive `requireApproval` (“Sentrook is unreachable…” /
     rate-limit copy). Decisions are **allow-once** or **deny** only (no
     allow-always, no local allowlist, no `/feedback`). Cron/subagent does
     **not** wait the human-review window; it applies
     `approval.scheduledTimeoutBehavior` immediately (default deny).
   HTTP 401/403 always deny — bad credentials must not silently skip scans.
   This is *not* the same as a human-review timeout.
2. **`approval.*` (human review)** — after Sentrook returns `review`, how long
   to wait for allow / deny. Interactive and scheduled (cron / subagent) both
   **fail closed** (`deny`) by default. Opt into
   `approval.scheduledTimeoutBehavior: "allow"` only if unattended jobs must
   proceed without a human.

### Where secrets live (Docker vs native)

Configure writes `SENTROOK_SCAN_*` to **`~/.openclaw/.env`**. The plugin reads
them after OpenClaw loads that file at gateway start — the same pattern OpenClaw
recommends for provider API keys
([Environment variables](https://docs.openclaw.ai/help/environment)).

| Install | Credentials | Reload after configure |
| --- | --- | --- |
| Native / systemd | `~/.openclaw/.env` | `openclaw gateway restart` |
| Docker Compose | `~/.openclaw/.env` (bind-mounted) | `docker compose restart openclaw-gateway` |

Avoid putting Sentrook scan secrets **only** in a compose `env_file`
(`~/openclaw/.env`). Compose injects that file at container **create** time, so
credential changes need a recreate. State-dir `.env` reloads on a normal
**restart**.

Missing credentials → the plugin warns and soft-fails scans; the gateway stays up.

## Chat-channel approvals

When Sentrook returns **review**, the plugin asks OpenClaw for a human decision
(`allow-once` / `allow-always` / `deny`). If you talk to the agent over Discord,
Slack, Telegram, or similar, those prompts must be delivered on that channel —
otherwise the tool call waits on an approval you never see.

This is an **OpenClaw** setting; Sentrook configure does not set it for you.
Upstream:
[Approval forwarding to chat channels](https://docs.openclaw.ai/tools/exec-approvals-advanced#approval-forwarding-to-chat-channels)
and
[Plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests).

### Discord example

In `~/.openclaw/openclaw.json` (shape illustrative — keep your existing Discord
token / guild config):

```json5
{
  channels: {
    discord: {
      enabled: true,
      token: {
        // ...
      },
      execApprovals: {
        enabled: true,
        approvers: [
          "<your-discord-user-id>",
        ],
        target: "both",
        cleanupAfterResolve: false,
      },
    },
  },
}
```

Notes:

- The important part is the `execApprovals` block.
- Put **your** Discord user id in `approvers` — only listed approvers can
  allow / deny.
- `target: "both"` is a practical default so prompts can land in DM and in the
  originating chat (see OpenClaw’s docs for `dm` / `channel` / `both`).
- Restart the gateway after changing channel approval config.
- You can still resolve with `/approve <id> allow-once|allow-always|deny` when
  the channel falls back to text instructions.

### Other channels

Slack, Telegram, and others use the same idea under
`channels.<name>.execApprovals` (or channel-specific equivalents). You can also
forward plugin approvals via the shared `approvals.plugin` block — see the
OpenClaw docs linked above.

After changing approvals, trigger a tool call that Sentrook would `review` and
confirm the card or `/approve` prompt appears where you expect.

## Allow every time (local allowlist)

Sentrook `review` decisions surface OpenClaw’s approval UI (`allow-once` /
`allow-always` / `deny`). Hosted Sentrook does **not** keep a per-user personal
corpus, so “Allow every time” would otherwise re-prompt forever.

The plugin keeps a short-circuit list **locally** on the OpenClaw host:

1. Scan still always runs (`POST /scan`); Sentrook `block` is never overridden
2. On `allow-always`, the plugin records a local entry (and still posts
   `/feedback` when contribution is on)
3. On later matching `review`s, the plugin skips the approval prompt

Store: `~/.openclaw/sentrook-allowlist.json` (or
`$OPENCLAW_STATE_DIR/sentrook-allowlist.json`). Treat it like `openclaw.json` —
do not let the agent edit it unchecked.

Only entries recorded via the plugin’s `allow-always` handler are honoured;
hand-edited or poisoned JSON is ignored. Unexpected auto-allows show up in
gateway logs as `local allowlist hit`.

| Kind | When | Match |
| --- | --- | --- |
| `script_bind` | Interpreter + a concrete local script file | Same interpreter + path + **content hash**; script rewrite ⇒ re-prompt |
| `skeleton` | Other safe command shapes | Constrained argv skeleton; never bare `curl` / pipes / inline-eval |

```bash
openclaw sentrook allowlist path              # print resolved JSON path
openclaw sentrook allowlist list              # show entries
openclaw sentrook allowlist clear --yes       # wipe all entries
```

## Uninstall

```bash
openclaw plugins uninstall sentrook-openclaw
# Docker Compose: run the same inside the gateway container, then restart if needed
```

Removes the managed install and `plugins.entries.sentrook-openclaw`. Optional
manual purge afterwards:

- `SENTROOK_SCAN_*` lines in `~/.openclaw/.env`
- `~/.openclaw/sentrook-allowlist.json` (or `openclaw sentrook allowlist clear --yes` before uninstall)

## Verify & logs

Use the built-in verify command to confirm the plugin is installed, configured,
can mint an OIDC scan token, and can reach the scan service:

```bash
# native
openclaw sentrook verify

# Docker Compose
docker compose exec openclaw-gateway openclaw sentrook verify
```

Verify checks that `SENTROOK_SCAN_CLIENT_ID` / `SECRET` are present **and** that
FIDU Identity accepts a `client_credentials` mint (HTTP 401 here usually means
wrong secret, missing `client_credentials` grant, or missing `sentrook.scan`
scope on the OAuth client). `/health` alone does not prove that.

If credentials look fine in `~/.openclaw/.env` but verify says they are not
loaded in-process, restart the gateway and run verify again.

After a green verify, **still** have the agent run a tool call and watch the
gateway logs. Scans run only on **tool calls** — chat-only turns produce no
scan lines — and fail-open paths only show up live:

```bash
docker compose logs -f openclaw-gateway 2>&1 | grep --line-buffered sentrook-openclaw
```

Healthy traffic looks like timing / decision lines. `scan failed: … failing open`
means the tool proceeded without a Sentrook decision — fix auth or connectivity,
then retry a tool call.

## Privacy (plugin side)

The plugin **always** scrubs PlanIR before `POST /scan` and `/feedback` when set
up via configure. Pattern scrubbing catches credentials and common PII shapes; it
is **not** a full guarantee that no personal detail remains in free-form text.

On the hosted scan path, the execution plan is evaluated in memory and is **not**
stored as PlanIR. Opt-in review feedback is a separate path (derived intent +
human-gated community corpus) — see the root
[README — Privacy and community contribution](../../README.md#privacy-and-community-contribution).
