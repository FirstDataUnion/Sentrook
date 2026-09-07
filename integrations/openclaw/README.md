# Sentrook OpenClaw integration

Thin TypeScript plugin that scans every `before_tool_call` against **hosted**
Sentrook (`https://sentrook.firstdataunion.org`).

## How it works

On each `before_tool_call`, the plugin builds a short **PlanIR** trajectory
(recent tool calls in the session plus the pending action) and `POST`s it to
`/scan`. The pending step is the tool under review.

The plugin waits for the decision and maps **allow** / **review** / **block** to
OpenClaw continue / approval UI / veto. Review cards are rebuilt from **local**
pending args (secret-scrubbed): a shell command when present, otherwise a
compact action/session preview so `process log` is still decidable. OpenClaw
shows `title` as **Command** (80 chars) and `description` as **Shell Preview**
(512). Copy uses a structural ladder (destination / sensitive path / packed
argv or structured args) rather than rule ids. `process` write/submit/start/spawn
are sent to scan as `exec` so command rules apply; poll/log/wait/kill stay as
`process`. Hosted `/scan` still receives length-bounded PlanIR.

PlanIR is always scrubbed before egress (not configurable). Optional review
feedback can `POST /feedback` with a sanitized resolution for the community
corpus (human-gated publish).

Operators can inspect pending reviews and history with `/sentrook` in chat
(owner-only; bare command is a snapshot, `/sentrook help` lists verbs) or open
`/sentrook` on the gateway (same port as Control UI).
See [Operator dashboard](#operator-dashboard) and
[`/sentrook` chat commands](#sentrook-chat-commands).

For the bigger picture (layers, privacy, community contribution) see the root
[README — How it works](../../README.md#how-it-works).

## Install

Requires **OpenClaw ≥ 2026.6.0** (`before_tool_call` + `requireApproval`; feature
landed in 2026.3.28, tested from 2026.6.0).

Package: [`@firstdataunion/sentrook-openclaw`](https://www.npmjs.com/package/@firstdataunion/sentrook-openclaw)
on public npmjs — no `.npmrc` or GitHub token.

```bash
# 1. Install (tracks npm latest — see Updates below)
#    npm: is an arbitrary source. Interactive installs prompt; noninteractive
#    (Docker compose exec) needs --force after you trust the package.
openclaw plugins install npm:@firstdataunion/sentrook-openclaw --force

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
  openclaw plugins install npm:@firstdataunion/sentrook-openclaw --force
docker compose exec openclaw-gateway openclaw sentrook configure
docker compose restart openclaw-gateway
docker compose exec openclaw-gateway openclaw sentrook verify
# Then exercise a tool call and:
docker compose logs -f openclaw-gateway 2>&1 | grep --line-buffered sentrook-openclaw
```

`openclaw-gateway` is the default Compose **service** name in OpenClaw's
official `docker-compose.yml`. The running **container** is often named
`openclaw-gateway-1` or `{project}-openclaw-gateway-1`. If a command fails
with "no such service", run `docker compose ps` from your compose project
and substitute the service name shown there. Helper scripts honour
`OPENCLAW_GATEWAY_SERVICE` when yours is not the default.

### Updates

```bash
openclaw plugins update @firstdataunion/sentrook-openclaw
# or: openclaw plugins update --all
# then restart the gateway
```

OpenClaw does not auto-update plugins on restart. Prefer staying on `latest`
unless you deliberately pin a version for a frozen host. First-time npm
installs from an arbitrary source need `--force` in noninteractive shells;
tracked `plugins update` does not.

## Configure

### Wizard (preferred)

```bash
openclaw sentrook configure
```

Interactive flow:

1. Accept the default scan timeout (or override)
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
# optional: --timeout-ms --contribute-corpus false
```

Then restart the gateway and run `openclaw sentrook verify`.

### CLI reference

| Command | Purpose |
|---------|---------|
| `openclaw sentrook configure` | Credentials + plugin entry (interactive or `--non-interactive`) |
| `openclaw sentrook verify` | Confirm plugin config, credentials, and scan connectivity |
| `openclaw sentrook allowlist list\|path\|clear --yes` | Inspect / wipe local allow-always store |

Chat (owner-only, not the CLI): `/sentrook` — see
[`/sentrook` chat commands](#sentrook-chat-commands). Gateway panel: `/sentrook`
on the Control UI port — see [Operator dashboard](#operator-dashboard).

## Configuration

Configure does **not** restart the gateway — do that yourself after the first
setup or after credential changes.

### What configure writes

| Location | Contents |
|----------|----------|
| `~/.openclaw/.env` | `SENTROOK_SCAN_CLIENT_ID` / `SENTROOK_SCAN_CLIENT_SECRET`. Prefer this over compose `env_file` so a normal **restart** reloads secrets |
| `~/.openclaw/openclaw.json` → `plugins.entries.sentrook-openclaw` | `enabled`, `timeoutMs`, `feedback`, and related plugin settings. **No** credentials or scan URL in this file |

### Plugin settings

The scan / feedback origin is **pinned in plugin code**
(`scanEndpoint.ts` → `SCAN_BASE_URL` = `https://sentrook.firstdataunion.org`).
It is not read from `openclaw.json` or `SENTROOK_SCAN_URL`. Self-hosted forks
change that constant and rebuild.

Useful knobs under `plugins.entries.sentrook-openclaw.config`:

| Setting | Default | Role |
|---------|---------|------|
| `timeoutMs` | `14000` | Wait for `POST /scan` including OIDC mint. Default stays inside OpenClaw 2.0's 15s fail-closed hook. Env: `SENTROOK_SCAN_TIMEOUT_MS`. Raising this also raises the plugin-authored hook budget (host cap 10 min). |
| `onScanError` | `review` | `allow` (continue without scanning), `deny` (block the tool), or `review` (ask, interactive; unattended blocks). Env: `SENTROOK_ON_SCAN_ERROR`. Set `allow` only if the agent must proceed when Sentrook is unreachable (auth failures still block). |
| `feedback.mode` | `submit` after configure | `submit` posts sanitized allow-once / deny reviews for the community corpus (human-gated publish). The wizard default is `submit`. If you enable the plugin without configure, feedback stays `off`. Opt out: wizard prompt, `--contribute-corpus false`, or `feedback.mode: "off"` |
| `allowlist.enabled` | `true` | Local short-circuit for “allow every time” — see [Allow every time](#allow-every-time-local-allowlist) |
| `allowlist.path` | `~/.openclaw/sentrook-allowlist.json` | Override store path |
| `sensitivity` | `strict` | Attended review floor after hosted `review`: `strict` always prompts; `info` / `warning` / `critical` auto-approve that severity and below (legacy `lenient` = `info`). Includes hard L2 reviews. Never skips `block` or scan errors. Env: `SENTROOK_SENSITIVITY`. See [Session policy](#session-policy). |
| `unattendedSensitivity` | `strict` | Same floor for cron / subagent runs. Allow-all and quiet do not apply. Env: `SENTROOK_UNATTENDED_SENSITIVITY`. |
| `operatorLog.enabled` | `true` | Local JSONL history on the OpenClaw host. Env: `SENTROOK_OPERATOR_LOG=0` to disable. See [Operator log](#operator-log). |
| `operatorLog.path` | `$OPENCLAW_STATE_DIR/sentrook-operator.jsonl` | Override path. Env: `SENTROOK_OPERATOR_LOG_PATH`. |
| `operatorLog.maxAgeDays` | `14` | Drop lines older than this many days (`0` = no age purge). Env: `SENTROOK_OPERATOR_LOG_MAX_DAYS`. |
| `operatorLog.maxBytes` | `33554432` (32 MiB) | Rotate the live file near this size. Env: `SENTROOK_OPERATOR_LOG_MAX_BYTES`. |
| `approval.interactiveTimeoutMs` | `600000` (10 min) | Review timeout for interactive sessions. Capped at 10 min (OpenClaw 2.0). Deny on timeout. |
| `approval.scheduledTimeoutMs` | `600000` (10 min) | Review timeout for unattended cron / subagent runs. Same 10 min cap. |
| `approval.scheduledTimeoutBehavior` | `deny` | **Deprecated.** Unresolved reviews always deny. The key is still accepted so older configs load; `allow` is ignored. |

PlanIR is always scrubbed before egress. Decisions are always enforced (allow /
review / block) — there is no observe-only or sanitization-off toggle.

### Timeouts

Two different options. Both fail closed.

1. **`timeoutMs` (scan)** — how long to wait for hosted `POST /scan`, **including**
   OIDC discovery and token mint (default `14000`). Mint and scan share that
   budget so a hung Identity host cannot overrun OpenClaw 2.0's **15s**
   fail-closed `before_tool_call` wait. The plugin registers the hook with a 1s
   slack (`15000` by default). Raising `timeoutMs` also raises that hook budget
   (OpenClaw caps it at 10 minutes). Mint failures are scan errors (401/403
   never fail-open).

   If `/scan` times out, cannot connect, returns 5xx, is still rate-limited after
   one `Retry-After` retry, or returns HTTP 200 with invalid JSON or a missing /
   unknown `decision`, the plugin applies **`onScanError`**:
   - `allow` — continue the tool without scanning (explicit opt-in fail-open;
     auth failures still block)
   - `deny` — block the tool
   - `review` — interactive `requireApproval` (“Sentrook is unreachable…” /
     rate-limit / auth-config copy). Decisions are **allow-once** or **deny**
     only (no allow-always, no local allowlist, no `/feedback`). Cron/subagent
     **blocks** immediately on scan errors (same as Hermes). Default is
     `review`.
   Auth failures (HTTP 401/403, including a failed OIDC mint) never fail-open:
   `allow` still **blocks**. Interactive `review` escalates with a
   configuration-error card. This is *not* the same as a human-review timeout.
   Unexpected plugin errors in `before_tool_call` always **block** (not gated
   by `onScanError`).
2. **`approval.*` (human review)** — after Sentrook returns `review`, how long
   to wait for allow / deny. Interactive and scheduled (cron / subagent) both
   default to **10 minutes** and **always deny** if nobody answers (OpenClaw 2.0
   ignores `timeoutBehavior`). `approval.scheduledTimeoutBehavior: "allow"` is
   still accepted so older configs load; it has no effect.

### Where secrets live (Docker vs native)

Configure writes `SENTROOK_SCAN_*` to **`~/.openclaw/.env`**. The plugin reads
them after OpenClaw loads that file at gateway start — the same pattern OpenClaw
recommends for provider API keys
([Environment variables](https://docs.openclaw.ai/help/environment)).

| Install | Credentials | Reload after configure |
| --- | --- | --- |
| Native / systemd | `~/.openclaw/.env` | `openclaw gateway restart` |
| Docker Compose | `~/.openclaw/.env` (bind-mounted) | `docker compose restart openclaw-gateway` (default service name; see Install) |

Avoid putting Sentrook scan secrets **only** in a compose `env_file`
(`~/openclaw/.env`). Compose injects that file at container **create** time, so
credential changes need a recreate. State-dir `.env` reloads on a normal
**restart**.

Missing credentials: the plugin warns at register. Tool calls still hit `/scan`,
get HTTP 401, and follow the auth-failure path (never fail-open). The gateway
stays up.

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

## Operator dashboard

The plugin serves a panel at **`/sentrook` on the OpenClaw gateway** — same
port as Control UI (default **18789**). Auth is the gateway’s own
(`operator.admin`). If the host supports plugin Control UI tabs, a **Sentrook**
tab opens that path.

The page is server-rendered HTML (no extra port, no SPA), tabbed:

- **Reviews** (home) — pending cards with severity and risk, the run’s intent,
  a compact episode trail (last two calls, older history behind “Show earlier
  calls”) that ends on the pending command (dangerous spans highlighted),
  human-readable policy labels (not AIRA ids), session key (linked into
  Timeline), and allow / deny. The page polls `/api/state` and reloads only
  when pending reviews or timeline rows actually change; open timeline cards
  stay open across that reload.
- **Timeline** — the newest 100 scans from the [operator log](#operator-log)
  (live file, then `.1` if needed). Counts are for those loaded rows. Search,
  stream or per-session layout, expandable rows that lead with the command
  (or the URL for browser args), then decision, how it was resolved, tool,
  time (date when it is not today), session, and whether the call ran. Expand
  for scan (severity, risk, policy labels, dangerous spans in the command),
  decision (allowlist / you / timeout, and how long you waited), result
  (output, size, URLs and paths), extra arguments, and earlier calls in the
  same run. Filter by allow / review / block / error and session. Reviews
  link in with `?session=` and `#timeline`.
- **Allowlist** — local allow-always entries. A collapsed “How matchers work”
  note at the top explains skeleton vs script-bind. Remove one to start
  reviewing that shape again.
- **Settings** — allow-all (off / on for all; per-session toggles live in the
  table below) and quiet (global TTL or per session); attended and unattended
  sensitivity floors (strict / info / warning / critical, with lower levels
  highlighted); `feedback.mode` and `onScanError`; operator-log path, retention,
  max size, aged-line purge, and full delete. Allow-all and quiet stay in memory
  (cleared on restart). Sensitivity, feedback, scan-error policy, and log
  retention write into `plugins.entries.sentrook-openclaw.config` when the
  gateway can save `openclaw.json`. Scan origin and credentials are not editable
  here. Older `#sessions` / `#log` / `#set-sessions` hashes open Settings.

To iterate on layout without a running gateway, from `plugin/`:
`npm run preview:dashboard` (fixture data at http://127.0.0.1:3456).

Approve / deny calls OpenClaw `plugin.approval.resolve` so the waiting tool
actually continues. If the host has not minted a `plugin:` id yet, the panel
returns an error and tells you to use `/approve plugin:…` in chat.

Control UI plugin-tab cookies are **GET/HEAD only**. Buttons still POST; from
the sandboxed iframe that can 401. Direct bearer access to `/sentrook` (or
curl against the gateway) is the mutation path that always works. Keep
`/approve` in chat as the fallback.

## `/sentrook` chat commands

Owner-only (`requireAuth` + `operator.admin`). Replies are ordinary channel
messages (`{ text }`). In a **public** Discord/Telegram room anyone present can
read them — secrets are scrubbed, that is not a guarantee. Prefer a DM, a
private channel, or the [dashboard](#operator-dashboard).

| Command | What it does |
|---------|----------------|
| `/sentrook` | Snapshot: policy knobs + pending leads. Ends with `More commands: /sentrook help` |
| `/sentrook help` | Short catalog (same verbs as this table) + public-channel warning |
| `/sentrook status` | Policy knobs only (no pending list) |
| `/sentrook policy` | All settings with the same current-choice lines as the dashboard |
| `/sentrook pending [all\|id]` | This session; `all` = every card on the gateway; `<id>` = full scrubbed command |
| `/sentrook history [all\|gateway\|before <id>\|n\|id]` | Newest 8 (max 20) review/block/scan-error this session; `all` includes allows; `gateway` is every session; `before <id>` older page; `<id>` is the investigation |
| `/sentrook sessions` | Live session allow-all / quiet flags |
| `/sentrook allow-all [all\|session <key>] [on\|off]` | Skip future attended reviews. Bare = this session on. `all` = gateway-wide (`off` also clears every session flag). In-memory |
| `/sentrook quiet [all\|session <key>] <duration\|off>` | Same skip with a TTL (`30m`, `2h`, `8h` max). In-memory |
| `/sentrook sensitivity [attended\|unattended] [strict\|info\|warning\|critical]` | Persist the review floor (`lenient` = `info`). `critical` needs a trailing `confirm` |
| `/sentrook feedback [submit\|off]` | Persist whether sanitized reviews are posted to the community corpus |
| `/sentrook scan-error [review\|deny\|allow]` | Persist what happens when `/scan` fails. `allow` needs a trailing `confirm` |
| `/sentrook allowlist [rm n]` | List / remove a 1-based local allowlist entry |
| `/sentrook log [retention\|purge]` | Stats; `retention 7d` / `32MiB`; `purge confirm` / `purge all confirm` |

Every verb accepts `help` (or `?` / `-h`) as its first argument — options, scopes, and the value in effect right now. That in-chat page is the source of truth; this table is only the catalog. `/sentrook help` matches it.

Lists stay short: no AIRA ids, no matched-rule dumps, no full tool results.
`pending <id>` / `history <id>` is the investigation (command, hosted decision, what happened next, whether it ran). OpenClaw `/approve` is still how you resolve a card from chat (there is no `/sentrook allow`).

Allow-all and quiet do **not** resolve cards already waiting on `/approve`.
Turn them on, then still approve or deny the open ones.

## Session policy

After hosted Sentrook returns **`review`** only (scan still always `POST`s).
Order: local allowlist → (attended only) allow-all → quiet TTL → the matching
sensitivity floor (`review_severity` at or below `info` / `warning` /
`critical`). Attended and unattended floors are independent. Legacy `lenient`
is `info`. The floor includes **hard** L2 reviews: Layer 3 already ran on the
host, so a remaining `review` is eligible.

Never skipped: hosted **`block`**, **scan errors**. Unattended (cron/subagent)
reviews ignore allow-all and quiet; they follow `unattendedSensitivity`
instead. A matching local allowlist entry can still skip an unattended review.

Allow-all and quiet live in memory for the current gateway process (global
and/or per session). `session_end` clears that session’s flags; a restart
clears globals too. Sensitivity, unattended sensitivity, `feedback.mode`,
`onScanError`, and operator-log retention persist in
`plugins.entries.sentrook-openclaw.config`. Environment variables
(`SENTROOK_SENSITIVITY`, `SENTROOK_UNATTENDED_SENSITIVITY`,
`SENTROOK_FEEDBACK_MODE`, `SENTROOK_ON_SCAN_ERROR`, …) still win after a
restart. Sensitivity `critical` is the standing equivalent of allow-all for
that scope (still never block / scan-error).

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

Chat: `/sentrook allowlist` / `/sentrook allowlist rm n`. Dashboard: remove
from the Allowlist section.

## Operator log

A local JSONL history (`sentrook.operator.log/v1`) is **on by default**. It is
a product feature, not a maintainer debug dump.

| | |
| --- | --- |
| Path | `$OPENCLAW_STATE_DIR/sentrook-operator.jsonl` (usually `~/.openclaw/sentrook-operator.jsonl`) |
| Mode | `0600`, append-only |
| Retention | 14 days and 32 MiB (whichever bites first). Tune with `operatorLog.*` or `/sentrook log retention` |
| Payload | Full scrubbed command and result (no 500-char pack). Same secret/PII patterns as scan egress |
| Hook | Log I/O never fail-closes a tool call |

It is **never** uploaded to hosted Sentrook or Rookery. Opt-in `/feedback` is a
separate, human-gated path. Disable with `SENTROOK_OPERATOR_LOG=0` or
`operatorLog.enabled: false` if you want scans without on-disk history
(history is empty after restart either way).

`/sentrook history` and the dashboard timeline read this file. Gateway
`[sentrook-openclaw]` log lines are still the live scan trace — see
[Verify & logs](#verify--logs).

## Uninstall

```bash
openclaw plugins uninstall sentrook-openclaw
# Docker Compose: run the same inside the gateway container, then restart if needed
```

Removes the managed install and `plugins.entries.sentrook-openclaw`. Optional
manual purge afterwards:

- `SENTROOK_SCAN_*` lines in `~/.openclaw/.env`
- `~/.openclaw/sentrook-allowlist.json` (or `openclaw sentrook allowlist clear --yes` before uninstall)
- `~/.openclaw/sentrook-operator.jsonl` (and a `.1` rotate sibling if present)

## Verify & logs

Use the built-in verify command to confirm the plugin is installed, configured,
can mint an OIDC scan token, and can reach the scan service:

```bash
# native
openclaw sentrook verify

# Docker Compose (default service name; docker compose ps if yours differs)
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
scan lines — and `onScanError=allow` paths only show up live:

```bash
# default Compose service name; docker compose ps if yours differs
docker compose logs -f openclaw-gateway 2>&1 | grep --line-buffered sentrook-openclaw
```

Healthy traffic looks like timing / decision lines. `continuing without scan (onScanError=allow)`
means the tool proceeded without a Sentrook decision — that is opt-in; default
`review` will ask or block instead.

For a durable, queryable history of what the agent tried, use the
[operator log](#operator-log) (`/sentrook history` or the dashboard timeline) —
not only the gateway stream.

## Privacy (plugin side)

The plugin **always** scrubs PlanIR before `POST /scan` and `/feedback`.
Pattern scrubbing catches credentials and common PII shapes; it is **not** a
full guarantee that no personal detail remains in free-form text.

The **operator log** uses the same scrubbers and stays on the OpenClaw host.
It is never auto-uploaded. Chat `/sentrook` replies are scrubbed the same way
but are still ordinary channel messages. The **dashboard** shows unsanitized
local argv for pending cards — treat gateway access like `openclaw.json`.

On the hosted scan path, the execution plan is evaluated in memory and is **not**
stored as PlanIR. Opt-in review feedback is a separate path (derived intent,
matched-step slice, human-gated community corpus) — see the root
[README — Privacy and community contribution](../../README.md#privacy-and-community-contribution).
