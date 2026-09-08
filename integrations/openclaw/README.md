# Sentrook OpenClaw integration

Thin TypeScript plugin that scans every `before_tool_call` against Sentrook
(`https://sentrook.firstdataunion.org`).

## How it works

On each `before_tool_call`, the plugin builds a short **PlanIR** trajectory
(recent tool calls in the session plus the pending action) and `POST`s it to
`/scan`. The pending step is the tool under review.

The plugin waits for the decision and maps **allow** / **review** / **block** to
OpenClaw continue / approval UI / veto. Review cards are rebuilt from **local**
pending args (secret-scrubbed): a shell command when present, otherwise a
compact action/session preview so `process log` is still decidable. OpenClaw
caps `title` at 80 characters and `description` at 512; chat channels usually
show both, while the Control UI overlay may prefer the tool invocation.
Copy uses a structural ladder (destination / sensitive path / packed
argv or structured args) rather than rule ids, and ends with a pointer to the
Sentrook tab or `/sentrook pending <id>`. `process` write/submit/start/spawn
are sent to scan as `exec` so command rules apply; poll/log/wait/kill stay as
`process`. `/scan` still receives length-bounded PlanIR.

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

Requires **OpenClaw ≥ 2026.6.0** for scanning (`before_tool_call` +
`requireApproval`). The **editable** Control UI dashboard needs **OpenClaw
≥ 2026.9.2** and is still beta — see [Operator dashboard](#operator-dashboard).

Package: [`@firstdataunion/sentrook-openclaw`](https://www.npmjs.com/package/@firstdataunion/sentrook-openclaw)
on public npmjs — no `.npmrc` or GitHub token.

```bash
# 1. Install (tracks npm latest — see Updates below)
#    npm: is an arbitrary source. Interactive installs prompt; noninteractive
#    (Docker compose exec) needs --force after you trust the package.
openclaw plugins install npm:@firstdataunion/sentrook-openclaw --force

# 2. Configure (OIDC + defaults) — CLI, or the Sentrook tab after restart
openclaw sentrook configure

# 3. Restart gateway (reload ~/.openclaw/.env + plugin config)
# 4. Verify (includes a live client_credentials mint against FIDU Identity)
openclaw sentrook verify

# 5. Ask the agent to run a tool, then confirm [sentrook-openclaw] scan lines
#    in the gateway logs (verify does not replace an end-to-end tool call)
```

From a git checkout of this plugin (editable dashboard on OpenClaw 2026.9.2):

```bash
cd integrations/openclaw/plugin
npm install
npm test
npm run build
# Copy the folder onto the gateway host, then:
openclaw plugins install /path/to/plugin --force
# Settings → Labs → Custom plugin UI, restart gateway, reload the browser.
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

After a ClawHub / Control UI install, restart the gateway, then open the
**Sentrook** tab. If scan credentials are missing, Reviews is a first-run form:
open [FIDU Identity](https://identity.firstdataunion.org), create a Sentrook
OAuth client, paste `client_id` / `client_secret`, choose feedback and
`onScanError`, then **Save and test**. That writes `~/.openclaw/.env` (chmod
600) — never `openclaw.json` — and mints against Identity in the same process.
Do not paste secrets into Control UI plugin Config (SecretRefs can fail-close
the gateway).

The CLI wizard is the same credentials path for scripts and terminals.

### Wizard (CLI)

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
| `sensitivity` | `strict` | Attended review floor after a `review`: `strict` always prompts; `info` / `warning` / `critical` auto-approve that severity and below (legacy `lenient` = `info`). Includes hard L2 reviews. Never skips `block` or scan errors. Env: `SENTROOK_SENSITIVITY`. See [Session policy](#session-policy). |
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

1. **`timeoutMs` (scan)** — how long to wait for `POST /scan`, **including**
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
(`allow-once` / `allow-always` / `deny`). The card uses the usual command
summary (title 80 / description 512). Chat channels typically show both.
OpenClaw’s in-browser overlay reuses exec-approval chrome and may show the
tool invocation instead of that description. Every description still ends
with a pointer to the **Sentrook** tab on the OpenClaw Control UI, or
`/sentrook pending <id>` for the full scrubbed command in chat. The tab has
the command and scan with no character limit. If you talk to the agent over
Discord, Slack, Telegram, or similar, those prompts must be delivered on
that channel — otherwise the tool call waits on an approval you never see.

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

Two Control UI entries can appear. Use **Sentrook** (native). Treat
**Sentrook (read-only)** as status plus command copy.

The **writable** dashboard is the native Control UI page. It needs
**OpenClaw 2026.9.2 or later** with **Settings → Labs → Custom plugin UI**
enabled (`gateway.controlUi.experimental.customPlugins: true`), then a gateway
restart and a browser reload.

That page runs in the Control UI origin, so allow / deny / settings save
through the signed-in operator session (`operator.write`). Pending reviews
refresh when the plugin emits a change (a new review, a resolve, a policy
save) — it does not poll.

### Where you can open the native page

Native plugin UI needs HTTPS or a browser-trusted loopback origin
(`http://127.0.0.1:18789/`). Plain HTTP on a LAN or public hostname can pair
and use the rest of Control UI, but cannot load native plugin pages.

| How you reach Control UI | Native Sentrook page |
| --- | --- |
| SSH tunnel / local forward to `127.0.0.1` | Works |
| Tailscale Serve or other HTTPS | Works |
| Reverse proxy with a real TLS cert | Works |
| `http://<lan-or-vps-ip>:18789` | Will not load native assets |

### Read-only iframe tab

The plugin still registers a **Sentrook (read-only)** Control UI tab that
loads `/sentrook` in a sandbox. It can show pending reviews, timeline,
allowlist, and current policy. It does not save: OpenClaw's iframe grant is
GET/HEAD with `operator.read` only. Each former button is replaced by the
`/sentrook` or `/approve` command that does the same job.

On OpenClaw older than 2026.9.2, or when Custom plugin UI is off, that tab
is the only dashboard. Change settings with those commands or
`openclaw sentrook …` on the CLI.

The HTTP panel at **`/sentrook`** (same port as Control UI, default **18789**)
is the same read-only view, including when you open the URL in a normal
browser.

The page is tabbed:

- **Reviews** (home) — native: when scan credentials are missing, a first-run
  form (Identity link, client id/secret, feedback, `onScanError`) instead of
  the empty queue. Iframe: point at `openclaw sentrook configure` instead of
  writing secrets. After setup: every waiting Sentrook approval OpenClaw still
  has open (`plugin.approval.list`), joined with the local pending stash and
  operator log. Cards show severity, command (dangerous spans highlighted),
  and human-readable policy labels (not AIRA ids). Native allow / deny calls
  `plugin.approval.resolve` so the waiting tool continues; iframe shows
  `/approve …`.
- **Timeline** — newest scans from the [operator log](#operator-log). Search
  and filters are local (they do not write).
- **Allowlist** — local allow-always entries. Native can remove one; iframe
  shows `/sentrook allowlist rm <n>`.
- **Settings** — allow-all and quiet; attended and unattended sensitivity;
  `feedback.mode` and `onScanError`; operator-log retention / purge; connection
  test. Native writes through session actions. Iframe shows the matching
  `/sentrook` / CLI lines.

To iterate on the fallback HTML without a running gateway, from `plugin/`:
`npm run preview:dashboard` (fixture data at http://127.0.0.1:3456;
`/unconfigured` is the first-run / configure hint).

If the host has not minted a `plugin:` id yet, native resolve returns an
error and tells you to use `/approve plugin:…` in chat.

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
| `/sentrook sessions` | OpenClaw sessions (Control UI store) plus in-memory allow-all / quiet flags |
| `/sentrook allow-all [all\|session <key>] [on\|off]` | Skip future attended reviews. Bare = this session on. `all` = gateway-wide (`off` also clears every session flag). In-memory |
| `/sentrook quiet [all\|session <key>] <duration\|off>` | Same skip with a TTL (`30m`, `2h`, `8h` max). In-memory |
| `/sentrook sensitivity [attended\|unattended] [strict\|info\|warning\|critical]` | Persist the review floor (`lenient` = `info`). `critical` needs a trailing `confirm` |
| `/sentrook feedback [submit\|off]` | Persist whether sanitized reviews are posted to the community corpus |
| `/sentrook scan-error [review\|deny\|allow]` | Persist what happens when `/scan` fails. `allow` needs a trailing `confirm` |
| `/sentrook allowlist [rm n]` | List / remove a 1-based local allowlist entry |
| `/sentrook log [retention\|purge]` | Stats; `retention 7d` / `32MiB`; `purge confirm` / `purge all confirm` |

Every verb accepts `help` (or `?` / `-h`) as its first argument — options, scopes, and the value in effect right now. That in-chat page is the source of truth; this table is only the catalog. `/sentrook help` matches it.

Lists stay short: no AIRA ids, no matched-rule dumps, no full tool results.
`pending <id>` / `history <id>` is the investigation (command, scan decision, what happened next, whether it ran). OpenClaw `/approve` is still how you resolve a card from chat (there is no `/sentrook allow`).

Allow-all and quiet do **not** resolve cards already waiting on `/approve`.
Turn them on, then still approve or deny the open ones.

## Manual operator checks

Run these after installing a plugin build (`npm run build` in `plugin/`,
`openclaw plugins install . --force`, gateway restart, browser reload). Prefer
a DM for `/sentrook`. Use loopback or HTTPS for the native page.

### Native Sentrook (writable)

Prerequisites: OpenClaw ≥ 2026.9.2, Labs → Custom plugin UI on, Control UI at
`http://127.0.0.1:18789/` (or HTTPS). Sidebar **Sentrook**, not
**Sentrook (read-only)**.

- [ ] Page loads with no "JSON-compatible" (or other) warning. Reviews /
      Timeline / Allowlist / Settings tabs match the original operator layout
      (severity hero + risk, episode spine, stream timeline, floor buttons,
      per-session allow-all/quiet).
- [ ] Empty reviews: "All clear". Missing credentials: first-run form writes
      `~/.openclaw/.env` via **Save and test**; Settings **Test connection**
      matches `openclaw sentrook verify`.
- [ ] Trigger a `review` tool call. Card shows command with dangerous-span
      highlighting (not AIRA ids), waiting age ticks, session link opens
      Timeline filtered to that session.
- [ ] **Allow once** continues the tool. Card leaves the queue. Timeline
      records the resolution.
- [ ] **Allow always** on a non-critical card adds an Allowlist row. A matching
      later `review` skips the prompt. **Remove** that row (confirm) and the
      next match prompts again.
- [ ] **Allow always** on a **critical** card asks for confirm first.
- [ ] **Deny** vetoes; the claw moves on; card leaves the queue.
- [ ] Two+ pending cards: jump list, critical first, all shown in full.
- [ ] Timeline: search, All/Allow/Review/Block/Error, Stream vs By session,
      per-session chips. Expanding a row shows command/output/resolution.
- [ ] Settings: attended and unattended floors (strict/info/warning/critical),
      including the covered-level styling. Hint text updates. Value survives
      reload (persisted in plugin config). `critical` confirm if the UI asks.
- [ ] Allow-all Off / On for all. Quiet Off / 30m / 2h / 8h (max 8h). These
      are in-memory: a gateway restart clears them. They do **not** close
      cards already waiting.
- [ ] Per session allow-all and quiet 30m on a named session; `/sentrook
      sessions` agrees. Global allow-all on makes session allow-all inert.
- [ ] Feedback submit/off and scan-error review/deny/allow (allow is
      dangerous). Operator log: change retention days + rotate MiB, **Save**,
      **Drop lines older than retention** (confirm), do **not** wipe unless
      you mean to.
- [ ] Click a setting twice more after it has saved: no error flash, no
      bricked page.
- [ ] Leave Sentrook, open another Control UI page, come back: state still
      loads.

### Sentrook (read-only) iframe / `/sentrook`

Open the sidebar **Sentrook (read-only)** tab, and once as
`http://127.0.0.1:18789/sentrook` in a normal browser window.

- [ ] Banner says the panel is read-only and how to get the native page
      (upgrade to 2026.9.2+ and Labs → Custom plugin UI, then sidebar
      **Sentrook**). Mentions `/sentrook` / CLI as the write path otherwise.
- [ ] Same four tabs and the same review/timeline visual language. **No**
      Allow once / Allow always / Deny / Save / Remove / floor clicks that
      mutate. Each former control shows the command to paste.
- [ ] Reviews show `/approve <id> allow-once|allow-always|deny`. Settings
      show `/sentrook allow-all`, `quiet`, `sensitivity`, `feedback`,
      `scan-error`, `allowlist rm`, `log retention|purge`. Connection test
      shows `openclaw sentrook verify`. Missing credentials show
      `openclaw sentrook configure`, not a secret form.
- [ ] Timeline search and filters still work (local only).
- [ ] Clicking the command copy does **not** change policy. Confirm by
      `/sentrook policy` before and after a click.
- [ ] On a host already on 9.2+ with Labs on, the banner still points at the
      native sidebar item (this tab stays a preview).

### `/sentrook` chat and `/approve`

Owner-only. Prefer a DM. After each mutation, `/sentrook policy` or the native
Settings tab should agree.

- [ ] `/sentrook help` lists the catalog and no longer tells you to paste the
      iframe URL to change settings. Each verb's `help` (`/sentrook status
      help`, …) shows usage and the value in effect.
- [ ] Bare `/sentrook`: snapshot (policy + pending leads) ending
      `More commands: /sentrook help`. `/sentrook status`: knobs only.
- [ ] `/sentrook pending` this session; `all` every card; `<id>` full scrubbed
      command. `/approve <plugin:id> allow-once` (and always/deny) actually
      continues or vetoes the tool.
- [ ] `/sentrook history` newest 8 review/block/scan-error; `all` includes
      allows; `gateway` every session; `before <id>` older page; `<id>`
      investigation. No AIRA ids in the list.
- [ ] `/sentrook sessions` matches Control UI session keys plus allow-all /
      quiet flags.
- [ ] `/sentrook allow-all` (this session on), `allow-all all on`,
      `allow-all all off` (clears session flags too),
      `allow-all session <key> off`. `/sentrook quiet all 30m` then `quiet
      all off`; `quiet session <key> 2h` (cap 8h). Open cards still need
      `/approve`.
- [ ] `/sentrook sensitivity attended warning` persists. `sensitivity
      unattended critical` refuses without `confirm`; with `confirm` it
      persists. `lenient` maps to `info`.
- [ ] `/sentrook feedback off` then `submit`. `/sentrook scan-error deny`;
      `scan-error allow` refuses without `confirm`.
- [ ] `/sentrook allowlist` lists 1-based rows; `allowlist rm n` removes.
- [ ] `/sentrook log`; `log retention 7d`; `log retention 32MiB`;
      `log purge confirm`; skip `log purge all confirm` unless you intend to
      delete the files.
- [ ] Non-owner sender is rejected. Public-channel replies include the
      disclosure that the room can read them.

### Cross-surface consistency

- [ ] Change attended sensitivity on native Settings. `/sentrook policy` and
      the iframe Settings display show the new floor.
- [ ] Change it back with `/sentrook sensitivity attended strict`. Native
      updates without a full Control UI reload (event refresh).
- [ ] Allow-always from native → iframe Allowlist shows the row and the
      `rm` command. Remove via chat → both dashboards drop it.
- [ ] A `block` (not review) never offers allow-all skip; unattended cron
      ignores allow-all/quiet and follows unattended sensitivity.

## Session policy

After scan returns **`review`** only (scan still always `POST`s).
Order: local allowlist → (attended only) allow-all → quiet TTL → the matching
sensitivity floor (`review_severity` at or below `info` / `warning` /
`critical`). Attended and unattended floors are independent. Legacy `lenient`
is `info`. The floor includes **hard** L2 reviews: Layer 3 already ran on the
host, so a remaining `review` is eligible.

Never skipped: **`block`**, **scan errors**. Unattended (cron/subagent)
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

It is **never** uploaded to Sentrook or Rookery. Opt-in `/feedback` is a
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

Use the built-in verify command, or **Test connection** on the dashboard
Settings page, to confirm the plugin is installed, configured, can mint an
OIDC scan token, and can reach the scan service:

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

On the scan path, the execution plan is evaluated in memory and is **not**
stored as PlanIR. Opt-in review feedback is a separate path (derived intent,
matched-step slice, human-gated community corpus) — see the root
[README — Privacy and community contribution](../../README.md#privacy-and-community-contribution).
