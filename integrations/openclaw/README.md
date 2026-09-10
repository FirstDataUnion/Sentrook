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
See [Operator dashboard](#operator-dashboard),
[`/sentrook` chat commands](#sentrook-chat-commands), and
[Chat-channel slash commands](#chat-channel-slash-commands) if those
commands refuse in Discord / Slack / Telegram / WhatsApp.

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
`onScanError`, then **Save and test**. Sentrook verifies the credentials
against Identity first. On success it writes `~/.openclaw/.env` (chmod 600) —
never `openclaw.json` — and shows a green confirmation. A failed check leaves
the form in place so you can correct the values. The plugin uses the default
Identity issuer; it does not write `SENTROOK_OIDC_ISSUER`. Do not paste secrets
into Control UI plugin Config (SecretRefs can fail-close the gateway).

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
| `openclaw sentrook allowlist list\|path\|add <id>\|clear --yes` | Inspect / trust-from-history / wipe local allow-always store |

Chat (owner-only, not the CLI): `/sentrook` — see
[`/sentrook` chat commands](#sentrook-chat-commands). From Discord / Slack /
Telegram / WhatsApp, OpenClaw must admit you on that surface first — see
[Chat-channel slash commands](#chat-channel-slash-commands). Gateway panel:
`/sentrook` on the Control UI port — see [Operator dashboard](#operator-dashboard).

## Configuration

Configure does **not** restart the gateway — do that yourself after the first
setup or after credential changes.

### What configure writes

| Location | Contents |
|----------|----------|
| `~/.openclaw/.env` | `SENTROOK_SCAN_CLIENT_ID` / `SENTROOK_SCAN_CLIENT_SECRET`. Prefer this over compose `env_file` so a normal **restart** reloads secrets |
| `~/.openclaw/openclaw.json` → `plugins.entries.sentrook-openclaw` | `enabled`, `hooks.allowConversationAccess` (so the plugin can read the turn prompt for operator-log intent), `timeoutMs`, `feedback`, and related plugin settings. **No** credentials or scan URL in this file |

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
| `feedback.mode` | `submit` after configure | `submit` posts sanitized **allow-once** and **deny** reviews for the community corpus (human-gated publish). **Allow-always** still posts even when mode is `off`. Host **cancelled** / **timeout** never post. The wizard default is `submit`. If you enable the plugin without configure, feedback stays `off`. Opt out: wizard prompt, `--contribute-corpus false`, or `feedback.mode: "off"` |
| `allowlist.enabled` | `true` | Local short-circuit for “allow every time” — see [Allow every time](#allow-every-time-local-allowlist) |
| `allowlist.path` | `~/.openclaw/sentrook-allowlist.json` | Override store path |
| `sensitivity` | `strict` | Attended review floor after a `review`: `strict` always prompts; `info` / `warning` / `critical` auto-approve that severity and below (legacy `lenient` = `info`). Includes hard L2 reviews. Never skips `block` or scan errors. Env: `SENTROOK_SENSITIVITY`. See [Session policy](#session-policy). |
| `unattendedSensitivity` | `strict` | Same floor for cron, heartbeat, and jobs they spawn. Allow-all and quiet do not apply. Env: `SENTROOK_UNATTENDED_SENSITIVITY`. |
| `operatorLog.enabled` | `true` | Local JSONL history on the OpenClaw host. Env: `SENTROOK_OPERATOR_LOG=0` to disable. See [Operator log](#operator-log). |
| `operatorLog.path` | `$OPENCLAW_STATE_DIR/sentrook-operator.jsonl` | Override path. Env: `SENTROOK_OPERATOR_LOG_PATH`. |
| `operatorLog.maxAgeDays` | `14` | Drop lines older than this many days (`0` = no age purge). Env: `SENTROOK_OPERATOR_LOG_MAX_DAYS`. |
| `operatorLog.maxBytes` | `33554432` (32 MiB) | Rotate the live file near this size. Env: `SENTROOK_OPERATOR_LOG_MAX_BYTES`. |
| `approval.interactiveTimeoutMs` | `600000` (10 min) | Review timeout for interactive sessions. Capped at 10 min (OpenClaw 2.0). Deny on timeout. |
| `approval.scheduledTimeoutMs` | `600000` (10 min) | Unused for unattended hosted reviews (those block immediately). Kept for scan-error cards if a future host can wait. |
| `approval.scheduledTimeoutBehavior` | `deny` | **Deprecated.** Unresolved reviews always deny. The key is still accepted so older configs load; `allow` is ignored. |

PlanIR is always scrubbed before egress. Decisions are always enforced (allow /
review / block) — there is no observe-only or sanitization-off toggle.

OpenClaw gates `before_prompt_build` for non-bundled plugins. Configure (and a
gateway start) set `plugins.entries.sentrook-openclaw.hooks.allowConversationAccess`
to `true` so the operator log can store the scrubbed turn prompt as `intent`.
That key lives next to `enabled` / `config`, not inside `config`. Without it,
Discord and dashboard scans still run, but `intent` stays `null`. Cron and
heartbeat turns can still have no utterance — `intent_kind` is classified from
the session key either way. `openclaw sentrook verify` checks the flag.

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
   to wait for allow / deny. Interactive and scheduled (cron / heartbeat) both
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

OpenClaw cannot deliver **plugin** approval cards for cron or heartbeat
(`trigger !== "user"`). Until that host gap closes
([openclaw#138853](https://github.com/openclaw/openclaw/issues/138853)),
Sentrook **blocks** those hosted reviews instead of waiting on a card that
cannot be answered. The block copy shows the command and a constructed
`/sentrook allowlist add <id>` (or `openclaw sentrook allowlist add <id>`).
If you trust that occurrence, run the command and re-run the job. Matching
later reviews skip the prompt. Scan still runs; blocks still win. Raise
`unattendedSensitivity` if the command cannot be allowlisted (pipes,
`curl | bash`, a bare curl/wget with no URL). A curl/wget to a specific host
and path can be allowlisted. Native **exec** approvals on Control UI are a separate OpenClaw gate
and do not satisfy a Sentrook review. We will restore live plugin cards for
unattended jobs when OpenClaw can deliver them
([Sentrook#59](https://github.com/FirstDataUnion/Sentrook/issues/59)).

When Sentrook returns **review** on an **interactive** turn, the plugin asks
OpenClaw for a human decision (`allow-once` / `allow-always` / `deny`). The
card uses the usual command summary (title 80 / description 512). Chat
channels typically show both.
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

`/sentrook` and `/approve` in that same DM or room still need OpenClaw to
admit you as a command sender — see [Chat-channel slash commands](#chat-channel-slash-commands).

## Chat-channel slash commands

`/sentrook` is an OpenClaw plugin command (`requireAuth` + `operator.admin`).
Sentrook does not keep its own Discord / Slack / Telegram / WhatsApp owner
list. If slash commands refuse in a room, that is almost always **OpenClaw
channel admission**, not the plugin.

This is an **OpenClaw** setting; Sentrook configure does not set it for you.
Upstream:
[Slash commands](https://docs.openclaw.ai/tools/slash-commands),
[Discord access control](https://docs.openclaw.ai/channels/discord/access-control),
[Telegram access control](https://docs.openclaw.ai/channels/telegram/access-control),
[Slack access control](https://docs.openclaw.ai/channels/slack/access-control),
[WhatsApp](https://docs.openclaw.ai/channels/whatsapp).

Two layers, both required:

1. **This sender may run commands here.** Same rules as ordinary messages:
   pairing and `channels.<name>.allowFrom` for **DMs**; the guild / group /
   channel allowlist for **rooms**. Native Discord slash can reply **You are
   not authorized to use this command** for *every* command when this layer
   fails — `/status` and `/approve` included, not only `/sentrook`.
2. **This sender is the owner.** `/sentrook` is owner-only. That identity is
   `commands.ownerAllowFrom` (`discord:…`, `telegram:…`, `slack:U…`,
   `whatsapp:+…`). Pairing a DM, or listing yourself only under
   `execApprovals.approvers`, does **not** make you an owner. The first CLI
   pairing can bootstrap `ownerAllowFrom`; Control UI pairing has a separate
   owner checkbox.

`/whoami` (alias `/id`) prints the sender id to put in those lists. Prefer a
**DM** or a private channel: `/sentrook` replies are ordinary messages, readable
by everyone in a public room.

If `commands.allowFrom` is set, it is the **only** allowlist for commands
(channel pairing lists are ignored for command auth). Leave it unset unless
you want that override.

### Discord

**DM:** `channels.discord.dmPolicy` (`pairing` by default) plus
`channels.discord.allowFrom`. A paired DM is enough to run commands there once
`commands.ownerAllowFrom` includes `discord:<user-id>`.

**Guild channel:** `ownerAllowFrom` is **not** enough. Native slash uses the
same guild allowlist as ordinary messages. You need the **server** under
`channels.discord.guilds` (when `groupPolicy` is `allowlist`, the default once
Discord is configured), this **channel** listed if that guild has a
`channels` map, and your **user id** on `channels.discord.allowFrom` and/or
`channels.discord.guilds.<guildId>.users` (bare numeric ids).

In `~/.openclaw/openclaw.json` (shape illustrative — keep your existing Discord
token / guild config):

```json5
{
  commands: {
    ownerAllowFrom: ["discord:<your-user-id>"],
  },
  channels: {
    discord: {
      enabled: true,
      allowFrom: ["<your-user-id>"],
      groupPolicy: "allowlist",
      guilds: {
        "<your-server-id>": {
          users: ["<your-user-id>"],
          channels: {
            "<this-channel-id>": { enabled: true },
          },
        },
      },
    },
  },
}
```

Notes:

- The important parts are `commands.ownerAllowFrom`, `allowFrom` (DMs), and
  the guild `users` / `channels` lists (server rooms).
- Put **your** Discord user id in those lists — `/whoami` in a DM prints it.
- Adding even one entry under a guild `channels` map turns the rest of that
  server into a deny list. Use `"*": { enabled: true }` if you still want the
  other rooms. Omit the `channels` map entirely to allow every channel in that
  guild, subject to `users`.
- Discord may still show slash commands in the picker for people who cannot
  run them; execution replies **You are not authorized to use this command**.
- Restart the gateway after changing channel command auth.
- `openclaw channels status --probe` warns when `groupPolicy` is allowlist
  with no guilds, or when a `channels` map omits this room.

### Telegram

**DM:** `channels.telegram.dmPolicy` plus `channels.telegram.allowFrom`
(numeric user id). Pairing grants **DM access only**.

**Group / supergroup:** put the group (negative id, e.g. `-100…`) under
`channels.telegram.groups`. Group sender auth does **not** inherit the pairing
store — put your user id in `channels.telegram.allowFrom` (and
`groupAllowFrom` if you set that). Owner-only: `commands.ownerAllowFrom`
includes `telegram:<user-id>`.

```json5
{
  commands: {
    ownerAllowFrom: ["telegram:<your-user-id>"],
  },
  channels: {
    telegram: {
      dmPolicy: "pairing",
      allowFrom: ["<your-user-id>"],
      groupPolicy: "allowlist",
      groups: {
        "<group-chat-id>": { requireMention: true },
      },
    },
  },
}
```

Notes:

- The important parts are `commands.ownerAllowFrom`, `allowFrom`, and the
  `groups` map for the chat you actually use.
- Pairing a DM does **not** authorize the same sender in a group.
- Native Telegram commands are on by default (`commands.native: "auto"`).
- Restart the gateway after changing channel command auth.

### Slack

**DM:** `channels.slack.dmPolicy` plus `channels.slack.allowFrom` (Slack user
ids such as `U…`).

**Channel:** `groupPolicy` plus `channels.slack.channels` (stable channel ids
such as `C…`, not `#name`). If a channel entry sets `users`, you must be on
that list. Owner-only: `commands.ownerAllowFrom` includes `slack:<user-id>`.

```json5
{
  commands: {
    ownerAllowFrom: ["slack:<your-user-id>"],
  },
  channels: {
    slack: {
      dmPolicy: "pairing",
      allowFrom: ["<your-user-id>"],
      groupPolicy: "allowlist",
      channels: {
        "<channel-id>": { enabled: true, requireMention: true },
      },
    },
  },
}
```

Notes:

- Text `/sentrook` in a message works on Slack without native slash
  (`commands.native` defaults to off for Slack).
- The native Slack picker needs `commands.native: true` **and** one
  Slack-app slash command per verb — see OpenClaw’s Slack docs. Slack
  reserves `/status`; native `/agentstatus` is the substitute, while text
  `/status` still works.
- Restart the gateway after changing channel command auth.

### WhatsApp

WhatsApp has **text** `/commands` (standalone messages starting with `/`), not
a Discord-style native picker. `commands.text` can be `false`; text commands
still parse on WhatsApp.

**DM:** `channels.whatsapp.dmPolicy` plus `channels.whatsapp.allowFrom` (E.164
numbers such as `+15551234567`).

**Group:** `groupPolicy` plus `channels.whatsapp.groups` (group JIDs). If the
`groups` map is present, it is an allowlist. `groupAllowFrom` filters who
inside an allowed group can talk; it does not inherit DM pairing. If
`groupAllowFrom` is unset, sender checks fall back to `allowFrom`. Owner-only:
`commands.ownerAllowFrom` includes `whatsapp:+15551234567`.

```json5
{
  commands: {
    ownerAllowFrom: ["whatsapp:+15551234567"],
  },
  channels: {
    whatsapp: {
      dmPolicy: "pairing",
      allowFrom: ["+15551234567"],
      groupPolicy: "allowlist",
      groupAllowFrom: ["+15551234567"],
      groups: {
        "<group-jid>": { requireMention: true },
      },
    },
  },
}
```

Notes:

- The important parts are `commands.ownerAllowFrom`, `allowFrom` (DMs), and
  `groups` / `groupAllowFrom` for rooms.
- Pairing a DM does **not** authorize the same number in a group.
- Restart the gateway after changing channel command auth.

### Check it

1. `/whoami` in a **DM** with the bot — should return your sender id.
2. The same command in the **room** you actually use. If DM works and the room
   says not authorized, fix that channel’s guild/group allowlist, not
   Sentrook.
3. Then `/sentrook status`. If `/whoami` works but `/sentrook` is owner-only,
   add that sender to `commands.ownerAllowFrom`.

## Operator dashboard

Two Control UI entries can appear when **Custom plugin UI** is off. Use
**Sentrook** (native) when Labs is on — the plugin then skips registering
**Sentrook (read-only)** so a native Settings write cannot remount that iframe
onto a dead token. Treat the read-only tab as status plus command copy on
older hosts, or when Labs is still off.

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

When **Settings → Labs → Custom plugin UI** is on, the plugin does **not**
register **Sentrook (read-only)**. Use the native sidebar **Sentrook** page.
`/sentrook` in a browser and `/sentrook` chat still work.

Otherwise the plugin registers a **Sentrook (read-only)** Control UI tab that
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
  has open, joined with the local pending stash and operator log. The plugin
  runtime's `plugin.approval.list` is often empty (those records are bound to
  the tool-call requester, not the plugin). Sentrook joins `plugin:` ids through
  OpenClaw's approval-runtime client — the same client `/approve` uses — and
  from `plugin.approval.requested` when the host delivers it. Cards show
  severity, command (dangerous spans highlighted), and human-readable policy
  labels (not AIRA ids). Native allow / deny calls `plugin.approval.resolve`
  so the waiting tool continues; iframe shows `/approve …`.
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

If the host has not minted a `plugin:` id this plugin can see yet, native
Allow/Deny still show. Resolve looks the id up on click (approval-runtime
list, then `plugin.approval.list`). Chat copy is the three complete `/approve
<id> allow-once|allow-always|deny` lines when the id is known; `/sentrook
pending` joins the id before printing those lines. Otherwise the reply tells
you to use the OpenClaw approval card in chat. The UI never shows a truncated
`/approve plugin:…`.

Before a release, work through the [Operator test matrix](#operator-test-matrix)
(`npm test` plus a live pass on native, read-only, and `/sentrook`).

## `/sentrook` chat commands

Owner-only (`requireAuth` + `operator.admin`). OpenClaw must already admit
you on that DM or room — see [Chat-channel slash commands](#chat-channel-slash-commands).
Replies are ordinary channel messages (`{ text }`). `/sentrook help` reminds
you that in a **public** Discord, Telegram, or WhatsApp chat anyone present can
read these replies — secrets are scrubbed, that is not a guarantee. Prefer a DM, a
private channel, or the [dashboard](#operator-dashboard).

| Command | What it does |
|---------|----------------|
| `/sentrook` | Snapshot: policy plus pending. One waiting review is shown in full (same as `/sentrook pending`). Ends with `More commands: /sentrook help` |
| `/sentrook help` | Catalog (command on its own line, description indented) plus the public-channel warning |
| `/sentrook status` | Policy for this chat and the gateway (no pending list) |
| `/sentrook policy` | All settings, with a short explanation of the current choice |
| `/sentrook pending [all\|id]` | This chat; `all` = every card on the gateway. One waiting review is shown in full; two or more is a table plus copy-paste `/sentrook pending <id>`. `<id>` is the investigation |
| `/sentrook history [all\|gateway\|before <id>\|n\|id]` | Newest 8 (max 20) as a table with an `id` column. Default is reviews, blocks, and scan errors in this chat; `all` includes allows; `gateway` is those events across every session and never includes allows; `before <id>` older page; `<id>` is the investigation |
| `/sentrook sessions` | OpenClaw sessions plus attended / unattended floors, allow-all, and quiet. The `key` column is what you pass to `sensitivity session <key>` / `quiet session <key>` / `allow-all session <key>`. Uses each session’s label or display name when the store has one |
| `/sentrook allow-all [all\|session <key>] [on\|off]` | Skip future attended reviews. Bare = this session on. `all` = every attended session (`off` also clears every session flag). Sessions with their own attended floor ignore this |
| `/sentrook quiet [all\|session <key>] <duration\|off>` | Same skip with a timer (`30m`, `2h`, `8h` max). Sessions with their own attended floor ignore this |
| `/sentrook sensitivity [attended\|unattended\|session <key> attended\|unattended] [strict\|info\|warning\|critical\|default]` | Gateway or per-session floor (`lenient` = `info`). `default` on a session inherits the matching global floor. `critical` needs a trailing `confirm` |
| `/sentrook feedback [submit\|off]` | Whether sanitized reviews are posted to the community corpus |
| `/sentrook scan-error [review\|deny\|allow]` | What happens when Sentrook cannot scan. `allow` needs a trailing `confirm` |
| `/sentrook allowlist [add <id> \| rm n]` | List; `add` trusts the command from a history id; `rm` removes a 1-based local allowlist entry |
| `/sentrook log [retention\|purge]` | Stats; `retention 7d` / `32MiB`; `purge confirm` / `purge all confirm` |

Every command accepts `help` (or `?` / `-h`) as its first argument — options, scopes, and the value in effect right now. That in-chat page is the source of truth; this table is only the catalog. `/sentrook help` matches it.

Lists stay short: no AIRA ids, no matched-rule dumps, no full tool results.
`pending` with one waiting review (or `pending <id>` / `history <id>`) is the
investigation (command, scan why, `/approve` lines when known). OpenClaw
`/approve` is still how you resolve a card from chat (there is no `/sentrook allow`).

Allow-all and quiet do **not** resolve cards already waiting on `/approve`.
Turn them on, then still approve or deny the open ones.

## Operator test matrix

Automated coverage lives in `plugin/` (`npm test`). It already asserts slash
verbs and help copy, native write hooks vs read-only command lists, HTTP
`/sentrook` HTML (no mutation buttons, no `_srk` POSTs from the page),
session-action JSON limits, session-policy skip order, and iframe banner copy.

Live: from `plugin/`, `npm run build`, then `openclaw plugins install . --force`,
gateway restart, browser reload. Control UI on loopback or HTTPS. Prefer a
**DM** for chat unless that guild/group is on the channel allowlist (see
[Chat-channel slash commands](#chat-channel-slash-commands)). Tick **N** native
sidebar **Sentrook**, **R** both the iframe tab **and** standalone
`http://127.0.0.1:18789/sentrook`, **S** `/sentrook` / `/approve`.

`Auto` means `npm test` already covers the copy or handler. Live is still
required wherever a real tool call, Labs flag, or host chrome is involved.

Preview without a gateway: `npm run preview:dashboard` (http://127.0.0.1:3456)
is the **read-only** HTML with fixture data (`/unconfigured` for first-run).

### Load and chrome

| Case | Auto | N | R |
| --- | --- | --- | --- |
| No “JSON-compatible” (or other) warning on load, or after two setting clicks | session-action JSON clone | [ ] | — |
| Four tabs: Reviews, Timeline, Allowlist, Settings. Hero + risk, spine, stream, floor buttons / command lists, per-session rows | HTML render | [ ] | [ ] |
| Banner: this `/sentrook` page cannot save; Labs → Custom plugin UI; sidebar **Sentrook**, not this page / not **Sentrook (read-only)** | hostVersion + HTML | — | [ ] |
| Empty queue “All clear”. Missing creds: native **Save and test** verifies then writes `~/.openclaw/.env`; failed check stays on the form; R shows `openclaw sentrook configure` only | setup HTML | [ ] | [ ] |
| Leave Sentrook, open another Control UI page, come back: state still loads | — | [ ] | [ ] |

### Reviews

| Case | Auto | N | R | S |
| --- | --- | --- | --- | --- |
| Card: command with dangerous-span highlight, no AIRA ids, age ticks, session link → Timeline filter | present + panels | [ ] | [ ] | — |
| Two+ cards: jump list, critical first, all shown in full | HTML | [ ] | [ ] | — |
| Allow once continues the tool; card leaves; timeline records it | HTTP resolve + live tool | [ ] | — | `/approve <id> allow-once` [ ] |
| Allow always (non-critical) writes allowlist; matching later review skips; Remove (confirm) prompts again | allowlist + live | [ ] | copy `allowlist rm n` [ ] | [ ] |
| Allow always on **critical** asks confirm first | native confirm dialog | [ ] | — | — |
| Deny vetoes; claw moves on | resolve + live | [ ] | — | `/approve <id> deny` [ ] |
| R shows `/approve <id> allow-once\|always\|deny`; clicks do not mutate | panels + hints | — | [ ] | — |
| No `plugin:` id: native buttons still work; chat copy is `/sentrook pending <id>` (never `plugin:…`) | HTTP 409 + panels | [ ] | inspect command [ ] | [ ] |

### Timeline, allowlist, settings

| Case | Auto | N | R |
| --- | --- | --- | --- |
| Search; All/Allow/Review/Block/Error; Stream vs By session; session chips; expand row | HTML + live filters | [ ] | [ ] |
| Expanded row stays open across a native refresh | — | [ ] | — |
| Attended + unattended floors (strict/info/warning/critical), covered styling, hint updates, persists across reload | sessionPolicy + HTML | [ ] | commands listed [ ] |
| `critical` confirm in UI / `… critical confirm` in R copy | native + hints | [ ] | [ ] |
| Allow-all Off / On for all (On for all asks confirm). Quiet Off / 30m / 2h / 8h (9h refused). Active quiet shows a remaining-time banner. Does **not** close open cards. Does **not** skip blocks | policy + quiet parse | [ ] | commands listed [ ] |
| Per session allow-all / quiet 30m; readable OpenClaw names when labelled; `/sentrook sessions` agrees; global allow-all ignores session flags | mergeSessionRows + slash | [ ] | [ ] |
| Feedback submit/off. Scan-error review/deny; allow is dangerous (confirm) | slash + HTML | [ ] | [ ] |
| Log: retention days + MiB save; purge aged (confirm). Skip wipe unless you mean it | HTTP log + slash | [ ] | commands listed [ ] |
| Test connection = `openclaw sentrook verify` | verify + hints | [ ] | [ ] |

### `/sentrook` chat

Owner-only. After each mutation, `/sentrook policy` and native Settings should agree.
`/whoami` in a DM, then in the room you use — see [Chat-channel slash commands](#chat-channel-slash-commands).

| Command | Auto | Live |
| --- | --- | --- |
| `help` catalog; no “paste the iframe URL to save”. Each command help has Usage | slash | [ ] |
| `/whoami` in a DM, then in the Discord/Slack/Telegram/WhatsApp room (room “not authorized” is OpenClaw channel admission) | — | [ ] |
| Bare snapshot + `More commands: /sentrook help`. One pending = full review. `status` policy only. `policy` explains the current choice | slash | [ ] |
| `pending` / `pending all` / `pending <id>`. One card = full detail. No AIRA ids | slash | [ ] |
| `history` 8 (max 20) table with `id`; `all`; `gateway`; `before <id>`; `<id>` investigation | slash | [ ] |
| `sessions` — `key` column for follow-up commands; allow-all column | slash | [ ] |
| `allow-all` (this session on); `allow-all all on\|off` (`off` clears session flags); `allow-all session <key> off` | slash | [ ] |
| `quiet all 30m` / `off`; `quiet session <key> 2h`; `quiet all 9h` rejected | slash + cap | [ ] |
| `sensitivity attended warning`; `unattended critical` needs `confirm`; `lenient` → info | slash | [ ] |
| `feedback off\|submit`. `scan-error deny`; `allow` needs `confirm` | slash | [ ] |
| `allowlist`; `allowlist add <id>`; `allowlist rm n` | slash | [ ] |
| `log`; `retention 7d` / `32MiB`; `purge confirm`. Avoid `purge all confirm` unless wiping | slash | [ ] |
| Unknown verb → catalog. Non-owner refused. Public-channel disclosure on `help` only | slash | [ ] |

### Cross-surface

| Case | Auto | Live |
| --- | --- | --- |
| Native sensitivity change → R Settings + `policy` show the new floor | — | [ ] |
| Slash sets it back → native updates without a full Control UI reload | feature events | [ ] |
| Native allow-always → R Allowlist `rm` command. Chat `rm` → both drop the row | — | [ ] |
| `block` never skipped by allow-all. Unattended ignores allow-all/quiet; uses unattended floor | sessionPolicy | [ ] |

Live-only (no useful unit substitute): real tool continuation after allow/deny,
Labs native load, Control UI navigation, event refresh without full reload.

## Session policy

After scan returns **`review`** only (scan still always `POST`s).
Order: local allowlist → if unattended, that session’s unattended floor (or the
global unattended floor when Default) → if attended and the session attended
floor is set, that floor only → otherwise allow-all → quiet TTL → global
attended floor (`review_severity` at or below `info` / `warning` /
`critical`). Attended and unattended floors are independent. Legacy `lenient`
is `info`. The floor includes **hard** L2 reviews: Layer 3 already ran on the
host, so a remaining `review` is eligible.

Never skipped: **`block`**, **scan errors**. Unattended (cron, heartbeat, and
jobs they spawn) reviews ignore allow-all and quiet; they follow
`unattendedSensitivity` instead. If the unattended floor does not cover the
review, Sentrook **blocks** (it does not ask OpenClaw for a plugin card —
OpenClaw cannot deliver those on scheduled runs; see
[openclaw#138853](https://github.com/openclaw/openclaw/issues/138853)). The
block reason shows the command and `/sentrook allowlist add <id>`. A matching local
allowlist entry can still skip an unattended review. A subagent of an
interactive session stays on the attended floor.

Unattended is classified from OpenClaw host signals, not from prompt text:
`ctx.trigger` / `ctx.jobId` on agent-turn hooks, then the session key
(`agent:…:cron:…` or isolated `:heartbeat`), then parent inheritance for
`subagent:` children. Prompt `[cron:]` markers are a last resort.

Allow-all and quiet are stored on the OpenClaw host (`sentrook-live-policy.json`)
so the dashboard isolate and the scan hook share them. **Per-session attended and
unattended floors** live in that same file, keyed by session key, and survive
restart and `session_end`. Allow-all and quiet on a session still clear when that
session ends. Turn those switches off when you are done — a restart no longer
clears them. Sensitivity, unattended sensitivity, `feedback.mode`,
`onScanError`, and operator-log retention persist in
`plugins.entries.sentrook-openclaw.config`. Environment variables
(`SENTROOK_SENSITIVITY`, `SENTROOK_UNATTENDED_SENSITIVITY`,
`SENTROOK_FEEDBACK_MODE`, `SENTROOK_ON_SCAN_ERROR`, …) still win after a
restart for the **global** floors. Sensitivity `critical` is the standing
equivalent of allow-all for that scope (still never block / scan-error).

Per-session floors: Default inherits the matching global floor. A set
**unattended** session floor is the only floor that unattended run uses (global
unattended if Default). A set **attended** session floor is the only floor that
attended run uses — global attended, allow-all, and quiet do not apply. Allowlist
always wins. Quiet still only matters while that session’s attended floor is
Default. Sticks only if OpenClaw keeps a stable session key (for example
`cron:nightly`).

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
| `skeleton` | Other command shapes | Constrained argv skeleton. `curl`/`wget` keep scheme+host+path (query may change). Never pipes, `curl \| bash`, or a bare curl/wget with no URL. |

```bash
openclaw sentrook allowlist path              # print resolved JSON path
openclaw sentrook allowlist list              # show entries
openclaw sentrook allowlist add <id>          # trust the command from a history event
openclaw sentrook allowlist clear --yes       # wipe all entries
```

Chat: `/sentrook allowlist` / `/sentrook allowlist add <id>` / `/sentrook allowlist rm n`.
Dashboard: allowlist from a timeline review, or remove from the Allowlist section.

## Operator log

A local JSONL history (`sentrook.operator.log/v1`) is **on by default**. It is
a product feature, not a maintainer debug dump.

| | |
| --- | --- |
| Path | `$OPENCLAW_STATE_DIR/sentrook-operator.jsonl` (usually `~/.openclaw/sentrook-operator.jsonl`) |
| Mode | `0600`, append-only |
| Retention | 14 days and 32 MiB (whichever bites first). Tune with `operatorLog.*` or `/sentrook log retention` |
| Payload | Full scrubbed command and result (no 500-char pack). Same secret/PII patterns as scan egress. Scan, resolution, and result lines store the turn prompt as `intent` when the host exposes it. Result excerpts are the inner tool output, not OpenClaw's JSON wrapper. Hosted `scan.log` is not duplicated here. |
| Hook | Log I/O never fail-closes a tool call |

It is **never** uploaded to Sentrook or Rookery. Opt-in `/feedback` is a
separate path for allow-once / deny / allow-always only. Disable with `SENTROOK_OPERATOR_LOG=0` or
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
