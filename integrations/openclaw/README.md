# Sentrook for OpenClaw

The Sentrook plugin scans each tool call your OpenClaw agent is about to make (shell commands, file reads and
writes, web fetches, messages and so on), in the context of what you asked for and what the agent did on the way.
Depending on the risk score it allows the call, asks you to approve it, or blocks it.

This guide takes you from nothing to a first scan in **observe mode**, where Sentrook scores and logs every call
but never blocks or asks. Switch to enforce mode once the scores look right to you.

The plugin is a beta (2.0.0-beta). Report problems at <https://github.com/FirstDataUnion/Sentrook/issues>.

## Requirements

- OpenClaw **2026.9.5 or newer** (`openclaw --version`). Tested on 2026.10.3.
- A shell on the machine that runs the OpenClaw gateway, as the user that runs it.
- An account on the FIDU identity service, <https://identity.firstdataunion.org> (sign-up is open).

OpenClaw keeps its files in `~/.openclaw` unless `OPENCLAW_STATE_DIR` or `OPENCLAW_HOME` says otherwise. The
paths below assume the default; substitute yours if it differs.

## 1. Get scan credentials

1. Sign in at <https://identity.firstdataunion.org>.
2. Open the **Sentrook** tab and click **Create Credentials**. Any name will do (for example `openclaw-laptop`).
3. Copy the **Client ID** and **Client Secret** somewhere private. The secret may not be shown again.

The secret is a password: never paste it into a chat with your agent.

## 2. Choose observe mode, before installing

Installing the plugin enables it straight away, so set its mode first and it starts in observe mode:

```bash
openclaw config set plugins.entries.sentrook.config.mode observe
openclaw config set plugins.entries.sentrook.hooks.allowConversationAccess true
```

Until the plugin is installed, OpenClaw warns `plugin not found: sentrook (stale config entry ignored …)`. That
is expected; the settings are kept and apply once it is installed.

`allowConversationAccess` lets the plugin read what you asked the agent for. Without it Sentrook cannot tell whether
a call matches your request, and scores are less accurate.

## 3. Save the credentials

The plugin reads `SENTROOK_SCAN_CLIENT_ID` and `SENTROOK_SCAN_CLIENT_SECRET` from the environment or from
`~/.openclaw/.env`. Keep them out of `openclaw.json`, which the agent can read. This block prompts for both
(the secret is not echoed) and writes them to a file only your user can read; run it again to replace them:

```bash
{
  ENV_FILE="${OPENCLAW_STATE_DIR:-${OPENCLAW_HOME:-$HOME}/.openclaw}/.env"
  read -r -p "Client ID: " SR_ID
  read -r -s -p "Client Secret (hidden): " SR_SECRET; echo
  mkdir -p "$(dirname "$ENV_FILE")" && touch "$ENV_FILE" && chmod 600 "$ENV_FILE"
  grep -v -e '^SENTROOK_SCAN_CLIENT_ID=' -e '^SENTROOK_SCAN_CLIENT_SECRET=' "$ENV_FILE" > "$ENV_FILE.tmp" || true
  printf 'SENTROOK_SCAN_CLIENT_ID=%s\nSENTROOK_SCAN_CLIENT_SECRET=%s\n' "$SR_ID" "$SR_SECRET" >> "$ENV_FILE.tmp"
  mv "$ENV_FILE.tmp" "$ENV_FILE" && chmod 600 "$ENV_FILE"
  unset SR_ID SR_SECRET
  echo "Saved to $ENV_FILE"
}
```

## 4. Install

```bash
openclaw plugins install npm:@firstdataunion/sentrook-openclaw --force --accept-capabilities
```

- `--force` confirms a source outside ClawHub; OpenClaw warns that the package is "outside ClawHub review".
- `--accept-capabilities` accepts the hooks the plugin declares: it reads tool calls before they run and their
  results after.

The output ends with `Installed plugin: sentrook`. Then make sure it is enabled (a plugin that was installed before
comes back disabled) and restart the gateway:

```bash
openclaw plugins enable sentrook && openclaw gateway restart
```

## 5. Check the setup

```bash
openclaw sentrook verify
```

Every line should start with `ok`, and `policy` should show `mode=observe`:

| Failing line | Fix |
| --- | --- |
| `credentials` | Run step 3 again, then restart the gateway. |
| `token mint` | The Client ID or secret is wrong or revoked: create new credentials (step 1) and repeat step 3. |
| `scan URL`, `OIDC issuer`, `Rookery URL` | A custom endpoint is set that the plugin refuses (see [Settings](#settings)). Remove it. |
| `scanner health` | The scan service is unreachable from this machine. Check outbound HTTPS to `sentrook.firstdataunion.org`. |

`openclaw plugins list` should show `sentrook` as enabled, with a 2.0 version.

## 6. First scan

Ask the agent for something small that uses a tool, such as "list the files in your workspace". Then look at what
Sentrook recorded:

```bash
openclaw sentrook history 5
```

Each row is one scan: time, tool, risk score, the action Sentrook would take, and the review outcome. In observe mode
the action is recorded but never applied. `openclaw sentrook why last` shows the most recent scan in detail: risk,
tier scores, reason codes and the entities it found.

If the history is empty, the agent has not made a tool call since the restart.

## Commands

The plugin adds chat commands, which OpenClaw answers without sending them to the model, and the same verbs on the
command line as `openclaw sentrook <verb>`.

| Chat | What it does |
| --- | --- |
| `/sentrook status` | Plugin version, mode, thresholds, scan host and whether credentials are set |
| `/sentrook help` | Lists the commands |
| `/sentrook-history [n]` | The last n scans (default 10) |
| `/sentrook-why [request_id\|last]` | One scan in detail |
| `/sentrook-grants` | Grants in force: from config (read-only) and set by command |
| `/sentrook-grant <kind> <pattern> [flags]` | Add a grant. `kind` is `destination`, `file` or `provider`. Flags: `--persistent` (default is this session only), `--allows read,write` (file only), `--expires 12h` |
| `/sentrook-revoke <id>` | Remove a grant set by command |
| `/sentrook-bind add\|remove\|list [channel]` | Manage channel bindings: the channels this deployment normally delivers to |
| `/sentrook-snooze [duration\|off\|status] [--all]` | Allow review prompts in this session (`--all`: every session) for a while, default 1h, at most 24h |

`openclaw sentrook verify` exists only on the command line.

**Owner only.** `/sentrook status` and `/sentrook help` are open to anyone who can message the agent. The dashed
commands need the gateway scope `operator.admin`: the owner's default Control UI connection has it, and so does
anyone holding the shared gateway token. Limited Control UI sessions are refused. On the command line, whoever can
run `openclaw` on the machine counts as the owner. Every attempt, allowed or refused, is recorded in the traffic log
(unless you turned it off).

On the command line there is no session, so `openclaw sentrook snooze` needs `--all`.

A snooze never relaxes a block, a review the scanner marks as enforced, or an unattended run (cron jobs, subagents,
webhooks): those still stop.

On Mattermost, a message that starts with `/` is taken by Mattermost as one of its own slash commands. Mention the
bot first: `@yourbot /sentrook status`.

> **Warning: `commands.ownerAllowFrom`.** If you set OpenClaw's `commands.ownerAllowFrom`, check that every entry
> matches a real client. An entry that matches no one locks every unlisted non-admin gateway client out of **all**
> plugin commands, including `/sentrook status`, with "requires authorization". The plugin cannot see the sender
> list, so it cannot warn you.

## Observe, enforce and off

| To | Run, then `openclaw gateway restart` |
| --- | --- |
| Enforce: ask at risk 45 or above, block at 80 or above | `openclaw config set plugins.entries.sentrook.config.mode enforce` |
| Go back to observe (the off switch: nothing is blocked or asked, scans are still logged) | `openclaw config set plugins.entries.sentrook.config.mode observe` |
| Stop scanning entirely (no calls are sent to Sentrook) | `openclaw plugins disable sentrook` |

In enforce mode, when the scan service gives no usable answer the plugin asks you whether to run the call without a
scan (`onScanError`, default `review`); unattended runs are blocked instead. Bad credentials or endpoints are never let
through silently: even with `onScanError` set to `allow`, the call is blocked, or you are asked. If the scan service is down
and you need the agent to keep working, switch to observe mode.

Watch the history for a while before switching to enforce. If a channel you deliver to all the time (a daily report
to your own chat, say) keeps being flagged, bind it with `/sentrook-bind add <channel>`.

## What is sent

Each scan sends one request to `sentrook.firstdataunion.org`:

- the request you gave the agent in this turn (with `allowConversationAccess`), and whether it came from you, a
  scheduled job, a subagent or another sender;
- the pending tool call, its arguments and the agent's narration before it, plus any other calls in the same batch;
- the tool results and other new inputs since the last scan, capped at 256 KB (head and tail are kept);
- a short history of the session's earlier calls (the last 20, arguments capped at 4 KB each);
- host facts: platform and plugin version, operating system, home and workspace paths, and how OpenClaw is
  configured to run commands and approvals;
- the grants and channel bindings whose pattern appears in the call's arguments;
- references to the session and agent. Session ids are sent as hashes, not as the ids themselves.

Before anything leaves the machine, secrets the plugin recognises (API keys, tokens, passwords, private keys and
similar) are replaced with placeholders such as `⟦secret:github:…⟧`. Recipients, hosts and email addresses are
kept, because the scanner needs them to judge where data is going. Your files, messages and tool output can still
contain personal information, and that is sent as it is.

A local copy of each scan (the redacted request and the response) is kept in `~/.openclaw/sentrook/traffic.jsonl`,
readable only by your user and rotated at 50 MB. The plugin never uploads it. Turn it off with
`openclaw config set plugins.entries.sentrook.config.trafficLog.enabled false`; the history and why commands then
have nothing to show.

## Settings

Set with `openclaw config set plugins.entries.sentrook.config.<key> <value>` and restart the gateway. Most keys can
also come from a `SENTROOK_*` environment variable; the config value wins.

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `enforce` | `observe` or `enforce` |
| `reviewAt` | `45` | Ask at or above this risk |
| `blockAt` | `80` | Block at or above this risk |
| `onScanError` | `review` | `allow`, `deny` or `review` when the scan gives no usable answer |
| `timeoutMs` | `30000` | How long to wait for a scan |
| `approval.interactiveTimeoutMs` | `300000` | How long a review waits for your answer |
| `trafficLog.enabled` | `true` | Keep the local traffic log |
| `channelBindings` | | Channels this deployment normally delivers to |
| `grants` | | Standing grants, as `{kind, pattern, allows?, scope?}` objects |
| `scanUrl`, `oidcIssuer`, `rookeryUrl` | hosted service | Endpoints. Any other value must be https on a `firstdataunion.org` host |

## Updating

```bash
openclaw plugins update sentrook && openclaw gateway restart
```

## Uninstall

```bash
openclaw plugins uninstall sentrook --force && openclaw gateway restart
```

This removes the plugin and its settings. It leaves the traffic log, grants and snooze state in
`~/.openclaw/sentrook/` and the credentials in `~/.openclaw/.env`. To remove those too, delete the folder, delete
the two `SENTROOK_SCAN_CLIENT_*` lines from `.env`, and delete the credentials on the identity service's
**Sentrook** tab. To install again later, start from step 2.
