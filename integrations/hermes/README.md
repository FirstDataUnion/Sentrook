# Sentrook for Hermes Agent

The Sentrook plugin scans each tool call your Hermes agent is about to make (terminal commands, file reads and
writes, web fetches, messages and so on), in the context of what you asked for and what the agent did on the way.
Depending on the risk score it allows the call, asks you through Hermes's own approval prompt, or blocks it.

This guide takes you from nothing to a first scan in **observe mode**, where Sentrook scores and logs every call
but never blocks or asks. Switch to enforce mode once the scores look right to you.

The plugin is a beta (2.0.0-beta). Report problems at <https://github.com/FirstDataUnion/Sentrook/issues>.

## Requirements

- Hermes Agent **v0.21 or newer** (`hermes --version`). Tested on v0.21.7.
- A shell on the machine that runs Hermes, as the user that runs it. If Hermes runs in Docker, run the commands
  inside the container (`docker exec -it <container> sh`).
- An account on the FIDU identity service, <https://identity.firstdataunion.org> (sign-up is open).

Hermes keeps its files in `~/.hermes` (`/opt/data` in the Docker image, or wherever `HERMES_HOME` points).
`hermes config path` prints the settings file inside it.

## 1. Get scan credentials

1. Sign in at <https://identity.firstdataunion.org>.
2. Open the **Sentrook** tab and click **Create Credentials**. Any name will do (for example `hermes-laptop`).
3. Copy the **Client ID** and **Client Secret** somewhere private. The secret may not be shown again.

The secret is a password: never paste it into a chat with your agent.

## 2. Install, switched off

```bash
hermes plugins install FirstDataUnion/Sentrook-hermes --no-enable
```

`--no-enable` keeps the plugin off until its settings are in place, so it never runs in enforce mode by accident.
`hermes plugins list` now shows `sentrook` as not enabled.

## 3. Choose observe mode

```bash
hermes config set plugins.entries.sentrook.settings.mode observe
```

## 4. Save the credentials

The plugin reads `SENTROOK_SCAN_CLIENT_ID` and `SENTROOK_SCAN_CLIENT_SECRET` from the environment or from Hermes's
`.env` file. Keep them out of `config.yaml`. This block prompts for both (the secret is not echoed) and writes them to
the `.env` file, readable only by your user; run it again to replace them:

```bash
{
  ENV_FILE="$(hermes config env-path 2>/dev/null | tail -n 1)"
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

## 5. Switch it on

```bash
hermes plugins enable sentrook && hermes gateway restart
```

If you don't run the gateway as a service, restart Hermes the way you normally start it.

## 6. Check the setup

```bash
hermes sentrook verify
```

Every line should start with `ok`, and `policy` should show `mode=observe`:

| Failing line | Fix |
| --- | --- |
| `credentials` | Run step 4 again, then restart. |
| `token mint` | The Client ID or secret is wrong or revoked: create new credentials (step 1) and repeat step 4. |
| `scan URL`, `OIDC issuer`, `Rookery URL` | A custom endpoint is set that the plugin refuses (see [Settings](#settings)). Remove it. |
| `scanner health` | The scan service is unreachable from this machine. Check outbound HTTPS to `sentrook.firstdataunion.org`. |

If Hermes answers `'sentrook' is not a hermes command`, the plugin is not enabled: run step 5 again.
`hermes plugins list` should show `sentrook` as enabled, with a 2.0 version.

## 7. First scan

Ask the agent for something small that uses a tool, such as "list the files in your home folder". Then look at what
Sentrook recorded:

```bash
hermes sentrook history 5
```

Each row is one scan: time, tool, risk score, the action Sentrook would take, and the review outcome. In observe mode
the action is recorded but never applied. `hermes sentrook why last` shows the most recent scan in detail: risk,
tier scores, reason codes and the entities it found.

If the history is empty, the agent has not made a tool call since the restart.

## Commands

In a chat with the agent (gateway platforms, and interactive `hermes chat`) type `/sentrook <command>`. Hermes
answers it without sending it to the model. On the command line the same commands are `hermes sentrook <command>`
(all but `help`), plus `verify`. There is no session on the command line, so `hermes sentrook snooze` needs `--all`.

| Command | What it does |
| --- | --- |
| `status` | Plugin version, mode, thresholds, scan host, whether credentials are set, traffic log, grants |
| `history [n]` | The last n scans (default 10) |
| `why [request_id\|last]` | One scan in detail |
| `grants` | Grants in force: from config (read-only) and set by command |
| `grant <kind> <pattern> [flags]` | Add a grant. `kind` is `destination`, `file` or `provider`. Flags: `--persistent` (default is this session only), `--allows read,write` (file only), `--expires 12h` |
| `revoke <id>` | Remove a grant set by command |
| `bind add\|remove\|list [channel]` | Manage channel bindings: the channels this deployment normally delivers to |
| `snooze [duration\|off\|status] [--all]` | Allow review prompts in this session (`--all`: every session) for a while, default 1h, at most 24h |
| `help` | Lists the commands |

**Owner only.** `status` and `help` are open to anyone the gateway admits. Every other command runs only for the
owner: a direct message from a sender listed individually in `<PLATFORM>_ALLOWED_USERS` or `GATEWAY_ALLOWED_USERS`,
or the local terminal (`hermes chat` or `hermes sentrook …`). Group and channel messages are refused, and so is a
direct message admitted only because the gateway allows all users. Every attempt, allowed or refused, is recorded in
the traffic log (unless you turned it off).
Hermes's own `allow_admin_from` is not used.

A snooze never relaxes a block, a review the scanner marks as enforced, or an unattended run (cron jobs, webhooks,
the API server): those still stop.

Where slash commands don't reach the plugin, use `hermes sentrook <command>` on the machine instead:

- **API server and `--oneshot`**: Hermes passes `/sentrook …` to the model as plain text.
- **Mattermost**: a message that starts with `/` is taken by Mattermost as one of its own slash commands. Mention
  the bot first: `@yourbot /sentrook status`.

## Observe, enforce and off

| To | Run, then restart |
| --- | --- |
| Enforce: ask at risk 45 or above, block at 80 or above | `hermes config set plugins.entries.sentrook.settings.mode enforce` |
| Go back to observe (the off switch: nothing is blocked or asked, scans are still logged) | `hermes config set plugins.entries.sentrook.settings.mode observe` |
| Stop scanning entirely (no calls are sent to Sentrook) | `hermes plugins disable sentrook` |

Reviews use Hermes's approval prompt, which needs a person on the other end. Chat platforms and the local terminal
count as attended. Elsewhere, including the API server, cron and webhooks, a review blocks instead. If a UI in front of
the API server shows Hermes's approval prompts, add it with `attended_platforms` (see [Settings](#settings)).

In enforce mode, when the scan service gives no usable answer the plugin asks you whether to run the call without a
scan (`on_scan_error`, default `review`); unattended runs are blocked instead. Bad credentials or endpoints are never let
through silently: even with `on_scan_error` set to `allow`, the call is blocked, or you are asked. If the scan service is down
and you need the agent to keep working, switch to observe mode.

Watch the history for a while before switching to enforce. If a channel you deliver to all the time (a daily report
to your own chat, say) keeps being flagged, bind it with `/sentrook bind add <channel>`.

## What is sent

Each scan sends one request to `sentrook.firstdataunion.org`:

- the request you gave the agent in this turn, and whether it came from you, a scheduled job, a subagent or another
  sender, with the kind of channel it arrived on (chat, API, cron and so on);
- the pending tool call, its arguments and the agent's narration before it, plus any other calls in the same batch;
- the tool results and other new inputs since the last scan, capped at 256 KB (head and tail are kept);
- a short history of the session's earlier calls (the last 20, arguments capped at 4 KB each);
- host facts: platform and plugin version, operating system, home and workspace paths, and whether Hermes's
  approvals and secret redaction are on;
- the grants and channel bindings whose pattern appears in the call's arguments;
- references to the session and agent. Session ids are sent as hashes, not as the ids themselves.

Before anything leaves the machine, secrets the plugin recognises (API keys, tokens, passwords, private keys and
similar) are replaced with placeholders such as `⟦secret:github:…⟧`. Recipients, hosts and email addresses are kept,
because the scanner needs them to judge where data is going. Your files, messages and tool output can still contain
personal information, and that is sent as it is.

A local copy of each scan (the redacted request and the response) is kept in `~/.hermes/sentrook/traffic.jsonl`,
readable only by your user and rotated at 50 MB. The plugin never uploads it. Turn it off with
`hermes config set plugins.entries.sentrook.settings.traffic_log.enabled false`; the history and why commands then
have nothing to show.

## Settings

Set with `hermes config set plugins.entries.sentrook.settings.<key> <value>` and restart. Most keys can also come
from a `SENTROOK_*` environment variable; the setting wins.

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `enforce` | `observe` or `enforce` |
| `review_at` | `45` | Ask at or above this risk |
| `block_at` | `80` | Block at or above this risk |
| `on_scan_error` | `review` | `allow`, `deny` or `review` when the scan gives no usable answer |
| `attended_platforms` | | Extra session platforms where a person answers approvals, such as `api_server` |
| `timeout_ms` | `30000` | How long to wait for a scan |
| `traffic_log.enabled` | `true` | Keep the local traffic log |
| `channel_bindings` | | Channels this deployment normally delivers to |
| `grants` | | Standing grants, as `{kind, pattern, allows?, scope?}` entries |
| `scan_url`, `oidc_issuer`, `rookery_url` | hosted service | Endpoints. Any other value must be https on a `firstdataunion.org` host |

## Updating

```bash
hermes plugins update sentrook && hermes gateway restart
```

After a Hermes update, check that `hermes plugins list` still shows `sentrook` as enabled.

## Uninstall

```bash
hermes plugins remove sentrook && hermes gateway restart
```

This removes the plugin and its settings. It leaves the traffic log, grants and snooze state in
`~/.hermes/sentrook/` and the credentials in `.env`. To remove those too, delete the folder, delete the two
`SENTROOK_SCAN_CLIENT_*` lines from `.env`, and delete the credentials on the identity service's **Sentrook** tab.
To install again later, start from step 2.
