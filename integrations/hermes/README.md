# Sentrook for Hermes Agent

The Sentrook plugin scans each tool call your Hermes agent is about to make (terminal commands, file reads and
writes, web fetches, messages and so on), in the context of what you asked for and what the agent did on the way.
Depending on the risk score it allows the call, asks you through Hermes's own approval prompt, or blocks it.

This guide installs Sentrook in **enforce mode**, where it protects the agent from the first call. To try it without
it ever blocking or asking, use [observe mode](#observe-mode) instead.

The plugin is a beta (2.0.0-beta). Report problems at <https://github.com/FirstDataUnion/Sentrook/issues>.

## Requirements

- Hermes Agent **v0.21 or newer** (`hermes --version`). Tested on v0.21.7.
- A shell on the machine that runs Hermes, as the user that runs it. If Hermes runs in Docker, run the commands
  inside the container (`docker exec -it <container> sh`).
- A free FIDU account, created at <https://identity.firstdataunion.org>.

Hermes keeps its files in `~/.hermes` (`/opt/data` in the Docker image, or wherever `HERMES_HOME` points).
`hermes config path` prints the settings file inside it.

## 1. Get scan credentials

1. Sign in at <https://identity.firstdataunion.org>.
2. Open the **Sentrook** tab and click **Create Credentials**. Any name will do (for example `hermes-laptop`).
3. Copy the **Client ID** and **Client Secret** somewhere private. The secret will not be shown again.

The secret is a password: never paste it into a chat with your agent.

## 2. Add the credentials to Hermes

Add them before installing: in enforce mode, a plugin without credentials stops every tool call.

`hermes config env-path` prints Hermes's `.env` file, usually `~/.hermes/.env`. Open it in a text editor and add these
two lines at the end, with your own values:

```
SENTROOK_SCAN_CLIENT_ID=your-client-id
SENTROOK_SCAN_CLIENT_SECRET=your-client-secret
```

Save the file, and make sure only your user can read it:

```bash
chmod 600 ~/.hermes/.env
```

Keep the credentials in `.env`, not in `config.yaml`. To replace them later, edit the same two lines and restart.

## 3. Install

```bash
hermes plugins install FirstDataUnion/Sentrook-hermes --enable && hermes gateway restart
```

If you don't run the gateway as a service, restart Hermes the way you normally start it.

## 4. Check the setup

```bash
hermes sentrook verify
```

Every line should start with `ok`, and `policy` should show `mode=enforce`:

| Failing line | Fix |
| --- | --- |
| `credentials` | Check the two lines in `.env` (step 2), then restart. |
| `token mint` | The Client ID or secret is wrong or revoked: create new credentials (step 1) and replace them in `.env`. |
| `scan URL`, `OIDC issuer`, `Rookery URL` | A custom endpoint is set that the plugin refuses (see [Settings](#settings)). Remove it. |
| `scanner health` | The scan service is unreachable from this machine. Check outbound HTTPS to `sentrook.firstdataunion.org`. |

If Hermes answers `'sentrook' is not a hermes command`, the plugin is not enabled: run
`hermes plugins enable sentrook` and restart. `hermes plugins list` should show `sentrook` as enabled, with a 2.0
version.

## 5. First scan

Ask the agent for something small that uses a tool, such as "list the files in your home folder". Then look at what
Sentrook recorded:

```bash
hermes sentrook history 5
```

Each row is one scan: time, tool, risk score, the action Sentrook took, and the review outcome.
`hermes sentrook why last` shows the most recent scan in detail: risk, tier scores, reason codes and the entities it
found (hosts, files, recipients, channels).

If the history is empty, the agent has not made a tool call since the restart.

## 6. Tell Sentrook what is normal for you

Sentrook doesn't know which destinations and files are routine for your deployment. Two things tell it, so routine
work stops asking for approval:

- **Channel bindings**: the channels this deployment normally delivers to, such as the chat your daily report goes
  to. A send to a bound channel is not treated as an unfamiliar destination.
- **Grants**: hosts, email domains or channels the agent may send to (`destination`), files or folders it may
  read, write or delete (`file`), and the MCP servers or plugins it may use (`provider`).

Neither ever lowers a scanner floor (reading your SSH keys and sending them somewhere is blocked whatever you grant),
and a file grant never covers a call that also sends data off the machine. You don't need a grant to send to a destination
you name yourself in your request: Sentrook already takes that into account.

Run these commands in a direct message to the agent or on the machine (see [who may run them](#commands)). In chat
type `/sentrook …`. On the command line it is `hermes sentrook …`, with patterns in quotes so the shell leaves the `*`
alone: `hermes sentrook grant file '/home/you/notes/*' --allows read,write --persistent`.

### Bind the channel a scheduled job reports to

Say a daily-brief cron job posts to a Discord channel and Sentrook asks for approval each time. Find the scan and
read the channel as Sentrook saw it:

```
/sentrook history
/sentrook why <id>
```

The channel is listed under `entities`. Bind exactly that value (here, as an example, `discord:#daily-brief`),
then check it:

```
/sentrook bind add discord:#daily-brief
/sentrook bind list
```

Bindings stay until you remove them (`/sentrook bind remove discord:#daily-brief`).

A binding can also name a channel the way you know it. `#daily-brief` covers that channel on any platform, however a
send writes it (`#daily-brief`, `channel:daily-brief` or `discord:#daily-brief`). `discord:#daily-brief` covers it on
Discord only, including a send that names Discord in its own argument (`{channel: discord, target: "#daily-brief"}`).
`discord:*` covers every Discord channel. A `#name` binding, with or without a platform, never covers a direct
message (`user:` or `dm:`). `/sentrook bind list` and `hermes sentrook verify` say when a binding can never apply:
one that matches every channel (`*`, `#*`), or one with fewer than three characters besides `*`, which is never sent
with a scan.

### Typical grants

A grant set by command covers only the session you set it in unless you add `--persistent`. It does not reach
cron jobs, subagents or other chats, so a grant they need must be `--persistent`.
`--expires` sets an end time. On the command line there is no session: add `--persistent`, or bind the grant to one
session with `--session <ref>`, taking the ref from the `session` column of `/sentrook history`.

| You want the agent to | Grant |
| --- | --- |
| Call your company's own APIs and email your team | `/sentrook grant destination *.example.com --persistent` (covers `example.com`, its subdomains and `@example.com` addresses) |
| Post to one webhook or partner API | `/sentrook grant destination hooks.partner.example --persistent` |
| Keep notes in a folder | `/sentrook grant file /home/you/notes/* --allows read,write --persistent` |
| Write a nightly report | `/sentrook grant file /srv/reports/* --allows write --persistent` |
| Work on a client's site for the afternoon | `/sentrook grant destination *.client.example --expires 4h` |
| Let it clear out a scratch folder | `/sentrook grant file /home/you/scratch/ --allows delete --persistent` |
| Use your team's MCP servers | `/sentrook grant provider npm:@yourteam/ --persistent` |

A file grant can use the full path or `~` for your home folder (`~/notes/*`). A `*` matches anything, including `/`.
A pattern ending in `/` covers that folder and everything in it. `--allows` must name everything the call does to
the file: deleting it (`rm`, or moving it away) needs `delete`. Without `--allows` a file grant allows reading only.
A provider pattern is the server's package as `/sentrook why` shows it, for example `npm:@yourteam/notes-mcp@1.4.0`;
ending it in `/` covers the whole scope. Patterns that would match everything (`*`, `*.*`, `/`) are ignored.

`/sentrook grants` lists every grant in force with its id; `/sentrook revoke <id>` removes one set by command.

### Or keep them in config

Grants and bindings can also live in `config.yaml`, where the commands show them as read-only. Grants there apply
in every session until you remove them, so they need no `scope`. A config grant with scope `session`, or with a scope
Sentrook does not know, has no session to apply in and is never sent; `/sentrook grants`, `/sentrook status` and
`hermes sentrook verify` flag it. Use `/sentrook grant` for a grant in one session.

```yaml
plugins:
  entries:
    sentrook:
      settings:
        channel_bindings: ["discord:#daily-brief"]
        grants:
          - {kind: destination, pattern: "*.example.com"}
          - {kind: file, pattern: "/home/you/notes/*", allows: [read, write]}
```

Restart after editing.

## Commands

In a chat with the agent (gateway platforms, and interactive `hermes chat`) type `/sentrook <command>`. Hermes
answers it without sending it to the model. On the command line the same commands are `hermes sentrook <command>`
(all but `help`), plus `verify`. There is no session on the command line, so `hermes sentrook snooze` needs `--all`
and `hermes sentrook grant` needs `--persistent` or `--session <ref>`.

| Command | What it does |
| --- | --- |
| `status` | Plugin version, mode, thresholds, scan host, whether credentials are set, traffic log, grants, snooze, and how many of Hermes's own skill and memory saves were allowed or blocked |
| `history [n]` | The last n scans (default 10) |
| `why [request_id\|last]` | One scan in detail |
| `grants` | Grants in force: from config (read-only) and set by command |
| `grant <kind> <pattern> [flags]` | Add a grant. `kind` is `destination`, `file` or `provider`. Flags: `--persistent` (default is this session only, not cron jobs, subagents or other chats), `--session <ref>` (bind to that session instead, ref from `history`), `--allows read,write` (file only), `--expires 12h` |
| `revoke <id>` | Remove a grant set by command |
| `bind add\|remove\|list [channel]` | Manage channel bindings |
| `snooze [duration\|off\|status] [--all]` | Allow review prompts in this session (`--all`: every session) for a while, default 1h, at most 24h |
| `help` | Lists the commands |

**Owner only.** `status` and `help` are open to anyone the gateway admits. Every other command runs only for the
owner: a direct message from a sender listed individually in `<PLATFORM>_ALLOWED_USERS` or `GATEWAY_ALLOWED_USERS`,
or the local terminal (`hermes chat` or `hermes sentrook …`). Group and channel messages are refused, and so is a
direct message admitted only because the gateway allows all users. Every attempt, allowed or refused, is recorded in
the traffic log (unless you turned it off). Hermes's own `allow_admin_from` is not used.

A snooze never relaxes a block, a review the scanner marks as enforced, or an unattended run (cron jobs, webhooks,
the API server): those still stop.

Where slash commands don't reach the plugin, use `hermes sentrook <command>` on the machine instead:

- **API server and `--oneshot`**: Hermes passes `/sentrook …` to the model as plain text.
- **Mattermost**: a message that starts with `/` is taken by Mattermost as one of its own slash commands. Mention
  the bot first: `@yourbot /sentrook status`.

## How enforce mode decides

Sentrook asks for approval at risk 45 or above and blocks at 80 or above (`review_at`, `block_at`). Some findings,
such as reading credentials and sending them off the machine, are floors that apply whatever the score.

When a call is blocked the agent is told it was a security block, given a broad category (for example "it reads or
sends sensitive data"), and asked not to retry it or work around it unless you tell it to, and to check with you. It
is not told which checks fired or the risk score; you can see those with `hermes sentrook why last`.

Reviews use Hermes's approval prompt, which needs a person on the other end. Chat platforms and the local terminal
count as attended. Elsewhere, including the API server, cron and webhooks, a review blocks instead. If a UI in front of
the API server shows Hermes's approval prompts, add it with `attended_platforms` (see [Settings](#settings)).

### Hermes's own skill and memory saves

After a turn, Hermes reviews what it learned and saves skills (`skill_manage`) and memory (`memory`) in the
background; when idle, its curator tidies those skills. This background review has no request of its own, so a
save would otherwise look like a write nobody asked for. By default (`skill_review: allow`) the plugin tells
Sentrook that the call is one of these background saves and sends the part of the conversation the review read,
and Sentrook judges the save against that conversation. A save that follows from what you said and did goes
through. A save is reviewed or blocked when it carries instructions that came from content the agent read or from
other people, weakens one of your rules, claims approvals you never gave, or stores secrets you did not ask it to
keep. As for any call, on unattended runs (the API server, webhooks, cron) a review is a block, because nobody is
there to answer it; in a chat or the local terminal you are asked.

Every background save is scanned and logged, and `status` counts them: allowed, blocked and asked. Only Hermes's
automatic review and curator count: a skill or memory change you ask for in a turn, or a `/refine` you run, is
scanned like any other call, and so is every other tool those background runs call. Every call a background run
makes is sent with your last message as its request and the number of the turn it follows, and does not count as
a turn of its own; if you have not written anything in the session yet, the request names the background review
instead. Set `skill_review` to `review`
to send the background saves like any other call, without the conversation; with nothing to judge them against,
expect more of them to be reviewed or blocked.

When the scan service gives no usable answer the plugin asks you whether to run the call without a scan
(`on_scan_error`, default `review`); unattended runs are blocked instead. Bad credentials or endpoints are never let
through silently: even with `on_scan_error` set to `allow`, the call is blocked, or you are asked.

## Observe mode

In observe mode Sentrook scores and logs every call but never blocks or asks. Use it to try Sentrook before trusting
it with your agent, or as the off switch if it gets in the way, or when the scan service is down and the agent has to
keep working. History and why keep working.

| To | Run, then restart |
| --- | --- |
| Switch to observe | `hermes config set plugins.entries.sentrook.settings.mode observe` |
| Switch back to enforce | `hermes config set plugins.entries.sentrook.settings.mode enforce` |
| Stop scanning entirely (no calls are sent to Sentrook) | `hermes plugins disable sentrook` |

To start in observe mode from the beginning, install with `--no-enable` in step 3, set the mode, then run
`hermes plugins enable sentrook` and restart. In observe mode the history's `action` column shows what Sentrook
would have done, such as `observed (would review)`.

## What is sent

Each scan sends one request to `sentrook.firstdataunion.org`:

- the request you gave the agent in this turn, and whether it came from you, a scheduled job, a subagent, another
  sender or Hermes's own background skill review, with the kind of channel it arrived on (chat, API, cron and so on);
- the pending tool call, its arguments and the agent's narration before it, plus any other calls in the same batch;
- the tool results and other new inputs since the last scan, capped at 256 KB (head and tail are kept);
- a short history of the session's earlier calls (the last 20, arguments capped at 4 KB each);
- host facts: platform and plugin version, operating system, home and workspace paths, and whether Hermes's
  approvals and secret redaction are on;
- the grants and channel bindings that could apply to the call: those whose pattern fits its arguments or the MCP
  server it calls (a `#name` also fits `channel:name`, and a `<platform>:` prefix fits a send that names that
  platform);
- references to the session and agent. Session ids are sent as hashes, not as the ids themselves;
- for Hermes's own background skill and memory saves only (see
  [Hermes's own skill and memory saves](#hermess-own-skill-and-memory-saves)): your recent messages with who sent
  them, the agent's replies, and excerpts of the tool results the save draws on, all redacted the same way. To
  have them at hand, the plugin keeps the last 200 or so messages and tool results of each session, redacted, in
  `~/.hermes/sentrook/conversations/`. When it writes one of these logs, at most once an hour, it deletes logs not
  changed in 7 days and keeps only the 100 most recently changed. With `skill_review` set to `review` it deletes them
  all (at startup, or on its next hook after you change the setting) and keeps nothing.

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
| `skill_review` | `allow` | `allow` tells Sentrook which calls are Hermes's own background skill and memory saves and sends the conversation they are judged against; `review` sends them like any other call. A YAML `false` (`off`, `no`) reads as `review` and `true` as `allow`; any other value reads as `allow`, and `status` names it |
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

This removes the plugin and its settings, including grants and bindings kept in `config.yaml`. It leaves the
traffic log, the grants and bindings set by command, and the snooze state in `~/.hermes/sentrook/`, and the
credentials in `.env`. To remove those too, delete the folder, delete the two `SENTROOK_SCAN_CLIENT_*` lines from
`.env`, and delete the credentials on the identity service's **Sentrook** tab. To install again later, start from
step 3.
