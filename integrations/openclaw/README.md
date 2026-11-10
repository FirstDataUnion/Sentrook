# Sentrook for OpenClaw

The Sentrook plugin scans each tool call your OpenClaw agent is about to make (shell commands, file reads and
writes, web fetches, messages and so on), in the context of what you asked for and what the agent did on the way.
Depending on the risk score it allows the call, asks you to approve it, or blocks it.

This guide installs Sentrook in **enforce mode**, where it protects the agent from the first call. To try it without
it ever blocking or asking, use [observe mode](#observe-mode) instead.

The plugin is a beta (2.0.0-beta). Report problems at <https://github.com/FirstDataUnion/Sentrook/issues>.

## Requirements

- OpenClaw **2026.9.5 or newer** (`openclaw --version`). Tested on 2026.10.3.
- A shell on the machine that runs the OpenClaw gateway, as the user that runs it.
- A free FIDU account, created at <https://identity.firstdataunion.org>.

OpenClaw keeps its files in `~/.openclaw` unless `OPENCLAW_STATE_DIR` or `OPENCLAW_HOME` says otherwise. The
paths below assume the default; substitute yours if it differs.

## 1. Get scan credentials

1. Sign in at <https://identity.firstdataunion.org>.
2. Open the **Sentrook** tab and click **Create Credentials**. Any name will do (for example `openclaw-laptop`).
3. Copy the **Client ID** and **Client Secret** somewhere private. The secret will not be shown again.

The secret is a password: never paste it into a chat with your agent.

## 2. Add the credentials to OpenClaw

Add them before installing: in enforce mode, a plugin without credentials stops every tool call.

Open `~/.openclaw/.env` in a text editor (create it if it doesn't exist) and add these two lines at the end, with
your own values:

```
SENTROOK_SCAN_CLIENT_ID=your-client-id
SENTROOK_SCAN_CLIENT_SECRET=your-client-secret
```

Save the file, and make sure only your user can read it:

```bash
chmod 600 ~/.openclaw/.env
```

Keep the credentials in `.env`, not in `openclaw.json`, which the agent can read. To replace them later, edit the same
two lines and restart the gateway.

## 3. Let Sentrook see your requests

```bash
openclaw config set plugins.entries.sentrook.hooks.allowConversationAccess true
```

This lets the plugin read what you asked the agent for. Without it Sentrook cannot tell whether a call matches your
request: scores are less accurate and more routine work asks for approval.

Until the plugin is installed, OpenClaw warns `plugin not found: sentrook (stale config entry ignored …)`. That is
expected; the setting is kept and applies once the plugin is installed.

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

Every line should start with `ok`, and `policy` should show `mode=enforce`:

| Failing line | Fix |
| --- | --- |
| `credentials` | Check the two lines in `.env` (step 2), then restart the gateway. |
| `token mint` | The Client ID or secret is wrong or revoked: create new credentials (step 1) and replace them in `.env`. |
| `scan URL`, `OIDC issuer`, `Rookery URL` | A custom endpoint is set that the plugin refuses (see [Settings](#settings)). Remove it. |
| `scanner health` | The scan service is unreachable from this machine. Check outbound HTTPS to `sentrook.firstdataunion.org`. |

`openclaw plugins list` should show `sentrook` as enabled, with a 2.0 version.

## 6. First scan

Ask the agent for something small that uses a tool, such as "list the files in your workspace". Then look at what
Sentrook recorded:

```bash
openclaw sentrook history 5
```

Each row is one scan: time, tool, risk score, the action Sentrook took, and the review outcome.
`openclaw sentrook why last` shows the most recent scan in detail: risk, tier scores, reason codes and the entities
it found (hosts, files, recipients, channels).

If the history is empty, the agent has not made a tool call since the restart.

## 7. Tell Sentrook what is normal for you

Sentrook doesn't know which destinations and files are routine for your deployment. Two things tell it, so routine
work stops asking for approval:

- **Channel bindings**: the channels this deployment normally delivers to, such as the chat your daily report goes
  to. A send to a bound channel is not treated as an unfamiliar destination.
- **Grants**: hosts, email domains or channels the agent may send to (`destination`), files or folders it may
  read, write or delete (`file`), and the MCP servers or plugins it may use (`provider`).

Neither ever lowers a scanner floor (reading your SSH keys and sending them somewhere is blocked whatever you grant),
and a file grant never covers a call that also sends data off the machine. You don't need a grant to send to a
destination you name yourself in your request: Sentrook already takes that into account.

Run these commands in the owner's Control UI chat or on the machine (see [who may run them](#commands)). In chat
the commands are `/sentrook-bind`, `/sentrook-grant` and so on. On the command line they are `openclaw sentrook bind`,
`openclaw sentrook grant` and so on, with patterns in quotes so the shell leaves the `*` alone:
`openclaw sentrook grant file '/home/you/notes/*' --allows read,write --persistent`.

### Bind the channel a scheduled job reports to

Say a daily-brief cron job posts to a Discord channel and Sentrook asks for approval each time. Find the scan and
read the channel as Sentrook saw it:

```
/sentrook-history
/sentrook-why <id>
```

The channel is listed under `entities`. Bind exactly that value (here, as an example, `channel:1234567890`), then
check it:

```
/sentrook-bind add channel:1234567890
/sentrook-bind list
```

Bindings stay until you remove them (`/sentrook-bind remove channel:1234567890`).

A binding can also name a channel the way you know it. `#daily-brief` covers that channel however a send writes it
(`#daily-brief`, `channel:daily-brief` or `discord:#daily-brief`). `discord:#daily-brief` covers it on Discord only,
including a send that names Discord in its own argument, as the `message` tool does (`{channel: discord, target:
"#daily-brief"}`). `discord:*` covers every Discord channel a send delivers to. Neither form covers a direct message
(`user:`, `dm:`, an `@handle`), an email address or anything else the call reaches. `/sentrook-bind add` and
`/sentrook-bind list` say when a binding can never apply, and `openclaw sentrook verify` does for the bindings in
`openclaw.json`: one that matches every channel (`*`, `#*`), or one too short to be sent with a scan (such as `ab`).

### Typical grants

A grant set by command covers only the session you set it in unless you add `--persistent`. It does not reach
cron jobs, subagents or other chats, so a grant they need must be `--persistent`.
`--expires` sets an end time. On the command line there is no session: add `--persistent`, or bind the grant to one
session with `--session <ref>`, taking the ref from the `session` column of `/sentrook-history`.

| You want the agent to | Grant |
| --- | --- |
| Call your company's own APIs and email your team | `/sentrook-grant destination *.example.com --persistent` (covers `example.com`, its subdomains and `@example.com` addresses) |
| Post to one webhook or partner API | `/sentrook-grant destination hooks.partner.example --persistent` |
| Keep notes in a folder | `/sentrook-grant file /home/you/notes/* --allows read,write --persistent` |
| Write a nightly report | `/sentrook-grant file /srv/reports/* --allows write --persistent` |
| Work on a client's site for the afternoon | `/sentrook-grant destination *.client.example --expires 4h` |
| Let it clear out a scratch folder | `/sentrook-grant file /home/you/scratch/ --allows delete --persistent` |
| Use your team's MCP servers | `/sentrook-grant provider npm:@yourteam/ --persistent` |

A file grant can use the full path or `~` for your home folder (`~/notes/*`). A `*` matches anything, including `/`.
A pattern ending in `/` covers that folder and everything in it. `--allows` must name everything the call does to
the file: deleting it (`rm`, or moving it away) needs `delete`. Without `--allows` a file grant allows reading only.
A provider pattern is the server's package as `/sentrook-why` shows it, for example `npm:@yourteam/notes-mcp@1.4.0`;
ending it in `/` covers the whole scope. Patterns that would match everything (`*`, `*.*`, `/`) are ignored.

`/sentrook-grants` lists every grant in force with its id; `/sentrook-revoke <id>` removes one set by command.

### Or keep them in config

Grants and bindings can also live in `openclaw.json`, where the commands show them as read-only. Grants there apply
in every session until you remove them, so they need no `scope`. A config grant with scope `session`, or with a scope
Sentrook does not know, has no session to apply in and is never sent; `/sentrook-grants`, `/sentrook status` and `openclaw sentrook verify` flag it. Use
`/sentrook-grant` for a grant in one session.

```json
{
  "plugins": {
    "entries": {
      "sentrook": {
        "config": {
          "channelBindings": ["channel:1234567890"],
          "grants": [
            { "kind": "destination", "pattern": "*.example.com" },
            { "kind": "file", "pattern": "/home/you/notes/*", "allows": ["read", "write"] }
          ]
        }
      }
    }
  }
}
```

Merge this into your existing `plugins.entries.sentrook` entry, then restart the gateway.

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
| `/sentrook-grant <kind> <pattern> [flags]` | Add a grant. `kind` is `destination`, `file` or `provider`. Flags: `--persistent` (default is this session only, not cron jobs, subagents or other chats), `--session <ref>` (bind to that session instead, ref from `history`), `--allows read,write` (file only), `--expires 12h` |
| `/sentrook-revoke <id>` | Remove a grant set by command |
| `/sentrook-bind add\|remove\|list [channel]` | Manage channel bindings |
| `/sentrook-snooze [duration\|off\|status] [--all]` | Allow review prompts in this session (`--all`: every session) for a while, default 1h, at most 24h |

`openclaw sentrook verify` exists only on the command line. There is no session on the command line, so
`openclaw sentrook snooze` needs `--all` and `openclaw sentrook grant` needs `--persistent` or `--session <ref>`.

**Owner only.** `/sentrook status` and `/sentrook help` are open to anyone who can message the agent. The dashed
commands need the gateway scope `operator.admin`: the owner's default Control UI connection has it, and so does
anyone holding the shared gateway token. Limited Control UI sessions are refused. On the command line, whoever can
run `openclaw` on the machine counts as the owner. Every attempt, allowed or refused, is recorded in the traffic log
(unless you turned it off).

A snooze never relaxes a block, a review the scanner marks as enforced, or an unattended run (cron jobs, subagents,
webhooks): those still stop.

On Mattermost, a message that starts with `/` is taken by Mattermost as one of its own slash commands. Mention the
bot first: `@yourbot /sentrook status`.

> **Warning: `commands.ownerAllowFrom`.** If you set OpenClaw's `commands.ownerAllowFrom`, check that every entry
> matches a real client. An entry that matches no one locks every unlisted non-admin gateway client out of **all**
> plugin commands, including `/sentrook status`, with "requires authorization". The plugin cannot see the sender
> list, so it cannot warn you.

## How enforce mode decides

Sentrook asks for approval at risk 45 or above and blocks at 80 or above (`reviewAt`, `blockAt`). Some findings,
such as reading credentials and sending them off the machine, are floors that apply whatever the score.

When a call is blocked the agent is told it was a security block, given a broad category (for example "it reads or
sends sensitive data"), and asked not to retry it or work around it unless you tell it to, and to check with you. It
is not told which checks fired or the risk score; you can see those with `openclaw sentrook why last`.

A review is an OpenClaw approval prompt. In a chat it waits 5 minutes for your answer
(`approval.interactiveTimeoutMs`) and then denies the call. Cron jobs and subagents wait 30 minutes
(`approval.scheduledTimeoutMs`) and then deny it too.

`approval.scheduledTimeoutBehavior: allow` asks OpenClaw to let an unanswered cron or subagent review go through
instead. It works only on an OpenClaw release that reads the approval's timeout behaviour, and no release up to
and including 2026.11.2 does (nor the 2026.11.5-beta.1 pre-release): on those, a plugin approval nobody answers is always denied, whatever this is set to.
With `allow` on such a release, `openclaw sentrook status` and `openclaw sentrook verify` say the setting is not
honoured.

### Skills and memory the agent saves on its own

OpenClaw saves to the agent's skills and memory on its own, with nobody asking:

- after a long turn, the Skill Workshop review reads the conversation and saves skills (file writes in the agent's
  `workshop-skills` folder, or `skill_workshop` proposals);
- before older turns are compacted away, the memory flush saves durable notes to the day's file, `memory/YYYY-MM-DD.md`;
- once a week, the skill collection review tidies the Workshop's skills.

These runs carry your context but are not your messages, and a save has no request of its own, so it would otherwise
look like a write nobody asked for. By default (`skillReview: allow`) the plugin sends every call these runs make as
the host's own (never as your message, and never snoozed), with your last message in the conversation they read as
the request, tells Sentrook which calls are their saves (skill files written inside the Workshop folder, or the
memory flush's write to the day's note; a write anywhere else is scanned like any other call), and sends the
part of the conversation the run read, so Sentrook can judge the save against it. A save that follows from what you
said and did goes through. A save is reviewed or blocked when it carries instructions that came from content the
agent read or from other people, weakens one of your rules, claims approvals you never gave, or stores secrets you
did not ask it to keep. The other calls these runs make (commands, reads) are scanned like any other call. A skill or
memory change you ask for in a turn is scanned like any other call, too.

Each message in that conversation is marked as yours, someone else's or unknown from OpenClaw's own sender flag, never
from what the message says. Set `skillReview` to `review` to send these runs' calls as before, without the
conversation; with nothing to judge them against, expect more saves to be reviewed or blocked. `status` counts the
saves (allowed, blocked, asked) and the history marks them `(self-edit)`.

Two of OpenClaw's own writers never make a tool call, so no plugin can see them: dreaming (the nightly promotion of
notes into `MEMORY.md` and `DREAMS.md`) and the session-memory hook (which writes recent messages into `memory/` on
`/new` and `/reset`). Sentrook does not scan them.

When the scan service gives no usable answer the plugin asks you whether to run the call without a scan
(`onScanError`, default `review`); unattended runs are blocked instead. Bad credentials or endpoints are never let
through silently: even with `onScanError` set to `allow`, the call is blocked, or you are asked.

## Observe mode

In observe mode Sentrook scores and logs every call but never blocks or asks. Use it to try Sentrook before trusting
it with your agent, or as the off switch if it gets in the way, or when the scan service is down and the agent has to
keep working. History and why keep working.

| To | Run, then `openclaw gateway restart` |
| --- | --- |
| Switch to observe | `openclaw config set plugins.entries.sentrook.config.mode observe` |
| Switch back to enforce | `openclaw config set plugins.entries.sentrook.config.mode enforce` |
| Stop scanning entirely (no calls are sent to Sentrook) | `openclaw plugins disable sentrook` |

To start in observe mode from the beginning, set the mode alongside step 3, before installing. In observe mode the
history's `action` column shows what Sentrook would have done, such as `observed (would review)`.

## What is sent

Each scan sends one request to `sentrook.firstdataunion.org`:

- the request you gave the agent in this turn (with `allowConversationAccess`), and whether it came from you, a
  scheduled job, a subagent or another sender;
- the pending tool call, its arguments and the agent's narration before it, plus any other calls in the same batch;
- the tool results and other new inputs since the last scan, capped at 256 KB (head and tail are kept);
- a short history of the session's earlier calls (the last 20, arguments capped at 4 KB each);
- host facts: platform and plugin version, operating system, home and workspace paths, and how OpenClaw is
  configured to run commands (`tools.exec.mode`, read at each scan). This is what the config says, not whether
  OpenClaw will ask about this call: its own approvals store (which the plugin cannot see) and per-agent overrides
  can be stricter;
- the grants and channel bindings that could apply to the call: those whose pattern fits its arguments or the MCP
  server it calls (a `#name` also fits `channel:name`, and a `<platform>:` prefix fits a send that names that
  platform);
- references to the session and agent. Session ids are sent as hashes, not as the ids themselves;
- for a skill or memory save that OpenClaw makes on its own (see above): the conversation that run read, as its
  messages, the agent's replies and the tool results (each cut short, the results to the part that overlaps the save
  most, about 48 KB in all). To have it at hand, the plugin keeps each run's conversation, redacted, in
  `~/.openclaw/sentrook/selfedit/`; it deletes files not changed in 7 days and keeps only the 100 most recent. With `skillReview` set to `review` it deletes them all (at startup, or on its next hook after you
  change the setting) and keeps nothing.

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
| `approval.interactiveTimeoutMs` | `300000` | How long a review in a chat waits for your answer |
| `approval.scheduledTimeoutMs` | `1800000` | How long a review in a cron job or subagent waits |
| `approval.scheduledTimeoutBehavior` | `deny` | What a cron or subagent review does when nobody answers: `allow` or `deny`. OpenClaw 2026.11.2 and older ignore `allow` and deny it |
| `skillReview` | `allow` | `allow` tells Sentrook which calls are OpenClaw's own skill and memory saves and sends the conversation they are judged against; `review` sends them like any other call. Any other value reads as `allow`, and `status` names it |
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

This removes the plugin and its settings, including grants and bindings kept in `openclaw.json`. It leaves the
traffic log, the grants and bindings set by command, the snooze state and any kept conversations in `~/.openclaw/sentrook/`, and the
credentials in `~/.openclaw/.env`. To remove those too, delete the folder, delete the two `SENTROOK_SCAN_CLIENT_*`
lines from `.env`, and delete the credentials on the identity service's **Sentrook** tab. To install again later,
start from step 3.
