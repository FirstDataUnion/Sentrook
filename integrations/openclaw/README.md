# Sentrook for OpenClaw

The Sentrook plugin scans each tool call your OpenClaw agent is about to make (shell commands, file reads and
writes, web fetches, messages and so on), in the context of what you asked for and what the agent did on the way.
Depending on the risk score it allows the call, asks you to approve it, or blocks it.

This guide installs Sentrook in **enforce mode**, where it protects the agent from the first call. To try it without
it ever blocking or asking, use [observe mode](#observe-mode) instead.

The plugin is a beta (2.0.0-beta). Report problems at <https://github.com/FirstDataUnion/Sentrook/issues>.

## Requirements

- OpenClaw **2026.9.5 or newer** (`openclaw --version`). Tested on 2026.9.5 and 2026.11.5. Older releases refuse
  to install the plugin.
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

Then point the plugin at them. These two commands store references to the two variables in `openclaw.json`, not the
values: OpenClaw loads `.env` into its environment, and the plugin reads the variables the references name.

```bash
openclaw config set plugins.entries.sentrook.config.clientId --ref-provider default --ref-source env --ref-id SENTROOK_SCAN_CLIENT_ID
openclaw config set plugins.entries.sentrook.config.clientSecret --ref-provider default --ref-source env --ref-id SENTROOK_SCAN_CLIENT_SECRET
```

Keep the values in `.env`, not in `openclaw.json`, which the agent can read. Without the references the plugin still
finds the two lines, because it reads `.env` itself too; that works in this release. To replace the credentials later, edit the same
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
| `credentials` | Check the two lines in `.env` and the two references (step 2), then restart the gateway. |
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
  read, write or delete (`file`), the MCP servers or plugins it may use (`provider`), and which API key belongs to
  which service (`credential`).

Neither ever lowers a scanner floor (reading your SSH keys and sending them somewhere is blocked whatever you grant),
and a file grant never covers a call that also sends data off the machine. You don't need a grant to send to a
destination you name yourself in your request: Sentrook already takes that into account.

You don't have to work these out in advance. When a review is caused by something a grant would cover, such as a
host Sentrook has not seen before, the approval card ends with the command that would let calls like it through next
time, for example `/sentrook-grant destination api.example.com --persistent --expires 30d`. Sentrook only suggests a
grant after checking that, with it, the same call would score below the review line; it never suggests one for a
known-bad or look-alike host, for something that content the agent read put in front of it, for a file being sent
out of a session that has read content trying to instruct the agent, or for a call with a clear attack signal, and it
suggests trusting a new tool provider only when you asked for the work in your own chat. It suggests a grant only for
a call that came from your own message (or a run OpenClaw marks as yours), or from a cron job or heartbeat OpenClaw
started itself; someone else's message, a subagent or a webhook or event run gets none. A cron job's or heartbeat's
suggestion reaches you only through its held call: `/sentrook-why <id>` names the grant and the run it came from, and
`/sentrook-approve <id>` sets it. A suggestion is a good guess, not a promise: Sentrook's judge sees
the grant on the next scan too. When you asked for the work yourself (your own message, not a group chat), the card also offers
**Allow always**, which allows the call and sets that grant, persistent for 30 days. `/sentrook-why` lists every
grant Sentrook suggested for a scan.

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

You don't need a binding for the channel a cron job is set up to deliver to (its `delivery.channel` and
`delivery.to`, from `openclaw cron add --announce --channel discord --to <channel id>`): on that job's run, a send
to that channel is not treated as going somewhere unfamiliar on that run. The plugin reads the job's delivery from
OpenClaw's job store when the run starts, so only what the job itself is set to counts, never a channel named in its
task or in anything the run read. Only a channel or group target counts: not a direct message, a phone number or
another person's chat, and not a job with no target of its own (`--channel last`, or no `--to`). It also counts for
nothing once the job is changed during the run (by the agent's cron tool or in the store). The dashboard shows that
relief as a cron job's delivery target.

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
| Run install scripts from a GitHub repository you trust | `/sentrook-grant repo github.com/yourteam/tools --persistent` |
| Use your own API key with the service it is for | `/sentrook-grant credential MY_SERVICE_TOKEN@api.myservice.example` |

An agent that reads an API key from its env file and sends it to the service it belongs to is doing the normal
thing. Sentrook already knows the keys of some common providers and the hosts they go to; for any other
service, a `credential` grant says the same: `NAME@host`, the key's environment name and the service's API host.
The name may end in `*` after three or more characters (`MY_SERVICE_*`), and the host may be `*.example.com` (that
domain and every name under it, but not a shared suffix such as `*.co.uk`). With it, sending that key only to that host is not treated as sensitive data
leaving the machine, and the host is not treated as unfamiliar on that call. The key sent anywhere else, written to a
file or printed, sent alongside another secret or file, or sent to a host that content the agent read named, is
still reviewed. A credential grant lasts until you revoke it unless you give `--scope session` or `--expires`. When a
review is caused by such a key going to its own service, the prompt suggests this grant (`/sentrook-grant credential
MY_SERVICE_TOKEN@api.myservice.example --persistent --expires 30d`).

A file grant can use the full path or `~` for your home folder (`~/notes/*`). A `*` matches anything, including `/`.
A pattern ending in `/` covers that folder and everything in it. `--allows` must name everything the call does to
the file: deleting it (`rm`, or moving it away) needs `delete`. Without `--allows` a file grant allows reading only.
A provider pattern is the server's package as `/sentrook-why` shows it, for example `npm:@yourteam/notes-mcp@1.4.0`;
ending it in `/` covers the whole scope. Patterns that would match everything (`*`, `*.*`, `/`) are ignored.
Anyone can publish on GitHub and Hugging Face, so a script fetched from one and run counts as code from an unknown source until a
repo grant covers its repository: `github.com/<owner>/<repo>` (raw.githubusercontent.com and git remotes count as
github.com), `github.com/<owner>/*` for an account, `huggingface.co/<org>/<name>`. The host and owner must be written
out; a release-asset download (objects.githubusercontent.com) names no repository and no grant covers it.

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
| `/sentrook status` | Plugin version, mode, thresholds, scan host, whether credentials are set, held calls, where notices go, and OpenClaw's own saves by outcome |
| `/sentrook help` | Lists the commands |
| `/sentrook-history [n]` | The last n scans (default 10) |
| `/sentrook-why [request_id\|last]` | One scan in detail, with the grants that would allow it next time; with the id from a held-call notice, also the hold and the grant approving it sets |
| `/sentrook-report [request_id\|last] [--full\|--github\|--save]` | A report of a scan that looks wrong, to send to us (see [Report a wrong scan](#report-a-wrong-scan)) |
| `/sentrook-grants` | Grants in force: from config (read-only) and set by command |
| `/sentrook-grant <kind> <pattern> [flags]` | Add a grant. `kind` is `destination`, `file` or `provider`. Flags: `--persistent` (default is this session only, not cron jobs, subagents or other chats), `--session <ref>` (bind to that session instead, ref from `history`), `--allows read,write` (file only), `--expires 12h` |
| `/sentrook-revoke <id>` | Remove a grant set by command |
| `/sentrook-bind add\|remove\|list [channel]` | Manage channel bindings |
| `/sentrook-snooze [duration\|off\|status] [--all]` | Allow review prompts in this session (`--all`: every session) for a while, default 1h, at most 24h; blocks without a clear attack signal ask you instead |
| `/sentrook-notify here\|off\|status` | Where notices go (held calls, scan failures on unattended runs, [background saves](#background-skill-and-memory-saves)): `here`, sent as a direct message to the agent, sends notices to you in that chat |
| `/sentrook-approve <id>` | Approve a held call by the id in its notice, within 24 hours (see [Held calls](#held-calls-in-cron-jobs-and-subagents)) |

`openclaw sentrook verify` exists only on the command line. There is no session on the command line, so
`openclaw sentrook snooze` needs `--all` and `openclaw sentrook grant` needs `--persistent` or `--session <ref>`.

**Owner only.** `/sentrook status` and `/sentrook help` are open to anyone who can message the agent. The dashed
commands need the gateway scope `operator.admin`: the owner's default Control UI connection has it, and so does
anyone holding the shared gateway token. Limited Control UI sessions are refused. In a chat channel, OpenClaw lets the
owner (a sender in `commands.ownerAllowFrom`) run them from a direct message, which is how `/sentrook-notify here` and
`/sentrook-approve` are meant to be used. On the command line, whoever can
run `openclaw` on the machine counts as the owner. Every attempt, allowed or refused, is recorded in the traffic log
(unless you turned it off).

If Sentrook blocks your own setup work, snooze for the duration: blocks without a clear attack signal then ask you
instead; blocks with a clear attack signal still stop. While a snooze is on, in a chat you attend, a block the scanner
marks as having no clear attack signal (you asked in the chat, nothing came from content the agent read, no known-bad
or look-alike entity, no retry of a call you denied, no credential leaving for a destination you have not named or
granted, no floor, and the scan was complete) becomes an approval prompt at critical severity that says "Would be
blocked, but a snooze is on." It is never allowed without asking, and the snooze does not skip that prompt. The score
is the same either way.

A snooze never allows a block, a review the scanner marks as enforced, or anything on an unattended run (cron jobs,
subagents, webhooks): blocks still stop, and a review on an unattended run is held for you instead.

A chat you attend is a direct chat with the agent: a DM, webchat or the Control UI. A group or channel room is not,
even when you wrote the message, and neither is a turn of OpenClaw's own system agent. The plugin tells them apart by
the session key OpenClaw gives the turn (a room has its own `...:group:...` or `...:channel:...` key; with the
default `session.dmScope: "main"` a DM runs in the agent's main session). If you set `session.groupScope: "main"`,
globally or on a route binding, rooms share the main session too, so the plugin can no longer tell a DM from a room
there and treats those turns as not attended.

On Mattermost, a message that starts with `/` is taken by Mattermost as one of its own slash commands. Mention the
bot first: `@yourbot /sentrook status`.

> **Warning: `commands.ownerAllowFrom`.** If you set OpenClaw's `commands.ownerAllowFrom`, check that every entry
> matches a real client. An entry that matches no one locks every unlisted non-admin gateway client out of **all**
> plugin commands, including `/sentrook status`, with "requires authorization". The plugin cannot see the sender
> list, so it cannot warn you.

## Dashboard

The plugin adds a **Sentrook** tab to the Control UI with the recent scans, newest first. Open a scan to see its
risk broken down: the three scores the scanner combines (suspicion, consequence and confidence), every signal under
each one with the reasons that raised it, and any floor or grant that changed the result. Grants and snooze are shown
as they stand.

Anything waiting for you comes first: an approval prompt still open, or a call held for your approval, each with the command that answers it. Below, the history shows 10, 25 or 50 scans a page; **Older** pages back. Search by tool name, outcome, time window or minimum risk. The traffic log has no index, so a search reads it backwards from the newest line, skipping lines outside the time window without parsing them; a time window makes searches faster. A search reads at most the whole log at its configured size (twice `trafficLog.maxBytes`, up to 256 MB) and says when it stopped early.

The tab only reads. To change a grant or a snooze, use the commands above. It shows the same records as
`/sentrook-history` and `/sentrook-why`, and nothing when the traffic log is off.

By default the tab never shows what a call contained: an edit shows its tool and the files it touched, not the edit.
To see the call itself, turn on `dashboardShowCalls`:

```bash
openclaw config set plugins.entries.sentrook.config.dashboardShowCalls true
```

Each scan then has **Show the call**, collapsed under its details: the tool and its arguments as the plugin sent them
to the scanner. Secrets are masked; file contents, messages and commands are shown as the agent wrote them (an edit's
old and new text side by side), and very long text is cut. Anyone with gateway access can open the tab, so leave it
off on a gateway you share. Without it, `/sentrook-report <id> --save` writes a scan's full record to a file only you
can read.

Every scan has **Report this scan…**, which opens the report described in [Report a wrong scan](#report-a-wrong-scan):
the summary to copy, a button for a public GitHub issue with it filled in, and the commands and email address for the
full record, which the tab does not show.

The tab uses the Control UI's own sign-in, so it needs HTTPS (or Tailscale Serve) or the Control UI on a loopback
address, and a browser that allows the Control UI's cookies in embedded frames. On plain HTTP from another machine,
the tab shows an unavailable message; use the commands instead. The page is also served at `/sentrook` on the gateway
to anyone with gateway access.


## Report a wrong scan

If Sentrook stopped something it should have allowed, or let through something it should have stopped, send us a
report. `/sentrook-report <id>` (the id from `/sentrook-history`; `last` or nothing for the newest scan) prints the
scan as `/sentrook-why` shows it, plus the host, plugin and scanner versions, between `BEGIN` and `END` lines. Fill in
its last two lines (what you expected, what you were doing) where you paste it. It holds no call arguments or
conversation text. Then:

- **Colleagues:** paste it into Discord or chat. If we ask for the full record, `/sentrook-report <id> --full`
  prints it too.
- **Everyone else:** `/sentrook-report <id> --github` gives a link that opens a GitHub issue with the report filled
  in. The issue is public: read the report and remove anything private before you submit it.
- **The full record, privately:** `/sentrook-report <id> --save` writes the report and the full record (the exact
  request Sentrook saw) to a file only you can read, under the plugin's state folder. Email it to
  sentrook@firstdataunion.org with the subject the command gives. The full record can hold conversation text, file
  paths, names and addresses: read it first, and never post it in an issue. Email is not end-to-end encrypted; we keep
  emailed records for up to 30 days, then delete them.

## How enforce mode decides

Sentrook asks for approval at risk 45 or above and blocks at 80 or above (`reviewAt`, `blockAt`). Some findings,
such as reading credentials and sending them off the machine, are floors that apply whatever the score. If a scanner marks a call as review at most
(an option for chats you attend, which the hosted scanner leaves off), the plugin asks you about a block-level score
instead of blocking it, and a snooze never skips that review.

A snooze can turn a block on your own setup work into a question; see the snooze paragraph under
[Commands](#commands).

When a call is blocked the agent is told it was a security block, given a broad category (for example "it reads or
sends sensitive data"), and asked not to retry it or work around it unless you tell it to, and to check with you. It
is not told which checks fired or the risk score; you can see those with `openclaw sentrook why last`.

A review is an OpenClaw approval prompt. In a chat it waits 5 minutes for your answer
(`approval.interactiveTimeoutMs`) and then denies the call.

### What a review looks like

The prompt's title starts with a feather and the risk score; OpenClaw adds the plugin id (`sentrook`) and the
buttons:

```text
🪶 Sentrook security check · risk 62/100

Sends ~/notes/q3-plan.md to paste.example.net.
Because paste.example.net is new to Sentrook as a place to send data, and earlier, the agent read content aimed at steering it.
"Always allow" also trusts paste.example.net for 30 days.
Details: /sentrook-why 3f9c2a1b
```

- Reviews start at risk 45 and blocks at 80. "Safety rule" in place of "security check" means a rule that always
  asks, whatever the score; the card is then marked critical.
- The lines below say what the call does and, in plain words, the main reasons. Long files and addresses are
  shortened in the middle. OpenClaw refuses a prompt over its size limit, so Sentrook fits the card first, keeping
  the reasons and your options and shortening the description of the call.
- **Allow once** runs this call. **Allow always** appears only when a grant would cover calls like this and you asked
  for the work yourself; it runs the call and sets that grant for 30 days. Otherwise the card gives the command.
- `/sentrook-why <id>` shows everything behind the decision: the scores, the checks that fired, the files and
  addresses in full, and every grant that would allow it next time.

### Held calls in cron jobs and subagents

Nobody is there to answer a review in a cron job, a heartbeat, a subagent, or a run OpenClaw starts from an event (a
webhook or mapped hook, or the agent joining a channel). There the call is **held** instead. Which runs count is set
by `approval.scheduledIntentKinds` (default `cron` and `subagent`); heartbeats and event runs count as `cron`.

- The call does not run. The agent is told it is held for your approval and not to retry it in this run.
- You get one notice as a direct message. It says only that a call was held, which run (a cron job by its id, and
  its name in quotes, or a heartbeat, subagent, or webhook or event run), the tool and its target, a broad category,
  and the commands; read the risk, the reasons and any grant Sentrook suggests with `/sentrook-why <id>`. Run `/sentrook-notify here` once, as a direct message to the
  agent on the channel where you want the notices (not in a group or channel; on Discord the notice goes to you as
  a user). Until then nothing is sent, the call is still held, and `status` and `verify` say notices are not sent.
- Reply `/sentrook-approve <id>` within 24 hours. When Sentrook suggested a grant for the call, approving sets it as a
  persistent grant that ends after 30 days, so the job's next run is scanned with it. When it suggested none,
  approving sets nothing and the reply says so; add a grant with `/sentrook-grant --persistent` if the job should pass.
  The held call itself is never run again.
- A hold nobody approves expires after 24 hours, and nothing runs.

A block (at `blockAt` or above, or one the scanner enforces) is never held: it stays a block. The one exception is a retry of a call whose review nobody answered (it timed out or was held) when only the retry takes it to a block: that retry is held, as a review would be. The traffic log records
the scan with decision `held`, then the approval or the expiry; `/sentrook-history` shows them.

### Skills and memory the agent saves on its own

OpenClaw saves to the agent's skills and memory on its own, with nobody asking:

- after a long turn, the Skill Workshop review reads the conversation and saves skills (file writes in the agent's
  `workshop-skills` folder, or `skill_workshop` proposals);
- before older turns are compacted away, the memory flush saves durable notes to the day's file, `memory/YYYY-MM-DD.md`;
- once a week, the skill collection review tidies the Workshop's skills.

These runs carry your context but are not your messages, and a save has no request of its own, so it would otherwise
look like a write nobody asked for. By default (`skillReview: allow`) the plugin sends every call these runs make as
the host's own (never as your message), with your last message in the conversation they read as
the request, tells Sentrook which calls are their saves (skill files written inside the Workshop folder, or the
memory flush's write to the day's note; a write anywhere else is scanned like any other call), and sends the
part of the conversation the run read, so Sentrook can judge the save against it. A run can also save from the
shell (a heredoc, `tee` or `cp` into a skill folder), which the plugin cannot tell from any other command, so it sends
each of these runs' commands with the conversation too, and Sentrook treats a command as a save only when writing
skill files into the Workshop folder (the day's note for the memory flush) is all it does; a command that also does
anything else is scanned like any other call. A save that follows from what you
said and did goes through. A save is reviewed or blocked when it carries instructions that came from content the
agent read or from other people, weakens one of your rules, claims approvals you never gave, or stores secrets you
did not ask it to keep. The other calls these runs make (reads, commands that save nothing) are scanned like any
other call. A skill or
memory change you ask for in a turn is scanned like any other call, too.

Each message in that conversation is marked as yours, someone else's or unknown from OpenClaw's own sender flag, never
from what the message says. Set `skillReview` to `review` to send these runs' calls as before, without the
conversation; with nothing to judge them against, expect more saves to be reviewed or blocked. `status` counts the
saves by outcome and the history marks them `(self-edit)`.

### Background skill and memory saves

Nobody can answer an approval prompt in these runs: OpenClaw cancels it at once, or ends the run before you could
answer, and the save would be lost without anyone telling you. So Sentrook never asks about one of their saves, on
any OpenClaw version and whatever `skillReview` or `approval.scheduledIntentKinds` say (adding `system` to
`approval.scheduledIntentKinds` is no longer needed for this). Instead:

| Sentrook's answer | What happens to the save | What you get |
| --- | --- | --- |
| allow | It is saved. | Nothing. |
| review below the block line, on a complete scan, and Sentrook marks the save as one it can let through (only with `skillReview: allow`, when Sentrook judged it as a background save, and only for a save that carries what it saves: a Skill Workshop create, patch, write_file or draft, or a file write, edit or patch) | It is saved. | A notice that a save Sentrook would normally ask about was let through: a skill or a memory note, and what it saves as a review would show it. |
| any other review below the block line, of a Skill Workshop draft the agent makes itself, or of a new skill on OpenClaw 2026.11.5 or newer | It goes to the Skill Workshop **drafts** (a new skill is sent there instead), which the agent does not use until you apply it. | Once OpenClaw reports the draft kept, a notice that a skill was saved as a draft for you to review: apply or discard it from the Skill Workshop drafts in the Control UI, or send `/learn drafts` in a chat with the agent. If OpenClaw does not keep it (too many drafts waiting, an invalid skill, the run ended), a notice that the save was not made; if OpenClaw saved the new skill itself instead of the draft, a notice that it was saved live. |
| any other review below the block line of a change to an existing skill's `SKILL.md` (a Skill Workshop patch), on OpenClaw 2026.11.5 or newer, when Sentrook judged it as a background save (`skillReview: allow`) | The plugin reads the live skill, applies the change the way OpenClaw's own patch does (the old text must appear exactly once), and sends the whole changed skill to the **drafts** instead; the live skill is unchanged. The draft's note says it was held by Sentrook, names the scan (for `/sentrook-why`), and says it is the skill as it stood at that time with one change. | The same notices as for a new skill's draft, and the kept-draft notice adds that applying it replaces the skill with the version from when the change was held, so a later change to that skill would be undone (it can be brought back from the skill's history). Each of these drafts is announced, up to 5 per run in 6 hours; a second draft of the same skill says how many drafts of it the run made, since applying them in turn keeps only the last one's change. |
| any other review (a change that cannot be applied to the live skill as OpenClaw would apply it, a change to a support file, a restore, archive or file removal, a memory note, a skill file written directly or by a command, an older OpenClaw or one whose version the plugin cannot read, or a retry the scanner would block) | It is **held**: it is not saved, and the run is told it was not saved and not to retry it. | A notice that the save was held and not made; for an archive or restore, where to do it yourself (Plugins → Skill workshop in the Control UI). |
| block | It is not saved. | A notice that a background save was blocked, with a broad category. |
| the scan fails | As for any unattended run ([When the scan service fails](#when-the-scan-service-fails)): with the default `onScanError` the save is blocked and not kept, with `allow` it is saved unscanned. | The scan-failure notice when it is blocked. |

A save is never sent to the drafts when Sentrook reads a secret in what it saves (a draft would keep it). That check
needs the scan to report what the save adds, which it does with the default `skillReview: allow` and a scanner that
reports it; with an older scanner or `skillReview: review`, a new skill still goes to the drafts as before and only
OpenClaw's own checks apply. A change to an existing skill is not drafted when the skill file cannot be read safely: it
must be the skill's own `SKILL.md` under the agent's Skill Workshop folder, a regular file and not a link, at most
1 MB, and valid UTF-8. Sentrook scanned the change, not the rest of the skill; the rest is what the agent already uses.
OpenClaw also refuses a background patch of a skill the run has not viewed first; the draft route does not check that,
so such a change can still reach your drafts. Applying a draft does not check whether the skill changed since:
OpenClaw replaces the skill with the draft and keeps the version it replaced in the skill's history.

A held background save is not a [held call](#held-calls-in-cron-jobs-and-subagents) you can approve: approving could
not make the save, so it gets no approve id and is not kept with the held calls (`status` counts it on its `skill
review` line instead). If you want the save, ask the agent for it in a chat. Every background save is in
`/sentrook-history`, as `allowed (let through, self-edit)`, `drafted (self-edit)` (`sent to drafts` until OpenClaw
reports it, `not saved (draft refused)` if it does not keep it, `saved live (draft ignored)` if it saved the skill
itself), `held (self-edit)` and so on, and `/sentrook-why <id>` shows the id from a notice in detail.

The notices go where held-call notices go (`/sentrook-notify here`). They name the run (the Skill Workshop background
review, the memory flush before compaction, or the skill collection review's cron job), the kind of save and what it
saves, as a review card would describe it, never the saved text. One notice of each kind is sent per run (per cron job
for the skill collection review) in 6 hours; further ones are only in the history. The first held retry in a run
that Sentrook would otherwise block is announced even after other notices; further ones in that run are not. Without a notify target nothing changes in the table above except that you are
not told: `status` and `verify` then say that background-save notices cannot be delivered. If you only use OpenClaw
from the Control UI or the terminal, there is no direct message to send notices to; check `/sentrook-history` instead.
In observe mode nothing is drafted, held or announced.

The same runs' other calls (a command, a file read) are never asked about either: a prompt there would be lost the
same way, and the run could stop before its save. An allowed call runs and a blocked one is blocked, as anywhere. A
call that needs review is **held**: it does not run, and the run is told nobody can approve it and not to retry it.
You get one notice per run (per cron job for the skill collection review) in 6 hours, naming the run and the call as
a review card would describe it; it is not kept with the held calls you can approve, and `/sentrook-history` shows it
as `held`. A scan failure follows the policy for unattended runs, as for a save.

### Memory Sentrook does not see

Some of OpenClaw's memory writers work inside OpenClaw itself and never make a tool call, so no plugin, Sentrook
included, can scan what they write. This is a known limit of this release. What they write is read back into later
sessions as trusted context, so text that reaches it stays there unscanned. Two of them run on their own:

- **Dreaming** (on by default) runs nightly. It promotes short-term notes into `MEMORY.md`, which is part of the system
  prompt of every later session, and writes `DREAMS.md` and `memory/dreaming/`. OpenClaw counts some fetched text
  as trusted for this promotion (the output of `curl` in a command, for example), so text from a web page can end up
  in `MEMORY.md`.
- **The session-memory hook** (off in a bare config; onboarding turns it on) saves the last messages of a session,
  yours and the agent's, into `memory/YYYY-MM-DD-HHMM.md` on `/new`, `/reset` and the automatic daily or idle reset.

`openclaw sentrook verify` names each one that is on, with the setting that turns it off. It never fails because of
them.

If your agent fetches content you don't trust (web pages, files from other people, output of commands that download
things), turn dreaming off:

```bash
openclaw config set plugins.entries.memory-core.config.dreaming.enabled false
```

It takes effect at once (or send `/dreaming off` in the owner's chat). You lose the automatic nightly consolidation
into `MEMORY.md` and the dream diary; an existing `MEMORY.md` is still read into every session, so check it for
anything you didn't put there.

To close the gap fully, also turn off the session-memory hook:

```bash
openclaw hooks disable session-memory
```

(the setting is `hooks.internal.entries.session-memory.enabled: false`; `hooks.internal.enabled: false` turns off all
of OpenClaw's internal hooks). You lose the session notes saved on `/new` and resets, so later sessions and dreaming
can no longer recall them.

Neither setting can be set per agent. Other memory writers that no plugin sees are run by you rather than the agent:
importing or migrating memory, the `openclaw memory` operator commands (`forget`, `promote --apply`, backfills) and
the memory-wiki vault.

### When the scan service fails

A scan gives no usable answer when the scan service returns an error, does not answer within `timeoutMs` (30
seconds), cannot be reached, or rate-limits the scan. The call is then not scanned, and with the default setting
(`onScanError`: `review`):

- **In a cron job, a heartbeat, a subagent or a run started from an event** (`approval.scheduledIntentKinds`) nobody
  is there to answer, so the call is blocked. The agent is told that Sentrook did not scan the call, that this is a
  service problem rather than a security block, and that the call did not run. The call is not held, so there is
  nothing to approve, but you get a notice where held-call notices go (`/sentrook-notify here`). It names the run,
  the tool and the reason (the service could not be reached, did not answer in time, returned an error or
  rate-limited the scan, or the endpoint or credentials are wrong). You get one notice per cron job (per session for
  other runs): further failures in the same job are blocked without a notice for 6 hours, so an outage sends one
  message per job, not one per call. The traffic log records each with `notice` `queued`, `quiet` or `unsent`.
- **Anywhere else**, such as a chat, you are asked whether to run the call without a scan. It runs only if you
  approve; a prompt nobody answers denies the call after 5 minutes (`approval.interactiveTimeoutMs`).

A snooze does not change this. Set `onScanError` to `deny` to block the call everywhere, or to `allow` to run it
without a scan everywhere. Bad credentials or endpoints are never let through silently: with `allow` the call is
blocked, and with `review` you are asked as above. Whatever the setting, a call blocked on an unattended run because
the scan failed sends the notice described above. In observe mode the failure is logged and the call runs.
The traffic log records these scans with decision `blocked_on_error` or `allowed_on_error`, and `/sentrook-history`
shows them as scan errors.

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
  for a Code Mode `exec` (JavaScript that runs other tools), OpenClaw's mark that it is one, so the code is not read
  as a shell command;
- the tool results and other new inputs since the last scan, capped at 256 KB (head and tail are kept);
- a short history of the session's earlier calls (the last 20, arguments capped at 4 KB each);
- host facts: platform and plugin version, operating system, home and workspace paths, and how OpenClaw is
  configured to run commands (`tools.exec.mode`, read at each scan). This is what the config says, not whether
  OpenClaw will ask about this call: its own approvals store (which the plugin cannot see) and per-agent overrides
  can be stricter;
- the grants and channel bindings that could apply to the call: those whose pattern fits its arguments or the MCP
  server it calls (a `#name` also fits `channel:name`, and a `<platform>:` prefix fits a send that names that
  platform), and on a cron run its job's own delivery target, as a grant for that run only (named by a hash of the
  job id);
- references to the session and agent. Session ids are sent as hashes, not as the ids themselves;
- for a skill or memory save that OpenClaw makes on its own (see above): the conversation that run read, as its
  messages, the agent's replies and the tool results (each cut short, the results to the part that overlaps the save
  most, about 48 KB in all). To have it at hand, the plugin keeps each run's conversation, redacted, in
  `~/.openclaw/sentrook/selfedit/`; it deletes files not changed in 7 days and keeps only the 100 most recent. With `skillReview` set to `review` it deletes them all (at startup, or on its next hook after you
  change the setting) and keeps nothing.

Before anything leaves the machine, secrets the plugin recognises (API keys, tokens, passwords, private keys and
similar) are replaced with placeholders such as `⟦secret:github:…⟧`. Recipients, hosts and email addresses are kept,
because the scanner needs them to judge where data is going. So is code that only reads a secret from where it is
kept, such as `os.environ["API_KEY"]`, `config.token` or `sys.argv[1]`: it names the place, not the secret. Your
files, messages and tool output can still contain personal information, and that is sent as it is.

A local copy of each scan (the redacted request and the response) is kept in `~/.openclaw/sentrook/traffic.jsonl`,
readable only by your user and rotated at 50 MB. The plugin never uploads it. Turn it off with
`openclaw config set plugins.entries.sentrook.config.trafficLog.enabled false`; the history and why commands then
have nothing to show.

## What the plugin does on your machine

In short, for anyone deciding whether to install it:

- **Network:** it calls two services run by First Data Union: the scan service (`sentrook.firstdataunion.org`), once
  per tool call, with the redacted request described in [What is sent](#what-is-sent), and the identity service
  (`identity.firstdataunion.org`) to exchange the scan credentials for a short-lived token. Nothing else, and no
  telemetry beyond the scans themselves.
- **OpenClaw's own saves:** with `skillReview: allow` (the default), the redacted part of the conversation goes with
  each skill and memory save OpenClaw makes on its own, and a redacted copy is kept on disk for up to 7 days to send
  with them. Set it to `review` to stop both.
- **What it can do to a call:** allow it, block it, or ask you through OpenClaw's own approval prompt. It never approves
  a call on your behalf. Where nobody can answer (cron jobs, subagents) a review holds the call and sends you one
  notice, through the channel you chose with `/sentrook-notify here`, and a call blocked because the scan failed sends
  you one notice per job (per session for other runs) every 6 hours at most. OpenClaw's own skill and memory saves
  are never asked about: a reviewed one is let through, saved as a Skill Workshop draft or held, and a notice tells
  you ([Background skill and memory saves](#background-skill-and-memory-saves)). Turning a save into a draft is the
  only change it makes to a call; those notices are the only messages it sends.
- **Files:** it writes only to its own folder, `~/.openclaw/sentrook/` (the traffic log, grants and bindings set by
  command, snooze state, held calls and their lock files, the notice target, when each job or run last had a notice with a quiet period, and
  the conversations above), or to the paths you set for them (`stateDir`,
  `trafficLog.path`). It reads OpenClaw's live config for how commands are run and which memory writers are on; on a
  cron run, that job's definition from OpenClaw's job store (`~/.openclaw/state/openclaw.sqlite`, or
  `~/.openclaw/cron/jobs.json` on releases without it), read-only, for its delivery target; and, to turn a reviewed
  background change to a skill into a draft, that skill's `SKILL.md`. It runs no shell commands and
  starts no background processes.
- **Credentials:** OpenClaw keeps them in `.env` and the plugin reads them through the references set in step 2.
  The plugin also reads `~/.openclaw/.env` itself, at each scan and command, whether or not the references are set: it
  uses only its own `SENTROOK_*` entries from it, and only where its config and OpenClaw's environment do not already
  set them (the credentials, and settings such as `SENTROOK_MODE`). It reads no other credential file.
- **Turning it down or off:** [observe mode](#observe-mode) scores and logs without ever blocking or asking, and
  `openclaw plugins disable sentrook` stops it sending anything.

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
| `skillReview` | `allow` | `allow` tells Sentrook which calls are OpenClaw's own skill and memory saves and sends the conversation they are judged against; `review` sends them like any other call. Any other value reads as `allow`, and `status` names it. Either way those saves are never asked about ([Background skill and memory saves](#background-skill-and-memory-saves)) |
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
