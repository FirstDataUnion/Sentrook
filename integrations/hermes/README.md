# Sentrook for Hermes Agent

The Sentrook plugin scans each tool call your Hermes agent is about to make (terminal commands, file reads and
writes, web fetches, messages and so on), in the context of what you asked for and what the agent did on the way.
Depending on the risk score it allows the call, asks you through Hermes's own approval prompt, or blocks it.

This guide installs Sentrook in **enforce mode**, where it protects the agent from the first call. To try it without
it ever blocking or asking, use [observe mode](#observe-mode) instead.

The plugin is a beta (2.0.0-beta). Report problems at <https://github.com/FirstDataUnion/Sentrook/issues>.

## Requirements

- Hermes Agent **v0.23.0 or newer** (`hermes --version`), the oldest version the plugin declares.
  Tested on v0.23.0 and v0.23.4.
  On an older Hermes, update Hermes first (`hermes update`).
- Plugins loaded inside Hermes (`plugins.isolation: in_process`, the default). With `plugins.isolation: host` every
  call is still scanned, but Hermes's background skill and memory saves are not recognised (see
  [Background skill and memory saves](#background-skill-and-memory-saves)), and Hermes offers no `hermes sentrook`
  commands (`verify`, `history` and the rest): use `/sentrook` in a chat or the terminal session instead.
- A shell on the machine that runs Hermes, as the user that runs it. If Hermes runs in Docker, run the commands
  inside the container (`docker exec -it <container> sh`).
- A FIDU account. It is free, and you can create one while signing in (step 2).

Hermes keeps its files in `~/.hermes` (`/opt/data` in the Docker image, or wherever `HERMES_HOME` points).
`hermes config path` prints the settings file inside it.

## 1. Install

```bash
hermes plugins install FirstDataUnion/Sentrook-hermes --enable
```

From now until you sign in (next step), Sentrook stops every tool call: it never lets a call through unchecked. Each
block tells the agent, and you, to run `hermes sentrook login`.

## 2. Sign in

```bash
hermes sentrook login
```

It prints a link and a code. Open the link on any device (your phone is fine), sign in to your FIDU account or
create a free one, check that the code on the page matches the one in your terminal, and click **Approve**. The
command then has Hermes store this machine's scan credentials (in Hermes's own `.env`, never `config.yaml`) and runs
the checks from step 3. There is nothing to copy. Then restart Hermes so the gateway uses them:

```bash
hermes gateway restart
```

If you don't run the gateway as a service, restart Hermes the way you normally start it.

- If Hermes runs in Docker, run the command inside the container (`docker exec -it <container> hermes sentrook login`).
- The machine is listed in your account as `Hermes on <hostname>`; `--name <label>` picks another name.
- Signing in again from the same machine replaces its credentials rather than adding new ones.
- Your account can have 5 Sentrook connections. To remove one, use the **Sentrook** tab at
  <https://identity.firstdataunion.org/dashboard>.

### Set the credentials by hand instead

With `plugins.isolation: host` there is no `hermes sentrook` command, so set them by hand (or if you prefer to):

1. Sign in at <https://identity.firstdataunion.org>, open the **Sentrook** tab and click **Create Credentials**.
   Copy the **Client ID** and **Client Secret** somewhere private; the secret will not be shown again, and it is a
   password: never paste it into a chat with your agent.
2. Paste this into the shell. It asks for the Client ID and then the Client Secret (the secret is not shown as you
   paste it), hands them to Hermes, and keeps both out of your shell history:

   ```bash
   { printf 'Client ID: '; read -r id; printf 'Client secret: '; stty -echo; read -r secret; stty echo; echo
     hermes config set SENTROOK_SCAN_CLIENT_ID "$id" && hermes config set SENTROOK_SCAN_CLIENT_SECRET "$secret"
     unset id secret; }
   ```

   Both lines should end `Set ... in .../.hermes/.env`.
3. Restart Hermes: the plugin sees new credentials after Hermes restarts, not before.

## 3. Check the setup

```bash
hermes sentrook verify
```

Every line should start with `ok`, and `policy` should show `mode=enforce`:

| Failing line | Fix |
| --- | --- |
| `credentials` | Not signed in: run `hermes sentrook login` (step 2), then restart Hermes. |
| `token mint` | The credentials were revoked or are wrong: run `hermes sentrook login` again, then restart Hermes. |
| `scan URL`, `OIDC issuer`, `Rookery URL` | A custom endpoint is set that the plugin refuses (see [Settings](#settings)). Remove it. |
| `scanner health` | The scan service is unreachable from this machine. Check outbound HTTPS to `sentrook.firstdataunion.org`. |

If Hermes answers `'sentrook' is not a hermes command`, the plugin is not enabled: run
`hermes plugins enable sentrook` and restart. With `plugins.isolation: host` Hermes has no `hermes sentrook`
commands at all; check with `/sentrook status` in a session instead. `hermes plugins list` should show `sentrook` as enabled, with a 2.0
version.

## 4. First scan

Ask the agent for something small that uses a tool, such as "list the files in your home folder". Then look at what
Sentrook recorded:

```bash
hermes sentrook history 5
```

Each row is one scan: time, tool, risk score, the action Sentrook took, and the review outcome.
`hermes sentrook why last` shows the most recent scan in detail: risk, tier scores, reason codes and the entities it
found (hosts, files, recipients, channels).

If the history is empty, the agent has not made a tool call since the restart.

## 5. Tell Sentrook what is normal for you

First, tell Sentrook where to reach you. When a scheduled job or another run nobody watches tries something
Sentrook wants you to check, it stops that call and sends you a notice. In a direct message with the agent, send
`/sentrook notify here` (see [Where notices go](#where-notices-go)). Until you do, those calls are held silently.

Sentrook doesn't know which destinations and files are routine for your deployment. Two things tell it, so routine
work stops asking for approval:

- **Channel bindings**: the channels this deployment normally delivers to, such as the chat your daily report goes
  to. A send to a bound channel is not treated as an unfamiliar destination.
- **Grants**: hosts, email domains or channels the agent may send to (`destination`), files or folders it may
  read, write or delete (`file`), the MCP servers or plugins it may use (`provider`), and which API key belongs to
  which service (`credential`).

Neither ever lowers a scanner floor (reading your SSH keys and sending them somewhere is blocked whatever you grant),
and a file grant never covers a call that also sends data off the machine. You don't need a grant to send to a destination
you name yourself in your request: Sentrook already takes that into account.

You don't have to work these out in advance. When a review is caused by something a grant would cover, such as a
host Sentrook has not seen before, the approval prompt names the grant that would let calls like it through next
time: what answering **Always** would also set, or the command to set it yourself, for example
`/sentrook grant destination api.example.com --persistent --expires 30d`. Sentrook only
suggests a grant after checking that, with it, the same call would score below the review line; it never suggests
one for a known-bad or look-alike host, for something that content the agent read put in front of it, for a file
being sent out of a session that has read content trying to instruct the agent, or for a call with a clear attack
signal, and it suggests trusting a new tool provider only when you asked for the work in your own chat. It suggests
a grant only for a call that came from your own message or from a cron job Hermes started itself; a group chat,
someone else's message, a subagent or a webhook gets none. A cron job's suggestion reaches you only through its held
call: `/sentrook why <id>` names the grant, the job it came from and the command that sets it; answering the hold never
sets it, so you decide whether to trust it for every job. A suggestion is a good guess, not a promise: Sentrook's judge sees the
grant on the next scan too. When you asked for the work yourself (your own message, not a group chat), answering
**Always** also sets that grant, persistent for 30 days, and answering **Session** sets it for this session only.
`/sentrook why` lists every grant Sentrook suggested for a scan.

Run these commands in a direct message to the agent or on the machine (see [who may run them](#commands)). In chat
type `/sentrook …`. On the command line it is `hermes sentrook …`, with patterns in quotes so the shell leaves the `*`
alone: `hermes sentrook grant file '/home/you/notes/*' --allows read,write --persistent`.

### Set up with /sentrook setup

`/sentrook setup` lists what Sentrook would need to stop asking about routine work, worked out from what it can see
itself, and sets it with one command:

- **From your config**: a channel binding for each cron job that delivers to a chat room not bound yet
  (`deliver: discord:#daily-brief` in `~/.hermes/cron/jobs.json`), and a provider grant for each MCP server in
  `mcp_servers` that no grant covers. Cron jobs can be changed by the agent, so these items say so: check the
  channel is one you chose.
- **From reviews you approved**: the grant Sentrook suggested on at least two reviews you approved in the last 30
  days, from your own message, in a chat where the scanner saw no content trying to steer the agent. Only that exact
  grant counts: a broader pattern never inherits the count. With the traffic log off, there is no evidence to count.
- **From the agent**: items the agent proposed with its `sentrook_propose_setup` tool (see "The agent's setup
  proposals" below), marked "not seen yet" unless reviews you approved back them, with its reason shown last as a
  quoted note. A proposal lasts a day.

Sentrook describes each item in its own words, with how long it lasts and warnings to check (a name with characters
that are not plain ASCII, shown with its registrable domain; deleting files; your whole home folder; a whole package
registry; something a grant already covers; an agent proposal from a chat that had read content trying to steer it):

```
3. Send data to `api.example.com`, from any chat or job, until you revoke it.
   Sentrook suggested this in 3 reviews you approved, the last one 2 days ago.

To set them all, send: /sentrook setup apply 4821
To set some, list their numbers: /sentrook setup apply 4821 1,3
```

The code is new each time you open the list and works once, for 15 minutes, so nothing is set unless you have just
seen the list. Grants backed by reviews you approved last until you revoke them, the others 30 days, and channel
bindings until you remove them; add `--expires 90d` or `--until-revoked` to `apply` to change how long the grants
last. Applied grants are persistent, list in `/sentrook grants` and record where they came from; applying an item
twice sets nothing new. `/sentrook setup discard <id>` drops an agent proposal. Sentrook still decides whether a
pattern is too broad to relieve anything.

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

A binding can also name a channel the way you know it. `#daily-brief` covers that channel on any platform however a
send writes it (`#daily-brief`, `channel:daily-brief` or `discord:#daily-brief`). `discord:#daily-brief` covers it on
Discord only, including a send that names Discord in its own argument (`{channel: discord, target: "#daily-brief"}`).
`discord:*` covers every Discord channel a send delivers to. Neither form covers a direct message (`user:`, `dm:`, an
`@handle`), an email address or anything else the call reaches. `/sentrook bind add` and `/sentrook bind list` say
when a binding can never apply, and `hermes sentrook verify` does for the bindings in `config.yaml`: one that matches
every channel (`*`, `#*`), or one too short to be sent with a scan (such as `ab`).

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
| Run install scripts from a GitHub repository you trust | `/sentrook grant repo github.com/yourteam/tools --persistent` |
| Use your own API key with the service it is for | `/sentrook grant credential MY_SERVICE_TOKEN@api.myservice.example` |

An agent that reads an API key from its env file and sends it to the service it belongs to is doing the normal
thing. Sentrook already knows the keys of some common providers and the hosts they go to; for any other
service, a `credential` grant says the same: `NAME@host`, the key's environment name and the service's API host.
The name may end in `*` after three or more characters (`MY_SERVICE_*`), and the host may be `*.example.com` (that
domain and every name under it, but not a shared suffix such as `*.co.uk`). With it, sending that key only to that host is not treated as sensitive data
leaving the machine, and the host is not treated as unfamiliar on that call. The key sent anywhere else, written to a
file or printed, sent alongside another secret or file, or sent to a host that content the agent read named, is
still reviewed. A credential grant lasts until you revoke it unless you give `--scope session` or `--expires`. When a
review is caused by such a key going to its own service, the prompt suggests this grant (`/sentrook grant credential
MY_SERVICE_TOKEN@api.myservice.example --persistent --expires 30d`).

A file grant can use the full path or `~` for your home folder (`~/notes/*`). A `*` matches anything, including `/`.
A pattern ending in `/` covers that folder and everything in it. `--allows` must name everything the call does to
the file: deleting it (`rm`, or moving it away) needs `delete`. Without `--allows` a file grant allows reading only.
A provider pattern is the server's package as `/sentrook why` shows it, for example `npm:@yourteam/notes-mcp@1.4.0`;
ending it in `/` covers the whole scope. Patterns that would match everything (`*`, `*.*`, `/`) are ignored.
Anyone can publish on GitHub and Hugging Face, so a script fetched from one and run counts as code from an unknown source until a
repo grant covers its repository: `github.com/<owner>/<repo>` (raw.githubusercontent.com and git remotes count as
github.com), `github.com/<owner>/*` for an account, `huggingface.co/<org>/<name>`. The host and owner must be written
out; a release-asset download (objects.githubusercontent.com) names no repository and no grant covers it.

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
| `status` | Plugin version, mode, thresholds, scan host, whether credentials are set, traffic log, grants, snooze, where notices go, attended platforms, held calls (and the one held most often), passes and denials, and how many of Hermes's own skill and memory saves were allowed, blocked or held |
| `history [n]` | The last n scans (default 10) |
| `why [request_id\|last]` | One scan in detail, with the grants that would allow it next time; with the id from a held-call notice, also the hold, the answers it offers and the command of any grant Sentrook suggests |
| `report [request_id\|last] [--full\|--github\|--save]` | A report of a scan that looks wrong, to send to us (see [Report a wrong scan](#report-a-wrong-scan)) |
| `grants` | Grants in force: from config (read-only) and set by command |
| `grant <kind> <pattern> [flags]` | Add a grant. `kind` is `destination`, `file` or `provider`. Flags: `--persistent` (default is this session only, not cron jobs, subagents or other chats), `--session <ref>` (bind to that session instead, ref from `history`), `--allows read,write` (file only), `--expires 12h` |
| `revoke <id>` | Remove a grant set by command |
| `bind add\|remove\|list [channel]` | Manage channel bindings |
| `snooze [duration\|off\|status] [--all]` | Allow review prompts in this session (`--all`: every session) for a while, default 1h, at most 24h; blocks without a clear attack signal ask you instead |
| `allow <id> [now\|later\|always]` | Answer a held call by the id in its notice, within 7 days: run the cron job again now and let the call through once in that run (`later`: on the job's next scheduled run instead), or with `always` for 30 days on that job (see [Held calls](#held-calls-on-unattended-runs)) |
| `deny <id>` | Refuse a held call on that cron job for 30 days, with no more notices |
| `approve <id>` | The same as `allow <id>`, kept for one release |
| `passes [revoke <id>]` | The passes and denials your answers set, with their use counts; remove one by its id |
| `notify here\|off\|status\|<platform>` | Where Sentrook's notices go (see [Where notices go](#where-notices-go)). `here` stores the chat you send it in; `<platform>` that platform's home channel (the form for the command line); `off` goes back to `owner_channel` in the config |
| `attended add\|remove\|list [platform] [--confirm]` | Platforms where a person answers Hermes's approval prompts, besides the chat platforms and apps (see [Attended platforms](#attended-platforms)). Adding one loosens Sentrook |
| `setup [apply <code> [1,3] \| discard <id>]` | What would stop Sentrook asking about routine work, each item described by Sentrook; `apply` with the code the list ends with sets them, `--expires 90d` or `--until-revoked` changes how long the grants last (see [Set up with /sentrook setup](#set-up-with-sentrook-setup)) |
| `help` | Lists the commands, and says where notices go and which platforms are attended |

**Owner only.** `status` and `help` are open to anyone the gateway admits. Every other command runs only for the
owner: a direct message from a sender listed individually in `<PLATFORM>_ALLOWED_USERS` or `GATEWAY_ALLOWED_USERS`,
or the local terminal (`hermes chat` or `hermes sentrook …`). Group and channel messages are refused, and so is a
direct message admitted only because the gateway allows all users. Every attempt, allowed or refused, is recorded in
the traffic log (unless you turned it off). Hermes's own `allow_admin_from` is not used.

If Sentrook blocks your own setup work, snooze for the duration: blocks without a clear attack signal then ask you
instead; blocks with a clear attack signal still stop. While a snooze is on, in a chat you attend, a block the scanner
marks as having no clear attack signal (you asked in the chat, nothing came from content the agent read, no known-bad
or look-alike entity, no retry of a call you denied, no credential leaving for a destination you have not named or
granted, no floor, and the scan was complete) becomes an approval prompt that says "Would be blocked, but a snooze
is on." The snooze does not skip that prompt. If you answer **Session** or **Always**, the same action (same tool,
source and destination) goes through without asking until that snooze ends; a new snooze asks again. The score is the
same either way.

A snooze never allows a block, a review the scanner marks as enforced, or anything on an unattended run (cron jobs,
webhooks, the API server): blocks still stop, and a review on an unattended run is held for you instead.

Where slash commands don't reach the plugin, use `hermes sentrook <command>` on the machine instead:

- **API server and `--oneshot`**: Hermes passes `/sentrook …` to the model as plain text.
- **Mattermost**: a message that starts with `/` is taken by Mattermost as one of its own slash commands. Mention
  the bot first: `@yourbot /sentrook status`.

## Agent skills

The plugin gives your agent two skills, which Hermes lists while the plugin is enabled (read-only, and not copied
into `~/.hermes/skills`):

- `sentrook:sentrook-guide`: how Sentrook works, so the agent can explain an approval prompt, a block, a held call or
  a notice, and point you to `/sentrook why` and `/sentrook report`.
- `sentrook:sentrook-setup`: setting Sentrook up with you. Ask the agent to help you set up Sentrook: it checks the
  setup with `hermes sentrook verify`, asks what work is routine (the services, folders, channels and API key names
  it uses), explains where notices go, adds what you told it to your `/sentrook setup` list with
  `sentrook_propose_setup`, sends you there to read and set the items, and offers to explain any of them. Later, when Sentrook keeps asking about the same thing,
  it sends you back to `/sentrook setup` or helps you find the grant with `/sentrook why`.

The agent never runs those commands itself, `/sentrook setup apply` included, and Sentrook refuses them if it tries. Hermes's system prompt also gets a
short section with the rules the agent follows whether or not it opens a skill: never run the commands that change
Sentrook, never edit its settings or folder, never disable the plugin, and never retry a blocked or held call
reworded. `/sentrook` replies go to you, not to the model, so show it what `/sentrook why` says when you want its
help with one scan.

### The agent's setup report

The plugin also gives the agent one read-only tool, `sentrook_setup_report`, which the setup skill uses at check-in.
It tells the agent what is set and what is missing, the grants Sentrook suggested on reviews you approved at least
twice (marked covered when a grant already lets them through), the reviews you approved at least twice with nothing
to suggest (by tool), and the API key names Sentrook saw sent only to their own service, over the last 14 days (up
to 30), with the same rule as `/sentrook setup`: your own message, no steering content flagged in that chat. It
changes nothing.

It never shows the grants themselves (only how many of each kind are in force), any call's arguments or request text,
key values, or anything from a group chat or another sender; every name from a tool call is shown as plain text, and
with the traffic log off it shows only the settings. Hermes turns plugin tools on everywhere, so Sentrook itself
decides who gets an answer: only your own message in a direct chat or on the local terminal. In a group chat, a cron
job, a subagent, a webhook or the API server, Hermes's background review, or with `plugins.isolation: host`, the
whole answer is "Setup needs the owner in a direct chat." Each call is recorded in the traffic log as a
`setup_report` record, and the report itself goes to the next scan like any tool result.

### The agent's setup proposals

The agent has a second tool, `sentrook_propose_setup`, which the setup skill uses at hand-over: it adds what you told
the agent (a service, a folder, a key name, a channel a job posts to) to your `/sentrook setup` list, up to 20 items
at a time, each with a short reason. It sets nothing: you read each item on the list in Sentrook's words and set it
with the list's code. Each item must be one `/sentrook grant ... --persistent` or `/sentrook bind add` would accept;
the agent is told which it did not add and why. It never takes settings, attended platforms or grants for one
session, a destination's wildcard may only be `*.` and one registrable domain (such as `*.example.com`, never `*`
or `*.com`), and a key is named, never its value (a name shaped like a key itself is refused). The agent hears only how many items were added and to ask you to open
`/sentrook setup`: never the list, its warnings or its code. A proposal is kept in `proposals.json` in the plugin's
state folder for a day; at most three are open, and a new one replaces the oldest. Its reason never counts as
evidence: an item stays "not seen yet" and lasts 30 days unless reviews you approved back it. If the chat had read
something no scan had seen yet when the agent proposed (a page fetched just before, say), each of its items says
Sentrook could not check what the chat read just before. It answers in the same
places as the setup report, and anywhere else the whole answer is "Setup needs the owner in a direct chat." and
nothing is stored. Each call is recorded in the traffic log as a `setup_proposal` record with its session and item
count.

## Dashboard

`hermes dashboard` gets a **Sentrook** tab with the recent scans, newest first. Open a scan to see its risk broken
down: the three scores the scanner combines (suspicion, consequence and confidence), every signal under each one with
the reasons that raised it, and any floor or grant that changed the result. Grants and snooze are shown as they stand.

Anything waiting for you comes first: an approval prompt still open, or a call held for your approval, each with the command that answers it. Below, the history shows 10, 25 or 50 scans a page; **Older** pages back. Search by tool name, outcome, time window or minimum risk. The traffic log has no index, so a search reads it backwards from the newest line, skipping lines outside the time window without parsing them; a time window makes searches faster. A search reads at most the whole log at its configured size (twice `traffic_log.max_bytes`, up to 256 MB) and says when it stopped early.

The tab only reads. To change a grant or a snooze, use the commands above. It shows the same records as
`/sentrook history` and `/sentrook why`, and nothing when the traffic log is off. It reads the traffic log of the
profile the dashboard is showing.

By default the tab never shows what a call contained: an edit shows its tool and the files it touched, not the edit.
To see the call itself, turn on `dashboard_show_calls`:

```bash
hermes config set plugins.entries.sentrook.settings.dashboard_show_calls true
```

Each scan then has **Show the call**, collapsed under its details: the tool and its arguments as the plugin sent them
to the scanner. Secrets are masked; file contents, messages and commands are shown as the agent wrote them (a patch's
old and new text side by side), and very long text is cut. Anyone who can open the dashboard can read them, so leave
it off where others can. Without it, `/sentrook report <id> --save` writes a scan's full record to a file only you can
read.

Every scan has **Report this scan…**, which opens the report described in [Report a wrong scan](#report-a-wrong-scan):
the summary to copy, a button for a public GitHub issue with it filled in, and the commands and email address for the
full record, which the tab does not show.

The tab appears once the plugin is enabled (`plugins.enabled`). After installing or updating the plugin, restart
`hermes dashboard`. The Hermes desktop app does not show dashboard tabs.

## Report a wrong scan

If Sentrook stopped something it should have allowed, or let through something it should have stopped, send us a
report. `/sentrook report <id>` (the id from `/sentrook history`; `last` or nothing for the newest scan) prints the
scan as `why` shows it, plus the host, plugin and scanner versions, between `BEGIN` and `END` lines. Fill in its last
two lines (what you expected, what you were doing) where you paste it. It holds no call arguments or conversation
text. Then:

- **Colleagues:** paste it into Discord or chat. If we ask for the full record, `/sentrook report <id> --full`
  prints it too.
- **Everyone else:** `/sentrook report <id> --github` gives a link that opens a GitHub issue with the report filled
  in. The issue is public: read the report and remove anything private before you submit it.
- **The full record, privately:** `/sentrook report <id> --save` writes the report and the full record (the exact
  request Sentrook saw) to a file only you can read, under the plugin's state folder. Email it to
  sentrook@firstdataunion.org with the subject the command gives. The full record can hold conversation text, file
  paths, names and addresses: read it first, and never post it in an issue. Email is not end-to-end encrypted; we keep
  emailed records for up to 30 days, then delete them.

## How enforce mode decides

Sentrook asks for approval at risk 45 or above and blocks at 80 or above (`review_at`, `block_at`). Some findings,
such as reading credentials and sending them off the machine, are floors that apply whatever the score. If a scanner marks a call as review at most
(an option for chats you attend, which the hosted scanner leaves off), the plugin asks you about a block-level score
instead of blocking it, and a snooze never skips that review.

A snooze can turn a block on your own setup work into a question; see the snooze paragraph under
[Commands](#commands).

When a call is blocked the agent is told it was a security block, given a broad category (for example "it reads or
sends sensitive data"), and asked not to retry it or work around it unless you tell it to, and to check with you. It
is not told which checks fired or the risk score; you can see those with `hermes sentrook why last`.

Reviews use Hermes's approval prompt, which needs a person on the other end. Chat platforms (every one Hermes's
gateway ships except Raft, whose adapter sends nothing into the chat), the Hermes TUI, the Hermes desktop app (also when
it connects to a gateway on another machine), an editor connected over ACP and the local terminal count as attended. Elsewhere, including the API
server, cron, subagents, webhooks and A2A peers, a review holds the call instead
(see [Held calls](#held-calls-on-unattended-runs)). If a UI in front of the API server shows Hermes's approval
prompts, add it with `/sentrook attended add api_server --confirm` (see [Attended platforms](#attended-platforms)). Hermes's own background skill and memory saves
never ask, wherever they run (see [Background skill and memory saves](#background-skill-and-memory-saves)).

### What a review looks like

Hermes frames the prompt with its own heading and buttons; Sentrook's part starts with a feather:

```text
🪶 Sentrook security check · risk 62/100
Sends ~/notes/q3-plan.md to paste.example.net.
Because paste.example.net is new to Sentrook as a place to send data.
"Session" also trusts paste.example.net in this chat, "Always" for 30 days.
Details: /sentrook why 3f9c2a1b
```

- The first line says it is Sentrook asking and gives the risk score (reviews start at 45, blocks at 80). "Safety
  rule" in place of "security check" means a rule that always asks, whatever the score.
- The next lines say what the call does and, in plain words, the main reasons. Long files and addresses are
  shortened in the middle; on small screens (a Discord message holds 300 characters) the reasons and your options
  are kept and the description of the call is shortened first.
- **Once** runs this call. **Session** and **Always** also run the same action (same tool, files and addresses)
  without asking again: for this session, or from now on, in every later session too. A call that names no file,
  address or other target is covered only when it is repeated exactly.
- When you asked for the work in your own chat, **Session** also covers the rest of the job in that chat for 12
  hours: a later call of the same tool about the same parties (the hosts and files the review's reasons and its
  description of the call name), scoring no higher, goes through without asking, even when it writes a different
  output file. It still asks when the later call adds a warning the answered one did not have (for example content
  that tried to change the agent's task or that the call uses, a target only such content named, a secret carried
  into the request, a look-alike or known-bad party, a remote delete, a retry after a refusal), and for another
  party, a higher score, another tool, another chat or a block. What the session has been reading (documents with
  instructions in them) does not count as new on its own; it still raises the score.
  The prompt says which applies: "also covers the same parties at no higher risk", or "covers only this exact
  action" when the review named no party or the answer is not known to be yours (a group chat, someone else's
  message, a subagent). **Always** covers only the same action, as above.
- Where a grant would cover calls like this, the prompt says what **Session** (for this chat) and **Always** (for 30
  days) also set, or gives the command. A grant goes to the scanner, which scores later calls with it; with a grant
  set, Session skips no further questions.
- `/sentrook why <id>` shows everything behind the decision: the scores, the checks that fired, the files and
  addresses in full, and every grant that would allow it next time.

With approvals switched off (`approvals.mode: off`), Hermes would approve every prompt itself, so a review holds the
call instead; the same goes for a gateway started with `HERMES_YOLO_MODE=1` in its environment, and on those runs a
snooze never turns a block into a question. YOLO you switch on for one session (`/yolo` in a chat, or `hermes --yolo` /
`hermes chat --yolo`, which Hermes applies to that session) is not visible to Sentrook, so in that session Hermes
approves Sentrook's reviews the way it approves everything else there. Blocks still apply, with one exception: if a
snooze is on in that session, a block Sentrook marks as having no clear attack signal becomes a review (see
[Commands](#commands)), which YOLO then approves, so the call runs. Do not snooze a session you have switched to YOLO.

### Held calls on unattended runs

Where nobody can answer a review (the runs above), the call is **held**:

- The call does not run. The agent is told it is held for your approval and not to retry it in this run.
- You get one notice where you told Sentrook to send them (see [Where notices go](#where-notices-go)). Until you
  do, nothing is sent, the call is still held, and `status` and `verify` say notices are not sent. Hermes copies what it sends into the agent's own conversation, so the notice says only that a call
  was held, which run (a cron job by its id, and its name in quotes), the tool and its target, a broad category,
  and the commands. Read the risk, the reasons and any grant Sentrook suggests with `/sentrook why <id>`.
- The notice is sent with Hermes's own `hermes send` command, which works from every Hermes process: the gateway,
  the desktop app's backend (`hermes serve`), the command line and cron. Where a Hermes process has neither
  `hermes send` nor a `send_message` tool, the call is still held, its record says the notice is `unsent` and why,
  and the startup log, `status` and `verify` say that notices cannot be sent from that process.
- Answer within 7 days, from a direct message or the local terminal (like the other owner commands). The notice
  lists only the answers this hold offers:
  - `/sentrook allow <id>`: Sentrook runs the cron job again now (`hermes cron run <id>`, as you would yourself), and
    the same call goes through once in that run. Sentrook never runs the held call itself: the job runs as it is, with
    no extra prompt. When that run ends you get one line: the call went through, the run did not make it, or it made a
    different call (held as a new `h-` id). The run is started at most once per held call.
    - Nothing is started, and the call may go through once on the job's next scheduled run instead, when the job is
      gone, finished, paused, running right now, or changed since the call was held, or when the plugin is in observe
      mode. The reply says which.
    - When the held run had already sent or written something before the held call, a new run would do that again, so
      `allow` waits for the next scheduled run, and the notice offers `/sentrook allow <id> now` instead: that runs the
      whole job again now, and the reply warns that what it already did happens again.
  - `/sentrook allow <id> later`: the job's next scheduled run may make the same call once; nothing is started now.
  - `/sentrook allow <id> always`: the job may make the same call for 30 days. Offered only when Sentrook judges the
    call safe to let through on every run and the call names who or what it acts on.
  - `/sentrook deny <id>`: the job is refused the same call for 30 days. The agent is told you declined it and to go
    on without it, and you get no more notices about it.
  - `/sentrook approve <id>` still works, as `allow`.
- "The same call" means: the same tool, about the same parties (the destination, file or account the hold named),
  scoring no higher, with no warning the held call did not have, and nothing Sentrook enforces or floors. A send to
  another channel, a riskier version of the call, or the same call from another job is held again. A call that names
  nothing Sentrook can recognise is matched on its exact arguments, and only `allow` is offered for it. The job is
  the one Hermes says the run belongs to, never anything in the prompt.
- On another unattended run, the answers are bound to where the run came from, when Hermes names it:
  - a subagent: its parent session. Another subagent of the same parent session counts as the same source;
  - a webhook run: its route (the name in `/webhooks/<route>`).

  There `/sentrook allow <id>` lets the next matching call from the same source through once within 7 days (nothing
  is started), `/sentrook allow <id> always` lets that source make it for 30 days (where offered), and
  `/sentrook deny <id>` refuses it from that source for 30 days. The same call from another parent session or route
  is held again.
- A run Hermes names no source for, such as an API-server run (Hermes gives the run no key name), offers only
  `allow`: the next call with exactly the same arguments, from any such run, goes through once within 7 days.
- `/sentrook passes` lists what your answers set, with their use counts and end dates; `/sentrook passes revoke <id>`
  removes one. `status`, `verify` and the dashboard show them too.
- Answering never sets the grant Sentrook may suggest for the call: `/sentrook why <id>` shows its command, for you to
  run if you want that destination trusted for every job.
- A daily job held again before you answer does not send another notice: the waiting hold counts it, and `status`
  and `why` say how many times it was held.
- A hold nobody answers expires after 7 days, and nothing runs.

A block (at `block_at` or above, or one the scanner enforces) is never held: it stays a block. The one exception is a retry of a call whose review nobody answered (it timed out, was held, or was auto-denied by the review loop) when only the retry takes it to a block: that retry is held, as a review would be. The traffic log records
the scan with decision `held`, then your answer or the expiry; a call a pass let through is recorded as
`allowed_by_pass`, and one a denial refused as `denied_by_owner`. `/sentrook history` shows them.

### Where notices go

In the chat where you want Sentrook's notices (a direct message with the agent), send:

```
/sentrook notify here
```

From then on the notices of held calls, of scan failures on unattended runs and of Hermes's background saves go to
that chat, and Sentrook sends a test notice there straight away. If it does not arrive, `/sentrook notify status`
(and `status` and `verify`) says the last test notice was not delivered until a later notice gets through: check the
Hermes log, and send `/sentrook notify here` again a few minutes later (on some platforms Hermes can reach a new chat
only once it has listed it). On the command line, which has no chat, name a platform instead: `hermes sentrook notify telegram` sends
them to that platform's home channel (set with `/sethome` in the chat you want). If Hermes does not say which chat a
command came from, `notify here` uses the platform's home channel and the reply names it, so you can tell when that
is not the chat you are in. A platform with no home channel is refused, with what to set.

`owner_channel` in the config (a platform whose home channel gets the notices) still works. A target set with
`notify` wins over it, and `status` names both; `/sentrook notify off` removes the one set by command, so
`owner_channel` applies again. `status`, `verify`, `help` and `/sentrook notify status` explain the setting in force,
for example:

> Notices: the telegram chat where you sent /sentrook notify here (set by command). When a scheduled job or another
> run nobody watches tries something Sentrook wants you to check, Sentrook stops that call and tells you there.

> Notices not set: calls held on scheduled jobs and other runs nobody watches are held silently. In the chat where
> you want notices, send /sentrook notify here.

### Attended platforms

On chat platforms, the local terminal, the TUI, the desktop app and editors (ACP), a review shows you Hermes's
approval prompt. Everywhere else (scheduled jobs, the API server, webhooks and the like) nobody is assumed to be
watching, so a review holds the call for you. If a person does answer Hermes's approval prompts on one of those, for
example a UI in front of the API server that shows them, add it:

```
/sentrook attended add api_server --confirm
```

This loosens Sentrook: on that platform a review shows an approval prompt instead of holding the call. Only front
ends that can put a person in front of the prompts can be added (`api_server`, `webhook`, `a2a`, `relay`,
`homeassistant`, `msgraph_webhook`, `wecom_callback`), and without `--confirm` the reply only warns you. Runs Hermes
starts itself (cron jobs, subagents, batch runs, the curator, kanban workers and the like) and Raft can never be
added: where nobody answers, Hermes may approve a prompt on its own. Nor can the local terminal (`cli`, `local`),
which is attended when it has a terminal; a scripted run without one stays unattended. An unknown name is refused
with the list of known platforms. `/sentrook attended remove api_server` holds its reviews again, and
`/sentrook attended list` shows what is added and where it came from (`attended_platforms` in the config, or set by
command). The plugin settings' `attended_platforms` still applies alongside.

Both `notify` and `attended` are owner-only, recorded in the traffic log, and kept in `settings.json` in the plugin's
folder. The agent cannot run them: `hermes sentrook notify …` or `hermes sentrook attended …` in one of its own
commands is blocked like any other `hermes sentrook` command but `status` and `verify`.

### Hermes's own skill and memory saves

After a turn, Hermes reviews what it learned and saves skills (`skill_manage`) and memory (`memory`) in the
background; when idle, its curator tidies those skills. This background review has no request of its own, so a
save would otherwise look like a write nobody asked for. By default (`skill_review: allow`) the plugin tells
Sentrook that the call is one of these background saves and sends the part of the conversation the review read,
and Sentrook judges the save against that conversation. A save that follows from what you said and did goes
through. A save is reviewed or blocked when it carries instructions that came from content the agent read or from
other people, weakens one of your rules, claims approvals you never gave, or stores secrets you did not ask it to
keep. These saves never ask you (see [Background skill and memory saves](#background-skill-and-memory-saves)).

Every background save is scanned and logged, and `status` counts them: allowed, blocked, held, staged and let through. Only Hermes's
automatic review and curator count: a skill or memory change you ask for in a turn, or a `/refine` you run, is
scanned like any other call. Every other tool those background runs call is scanned as usual too, but never asks
(see [Background skill and memory saves](#background-skill-and-memory-saves)). Every call a background run
makes is sent with your last message as its request and the number of the turn it follows, and does not count as
a turn of its own; if you have not written anything in the session yet, the request names the background review
instead. Set `skill_review` to `review`
to send the background saves like any other call, without the conversation; with nothing to judge them against,
expect more of them to be reviewed or blocked.

On the local terminal the background review cannot show you its prompts, so Hermes denies them itself. That still
happens to the calls of a `/refine` you run there; history shows such a call as "auto-denied by the review loop". If you then ask the agent to make that call, or one whose review
timed out, Sentrook treats it as a retry of a review nobody answered: it can ask you (or, on an unattended run, be
held for you), but it is not blocked for being a retry. A retry of a call you denied yourself, or one Sentrook blocked, is scored as before.

### Background skill and memory saves

Hermes's background review and curator save after your turn is over, so nobody is there to answer a question about
a save: on the local terminal Hermes would deny it unseen, and in a chat the question would reach nobody. So
Sentrook never asks about these saves, wherever Hermes runs and whatever your approval settings, and tells you
instead:

| Sentrook's verdict | What happens to the save | What you get |
|---|---|---|
| Allow | It is saved. | Nothing; it is in history. |
| Review, and Sentrook finds nothing in the save that needs you | It is saved without asking. | A notice that a save Sentrook would normally ask about was let through. |
| Review, and Hermes can keep it for you (see below) | It is held, not saved, and **staged** in Hermes's own pending list: you can look at it and approve or reject it with Hermes's commands. | A notice with its pending id and the commands. |
| Review, otherwise | It is held: not saved, and nothing keeps it; to keep it, ask the agent for it in a chat. | A notice that a background save was held. |
| Block | It is not saved. | A notice that a background save was blocked. |
| The scan failed | As on an unattended run: with `on_scan_error` `review` or `deny` it is not saved, with `allow` it is (see [When the scan service fails](#when-the-scan-service-fails)). | The scan-failure notice when it is not saved. |

The notices go where you set them (see [Where notices go](#where-notices-go)). They say whether it was a skill or a memory
save and what it saved, as a review would describe it, and point to `/sentrook why <id>` and `/sentrook history`.
You get at most one notice of each kind (let through, held, staged, blocked) per session every 6 hours; history has
every save, and shows a held one as "not saved" and a staged one as "pending in Hermes".
Without a notice target (for example when you use Hermes only on the local terminal) the saves are handled the same
way, but nothing tells you: `status` and `verify` say so, and the saves show only in `/sentrook history` and the
`skill review` counts in `status`. A snooze on the session (or on every session) lets a save through that would
otherwise be held, with the "let through" notice, when the save follows a chat, a local terminal, TUI or desktop app
session, or an [attended platform](#attended-platforms) you added; it never lets a blocked save through, and never one from the curator or after a
cron job, a webhook, the API server or any other platform. History marks these saves "(self-edit)".

The background review's and the curator's other calls (reading a file, a terminal command) never ask either: a
prompt there would be lost the same way, and the review could stop before its save. An allowed call runs and a
blocked one is blocked, as anywhere. A call that needs review is held: it does not run, and the review is told nobody
can approve it and not to retry it. You get one notice per session every 6 hours, naming the call as a review would
describe it; it is not kept with the held calls you can approve, and history shows it as "held". A scan failure
follows `on_scan_error` as for any unattended run. An owner's `/refine` still asks.

All of this needs the plugin to run inside Hermes, which is Hermes's default (`plugins.isolation: in_process`). With
`plugins.isolation: host` Hermes runs plugins in a separate process, where the plugin cannot tell a background save
from your own call: background saves are then scanned like any other call of your session, without the conversation,
and none of the above applies. A save Sentrook would ask about becomes an ordinary approval prompt in your session, or
on the local terminal is refused by Hermes's background review, which cannot ask you (history then shows it as denied,
not as auto-denied by the review loop). `/sentrook status` shows `background saves: not recognised`, and the plugin
logs a warning when it starts (in Hermes's `agent.log`, as a line from the plugin host). To have them recognised, set
it back:

```bash
hermes config set plugins.isolation in_process
```

then restart Hermes.

#### Approving a held save in Hermes

A held background save that Hermes can replay is put in Hermes's own pending list (the one its `skills.write_approval`
and `memory.write_approval` settings use; you do not need to switch those on). The notice gives its id and the
commands, which work in a chat and on the local terminal:

- A skill save: `/skills diff <id>` shows what it would write; then `/skills approve <id>` saves it, or
  `/skills reject <id>` drops it. `/skills pending` lists every pending skill save.
- A memory save: `/memory pending` lists it; then `/memory approve <id>` or `/memory reject <id>`. The list shows
  what kind of change it is, not the text; the text is in `pending/memory/<id>.json` in the Hermes home folder.

Approving replays the save through Hermes's own skill or memory tool, with Hermes's own checks. If the skill has
changed since, so that an edit no longer fits, the diff and the approval say so and nothing is written; reject it.
Sentrook writes each entry's summary itself ("Held by Sentrook ...": the kind of change, never what it saves), makes
the staged file readable by you only, and keeps at most 20 of its own entries waiting in each list; past that, saves
are held as before until you approve or reject some. The agent is told the save was not made, is waiting for you,
and must not be retried in that run.

What is staged: a new skill, a skill edit or patch, writing or removing a file in a skill (alone or in one batch),
and adding memory entries (alone or in one batch). These stay held and are lost, as before:

- deleting a skill (Hermes deletes an approved skill for good, not to its archive);
- a save Sentrook finds a secret in, which staging would write to a file in plain text;
- a save too large for Sentrook to scan whole (over `input_cap_bytes`);
- a save Sentrook blocks, or one that scored at the block line;
- with `skill_review: review`, every held save.

Changing or removing memory entries is held too, except on Hermes builds Sentrook has verified. Hermes itself never
lets its unattended background review change or remove memory entries: it puts the change in its pending list
instead. Sentrook checks the code of that safeguard in the Hermes it runs in against a list of Hermes builds it has
verified (at present Hermes 0.23.0 to 0.23.2). On those builds it leaves the change to Hermes, and the notice says
what Hermes did: staged it (with its id), or, if Hermes reports otherwise, that it may have been saved without your
approval; after that, Sentrook holds such changes until Hermes restarts. On any other Hermes build the change is held
and lost as before.

Staging needs the plugin to run inside Hermes's own process, as Hermes loads plugins by default. If staging fails
for any reason, the save is held as before and the notice says it was not saved.

### When the scan service fails

A scan gives no usable answer when the scan service returns an error, does not answer within `timeout_ms` (30
seconds), cannot be reached, or rate-limits the scan. The call is then not scanned, and with the default setting
(`on_scan_error`: `review`):

- **Where reviews are attended** (chat platforms, the TUI and desktop app, the local terminal, and the
  [attended platforms](#attended-platforms) you added) you are
  asked, with Hermes's approval prompt, whether to run the call without a scan. It runs only if you approve, except
  in a session where you switched on YOLO, where Hermes approves the prompt itself (see above). Answering
  **Session** or **Always** stops these questions in that chat until Sentrook can scan again; another chat, or a
  different kind of failure (for example credentials that expire meanwhile), still asks.
- **On unattended runs** (the API server, cron, subagents, webhooks, and anywhere Hermes approvals are switched off
  as described above) nobody can answer, so the call is blocked. The agent is told that Sentrook did not scan the
  call, that this is a service problem rather than a security block, and that the call did not run. The call is not
  held, so there is nothing to approve, but you get a notice where notices go, like a held call's.
  It names the run, the tool and the reason (the service could not be reached, did not answer in time, returned an
  error or rate-limited the scan, or the endpoint or credentials are wrong). You get one notice per cron job (per
  session for other runs): further failures in the same job are blocked without a notice for 6 hours, so an outage
  sends one message per job, not one per call. The traffic log records each with `notice` `queued`, `quiet` or
  `unsent`.

A snooze does not change this. Set `on_scan_error` to `deny` to block the call everywhere, or to `allow` to run it
without a scan everywhere. Bad credentials or endpoints are never let through silently: with `allow` the call is
blocked, and with `review` you are asked as above. Whatever the setting, a call blocked on an unattended run because
the scan failed sends the notice described above. In observe mode the failure is logged and the call runs. The
traffic log records these scans with decision `blocked_on_error` or `allowed_on_error`, and `/sentrook history` shows
them as scan errors.

## Observe mode

In observe mode Sentrook scores and logs every call but never blocks or asks. Use it to try Sentrook before trusting
it with your agent, or as the off switch if it gets in the way, or when the scan service is down and the agent has to
keep working. History and why keep working.

| To | Run, then restart |
| --- | --- |
| Switch to observe | `hermes config set plugins.entries.sentrook.settings.mode observe` |
| Switch back to enforce | `hermes config set plugins.entries.sentrook.settings.mode enforce` |
| Stop scanning entirely (no calls are sent to Sentrook) | `hermes plugins disable sentrook` |

To start in observe mode from the beginning, install with `--no-enable` in step 1, set the mode, then run
`hermes plugins enable sentrook` and restart. In observe mode the history's `action` column shows what Sentrook
would have done, such as `observed (would review)`.

## What is sent

Each scan sends one request to `sentrook.firstdataunion.org`:

- the request you gave the agent in this turn, and whether it came from you, a scheduled job, a subagent, another
  sender or Hermes's own background skill review, with the kind of channel it arrived on (chat, API, cron and so on).
  Hermes also starts turns with its own text: when a sub-agent or a background process the agent started finishes
  (or a process matches a watch, is still running or has its watch turned off), for a kanban task's update or
  next step, and for your heartbeats, `/loop` wakeups and standing goals. None of these is counted as your
  message. For a result or event, the calls carry your last request and the turn it came from, and the text is
  sent with the other new inputs as content the agent received, not as your words; a heartbeat, `/loop` wakeup or
  goal step is sent as the run's request, like a cron job's prompt, except that a failed quality gate's output is
  sent as content. Someone else in a chat who types one of these forms gets nothing from it: they keep their own
  sender, a result or event they type is sent as content with no earlier request in its place, and a heartbeat,
  `/loop` or goal form they type stays their own request. Short notes Hermes puts in front of your next message
  (a model switch, a skills reload, a system note) are left out of the request. When the gateway resumes a turn a
  restart or shutdown interrupted, its note is not your request either: the calls carry the interrupted turn's
  request and the turn it came from, and the note is sent as content. A message another Hermes plugin injects into
  the chat is not recognised and is sent as the turn's request, as before: Hermes does not tell plugins which
  messages were injected;
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
similar) are replaced with placeholders such as `⟦secret:github:…⟧`. So are access codes and PINs named as such ("the
gate code is …", `client_pin=…`), passport numbers (`⟦secret:identifier:…⟧`) and random-looking values under a key or
header (`X-Desk: …`); a number with no such cue word, such as an order number or a status code, is kept. Recipients,
hosts and email addresses are kept,
because the scanner needs them to judge where data is going. So is code that only reads a secret from where it is
kept, such as `os.environ["API_KEY"]`, `config.token` or `sys.argv[1]`: it names the place, not the secret. The name of a credential field, such as
`api_key:api_secret` quoted from an API's docs or `password: your_password`, is kept too. Your
files, messages and tool output can still contain other personal information, and that is sent as it is.

A local copy of each scan (the redacted request and the response) is kept in `~/.hermes/sentrook/traffic.jsonl`,
readable only by your user and rotated at 50 MB. The plugin never uploads it. Turn it off with
`hermes config set plugins.entries.sentrook.settings.traffic_log.enabled false`; the history and why commands then
have nothing to show.

## What the plugin does on your machine

In short, for anyone deciding whether to install it:

- **Network:** it calls two services run by First Data Union: the scan service (`sentrook.firstdataunion.org`), once
  per tool call, with the redacted request described in [What is sent](#what-is-sent), and the identity service
  (`identity.firstdataunion.org`) to exchange the scan credentials for a short-lived token (and, when you run `hermes sentrook login`, to sign in). Nothing else, and no
  telemetry beyond the scans themselves.
- **Hermes's own saves:** with `skill_review: allow` (the default), the redacted recent conversation goes with each of
  Hermes's background skill and memory saves, and a redacted copy of recent messages is kept on disk to send with
  them. Set it to `review` to stop both.
- **What it can do to a call:** allow it, block it, or hand it to Hermes's own approval prompt. It never approves a
  call on your behalf. Where nobody can answer a prompt (cron, webhooks, the API server) a review holds the call and
  sends you one notice in the chat or home channel you set, with Hermes's own `hermes send`, and a call blocked because the scan
  failed sends you one notice per job (per session for other runs) every 6 hours at most; those notices are the
  only messages it sends.
- **Files:** it writes only to its own folder in Hermes's home (`~/.hermes/sentrook/`, `/opt/data/sentrook/` in Docker:
  the traffic log, grants, snooze state, held calls, passes and denials, where notices go and the attended platforms
  you added, when each job last had a scan-failure notice, the agent's setup proposals and the last `/sentrook setup`
  list with its code, and the conversation logs above), or to the paths you set for them (`state_dir`,
  `traffic_log.path`). Besides that folder it reads Hermes's `config.yaml`, for whether approvals and secret redaction
  are on (and, when you open `/sentrook setup`, your MCP servers), and the cron jobs in `cron/jobs.json` (a running
  job's own prompt, and every job's delivery when you open `/sentrook setup`). It runs no shell commands. The one
  process it starts is Hermes's own `hermes send`
  command, to send a notice above; the notice text goes to it on standard input.
- **Credentials:** the scan credentials are stored and handed over by Hermes. `hermes sentrook login` (step 2), which
  you run yourself, contacts the identity service and has Hermes store the two `SENTROOK_SCAN_CLIENT_*` values with
  its own writer. It also keeps a random id for this machine in `~/.hermes/sentrook/device-id`, so signing in again
  replaces this machine's credentials instead of adding new ones. The plugin never reads `.env`, `auth.json` or any
  other credential file.
- **Turning it down or off:** [observe mode](#observe-mode) scores and logs without ever blocking or asking, and
  `hermes plugins disable sentrook` stops it sending anything.

## Settings

Set with `hermes config set plugins.entries.sentrook.settings.<key> <value>` and restart. Most keys can also come
from a `SENTROOK_*` variable in the environment Hermes starts with; the setting wins. The scan credentials are not
settings (see [step 2](#2-sign-in)).

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `enforce` | `observe` or `enforce` |
| `review_at` | `45` | Ask at or above this risk |
| `block_at` | `80` | Block at or above this risk |
| `on_scan_error` | `review` | `allow`, `deny` or `review` when the scan gives no usable answer |
| `attended_platforms` | | Extra session platforms where a person answers approvals, such as `api_server`. `/sentrook attended add` adds more without editing the config (see [Attended platforms](#attended-platforms)) |
| `owner_channel` | | The platform whose home channel gets the notices of held calls, of scan failures on unattended runs, and of background skill and memory saves blocked or let through without asking, such as `telegram`. `/sentrook notify here` sets a chat instead and wins over this (see [Where notices go](#where-notices-go)). No notice is sent until one of them is set |
| `skill_review` | `allow` | `allow` tells Sentrook which calls are Hermes's own background skill and memory saves and sends the conversation they are judged against; `review` sends them like any other call. Either way they never ask (see [Background skill and memory saves](#background-skill-and-memory-saves)). A YAML `false` (`off`, `no`) reads as `review` and `true` as `allow`; any other value reads as `allow`, and `status` names it |
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
credentials Hermes keeps in its `.env`. To remove those too, delete the folder, delete the two
`SENTROOK_SCAN_CLIENT_*` lines from the file `hermes config env-path` prints, and remove this machine on the identity
service's **Sentrook** tab. To install again later, start from
step 1.

## License

MIT. The Sentrook name and logo are trademarks of First International Data Union Ltd and are not covered by
the licence: see [TRADEMARKS.md](https://github.com/FirstDataUnion/Sentrook/blob/main/TRADEMARKS.md).
