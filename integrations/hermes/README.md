# Sentrook for Hermes Agent

The Sentrook plugin scans each tool call your Hermes agent is about to make (terminal commands, file reads and
writes, web fetches, messages and so on), in the context of what you asked for and what the agent did on the way.
Depending on the risk score it allows the call, asks you through Hermes's own approval prompt, or blocks it.

This guide installs Sentrook in **enforce mode**, where it protects the agent from the first call. To try it without
it ever blocking or asking, use [observe mode](#observe-mode) instead.

The plugin is a beta (2.0.0-beta). Report problems at <https://github.com/FirstDataUnion/Sentrook/issues>.

## Requirements

- Hermes Agent **v0.23.0 or newer** (`hermes --version`), the oldest version the plugin declares.
  Tested on v0.23.0 and v0.23.2.
  On an older Hermes, update Hermes first (`hermes update`).
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

Hermes keeps the credentials, not the plugin: it stores them in its own `.env` file and hands them to the plugin when
asked. Paste this into the shell; it asks for the Client ID and then the Client Secret (the secret is not shown as you
paste it) and keeps both out of your shell history:

```bash
{ printf 'Client ID: '; read -r id; printf 'Client secret: '; stty -echo; read -r secret; stty echo; echo
  hermes config set SENTROOK_SCAN_CLIENT_ID "$id" && hermes config set SENTROOK_SCAN_CLIENT_SECRET "$secret"
  unset id secret; }
```

Both lines should end `Set ... in .../.hermes/.env`. Never put the credentials in `config.yaml`: the plugin does not
read them from there. If you install without setting them first, `hermes plugins install` asks for them itself.

To replace them later, run the same block again and restart Hermes: the plugin sees new credentials after Hermes
restarts, not before.

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
| `credentials` | It names the missing one. Set it (step 2), then restart. |
| `token mint` | The Client ID or secret is wrong or revoked: create new credentials (step 1) and set them again (step 2). |
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
call: `/sentrook why <id>` names the grant and the job it came from, and `/sentrook approve <id>` sets it. A suggestion is a good guess, not a promise: Sentrook's judge sees the
grant on the next scan too. When you asked for the work yourself (your own message, not a group chat), answering
**Always** also sets that grant, persistent for 30 days. `/sentrook why` lists every grant Sentrook suggested for a
scan.

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
| `status` | Plugin version, mode, thresholds, scan host, whether credentials are set, traffic log, grants, snooze, held calls and where their notices go, and how many of Hermes's own skill and memory saves were allowed, blocked or held |
| `history [n]` | The last n scans (default 10) |
| `why [request_id\|last]` | One scan in detail, with the grants that would allow it next time; with the id from a held-call notice, also the hold and the grant approving it sets |
| `grants` | Grants in force: from config (read-only) and set by command |
| `grant <kind> <pattern> [flags]` | Add a grant. `kind` is `destination`, `file` or `provider`. Flags: `--persistent` (default is this session only, not cron jobs, subagents or other chats), `--session <ref>` (bind to that session instead, ref from `history`), `--allows read,write` (file only), `--expires 12h` |
| `revoke <id>` | Remove a grant set by command |
| `bind add\|remove\|list [channel]` | Manage channel bindings |
| `snooze [duration\|off\|status] [--all]` | Allow review prompts in this session (`--all`: every session) for a while, default 1h, at most 24h; blocks without a clear attack signal ask you instead |
| `approve <id>` | Approve a held call by the id in its notice, within 24 hours (see [Held calls](#held-calls-on-unattended-runs)) |
| `help` | Lists the commands |

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

## Dashboard

`hermes dashboard` gets a **Sentrook** tab with the recent scans, newest first. Open a scan to see its risk broken
down: the three scores the scanner combines (suspicion, consequence and confidence), every signal under each one with
the reasons that raised it, and any floor or grant that changed the result. Grants and snooze are shown as they stand.

Anything waiting for you comes first: an approval prompt still open, or a call held for your approval, each with the command that answers it. Below, the history shows 10, 25 or 50 scans a page; **Older** pages back. Search by tool name, outcome, time window or minimum risk. The traffic log has no index, so a search reads it backwards from the newest line, skipping lines outside the time window without parsing them; a time window makes searches faster. A search reads at most the whole log at its configured size (twice `traffic_log.max_bytes`, up to 256 MB) and says when it stopped early.

The tab only reads. To change a grant or a snooze, use the commands above. It shows the same records as
`/sentrook history` and `/sentrook why`, never a call's arguments, and nothing when the traffic log is off. It reads
the traffic log of the profile the dashboard is showing.

The tab appears once the plugin is enabled (`plugins.enabled`). After installing or updating the plugin, restart
`hermes dashboard`. The Hermes desktop app does not show dashboard tabs.

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

Reviews use Hermes's approval prompt, which needs a person on the other end. Chat platforms and the local terminal
count as attended. Elsewhere, including the API server, cron, subagents and webhooks, a review holds the call instead
(see [Held calls](#held-calls-on-unattended-runs)). If a UI in front of the API server shows Hermes's approval
prompts, add it with `attended_platforms` (see [Settings](#settings)). Hermes's own background skill and memory saves
never ask, wherever they run (see [Background skill and memory saves](#background-skill-and-memory-saves)).

### What a review looks like

Hermes frames the prompt with its own heading and buttons; Sentrook's part starts with a feather:

```text
🪶 Sentrook security check · risk 62/100
Sends ~/notes/q3-plan.md to paste.example.net.
Because paste.example.net is new to Sentrook as a place to send data.
"Always" also trusts paste.example.net for 30 days.
Details: /sentrook why 3f9c2a1b
```

- The first line says it is Sentrook asking and gives the risk score (reviews start at 45, blocks at 80). "Safety
  rule" in place of "security check" means a rule that always asks, whatever the score.
- The next lines say what the call does and, in plain words, the main reasons. Long files and addresses are
  shortened in the middle; on small screens (a Discord message holds 300 characters) the reasons and your options
  are kept and the description of the call is shortened first.
- **Once** runs this call. **Session** and **Always** also run the same action (same tool, source and destination)
  without asking again: for this session, or from now on, in every later session too. A call that names no file, address or other target is
  covered only when it is repeated exactly. Where a grant would cover calls like this, the prompt says what
  **Always** also sets, or gives the command.
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
- You get one notice on the home channel (`/sethome`) of the platform you name in `owner_channel`, for example
  `telegram`. Set it: until you do, nothing is sent, the call is still held, and `status` and `verify` say notices
  are not sent. Hermes copies what it sends into the agent's own conversation, so the notice says only that a call
  was held, which run (a cron job by its id, and its name in quotes), the tool and its target, a broad category,
  and the commands. Read the risk, the reasons and any grant Sentrook suggests with `/sentrook why <id>`.
- Reply `/sentrook approve <id>` within 24 hours (from a direct message or the local terminal, like the other owner
  commands). When Sentrook suggested a grant for the call, approving sets it as a persistent grant that ends after 30
  days, so the job's next run is scanned with it. When it suggested none, approving sets nothing and the reply says
  so; add a grant with `/sentrook grant ... --persistent` if the job should pass. The held call itself is never run
  again.
- A hold nobody approves expires after 24 hours, and nothing runs.

A block (at `block_at` or above, or one the scanner enforces) is never held: it stays a block. The one exception is a retry of a call whose review nobody answered (it timed out, was held, or was auto-denied by the review loop) when only the retry takes it to a block: that retry is held, as a review would be. The traffic log records
the scan with decision `held`, then the approval or the expiry; `/sentrook history` shows them.

### Hermes's own skill and memory saves

After a turn, Hermes reviews what it learned and saves skills (`skill_manage`) and memory (`memory`) in the
background; when idle, its curator tidies those skills. This background review has no request of its own, so a
save would otherwise look like a write nobody asked for. By default (`skill_review: allow`) the plugin tells
Sentrook that the call is one of these background saves and sends the part of the conversation the review read,
and Sentrook judges the save against that conversation. A save that follows from what you said and did goes
through. A save is reviewed or blocked when it carries instructions that came from content the agent read or from
other people, weakens one of your rules, claims approvals you never gave, or stores secrets you did not ask it to
keep. These saves never ask you (see [Background skill and memory saves](#background-skill-and-memory-saves)).

Every background save is scanned and logged, and `status` counts them: allowed, blocked, held and let through. Only Hermes's
automatic review and curator count: a skill or memory change you ask for in a turn, or a `/refine` you run, is
scanned like any other call, and so is every other tool those background runs call. Every call a background run
makes is sent with your last message as its request and the number of the turn it follows, and does not count as
a turn of its own; if you have not written anything in the session yet, the request names the background review
instead. Set `skill_review` to `review`
to send the background saves like any other call, without the conversation; with nothing to judge them against,
expect more of them to be reviewed or blocked.

On the local terminal the background review cannot show you its prompts, so Hermes denies them itself. That still
happens to the review's other calls (reading a file, for example) and to a `/refine` you run there; history shows
such a call as "auto-denied by the review loop". If you then ask the agent to make that call, or one whose review
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
| Review, otherwise | It is held: not saved. There is nothing to approve, because approving could not make the save; to keep it, ask the agent for it in a chat. | A notice that a background save was held. |
| Block | It is not saved. | A notice that a background save was blocked. |
| The scan failed | As on an unattended run: with `on_scan_error` `review` or `deny` it is not saved, with `allow` it is (see [When the scan service fails](#when-the-scan-service-fails)). | The scan-failure notice when it is not saved. |

The notices go to the home channel of the platform in `owner_channel`. They say whether it was a skill or a memory
save and what it saved, as a review would describe it, and point to `/sentrook why <id>` and `/sentrook history`.
You get at most one notice of each kind (let through, held, blocked) per session every 6 hours; history has every
save, and shows a held one as "not saved".
Without `owner_channel` (for example when you use Hermes only on the local terminal) the saves are handled the same
way, but nothing tells you: `status` and `verify` say so, and the saves show only in `/sentrook history` and the
`skill review` counts in `status`. A snooze on the session (or on every session) lets a save through that would
otherwise be held, with the "let through" notice, when the save follows a chat, a local terminal session or a
platform in `attended_platforms`; it never lets a blocked save through, and never one from the curator or after a
cron job, a webhook, the API server or any other platform. History marks these saves "(self-edit)".

### When the scan service fails

A scan gives no usable answer when the scan service returns an error, does not answer within `timeout_ms` (30
seconds), cannot be reached, or rate-limits the scan. The call is then not scanned, and with the default setting
(`on_scan_error`: `review`):

- **Where reviews are attended** (chat platforms, the local terminal, and platforms in `attended_platforms`) you are
  asked, with Hermes's approval prompt, whether to run the call without a scan. It runs only if you approve, except
  in a session where you switched on YOLO, where Hermes approves the prompt itself (see above). Answering
  **Session** or **Always** stops these questions in that chat until Sentrook can scan again; another chat, or a
  different kind of failure (for example credentials that expire meanwhile), still asks.
- **On unattended runs** (the API server, cron, subagents, webhooks, and anywhere Hermes approvals are switched off
  as described above) nobody can answer, so the call is blocked. The agent is told that Sentrook did not scan the
  call, that this is a service problem rather than a security block, and that the call did not run. The call is not
  held, so there is nothing to approve, but you get a notice on the `owner_channel` home channel, like a held call's.
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

To start in observe mode from the beginning, install with `--no-enable` in step 3, set the mode, then run
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
similar) are replaced with placeholders such as `⟦secret:github:…⟧`. Recipients, hosts and email addresses are kept,
because the scanner needs them to judge where data is going. So is code that only reads a secret from where it is
kept, such as `os.environ["API_KEY"]`: it names the place, not the secret. Your files, messages and tool output can
still contain personal information, and that is sent as it is.

A local copy of each scan (the redacted request and the response) is kept in `~/.hermes/sentrook/traffic.jsonl`,
readable only by your user and rotated at 50 MB. The plugin never uploads it. Turn it off with
`hermes config set plugins.entries.sentrook.settings.traffic_log.enabled false`; the history and why commands then
have nothing to show.

## What the plugin does on your machine

In short, for anyone deciding whether to install it:

- **Network:** it calls two services run by First Data Union: the scan service (`sentrook.firstdataunion.org`), once
  per tool call, with the redacted request described in [What is sent](#what-is-sent), and the identity service
  (`identity.firstdataunion.org`) to exchange the scan credentials for a short-lived token. Nothing else, and no
  telemetry beyond the scans themselves.
- **Hermes's own saves:** with `skill_review: allow` (the default), the redacted recent conversation goes with each of
  Hermes's background skill and memory saves, and a redacted copy of recent messages is kept on disk to send with
  them. Set it to `review` to stop both.
- **What it can do to a call:** allow it, block it, or hand it to Hermes's own approval prompt. It never approves a
  call on your behalf. Where nobody can answer a prompt (cron, webhooks, the API server) a review holds the call and
  sends you one notice on a home channel, through Hermes's own `send_message`, and a call blocked because the scan
  failed sends you one notice per job (per session for other runs) every 6 hours at most; those notices are the
  only messages it sends.
- **Files:** it writes only to its own folder in Hermes's home (`~/.hermes/sentrook/`, `/opt/data/sentrook/` in Docker:
  the traffic log, grants, snooze state, held calls, when each job last had a scan-failure notice, and the
  conversation logs above), or to the paths you set for them
  (`state_dir`, `traffic_log.path`). Besides that folder it reads Hermes's `config.yaml`, for whether approvals and
  secret redaction are on. It runs no shell commands and starts no background processes.
- **Credentials:** the scan credentials are stored and handed over by Hermes. The plugin never reads `.env`,
  `auth.json` or any other credential file.
- **Turning it down or off:** [observe mode](#observe-mode) scores and logs without ever blocking or asking, and
  `hermes plugins disable sentrook` stops it sending anything.

## Settings

Set with `hermes config set plugins.entries.sentrook.settings.<key> <value>` and restart. Most keys can also come
from a `SENTROOK_*` variable in the environment Hermes starts with; the setting wins. The scan credentials are not
settings (see [step 2](#2-add-the-credentials-to-hermes)).

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `enforce` | `observe` or `enforce` |
| `review_at` | `45` | Ask at or above this risk |
| `block_at` | `80` | Block at or above this risk |
| `on_scan_error` | `review` | `allow`, `deny` or `review` when the scan gives no usable answer |
| `attended_platforms` | | Extra session platforms where a person answers approvals, such as `api_server` |
| `owner_channel` | | The platform whose home channel gets the notices of held calls, of scan failures on unattended runs, and of background skill and memory saves blocked or let through without asking, such as `telegram`. No notice is sent until it is set |
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
`SENTROOK_SCAN_CLIENT_*` lines from the file `hermes config env-path` prints, and delete the credentials on the identity
service's **Sentrook** tab. To install again later, start from
step 3.
